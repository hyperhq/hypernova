# Copyright (c) 2013 dotCloud, Inc.
# Copyright 2014 IBM Corp.
# Copyright (c) 2015 HyperHQ Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
A Hyper.sh Hypervisor which allows running Docker Images as VMs.
"""

import os
import shutil
import socket
import time
import uuid

#from docker import utils as docker_utils
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import fileutils
from oslo_utils import importutils
from oslo_utils import units

from nova.compute import arch
from nova.compute import flavors
from nova.compute import hv_type
from nova.compute import power_state
from nova.compute import task_states
from nova.compute import vm_mode
from nova import exception
from nova.image import glance
from nova import objects
from nova import utils
from nova import utils as nova_utils
from nova.virt import driver
from nova.virt import firewall
from nova.virt import hardware
from nova.virt import images

from novahyper.i18n import _, _LI, _LE
from novahyper.virt.hyper import client as hyper_client
from novahyper.virt.hyper import hostinfo
from novahyper.virt.hyper import network
from novahyper.virt.hyper import errors
from novahyper.virt import hostutils

CONF = cfg.CONF
CONF.import_opt('my_ip', 'nova.netconf')
CONF.import_opt('instances_path', 'nova.compute.manager')

hyper_opts = [
    cfg.StrOpt('root_directory',
               default='/var/lib/hyper',
               help='Path to use as the root of the Hyper runtime.'),
    cfg.StrOpt('host_url',
               default='unix:///var/run/hyper.sock',
               help='tcp://host:port to bind/connect to or '
                    'unix://path/to/socket to use'),
    cfg.BoolOpt('api_insecure',
                default=False,
                help='If set, ignore any SSL validation issues'),
#    cfg.StrOpt('ca_file',
#               help='Location of CA certificates file for '
#                    'securing docker api requests (tlscacert).'),
#    cfg.StrOpt('cert_file',
#               help='Location of TLS certificate file for '
#                    'securing docker api requests (tlscert).'),
#    cfg.StrOpt('key_file',
#               help='Location of TLS private key file for '
#                    'securing docker api requests (tlskey).'),
    cfg.StrOpt('vif_driver',
               default='novahyper.virt.hyper.vifs.HyperGenericVIFDriver'),
    cfg.StrOpt('snapshots_directory',
               default='$instances_path/snapshots',
               help='Location where hyper driver will temporarily store '
                    'snapshots.'),
    cfg.BoolOpt('inject_key',
                default=False,
                help='Inject the ssh public key at boot time'),
    cfg.StrOpt('shared_directory',
               default=None,
               help='Shared directory where glance images located. If '
                    'specified, hyper will try to load the image from '
                    'the shared directory by image ID.'),
    cfg.BoolOpt('privileged',
                default=False,
                help='Set true can own all root privileges in a pod-vm.'),
]

CONF.register_opts(hyper_opts, 'hyper')

LOG = log.getLogger(__name__)


class HyperDriver(driver.ComputeDriver):
    """Hyper hypervisor driver."""

    def __init__(self, virtapi):
        #driver.ComputeDriver.__init__(self, virtapi)
        super(HyperDriver, self).__init__(virtapi) #todo: check
        self._hyper = None
        vif_class = importutils.import_class(CONF.hyper.vif_driver)
        self.vif_driver = vif_class()
        self.firewall_driver = firewall.load_driver(
            default='nova.virt.firewall.NoopFirewallDriver')

    @property
    def hyper(self):
        if self._hyper is None:
            self._hyper = hyper_client.HyperHTTPClient(CONF.hyper.host_url)
        return self._hyper

    def init_host(self, host):
        if self._is_daemon_running() is False:
            raise exception.NovaException(
                _('Hyper daemon is not running or is not reachable'
                  ' (check the rights on /var/run/hyper.sock)'))

    def _is_daemon_running(self):
        return self.hyper.ping()

    def _start_firewall(self, instance, network_info):
        self.firewall_driver.setup_basic_filtering(instance, network_info)
        self.firewall_driver.prepare_instance_filter(instance, network_info)
        self.firewall_driver.apply_instance_filter(instance, network_info)

    def _stop_firewall(self, instance, network_info):
        self.firewall_driver.unfilter_instance(instance, network_info)

    def refresh_security_group_rules(self, security_group_id):
        """Refresh security group rules from data store.

        Invoked when security group rules are updated.

        :param security_group_id: The security group id.

        """
        self.firewall_driver.refresh_security_group_rules(security_group_id)

    def refresh_security_group_members(self, security_group_id):
        """Refresh security group members from data store.

        Invoked when instances are added/removed to a security group.

        :param security_group_id: The security group id.

        """
        self.firewall_driver.refresh_security_group_members(security_group_id)

    def refresh_provider_fw_rules(self):
        """Triggers a firewall update based on database changes."""
        self.firewall_driver.refresh_provider_fw_rules()

    def refresh_instance_security_rules(self, instance):
        """Refresh security group rules from data store.

        Gets called when an instance gets added to or removed from
        the security group the instance is a member of or if the
        group gains or loses a rule.

        :param instance: The instance object.

        """
        self.firewall_driver.refresh_instance_security_rules(instance)

    def ensure_filtering_rules_for_instance(self, instance, network_info):
        """Set up filtering rules.

        :param instance: The instance object.
        :param network_info: Instance network information.

        """
        self.firewall_driver.setup_basic_filtering(instance, network_info)
        self.firewall_driver.prepare_instance_filter(instance, network_info)

    def unfilter_instance(self, instance, network_info):
        """Stop filtering instance.

        :param instance: The instance object.
        :param network_info: Instance network information.

        """
        self.firewall_driver.unfilter_instance(instance, network_info)

    ###

    def list_instances(self, inspect=False):
        res = []
        for pod in self.hyper.pods(all=True):
            info = self.hyper.inspect_pod(pod) ## pod['id']
            if not info:
                continue
            if inspect:
                res.append(info)
            else:
                res.append(info['Config'].get('Hostname'))
        return res

    def attach_interface(self, instance, image_meta, vif):
        """Attach an interface to the pod-vm."""
        self.vif_driver.plug(instance, vif)
        pod_id = self.hyper.find_pod_by_uuid(instance['uuid']).get('id')
        self.vif_driver.attach(instance, vif, pod_id)

    def detach_interface(self, instance, vif):
        """Detach an interface from the pod-vm."""
        self.vif_driver.unplug(instance, vif)

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        for vif in network_info:
            self.vif_driver.plug(instance, vif)
        self._start_firewall(instance, network_info)

    def _attach_vifs(self, instance, network_info):
        """Plug VIFs into pod."""
        if not network_info:
            return
        pod_id = self.hyper.find_pod_by_uuid(instance)
        if not pod_id:
            return
        # todo: link/create ifaces
        for vif in network_info:
            self.vif_driver.attach(instance, vif, pod_id)

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        for vif in network_info:
            self.vif_driver.unplug(instance, vif)
        self._stop_firewall(instance, network_info)

    def _encode_utf8(self, value):
        return unicode(value).encode('utf-8')

    def get_info(self, instance):
        pod = self.hyper.find_pod_by_uuid(instance['uuid'])
        if not pod:
            raise exception.InstanceNotFound(instance_id=instance['name'])
        running = pod['State'].get('Running')
        mem = pod['Config'].get('Memory', 0)

        # todo: check 1024 multiplier
        num_cpu = pod['Config'].get('CpuShares', 0) / 1024

        info = hardware.InstanceInfo(
            max_mem_kb=mem,
            mem_kb=mem,
            num_cpu=num_cpu,
            cpu_time_ns=0,
            state=(power_state.RUNNING if running
                   else power_state.SHUTDOWN)
        )
        return info

    def get_host_stats(self, refresh=False):
        hostname = socket.gethostname()
        stats = self.get_available_resource(hostname)
        stats['host_hostname'] = stats['hypervisor_hostname']
        stats['host_name_label'] = stats['hypervisor_hostname']
        return stats

    def get_available_nodes(self, refresh=False):
        hostname = socket.gethostname()
        return [hostname]

    def get_available_resource(self, nodename):
        if not hasattr(self, '_nodename'):
            self._nodename = nodename
        if nodename != self._nodename:
            LOG.error(_('Hostname has changed from %(old)s to %(new)s. '
                        'A restart is required to take effect.'
                        ), {'old': self._nodename,
                            'new': nodename})

        memory = hostinfo.get_memory_usage()
        disk = hostinfo.get_disk_usage()
        cur_hv_type = hv_type.HYPER #todo: check
        stats = {
            'vcpus': hostinfo.get_total_vcpus(),
            'vcpus_used': hostinfo.get_vcpus_used(self.list_instances(True)),
            'memory_mb': memory['total'] / units.Mi,
            'memory_mb_used': memory['used'] / units.Mi,
            'local_gb': disk['total'] / units.Gi,
            'local_gb_used': disk['used'] / units.Gi,
            'disk_available_least': disk['available'] / units.Gi,
            'hypervisor_type': 'hyper', #todo: check
            'hypervisor_version': utils.convert_version_to_int('1.0'),
            'hypervisor_hostname': self._nodename,
            'cpu_info': '?',
            'numa_topology': None,
            'supported_instances': jsonutils.dumps([
                (arch.I686, cur_hv_type, vm_mode.EXE),
                (arch.X86_64, cur_hv_type, vm_mode.EXE)
            ])
        }
        return stats

    def _get_memory_limit_mbytes(self, instance):
        if isinstance(instance, objects.Instance):
            return instance.get_flavor().memory_mb
        else:
            system_meta = utils.instance_sys_meta(instance)
            return int(system_meta.get(
                'instance_type_memory_mb', 0))

    def _get_image_name(self, context, instance, image):
        fmt = image['container_format']
        if fmt != 'docker':
            msg = _('Image container format not supported ({0})')
            raise exception.InstanceDeployFailure(msg.format(fmt),
                                                  instance_id=instance['name'])
        return image['name']

    def _pull_missing_image(self, context, image_meta, instance):
        msg = 'Image name "%s" does not exist, fetching it...'
        LOG.debug(msg, image_meta['name'])

        shared_directory = CONF.hyper.shared_directory
        #todo: check image location
        if (shared_directory and
                os.path.exists(os.path.join(shared_directory,
                                            image_meta['id']))):
            try:
                self.hyper.load_image(
                    self._encode_utf8(image_meta['name']),
                    os.path.join(shared_directory, image_meta['id']))
                return self.hyper.inspect_image(
                    self._encode_utf8(image_meta['name']))
            except Exception as e:
                # If failed to load image from shared_directory, continue
                # to download the image from glance then load.
                LOG.warning(_('Cannot load repository file from shared '
                              'directory: %s'),
                            e, instance=instance, exc_info=True)

        snapshot_directory = CONF.hyper.snapshots_directory
        fileutils.ensure_tree(snapshot_directory)
        with utils.tempdir(dir=snapshot_directory) as tmpdir:
            try:
                out_path = os.path.join(tmpdir, uuid.uuid4().hex)

                images.fetch(context, image_meta['id'], out_path,
                             instance['user_id'], instance['project_id'])
                self.hyper.load_image(
                    self._encode_utf8(image_meta['name']),
                    out_path
                )
            except Exception as e:
                LOG.warning(_('Cannot load repository file: %s'),
                            e, instance=instance, exc_info=True)
                msg = _('Cannot load repository file: {0}')
                raise exception.NovaException(msg.format(e),
                                              instance_id=image_meta['name'])

        return self.hyper.inspect_image(self._encode_utf8(image_meta['name']))

    def _extract_dns_entries(self, network_info):
        dns = []
        if network_info:
            for net in network_info:
                subnets = net['network'].get('subnets', [])
                for subnet in subnets:
                    dns_entries = subnet.get('dns', [])
                    for dns_entry in dns_entries:
                        if 'address' in dns_entry:
                            dns.append(dns_entry['address'])
        return dns if dns else None

    def _get_key_binds(self, vm_id, instance):
        binds = None
        # Handles the key injection.
        if CONF.hyper.inject_key and instance.get('key_data'):
            key = str(instance['key_data'])
            mount_origin = self._inject_key(vm_id, key)
            binds = {mount_origin: {'bind': '/root/.ssh', 'ro': True}}
        return binds

    def _start_pod(self, pod_id, instance, network_info=None):
        binds = self._get_key_binds(pod_id, instance)
        dns = self._extract_dns_entries(network_info)
        self.hyper.start(pod_id, binds=binds, dns=dns,
                         privileged=CONF.hyper.privileged)

        if not network_info:
            return
        try:
            self.plug_vifs(instance, network_info)
            self._attach_vifs(instance, network_info) #todo: remove?
        except Exception as e:
            LOG.warning(_('Cannot setup network: %s'),
                        e, instance=instance, exc_info=True)
            msg = _('Cannot setup network: {0}')
            self.hyper.kill(pod_id)
            self.hyper.remove_pod(pod_id, force=True)
            raise exception.InstanceDeployFailure(msg.format(e),
                                                  instance_id=instance['name'])

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None,
              flavor=None):
        image_name = self._get_image_name(context, instance, image_meta)
        args = {
            'hostname': instance['name'],
            'mem_limit': self._get_memory_limit_mbytes(instance),
            'cpu_shares': self._get_cpu_shares(instance),
            'network_disabled': False,
        }

        try:
            image = self.hyper.inspect_image(self._encode_utf8(image_name))
        except errors.APIError:
            image = None

        if not image:
            image = self._pull_missing_image(context, image_meta, instance)
        # Glance command-line overrides any set in the Docker image
        if (image_meta and
                image_meta.get('properties', {}).get('os_command_line')):
            args['command'] = image_meta['properties'].get('os_command_line')

        if 'metadata' in instance:
            args['environment'] = nova_utils.instance_meta(instance)

        pod_id = self._create_pod(instance, image_name, args)
        if not pod_id:
            raise exception.InstanceDeployFailure(
                _('Cannot create pod'),
                instance_id=instance['name'])

        self._start_pod(pod_id, instance, network_info)

    def _inject_key(self, id, key):
        if isinstance(id, dict):
            id = id.get('id')
        sshdir = os.path.join(CONF.instances_path, id, '.ssh')
        key_data = ''.join([
            '\n',
            '# The following ssh key was injected by Nova',
            '\n',
            key.strip(),
            '\n',
        ])
        fileutils.ensure_tree(sshdir)
        keys_file = os.path.join(sshdir, 'authorized_keys')
        with open(keys_file, 'a') as f:
            f.write(key_data)
        os.chmod(sshdir, 0o700)
        os.chmod(keys_file, 0o600)
        return sshdir

    def _cleanup_key(self, instance, id):
        if isinstance(id, dict):
            id = id.get('id')
        dir = os.path.join(CONF.instances_path, id)
        if os.path.exists(dir):
            LOG.info(_LI('Deleting instance files %s'), dir,
                     instance=instance)
            try:
                shutil.rmtree(dir)
            except OSError as e:
                LOG.error(_LE('Failed to cleanup directory %(target)s: '
                              '%(e)s'), {'target': dir, 'e': e},
                          instance=instance)

    def restore(self, instance):
        pod_id = self.hyper.find_pod_by_uuid(instance)
        if not pod_id:
            return

        self._start_pod(pod_id, instance)

    def _stop(self, pod_id, instance, timeout=5):
        try:
            self.hyper.stop(pod_id, max(timeout, 5))
        except errors.APIError as e:
            #if 'Unpause the pod before stopping' not in e.explanation:
            #    LOG.warning(_('Cannot stop container: %s'),
            #                e, instance=instance, exc_info=True)
            #    raise
            self.hyper.unpause(pod_id)
            self.hyper.stop(pod_id, timeout)

    def soft_delete(self, instance):
        pod_id = self.hyper.find_pod_by_uuid(instance)
        if not pod_id:
            return
        self._stop(pod_id, instance)

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        self.soft_delete(instance)
        self.cleanup(context, instance, network_info,
                     block_device_info, destroy_disks)

    def cleanup(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None, destroy_vifs=True):
        """Cleanup after instance being destroyed by Hypervisor."""
        pod_id = self.hyper.find_pod_by_uuid(instance)
        if not pod_id:
            self.unplug_vifs(instance, network_info)
            return
        self.hyper.remove_pod(pod_id, force=True)
        network.teardown_network(pod_id) #todo: remove?
        self.unplug_vifs(instance, network_info)
        if CONF.hyper.inject_key:
            self._cleanup_key(instance, pod_id)

    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        pod_id = self.hyper.find_pod_by_uuid(instance)
        if not pod_id:
            return
        self._stop(pod_id, instance)
        try:
            network.teardown_network(pod_id) #todo: remove?
            if network_info:
                self.unplug_vifs(instance, network_info)
        except Exception as e:
            LOG.warning(_('Cannot destroy the pod network'
                          ' during reboot {0}').format(e),
                        exc_info=True)
            return

        binds = self._get_key_binds(pod_id, instance)
        dns = self._extract_dns_entries(network_info)
        self.hyper.start(pod_id, binds=binds, dns=dns)
        try:
            if network_info:
                self.plug_vifs(instance, network_info)
                self._attach_vifs(instance, network_info) #todo: remove?
        except Exception as e:
            LOG.warning(_('Cannot setup network on reboot: {0}'), e,
                        exc_info=True)
            return

    def power_on(self, context, instance, network_info,
                 block_device_info=None):
        pod_id = self.hyper.find_pod_by_uuid(instance)
        if not pod_id:
            return
        binds = self._get_key_binds(pod_id, instance)
        dns = self._extract_dns_entries(network_info)
        self.hyper.start(pod_id, binds=binds, dns=dns)
        if not network_info:
            return
        try:
            self.plug_vifs(instance, network_info)
            self._attach_vifs(instance, network_info)
        except Exception as e:
            LOG.debug(_('Cannot setup network: %s'),
                      e, instance=instance, exc_info=True)
            msg = _('Cannot setup network: {0}')
            self.hyper.kill(pod_id)
            self.hyper.remove_pod(pod_id, force=True)
            raise exception.InstanceDeployFailure(msg.format(e),
                                                  instance_id=instance['name'])

    def power_off(self, instance, timeout=0, retry_interval=0):
        pod_id = self.hyper.find_pod_by_uuid(instance)
        if not pod_id:
            return
        self._stop(pod_id, instance, timeout)

    def pause(self, instance):
        """Pause the specified instance.

        :param instance: nova.objects.instance.Instance
        """
        try:
            pod_id = self.hyper.find_pod_by_uuid(instance)
            if not self.hyper.pause(pod_id):
                raise exception.NovaException
        except Exception as e:
            LOG.debug(_('Error pause pod: %s'),
                      e, instance=instance, exc_info=True)
            msg = _('Cannot pause pod: {0}')
            raise exception.NovaException(msg.format(e),
                                          instance_id=instance['name'])

    def unpause(self, instance):
        """Unpause paused VM instance.

        :param instance: nova.objects.instance.Instance
        """
        try:
            pod_id = self.hyper.find_pod_by_uuid(instance)
            if not self.hyper.unpause(pod_id):
                raise exception.NovaException
        except Exception as e:
            LOG.debug(_('Error unpause pod: %s'),
                      e, instance=instance, exc_info=True)
            msg = _('Cannot unpause pod: {0}')
            raise exception.NovaException(msg.format(e),
                                          instance_id=instance['name'])

    def get_console_output(self, context, instance):
        pod_id = self.hyper.find_pod_by_uuid(instance)
        if not pod_id:
            return ''
        return self.hyper.get_pod_logs(pod_id)

    #todo
    def snapshot(self, context, instance, image_href, update_task_state):
        pod_id = self.hyper.find_pod_by_uuid(instance)
        if not pod_id:
            raise exception.InstanceNotRunning(instance_id=instance['uuid'])

        update_task_state(task_state=task_states.IMAGE_PENDING_UPLOAD)
        (image_service, image_id) = glance.get_remote_image_service(
            context, image_href)
        image = image_service.show(context, image_id)
        if ':' not in image['name']:
            commit_name = self._encode_utf8(image['name'])
            tag = 'latest'
        else:
            parts = self._encode_utf8(image['name']).rsplit(':', 1)
            commit_name = parts[0]
            tag = parts[1]

        self.hyper.commit(pod_id, repository=commit_name, tag=tag)

        update_task_state(task_state=task_states.IMAGE_UPLOADING,
                          expected_state=task_states.IMAGE_PENDING_UPLOAD)

        metadata = {
            'is_public': False,
            'status': 'active',
            'disk_format': 'raw',
            'container_format': 'docker',
            'name': image['name'],
            'properties': {
                'image_location': 'snapshot',
                'image_state': 'available',
                'status': 'available',
                'owner_id': instance['project_id'],
                'ramdisk_id': instance['ramdisk_id']
            }
        }
        if instance['os_type']:
            metadata['properties']['os_type'] = instance['os_type']

        # todo: ?????
        """
        try:
            raw = self.docker.get_image(commit_name)
            # Patch the seek/tell as urllib3 throws UnsupportedOperation
            raw.seek = lambda x=None, y=None: None
            raw.tell = lambda: None
            image_service.update(context, image_href, metadata, raw)
        except Exception as e:
            LOG.debug(_('Error saving image: %s'),
                      e, instance=instance, exc_info=True)
            msg = _('Error saving image: {0}')
            raise exception.NovaException(msg.format(e),
                                          instance_id=instance['name'])
        """

    def _get_cpu_shares(self, instance):
        if isinstance(instance, objects.Instance):
            flavor = instance.get_flavor()
        else:
            flavor = flavors.extract_flavor(instance)
        return int(flavor['vcpus'])

    def _create_pod(self, instance, image_name, args):
        name = "nova-" + instance['uuid']
        hostname = args.pop('hostname', None)
        cpu_shares = args.pop('cpu_shares', None)
        network_disabled = args.pop('network_disabled', False)
        environment = args.pop('environment', None)
        command = args.pop('command', None)
        host_config = args
        #host_config = self.hyper.create_host_config(**args) #todo: check
        return self.hyper.create_pod(image_name,
                                     name=self._encode_utf8(name),
                                     hostname=hostname,
                                     cpu_shares=cpu_shares,
                                     network_disabled=network_disabled,
                                     environment=environment,
                                     command=command,
                                     host_config=host_config)

    def get_host_uptime(self):
        return hostutils.sys_uptime()
