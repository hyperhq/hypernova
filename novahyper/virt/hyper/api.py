# Copyright (c) 2015 HyperHQ Inc.
# Copyright 2013 dotCloud inc.
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

import json

class HyperClient(object):
    def __init__(self):
        pass

    def ping(self):
        try:
            self._result(self._get(self._url('/info')))
        except Exception:
            return False
        return True

    def info(self):
        return self._result(self._get(self._url('/info')),json=True)

    def pods(self, all=True):
        pods = self._result(self._get(self._url('/list?item=pod')),json=True)
        ret = []
        for item in pods.get("podData",[]):
            sitem = item.split(":")
            ret.append({
                "id":item[0],
                "name":item[1],
                "status":item[3]
            })
        return ret

    # todo: get pod (vm) info with ID
    # todo: change CpuShares
    def inspect_pod(self, pod_id):
        return {
            "Config": {
                "Hostname":pod_id,
                "CpuShares":1,
            }
        }

    def find_pod_from_name(self, name):
        l = self.find_pods_from_name(name)
        return (l[0] if len(l) else None)

    def find_pods_from_name(self, name):
        return [pod.get("id") for pod in self.pods() if pod.get("name") == name]

    def find_pod_by_uuid(self, uuid):
        pod_id = self.find_pod_from_name("nova-"+uuid)
        return ({"id": pod_id,
                 "State": {
                     "Running": True,
                 },
                 "Config": {
                     "Memory": 512,
                     'CpuShares': 1,
                 }
             } if pod_id else None)

    def pull_image(self, image):
        return self._result(self._post(self._url('/image/create?imageName={0}'.format(image))),json=True)

    #todo: login? - use path? ..
    def load_image(self, image, path):
        return self.pull_image(image)

    # todo: get image info from image name
    def inspect_image(self, image):
        return image
        #return {}

    def start(self, pod_id, binds=None, dns=None, privileged=False):
        return self._result(self._post(self._url('/pod/start?podId={0}'.format(pod_id))),json=True)

    def kill(self, pod_id):
        return self.stop(pod_id)

    def remove_pod(self, pod_id, force=False):
        return self._result(self._delete(self._url('/pod?podId={0}'.format(pod_id))),json=True)

    def stop(self, pod_id, timeout=0):
        return self._result(self._post(self._url('/pod/stop?podId={0}&stopVM=yes'.format(pod_id))),json=True)

    def pause(self, pod_id):
        return self._result(self._post(self._url('/pod/stop?podId={0}&stopVM=no'.format(pod_id))),json=True)

    def unpause(self, pod_id):
        return self.start(pod_id)

    ## ?
    #todo: check
    #def create_host_config(self, ?**args):
    #    return {}

    #todo: clean
    def create_pod(self, image_name, name, hostname, cpu_shares, network_disabled,environment, command, host_config):
        obj = {
            "id": name,
            "tty": True,
            "resource":{
                "vcpu": cpu_shares,
                "memory": host_config['mem_limit'],
            },
            "containers": [{
                "image": image_name,
                "command": ["/bin/sh"],
                "files": [
                ],
            }],
            "files": [
            ],
            "volumes": [
            ],
            #"interfaces":{
            #    "bridge": bridge,
            #    "ifname": tapName,
            #    "mac": port.MACAddress,
            #    "ip": ipcidr,
            #    "gateway": gateway,
            #}
        }
        result = self._result(self._post_json(url=self._url('/pod/create'),
                                              data=obj),
                              json=True)
        return result

    # todo
    def get_pod_logs(self, pod_id):
        return "logs"

    # todo
    def commit(self, pod_id, repository, tag):
        return True
