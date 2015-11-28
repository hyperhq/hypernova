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

class HyperClient():
    def __init__(self, url):
        self.base_url = url

    def ping(self):
        try:
            self._result(self._get(self._url('/info')))
        except Exception:
            return False
        return True

    def info(self):
        return self._result(self._get(self._url('/info')))

    def pods(self, all=True):
        return self._result(self._get(self._url('/list?item=pod')))

    # todo: get pod (vm) info with ID
    def inspect_pod(self, pod_id):
        #[Config][Hostname]
        return {"Config":{"Hostname":pod_id}}

    # todo: get pod id form uuid (vm id?)
    def find_pod_by_uuid(self, uuid):
        #[id]
        return {"id": uuid}

    def pull_image(self, image):
        return self._result(self._get(self._url('/image/create?imageName={0}'.format(image))))

    #todo: login? - use path? ..
    def load_image(self, image, path):
        return self.pull_image(image)

    # todo: get image info from image name
    def inspect_image(self, image):
        return image
        #return {}

    def start(self, pod_id, binds=None, dns=None, privileged=False):
        return self._result(self._get(self._url('/pod/start?podId={0}'.format(pod_id))))

    def kill(self, pod_id):
        return self.stop(pod_id)

    def remove_pod(self, pod_id, force=False):
        return self._result(self._delete(self._url('/pod?podId={0}'.format(pod_id))))

    def stop(self, pod_id, timeout=0):
        return self._result(self._get(self._url('/pod/stop?podId={0}&stopVM=yes'.format(pod_id))))

    def pause(self, pod_id):
        return self._result(self._get(self._url('/pod/stop?podId={0}&stopVM=no'.format(pod_id))))

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
            #"tty": True,
            "resource":{
                "vcpu": cpu_shares,
                "memory": host_config['mem_limit'],
            },
            "containers": [{
                "image": image_name,
                "files": [
                ],
            }],
            "files": [
            ],
            "volumes": [
            ],
        }
        obj_str = json.dumps(obj)
        return self._result(self._post(self._url('/pod/create'), obj_str))

    # todo
    def get_pod_logs(self, pod_id):
        return "logs"

    # todo
    def commit(self, pod_id, repository, tag):
        return True
