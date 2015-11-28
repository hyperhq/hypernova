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

from oslo_config import cfg

from novahyper.virt.hyper import api
from novahyper.virt.hyper import errors

import requests
import requests.exceptions
import six

import json

CONF = cfg.CONF
DEFAULT_VERSION="1"
TIMEOUT=30

class HyperHTTPClient(
        requests.Session,
        api.HyperClient):

    def __init__(self, url='unix://var/run/hyper.sock'):
        super(HyperHTTPClient, self).__init__(url)
        self.base_url = url
        self._version = DEFAULT_VERSION
        self.timeout = TIMEOUT

    def set_version(self, version):
        self._version = version

    def _raise_for_status(self, response, explanation=None):
        """Raises stored :class:`APIError`, if one occurred."""
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                raise errors.NotFound(e, response, explanation=explanation)
            raise errors.APIError(e, response, explanation=explanation)

    def _result(self, response, json=False, binary=False):
        assert not (json and binary)
        self._raise_for_status(response)

        if json:
            return response.json()
        if binary:
            return response.content
        return response.text

    def _set_request_timeout(self, kwargs):
        """Prepare the kwargs for an HTTP request by inserting the timeout
        parameter, if not already present."""
        kwargs.setdefault('timeout', self.timeout)
        return kwargs

    def _post(self, url, **kwargs):
        return self.post(url, **self._set_request_timeout(kwargs))

    def _get(self, url, **kwargs):
        return self.get(url, **self._set_request_timeout(kwargs))

    def _put(self, url, **kwargs):
        return self.put(url, **self._set_request_timeout(kwargs))

    def _delete(self, url, **kwargs):
        return self.delete(url, **self._set_request_timeout(kwargs))

    def _url(self, pathfmt, *args, **kwargs):
        for arg in args:
            if not isinstance(arg, six.string_types):
                raise ValueError(
                    'Expected a string but found {0} ({1}) '
                    'instead'.format(arg, type(arg))
                )

        args = map(six.moves.urllib.parse.quote_plus, args)

        if kwargs.get('versioned_api', True):
            return '{0}/v{1}{2}'.format(
                self.base_url, self._version, pathfmt.format(*args)
            )
        else:
            return '{0}{1}'.format(self.base_url, pathfmt.format(*args))
