# Copyright 2015 HyperHQ Inc.
# Copyright 2013 dotCloud inc.

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.


from novahyper.virt.hyper import errors


DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_UNIX_SOCKET = "http+unix://var/run/hyper.sock"


# Based on utils.go:ParseHost http://tinyurl.com/nkahcfh
# fd:// protocol unsupported (for obvious reasons)
# Added support for http and https
# Protocol translation: tcp -> http, unix -> http+unix
def parse_host(addr, platform=None):
    proto = "http+unix"
    host = DEFAULT_HTTP_HOST
    port = None
    path = ''

    if not addr and platform == 'win32':
        addr = '{0}:{1}'.format(DEFAULT_HTTP_HOST, 2375)

    if not addr or addr.strip() == 'unix://':
        return DEFAULT_UNIX_SOCKET

    addr = addr.strip()
    if addr.startswith('http://'):
        addr = addr.replace('http://', 'tcp://')
        if addr.startswith('http+unix://'):
            addr = addr.replace('http+unix://', 'unix://')

    if addr == 'tcp://':
        raise errors.HyperException(
            "Invalid bind address format: {0}".format(addr))
    elif addr.startswith('unix://'):
        addr = addr[7:]
    elif addr.startswith('tcp://'):
        proto = "http"
        addr = addr[6:]
    elif addr.startswith('https://'):
        proto = "https"
        addr = addr[8:]
    elif addr.startswith('fd://'):
        raise errors.HyperException("fd protocol is not implemented")
    else:
        if "://" in addr:
            raise errors.HyperException(
                "Invalid bind address protocol: {0}".format(addr)
            )
            proto = "http"

    if proto != "http+unix" and ":" in addr:
        host_parts = addr.split(':')
        if len(host_parts) != 2:
            raise errors.HyperException(
                "Invalid bind address format: {0}".format(addr)
            )
        if host_parts[0]:
            host = host_parts[0]

        port = host_parts[1]
        if '/' in port:
            port, path = port.split('/', 1)
            path = '/{0}'.format(path)
        try:
            port = int(port)
        except Exception:
            raise errors.HyperException(
                "Invalid port: %s", addr
            )

    elif proto in ("http", "https") and ':' not in addr:
        raise errors.HyperException(
            "Bind address needs a port: {0}".format(addr))
    else:
        host = addr

    if proto == "http+unix":
        return "{0}://{1}".format(proto, host)
    return "{0}://{1}:{2}{3}".format(proto, host, port, path)
