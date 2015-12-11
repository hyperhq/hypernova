The contrib/devstack/ directory contains the files necessary to integrate Hyper Nova driver with devstack.

To install::

    $ git clone https://git.openstack.org/hyperhq/nova-hyper /opt/stack/nova-hyper
    $ git clone https://git.openstack.org/openstack-dev/devstack /opt/stack/devstack

    # Note : only needed until we can make use of configure_nova_hypervisor_rootwrap
    $ git clone https://git.openstack.org/openstack/nova /opt/stack/nova

    $ cd /opt/stack/nova-hyper
    $ ./contrib/devstack/prepare_devstack.sh

Run devstack as normal::

    $ ./stack.sh
