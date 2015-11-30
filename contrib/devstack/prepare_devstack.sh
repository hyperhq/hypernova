#!/bin/bash
set -xe

env

NOVAHYPERDIR=$(readlink -f $(dirname $0)/../..)
INSTALLDIR=${INSTALLDIR:-/opt/stack}

cp $NOVAHYPERDIR/contrib/devstack/extras.d/70-hyper.sh $INSTALLDIR/devstack/extras.d/
cp $NOVAHYPERDIR/contrib/devstack/lib/nova_plugins/hypervisor-hyper $INSTALLDIR/devstack/lib/nova_plugins/

cat - <<-EOF >> $INSTALLDIR/devstack/localrc
export VIRT_DRIVER=hyper
export DEFAULT_IMAGE_NAME=cirros
export NON_STANDARD_REQS=1
export IMAGE_URLS=" "
EOF

