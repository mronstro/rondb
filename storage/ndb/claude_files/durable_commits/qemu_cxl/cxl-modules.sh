#!/bin/bash
# Guest, as root (run by cloud-init): rebuild drivers/cxl of the installed
# elrepo kernel-ml with CONFIG_CXL_REGION_INVALIDATION_TEST and install the
# modules in /lib/modules/<kver>/updates/cxl. Without it an x86 guest cannot
# commit a CXL region: the kernel refuses ("Failed to synchronize CPU cache
# state") because it cannot invalidate caches by WBINVD under a hypervisor.
set -euxo pipefail
KVER=${1:-$(ls -t /lib/modules | grep elrepo | head -1)}
V=${KVER%%-*}            # 7.3.4-1.el9.elrepo.x86_64 -> 7.3.4
V=${V%.0}                # kernel.org names x.y.0 as x.y
MAJ=${V%%.*}
mkdir -p /var/tmp/ksrc && cd /var/tmp/ksrc
curl -sSfL -o linux-$V.tar.xz https://cdn.kernel.org/pub/linux/kernel/v$MAJ.x/linux-$V.tar.xz
tar xf linux-$V.tar.xz linux-$V/drivers/cxl
cd linux-$V/drivers/cxl
grep -q CXL_REGION_INVALIDATION_TEST core/region.c
make -j"$(nproc)" -C /lib/modules/$KVER/build M="$PWD" \
  KCFLAGS="-DCONFIG_CXL_REGION_INVALIDATION_TEST=1 -I$PWD" modules
install -d /lib/modules/$KVER/updates/cxl
install -m 644 core/cxl_core.ko cxl_*.ko /lib/modules/$KVER/updates/cxl/
depmod -a $KVER
