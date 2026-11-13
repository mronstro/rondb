#!/bin/bash
# Guest, as root, after each start of the VM:
#   sudo setup-region.sh <build directory>
# 1. Creates the CXL pmem region, the fsdax namespace /dev/pmem0 and an XFS
#    file system mounted with dax=always on /mnt/pmem0 (mkfs only the first
#    time: the namespace and the data survive in the backing files), and
#    prints what Q1 records: persistence_domain, numa_node, the
#    dirty-shutdown files.
# 2. Bind-mounts guest-local directories over <build>/mysql-test/var (MTR's
#    sockets cannot be on virtiofs, and --vardir elsewhere would delete the
#    host's var) and over the build's runtime, library and plugin output
#    directories: with guest kernel 7.3.4 under TCG, pages that exec faults
#    in from virtiofs are wrong (read() is right), and mysqld and ndbmtd
#    crash before main. The copies are made once; after a rebuild on the
#    host, delete /var/tmp/bincopy in the guest.
set -x
BLD=${1:?usage: setup-region.sh <build directory>}
USER_NAME=$(stat -c %U "$BLD")
uname -r
modinfo -n cxl_core | grep -q /updates/ ||
  echo "WARNING: cxl_core is not the rebuilt one (cxl-modules.sh, /var/log/cxl-modules.log): region commit will fail" >&2
cxl list -M -D -u
if [ ! -e /dev/pmem0 ]; then
  cxl create-region -m -t pmem -d decoder0.0 -w 1 mem0 || {
    echo "create-region failed: power the guest off, start QEMU again" >&2; exit 1; }
  # A namespace in the label storage area comes back with the region.
  for i in $(seq 10); do [ -e /dev/pmem0 ] && break; sleep 1; done
  if [ ! -e /dev/pmem0 ]; then
    R=$(ndctl list -R | sed -n 's/.*"dev":"\(region[0-9]*\)".*/\1/p' | head -1)
    ndctl create-namespace -m fsdax -r "$R" || exit 1
  fi
fi
ndctl list -RN -u
R=$(ndctl list -R | sed -n 's/.*"dev":"\(region[0-9]*\)".*/\1/p' | head -1)
RD=/sys/bus/nd/devices/$R
echo "persistence_domain=[$(cat $RD/persistence_domain)]"
echo "numa_node=$(cat $RD/numa_node) target_node=$(cat $RD/target_node)"
for m in $RD/mapping[0-9]*; do
  n=$(cut -d, -f1 "$m"); echo "$m: $(cat "$m")"
  for f in nfit/dirty_shutdown papr/dirty_shutdown cxl/dirty_shutdown dirty_shutdown; do
    [ -e /sys/bus/nd/devices/$n/$f ] && echo "$n/$f = $(cat /sys/bus/nd/devices/$n/$f)"
  done
done
dmesg | grep -E 'GPF|cxl region|cxl_pmem' | tail -5
echo "badblocks=[$(cat /sys/block/pmem0/badblocks)]"
if ! findmnt /mnt/pmem0 >/dev/null; then
  blkid /dev/pmem0 | grep -q xfs || mkfs.xfs -f -m reflink=0 /dev/pmem0
  mkdir -p /mnt/pmem0 && mount -o dax=always /dev/pmem0 /mnt/pmem0 || exit 1
fi
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS /mnt/pmem0
mkdir -p /mnt/pmem0/mtr && chown "$USER_NAME:" /mnt/pmem0 /mnt/pmem0/mtr
mkdir -p /var/tmp/mtrvar && chown "$USER_NAME:" /var/tmp/mtrvar
findmnt "$BLD/mysql-test/var" >/dev/null || mount --bind /var/tmp/mtrvar "$BLD/mysql-test/var"
for d in runtime_output_directory library_output_directory plugin_output_directory; do
  if ! findmnt "$BLD/$d" >/dev/null; then
    [ -d /var/tmp/bincopy/$d ] || { mkdir -p /var/tmp/bincopy && cp -a "$BLD/$d" /var/tmp/bincopy/; }
    mount --bind /var/tmp/bincopy/$d "$BLD/$d"
  fi
done
findmnt -o TARGET,SOURCE | grep -E 'mysql-test/var|_output_directory'
