#!/bin/bash
# Guest, as root, after each start of run-vm-nvdimm.sh:
#   sudo setup-nvdimm.sh <build directory>
# The NVDIMM has no label area, so its namespace is made fsdax (/dev/pmem0)
# the first time (it stays in the backing file); then an XFS on it mounted
# dax=always on /mnt/pmem0, and the bind mounts of setup-region.sh
# (guest-local MTR var, local copies of the build's outputs, as virtiofs
# exec faults are broken in the guest kernel). Prints the region facts
# that the data node's verdict line reports, and the libraries of the
# build that the guest lacks (copy them in, see qemu_cxl_test.md §6).
set -x
BLD=${1:?usage: setup-nvdimm.sh <build directory>}
USER_NAME=$(stat -c %U "$BLD")
ndctl list -N | grep -q '"mode":"fsdax"' ||
  ndctl create-namespace -f -e namespace0.0 -m fsdax || exit 1
ndctl list -RN -u
RD=/sys/bus/nd/devices/region0
echo "persistence_domain=[$(cat $RD/persistence_domain)] numa_node=$(cat $RD/numa_node)"
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
set +x
for f in "$BLD"/runtime_output_directory/*; do
  [ -x "$f" ] && ldd "$f" 2>/dev/null | grep 'not found'
done | sort -u
