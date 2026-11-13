#!/bin/bash
# Guest, as the user, after setup-region.sh: probe.sh <build directory>
# The MAP_SYNC probe (statx attribute 0x200000 = STATX_ATTR_DAX), then the
# phase 2 tests on the mount.
set -x
BLD=${1:?usage: probe.sh <build directory>}
grep -o -w -E 'avx2|clwb|clflushopt' /proc/cpuinfo | sort | uniq -c
rm -f /mnt/pmem0/probe
xfs_io -f -c "truncate 4m" -c "mmap -S -rw 0 4m" -c "mwrite -S 0x5a 0 4096" \
  -c "msync -s 0 4096" -c "statx -r" /mnt/pmem0/probe | grep -E 'attributes ='
echo "xfs_io rc=${PIPESTATUS[0]}"
rm -f /mnt/pmem0/probe
NDB_PMEM_DIR=/mnt/pmem0 "$BLD/runtime_output_directory/ndb_pmem-t" | tail -3; echo "ndb_pmem-t rc=${PIPESTATUS[0]}"
NDB_PMEM_DIR=/mnt/pmem0 "$BLD/runtime_output_directory/ndb_pmem_region-t"; echo "ndb_pmem_region-t rc=$?"
