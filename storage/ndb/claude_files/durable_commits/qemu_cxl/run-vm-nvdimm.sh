#!/bin/bash
# RONDB-1150: start the VM made by make-vm.sh with an emulated NVDIMM
# instead of the CXL device, under KVM, for MTR suites with the REDO log
# on fsdax (dax=always) at near-native speed:
#   SHARE_DIR=/path/above/the/source/tree ./run-vm-nvdimm.sh   # own terminal
# then setup-nvdimm.sh in the guest. The NVDIMM is guest RAM backed by a
# file (on /dev/shm by default), so the CPU's clwb runs natively; the CXL
# device is emulated MMIO, on which KVM stops at the first clwb.
# nvdimm-persistence=mem-ctrl makes the NFIT report the memory-controller
# persistence domain (ADR), so __RedoLogPmemTestMode=off is accepted.
# The same VM_DIR as run-vm.sh, so not both at once; for a copy beside the
# CXL VM, set VM_DIR and SSH_PORT (and export them for vm-ssh.sh).
# Host RAM: MEM + PMEM_SIZE. The ndb suite fits but for 8 tests in the
# defaults; MEM=24G PMEM_SIZE=16G runs them all (ndb_suite_nvdimm.md).
VM_DIR=${VM_DIR:-/var/tmp/cxlvm}
: "${SHARE_DIR:?set SHARE_DIR to the directory shared with the guest}"
SSH_PORT=${SSH_PORT:-2222}
SMP=${SMP:-8}
MEM=${MEM:-12G}
PMEM_SIZE=${PMEM_SIZE:-8G}
PMEM_FILE=${PMEM_FILE:-/dev/shm/$(basename "$VM_DIR")-nvdimm0.raw}
MAXMEM=${MAXMEM:-$(( ${MEM%G} + ${PMEM_SIZE%G} ))G}
export LD_LIBRARY_PATH=$VM_DIR/qemu/usr/lib64
# RHEL's QEMU has no 9p: virtiofs, unprivileged, with shared guest RAM
SOCK=$VM_DIR/virtiofs.sock; rm -f "$SOCK"
"$VM_DIR/qemu/usr/libexec/virtiofsd" --socket-path="$SOCK" --shared-dir="$SHARE_DIR" \
  --sandbox=none --cache=auto --inode-file-handles=never > "$VM_DIR/virtiofsd.log" 2>&1 &
VPID=$!
for i in $(seq 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
"$VM_DIR/qemu/usr/libexec/qemu-kvm" \
  -L "$VM_DIR/qemu/usr/share/qemu-kvm" -L "$VM_DIR/qemu/usr/share/seabios" \
  -L "$VM_DIR/qemu/usr/share/seavgabios" -L "$VM_DIR/qemu/usr/share/ipxe" \
  -machine q35,nvdimm=on,nvdimm-persistence=mem-ctrl -enable-kvm -cpu host \
  -smp "$SMP" -m "$MEM",maxmem="$MAXMEM",slots=4 \
  -nographic -serial mon:stdio \
  -object memory-backend-memfd,id=ram0,size="$MEM",share=on -numa node,memdev=ram0 \
  -drive file="$VM_DIR/guest.qcow2",if=none,id=d0 -device virtio-blk-pci,drive=d0 \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22 -device virtio-net-pci,netdev=n0 \
  -chardev socket,id=vfs0,path="$SOCK" -device vhost-user-fs-pci,chardev=vfs0,tag=share \
  -object memory-backend-file,id=pmem0,share=on,mem-path="$PMEM_FILE",size="$PMEM_SIZE" \
  -device nvdimm,id=nvdimm0,memdev=pmem0
RC=$?
kill $VPID 2>/dev/null
exit $RC
