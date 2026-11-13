#!/bin/bash
# RONDB-1150 Q1: start the CXL test VM made by make-vm.sh.
#   SHARE_DIR=/path/above/the/source/tree ./run-vm.sh tcg   # the tests
#   SHARE_DIR=... ./run-vm.sh kvm                           # set-up only
# KVM stops the guest ("KVM internal error ... emulation failure") at the
# first clwb to the CXL memory, which QEMU emulates as MMIO: the guest kernel
# runs clwb at msync on a DAX file, and ndb_pmem does at every persist. TCG
# with -cpu max has AVX2, CLWB and CLFLUSHOPT. Serial console on stdout;
# ssh with vm-ssh.sh. The guest's state of the CXL decoders is lost only by
# stopping QEMU (a reboot of the guest keeps it), so after a failed
# "cxl create-region" power the guest off and start it again.
VM_DIR=${VM_DIR:-/var/tmp/cxlvm}
: "${SHARE_DIR:?set SHARE_DIR to the directory shared with the guest}"
SSH_PORT=${SSH_PORT:-2222}
SEED_PORT=${SEED_PORT:-8787}
SMP=${SMP:-8}
MEM=${MEM:-8G}
export LD_LIBRARY_PATH=$VM_DIR/qemu/usr/lib64
case "${1:-tcg}" in
  tcg) ACCEL="-accel tcg,thread=multi -cpu max" ;;
  kvm) ACCEL="-enable-kvm -cpu host" ;;
  *) echo "usage: $0 tcg|kvm" >&2; exit 2 ;;
esac
SOCK=$VM_DIR/virtiofs.sock; rm -f "$SOCK"
# RHEL's QEMU has no 9p, so the tree is shared with virtiofs; virtiofsd
# runs unprivileged with --sandbox=none, and the guest RAM must be shared.
"$VM_DIR/qemu/usr/libexec/virtiofsd" --socket-path="$SOCK" --shared-dir="$SHARE_DIR" \
  --sandbox=none --cache=auto --inode-file-handles=never > "$VM_DIR/virtiofsd.log" 2>&1 &
VPID=$!
for i in $(seq 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
# Devices without bus= would go on the pxb-cxl bus, which takes only
# bridges, so every virtio device names pcie.0. cxl-type3 needs sn=, or
# cxl_pmem refuses the nd region ("invalid or missing serial number").
"$VM_DIR/qemu/usr/libexec/qemu-kvm" \
  -L "$VM_DIR/qemu/usr/share/qemu-kvm" -L "$VM_DIR/qemu/usr/share/seabios" \
  -L "$VM_DIR/qemu/usr/share/seavgabios" -L "$VM_DIR/qemu/usr/share/ipxe" \
  -machine q35,cxl=on $ACCEL -smp "$SMP" -m "$MEM",maxmem=16G,slots=4 \
  -nographic -serial mon:stdio \
  -object memory-backend-memfd,id=ram0,size="$MEM",share=on -numa node,memdev=ram0 \
  -drive file="$VM_DIR/guest.qcow2",if=none,id=d0 -device virtio-blk-pci,drive=d0,bus=pcie.0 \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22 -device virtio-net-pci,netdev=n0,bus=pcie.0 \
  -chardev socket,id=vfs0,path="$SOCK" -device vhost-user-fs-pci,chardev=vfs0,tag=share,bus=pcie.0 \
  -smbios type=1,serial=ds=nocloud\;s=http://10.0.2.2:"$SEED_PORT"/ \
  -object memory-backend-file,id=cxl-pmem0,share=on,mem-path="$VM_DIR/cxl-pmem0.raw",size=4G \
  -object memory-backend-file,id=cxl-lsa0,share=on,mem-path="$VM_DIR/cxl-lsa0.raw",size=256M \
  -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxl.1 \
  -device cxl-rp,port=0,bus=cxl.1,id=root_port13,chassis=0,slot=2 \
  -device cxl-type3,bus=root_port13,persistent-memdev=cxl-pmem0,lsa=cxl-lsa0,sn=0x1,id=cxl-pmem0 \
  -M cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=4G
RC=$?
kill $VPID 2>/dev/null
exit $RC
