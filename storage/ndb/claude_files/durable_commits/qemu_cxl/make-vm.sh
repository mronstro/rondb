#!/bin/bash
# RONDB-1150 Q1: build the QEMU CXL Type 3 test VM, without root, on a Rocky
# or RHEL 9 x86_64 host (see ../qemu_cxl_test.md). It downloads the QEMU,
# virtiofsd and firmware RPMs with "dnf download" and unpacks them under
# $VM_DIR/qemu, downloads the Rocky 9 cloud image, writes a cloud-init seed,
# and boots once with KVM to provision the guest: kernel-ml from elrepo, the
# CXL modules rebuilt with CONFIG_CXL_REGION_INVALIDATION_TEST, cxl-cli,
# ndctl, xfsprogs and what MTR needs. The guest powers off when it is done.
#
#   SHARE_DIR=/path/above/the/source/tree ./make-vm.sh
#
# Settings (environment):
#   SHARE_DIR   directory shared with the guest at the same path (required);
#               it must hold the source tree and the build directory
#   VM_DIR      where the VM lives (default /var/tmp/cxlvm), about 10 GB
#   SSH_PORT    host port forwarded to the guest's ssh (default 2222)
#   SEED_PORT   host port of the cloud-init seed server (default 8787)
#   ROCKY_IMAGE a local copy of the Rocky 9 GenericCloud qcow2 (optional)
set -euo pipefail
: "${SHARE_DIR:?set SHARE_DIR to the directory to share with the guest}"
VM_DIR=${VM_DIR:-/var/tmp/cxlvm}
SSH_PORT=${SSH_PORT:-2222}
SEED_PORT=${SEED_PORT:-8787}
HERE=$(cd "$(dirname "$0")" && pwd)
IMAGE_URL=https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2
USER_NAME=$(id -un); USER_UID=$(id -u)

mkdir -p "$VM_DIR"/{rpms,qemu,seed,bin}
cd "$VM_DIR"

echo "== QEMU, virtiofsd and firmware from the distribution's RPMs"
RPMS="qemu-kvm-core qemu-kvm-common qemu-img virtiofsd capstone libpmem
      libslirp liburing ndctl-libs daxctl-libs cxl-libs seabios-bin
      seavgabios-bin ipxe-roms-qemu"
(cd rpms && dnf -q download --arch=x86_64,noarch $RPMS)
for f in rpms/*.rpm; do (cd qemu && rpm2cpio "../$f" | cpio -idmu --quiet); done
export LD_LIBRARY_PATH=$VM_DIR/qemu/usr/lib64
qemu/usr/libexec/qemu-kvm --version | head -1
if ! qemu/usr/libexec/qemu-kvm -device help 2>/dev/null | grep -q '"cxl-type3"'; then
  echo "this QEMU has no cxl-type3 device" >&2; exit 1
fi

echo "== guest disk"
if [ ! -f rocky9.qcow2 ]; then
  if [ -n "${ROCKY_IMAGE:-}" ]; then cp "$ROCKY_IMAGE" rocky9.qcow2
  else curl -sSfL -o rocky9.qcow2 "$IMAGE_URL"; fi
fi
rm -f guest.qcow2
qemu/usr/bin/qemu-img create -q -f qcow2 -b "$VM_DIR/rocky9.qcow2" -F qcow2 guest.qcow2 30G

echo "== CXL persistent memory and label storage backing files (sparse)"
rm -f cxl-pmem0.raw cxl-lsa0.raw
truncate -s 4G cxl-pmem0.raw
truncate -s 256M cxl-lsa0.raw

echo "== ssh key for the guest only"
[ -f id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f id_ed25519 -C cxlvm
rm -f known_hosts

echo "== cloud-init seed"
cp "$HERE/run-vm.sh" "$HERE/vm-ssh.sh" bin/
chmod +x bin/*.sh
cat > seed/meta-data <<EOF
instance-id: cxlvm-$(date +%s)
local-hostname: cxlvm
EOF
cat > seed/user-data <<EOF
#cloud-config
users:
  - name: $USER_NAME
    uid: $USER_UID
    groups: wheel
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: [ "$(cat id_ed25519.pub)" ]
growpart: { mode: auto, devices: ['/'] }
mounts:
  - [ share, "$SHARE_DIR", virtiofs, "nofail", "0", "0" ]
write_files:
  - path: /usr/local/sbin/cxl-modules.sh
    permissions: '0755'
    encoding: b64
    content: $(base64 -w0 "$HERE/cxl-modules.sh")
runcmd:
  - dnf install -y https://www.elrepo.org/elrepo-release-9.el9.elrepo.noarch.rpm
  - dnf --enablerepo=elrepo-kernel install -y kernel-ml kernel-ml-devel
  - dnf install -y cxl-cli ndctl xfsprogs numactl numactl-libs libaio perl perl-JSON perl-Time-HiRes bzip2 nftables gdb gcc make elfutils-libelf-devel bc flex bison xz tar
  - /usr/local/sbin/cxl-modules.sh > /var/log/cxl-modules.log 2>&1
  - grubby --set-default=\$(ls -t /boot/vmlinuz-*elrepo* | head -1)
  - grubby --update-kernel=ALL --args="console=ttyS0"
  - mkdir -p /mnt/pmem0 && chown $USER_NAME:$USER_NAME /home/$USER_NAME
  - touch /var/tmp/cloud-init-done
  - poweroff
EOF

echo "== first boot with KVM: provisioning, the guest powers off when done (a few minutes)"
(cd seed && exec python3 -m http.server "$SEED_PORT" --bind 127.0.0.1 > ../seed-http.log 2>&1) &
SEED_PID=$!
trap 'kill $SEED_PID 2>/dev/null' EXIT
SEED_PORT=$SEED_PORT SSH_PORT=$SSH_PORT VM_DIR=$VM_DIR SHARE_DIR=$SHARE_DIR \
  bin/run-vm.sh kvm < /dev/null > provision.log 2>&1 || true
# The poweroff at the end of runcmd makes cloud-init log a SIGTERM error.
if grep -a 'cloud-init\|Kernel panic' provision.log | grep -iE 'error|failed|panic' |
     grep -vqE 'SIGTERM|modules-final'; then
  echo "provisioning reported errors, see $VM_DIR/provision.log" >&2
fi
grep -a 'reboot: Power down' provision.log >/dev/null || { echo "the guest did not power off cleanly, see $VM_DIR/provision.log" >&2; exit 1; }
echo "== done; next: $VM_DIR/bin/run-vm.sh tcg (see qemu_cxl_test.md)"
