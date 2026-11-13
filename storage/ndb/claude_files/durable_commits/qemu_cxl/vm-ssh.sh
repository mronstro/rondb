#!/bin/bash
# ssh into the CXL test VM: vm-ssh.sh [command...]
VM_DIR=${VM_DIR:-/var/tmp/cxlvm}
exec ssh -i "$VM_DIR/id_ed25519" -p "${SSH_PORT:-2222}" -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile="$VM_DIR/known_hosts" -o ConnectTimeout=10 "$(id -un)@127.0.0.1" "$@"
