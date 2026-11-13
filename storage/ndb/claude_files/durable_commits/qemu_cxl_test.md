# RONDB-1150 Q1: the PMEM REDO log on QEMU's emulated CXL Type 3 memory

Test Q1 of the step-1 test plan (`impl_step1_recovery_test.md` §4.1, §4.4,
§4.5) was run on 2026-11-13 on a Rocky Linux 9.8 x86_64 host (kernel 6.11,
32 CPUs, 62 GB), without root, in QEMU 10.1 (the Rocky 9 `qemu-kvm` build)
with a Rocky 9 guest on elrepo `kernel-ml` 7.3.4. The build was a debug
build of `f381b91e9f8`. This file has the result, the defects it found, the
corrections to the plan, and how to run MTR tests on the emulated device.
The scripts are in `qemu_cxl/`.

## 1. Result

| Step | Result |
|---|---|
| Region set-up | `cxl create-region -m -t pmem -d decoder0.0 -w 1 mem0`, `ndctl create-namespace -m fsdax`: `/dev/pmem0`, 3.94 GiB |
| `persistence_domain` | `memory_controller` |
| Region `numa_node` / `target_node` | 0 / 1 (the guest has one NUMA node; node 1 is the CXL window's proximity domain, not online) |
| Dirty-shutdown count | Not exposed. QEMU rejects Set Shutdown State (`cxl_nvdimm pmem0: GPF: could not set dirty shutdown state`), so the kernel hides `nmem0/cxl/dirty_shutdown` |
| Bad blocks | none |
| `xfs_io` MAP_SYNC probe on `/mnt/pmem0` (XFS, `dax=always`) | `mmap -S` maps; write + `msync` work under TCG; `statx` attributes `0x200000` (STATX_ATTR_DAX) |
| `NDB_PMEM_DIR=/mnt/pmem0 ndb_pmem-t` | pass: `map with MAP_SYNC required in /mnt/pmem0: mapped`; all five copy methods tested; auto chooses `ntstore-avx` |
| `NDB_PMEM_DIR=/mnt/pmem0 ndb_pmem_region-t` | pass: `device 'pmem0', domain memory_controller, numa node 0, target node 1, dirty shutdown -1, bad ranges 0, not stacked, DAX inode yes, region '/sys/devices/platform/ACPI0017:00/root0/nvdimm-bridge0/ndbus0/region0'` |
| `ndb.ndb_redo_pmem_ledger` (`GciLedgerTornTail -l 2 T1`), test mode off | pass, 293 s |
| `ndb.ndb_redo_pmem_restart` (SR and NR from the mappings), test mode off | pass, 352 s |

The verdict line of each data node, the same at every start, including the
restarts:

```
RedoLogMode=pmem: FileSystemPathRedoLog /mnt/pmem0/mtr/var/mysql_cluster.1/ndbd.1: device pmem0,
region /sys/devices/platform/ACPI0017:00/root0/nvdimm-bridge0/ndbus0/region0,
persistence domain memory_controller, NUMA node 0, dirty-shutdown count not exposed,
0 bad-block ranges
```

and `RedoLogMode=pmem: REDO log copied to persistent memory with
ntstore-avx, __RedoLogPmemTestMode=off`. The generated `my.cnf` had
`__RedoLogPmemTestMode=off` in `[cluster_config.1]`.

## 2. Defects found in the tree

Fixed by the commit "RONDB-1150: CXL dirty-shutdown count in cxl/, the DAX
test mode in [cluster_config.1], pmem_redo_cxl.cnf".

**D1. `pmem_redo_dax.cnf` did not reach the PMEM tests.** It set
`__RedoLogPmemTestMode=emulated` in `[cluster_config]`. The `.cnf` of the
PMEM tests (`ndb_redo_pmem_ledger.cnf`, `ndb_redo_pmem_restart.cnf` and the
others with `RedoLogMode=pmem`) set `__RedoLogPmemTestMode=nodax` in
`[cluster_config.1]`, which wins. So with `pmem_redo_dax.cnf` those tests
ran in nodax mode: ordinary mappings without `MAP_SYNC` and no DAX or
region checks, although the REDO files were on the DAX mount. MTR appends
the `--defaults-extra-file` after the test's `.cnf` (`ConfigFactory.pm`,
`$config->append`), and `My::Config::insert` replaces an option that is
already in the group, so the fix sets the test mode in
`[cluster_config.1]` as well. The 16 `ndb_redo_pmem_*` tests whose `.cnf`
sets `nodax` did not check the DAX path when run with
`pmem_redo_dax.cnf` before the fix, whatever their result; the other ndb
tests did (their `.cnf` has no test mode).

`ndb_redo_pmem_paths` needs `nodax`: its REDO log is in `BackupDataDir`,
off the DAX mount, and its `.result` prints the test mode. It now skips
itself when `MTR_NDB_PMEM_DIR` is set. Of the 16, only
`ndb_redo_pmem_ledger` and `ndb_redo_pmem_restart` have run with the DAX
checks (on CXL, test mode off); the others still have to be run with
`pmem_redo_dax.cnf` or `pmem_redo_cxl.cnf`.

**D2. The CXL dirty-shutdown count was looked for in the wrong place.**
`region_dirty_shutdown()` in `ndb_pmem_region.cpp` tried
`nmemX/nfit/dirty_shutdown`, `nmemX/papr/dirty_shutdown` and
`nmemX/dirty_shutdown`. The kernel's `cxl_pmem` (Linux 6.15 and later;
read in 7.3.4 `drivers/cxl/pmem.c`) shows it as
`nmemX/cxl/dirty_shutdown`, in the attribute group `cxl` next to `id` and
`provider`. On real CXL memory the node would have said "dirty-shutdown
count not exposed" although the kernel shows it. The fix adds
`cxl/dirty_shutdown` to the list and a fixture to `ndb_pmem_region-t`. The
kernel shows the file only when the device accepted Set Shutdown State, has
a GPF DVSEC and returns the count in Get Health Info; QEMU's device does
not, so Q1 cannot test it (§3).

New: `mysql-test/suite/ndb/pmem_redo_cxl.cnf`, `RedoLogMode=pmem` with
`__RedoLogPmemTestMode=off` in both sections, for a region with a
persistence domain.

## 3. Corrections to the plan

- **§4.1 row Q1.** "`persistence_domain` = `memory_controller` gives the
  ADR barrier mode": the code has no barrier mode to select. The domain
  goes only into `redo_pmem_path_verdict` (`RedoLogPaths.cpp`), which
  refuses an empty domain unless the test mode is `emulated`; the copy
  always writes back and fences, which is what ADR needs. What Q1 shows is
  that the CXL region is accepted with the test mode off and the REDO log
  runs on it with `ntstore-avx`. The ledger case run was
  `GciLedgerTornTail -l 2` (MTR `ndb_redo_pmem_ledger`), not
  `GciLedgerSR -l 3`.
- **§4.1 row Q1, E20.** The region's `numa_node` was 0 and every LDM on
  node 0, so the E20 placement warning was not exercised. A test of E20
  needs a guest with two NUMA nodes and the CXL window on the other one.
- **§4.4.** The command was missing `bus=pcie.0` on the virtio devices and
  `sn=` on `cxl-type3`, and needs TCG, not KVM (§4). The property names
  (`persistent-memdev`, `lsa`, `cxl-fmw.0.targets.0`, `cxl-fmw.0.size`)
  are right for QEMU 10.1. The guest kernel needs
  `CONFIG_CXL_REGION_INVALIDATION_TEST`, which no distribution kernel sets.
- **§4.5, the QEMU CXL row, "does not prove":** also the dirty-shutdown
  count (QEMU rejects Set Shutdown State), and the cache invalidation at
  region commit (bypassed by `CONFIG_CXL_REGION_INVALIDATION_TEST`, only
  with that option).
- **Platform plan S1.4 item 6:** CXL is `nmemX/cxl/dirty_shutdown` (D2).

## 4. Pitfalls of the emulation (not RonDB defects)

1. **KVM stops on `clwb` to CXL memory.** QEMU emulates CXL Type 3 memory
   as MMIO, so every access traps, and KVM's instruction emulator cannot
   do `clwb`: `KVM internal error. Suberror: 1 ... emulation failure` with
   `66 0f ae 37` (`clwb [rdi]`) at RIP, at CPL 0, in the guest kernel's
   DAX write-back at `msync`. RonDB's own `clwb` and probably its
   non-temporal stores would do the same. TCG (`-accel tcg -cpu max`) has
   AVX2, CLWB and CLFLUSHOPT and runs everything, more slowly.
2. **No region in a VM without `CONFIG_CXL_REGION_INVALIDATION_TEST`.**
   Committing a region needs `cpu_cache_invalidate_memregion()`, which
   x86 refuses under a hypervisor: `cxl region0: Failed to synchronize CPU
   cache state` and `failed to commit decode: No such device or address`.
   `qemu_cxl/cxl-modules.sh` rebuilds `drivers/cxl` of the guest's kernel
   with the option and installs it in `updates/`; the kernel then logs
   `Bypassing cpu_cache_invalidate_memregion() for testing!`.
3. **A failed commit leaves decoder state** in QEMU's device that a guest
   reboot keeps (`Range register decodes outside platform defined CXL
   ranges`, `endpoint2 failed probe`). Power the guest off and start QEMU
   again.
4. **`cxl-type3` needs `sn=`.** Without a serial number `cxl_pmem` refuses
   the nd region (`mem0: invalid or missing serial number`) and no
   `/dev/pmem0` appears.
5. **Devices without `bus=` go on the pxb-cxl bus** and QEMU stops: `PCI:
   Only PCI/PCIe bridges can be plugged into pxb-cxl`.
6. **RHEL's QEMU has no 9p** (`'virtio-9p-pci' is not a valid device model
   name`): share the tree with virtiofs. `virtiofsd --sandbox=none` runs
   unprivileged; the guest RAM must be `memory-backend-memfd,share=on`
   with `-numa node,memdev=`.
7. **Executing large binaries from virtiofs failed** (guest kernel 7.3.4,
   TCG): `mysqld` and `ndbmtd` died with SIGSEGV before `main`, in `_init`
   of `libabsl_base.so`, with garbage at RIP. `md5sum` through the share
   was right, and the same binary ran after a `read()` of it had filled the
   page cache, and crashed again after `drop_caches`; read-ahead 0 did not
   help. So the pages that exec faults in through virtiofs are wrong. Not
   investigated further; `setup-region.sh` bind-mounts guest-local copies
   of the build's output directories at the same paths. Whether it happens
   under KVM is not known.
8. **MTR's vardir.** MTR's Unix sockets cannot be on virtiofs, and
   `--vardir` elsewhere deletes `<build>/mysql-test/var` on the share,
   which is the host's. `setup-region.sh` bind-mounts a guest-local
   directory over `var` instead; MTR then warns `Couldn't remove directory
   ... var: Device or resource busy` and goes on.
9. **The namespace survives a restart** in the label storage area: after
   `cxl create-region` on the next start, `/dev/pmem0` comes back with its
   file system, and `ndctl create-namespace` would fail with `No space
   left on device`. `setup-region.sh` waits for it.
10. **Speed under TCG.** Booting takes a few minutes, `mysqld` start more
    than 60 s (MTR warns `Waited 60 seconds for ... pid`), the two Q1
    tests 11 min, the whole run 22 min. `run-mtr.sh` raises the
    timeouts.

## 5. Running MTR tests on the emulated device

Requirements: a Rocky or RHEL 9 x86_64 host with `dnf`, KVM for the
provisioning boot (`/dev/kvm` readable), 8 GB of RAM and about 25 GB in
`/var/tmp` for the VM, internet access, and a build of the tree on the host
(debug build used here). The guest runs the host's binaries, so the host
and the guest must have the same glibc: use Rocky 9 or RHEL 9 on the host.
No root on the host. On another distribution, use a QEMU 8 or later that
has the `cxl-type3` device and adapt `make-vm.sh`.

`SHARE_DIR` is a directory that holds the source tree and the build
directory; the guest mounts it at the same path. Below, `$SRC` is the
source tree, `$BLD` the build directory, `Q=$SRC/storage/ndb/claude_files/durable_commits/qemu_cxl`.

1. **Make the VM** (once; downloads about 1 GB, about 10 minutes):
   ```
   SHARE_DIR=/path/above/the/tree $Q/make-vm.sh
   ```
   The VM is in `/var/tmp/cxlvm` (`VM_DIR`); ssh goes to port 2222
   (`SSH_PORT`). It ends with the guest powered off. If `VM_DIR` or
   `SSH_PORT` is not the default, export it for `run-vm.sh` and
   `vm-ssh.sh` too. `/var/log/cxl-modules.log` in the guest has the
   module build.
2. **Start it under TCG** in a terminal of its own (serial console there;
   log in with ssh):
   ```
   SHARE_DIR=/path/above/the/tree /var/tmp/cxlvm/bin/run-vm.sh tcg
   ```
   Wait until `/var/tmp/cxlvm/bin/vm-ssh.sh true` works (a few minutes).
3. **Set up the region, the mount and the bind mounts** (after every start
   of QEMU):
   ```
   /var/tmp/cxlvm/bin/vm-ssh.sh sudo $Q/setup-region.sh $BLD
   ```
   Check `persistence_domain=[memory_controller]` and `dax=always`. If
   `cxl create-region` fails, stop the guest (`vm-ssh.sh sudo poweroff`),
   start QEMU again and repeat.
4. **Probe** (MAP_SYNC, `ndb_pmem-t`, `ndb_pmem_region-t`):
   ```
   /var/tmp/cxlvm/bin/vm-ssh.sh $Q/probe.sh $BLD
   ```
   Expect `attributes = 0x200000`, `xfs_io rc=0` and both tests `rc=0`.
5. **Run MTR** (default: the two Q1 tests; other tests as arguments):
   ```
   /var/tmp/cxlvm/bin/vm-ssh.sh $Q/run-mtr.sh $BLD
   /var/tmp/cxlvm/bin/vm-ssh.sh $Q/run-mtr.sh $BLD ndb.ndb_redo_pmem_gcp_save
   ```
   It uses `suite/ndb/pmem_redo_cxl.cnf` with
   `MTR_NDB_PMEM_DIR=/mnt/pmem0/mtr`, writes the log to
   `$BLD/mysql-test/mtr-cxl.log` (on the share), and prints the effective
   test mode and the data nodes' verdict lines. For a long run, start it
   inside `tmux` or with `nohup` in the guest. The test artefacts are in
   the guest's `/var/tmp/mtrvar` (= `$BLD/mysql-test/var` in the guest);
   copy what you need onto the share before the next run. With 4 GB of
   CXL memory, `--parallel=2` fits for the ledger configuration (5 files
   × 4 MB × 4 parts per node); the ndb suite with `pmem_redo.cnf` sizes
   needs 1 GB per worker (§4.3 of the test plan).
6. **After a rebuild on the host**, the guest's copies of the binaries are
   stale. Remove them and repeat step 3:
   ```
   /var/tmp/cxlvm/bin/vm-ssh.sh "sudo umount $BLD/runtime_output_directory $BLD/library_output_directory $BLD/plugin_output_directory; sudo rm -rf /var/tmp/bincopy"
   ```
7. **Stop:** `vm-ssh.sh sudo poweroff`. The CXL contents stay in
   `/var/tmp/cxlvm/cxl-pmem0.raw`. Delete `/var/tmp/cxlvm` to remove
   everything.
