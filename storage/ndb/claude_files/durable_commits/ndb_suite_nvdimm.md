# RONDB-1150: the ndb suite with the REDO log on emulated PMEM (NVDIMM, KVM)

Run on 2026-11-14 on a Rocky Linux 9.8 x86_64 host (32 CPUs, 62 GB), in
the VM of `qemu_cxl_test.md` §6: QEMU `-device nvdimm`, 8 GB backed by
`/dev/shm`, `nvdimm-persistence=mem-ctrl`, KVM, 8 vCPUs, 12 GB RAM, guest
kernel 7.3.4. fsdax namespace of 7.87 GB, XFS `dax=always` on
`/mnt/pmem0`. Debug build of `f381b91e9f8`, without the commits after it.

Mode: `RedoLogMode=pmem` with the production checks
(`__RedoLogPmemTestMode=off`: region, persistence domain
`memory_controller`, `MAP_SYNC`), `MTR_NDB_PMEM_DIR=/mnt/pmem0/mtr`,
`--defaults-extra-file` = `suite/ndb/pmem_redo_cxl.cnf`, `--parallel=1
--retry=0`. Without `--skip-test-list` by mistake, so the tests of
`pmem_redo.skip` ran too.

## Totals

| | passed | failed | skipped |
|---|---|---|---|
| part 1 (stopped at 88% by `rdrs2`, see below) | 371 | 29 | 10 |
| part 2 (the 38 tests not yet run) | 30 | 3 | 5 |
| total | 401 | 32 | 15 |

Not run: the 14 tests of `collections/disabled_ndb.def`, and
`ndb_setup_ronsql` (needs 16 GB of RAM; it made `rdrs2` abort and MTR stop).
No failure points at the PMEM REDO code: every `ndb_redo_pmem_*` test that
runs on DAX passed but for the two test defects below.

## Failures

Rerun one test in the VM:
`vm-ssh.sh $Q/run-mtr.sh $BLD --skip-test-list=suite/ndb/pmem_redo.skip ndb.<test>`.

| test | cause | class, state |
|---|---|---|
| `ndb_encrypted_filesystem_dd_disk2memory`, `_dd_initial_lg`, `_dd_restart`, `_fragmented_redo_log_buffer`, `ndb_secretsfile2`, `ndb_secretsfile_reader` | `RedoLogMode=pmem cannot be used with EncryptedFileSystem=1` | in `pmem_redo.skip`, expected |
| `ndb_blob_big` | `Diskless=1` | in `pmem_redo.skip`, expected |
| `ndb_fragmented_redo_log_buffer` | no REDO buffer in PMEM mode | in `pmem_redo.skip`, expected |
| `ndb_redo_file_change_hold`, `ndb_redo_late_file_open` | file switch of file mode | in `pmem_redo.skip`, expected |
| `ndb_redo_log_reader` | file-mode format, `EncryptedFileSystem` | in `pmem_redo.skip`, expected |
| `ndb_redo_paths_file_mode` | `FileSystemPathRedoLog` in file mode | in `pmem_redo.skip`, expected |
| `testNodeRestartGcpSaveAndFileChange` | error insert 5114 delays a file-mode write | in `pmem_redo.skip`, expected |
| `ndb_arbitration_president_failover`, `ndb_arbitration_rank_wait`, `ndb_config_change_rdrs`, `ndb_rolling_restart_mgmd_first` | M1 below: `Parameter __RedoLogPmemTestMode specified twice`, `ndb_mgmd` exits at its restart with `--config-change` | MTR defect, fixed |
| `ndb_activate_before_qmgr_phase1`, `ndb_add_partition`, `ndb_many_fragments`, and `large_txn_non_mt` in part | M2 below: the PMEM mount full of earlier tests' REDO files (error 2810) | MTR defect, fixed |
| `large_txn`, `large_txn_non_mt`, `ndb_restore_indexbuild` | `NoOfFragmentLogFiles=16`, 2 × 4 GB > 7.87 GB | VM too small: `PMEM_SIZE=16G` |
| `ndb_fully_replicated_addnode`, `ndb_fragment_count_addnode` | 8 data nodes × 1 GB of REDO | VM too small: `PMEM_SIZE=16G` |
| `ndb_mt_backup_ldms` | 6 nodes, 56 log parts × 256 MB = 14 GB | VM too small: `PMEM_SIZE=16G` |
| `ndb_print_sys_file` | 9 data nodes, the guest's OOM killer | VM too small: `MEM=24G` |
| `ndb_scan_start_restart` | 8 data nodes: OOM and more than 7.87 GB of REDO | VM too small: `MEM=24G PMEM_SIZE=16G` |
| `ndb_error_reporter` | `bzip2` not in the guest | VM set-up; `make-vm.sh` installs it now |
| `ndbinfo_plans` | M4 below: `ndb$config_values` 414 rows, estimate 402 ± 10 | open |
| `ndb_redo_pmem_paths` | needs `nodax` (its REDO log off the DAX mount); test mode off refuses it | skips itself under `MTR_NDB_PMEM_DIR` since `e7b4ce6eccd` |
| `ndb_redo_pmem_reader` | M3 below: `cannot open` the REDO files | test defect, fixed |

The run stopped once at 88%: `rdrs2` of this build links
`libprometheus-cpp-{core,push}.so.1.3` from the host's `/usr/local/lib64`,
which the guest did not have (exit 127). `setup-nvdimm.sh` now lists such
libraries.

Skipped (15): `ndb_bug13563280` (needs `--log-bin`), `ndb_tctakeover`
(release build), `clusterj` (Connector/J), `ndb_nr_unreachable_node`,
`ndb_sr_unreachable_node`, `ndb_sr_unreachable_node_group` (no `nft` or
`iptables` in the guest; `make-vm.sh` installs `nftables` now, not run
since), and 9 that skip themselves (rdrs, binlog and the like).

In `pmem_redo.skip` but passed here: `ndb_secretsfile1`, `ndbinfo`,
`ndbinfo_backup`. Either the entries are stale or they hold only in
`nodax` mode (`pmem_redo.cnf`); not checked.

Not counted: `ndb_insert` and `ndb_row_count`, disabled (BUG#16021097),
ran because they were named on the command line, and failed.

## Defects

**M1. `generate_ndb_config_ini` repeats keys.** For an `ndb_mgmd` restart
with `--config-change`, MTR writes a `config.ini` from `my.cnf`
(`mysql-test-run.pl`). It put every pair of `[cluster_config]` and of each
`[cluster_config.N]` into `[ndbd default]`, so a key in both came twice,
and `ndb_mgmd` refuses that. With `--mycnf` the later group wins. A key
in both sections is what `pmem_redo_dax.cnf` (since `e7b4ce6eccd`) and
`pmem_redo_cxl.cnf` do with `__RedoLogPmemTestMode`, and what any test
`.cnf` does that overrides a `default_ndbd.cnf` key in
`[cluster_config.1]`. Fix: one pair per key, case-insensitive, the last
value at the place of the first; also for `[api default]` and the node
sections.

**M2. MTR never cleans `MTR_NDB_PMEM_DIR`.** `clean_datadir` removed
`var/mysql_cluster.N` only. The data nodes then start on an empty
`FileSystemPath` without `--initial`, and that initial start does not
clear `FileSystemPathRedoLog` (`Ndbcntr::clearFilesystem` runs only with
`--initial`); the REDO initialisation writes only the files of the new
configuration. So files of earlier tests with more log files, log parts
or data nodes (`ndb_143_fs` and the like) stayed and filled the mount.
Fix: `clean_datadir` removes `$MTR_NDB_PMEM_DIR/<name of the vardir>`, the
directory of the worker that `fix_redo_log_path` fills, every time it
cleans the datadirs, including before the first test. The kernel side,
that an initial start leaves FileSystemPathRedoLog as it is, is the open
point of `step1_phases.md` decision 12.

**M3. `ndb_redo_pmem_reader` looked for the REDO files in the vardir.**
The test and `include/redo_pmem_find_end.inc` used
`$MYSQLTEST_VARDIR/mysql_cluster.1/ndbd.N/ndb_N_fs/D8+/DBLQH`; with
`MTR_NDB_PMEM_DIR` the files are under
`$MTR_NDB_PMEM_DIR/<name of the vardir>/mysql_cluster.1`. Fix: the new
`include/redo_pmem_cluster_dir.inc` sets `$redo_cluster` by the rule of
`fix_redo_log_path` for the test, and the include's perl applies the same
rule; the node logs stay in the vardir. (A `let` of an environment
variable in the sourced file did not reach `--perl`, so the rule is
there twice.)

## The fixes, verified

On the same VM, the build of `f381b91e9f8` (its `mysql-test-run.pl` and
these test files are the same as on the branch head), with
`pmem_redo_cxl.cnf`: `ndb_arbitration_president_failover`,
`ndb_arbitration_rank_wait`, `ndb_config_change_rdrs`,
`ndb_rolling_restart_mgmd_first` (M1), `ndb_redo_pmem_reader` (M3) and
`ndb_add_partition` pass. For M2, directories planted under
`/mnt/pmem0/mtr/var/mysql_cluster.1` (`ndbd.1/ndb_143_fs`, `ndbd.7`) were
gone after the run. `ndb_redo_pmem_reader` also passes without
`MTR_NDB_PMEM_DIR`. Not rerun: the tests too big for the VM, with a
bigger one, and the suite as a whole.

**M4. `ndbinfo_plans` and `FileSystemPathRedoLog` (open).** 207 rows per
data node against the 201 of the estimate in `NdbinfoTables.cpp`: with
the parameters of the DAX configuration, among them
`FileSystemPathRedoLog` (712), which has no default and adds a row only
when set. With 2 data nodes that is 12 rows over the estimate, outside its
tolerance of 10. Which other 5 parameters per node add rows was not
looked at. Choices: raise the estimate (then the file-mode count must
stay within 10 of it), or keep the test off the DAX runs.
