# CLAUDE.md — NDB Storage Engine

## Claude Context Files

Detailed documentation is organized by topic in `claude_files/`. Read the relevant files when working on a specific area.

| Topic | Directory | Description |
|-------|-----------|-------------|
| SET Config Param | `claude_files/set_config_param/` | Adding runtime-settable config parameters via the MGM client SET command |
| Data Node Security | `claude_files/data_node_security/` | Hardening data nodes against malicious NDB protocol messages |
| TTL / Error 899 rowid | `claude_files/ttl_899_rowid/` | TTL "leftover rowid" investigation: purge is replica-safe, but rowid-less ZINSERT_TTL/ZWRITE forwarding silently amplifies replica divergence into permanent 899; test plan + hardening proposal |
| Compiled Interpreter | `claude_files/compiled_interpreter/` | RONDB-1056 copy-and-patch JIT for pushed-down interpreted programs (aggregation + scan filters); start at `STATUS_AND_NEXT_STEPS.md` |
| TTL on Ring Buffer Tables | `claude_files/ttl_ring_buffer/` | Design (`design.md`), user view (`user_view.md`) and test coverage map (`test_plan.md`) of TTL + MAX_ROWS_PER_PK tables: meta row never expires (DBTUP), purge deletes pass the ring guard, deleteOldest rejected (4358), TTL is a creation-time property, version gate |
| QMGR Join Protocol | `claude_files/qmgr_join_protocol/` | Slides (`qmgr_join_protocol.html`, open in a browser) on how a data node gets its node id from ndb_mgmd before it may join, how the QMGR president includes it, signal by signal, the CM_ADD(Abort) of an inclusion that a missing transporter link stalls, and how a node that has not joined may fail without failing the others. `testing.md`: the tests to run and how to set up the firewall for the firewall tests |
| Durable Commits | `claude_files/durable_commits/` | RONDB-1150 plan to make acknowledged commits survive a full cluster crash: durable commits activated online at a GCI, memory-mapped REDO on persistent memory, COMMIT + COMPLETE records with transid, locks held until the COMPLETE record is persistent, SR = normal recovery to the GCP-durable GCI then a hash-table pass that executes a transaction's COMMITs at its COMPLETE and resolves the rest by exchange between REDO log parts (no global ordering needed); start at `durable_commits_plan.md` |

### set_config_param

- `architecture.md` — Signal flow from MGM client through to data node, design notes
- `howto_add_new_param.md` — Step-by-step guide (only 2 files need changes)
- `reference.md` — File locations, what doesn't need changes, verification checklist

### data_node_security

- `tiered_response_policy.md` — Two-tier response policy, full design (v2, FINAL)
- `audit_implementation_guide.md` — Step-by-step for adding new violation sites; API reference and pre-commit checklist
- `monitoring.md` — Prometheus scrape config, Loki/Splunk filters, alerting recommendations
- `fragmented_signal_security.md` — Phase 1 hardening (done) + Phase 2 protocol extension (planned)
- `tckeyreq_security.md` — Historical plan for TCKEYREQ/KEYINFO/ATTRINFO hardening (implemented)

### durable_commits

- `implementation_plan.md` — **Implementation plan** for all phases: order and critical path, milestones M0.1-M7, staffing, step 1 split into pull requests 0-12 with test gates, testing without CI on Linux x86_64, Linux ARM64 and macOS ARM64 (§2.4), conventions (config, CFG ids, symbols, error inserts, DUMP codes, ndbinfo, new signals), points R1-R18 settled between the detail plans, design issues DI-1..DI-9, questions Q-A1..A11 (before step 1; A1-A6 and A11 answered, A4 explained in §5.1) and Q-B1..B13 (before X4/X5)
- `step1_phases.md` — **Step 1 progress**: the 11 implementation phases (one pull request each) and two side tracks, with gates and state; phase 1 (CPU features, `ndb_xxh3` with AVX2 chosen at run time; XXH3 chosen over CRC32C on measured timings), phase 2 (`ndb_pmem` helper, platform queries) phase 3 (`RedoLogMode`, `FileSystemPathRedoLog` and the hidden test settings, CFG ids 711-715, management-server checks, `RedoLogPaths` parser) and phase 4 (4a: NDBFS maps the REDO files with `OM_MAP_SYNC`, address in FSOPENCONF; 4b: REDO files under `FileSystemPathRedoLog` with `OM_REDO_PATH`, lookup across paths, initial-start cleanup, each log part on its LDM's NUMA node, file mode unchanged; 4c start checks) in detail, with the decisions taken while implementing and the commands to run
- `impl_step1_platform.md` — Step 1 S1-S3 work packages: CPU features and XXH3 with AVX2 chosen at run time, `ndb_pmem` helper and device queries, power-loss emulation, config parameters and checks, NUMA placement, ndbinfo `redo_log_pmem`, hidden test modes, NDBFS `OM_MAP_SYNC` mapping and initial start
- `impl_step1_lqh_write.md` — Step 1 S4-S5 work packages: `PmemRedoFormat.hpp`, record writers (one `if (c_redo_pmem)` per writer), reservation, persist primitive and copy-out, mbyte/file switch, GCP_SAVEREQ, bypasses, shared parts, debug send check, DUMP 2368 benchmark switch
- `impl_step1_recovery_test.md` — Step 1 S6-S7 work packages: restart reads from the mapping, `PmemRedoScan`, control area and slots, exact end E, zeroing, `execSr`, node restart, `redoLogReader`, crash error inserts 5155-5172, power-loss emulation, GCP-saved ledger, and the step-1 test plan (unit, MTR, autotest, memmap=, QEMU CXL)
- `impl_next_steps.md` — Work packages for X1 and X3-X8 with file:line: takeover ack, ledger and TLA+, commit path and rule F, restart exchange and G', node-failure file and stale nodes, online activation, adaptive fencing and docs; new signals (GSN 987+), changed signals, milestones, design issues
- `durable_commits_plan.md` — Master plan (rev 12): the study's conclusion (§0), config and online activation at GCI g, invariants C/K/L/A/F, SR phases 1-3 (hash table, exchange between log parts, opCount fallback by node-group counts), node-failure file; stale nodes stay out of the SR and join by node restart, at least one non-stale node per node group; ordering proof, REDO records, subtasks P0-P6, phases X1-X8 (X2 = REDO on PMEM, the first step), decisions D0-D8 (all settled)
- `durable_commits_plan.html` — Illustrated version of the plan for review (open in a browser): commit-protocol swimlane with lock hold, REDO record layouts on PMEM, 64-byte persist units with FILLERs, step-through of SR phase 2 on one log part, the exchange between log parts, node-failure cases (D3, D4), and §10 on the first step (REDO on PMEM: settled decisions, end of log and zeroing at restart, steps S1-S7)
- `pmem_redo_design.md` — **Step 1 design: the REDO log on persistent memory.** Consolidates the four notes below and settles their conflicts: W = 64 B, position-bound XXH3 checksum per record, write-once page headers, FILLER at every persist point, DRAM build + non-temporal copy-out, barrier placement, atomic COMMIT invalidation, two-slot last-file pointer, end of log E and zeroing at restart, start-up checks (decisions E1-E20, implementation steps S1-S7; Q1-Q8 answered: persist before the dependent signal always, one restart scan, W = 64 fixed, unsafe shutdown = stale, encryption refused in v1, no REDO buffer so abort as today, each log part on the closest NUMA memory, target CXL 2.0 PMEM at 200-2000 ns)
- `research_pmem_hardware.md` — PMEM failure atomicity (8-byte only), rewriting partly persisted units, devices available in 2026, clwb/ntstore/sfence costs, MAP_SYNC/DAX detection, persistence_domain, dirty shutdown and bad blocks, PMDK status, CRC32C cost
- `pmem_redo_format.md` — PMEM record framing (type/flags/len word + XXH3 checksum bound to lap and position), write-once page header, every record layout, FILLER and space reservation, overhead for W = 64/128/256, `redoLogReader` changes
- `pmem_redo_recovery.md` — Today's REDO head/tail search traced with file:line, header fields read by recovery, what breaks on PMEM, end-of-log rule, invalidation by zeroing, torn-safe last-file slots, node restart, the durable tail
- `pmem_redo_write_path.md` — PMEM write path: NDBFS maps with MAP_SYNC, redoPersist primitive, barrier placement for COMMIT/COMPLETE/rule F, FILLER cost, shared log parts, mbyte/file switch, GCP_SAVEREQ, what disappears, config and start checks, adaptive scheme outline
- `research_commit_protocol.md` — DBTC/DBLQH commit and complete phases, where locks are released and rows become visible (primary vs backup), READ_BACKUP/TF_LATE_COMMIT, TC takeover, hook points
- `research_redo_log.md` — REDO layout, record formats, write/fsync path, GCP_SAVEREQ flush, tail management, durable-LSN group-commit hook
- `research_system_restart.md` — SR flow, sysfile and restorable GCI, REDO execution and invalidation, node-failure persistence gap, where the agreement phase fits
- `research_micro_gcp.md` — GCP/micro-GCP protocol, consistent-cut proof, GCI storage, durable-epoch variants (rev-1 alternative, not pursued), API side, cost model
- `research_literature.md` — 2PC variants, group commit and early lock release, epoch commit (Silo/COCO), recovery-cut computation in FoundationDB, Aurora, FaRM, CockroachDB, TiDB

### ttl_899_rowid

- `findings.md` — Full audit findings (mechanism verdicts M1-M6, restart scenarios S1-S6, end-to-end 899 interleaving, seed analysis with fixed-bug history, observability, test designs, hardening fix, continuation checklist)
- `repro_test.md` — Natural-window verdict (NR-copy window closed, 3 traces agree) + ttl_nr_copy_window regression test + timing-only ERROR_INSERT 5113
- `probe_tests.md` — Replica-consistency invariant include, 899 detector control test (SQL 1205 + Warning 1297 signature), copy×churn probe results
- `impact_analysis.md` — Always-carry-rowid principle blast radius, per-subsystem impact, failure policy, rollout plan; fully-replicated findings (deferred)
- `normal_insert_analysis.md` — Proof a normal INSERT cannot create the fork; abort-ordering closure; benign transient-899 windows on healthy clusters
- `fix_design.md` — Design of the replica-rowid forwarding + verification fix (error 1245, EI 5118, version gate): decision log, REDO safety proof, NR-copy interplay, mixed-version behavior
- `validation_report.md` — Fix build+test validation (33/33 green, both gate states, zero 1245 false positives); version-gate dormancy caveat; ERROR_codes merge rule
