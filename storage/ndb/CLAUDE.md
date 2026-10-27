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

- `durable_commits_plan.md` — Master plan (rev 6): the study's conclusion (§0), config and online activation at GCI g, invariants C/K/L/A/F, SR phases 1-3 (hash table, exchange between log parts, opCount fallback by node-group counts), node-failure file; stale nodes stay out of the SR and join by node restart, at least one non-stale node per node group; ordering proof, REDO records, subtasks P0-P6, phases X1-X8, decisions D0-D8 (all settled)
- `durable_commits_plan.html` — Illustrated version of the plan for review (open in a browser): commit-protocol swimlane with lock hold, REDO record layouts, step-through of SR phase 2 on one log part, the exchange between log parts, node-failure cases (D3, D4)
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
