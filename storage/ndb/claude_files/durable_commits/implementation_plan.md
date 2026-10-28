# RONDB-1150 implementation plan

Status: **plan, 2026-10-28. No code has been changed.** This is the
top-level implementation plan for durable commits. It orders the work,
splits step 1 into pull requests, settles where the detail plans differ,
and collects the questions for the architect. All paths are relative to
`storage/ndb/`. Reviews 10 and 11 answered Q-A1–Q-A6 and Q-A11 (§5; Q-A4
is explained in §5.1).

| Document | Content |
|---|---|
| `implementation_plan.md` | This file: order, milestones, pull requests, conventions, reconciled points, open questions |
| `impl_step1_platform.md` | Step 1, S1–S3: portlib (CPU features, CRC32C, PMEM helper, device queries, power-loss emulation), configuration and start-up checks, NDBFS mapping |
| `impl_step1_lqh_write.md` | Step 1, S4–S5: DBLQH record writers, the persist primitive, bypassing the file write path, GCP save, mbyte and file switch, benchmark switch |
| `impl_step1_recovery_test.md` | Step 1, S6–S7: restart reading and end of log, control area, zeroing, node restart, `redoLogReader`, power-loss testing, the test plan for step 1 |
| `impl_next_steps.md` | Steps after step 1: X1 and X3–X8, with new signals, milestones and design issues |
| `durable_commits_plan.md` | The architecture (revision 11) |
| `pmem_redo_design.md` | The design of step 1 (decisions E1–E20, amended in its §6 by this plan) |

Sizes are the detail plans' estimates in person-days (pd). They are rough
and not calibrated against past RonDB work.

---

## 1. Overview

| Phase | Content | Size | Detail |
|---|---|---|---|
| X1 | Takeover ack after COMPLETE (3 places in DBTC). Independent; also fixes READ_BACKUP read-your-writes after takeover today | 4 pd | `impl_next_steps.md` §2 |
| **X2** | **Step 1: the REDO log on PMEM at today's durability** (S1–S7) | **116–122 pd** | §2 below and the three `impl_step1_*` files |
| X3 | Test harness: acknowledged-commit ledger, crash of all nodes, power-loss runs, TLA+ model | 15 pd | `impl_next_steps.md` §3 |
| X4 | Commit path: durable flag, opCount, barriers C and K, primary commit at COMPLETE, late ack, rule F, API node-id hold-back | 50 pd | §4 |
| X5 | Restart: one scan with the hash table, exchange between log parts, verdicts with count fallback, SR_HEAD, raise to G' | 50 pd | §5 |
| X6 | Node failures: node-failure file, stale nodes, at least one non-stale node per node group, partial SR | 17 pd | §6 |
| X7 | Online activation at GCI g, armed after the save of g−1, deactivation by SR, ndbinfo, version gate | 17 pd | §7 |
| X8 | Adaptive fencing, benchmarks, `redoLogReader`, rondb-docs | 32 pd | §8 |
| | **Total** | **≈ 300 pd** | |

**Critical path:** X2 → X3 → X4 → X5 → X6 → X7 → X8 (benchmarks and docs).
X1, the node-failure file (X6.1), the activation plumbing (X7.1–X7.2), the
adaptive scheme (X8.1–X8.2) and the TLA+ model (X3.4) can run in parallel.

**Staffing:**

| People | Step 1 | After step 1 | Total |
|---|---|---|---|
| 1 | about 6 months | about 9 months | about 15 months |
| 2 | about 3.5 months | about 6 months | about 9.5 months |
| 3 | about 2.5 months (one per stream: platform, write side, recovery and tests) | about 5.5 months | about 8 months |

After step 1 the chain X3 → X4 → X5 → X6 → X7 is about 140 pd of the 185.
More people shorten it only if X4 and X5 are themselves split; otherwise
that chain sets the pace. (The next-steps plan's own "about 5 months" for
one person counts only this chain.)

**Milestones:**

| # | After | Demonstrable |
|---|---|---|
| M0.1 | S1, S2 | Portlib and config merged; unit tests pass on Linux x86_64, Linux ARM64 and macOS ARM64; file mode unchanged |
| M0.2 | S3 | PMEM mode maps, places and checks the REDO files with **today's format**; today's SR and NR tests pass in PMEM mode |
| M0.3 | S4–S6 | The new format end to end: initial start, traffic, SR and NR in PMEM mode |
| M0.4 | S7 | Power-loss emulation is part of the tests run before every push of PMEM code (§2.4): no loss at or below R_gcp |
| M1 | X1 | READ_BACKUP read-your-writes after TC takeover |
| M2 | X3 | The ledger measures the loss above R_gcp after a full crash (expected until M4) |
| M3 | X4 | Durable protocol on: rows visible only after COMPLETE is persistent, ack after the last COMPLETED, rule-F aborts; commit latency measured |
| M4 | X5 | **Zero ledger losses after a full crash or power loss with all nodes starting**; repeatable SR |
| M5 | X6 | Zero losses with node failures in the tail GCI and partial SR; a clear refusal when a node group has only stale nodes |
| M6 | X7 | `DurableCommits` activated on a running cluster; armed state in ndbinfo |
| M7 | X8 | Adaptive fencing, benchmark report, user documentation |

---

## 2. Step 1 in detail

### 2.1 Work packages

| Stream | Packages | Size |
|---|---|---|
| **Platform** (`impl_step1_platform.md`) | S1.1 CPU features and the `is_avx2_supported` fix · S1.2 `ndb_crc32c` · S1.3 `ndb_pmem` map, prefault, copy, flush, drain, stubs · S1.4 domain, bad-block, dirty-shutdown and NUMA queries · S1.5 power-loss emulation · S2.1 parameters and path parser · S2.2 management-server checks · S2.3 data-node reads · S2.4 part → NUMA node → path · S2.5 start-time refusals · S2.6 ndbinfo `redo_log_pmem` · S2.7 test settings · S3.1 signal changes · S3.2 map in the IO thread · S3.3 REDO base paths · S3.4 DBLQH open flags · S3.5 initial start · S3.6 every file mapped at SR and NR | 36–42 pd |
| **Write side** (`impl_step1_lqh_write.md`) | S4.1 `PmemRedoFormat.hpp` · S4.2 framing helpers · S4.3 PREPARE · S4.4 COMMIT, ABORT, COMPLETED_GCI, COMPLETE · S4.5 FILLER, NEXT_MBYTE · S4.6 header image and FD · S4.7 reservation · S4.8 initial-start images · S5.1 LSN and fields · S5.2 persist primitive and copy-out · S5.3 mbyte and file switch · S5.4 GCP_SAVEREQ · S5.5 bypasses · S5.6 shared parts · S5.7 debug send check · S5.8 benchmark switch and counters · S5.9 test wiring | 33 pd |
| **Recovery and tests** (`impl_step1_recovery_test.md`) | S6.1 restart reads from the mapping · S6.2 reader module `PmemRedoScan` and unit tests · S6.3 control area and slots · S6.4 phase 1 and exact E · S6.5 `execSr` and `readCommitLog` · S6.6 phase 4 and zeroing · S6.7 node restart · S6.8 `redoLogReader` · S7.1 crash error inserts · S7.2 torn-copy injector · S7.3 power-loss emulation wiring · S7.4 GCP-saved ledger · S7.5 MTR and autotest configs | 47 pd |

**How file mode stays unchanged** (write side, §2.2 of its plan): each
record type gets a separate PMEM writer, entered by one
`if (c_redo_pmem)` line at the top of today's writer. Small branches are
needed only in shared control flow (`checkNewMbyte`, `completedLogPage`,
`writeNextLog`, `start_synch_gcp`, `writeSinglePage`, the reservation). So
the file-mode diff can be checked by reading it.

### 2.2 Order and pull requests

Every pull request leaves file mode bit-identical and passes today's
regression tests in file mode.

| # | Pull request | Packages | Gate (beyond file-mode regression) | Needs |
|---|---|---|---|---|
| 0 | **Bug fix, separate ticket:** `ZMIN_READ_BUFFER_SIZE` 3 → 4 in both modes (R13, Q-A6) | — | A test with PREPARE records of the largest size, then SR, in file mode; the same in PMEM mode once pull request 9 is in | — |
| 1 | GCP-saved ledger checker | S7.4 | Runs in file mode on today's code: no loss at or below R_gcp after a full crash | — |
| 2 | CPU features and CRC32C | S1.1, S1.2 | CRC vector unit tests on the three platforms (§2.4) and the software fallback | — |
| 3 | PMEM helper | S1.3, S1.4 | `ndb_pmem-t` on a plain file on the three platforms, and on `memmap=` | 2 |
| 4 | Configuration | S2.1–S2.3, S2.7 | Config unit tests; management-server refusals | — |
| 5 | NDBFS mapping and placement | S3.1–S3.4, S2.4, S2.5 | PMEM mode with today's format: the MTR ndb suite and a testSystemRestart subset in `nodax` and on `memmap=` (**M0.2**) | 3, 4 |
| 6 | Initial start and restarts with every file mapped; ndbinfo | S3.5, S3.6, S2.6 | Initial start, SR and NR in PMEM mode; ndbinfo rows | 5 |
| 7 | Format and reader module | S4.1, S6.2 | Unit tests over synthetic logs, on the three platforms: framing, every torn, stale-lap and orphan case | 2 |
| 8 | Record writers | S4.2–S4.7, S5.1 | Unit tests; file-mode regression | 7 |
| 9 | **PMEM REDO end to end** | S4.8, S5.2–S5.5, S6.1, S6.3–S6.6 | Initial start, traffic, SR and NR in PMEM mode; ledger in PMEM mode (**M0.3**) | 6, 8 |
| 10 | Checks and benchmark switch | S5.6–S5.9, persist delay (Q-A11) | Shared log parts; debug send checks; `DUMP 2368` persist-latency numbers, also with `__RedoLogPmemPersistDelayNs` at 200–2000 ns | 9 |
| 11 | Node restart and `redoLogReader` | S6.7, S6.8 | testNodeRestart subset; reader on files from crash tests | 9 |
| 12 | Power-loss testing | S1.5, S7.1–S7.3, S7.5 | Power-loss emulation and crash inserts in `pmem-redo-tests.txt`, run before every push of PMEM code (**M0.4**) | 9, 11 |

Pull request 9 is the one where PMEM mode starts writing the new format.
It contains both the write path and the recovery that reads it, so PMEM
mode is never in a state where it writes a log it cannot read. Before it,
both sides are developed and tested against synthetic logs (pull request 7).

```
0     (independent; it changes file mode, so it is the one pull request
       that is not bit-identical there)
1 ──────────────────────────────────────────────────────────────┐
2 ── 3 ──┐                                                       │
4 ───────┴── 5 ── 6 ──┐                                          │
2 ── 7 ── 8 ──────────┴── 9 ── 10                                │
                          └─── 11 ── 12 ◄────────────────────────┘
```

**The bug fix (pull request 0).** `execSr` stops and waits for more pages
when fewer than `ZMIN_READ_BUFFER_SIZE` pages are read ahead
(`DblqhMain.cpp:39054`), so that `stepAhead` never steps into a page not
yet read. The comment there assumes a PREPARE spans at most 3 pages, from
an old 30000-byte row limit. Today TUP logs up to
`MAX_LOG_RECORD_SIZE_WORDS` = 18000 + 4096 words (`include/kernel/ndb_limits.h:175`,
checked at `DbtupExecQuery.cpp:6670`), so a PREPARE can be 23130 words. A
page holds 8160 record words, so any PREPARE over 16320 words touches 4
pages unless it starts early in a page; at 23130 words, whenever it starts
after the first 1350 words of a page (`pmem_redo_format.md` §6.3). Such a
record needs a row over about 64 KB, which takes disk columns. The fix
changes the constant and its comment, and adds an `ndbrequire` that
`stepAhead` stays inside the pages read. The test writes rows of the
largest size, with in-memory and disk columns, then runs SR.

### 2.3 Points settled between the detail plans

The detail plans were written in parallel. Where they differed, or where
they found that the design needs a change, this is the decision. The
design changes are recorded in `pmem_redo_design.md` §6.

| # | Point | Decision | Source |
|---|---|---|---|
| R1 | Staging buffer per log part | RedoBuffer in PMEM mode defaults to **2 MB per part**. Writing needs at least 32 pages (below 10 free pages counts as "buffer full"), SR reading at least 43 pages. E15's "about 8 pages" was too few | write D3, recovery |
| R2 | Page-header CRC (**answered, Q-A4: option B**, §5.1) | Covers all of words 1–31; the DRAM-only words (links, fill index, dirty flag, debug stamps, unused words) are stored as 0. The initial-start pages are written through the mapping by `redoPmemInitFile()`, as the platform plan (S3.5) and the recovery plan already assume, not by `writeSinglePage`. No mask. The write plan's S4.8 and D1 change accordingly | write D1, platform S3.5, recovery §1 |
| R3 | Page identity and header CRC | Set at the first copy of the page, not in `initLogpage`, which cannot know the page number. The bytes on PMEM are the same | write D2 |
| R4 | Control area | Words 8128–8191 of page 0 of file 0, owned by recovery. The FILLER after the FD covers it, so a FILLER body is never stored, and page 0 is never copied in full | write D4, recovery D1, D7 |
| R5 | Reservation release in step 1 | Released in full at COMMIT, since no COMPLETE is written yet. The two-step release starts in X4 | write D5 |
| R6 | Initial head | Word 48 (`ZPAGE_HEADER_SIZE + 16`) in PMEM mode: COMPLETED_GCI(1) and a FILLER come first | write D8, recovery |
| R7 | Resume position after a restart | The persisted position handed to `redoInitWritePosition` is a page start when the head page's header never persisted; otherwise a W boundary after E (or after H) with a FILLER. Recovery closes the unit, the writer continues | recovery issue 4 |
| R8 | PMEM mode without DAX | **Refused always** in production mode, not only with durable commits: without `MAP_SYNC` the REDO is not durable even at GCP level. Only a test mode allows it | platform issue 1 |
| R9 | Test modes (**answered, Q-A1**) | Hidden parameters `__RedoLogPmemTestMode = off \| emulated \| nodax` and `__RedoLogPmemPowerLossEmulation`, warned loudly and **allowed in release builds**. Until PMEM hardware is available, PMEM mode runs on normal DRAM: `nodax` maps a plain file on any file system (macOS included), `emulated` uses a `memmap=` device. **Durable commits are allowed in both**, or X4–X7 cannot be developed. A test mode changes only the map flags and which start checks run; the format, the copy with non-temporal stores, the flushes, the fences, the persist points and the recovery are the production code, compiled in and executed in every mode. No `#ifdef` and no separate DRAM write path. On DRAM, data survives a crash of the data-node processes (the page cache holds the mapped file) but not an OS crash or power loss; the power-loss emulation (`__RedoLogPmemPowerLossEmulation`) covers that case. The node logs this at every start | platform S2.7 |
| R10 | Unsafe shutdown in step 1 | Warn, record the count in the slots, show it in ndbinfo. Marking the node stale comes with X6 | platform issue 2, recovery D6 |
| R11 | Placement can change between starts | A node in PMEM mode looks for its files under every REDO path | platform issue 3 |
| R12 | Prefault | `MADV_POPULATE_WRITE`, with a write-touch fallback; `MAP_POPULATE` does not make shared pages writable | platform issue 5 |
| R13 | Read buffer (**answered, Q-A6**) | `ZMIN_READ_BUFFER_SIZE` 3 → 4 in **both modes**: a PREPARE can span 4 pages. A separate bug fix with its own ticket, pull request 0 | format, recovery D5 |
| R14 | CRC chaining | `ndb_crc32c(crc, buf, len)` chains like zlib; the InnoDB port has a seeded internal routine | platform |
| R15 | Base-path fallback | `get_base_path()` falls back to the main file system path when the REDO path is unset. Cleanup at initial start must never act on an unset REDO path, or it wipes the whole node file system. PMEM mode only, by R18 | platform |
| R16 | `secondFileFlags` | Never initialised by DBLQH; zero it before the new use | platform issue 4 |
| R17 | Numbers | DUMP 2368 (benchmark), 2369 (state), 2370 (power loss now). DBLQH error inserts 5155–5159 and 5161–5172 for step 1 (5160 is taken; next free becomes 5173); 5180–5199 for later steps | write, recovery, next steps |
| R18 | REDO path in file mode (**answered, Q-A2**) | `FileSystemPathRedoLog` is used **only in PMEM mode**. File mode keeps its REDO files exactly where they are today, under `FileSystemPath`; NDBFS treats the parameter as unset there. If it is set in file mode, the management server warns that it has no effect. Switching a node back from PMEM mode to file mode leaves the old files under the REDO path; the user removes them | architect |

### 2.4 Testing without CI

There is no CI. Whoever pushes to the git tree runs the tests and is
responsible for them. The gate column of §2.2 is therefore what the pusher
runs before pushing that pull request. The pull request description lists
the commands and their results.

**Platforms** (Q-A5): Linux x86_64, Linux ARM64 and macOS ARM64. macOS
x86_64 is not supported.

| Platform | Builds | Runs | Does not cover |
|---|---|---|---|
| Linux x86_64 | Everything | Every test set below; `memmap=` with `emulated` on a machine booted with it | Real CXL latencies |
| Linux ARM64 | Everything | The unit tests; the PMEM set in `nodax` | `getauxval` CPU detection and the Linux ARM64 CRC path are only here |
| macOS ARM64 | Everything | The unit tests; the PMEM set in `nodax` | `MAP_SYNC`, device queries (stubs), `memmap=` |

On macOS ARM64 the copy, flush and fence are the ARM64 code of Linux:
stores, `DC CVAP` per line and `DSB`. An Apple M5 Pro reports
`hw.optional.arm.FEAT_DPB` = 1 (`sysctl`), so `DC CVAP` exists there.
Whether user code may run it on macOS is not yet verified; `ndb_pmem-t`
shows it, and the fallback is `DC CIVAC`. This replaces the platform plan's
`memcpy` stub for macOS, so the production persist code runs on every
supported platform (Q-A1).

**What runs before a push:**

| Set | Content | Before pushing |
|---|---|---|
| Unit | Every step-1 unit test on the three platforms | Any change to portlib, configuration, the format or the reader |
| File mode | Today's REDO and restart cases in file mode (recovery plan A7) and the MTR `ndb` tests of the area changed | Every pull request, since each must leave file mode unchanged |
| PMEM | MTR `ndb_pmem_*` and `ndb_redo_pmem_*`, and the autotest list `pmem-redo-tests.txt`, in `nodax` | Any PMEM change, from pull request 5 on |
| Power loss and ledger | The power-loss emulation and the GCP-saved ledger (recovery plan S7) | Any change to the persist path, the PMEM helper or recovery, from pull request 12 on. The ledger in file mode from pull request 1 on |
| Long | `pmem-redo-long-tests.txt`, and the PMEM set on `memmap=` with `emulated` | Before each milestone |

---

## 3. Steps after step 1 in brief

Detail and `file:line` references are in `impl_next_steps.md`.

| Phase | Main packages | Exit |
|---|---|---|
| X1 | Move TCKEY_FAILCONF after COMPLETE in the three takeover paths | READ_BACKUP read-your-writes after takeover |
| X3 | Ledger of acknowledged commits (extends `testRestartGci`); crash of all nodes; power-loss runs with step 1's emulation; TLA+ model of C/K/L/A/F and the restart, checked before X5.4 | Loss above R_gcp measured |
| X4 | Durable flag set at DIVERIFYCONF (GCI ≥ g); opCount in TC and takeover; `redoPersistOp` at the E8 points; primary's local commit moved to COMPLETE; `writeCompleteLog`; TF_LATE_COMMIT forced; rule F in TC, takeover and LQH (abort from the committed state, ABORT with `AF_AFTER_COMMIT`); API node-id hold-back in QMGR | M3 |
| X5 | One scan with the per-part hash table; step B exchange; step C verdicts with the count fallback; flag invalidation; SR_HEAD; raising the restorable GCI to G' in sysfile, DIH, LQH, Backup, NDBCNTR and the replica intervals | M4 |
| X6 | Node-failure file written by QMGR before PREP_FAILCONF; records sent with CNTR_START_REQ; stale nodes in `m_withLogNotRestorable`; unsafe shutdown → stale; at least one non-stale node per node group | M5 |
| X7 | `DurableCommits` config; activation GCI g through GCP_PREPARE/GCP_COMMIT; sysfile field; armed after the save of g−1; deactivation by SR; version gate; ndbinfo `durable_commits` | M6 |
| X8 | Adaptive fencing: one fence per log part per scheduler round, dependent signals held back until it is done (`vm/mt.cpp`, `execSEND_PACKED`); benchmarks; `redoLogReader` for COMPLETE and flags; rondb-docs chapters (LaTeX source, then `./update-md`) | M7 |

**New signals** (GSNs from 987; each needs `SignalNames.cpp`, a printer and a
`Remote` entry in `SignalScopes.hpp`; content checks with `ndbrequire`, as
for other data-node-only signals):

| Signal | Route | Purpose |
|---|---|---|
| `SR_TAIL_INDOUBT_REP` | DBLQH worker → DBLQH proxy → proxies of the SR nodes → workers | Step B: in-doubt sets (transid, count, gci_hi), batched |
| `SR_TAIL_HIT_REP` | same | Step B: "T complete" or "T aborted" |
| `SR_TAIL_DONE_REP` | same | Step B: done, with the part's highest executed GCI so all parts agree on G' |
| `DURABLE_ACTIVATE_REQ/CONF/REF` | CMVMI → DIH → master DIH | Activation |

Fourteen existing signals grow (packed COMMIT gets a durable variant,
COMMITREQ, ABORTREQ, LQH_TRANSCONF, DIVERIFYCONF, the GCP signals,
COPY_GCIREQ, START_RECREQ/CONF, CNTR_START_REQ). They change only once
durable commits are active.

**Design issues the next-steps plan found** (each has a proposal there;
the ones marked * need your decision, see §5):

| # | Issue | Proposal |
|---|---|---|
| DI-1* | A dirty write's COMPLETE record would give a false "T complete" in step B, and its GCI comes from LQH, not TC | Flag such records (`CPF_SELF`), or turn dirty writes into normal writes in durable mode; pick phase-2 records by `CF_DURABLE` |
| DI-2 | Step B's rescan starts before the tail, so a COMPLETE from before the tail with a reused transid could give a false hit or a false "corrupt log" crash | Count a COMPLETE only after a tail COMMIT of the same transaction in the same part; drop the step-A crash check |
| DI-3 | The exchange grows with the square of the number of log parts | Aggregate per node in the DBLQH proxy; the verdicts do not change |
| DI-4 | All parts need the same G' for SR_HEAD | DONE carries each part's highest GCI; in-doubt entries carry gci_hi |
| DI-5* | API node-id hold-back: GCIs can differ by one between data nodes | Hold back until the save of f+1 |
| DI-6 | A rule-F abort after `commitGciHandling` must unlink the operation from its GcpRecord, or the GCP stops | In X4.10 |
| DI-7* | A COMPLETE from the failed TC may be executed after the takeover's LQH_TRANSREQ scan, so "was any COMPLETE sent?" can be answered wrongly | Check in code and in the TLA+ model; marker bit or opCount |
| DI-8 | D4 with all nodes present hits `ndbrequire(!allNodes)` (`NdbcntrMain.cpp:2780`) | A clear `progError` instead |
| DI-9* | Read locks under invariant L | Decide whether shared locks are released at COMMIT or at COMPLETE |

---

## 4. Conventions

| Kind | Names |
|---|---|
| Config | `RedoLogMode` (`file` \| `pmem`), `FileSystemPathRedoLog` (PMEM mode only, R18; one path per NUMA node, `node:path,...`), `DurableCommits` (X7); hidden test settings of R9, allowed in release builds. CFG ids 711–716 are free on 26.10, 26.05 and 25.10 |
| Portlib | `include/util/ndb_crc32c.h` (`ndb_crc32c`); `include/portlib/ndb_pmem.h` (`ndb_pmem_map`, `_unmap`, `_prefault`, `_copy_nt`, `_flush`, `_drain`, `_persistence_domain`, `_numa_node`, emulation `ndb_pmem_emul_*`) |
| NDBFS | `FsOpenReq::OM_MAP_SYNC`; FSOPENCONF grows from 5 to 7 words with the mapping address |
| DBLQH | `c_redo_pmem`; `LogFileRecord::m_pmem_base`; `LogPartRecord::m_pmem_persisted_lsn`; `TcConnectionrec::m_redo_end_lsn`; `redoPersist`, `redoPersistOp`, `redoCopyOut`, `redoPadToUnit`, `redoEndOfRecord`, `redoInitWritePosition`, `redoWriteLastFileSlot`; format constants in `PmemRedoFormat.hpp`; reader in `PmemRedoScan` |
| Files | REDO files stay `D<8+p>/DBLQH/S<n>.FragLog`, under the REDO path of the part's NUMA node |
| ndbinfo | `redo_log_pmem` (step 1); `durable_commits`, `durable_commit_stats`, `node_failure_records` (later steps) |
| Error inserts | DBLQH 5155–5172 (step 1), 5180–5199 (later); DBTC 8320–8339; DBDIH 7260–7279; QMGR 990–998; NDBCNTR 1040–1049 |
| DUMP | 2368–2370 (step 1) |
| Platforms | Linux x86_64, Linux ARM64, macOS ARM64 (Q-A5); not macOS x86_64 |
| Tests | Unit tests with `NDB_ADD_TEST` and `TAPTEST`; MTR with `--defaults-extra-file=suite/ndb/pmem_redo.cnf` (`nodax`) or `pmem_redo_dax.cnf` (`memmap=`, `MTR_NDB_PMEM_DIR`); autotest lists `pmem-redo-tests.txt` and `pmem-redo-long-tests.txt` with about 50 existing restart cases in PMEM mode; no CI, the pusher runs them (§2.4) |

---

## 5. Questions for the architect

**Needed before step 1 starts:**

| # | Question | Proposal or answer |
|---|---|---|
| Q-A1 | Accept the hidden test modes of R9, with `nodax` running PMEM mode on any file (macOS, Linux without PMEM)? Allowed in release builds? Durable commits never allowed with `nodax`? | **Answered (review 10):** PMEM mode must run on normal DRAM, since no PMEM hardware is available, release builds included. The code is built for real PMEM so it can be tested when hardware arrives. Consequence: durable commits are allowed in the test modes too (R9) |
| Q-A2 | Should `FileSystemPathRedoLog` also move the REDO log in file mode? | **Answered (review 10):** no. File mode keeps today's REDO placement; too much relies on it (R18) |
| Q-A3 | Path syntax `node:path,...`, at most 8 entries? | **Answered (review 11):** yes |
| Q-A4 | Header CRC over all of words 1–31 with the initial-start pages written through the mapping, or a CRC that skips the DRAM-only words so they can still be written by `writeSinglePage`? See §5.1 | **Answered (review 10):** B, through the mapping, no mask |
| Q-A5 | Is ARM in scope for the first version? | **Answered (review 11):** build and unit-test on Linux x86_64, Linux ARM64 and macOS ARM64; macOS x86_64 is not supported. Every step-1 unit test runs on all three (`ndb_crc32c-t`, `ndb_pmem-t`, `RedoLogPaths-t`, `pmem_redo_format-t`, the `PmemRedoScan` tests). On ARM64 the persist path is stores, `DC CVAP` per line and `DSB`, on macOS too (§2.4) |
| Q-A6 | Fix `ZMIN_READ_BUFFER_SIZE` (3 → 4) in file mode too? | **Answered (review 10):** yes, as a separate bug fix for both file mode and PMEM mode (pull request 0) |
| Q-A7 | Unsafe shutdown before X6: warn or refuse? | Warn and record (R10) |
| Q-A8 | Bad blocks elsewhere on the device, when they cannot be mapped to a file: refuse or warn? | Warn |
| Q-A9 | Should a full CRC check of every record run in the restart's execution scan, not only in phase 1? | Yes; the cost is small next to applying the records |
| Q-A10 | Persist-latency histogram: time every persist, or 1 in 16? | 1 in 16 |
| Q-A11 | New, from Q-A1: on DRAM a persist costs far less than the 200–2000 ns of CXL persistent memory. Add a hidden setting that spins for a given time after each persist barrier, so commit latency and throughput can be measured for the target hardware before it exists? | **Answered (review 10):** yes, `__RedoLogPmemPersistDelayNs`, default 0, about 1 pd, in pull request 10 with the benchmark switch |

**Needed before X4 and X5:**

| # | Question | Proposal |
|---|---|---|
| Q-B1 | Dirty writes in durable mode (DI-1): flag their records, or turn them into normal writes? | Turn them into normal writes; simpler to reason about |
| Q-B2 | Read locks (DI-9): released at COMMIT or at COMPLETE? | At COMPLETE, like write locks |
| Q-B3 | Error code for a rule-F abort | A new temporary error, retryable |
| Q-B4 | Should TCKEY_FAILCONF carry the GCI? | No change |
| Q-B5 | Forced start to R_gcp when a node group has only stale nodes? | No forced start in the first version |
| Q-B6 | `SET DurableCommits=0` on a running cluster: accepted as pending until the next SR, or refused? | Accepted as pending |
| Q-B7 | Block activation while a node restart runs? | Yes |
| Q-B8 | API node-id hold-back until the save of f or of f+1 (DI-5)? | f+1 |
| Q-B9 | Takeover: decide "any COMPLETE sent?" by opCount or by a marker bit (DI-7)? | Decide after the TLA+ check |
| Q-B10 | Path of the node-failure file | Under the REDO path of NUMA node 0 |
| Q-B11 | Memory for the step-A hash table, and what happens when it runs out | Sized from the transaction-record count; out of memory stops the SR with a clear message |
| Q-B12 | Force durable transactions onto the parallel commit path? | No; measure first |
| Q-B13 | There is no CI (§2.4). Which developer machines cover Linux ARM64 and `memmap=`, and when do real CXL modules arrive? | Linux ARM64 by pull request 2, `memmap=` by pull request 5 |

### 5.1 Q-A4 explained: the DRAM-only words of the page header

**The page header today.** Every 32 KB REDO page starts with a 32-word
header (`Dblqh.hpp:188-211`). Its words are of two kinds:

| Words | Content | Use after a restart |
|---|---|---|
| 1 | Lap | Read by recovery |
| 2, 3 | Highest completed and highest started GCI | Read by recovery |
| 6, 7 | Version, number of log files | Read by recovery |
| 10 | Reference to the last PREPARE | Read by recovery |
| 21 | Number of log parts | Read by recovery |
| 15, 16 | Page and file number (debug words today) | PMEM mode: the page identity, read by recovery |
| 22–26 | PMEM mode only: format magic, restart generation, log part, write unit, node id | Read by recovery |
| 4, 5 | Next and previous page: the links of the page in DBLQH's page lists in memory (i-values) | None |
| 8 | Fill index: where the next record goes; it grows with every record | None in PMEM mode: the end of the records is found from their checksums |
| 11 | Dirty flag, used while the restart executes the log | None |
| 12–14, 17–20 | Debug stamps written before each file write: log timer, page i-value, place written from, words written, in writing, previous page number, in free list | None |
| 9, 27–31 | Unused | None |

The **DRAM-only words** are those of the last five rows: 4, 5, 8, 9, 11,
12–14, 17–20 and 27–31. They describe the copy of the page in DBLQH's
memory (its links, how full it is, debug state) or are unused. In file mode
they reach the disk because the whole page does, but only `redoLogReader`
reads them back.

**Why PMEM mode stores them as 0.** In file mode a page goes to disk
several times while it fills, and every write carries the whole header as
it is in memory, with a new checksum in word 0. In PMEM mode the header is
written once (E5): the first copy of the page stores it, and it is not
written again in that lap. Rewriting a 64-byte unit that has persisted can
tear on a power loss, since only 8-byte stores are failure-atomic, and a
torn header would make the whole page unreadable. A word such as the fill
index, which changes with every record, can therefore not be part of the
stored header. The stored header holds the recovery words and 0 in every
DRAM-only word, and word 0 holds a CRC32C of words 1–31.

**The question.** At run time the copy-out builds this clean image, so it
is always right. The first page of each mbyte, formatted in the NDBFS
initialisation callback, is built by the same pure image function and is
clean too. The question is about the pages DBLQH writes at initial start:
page 0 of every file (header, FD, FILLER) and page 1 of file 0 (header,
COMPLETED_GCI(1), FILLER). Today they are written by `writeSinglePage`
through a log-file operation and an NDBFS write. That path needs DRAM-only
values in the page while the write runs. Word 4 must be RNIL, because when
the write completes `releaseLfoPages` follows word 4 to free the pages
(`DblqhMain.cpp:35915-35926`), and `writeDbgInfoPageHeader` stamps words
12–20 (`36212-36217`). NDBFS writes the page as it is in memory, so the
stored header would hold RNIL and debug values where the clean image holds
0, and a CRC over all of words 1–31 would not be the CRC of the clean
image. There are two ways out:

| | A: the CRC skips the DRAM-only words | B: write these pages through the mapping |
|---|---|---|
| Rule | CRC over words 1–31 with the DRAM-only words read as 0, whatever they hold; the reader does the same | CRC over all of words 1–31; every stored header has 0 in the DRAM-only words |
| Initial start | As today: `writeSinglePage` and an NDBFS write | `redoPmemInitFile()` copies the pages into the mapping with the run-time copy and persists them; no log-file operation, no NDBFS write |
| What the CRC protects | Every word recovery reads; not the DRAM-only words, which nothing reads | Every word of the header |
| Cost | One mask constant in `PmemRedoFormat.hpp`, shared by writer and reader; a later use of one of these words on PMEM must take it out of the mask | A PMEM-only path in initial start. The files are already mapped at that point (S3.5 maps them at open with `OM_INIT`), so it is small |
| Power-loss emulation | Does not see these writes. Harmless at initial start, but it breaks the rule that every PMEM write goes through the `ndb_pmem` calls | Sees every PMEM write |

**Decision: B** (review 10). The first proposal was A, taken from the
write-side plan alone. Read together, the platform plan (S3.5) and the recovery plan
already write these pages with `redoPmemInitFile()` through the mapping, so
B costs nothing extra. It removes the mask, and PMEM mode then never writes
a REDO page through NDBFS. Recovery behaves the same with A or B.

---

## 6. Schedule risks

1. **Pull request 9** is large: it switches PMEM mode to the new format and
   must bring the restart along. Synthetic-log tests in pull request 7
   keep it reviewable.
2. **Power-loss emulation** is the only test that catches a missing
   barrier. If it slips, M0.4 and everything after rests on review alone.
   With no CI it runs only when the pusher runs it, so it belongs in the
   tests run before every push of PMEM code (§2.4).
3. **The commit path (X4)** touches the hottest code in DBTC and DBLQH,
   including takeover; the TLA+ model should run before X5.4.
4. **Hardware.** CXL 2.0 persistent memory modules are needed for real
   performance numbers and for the device-specific dirty-shutdown flag.
   Until then everything runs on DRAM in the test modes (R9). Since the
   persist code is the production code, the hardware adds only the start
   checks of production mode and the real latencies (Q-A11 approximates
   them).
5. **Estimates** come from planning, not from past RonDB work. Treat them as
   ±50 %.
