# RONDB-1150 — Implementation plan for the steps after step 1 (X1, X3–X8)

Status: **plan, 2026-10-28. No code changed.** Part of the implementation
plan for the master plan `durable_commits_plan.md` (rev 9). The other three
parts plan step 1 (X2, the REDO on PMEM): `impl_step1_platform.md`,
`impl_step1_lqh_write.md`, `impl_step1_recovery_test.md`.

All paths are relative to `storage/ndb/`. Line numbers are for commit
`bf6848d754f`. **[V]** = verified in the code at the cited line, **[I]** =
inferred. Sizes: S ≤ 4, M 5–12, L > 12 person-days (pd).

---

## 0. What this plan assumes from step 1 (X2)

| Step 1 deliverable | Used by |
|---|---|
| `redoPersist(part)`, `redoPersistOp(op)`, per-op `m_redo_end_lsn`, per-part `m_pmem_persisted` (`pmem_redo_design.md` E7) | X4.4, X4.5, X4.10, X5.6, X8.1 |
| COMMIT writer with transid, gci_lo, opCount (0 until X4) and flags `CF_DURABLE`, `RF_INVALIDATED`; ABORT writer with `AF_AFTER_COMMIT`; COMPLETE type 11 in the format (E13) | X4.3, X4.5, X4.10 |
| Atomic `RF_INVALIDATED` store + flush (E9) | X5.2, X5.5 |
| Exact end of log E from phase 1, zeroing `[E, end of mbyte)` (E11, E12) | X5.2–X5.6 |
| NDBFS `OM_MAP_SYNC` and the `ndb_pmem` helpers (E14, S1, S3) | X6.1 |
| Dirty-shutdown count recorded in the control area (E17) | X6.7 |
| Power-loss emulation and the S7 checker of acknowledged writes | X3 |
| Persist counters in ndbinfo (E19) | X8.3 |

If a step-1 plan names these differently, the names here follow it.

---

## 1. Overview

| Phase | Content | Size | Depends on | Demonstrable at the end |
|---|---|---|---|---|
| X1 | TCKEY_FAILCONF after COMPLETE in takeover | S (4 pd) | — | READ_BACKUP read-your-writes after a TC failure |
| X3 | Ledger, crash of all nodes, power-loss runs, TLA+ model | M (15 pd) | X2 (S7) | Losses only above R_gcp, measured |
| X4 | Commit path: flag, opCount, barriers, local commit at COMPLETE, late ack, rule F, API hold-back | L (50 pd) | X2, X3 | Durable protocol running; F tested by node failures |
| X5 | SR phases 1–3: one scan, exchange, verdicts, raise to G' | L (50 pd) | X4 | **Zero ledger losses after a full crash, all nodes starting** |
| X6 | Node-failure file, stale nodes, D4 check, partial SR fallback | M (17 pd) | X5 (X6.1 only X2) | Zero losses with a node failure in the tail GCI and with partial SR |
| X7 | Online activation at g, arming, deactivation by SR, ndbinfo, version gate | M (17 pd) | X4 (X7.1–7.2), X5 | Activation on a running cluster |
| X8 | Adaptive fencing, benchmarks, `redoLogReader`, documentation | L (32 pd) | X4 (X8.1–8.2), X5–X7 | Published numbers, rondb-docs chapters |

Total about 185 pd after step 1. Critical path in §9.

---

## 2. X1 — Takeover ack fix

**Goal.** After a TC takeover the API gets TCKEY_FAILCONF only after the
takeover TC has finished the COMPLETE phase. Today it is sent before
COMPLETEREQ, which also breaks READ_BACKUP read-your-writes after a TC
failure (`research_commit_protocol.md` §1 item 7).

**Exit criteria.** No TCKEY_FAILCONF before the last COMPLETECONF of that
transaction; new test passes; existing takeover tests in
`daily-basic-tests.txt` pass.

### X1.1 Move the ack (S, 1 pd)

| Place | Today | Change |
|---|---|---|
| `completeTransAtTakeOverDoOne`, case CS_FAIL_COMMITTED, `DbtcMain.cpp:14685-14707` | `sendTCKEY_FAILCONF` at `14694` [V], then `toCompleteHandlingLab` | Remove the send |
| `check_finished_commit_handling`, takeover branch, `DbtcMain.cpp:15502-15506` | `sendTCKEY_FAILCONF` at `15505` [V], then `toCompleteHandlingLab` | Remove the send (the non-takeover branch `sendApiCommitAndCopy` stays) |
| `check_finished_complete_handling`, takeover branch, `DbtcMain.cpp:15892-15900` | CONTINUEB, `handleGcp`, `releaseTakeOver` | Call `sendTCKEY_FAILCONF` first |
| CS_FAIL_COMPLETED, `DbtcMain.cpp:14769-14781` | ack at once | Unchanged (nothing left to complete) |

- `sendTCKEY_FAILCONF` clears `commitAckMarker` (`DbtcMain.cpp:14851`) [V],
  and `releaseApiConnectFail` asserts it is RNIL (`21946`) [V]. With the
  send before `releaseTakeOver` the assertion still holds. The COMPLETEREQ
  path does not touch the marker (`toCompleteHandlingLab`, `15917-16010`) [V].
- Apply it to every transaction, not only TF_LATE_COMMIT ones: the
  takeover record does not know the flag, and the path is rare.
- The API accepts TCKEY_FAILCONF while it is in `sendTC_OP` or
  `sendTC_COMMIT` (`ndbapi/Ndbif.cpp:1145-1195`) [V]; a later ack changes
  nothing there.

### X1.2 Tests (S, 3 pd)

- New error insert **8320**: the takeover TC delays its COMPLETEREQ round
  by 2 s. The test checks that the API has no commit ack during the delay.
- `test/ndbapi/testNodeRestart.cpp`: case `TakeoverReadBackupRYW`. Write a
  row of a READ_BACKUP table, kill the TC node after COMMITTED (existing EI
  8133, "leave a committed, not completed transaction behind",
  `ERROR_codes.txt:720`) [V], wait for the ack, read through a backup
  replica: the new value must be there. Register in
  `test/run-test/daily-basic-tests.txt`.

**Order:** X1.1, X1.2. **Risk:** low; the ack after takeover gets slower
by one COMPLETEREQ round.

---

## 3. X3 — Test harness

**Goal.** A repeatable way to crash every data node (process kill and
emulated power loss) under load and to check what survived, before the
commit path changes.

**Exit criteria.** The harness runs in ATRT and MTR on `memmap=` PMEM;
after step 1 it reports zero losses at GCI ≤ R_gcp and measures losses
above R_gcp (expected until X5). After X5 the same runs must report zero
losses.

### X3.1 Acknowledged-commit ledger (M, 6 pd)

New NdbApi program `test/ndbapi/testDurableCommits.cpp` (NDBT test with a
standalone `--verify` mode). It builds on the S7 checker of step 1; it adds
per-transaction acks, GCIs and multi-row checks.

| Workload | What it writes | What verification checks |
|---|---|---|
| W1 multi-row | Each worker owns k rows spread over every node group (keys picked by partition id); each transaction writes `(worker, seq)` into all k | **Durability:** seq ≥ the last acked seq. **Atomicity:** all k rows hold the same seq |
| W2 chain | Read counter c, write c+1, insert `log[c+1]` | **Closure (G2):** with c = n, rows `log[1..n]` all exist |
| W3 hot row | Many clients update one row | Durability; lock-hold effects for X8 |
| W4 mixed | READ_BACKUP and non-READ_BACKUP tables, unique index, BLOB, disk column, fully replicated table | As W1 |

- Ledger entry per transaction: worker, seq, transid
  (`NdbTransaction::getTransactionId`), GCI (`getGCI`), outcome (acked,
  error, unknown such as 4010 or a timeout). Written to a local file,
  flushed per batch; the client host does not crash.
- Unknown outcomes may go either way.
- **Replica check (G3):** read every row from every replica and compare;
  reuse the replica-consistency include of
  `claude_files/ttl_899_rowid/probe_tests.md`.
- Report: losses, the highest lost GCI, and R_gcp after the SR (NDBCNTR
  logs it: "System Restart: master node: %u, num starting: %u, gci: %u",
  `NdbcntrMain.cpp:2852`) [V].
- Tables: the MTR wrapper creates them through SQL (CLAUDE.md rule); the
  ATRT variant uses NDBT tables, as other ATRT tests do, since no mysqld is
  involved.

### X3.2 Crash orchestration (S, 3 pd)

- (a) Kill all `ndbmtd` at once: `NdbRestarter::insertErrorInAllNodes(9999)`
  ("crash system immediately", `ERROR_codes.txt:775`) [V].
- (b) Emulated power loss: the S1/S7 mode that keeps only fenced lines,
  triggered on all nodes with one `insertErrorInAllNodes(<S7 code>)`.
- (c) Crash at protocol points: the X4/X5 error inserts of §12.2.
- Loop: load → crash → SR → verify → repeat, N iterations, random
  timing.

### X3.3 MTR and ATRT wiring (S, 2 pd)

- `mysql-test/suite/ndb_durable/` with `include/have_ndb_pmem.inc`, which
  skips unless a PMEM path is configured (env `NDB_PMEM_PATH`), and a
  `my.cnf` with `RedoLogMode=pmem`.
- `test/run-test/conf-durable.cnf` and `durable-tests.txt` for autotest.

### X3.4 TLA+ model (M, 6 pd, recommended before X5)

Plan P6 asks for it. `claude_files/durable_commits/tla/DurableCommits.tla`:
replicas, linear and parallel commit, C/K/L/A/F, node and TC failure with
takeover, crash, phase 2 steps A–C with the fallback, stale nodes. Check
G1–G3. Small configurations (2 node groups × 2 replicas, 2–3
transactions). It is the cheapest way to check DI-1 and DI-2 (§13) before
coding X5.

**Order:** X3.1, X3.2, X3.3; X3.4 in parallel with X4.

---

## 4. X4 — Commit path

**Goal.** Every durable transaction (GCI ≥ g) follows invariants C, K, L, A
and F on every path of plan §3.4; COMMIT records carry transid, gci_lo,
opCount and `CF_DURABLE`; failed API node ids are held back.

**Exit criteria.**
- The persistence debug check of E7 never fires in the file-mode
  regression lists and the durable test set.
- A primary row is not visible to READ_COMMITTED or locking readers before
  its COMPLETE record is persistent (test with EI 5183).
- No commit ack before the last COMPLETED, on any path.
- Node failure in the COMMIT phase aborts the transaction (F), with ABORT
  `AF_AFTER_COMMIT` on every replica that had a COMMIT record.
- Ledger: still losses above R_gcp (no phase 2 yet), none below.

### 4.1 Path table (plan §3.4)

| Path | C | K | L | A | F | Package |
|---|---|---|---|---|---|---|
| Linear COMMIT/COMPLETE | barrier #1 | `writeCompleteLog` + barrier in `execCOMPLETE` | primary local commit at COMPLETE | forced late ack | — | X4.4–X4.7 |
| Parallel COMMITREQ/COMPLETEREQ (LowLatency, simple reads, failure fallback) | #1 via `commitReqLab` | barrier in `execCOMPLETEREQ` | seq-0 branch in `execCOMPLETEREQ` | late ack in `check_finished_complete_handling` | — | X4.4–X4.7 |
| Takeover COMMITREQ/COMPLETEREQ | as parallel | as parallel | as parallel | X1 | abort if no COMPLETE was sent | X4.9 |
| Participant failure in COMMIT phase | — | — | — | no ack | abort after commit | X4.8, X4.10 |
| Dirty writes | one barrier for PREPARE + COMMIT + COMPLETE | same | local commit after it | n/a (TC drops them, `releaseDirtyWrite`, `DbtcMain.cpp:9546`) [V] | — | X4.13, DI-1 |
| `AC_NR_COPY` (commits at COMMIT) | #1 | no COMPLETE record needed (DI-10) | stays at COMMIT | — | — | X4.6 |
| Several ops on one row (`LOG_COMMIT_WRITTEN_WAIT_SIGNAL`) | one barrier after TUP's loop (`DbtupCommit.cpp:247-276`) [V] | one COMPLETE per op | as linear | — | sibling state handled | X4.3, X4.10 |
| Queued commit-log write (`DblqhMain.cpp:909-938`) | barrier before unlock | — | seq 0 → `commitReplyLab` | — | — | X4.4, X4.6 |
| Unique index, fully replicated, reorg triggers | ordinary TcConnect ops | same | same | same | same | counted in opCount (X4.2) |
| Replica applier (`TF_REPLICA_APPLIER`) | ordinary path | | | | | tests only |
| Disk-data columns (`ZTUP_WAIT_COMMIT`, `tupcommit_conf_callback`) | #1 | as linear | the disk-page wait moves to COMPLETE on the primary | | | X4.6 |
| Operation-level abort with IgnoreError | none (PREPARE without COMMIT, C5) | | | | unflagged ABORT, not counted | X4.2 |

### X4.1 Durable flag at the commit point; forced late ack (S, 3 pd)

- **DIH.** New `m_micro_gcp.m_durable_gci` (g; 0 = off), read under the
  same seqlock as the GCI in `execDIVERIFYREQ` (`DbdihMain.cpp:17879-17907`)
  [V] and in the queued path (`emptyverificbuffer`, DIVERIFYCONF sent at
  `25019` with length 4) [V]. Return `theData[4] = (gci_hi >= g && g != 0)`;
  DIVERIFYCONF length 5.
- **Interim activation** for X4 and X5: `DurableCommits=1` read at start,
  g = the first gci_hi the cluster uses after the start. g reaches the
  sysfile with X5.7 (written at the first GCP save); X4 runs no phase 2.
  X7 replaces this with online activation.
- **TC.** `execDIVERIFYCONF` (`DbtcMain.cpp:7710`) [V]: if the flag is set
  and `m_durable_op_count > 0`, set new `TF_DURABLE = 8192` (next free bit,
  `Dbtc.hpp:1115-1131`) [V] and `TF_LATE_COMMIT`.
- **Invariant A** then holds on the normal path without other changes: the
  flag is read in `sendApiCommitSignal` (`8303`) and `copyApi` (`8472`),
  both after DIVERIFYCONF [V]; the ack comes from
  `sendApiLateCommitSignal` (`9131`), called from `execCOMPLETED`
  (`9302-9307`) or `check_finished_complete_handling` (`15905-15912`) [V].
  An API failure during commit drops the flag (`8474-8478`) [V]: correct,
  nobody is acked.

### X4.2 opCount in TC (S, 3 pd)

- `ApiConnectRecord::m_durable_op_count`, cleared at transaction start and
  release. Incremented in `execLQHKEYCONF` (`DbtcMain.cpp:6756`) for a
  non-dirty write (`ZINSERT`, `ZUPDATE`, `ZDELETE`, `ZWRITE`, `ZREFRESH`)
  on a logged table (`get_storedTable`, `Dbtc.hpp:1752`; set from
  `tableLogged`, `DbtcMain.cpp:1091`) [V].
- Counting at LQHKEYCONF means every replica has prepared and logged the
  op. IgnoreError failures get LQHKEYREF, not LQHKEYCONF, so they are not
  counted [I]. Dirty writes are released at LQHKEYCONF and not counted.
- Trigger-generated ops (UK, FK, fully replicated, reorg) reach TC through
  the same `execLQHKEYCONF` and are counted [I].
- Deferred triggers fire before DIVERIFY (`diverify010Lab` FIRE_TRIG_REQ
  round, `7552-7571`) [V per research], so the count is final before the
  first COMMIT.
- Takeover: from LQH_TRANSCONF (X4.3), see X4.9.
- Check in X4.14: a debug DUMP in LQH that counts COMMIT records per
  transid in a part, compared with opCount for a sample of transactions.
  A wrong opCount only matters for the partial-SR fallback (risk 5).

### X4.3 Signal formats: durable flag and opCount (M, 5 pd)

| Signal | Today | Change |
|---|---|---|
| Packed COMMIT (TC → last LQH, LQH → previous LQH) | code `ZCOMMIT` 0, 5 words `[ptr, gci_hi, transid1, transid2, gci_lo]` (`PackedSignal.hpp:34-42`, `DblqhMain.cpp:6362-6368`) [V] | New code `ZCOMMIT_DURABLE = 8` (codes 8–15 free), 6 words, + opCount. Durable is implied by the code |
| Unpacked `GSN_COMMIT` (`Commit`, `CommitReq.hpp:66-94`, length 5) [V] | | Length 6 when durable |
| `COMMITREQ` (`CommitReq.hpp:53`, length 8) [V] | | Length 10: opCount, flags (bit 0 durable) |
| `LQH_TRANSCONF` (`LqhTransConf.hpp:50`, length 18) [V] | | Length 19: `opCount | durable << 31`, valid for status Committed |
| `TUP_WRITELOG_REQ` → `LQH_WRITELOG_REQ` (direct calls) | theData[0..2] (`DbtupCommit.cpp:247-276`) [V] | theData[3] = opCount and flag, copied in TUP's loop, so a sibling op's COMMIT record gets them before its own COMMIT signal arrives |

- Senders: `Dbtc::sendCommitLqh` (`DbtcMain.cpp:8052`), `toCommitHandlingLab`
  (`15517`), `Dblqh::sendCommitLqh` (`DblqhMain.cpp:6901`; the container
  threshold `25 - len` adapts), `sendLqhTransconf` (`43406`) [V].
- Receivers: `Dblqh::execPACKED_SIGNAL` (`6329`), `execCOMMIT` (`14712`),
  `execCOMMITREQ` (`14827`), `execLQH_WRITELOG_REQ` (`15276`),
  `Dbtc::execLQH_TRANSCONF` (`14130`) [V].
- `LQH_RECEIVE_TYPES`, `PackedSignal::verify` and the printers in
  `src/common/debugger/signaldata/` learn code 8.
- LQH keeps `m_op_count` and new flag `OP_DURABLE = 0x400` in
  `TcConnectionrec::m_flags` (`Dblqh.hpp:3223-3242`, last used `0x200`) [V].
  `writeCommitLog` (`DblqhMain.cpp:43566`) fills them into the S4 record.
- New formats are sent only with TF_DURABLE, which needs every data node to
  support the feature (X7.6), so no mixed-version receiver sees them.

### X4.4 Barriers at the E8 points (S, 3 pd)

| # | Function | Position (today's lines) | Inv. |
|---|---|---|---|
| 1 | `commitReqLab` | after `c_tup->execTUP_WRITELOG_REQ` (`15219`), before the branch at `15267`: `redoPersistOp(op)` [V] | C |
| 2 | same, sibling in `LOG_COMMIT_WRITTEN_WAIT_SIGNAL` (`15257-15259`) | same call; normally a no-op | C |
| 3 | `handle_queued_log_write` | after `writeCommitLog` (`912`), before `unlock_log_part` (`914`): `redoPersist(part)` [V] | C |
| 4 | `doWritePrepareLog` (dirty write) | PREPARE, COMMIT (`13577`), COMPLETE; one `redoPersist` before the unlock (`13579`), so before `localCommitLab` (`13583`) [V] | C, K |
| 7 | `execCOMPLETE` | X4.5 + barrier before the branch at `15004` [V] | K |
| 8 | `execCOMPLETEREQ` | same, before the branch at `15120` [V] | K |
| 10 | rule-F abort | X4.10 | F |

- Only for `OP_DURABLE` ops. Non-durable ops keep the step-1 rules.
- **Debug check (E7):** assert `m_redo_end_lsn <= m_pmem_persisted` for
  durable ops in `commitReplyLab` (`15617`), `sendCommitLqh` (`6901`),
  `sendCompleteLqh` (`6955`), `sendCommittedTc` (`7004`),
  `sendCompletedTc` (`7049`), the COMMITCONF/COMPLETECONF sends, and at
  the start of `localCommitLab` (`15358`) [V function lines].

### X4.5 `writeCompleteLog` (S, 2 pd)

- New `Dblqh::writeCompleteLog`, next to `writeAbortLog` (`43542`) and
  `writeCommitLog` (`43566`) [V]: the 4-word COMPLETE record (transid)
  under `lock_log_part`, from the second half of the per-operation
  reservation (format §7.3).
- Called from `execCOMPLETE` and `execCOMPLETEREQ` in state COMMITTED for
  `OP_DURABLE` ops. New flag `OP_COMPLETE_LOGGED = 0x1000` so it is written
  once: `execCOMPLETEREQ` in `WAIT_TUP_COMMIT` (`15103-15114`) [V] finds it
  set.
- Not written for `AC_NR_COPY` and `AC_IGNORED` (DI-10); their reservation
  is released at COMPLETE.

### X4.6 Primary local commit moved to COMPLETE (M, 8 pd)

| Function | Today | Durable (`OP_DURABLE`) |
|---|---|---|
| `commitReqLab`, `DblqhMain.cpp:15267-15273` | seq 0 or `AC_NR_COPY` → `localCommitLab` [V] | seq 0 (not `AC_NR_COPY`) → `commitReplyLab`; `AC_NR_COPY` unchanged |
| `handle_queued_log_write`, `921-927` | same decision [V] | same change |
| `execCOMPLETE`, `15004-15017` | seq 0 → `completeTransLastLab` [V] | seq 0 → set `OP_LOCAL_COMMIT_AT_COMPLETE = 0x800`, `localCommitLab` |
| `execCOMPLETEREQ`, `15120-15135` | seq 0 → `completeTransLastLab` [V] | same as `execCOMPLETE` |
| `tupcommit_conf`, `15552-15615` | at `15578`: seq 0 or `AC_NR_COPY` → `commitReplyLab`; the following `seqNoReplica == 0` test is unreachable [V] | test `OP_LOCAL_COMMIT_AT_COMPLETE` first → `completeTransLastLab` (COMPLETED, or COMPLETECONF through `completeUnusualLab` when the request came as COMPLETEREQ) |

- The flag is needed because `transactionState` is overwritten with
  `WAIT_TUP_COMMIT` (`15414`) [V].
- Backups already local-commit at COMPLETE, so the multi-op-row and
  disk-page paths are exercised today on backups [I].
- **Reads** in a durable transaction keep releasing their S-locks at
  COMMIT on the primary; L is about logged operations (DI-9, open
  question).
- Side effects to test: detached triggers (SUMA, binlog, backup log) fire
  one round later; the lock-free unique-index base read sees
  `ZTUPLE_NOT_YET_COMMITTED_ERROR` longer (existing EI 5160,
  `DblqhMain.cpp` in `execCOMMIT`) [V].

### X4.7 Late ack on every path (S, 1 pd)

X4.1 covers the normal path, X1 the takeover. Audit the other TCKEYCONF,
TC_COMMITCONF and TCKEY_FAILCONF senders; `ndbassert(!TF_DURABLE)` where
`sendApiCommitSignal` would send.

### X4.8 Rule F in TC, normal path (M, 6 pd)

- **Trigger.** `timeOutFoundLab`, states CS_COMMITTING and CS_COMMIT_SENT
  (`DbtcMain.cpp:12033-12069`) [V], reached at once after a participant
  failure through `nodeFailCheckTransactions` (`13396`, which forces
  `ZNODEFAIL_BEFORE_COMMIT` for transactions with the failed node in
  `m_transaction_nodes`) [V]. Also the parallel state CS_WAIT_COMMIT_CONF.
- **Decision.** If `TF_DURABLE` and a node of `m_transaction_nodes` has
  failed: new setup type `ZABORT_AFTER_COMMIT_SETUP = 4`
  (`Dbtc.hpp:137-139`) [V] instead of `ZCOMMIT_SETUP`. Only a failure of a
  non-participant keeps the COMMITREQ path of today.
- **Was a COMPLETE sent?** TC knows from the ApiConnect state: CS_COMMITTING,
  CS_COMMIT_SENT, CS_WAIT_COMMIT_CONF → none; CS_COMPLETING,
  CS_COMPLETE_SENT, CS_WAIT_COMPLETE_CONF → yes (normal ZCOMPLETE_SETUP).
  With TF_LATE_COMMIT, `copyApi` parks the user record with timer 0 and
  cleared `m_transaction_nodes` (`8451-8503`) [V], so only the copy record,
  which carries the real state, is found.
- **Fail data.** `setupFailData` (`16420-16530`) [V] maps OS_PREPARED and
  OS_COMMITTING to Prepared and OS_COMMITTED to Committed, as for
  ZCOMMIT_SETUP.
- **Abort.** A variant of `toAbortHandlingLab` (`15126`) sends ABORTREQ
  with the after-commit flag (X4.10) to every live replica with status
  Prepared or Committed; ABORTCONF as today; the API gets TCROLLBACKREP
  with `ZNODEFAIL_BEFORE_COMMIT` (open question Q2).
- **GCP.** After DIVERIFYCONF the ApiConnect is linked to a GcpRecord
  (`commitGciHandling`, `7825`) [V]. No abort follows that point today, so
  the abort path never unlinks. The F path must call `handleGcp`
  (`9415`) [V] or GCP_TCFINISHED never comes (DI-6).
- Late COMMITTED/COMMITCONF after the switch are ignored by
  `setup_fail_data`, as today.

### X4.9 Rule F in takeover (M, 6 pd)

- `initApiConnectFail` (`16139`) and `updateApiStateFail` (`16540`) [V]
  record, per transaction, the durable flag and opCount from Committed
  reports (X4.3), and count distinct logged write ops reported.
- `completeTransAtTakeOverDoOne` (`14678`), durable transactions only:

| State | Today | Durable |
|---|---|---|
| CS_FAIL_PREPARED | abort | abort |
| CS_FAIL_COMMITTING (some Prepared) | COMMITREQ, then complete | **abort after commit** (no COMPLETE can have been sent: TC sends COMPLETE only after every COMMITTED; a sibling in `LOG_COMMIT_WRITTEN_WAIT_SIGNAL` reports Prepared but has not had its COMMIT signal) |
| CS_FAIL_COMMITTED | ack, complete | complete + ack after (X1) if a COMPLETE was sent; otherwise **abort after commit** |
| CS_FAIL_COMPLETED (markers only) | ack | ack |

- **COMPLETE sent** iff (a) the number of distinct logged write ops reported
  is less than opCount, or (b) a reported write op has no report from a
  replica on a live node (`failData` still InvalidStatus for a live
  `tcNodedata[i]`). Both mean an op record was freed, which happens only at
  COMPLETE (`cleanUp` in `completeTransNotLastLab`/`completeTransLastLab`,
  `15654-15688`) [V].
- Aborts answer the API with TCKEY_FAILREF (path exists, CS_FAIL_ABORTED,
  `14754-14768`) [V].
- A transaction re-opened into an old GCI by the takeover (`commitGciHandling`
  "Reopening GCI", `7846-7871`) and then aborted must be unlinked (DI-6).
- Race to verify: an in-flight COMPLETE from the failed TC executed after
  the LQH_TRANSREQ scan passed that op (DI-7).

### X4.10 Rule F in LQH: abort from the committed state (M, 5 pd)

- `execABORTREQ` (`DblqhMain.cpp:16310`) [V]: length 7 with
  `flags & ABORT_AFTER_COMMIT` sets new `OP_ABORT_AFTER_COMMIT = 0x2000`.
- `abortStateHandlerLab` (`16714`) [V] with that flag:

| State | Today | With `OP_ABORT_AFTER_COMMIT` |
|---|---|---|
| PREPARED | `abortCommonLab` | same; no ABORT record needed beyond today's |
| `LOG_COMMIT_WRITTEN_WAIT_SIGNAL` | only `NEW_FROM_TC` allowed (`16738-16754`) [V] | the COMMIT record exists (sibling's loop, persisted by its barrier): write ABORT `AF_AFTER_COMMIT` + barrier, then `abortCommonLab` |
| COMMITTED | only `NEW_FROM_TC` (`16864-16874`) [V] | same as above |
| `WAIT_TUP_COMMIT`, `LOG_COMMIT_QUEUED` | dirty/simple only | `ndbrequire`: a durable op local-commits only at COMPLETE, and queued commit logs do not occur on PMEM |

- `writeAbortLog` (`43542`) gets the flag argument; barrier before
  `abortCommonLab` (`16903`), so before ACC_ABORTREQ releases the lock and
  before ABORTCONF.
- TUP state is still `TRANS_STARTED` after `TUP_WRITELOG_REQ` (asserted in
  the loop, `DbtupCommit.cpp:261`) [V], so TUP's normal abort applies; the
  row was never TUP-committed because of L.
- `abortCommonLab` calls `remove_commit_marker` (`16908`, `15832`) [V], so
  "marker alone ⇒ commit" still holds.
- LQH_TRANSREQ reporting (`NEW_FROM_TC`) is unchanged except the opCount
  word. Iteration 1 persists synchronously, so the "waiting for sync"
  state of `research_commit_protocol.md` §6.2 does not exist until X8.2.

### X4.11 Failed API node id held back (S, 3 pd)

- `Qmgr::execAPI_FAILCONF` (`QmgrMain.cpp:5768`, failure handling done at
  `5797`) [V]: record `m_api_fail_gci[node]` = current gci_hi, read from
  DIH directly (same thread; QMGR already calls DIH by `EXECUTE_DIRECT` for
  BLOCK_COMMIT_ORD, `7433`) [V].
- `execAPI_REGREQ` (`6623`) [V]: after the ZFAIL_CLOSING check (`6651`) [V],
  if durable is active and the newest restorable GCI < `m_api_fail_gci[node]
  + 1` (DI-5), ignore the request as the ZFAIL_CLOSING path does; the API
  retries. Log once per node.
- Cost: a restarted API process waits up to about two GCP intervals before
  it can use the same node id.

### X4.12 GCP and epochs (S, 1 pd)

No GCP change: LQH persists by itself, so no wait depends on a GCP of the
transaction's own GCI (`research_commit_protocol.md` §1 item 8). Test that
epochs and the GCP-stop monitor (`checkGcpStopLab`, `DbdihMain.cpp:24281`)
stay quiet under load.

### X4.13 Dirty writes (S, 2 pd)

See DI-1. Implement the chosen variant: either TC turns dirty writes into
normal writes when durable is active, or LQH writes PREPARE, COMMIT
(`CF_DURABLE`, opCount 0) and COMPLETE with a new flag `CPF_SELF` and one
barrier (#4). LQH needs to know that durable is active for this (X7.2,
GCP_SAVEREQ flag; interim: the start-time config).

### X4.14 Tests (M, 10 pd)

- Unit-level: packed signal verify with code 8; COMMIT record fields.
- MTR/ATRT with error inserts (§12.2): crash after COMMIT persisted and
  before COMMITTED (5180); after COMPLETE persisted and before local commit
  (5181); delayed COMPLETE at the primary with concurrent READ_COMMITTED and
  locking readers (5183, checks L); node failure in COMMIT phase (F);
  TC crash with half the COMMITs sent (8321) and after the first COMPLETE
  (8322); crash during ABORT after commit (5184).
- The ledger under node failures: every acked commit survives node
  failures (no full crash) — regression of today's guarantee.
- The `daily-basic` lists with `DurableCommits=1` in a test mode, run by
  the pusher before pushing commit-path changes.

**Order inside X4:** X4.1 → X4.2 → X4.3 → X4.5 → X4.4 → X4.6 → X4.7 →
X4.10 → X4.8 → X4.9 → X4.11 → X4.13; X4.12 and X4.14 alongside.

**Risks:** the hottest commit code changes (`tupcommit_conf`, queued-log,
parallel and takeover paths); the abort-after-commit path is new in LQH
and TC; longer lock hold on hot rows (measured in X8.3).

---

## 5. X5 — Restart phases 1–3

**Goal.** A cluster restart with every node starting restores every
acknowledged durable commit, as whole transactions, with identical
replicas, and raises the restorable GCI to G'.

**Exit criteria.**
- Ledger: zero losses after kill -9 and after emulated power loss, all
  nodes starting, 100+ iterations.
- A crash at each SR step (EIs 5186–5189, 7262) followed by a new SR gives
  the same verdicts.
- The next SR after a durable SR works with no new traffic (R = G') and
  with traffic.
- Partial SR in durable mode is refused until X6 (X5.8).

### X5.1 Phase-2 parameters (S, 2 pd)

- `START_RECREQ` (`StartRec.hpp:48`, length 6 plus `sr_nodes`) [V], sent
  by `sendSTART_RECREQ` (`DbdihMain.cpp:468`) [V], gets: g (sysfile
  `durableGci`, X5.7), `durableTail =
  (g != 0 && R >= g - 1)` (plan §2.2), and a section with the node-group
  of every SR node (for the fallback, X5.5).
- `Dblqh::execSTART_RECREQ` (`DblqhMain.cpp:37619`) [V] stores them. The
  round-0 scan starts after this signal (UNDO, TSMAN, then `startExecSr`),
  so the values are known in time [V per research §5.2].

### X5.2 Phase 1 without invalidation of the durable tail (M, 5 pd)

In `execSr` (`DblqhMain.cpp:38962`) [V], when `durableTail`:

| Record | Today | Durable tail |
|---|---|---|
| COMMIT, `gci_hi > crestartNewestGci` (`39108-39132`) | rewritten to `ZINVALID_COMMIT_TYPE` [V] | `CF_DURABLE` set (assert gci_hi ≥ g): step A (X5.3). Not set: `RF_INVALIDATED` store (S6) |
| COMMIT already `RF_INVALIDATED` | — | skip; never queued or counted (repeatability) |
| `ZCOMPLETED_GCI_TYPE` = `logLastGci` (`39304-39345`) | new head, stop [V] | continue to E |
| `ZNEXT_MBYTE_TYPE` in the stop mbyte (`39253-39283`) | crash "end of log wo/ having found last GCI" [V] | no crash; the scan ends at E |

- `srGciLimits` (`38536`) and `srLogLimits` (`38671`) [V]: round 0 stops at
  the mbyte of E. The start mbyte stays as today (for `logStartGci =
  R + 1`); store the start position per part for step B.
- COMMITs with GCI ≤ R are executed as today.
- Phase 2 selects records by `CF_DURABLE`, with GCI ≥ g as a cross-check
  (DI-1).

### X5.3 Step A: the hash table (M, 6 pd)

- Per log part, a hash table keyed by transid; each entry holds a FIFO of
  COMMIT positions `(fileNo, pageNo, pageIndex)`, the opCount, the gci_hi,
  and a count. Entries from a pool allocated at SR (transaction memory is
  unused during SR [I]; Q11).
- COMMIT (durable, tail): append. COMPLETE with an entry: execute the
  queued COMMITs in FIFO order: copy the COMMIT from the mapping,
  `readCommitLog` (`42763`), `checkIfExecLog` (`40928-40955`), read the
  PREPARE through its reference, `execLogRecord` (`39478`) [V], with the
  record's gci_lo. Remove the entry. COMPLETE without entry: ignore. COMPLETE
  with `CPF_SELF`: execute only its own COMMIT (DI-1). ABORT
  `AF_AFTER_COMMIT`: move the entry's COMMITs to the part's abort list.
- Keep per part `maxGciExecuted`.
- Drop the plan's "COMMIT after COMPLETE of T ⇒ crash" check: the preferred
  variant has no memory of executed transids, and with transid reuse it
  would fire falsely (DI-2).
- The scan executes one COMMIT at a time as today; on PMEM the PREPARE read
  is a copy from the mapping, so no FSREADREQ round trip.

### X5.4 Step B: the exchange (L, 10 pd)

**Participants and routing.** Every DBLQH worker of every SR node.
Messages are aggregated per node in `DblqhProxy`, the pattern of
EXEC_SRREQ/EXEC_SRCONF (`DblqhProxy.cpp:1990-2096`: collect from all
workers, send to `NodeReceiverGroup(DBLQH, sr_nodes)`, fan out to workers)
[V]. Counts are per node in the fallback anyway, so verdicts are the same
as with part-to-part messages (DI-3).

| Step | From → to | Signal | Content |
|---|---|---|---|
| B1 | worker → own proxy | `SR_TAIL_INDOUBT_REP` | the worker's in-doubt set: `(transid1, transid2, count, gci_hi)`, counts summed over its parts |
| B2 | proxy → proxies of all SR nodes (itself included) | `SR_TAIL_INDOUBT_REP` | the node's merged set, in batches, `last` flag and total |
| B3 | proxy → own workers | `SR_TAIL_INDOUBT_REP` | each received batch, unchanged |
| B4 | worker (after `last` from every SR node) | — | rescan own parts from the stored start to E for COMPLETE and `AF_AFTER_COMMIT` ABORT of T ∈ U, counting a record only after a durable tail COMMIT of T in the same part (DI-2) |
| B5 | worker → proxy → all proxies → all workers | `SR_TAIL_HIT_REP` | `(transid1, transid2, kind = COMPLETE | ABORTED)` |
| B6 | worker → proxy; proxy (all workers done) → all proxies; proxy (all nodes done) → workers | `SR_TAIL_DONE_REP` | node, `maxGciExecuted` of step A, hits and entries sent |

- **U** is the union over all nodes, with a count per node. Every worker
  ends with the same U and the same hit set.
- "A COMPLETE of T in the part's own in-doubt set ⇒ corrupt log": kept,
  with the DI-2 rule, so it fires only after a tail COMMIT of T in that
  part.
- **Ordering.** Signals between one pair of block instances at JBB keep
  their order [I]; across nodes, multi-socket transporters pick the socket
  by receiver instance "to avoid any risk of changed signal order"
  (`Multi_Transporter.hpp:47-58`) [V]. The proxy forwards in arrival order
  and sends DONE only after all its workers' DONEs, so at every worker all
  hits precede the final DONE.
- **Batches, not fragmented signals.** In-doubt sets can reach
  ~100k entries per node (16 bytes each). Send explicit batches of one
  section each, numbered, with totals checked at DONE. Fragmented signals
  are dropped silently when the fragment hash is full
  (`claude_files/data_node_security/fragmented_signal_security.md`), which
  would hang the SR.
- **Place in the SR.** Inside round 0, after the worker's scan has reached
  E in all its parts, before `execLogComp` (`40260`) and `srPhase3Comp`
  (`40409`) send EXEC_SRCONF [V]. The existing EXEC_SRCONF barrier and
  phase 4 follow unchanged. A node failure during the SR stops the SR as
  today (`NdbcntrMain.cpp:4187-4209` per research), so the exchange needs
  no failure handling.

### X5.5 Step C: verdicts (M, 5 pd)

For each T in the worker's own in-doubt sets:

| Condition | Verdict |
|---|---|
| a COMPLETE hit for T | commit |
| no ABORTED hit, and for every node group all SR nodes of it report the same count (absent = 0), and the counts of the node groups add up to opCount (from T's COMMIT records; assert they agree) | commit (fallback, D5) |
| otherwise | abort |

- Commit: execute the queued COMMITs FIFO. In-doubt transactions of one
  part never share a row (§6 of the plan: a later writer needs the
  earlier one's COMPLETE in that part), so their order does not matter
  [I, from the proof].
- Abort: `RF_INVALIDATED` on each COMMIT of T and on the abort list; flush
  per batch, one fence at the end.
- **G'** = max(all `maxGciExecuted` from DONE, gci_hi of every T in U with
  verdict commit). Every worker computes it from the same data (DI-4).
- Counters for ndbinfo: in-doubt, committed by COMPLETE, committed by
  fallback, aborted, time.

### X5.6 Phase 4 and the SR-head record (M, 4 pd)

`readSrFourthPhaseLab` (`40474`) [V], durable tail:

- no head move back and no `invalidateLogAfterLastGCI` (`39534`);
- at E (after phase 1's zeroing): FILLER to the W boundary (W7), then
  SR_HEAD (R, G', `m_restart_seq`) and `COMPLETED_GCI(G')`, `redoPersist`;
  the head follows them; the tail from keepGci as today;
- `cnewestGci = cnewestCompletedGci = G'` (instead of R, `40499-40515`) [V
  per research];
- `c_backup->setRestorableGci(G')` (today R at `37661`, per research), so
  Backup's `ndbrequire(MaxGciWritten <= m_newestRestorableGci)`
  (`Backup.cpp:15204`) holds for the SR LCP.

### X5.7 Phase 3: raise the restorable GCI to G' (L, 8 pd)

- `START_RECCONF` (`StartRec.hpp:75`, length 2) [V] → length 3 with G';
  the LQH proxy checks all workers agree.
- DIH master, `execSTART_RECCONF` (`DbdihMain.cpp:21267`) [V], when the
  last arrives: check all nodes agree on G'; then `COPY_GCIREQ` with new
  reason `RESTART_DURABLE = 6` (`CopyGCIReq.hpp:52-59`) [V]:
  `newestRestorableGCI = G'`, `lastCompletedGCI[n] = G'` for SR nodes, the
  SR-head fields. On every node (`execCOPY_GCIREQ`, `961`; the RESTART case
  at `1088-1120` is the model) [V]: `crestartGci`, `c_newest_restorable_gci`,
  `m_old_gci = G' << 32`, `m_current_gci = (G' + 1) << 32`. Then the master
  continues to NDB_STARTCONF.
- The SR LCP (phase 5) and the first GCP (phase 6) then come after the
  raise; the forced gci_hi switch makes the first user GCI G' + 2 (per
  research §9.1).
- **Sysfile v3** (`Sysfile.hpp`, packed format v2 today at `60-72`) [V]:
  `durableGci` (g), `srHeadR`, `srHeadG`, `srHeadSeq`;
  `pack/unpack_sysfile_format_v3`; read in `readGciFileLab` (`9937`) [V].
- **NDBCNTR:** `m_max_completed_gci` and the local sysfile
  `m_max_restorable_gci` = G' where they are written after an SR today [I,
  locate in X5.7].
- **DIH replica intervals.** The open interval created by `resetReplicaSr`
  with `createGci = R + 1` (`20465`, per research) stays right: every SR
  replica executed and keeps the REDO for (R, G'] [I]. Check in the next-SR
  test that `findLogNodes` and the LCP validity tests accept the SR LCP.
- **LCP-restore bound** stays R (`crestartNewestGci` at START_FRAGREQ).
- Known test to adapt: `test/ndbapi/testRestartGci.cpp:262` asserts no rows
  newer than the restart GCI (per research).

### X5.8 Guard until X6 (S, 1 pd)

With a durable tail, NDBCNTR refuses partial and partitioned SR (all
configured nodes must start), logging why. Even then, a node failure in
the tail GCI is not handled until X6; the X5 ledger runs have no node
failures before the full crash.

### X5.9 Schema changes in the tail (S, 2 pd)

Tests: create table + writes, drop table, add column, add partition, all
inside the tail GCI, then crash. Records of dropped or changed tables are
filtered by `checkIfExecLog`'s schema-version test [V per research]; check
that no transaction ends half applied.

### X5.10 Tests (M, 8 pd)

Ledger runs (X3) with kill -9 and power loss; SR crash points (5186–5189,
7262); forced fallback (5185 skips COMPLETE records, so all verdicts come
from counts); next SR at R = G'; `redoLogReader` on the result.

**Order inside X5:** X5.1 → X5.2 → X5.3 → X5.4 → X5.5 → X5.6 → X5.7 →
X5.8, X5.9 → X5.10.

**Risks:** UNDO log space during a longer REDO run (research §6); memory
of the step-A table under heavy in-flight load; signal volume of step B.

---

## 6. X6 — Node failures

**Goal.** A node failure in the tail GCI, an unsafe device shutdown, and a
partial SR give the guarantees G1–G3, or a refusal to start with a clear
reason.

**Exit criteria.** The D3, D4, D5 scenarios of plan §5.4–5.5 pass; partial
SR allowed again in durable mode; stale nodes rejoin by node restart with
identical replicas.

### X6.1 The node-failure file (M, 5 pd)

- **Owner:** QMGR. **Location:** under the first `FileSystemPathRedoLog`
  path, beside the REDO, not in a log part, e.g. `D_NF/nodefail.dat` [I,
  Q10]. Mapped through NDBFS with `OM_MAP_SYNC` in QMGR's STTOR (`723`) [V],
  before the node can take part in a failure protocol.
- **Layout:** header (magic, version, own node id, checksum) and, per
  failed node id, two 64-byte slots `{seq64, failedNodeId, gci_hi, failNo,
  checksum}`, written alternately as in E10. Each checksum is the low 32
  bits of XXH3 over the other fields. Only the highest failure GCI per
  node matters (stale iff > R), so a slot per node replaces the plan's
  ring (DI-12). About 18 KB.
- **Write:** in `execCLOSE_COMCONF` (`7559`) just before PREP_FAILCONF
  (`7636`) [V], for each node in `cprepFailedNodes`: `gci_hi = max(current,
  new if a GCP_PREPARE is pending)` read from DIH; store the line, one
  `sfence`. Commits are already blocked by BLOCK_COMMIT_ORD (`7433`) [V].
- With durable active and no mapping: refuse to start (D8).
- Helper class `NodeFailFile` (`blocks/qmgr/`), read at start by NDBCNTR
  through the QMGR block object (same thread) [I].

### X6.2 Records with the start request (S, 2 pd)

`CNTR_START_REQ` (`CntrStart.hpp:47`, length 4) [V], sent at
`NdbcntrMain.cpp:2172-2178` [V]: a section with `(failedNodeId, gci_hi,
failNo)` records and a flags word (bit 0: unsafe shutdown, X6.7). The
master stores them per starting node.

### X6.3 Stale classification (S, 2 pd)

In `update_withLog` (`NdbcntrMain.cpp:2721-2745`) [V], after today's GCI
rule and only with a durable tail: X is stale if some starting node's
record has X with gci > R, or X reported an unsafe shutdown. Move X from
`m_withLog` to `m_withLogNotRestorable`: it takes no part in the SR and
joins by node restart afterwards (plan §5.4). Log each decision with its
evidence.

### X6.4 At least one non-stale node per node group (S, 2 pd)

- `trySystemRestart` runs `checkNodeGroups(m_withLog)` after
  `update_withLog` (`2770-2771`) [V]. Lose → wait for more nodes, as today.
- With all nodes present, Lose hits `ndbrequire(!allNodes)` (`2780`) [V]:
  replace by `progError` naming the node group and the stale nodes (DI-8).
  Forced start to R is not decided (Q3).
- A single node group cannot detect a stale node whose only witness is
  absent (plan §5.5); document it.

### X6.5 Partial SR and the fallback (S, 2 pd)

Remove the X5.8 guard. The fallback (X5.5) already uses the SR node set
and the node-group map from START_RECREQ.

### X6.6 Stale node rejoins (S, 1 pd)

A stale X with `lastCompletedGCI = R` replays to R and gets rows with
GCI > R by copy (`DbdihMain.cpp:9351-9366`, per research); its REDO beyond
R is zeroed as in any NR (`pmem_redo_recovery.md` §5). Test with the
replica check.

### X6.7 Unsafe shutdown (S, 1 pd)

Step 1 records the dirty-shutdown count (E17). X6 turns "count changed
since last start" into the stale flag of X6.2. The device-specific meaning
is verified in P6 (E17).

### X6.8 Tests (M, 5 pd)

- D3: X fails, transactions run on Y, full crash before the next GCP save,
  all nodes start: X stale, rejoins, replicas identical, no loss.
- D4: two node groups, X fails, T writes both groups, crash, Y absent:
  the SR waits (or stops with the message when all others are present).
- D5: COMPLETE only on a node that does not start: fallback commits.
- Negative: EI 991 skips the record; the replica check must find the
  divergence (shows the test can see the bug).
- Crash between the record and PREP_FAILCONF (990).

**Order inside X6:** X6.1 (can start after step 1, in parallel with X4) →
X6.2 → X6.3 → X6.4 → X6.7 → X6.5 → X6.6 → X6.8.

---

## 7. X7 — Online activation

**Goal.** Durable commits are turned on online at a GCI g; the guarantee
starts after the GCP save of g − 1; turning them off takes a cluster
restart; the state is visible in ndbinfo; only clusters where every data
node supports it can activate.

**Exit criteria.** Activation under ledger load: losses allowed only for
transactions before arming, none after; master failure during activation
handled; a node restart after activation works; activation refused with a
file-mode node or an old version.

### X7.1 Config `DurableCommits` (S, 3 pd)

- `ConfigInfo.cpp` entry: bool, default false, data node; same value
  expected on all nodes (warn on mismatch). `CFG_DB_DURABLE_COMMITS` in
  `mgmapi_config_parameters.h`.
- Start check: `DurableCommits=1` needs `RedoLogMode=pmem` on DAX, else
  refuse to start (D8; step 1's E17 checks). A test mode (`emulated`,
  `nodax`) also allows it, on DRAM (Q-A1): the node logs that commits
  survive a crash of the data-node processes but not an OS crash or a
  power loss.
- Online: `Cmvmi::execSET_CONFIG_PARAM_REQ` case
  (`claude_files/set_config_param/howto_add_new_param.md`): value 1 →
  `DURABLE_ACTIVATE_REQ` to the local DIH; value 0 → accepted, logged as
  "takes effect after a cluster restart" (Q6); `CommandInterpreter.cpp`
  `executeSet`.
- Not through DUMP_STATE_ORD: it is External scope, so an API node could
  send it (`SignalScopes.hpp`) [V].

### X7.2 Activation through the GCP protocol (M, 7 pd)

- Each DIH forwards `DURABLE_ACTIVATE_REQ(node, redoMode, version)` to the
  master. The master waits until every alive data node has asked, checks
  `ndbd_support_durable_commits` for all (min version as in
  `check_enable_micro_gcp`, `DbdihMain.cpp:17978`) [V], PMEM mode on
  all, and no node or system restart in progress (Q7). Else REF.
- **Choosing g.** At the next gci_hi switch in `startGcpLab`
  (`18172-18199`) [V]; force one by invalidating
  `m_gcp_save.m_master.m_start_time`. g = the new gci_hi. GCP_PREPARE
  (`GCP.hpp:39`, length 3) [V] gets a flags word with `GCP_ACTIVATE_DURABLE`.
- **Participants.** `execGCP_PREPARE` (`18632`) stores the pending g;
  `execGCP_COMMIT` (`18724`) sets `m_durable_gci = g` under the write lock
  together with `m_current_gci` (`18808-18813`) [V]. From then every
  DIVERIFY with gci_hi ≥ g returns the durable flag on every node.
- **Arming.** The GCP save of g − 1 (`GCP_SAVEhandling`, `18578`) [V]
  writes `durableGci = g` into the sysfile in the same COPY_GCIREQ. On
  COPY_GCICONF (`19272`) [V] the state is ARMED (event, ndbinfo).
  `GCP_SAVEREQ(g − 1)` carries a flag so every LQH knows durable is active
  before arming (for dirty writes, X4.13).
- **Master takeover.** `MASTER_GCPREQ/CONF` (`11312`, `11493`) [V] carry
  the pending and active g; the new master resumes or restarts activation.
- **Node restart after activation.** The starting node gets g in the
  sysfile (COPY_GCIREQ RESTART_NR) and refuses to start if it is not on
  PMEM or too old.
- `DURABLE_ACTIVATE_CONF/REF` back to the requester and to CMVMI's
  SET_CONFIG_PARAM_CONF/REF.

### X7.3 Deactivation by cluster restart (S, 2 pd)

At SR the sysfile g governs the tail (X5). In the RESTART_DURABLE
COPY_GCIREQ (X5.7) the master writes `durableGci = 0` if its config is 0,
else keeps g. Config 1 with sysfile 0: activate through X7.2 at the first
GCP after the SR.

### X7.4 The R ≥ g − 1 rule (S, 1 pd)

X5.1 computes `durableTail`. Records with R < GCI < g have no
`CF_DURABLE` and are invalidated as today. Test: crash between GCP_COMMIT(g)
and the save of g − 1 (EI 7261).

### X7.5 ndbinfo (S, 3 pd)

Tables in §12.3, defined in `src/common/debugger/NdbinfoTables.cpp` [V
file], served by `Dbdih::execDBINFO_SCANREQ` (`7843`) [V] and DBLQH; views
in the ndbinfo SQL generator.

### X7.6 Version gating (S, 1 pd)

`ndbd_support_durable_commits(version)` in `include/ndb_version.h.in`
(pattern of `ndbd_support_ttl_ring_buffer`, `1693`) [V]. All new signal
formats are sent only when durable is active, so a mixed-version cluster
never sees them; activation and node join check the version.

### X7.7 Tests (M, 5 pd)

Activation under load; activation with a file-mode node (REF); master
crash after GCP_PREPARE(activate) (7260); crash before arming (7261); NR
after activation; deactivation through SR; ndbinfo values.

**Order inside X7:** X7.6 → X7.1 → X7.2 (can start after X4.1) → X7.4 →
X7.3 (after X5.7) → X7.5 → X7.7.

---

## 8. X8 — Performance and documentation

**Goal.** Make the fence cost acceptable at high write rates, publish
numbers, extend the tools, document the feature.

**Exit criteria.** The adaptive scheme passes the full durable suite with
the E7 debug check; benchmark report; `redoLogReader` shows the durable
records; rondb-docs chapters merged.

### X8.1 One barrier per `execPACKED_SIGNAL` (M, 4 pd)

`Dblqh::execPACKED_SIGNAL` (`DblqhMain.cpp:6329`) [V] handles up to about
8 COMPLETEs or 5 COMMITs per signal (25 words). Park each durable op after
its record is appended, run one `redoPersist` per dirty part at the end,
then resume the parked ops (their sends and local commits). The Q1 rule
holds: the dependent signals wait for the fence.

### X8.2 One fence per log part per scheduler round (L, 8 pd)

- The scheduler calls every registered block's SEND_PACKED after the job
  buffers each loop (`sendpacked`, `vm/mt.cpp:6677`; calls at `7888-7892`,
  `8266-8269`, `6703-6719`; registration `1745-1770`) [V].
- At the start of `Dblqh::execSEND_PACKED` (`DblqhMain.cpp:6511`) [V]: for
  each part in a per-LDM `m_redo_dirty_parts` mask, lock, `redoPersist`,
  unlock; resume parked ops (bounded, rest by CONTINUEB). Their COMMIT,
  COMMITTED, COMPLETE and COMPLETED go into DBLQH's own `lqh_pack` and
  `tc_pack` containers, flushed in the same call [V]. Non-temporal copies
  are issued at append time ("flush early, fence late").
- New state `WAIT_REDO_PERSIST`: `abortStateHandlerLab` reports it as
  Committed only after the fence (research §6.2); rule F waits for it;
  `DblqhState.hpp` and `DblqhStateDesc.cpp` for ndbinfo.
- Unpacked sends (COMMITCONF, COMPLETECONF, takeover answers) check
  `m_redo_end_lsn` and persist synchronously.
- Adaptive rule: persist at once when the round has one parked op.
- Config `RedoPersistScheme = immediate | adaptive`, default immediate
  until X8.3 shows the gain.

### X8.3 Benchmarks (M, 8 pd)

| Benchmark | Measures |
|---|---|
| flexAsynch / ndb_bench key writes, 1–4 replicas | ops/s per LDM, fences per op (step-1 counters), LDM CPU in `sfence` |
| sysbench / DBT2 through mysqld | commit latency p50/p99; READ_BACKUP and not |
| W3 hot row (X3.1) | row throughput, lock hold, error 266 counts |
| SR with large tails | step A/B/C time vs in-doubt count; signal volume |
| Parallel vs linear commit for durable transactions | 2R vs 2 serial persists (Q12) |

Configurations: file REDO; PMEM without durable; durable immediate;
durable adaptive. Hardware: CXL 2.0 PMEM for numbers, QEMU CXL for the
path, `memmap=` for software cost only.

### X8.4 `redoLogReader` (S, 3 pd)

`src/kernel/blocks/dblqh/redoLogReader/{reader.cpp, records.cpp,
records.hpp}` [V]. Step 1 (S6) teaches it the format; X8 adds: COMPLETE
records with `CPF_SELF`, COMMIT `CF_DURABLE`/`RF_INVALIDATED`, transid,
gci_lo, opCount, ABORT `AF_AFTER_COMMIT`, SR_HEAD; `--transid` to follow
one transaction; `--simulate-sr R g` to list per part what step A would
execute and leave in doubt (support tool).

### X8.5 Documentation in rondb-docs (M, 6 pd)

Edit `latex/<slug>.tex`, regenerate with `./update-md <slug>`, commit both
(user rule). Chapters that need content:

| Chapter | Content |
|---|---|
| `rondb_checkpoints_global_redo` | REDO on PMEM, COMMIT/COMPLETE records, persist rule, SR phase 2 and 3 |
| `rondb_resiliency_model` | G1–G3, when they hold (armed, all or partial SR), stale nodes, D4 |
| `rondb_failure_protocols` | Rule F, node-failure file, API node-id hold-back |
| `rondb_nonblocking_2pc`, `rondb_concurrency_control` | Local commit at COMPLETE, lock hold, ack timing |
| `rondb_advanced_fs_config`, `rondb_hardware_setup` | `FileSystemPathRedoLog`, CXL PMEM, `memmap=` for tests |
| `rondb_advanced_config`, `rondb_config` | `DurableCommits`, `RedoLogMode`, `RedoPersistScheme` |
| `rondb_online_config` | SET DurableCommits, arming, deactivation |
| `rondb_ndbinfo` | New tables (§12.3) |
| `rondb_startup_phases`, `rondb_monitoring_restarts` | SR log lines for phases 2 and 3, stale decisions |
| `rondb_upgrade` | Version gate |
| `rondb_tools` | `redoLogReader` options |
| Release notes of the shipping version | Feature summary |

A new chapter `durable_commits` may hold the overview the others link to.

**Order inside X8:** X8.1 → X8.2 → X8.3 (needs X8.2) ; X8.4 any time after
X5 ; X8.5 last.

---

## 9. Dependency graph and critical path

```
X1 ─────────────────────────────────────────────── (independent)

X2 ──► X3.1-3.3 ──► X4 ──────────► X5 ──────────► X6.2-6.8 ──► X7.3,7.7 ──► X8.3, X8.5
 │                   │  └► X3.4 (TLA+, before X5.4)   ▲
 │                   ├──► X7.1, X7.2 (DIH activation) ─┘ (joins at X7.3)
 │                   └──► X8.1, X8.2 (adaptive) ──────────────────► X8.3
 └──► X6.1 (node-failure file, needs S3 mapping)
```

- **Critical path:** X2 → X3.1–3.3 → X4 (X4.1–4.10) → X5 (X5.2–5.7) →
  X6.2–6.5 → X7.3 → X8.3/X8.5. About 5 months for one person after step 1
  (X3 3 weeks, X4 10, X5 10, X6 2, X7.3 and tests 2); about 3 months with
  two people taking the parallel streams (X6.1, X7.1–7.2, X8.1–8.2, X3.4,
  X1).
- X5.4 should wait for the TLA+ check of DI-1 and DI-2 (X3.4).

## 10. Milestones

| # | After | Demonstrable |
|---|---|---|
| M1 | X1 | READ_BACKUP read-your-writes after TC takeover |
| M2 | X2 + X3 | REDO on PMEM; crash of all nodes and power loss lose nothing ≤ R_gcp; loss above R_gcp measured |
| M3 | X4 | Durable protocol on: rows visible only after COMPLETE is persistent, ack after last COMPLETED, F aborts on node failure; commit latency measured |
| M4 | X5 | **Zero ledger losses after a full crash or power loss with all nodes starting**; repeatable SR |
| M5 | X6 | Zero losses with node failures in the tail GCI and partial SR; clear refusal for D4 |
| M6 | X7 | `SET DurableCommits=1` on a running cluster, armed state in ndbinfo |
| M7 | X8 | Adaptive fencing, benchmark report, docs |

---

## 11. New signals

### 11.1 New GSNs

GSN numbers from 987 (`MAX_GSN = 986`, `GlobalSignalNumbers.h:40`) [V];
coordinate with step 1. Each needs `SignalNames.cpp`, a printer, an
`X(GSN_..., Remote)` entry in `SignalScopes.hpp`, and handlers in the
proxy and worker.

| GSN | Sender → receiver | Content | Scope | Receiver checks |
|---|---|---|---|---|
| `SR_TAIL_INDOUBT_REP` | DBLQH worker → DBLQH proxy (local); proxy → proxies of SR nodes; proxy → workers | node, batch no, flags (last), total; section `(transid1, transid2, count, gci_hi)`×n | Remote | sender block DBLQH; sender node ∈ `m_sr_nodes`; state = phase-2 exchange; section length multiple of 4 and ≤ batch max; batch numbers in sequence |
| `SR_TAIL_HIT_REP` | same route | node, batch no; section `(transid1, transid2, kind)`×n | Remote | as above; kind ∈ {COMPLETE, ABORTED} |
| `SR_TAIL_DONE_REP` | same route | node, maxGciExecuted, entries sent, hits sent | Remote | as above; totals match what arrived |
| `DURABLE_ACTIVATE_REQ` | CMVMI → DIH (local); DIH → master DIH | node, senderRef, redoMode, version, request (activate) | Remote | sender block CMVMI (local) or DBDIH; master only; sender an alive data node |
| `DURABLE_ACTIVATE_CONF` | master DIH → DIH → CMVMI | g, state | Remote | sender is the master DIH |
| `DURABLE_ACTIVATE_REF` | same | error (not all PMEM, version, restart running, already active) | Remote | same |

- **Scope:** all are sent only by data nodes. Remote scope makes the
  receiving node disconnect an API or MGM sender (`VT_SIGNAL_SCOPE_REMOTE`,
  Tier A, `tiered_response_policy.md` §7) [V]. The local hops pass, since
  `checkSignalSender` returns early for the own node (`vm/SimulatedBlock.hpp:2556-2568`) [V].
- **Content checks:** a malformed signal from a data node is a software
  bug; handle it with `ndbrequire`, like EXEC_SRREQ (`DblqhProxy.cpp:2042-2078`)
  [V]. No new ViolationType: Tier B from a data node is escalated to Tier A
  anyway, and during an SR a disconnect fails the SR, which is repeatable.
- DUMP_STATE_ORD is External; it must never trigger activation (X7.1).

### 11.2 Changed signals

| Signal | Change | Package |
|---|---|---|
| PACKED_SIGNAL | code `ZCOMMIT_DURABLE = 8`, 6 words | X4.3 |
| COMMIT (unpacked) | length 6 | X4.3 |
| COMMITREQ | length 10 (opCount, flags) | X4.3 |
| ABORTREQ | length 7 (flag after commit) | X4.10 |
| LQH_TRANSCONF | length 19 (opCount, durable) | X4.3 |
| DIVERIFYCONF (direct and queued) | `theData[4]` durable, length 5 | X4.1 |
| GCP_PREPARE, GCP_COMMIT | flags word (activate g) | X7.2 |
| MASTER_GCPCONF | pending/active g | X7.2 |
| GCP_SAVEREQ | flag "durable active" | X7.2 |
| COPY_GCIREQ | reason `RESTART_DURABLE`; sysfile v3 | X5.7 |
| START_RECREQ | g, durableTail, node-group section | X5.1 |
| START_RECCONF | G' | X5.7 |
| CNTR_START_REQ | node-failure section, flags (unsafe shutdown) | X6.2 |
| TCKEY_FAILCONF | unchanged (Q1) | X1 |

Existing scopes: GCP_PREPARE is Remote already (`SignalScopes.hpp`) [V];
the others keep their current entry or stay Unclassified.

---

## 12. Config, error inserts, ndbinfo

### 12.1 Config parameters

| Name | Type | Default | Restart | Phase |
|---|---|---|---|---|
| `DurableCommits` | bool | false | online on (activation at g); off at the next cluster restart | X4.1 (start-time), X7.1 (online) |
| `RedoPersistScheme` | enum immediate, adaptive | immediate | node restart | X8.2 |
| (step 1) `RedoLogMode`, `FileSystemPathRedoLog` | | | | X2 |

### 12.2 Error inserts (proposed ranges)

Ranges checked unused in `src` and `test` [V]; `ERROR_codes.txt` "Next"
lines are stale (`DBLQH 5155` but 5160 is used) [V]. Step 1 should take
LQH codes below 5180.

| Block | Range | Codes |
|---|---|---|
| DBLQH | 5180–5199 | 5180 crash after COMMIT persisted, before COMMITTED/forward; 5181 after COMPLETE persisted, before local commit; 5182 after local commit, before COMPLETE/COMPLETED; 5183 delay COMPLETE at primary 3 s; 5184 crash after ABORT `AF_AFTER_COMMIT` persisted, before release; 5185 skip COMPLETE records (debug, forces fallback); 5186 SR crash after step A; 5187 during the step-B rescan; 5188 mid-invalidation in step C; 5189 after SR_HEAD, before START_RECCONF; 5190 step-B batch size 1 |
| DBTC | 8320–8339 | 8320 takeover delays COMPLETEREQ 2 s (X1); 8321 crash after half the COMMITs; 8322 crash after the first COMPLETE; 8323 treat the next node failure as a participant failure; 8324 crash takeover TC during the F abort |
| DBDIH | 7260–7279 | 7260 crash master after GCP_PREPARE(activate); 7261 crash after GCP_COMMIT(g), before save of g − 1; 7262 crash during COPY_GCIREQ(RESTART_DURABLE); 7263 delay activation |
| QMGR | 990–998 | 990 crash after the node-failure record, before PREP_FAILCONF; 991 skip the record (negative test) |
| NDBCNTR | 1040–1049 | 1040 report unsafe shutdown; 1041 ignore received node-failure records (negative test) |

### 12.3 ndbinfo additions

| Table | Rows | Columns |
|---|---|---|
| `durable_commits` | one per data node (DIH) | config value, state (off, requested, activating, armed, off-pending), activation GCI g, armed at GCI, last SR: R, G', in-doubt, committed by COMPLETE, by fallback, aborted, phase-2 ms, stale nodes |
| `durable_commit_stats` | one per LDM (DBLQH) | durable ops, COMPLETE records, aborts after commit, persist waits (X8.2), parked ops |
| `node_failure_records` | one per record (QMGR) | failed node, gci_hi, failure no, valid |

Step 1 adds the persist counters per part (E19).

---

## 13. Design issues found

| # | Issue | Evidence | Proposal |
|---|---|---|---|
| DI-1 | **Dirty writes.** (a) A dirty write of T writes PREPARE + COMMIT + COMPLETE at prepare time. In step B its COMPLETE makes another part report "T complete", which commits T's in-doubt normal operations even when some replica lacks their COMMIT: T half applied. (b) Dirty writes are driven by LQH, not by TC's COMMIT flag, and take their GCI from LQH (`DblqhMain.cpp:10314`) [V], so "GCI ≥ g" and "durable" can disagree around activation | `doWritePrepareLog` `13566-13584` [V]; TC drops dirty writes at LQHKEYCONF (`9546`) [V] | Either TC turns dirty writes into normal writes when durable is active, or the COMPLETE of a dirty write gets flag `CPF_SELF`: step A executes only its own COMMIT, step B ignores it, opCount excludes it. Select phase-2 records by `CF_DURABLE`, with GCI ≥ g as a cross-check. LQH learns "durable active" from GCP_SAVEREQ (X7.2) |
| DI-2 | **Step B can see COMPLETE and ABORT records from before the tail.** The rescan starts at the start mbyte, which reaches back into GCIs ≤ R through `logLastPrepRef`. A restarted API that reuses a transid after the hold-back can put an old COMPLETE in range: false "T complete" (half-applied T), or a false "corrupt log" crash when T is in the part's own in-doubt set. Step A's "COMMIT after COMPLETE ⇒ crash" cannot be checked in the preferred variant (no memory of executed transids) and would also fire falsely | `srLogLimits` `38671` [V]; transid = prefix + per-process counter (`Ndbif.cpp:262-284`, `ndb_cluster_connection.cpp:815`) [V] | In the rescan, count a COMPLETE or flagged ABORT of T only if a durable tail COMMIT of T came before it in the same part (a COMPLETE always follows that op's COMMIT in its part). Drop the step-A crash check |
| DI-3 | **Exchange volume.** Part-to-part messages are O(L²) for L parts cluster-wide (48 nodes × 32 parts: 2.4 M messages) | plan §5.2 step B | Aggregate per node in DblqhProxy (X5.4); counts are per node in the fallback anyway, so the verdicts do not change |
| DI-4 | **G' needs global data before phase 4.** Each part writes G' into SR_HEAD, but G' is the max over all parts | plan §5.3 | DONE carries each worker's step-A max; in-doubt entries carry gci_hi; every worker computes the same G' (X5.5) |
| DI-5 | **API hold-back is per data node.** A transaction of the dead process committed through another node's TC can get a GCI one above the local hold-back GCI (failure detection skew, in-flight TCKEYREQ) [I] | `execAPI_FAILCONF` `5768` [V] | Hold back until the GCP save of f + 1 |
| DI-6 | **Abort after `commitGciHandling`.** No abort follows the commit point today, so the abort path never unlinks the ApiConnect from its GcpRecord; GCP_TCFINISHED would never come | `commitGciHandling` `7825`, `handleGcp` `9415` [V] | The F paths call `handleGcp` (X4.8, X4.9) |
| DI-7 | **Takeover: was a COMPLETE sent?** LQH frees the op at COMPLETE. Detection by missing ops (opCount) and missing live replicas works if no COMPLETE from the failed TC is executed after the LQH_TRANSREQ scan passed that op. `checkNodeFailSequence` orders LQH_TRANSREQ after NODE_FAILREP only | `SimulatedBlock.cpp:5313-5340` [V] | Verify that signals received from the failed node are executed before LQH_TRANSREQ (add a test with a delayed COMPLETE); fallback: a "complete seen" bit in the LQH commit-ack marker, with markers on every LDM in durable mode |
| DI-8 | **D4 with all nodes present** crashes the master on `ndbrequire(!allNodes)` | `NdbcntrMain.cpp:2780` [V] | `progError` with node group and stale nodes (X6.4) |
| DI-9 | **Reads under L.** L speaks of "an operation", but reads have no COMPLETE record | plan §3.1 | Keep read-lock release at COMMIT on the primary; confirm (Q5) |
| DI-10 | **`AC_NR_COPY`/`AC_IGNORED` at COMPLETE** (write path Q10). The starting node cannot be in an SR whose tail holds that GCI: it refuses GCP saves until its restart is done, so `lastCompletedGCI` stays below R [I] | `execGCP_SAVEREQ` refusal (research §2.9) | No COMPLETE record for them; `AC_NR_COPY` keeps local commit at COMMIT |
| DI-11 | `tupcommit_conf` has an unreachable `seqNoReplica == 0` branch | `DblqhMain.cpp:15578-15586` [V] | Use the new flag there (X4.6) |
| DI-12 | The node-failure "ring" can be one slot pair per node id: only the highest failure GCI per node matters | plan §5.4 | X6.1 |

---

## 14. Open questions

| # | Question |
|---|---|
| Q1 | Should TCKEY_FAILCONF carry the GCI (API change)? |
| Q2 | Error code for rule-F aborts: reuse 4010 / `ZNODEFAIL_BEFORE_COMMIT`, or a new temporary error "aborted after commit due to node failure"? |
| Q3 | A forced start to R for a node group with only stale nodes (D4)? |
| Q4 | Dirty writes: `CPF_SELF` COMPLETE, or convert them to normal writes (DI-1)? |
| Q5 | Read locks in durable transactions: release at COMMIT (proposed) or at COMPLETE (DI-9)? |
| Q6 | `SET DurableCommits=0` online: accept as pending until the next cluster restart (proposed) or refuse? |
| Q7 | Block activation while a node restart runs (proposed), or allow it? |
| Q8 | Hold-back until the save of f or f + 1 (DI-5)? |
| Q9 | Takeover detection by opCount and missing replicas (proposed) or by a marker bit (DI-7)? |
| Q10 | Where the node-failure file lives when `FileSystemPathRedoLog` has one path per NUMA node (proposed: the first path)? |
| Q11 | Memory for the step-A hash table at SR, its limit, and what to do when it is exhausted |
| Q12 | Force the parallel COMMITREQ/COMPLETEREQ path for durable transactions (2 serial persists instead of 2R)? Decide from X8.3 |
| Q13 | There is no CI: which developer machines get `memmap=` PMEM, so the durable test set can run before pushes? |
