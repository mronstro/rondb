# RONDB-1150 Durable commits: commit protocol and lock release

Scope: the transaction commit protocol (TC/LQH/TUP/ACC) and where locks are released
and row versions become visible. REDO write and flush internals, system restart and REDO
replay, and the GCP/micro-GCP protocol are covered by other research files. They are
only mentioned here where they constrain the commit-protocol design.

Conventions:
- **[V]** means VERIFIED in code at the cited `file:line`.
- **[I]** means INFERRED from code structure or comments, not traced end to end.
- Paths are relative to `storage/ndb/src/kernel/blocks/` unless stated otherwise.
  Line numbers refer to branch `RONDB-1150-durable-commits` at `7128c75dca4`.

---

## 1. Summary

1. **Commit is linear by default.** There are two variants.
   - LQHKEYREQ runs down the replica chain: primary → backup1 → backup2. Only the last
     replica sends LQHKEYCONF to TC.
   - COMMIT and COMPLETE are sent by TC to the *last* replica (`lastLqhNodeId`) and walk
     *back* up the chain to the primary. The primary answers COMMITTED or COMPLETED to TC.
   - With `LowLatency=1`, when the transaction contains simple reads, or after a
     node-failure or timeout, TC instead uses the parallel COMMITREQ/COMPLETEREQ
     protocol, one signal to each replica.
   - [V] `dbtc/DbtcMain.cpp:7797-7818`, `8057`, `8618`; `dblqh/DblqhMain.cpp:13712-13720`,
     `15617-15648`, `15654-15686`.
2. **Locks and visibility are asymmetric between the primary and the backups.** [V]
   - **Primary:** at COMMIT it does the TUP "real commit" (the new version becomes
     visible to READ_COMMITTED readers) and then ACC_COMMITREQ (the row lock is
     released). See `DblqhMain.cpp:15267-15272` → `localCommitLab`.
   - **Backup (AC_NORMAL):** at COMMIT it only writes the REDO commit record into the
     log buffer and sets state COMMITTED. The TUP commit and the ACC lock release happen
     at **COMPLETE** (`DblqhMain.cpp:15004-15009`, `15120-15130`).
3. **What READ_BACKUP does today.** It sets `TF_LATE_COMMIT` on any transaction that
   writes a READ_BACKUP table. TC then sends TCKEYCONF/TC_COMMITCONF only after the last
   COMPLETED, that is after every replica has become visible and unlocked
   (`DbtcMain.cpp:5616-5627`, `8303-8306`, `8472-8503`, `9302-9307`). The flag is
   transaction-wide, so a mixed transaction gets the late ack for all of its operations.
   `ndb_read_backup` defaults to ON in the MySQL plugin
   (`storage/ndb/plugin/ha_ndbcluster.cc:19708-19716`), so most tables already pay for
   the late ack.
4. **Critical answer.** If the only change is that LQH syncs REDO before answering
   COMPLETE:
   - On backups the new version stays invisible and locked until the sync.
   - On the **primary** it is already TUP-committed at COMMIT time. Locking readers and
     READ_COMMITTED readers (including query-thread reads) see the not-yet-durable value.
   - To avoid that, the primary's `localCommitLab` (TUP commit plus ACC release) must
     move out of the COMMIT phase. One option is to treat the primary like a backup and
     local-commit at COMPLETE. The other is to place the sync in the COMMIT phase,
     *before* the primary's local commit.
   - Moving only the ACC release does not help. TUP commit is what READ_COMMITTED
     readers observe (`dbtup/DbtupCommit.cpp:2508-2512`, `dbtup/DbtupExecQuery.cpp:1637-1700`).
5. **Whether retaining locks is desirable depends on the recovery model**, which is
   another agent's scope.
   - If system restart stays "GCI-prefix" (restore everything up to some GCI g and
     nothing after), early lock release is safe. A dependent transaction always has
     GCI ≥ the GCI of the transaction it read from [I]. It is then enough to delay the
     API ack until the transaction's GCI is durable, and locks need not be retained.
   - If restart instead replays individually-synced transactions beyond the restorable
     GCI, two things are needed:
     - no operation of a transaction may become visible before all its operations are
       durable;
     - restart must not recover a transaction partially.
6. **The cleanest commit-protocol shape for option 5b** is "sync in COMMIT, all local
   commits in COMPLETE":
   1. COMMIT/COMMITREQ: each replica writes the commit record, waits for REDO sync, and
      only then confirms.
   2. TC waits for all COMMITTED/COMMITCONF. This is the barrier where the transaction is
      durable everywhere.
   3. COMPLETE: every replica, the primary included, does the TUP commit and lock
      release.
   4. The API is acked after COMPLETE, as TF_LATE_COMMIT already does.

   The existing COMPLETE phase then serves as the "durable everywhere" round, so no
   fourth phase is needed.
7. **The takeover TC breaks the late ack today.** It sends TCKEY_FAILCONF (commit
   confirmed) to the API *before* running COMPLETE (`DbtcMain.cpp:14686-14707`,
   `15502-15506`). That ignores TF_LATE_COMMIT, so READ_BACKUP read-your-writes is
   already not guaranteed after a TC takeover [I]. TCKEY_FAILCONF carries no GCI. The
   durable design must move this ack after the complete or sync point.
8. **Deadlock hazard.** A commit or complete wait must never depend on
   GCP_SAVE/GCP_COMMIT of the transaction's own GCI. Micro-GCP g cannot finish until
   every transaction of g has reached `releaseTransResources()` → `handleGcp()`
   (`DbtcMain.cpp:9404`, `9418-9440`). LQH must therefore *initiate* its own REDO sync.
   If TC waits for "GCI durable", that wait must sit *after* `handleGcp()`.
9. **Lock-hold cost.** Primary lock-hold grows by Σ(sync) in linear mode, or by
   max(sync) + one round trip in parallel mode. Single-row hot spots serialize on that
   time, and group commit does not help them. The waiter queue that a row tolerates
   before `TransactionDeadlockDetectionTimeout` (default 1200 ms,
   `storage/ndb/src/common/mgmcommon/ConfigInfo.cpp:1193-1201`) aborts waiters shrinks
   in proportion.

---

## 2. Signal flow (write transaction, 2 replicas, linear commit; READ_BACKUP)

```
API            TC (DBTC)                 LQH-P (primary, seq 0)            LQH-B (backup, seq 1 = last)
 |  TCKEYREQ     |                              |                                 |
 |-------------->| tckeyreq050Lab: DIH node list; write on TR_DELAY_COMMIT table
 |               |   => m_flags |= TF_LATE_COMMIT (DbtcMain:5616-5627)
 |               |   first write op => seize CommitAckMarker, LQHKEYREQ marker flag (4896-4934, 5920-5926)
 |               | LQHKEYREQ (to tcNodedata[0])  |                                 |
 |               |----------------------------->| ACCKEYREQ: X-lock in ACC         |
 |               |                              | TUPKEYREQ: copy tuple (old version still visible)
 |               |                              | writePrepareLog -> REDO *buffer* (13338.., 13465-13585)
 |               |                              | packLqhkeyreqLab: LQHKEYREQ -> nextReplica (13709..)
 |               |                              |-------------------------------->| same: X-lock, TUP prepare,
 |               |                              |                                 | prepare log record in buffer
 |               |                LQHKEYCONF (only last replica, tcBlockref)       | (13712-13720)
 |               |<---------------------------------------------------------------|
 |               | execLQHKEYCONF: lastLqhNodeId = sender (6892); marker LQH list (6927-6950)
 |               | lqhKeyConf_checkTransactionState -> diverify010Lab (7181.., 7546..)
 |               |   [deferred UK/FK triggers: FIRE_TRIG_REQ round first, 7552-7571]
 |               | DIVERIFYREQ -> DIH ; DIVERIFYCONF(gci) (7590, 7710)
 |               | *** COMMIT POINT *** commitGciHandling(gci) links ApiCon to GcpRecord (7756-7767, 7825..)
 |               | commit020Lab: per op sendCommitLqh -> lastLqhNodeId (7965.., 8044-8110)
 |               |   packed ZCOMMIT{lqhPtr, gci_hi, transid, gci_lo}
 |               |---------------------------------------------------------------->| execCOMMIT -> commitReqLab
 |               |                              |                                 | TUP_WRITELOG_REQ -> LQH_WRITELOG_REQ
 |               |                              |                                 | -> writeCommitLog (REDO buffer) (15219, 15343)
 |               |                              |                                 | seq!=0: commitReplyLab: state COMMITTED,
 |               |                              |             COMMIT (clientBlockref = previous LQH) (15631)
 |               |                              |<--------------------------------|  (no TUP commit, lock kept)
 |               |                              | commitReqLab: commit record in buffer
 |               |                              | seq==0: localCommitLab (15267):
 |               |                              |   TUP real commit -> NEW VERSION VISIBLE (DbtupCommit 2508-2710)
 |               |                              |   ACC_COMMITREQ -> X-LOCK RELEASED, next waiter runs (15539)
 |               |                              | tupcommit_conf -> commitReplyLab -> COMMITTED to TC (15627)
 |               |<-----------------------------|                                 |
 |               | execCOMMITTED: last one -> sendApiCommitAndCopy (8142.., 8269)
 |               |   TF_LATE_COMMIT => returnsignal RS_NO_RETURN (no ack yet) (8303-8306)
 |               |   copyApi: copy record runs COMPLETE; user record parked CS_COMMITTING (8472-8503)
 |               | complete010Lab: per op sendCompleteLqh -> lastLqhNodeId (8516.., 8611..)
 |               |---------------------------------------------------------------->| execCOMPLETE (15004):
 |               |                              |                                 | seq!=0 && AC_NORMAL: localCommitLab:
 |               |                              |                                 |   TUP commit -> VISIBLE on backup
 |               |                              |                                 |   ACC_COMMITREQ -> LOCK RELEASED
 |               |                              |       COMPLETE (to previous LQH) + cleanUp (15660)
 |               |                              |<--------------------------------|
 |               |                              | execCOMPLETE seq==0: completeTransLastLab
 |               |       COMPLETED + cleanUp (op record freed) (15682)
 |               |<-----------------------------|
 |               | execCOMPLETED last: TF_LATE_COMMIT => sendApiLateCommitSignal (9302-9307, 9131..)
 |  TCKEYCONF / TC_COMMITCONF (gci_hi/gci_lo, marker bit) (7297.., 8299-8344)
 |<--------------|
 |               | releaseTransResources -> handleGcp (unlink from GcpRecord; maybe GCP_TCFINISHED) (9317.., 9404)
 | TC_COMMIT_ACK |                              |                                 |
 |-------------->| execTC_COMMIT_ACK -> sendRemoveMarkers -> REMOVE_MARKER_ORD to each (node,LDM) in marker
 |               |-----------------------------> (P) ----------------------------> (B)   (9027-9120; LQH 6438)
```

Without TF_LATE_COMMIT (non-READ_BACKUP write transaction), the API ack is sent in
`execCOMMITTED` (via `sendApiCommitAndCopy`, `DbtcMain.cpp:8269`), *before* COMPLETE has
started. [V]

**Parallel variant** (`LowLatency=1`, `m_simple_read_count != 0`, or node-failure/timeout
fallback). After DIVERIFYCONF, `init_setupFailData(ZCOMMIT_SETUP)` (`DbtcMain.cpp:7797-7818`)
marks every TcConnect as `OS_TAKE_OVER` and fills `failData[]` (`16412-16530`).
`toCommitHandlingLab` (`15519..`) then sends COMMITREQ directly to *every* replica at once.
Each replica answers COMMITCONF (`DblqhMain.cpp:15638-15646`). After the last COMMITCONF,
`check_finished_commit_handling` (`DbtcMain.cpp:15493-15515`) acks the API, or delays the
ack if TF_LATE_COMMIT is set, and then runs `toCompleteHandlingLab`, which sends parallel
COMPLETEREQ/COMPLETECONF (`15917..`). When everything is complete,
`check_finished_complete_handling` (`15886-15915`) sends the late ack. The per-replica LQH
actions are identical to the linear case; only the order is different, because the
primary local-commits concurrently with the backups writing their commit records. [V]

**GCI.** It is assigned at DIVERIFYCONF (`DbtcMain.cpp:7710-7767`) and stored in
`regApiPtr->globalcheckpointid`. It is sent to LQH inside COMMIT (`8083-8087`) and stored
in the REDO commit record (`gci_hi` only, `DblqhMain.cpp:43593-43618`) and in TUP row
metadata. The API receives `gci_hi`/`gci_lo` in TCKEYCONF (`DbtcMain.cpp:7328-7331`,
`7365-7375`) and in TC_COMMITCONF (`8326-8327`). TCKEY_FAILCONF (takeover) carries **no**
GCI (`include/kernel/signaldata/TcKeyFailConf.hpp:53-64`). [V]

---

## 3. Lock-release and visibility table

Linear commit; the parallel commit differs only in ordering.

| Replica | Phase | REDO | TUP (row version) | ACC (row lock) | State after | Cite |
|---|---|---|---|---|---|---|
| Primary (seq 0) | Prepare (LQHKEYREQ) | prepare record → buffer | copy tuple; old version visible to RC readers | X-lock acquired (or queued) | PREPARED | `DblqhMain.cpp:13244-13298`, `13465-13585`, `13712-13723` |
| Backup (seq≥1) | Prepare | prepare record → buffer | copy tuple | X-lock acquired | PREPARED | same path, via `packLqhkeyreqLab` |
| Backup, AC_NORMAL | COMMIT | commit record → buffer (TUP_WRITELOG_REQ → LQH_WRITELOG_REQ → writeCommitLog) | **unchanged** | **held** | COMMITTED | `15210-15226`, `15267-15273`, `15617-15632` |
| Backup, AC_NR_COPY (node restart in progress) | COMMIT | commit record | TUP commit | released | COMMITTED | `15267-15272` |
| Primary | COMMIT | commit record → buffer | **real commit → visible** | **released** (`tupcommit_conf_callback` → ACC_COMMITREQ) | COMMITTED | `15267-15272`, `15383-15500`, `15525-15550`, `DbtupCommit.cpp:2476-2733` |
| Backup, AC_NORMAL | COMPLETE | – | **real commit → visible** | **released** | op freed (`cleanUp`) | `15004-15009`, `15552-15615`, `15654-15665` |
| Backup, AC_IGNORED/NR_COPY | COMPLETE | – | nothing (ignored or already done) | – | op freed | `15014-15017` |
| Primary | COMPLETE | – | nothing | nothing | op freed, COMPLETED to TC | `15010-15013`, `15668-15686` |

When the new version becomes visible: [V] unless marked otherwise.

- **(a) Locking reads.** They go to the primary, except "simple reads" (S-lock), which may
  go to a local backup (`DbtcMain.cpp:5486-5520`). A locking read queues in ACC and is
  granted when the writer's ACC_COMMITREQ releases the lock. TUP is committed first
  ("WE MUST COMMIT TUP BEFORE ACC", `DblqhMain.cpp:15398-15400`), so the read sees the new
  version. On the primary that happens at COMMIT; on a backup, at COMPLETE.
- **(b) READ_COMMITTED / dirty reads.** They take no lock and read the main row, not the
  copy tuple (`DbtupExecQuery.cpp:1637-1700`). The new version becomes visible at TUP
  `execute_real_commit` under exclusive fragment commit access, so query threads cannot
  see a half-committed row (`DbtupCommit.cpp:2508-2512`, `2644-2710`). That is COMMIT
  time on the primary and COMPLETE time on backups.
- **READ_BACKUP routing.** Committed key reads (`TopSimple || TopDirty` or
  `m_read_committed_base`) and committed scans may go to a local or same-domain backup
  (`DbtcMain.cpp:5514-5520`, `18803-18860`). These see the new value only after COMPLETE
  has reached that backup. TF_LATE_COMMIT guarantees that this happened before the API
  is acked, which is the whole point of TR_DELAY_COMMIT.
- **Detached triggers fire at TUP real commit** (`checkDetachedTriggers`,
  `DbtupCommit.cpp:2655`). These feed SUMA events/binlog and backup logging. On the
  primary that is COMMIT time; backups also fire them at their local commit, where SUMA
  handles the duplicates [I].
- **Lock-free unique-index base read** (`SOF_LOCK_FREE_READ`). It reads the base row
  without a lock after reading the index row with one. If the base row's insert is not
  yet TUP-committed on that replica, it gets the temporary error
  `ZTUPLE_NOT_YET_COMMITTED_ERROR` (`DbtupExecQuery.cpp:1671-1686`, comment at
  `DbtcMain.cpp:5506-5512`). Any change that delays the TUP commit widens this window.

### Critical question: delaying lock release until a REDO sync at COMPLETE

- If the sync is placed before `localCommitLab` in `execCOMPLETE` on backups, the backups
  stay invisible and locked until synced.
- **The primary is not covered.** Its TUP commit and ACC release already happened in the
  COMMIT phase (`DblqhMain.cpp:15267`). READ_COMMITTED readers on the primary, and locking
  readers queued behind the primary's lock, see the not-yet-durable value immediately. So
  do query-thread readers.
- **To close this gap, one of two things must change:**
  - **Move the primary's local commit to COMPLETE.** For durable transactions,
    `commitReqLab` (`15267-15272`) and its twin in the queued-commit-log continuation
    (`921-927`) would call `commitReplyLab` for seq 0 instead of `localCommitLab`.
    `execCOMPLETE`/`execCOMPLETEREQ` (`15004-15017`, `15120-15140`) would get a seq-0
    branch that runs `localCommitLab`. `tupcommit_conf` (`15552-15615`) would need a
    discriminator, so that seq 0 at COMPLETE goes to `completeTransLastLab` and not to
    `commitReplyLab`.
  - **Put the sync in the COMMIT phase before each replica proceeds.** In the linear
    chain the primary is the *last* COMMIT hop, so when it TUP-commits every replica's
    commit record is already synced. But see 6.2: this is per operation, not per
    transaction.
- **ACC-only retention** (keep the lock, but let TUP commit) protects locking readers
  only. RC readers still see the value, and the row's TUP operation list is already
  cleared (`DbtupCommit.cpp:2658`). Not recommended.

Is retaining locks desirable at all? See section 7: it depends on the recovery model.

---

## 4. READ_BACKUP specifics

- **Table flags.** `TR_READ_BACKUP` (bit 5) and `TR_DELAY_COMMIT` (bit 7) in
  `Dbtc::TableRecord` (`dbtc/Dbtc.hpp:1745-1747`). Both are set together from
  `TC_SCHVERREQ.readBackup` (`DbtcMain.cpp:1130-1135`).
  - Ordered indexes inherit the flag from the base table (`dbdict/Dbdict.cpp:8619-8637`).
  - Unique-index tables and BLOB part tables carry their own flag, kept in sync with the
    base table (`Dbdict.cpp:10943-10990`; `storage/ndb/src/ndbapi/NdbBlob.cpp:100`).
  - FULLY_REPLICATED implies READ_BACKUP (`ha_ndbcluster.cc:10740-10764`).
  - All of the above [V].
- **ALTER TABLE ... READ_BACKUP=1 online.**
  - During prepare, TC sets only TR_DELAY_COMMIT (`DbtcMain.cpp:1414-1416`). It also runs
    `scan_for_read_backup` (`1281-1330`), which adds TF_LATE_COMMIT to in-flight
    transactions in CS_STARTED with operations, or in CS_RECEIVING.
  - Transactions that are already committing are left alone: "don't want to mix delayed
    and not delayed in the same transaction".
  - TR_READ_BACKUP itself is set only at alter commit (`1448-1458`). So the late ack is
    in force before any read is routed to a backup. [V]
  - A durable-commit table property would need the same two-step pattern.
- **Transaction flag.** `TF_LATE_COMMIT` (`Dbtc.hpp:1123`) is set when any INS/UPD/DEL
  (the `else` branch of the operation switch) touches a TR_DELAY_COMMIT table
  (`DbtcMain.cpp:5616-5627`).
  - Reads never set it.
  - Trigger-generated operations (UK index, FK cascade, fully-replicated copies) run
    through the same `tckeyreq050Lab`, so they set it as well.
  - **Mixed transactions:** one write to a READ_BACKUP table delays the ack of the whole
    transaction. Its non-READ_BACKUP operations are also complete everywhere before the
    ack, as a side effect. [V]
- **Where the ack is sent.**
  - `sendApiCommitSignal` suppresses the ack when TF_LATE_COMMIT is set (`8303-8306`).
  - `copyApi` keeps the user ApiConnect in CS_COMMITTING, links it to the copy, and moves
    the marker to the copy (`8472-8503`).
  - `sendApiLateCommitSignal` (`9131-9171`) sends TCKEYCONF/TC_COMMITCONF with the GCI.
    It is called from `execCOMPLETED` (`9302-9307`) or from
    `check_finished_complete_handling` (`15905-15912`). [V]
  - Exception: if the API failed during commit, the flag is dropped (`8474-8478`).
- **TTL tables.** READ_BACKUP read routing is suppressed for most TTL reads and scans
  (`DbtcMain.cpp:5150-5175`, `5331-5367`, `18814-18831`). TF_LATE_COMMIT is still set from
  TR_DELAY_COMMIT. [V]

---

## 5. Commit-ack markers (TC_COMMIT_ACK / REMOVE_MARKER_ORD)

- **TC side.** On the first non-dirty write operation, TC seizes a `CommitAckMarker`
  (hash keyed by transid) and sets the LQHKEYREQ marker flag (`DbtcMain.cpp:4896-4934`,
  `5920-5926`).
  - On that operation's LQHKEYCONF, TC records each `(node, LDM instance)` of the
    operation's replicas in the marker.
  - It then sets `TF_COMMIT_ACK_MARKER_RECEIVED`: "we have a marker in all nodes in at
    least one nodegroup, don't need to request any more" (`6927-6950`). [V]
- **LQH side.** Each replica runs `findOrSeizeCommitAckMarker` at LQHKEYREQ
  (`DblqhMain.cpp:10078-10087`). The marker is reference-counted by operations and is
  removed on abort (`remove_commit_marker`, `15832..`, called from the abort paths at
  `16291`, `16908`, `17160`). [V]
- **What it protects.** The *knowledge that the transaction committed* survives after
  all LQH operation records are gone (completed), until the API confirms it heard the
  outcome. [V]
  - If the TC dies, LQH_TRANSREQ scans the markers (`scanMarkers`, `17955-18050`) and
    reports `LqhTransConf::Marker`.
  - A transaction seen only through markers becomes CS_FAIL_COMPLETED
    (`DbtcMain.cpp:16176-16179`). The takeover TC sends TCKEY_FAILCONF (committed) to the
    API (`14769-14781`).
  - On abort the markers are removed, so a marker alone implies commit.
- **Removal.** The API sends TC_COMMIT_ACK when the conf carries the marker bit
  (`storage/ndb/src/ndbapi/Ndbif.cpp:541-586`, `808-834`, `1147-1195`). TC then sends
  REMOVE_MARKER_ORD to every recorded LQH (`DbtcMain.cpp:9027-9120`). With late commit
  this always happens after COMPLETE. Without it, TC_COMMIT_ACK can overtake COMPLETE
  (`DblqhMain.cpp:6456-6475`). [V]
- **Relevance to durability.** Markers are in memory only. They do not help after a
  full-cluster crash and need no change for durable commits. They stay the mechanism that
  lets a takeover TC confirm commit to the API.

---

## 6. Abort, timeouts, deadlock, takeover

### 6.1 Abort and timeouts

- **Abort is only possible before the commit point** (DIVERIFYCONF). TC sends ABORT to
  each alive replica (`DbtcMain.cpp:10900-10970`); LQH also forwards ABORT down the chain
  (`DblqhMain.cpp:16259-16290`). Locks are released through ACC_ABORTREQ. [V]
- **TC timeouts** (`timeOutFoundLab`, `DbtcMain.cpp:11963..`):
  - Prepare-phase states (CS_STARTED with outstanding operations, CS_RECEIVING,
    CS_START_COMMITTING, FIRE_TRIG states) abort on `TransactionDeadlockDetectionTimeout`.
    This is how waiters on a lock die.
  - An idle CS_STARTED transaction uses the inactive timeout.
  - **CS_COMMITTING/CS_COMMIT_SENT and CS_COMPLETING/CS_COMPLETE_SENT never abort**
    (`12039-12107`). They only log, unless a node failure was seen, in which case they
    switch to `init_setupFailData(ZCOMMIT_SETUP / ZCOMPLETE_SETUP)`, the parallel
    COMMITREQ/COMPLETEREQ. A slow REDO sync inside the COMMIT or COMPLETE phase is
    therefore safe from TC timeouts. [V]
- **TC_HBREP.** TC sends a heartbeat to the API during long commits, except in the
  RS_NO_RETURN complete phase (`DbtcMain.cpp:2707-2735`). [V]
- **Proactive deadlock detection** (RONDB-1062, off by default) builds DBACC wait-for
  edges (see `storage/ndb/claude_files/deadlock/CLAUDE.md`). A transaction in the
  COMMIT or COMPLETE phase waits for no lock, so it cannot be part of a cycle. Longer
  commit-phase lock holding only lengthens the waits of others. [I]

### 6.2 TC takeover after node failure (LQH_TRANSREQ / LQH_TRANSCONF)

The takeover TC sends LQH_TRANSREQ. Each LQH scans its operation records for
operations owned by the failed TC (`lqhTransNextLab`, `DblqhMain.cpp:17745..`) and reports
a status per operation (`abortStateHandlerLab`, `16714-16880`):

- PREPARED or LOG_COMMIT_*_WAIT_SIGNAL → `Prepared`.
- COMMITTED, WAIT_TUP_COMMIT or LOG_COMMIT_QUEUED → `Committed`, with the GCI, tableId
  and fragId in the signal (`43406-43460`).
- Operations in WAIT_TUP/WAIT_ACC/LOG_QUEUED are aborted or parked.
- After the operations, LQH reports the markers.

TC aggregates these per transaction (`initApiConnectFail` `16140-16180`,
`updateApiStateFail` `16585-16660`):

| What LQHs report | TC state | Action | Cite |
|---|---|---|---|
| only Prepared | CS_FAIL_PREPARED | abort (no commit decision visible) | `14731-14753` |
| any Committed + some Prepared | CS_FAIL_COMMITTING | COMMITREQ to Prepared replicas → `check_finished_commit_handling` → **TCKEY_FAILCONF to API** → COMPLETEREQ | `14709-14729`, `15502-15506` |
| all Committed | CS_FAIL_COMMITTED | **TCKEY_FAILCONF immediately**, then COMPLETEREQ | `14686-14707` |
| only markers (all operations already completed and freed) | CS_FAIL_COMPLETED | TCKEY_FAILCONF | `14769-14781` |

All of the above are [V].

Failure windows, today and for durable commits:

| Failure point | Today | Durable-commit implication |
|---|---|---|
| TC fails before the commit point | all Prepared → abort | none |
| TC fails between COMMIT and COMPLETE | takeover commits and **acks the API before COMPLETE**. TF_LATE_COMMIT is not consulted. The ack carries no GCI. | Must defer TCKEY_FAILCONF to `check_finished_complete_handling` (`15895-15904`) or to after the sync. The takeover TC can derive "durable" from `tableId` in LQH_TRANSCONF, or from a new reqinfo bit. [I] |
| TC fails mid-COMPLETE | some operations freed, others Committed → CS_FAIL_COMMITTED → ack, then complete the rest | same as above |
| TC fails after all COMPLETED but before the API ack (late commit) | markers only → TCKEY_FAILCONF | If the sync happens before COMPLETED, this ack is durable. OK. |
| A data node (participant) fails during COMMIT or COMPLETE | Timeout plus failureNr change → ZCOMMIT_SETUP/ZCOMPLETE_SETUP. Dead replicas are skipped (`failData` = InvalidStatus). | Durability then rests on the surviving replicas' sync. |
| LQH is waiting for a sync when LQH_TRANSREQ arrives (new) | – | Must **not** report Committed before the sync (the takeover would ack at once). Must **not** report Prepared (if every replica says Prepared, the takeover aborts even though commit records are in the buffer). Park the operation the way WAIT_TUP → WAIT_TUP_TO_ABORT parks, and report Committed after the sync. [I] |
| Full-cluster crash between COMMIT and API ack | The API was not told, so either outcome is acceptable. Atomicity across participants comes from the GCI-consistent restore. | If restart starts replaying per-transaction synced records beyond the restorable GCI, operations of one transaction can be synced on some LDMs or nodes and not on others. Restart then needs a transaction-level rule. Open question. |

---

## 7. Is retaining locks desirable? (recovery-model dependency)

**Claim [I]: commit-point GCIs respect real-time order.** If transaction B reads the value
committed by A, then B's GCI is at least A's GCI.

- A's commit point (DIVERIFYCONF, GCI g_A) precedes A's TUP commit. That precedes B's
  read, which precedes B's DIVERIFYREQ.
- The GCP_PREPARE/GCP_COMMIT protocol blocks new commits on every node before any node
  moves to g+1 (`DbtcMain.cpp:7590-7612` queueing; DIH side owned by the GCP agent).

Consequences of each recovery model:

- **Model A: GCI-prefix recovery, as today.**
  - Durability of B is achieved by ensuring that GCI g_B is recoverable, and recovering
    g_B also recovers A.
  - Early lock release (today's behaviour) is therefore safe. It is enough to delay the
    API ack until "g_B is durable", and the commit protocol needs only a TC-side ack queue.
  - That queue must sit after `handleGcp`. A GcpRecord cannot complete while its
    ApiConnect is still linked (`DbtcMain.cpp:9418-9440` → GCP_TCFINISHED →
    `dbdih/DbdihMain.cpp:18831-18897`), so waiting inside it would deadlock.
  - Lock hold is unchanged. Ack latency rises to the "GCI durable" latency, which is
    owned by the GCP agent.
- **Model B: per-transaction REDO durability beyond the restorable GCI.**
  - Two properties are needed:
    - (i) no operation of a transaction becomes visible, to RC readers or lock waiters,
      before all its operations are durable;
    - (ii) restart recovers a transaction all-or-nothing.
  - Placing the sync per operation in the COMMIT chain (design D-A below) gives
    per-operation durable-before-visible, but not (i). TC sends COMMIT for all operations
    in parallel (`commit020Lab`, up to `ZMAX_OUTSTANDING_COMMIT_OPS`), so op1 can be
    visible on its primary while op2's chain has not synced yet.
  - (i) requires a TC barrier: no local commit anywhere before *all* COMMITTED, as in
    design D-B.
  - Locks must then be retained across sync + one round trip. That is where the cost is.

---

## 8. Participants and operation sources

All of the following become TcConnect records in the same `ApiConnectRecord::tcConnect`
list, so COMMIT and COMPLETE cover them identically. [V] unless marked.

- **Unique indexes.** Immediate UK triggers fire at TUP prepare as FIRE_TRIG_ORD
  (`DbtcMain.cpp:24082`). `executeIndexTrigger` (`26080..`) then calls
  `insertIntoIndexTable`/`deleteFromIndexTable` (`27597`, `27744`), which issue an internal
  TCKEYREQ on the index table (its own TR_READ_BACKUP flag). The UK read path also uses
  internal TCKEYREQ (`SOF_INDEX_TABLE_READ`).
- **Deferred UK/FK triggers.** These are triggers deferred until commit. At commit,
  `diverify010Lab` first runs a FIRE_TRIG_REQ round over all operations
  (`DbtcMain.cpp:7552-7571`, `startSendFireTrigReq` `7509..`, `sendFireTrigReq` `8704..`,
  `execFIRE_TRIG_CONF` `8901`). This can add index writes and FK check reads (FK checks
  are forced to the primary, `5498-5501`, `5514`). Only then does DIVERIFY run.
- **FK cascades.** `executeFKParentTrigger`/`executeFKChildTrigger` → `fk_readFromChildTable`,
  `fk_scanFromChildTable` (`26290`, `26550`): scans with lock takeover, plus key operations.
- **Fully replicated tables.** `executeFullyReplicatedTrigger` (`27986..`) issues
  EXECUTE_DIRECT TCKEYREQ, one per extra fragment copy (`28135-28175`). This multiplies
  the number of participants: one per node group.
- **Reorg triggers** (online add-partition): `executeReorgTrigger` duplicates writes to the
  new fragments.
- **BLOB part tables.** The NDB API writes them as ordinary operations in the same
  transaction. Their READ_BACKUP flag is copied from the base table (`NdbBlob.cpp:100`).
  Base-table reads of a BLOB upgrade the lock and set `m_read_committed_base`, which
  allows backup reads (`DbtcMain.cpp:5519`). [V]
- **Dirty / simple writes** (`dirtyOp`). There is no 2PC.
  - Each replica writes the commit record immediately after the prepare record, local
    commits, and only then forwards the request (`DblqhMain.cpp:13565-13583`,
    `13244-13262`).
  - TC drops the operation on LQHKEYCONF (`releaseDirtyWrite`, `DbtcMain.cpp:9553-9575`).
  - TF_LATE_COMMIT does not apply. Durable dirty writes would need a sync before the
    forward or LQHKEYCONF at each replica, or should simply be excluded. [I]
- **No-logging tables** (`logFlag == STATE_FALSE`) write no REDO (`DblqhMain.cpp:13251-13268`)
  and cannot be durable. Exclude them, or reject the combination.
- **Read operations** inside a write transaction hold S-locks on the primary until COMMIT
  at the primary. Under D-B they would be held until COMPLETE.

---

## 9. Hook points and design options

### 9.1 Candidate hook points

**(a) Retaining locks and visibility until a durable point**

- **Primary local commit.**
  - Today it is decided in `Dblqh::commitReqLab`, `DblqhMain.cpp:15267-15272`
    (`seqNoReplica == 0 || AC_NR_COPY → localCommitLab`).
  - The same decision is duplicated for queued commit-log writes at `921-927`, and the
    multi-operation-row path via LOG_COMMIT_WRITTEN_WAIT_SIGNAL arrives through
    `15252-15259` (commit record written by the sibling operation's TUP_WRITELOG_REQ,
    `DbtupCommit.cpp:247-276`).
  - Factor this into one helper, "after the commit record is in the buffer", and branch
    there.
- **Local commit in COMPLETE.** Add a seq-0 branch to `execCOMPLETE` (`15004-15017`) and
  `execCOMPLETEREQ` (`15120-15140`).
- **`tupcommit_conf`** (`15552-15615`) chooses commitReply vs completeLast by
  `seqNoReplica`, so it needs a per-operation flag such as `OP_LOCAL_COMMIT_AT_COMPLETE`.
  It cannot use `transactionState`, because `commitContinueAfterBlockedLab` overwrites it
  with WAIT_TUP_COMMIT (`15418`).
- **Not recommended: ACC-only retention.** This would split `tupcommit_conf_callback`
  (`15525-15550`), which today calls ACC_COMMITREQ right after TUP finalize.

**(b) LQH waiting for the REDO sync**

- **B1, COMMIT phase.** Wait after `writeCommitLog` (`15343`, `912`) and before
  `commitReplyLab` (backup) or `localCommitLab` (primary).
- **B2, COMPLETE phase.** Wait in `execCOMPLETE`/`execCOMPLETEREQ` before
  `localCommitLab` (backup) or `completeTransLastLab` (primary).
- **New state.** Add a TcConnectionrec state such as `LOG_COMMIT_WAIT_SYNC`, plus a
  per-log-part waiter list keyed by the commit record's log position. Resume on the
  owning LDM instance through the existing cross-LDM "queued log write" CONTINUEB pattern
  (`ZCONTINUE_WRITE_LOG`, `DblqhMain.cpp:1408-1425`; `send_handle_queued_log_write`
  `770..`). Group-commit and fsync mechanics are owned by the REDO agent.
- **Takeover.** `abortStateHandlerLab` must park the new state (see 6.2).
- **ndbinfo.** Update the state description tables (`include/kernel/DblqhState.hpp`,
  `src/common/debugger/DblqhStateDesc.cpp`).
- **Self-initiated sync.** LQH must start the sync itself and must not wait for
  GCP_SAVEREQ of the transaction's GCI, which would deadlock (section 1, item 8).

**(c) TC side**

- **Transaction flag.** Add `TF_DURABLE_COMMIT`, set beside TF_LATE_COMMIT
  (`DbtcMain.cpp:5616-5627`) from a new table bit, or from an API/transaction hint. It
  must be **transaction-level**: every operation of a durable transaction syncs,
  including operations on non-durable logged tables, otherwise atomicity breaks under
  model B.
- **Passing the flag to LQH.**
  - At COMMIT time, use a new packed type code (codes 8..15 are free,
    `include/kernel/signaldata/PackedSignal.hpp:34-55`) or a COMMITREQ field. LQH forwards
    it along the chain in `sendCommitLqh`/`sendCompleteLqh` (`DblqhMain.cpp:6901-7002`).
  - An LQHKEYREQ flag is not enough, because operations prepared earlier do not know
    whether later operations will touch durable tables.
  - Version-gate both for online upgrade.
- **Linear vs parallel.**
  - Linear commit puts R syncs in series. Forcing the parallel path for durable
    transactions (same switch as `LowLatency`, `7797-7818`) costs max(sync) + 1 RTT
    instead.
  - COMMITREQ/COMPLETEREQ are not packed (one signal per operation per replica), so the
    parallel path is more CPU-expensive per operation. It is already well exercised via
    LowLatency and the failure paths.
- **API ack.** It is already after COMPLETE (`9302-9307`, `15905-15912`). Under D-B or D-C
  nothing else is needed in the normal path. Under D-D (model A), add a per-GCI
  "awaiting durable" queue *after* `handleGcp`, driven by a new "GCI g durable"
  notification.
- **Takeover ack.** Move TCKEY_FAILCONF in CS_FAIL_COMMITTED (`14686-14707`) and in
  `check_finished_commit_handling` (`15502-15506`) to `check_finished_complete_handling`
  (`15895-15904`) for durable or late-commit transactions. Consider adding the GCI to
  TCKEY_FAILCONF; that needs an API change.
- **Optional extra round** ("durable everywhere" → release): unnecessary under D-B,
  because the COMPLETE phase *is* that round. It is only useful if some design lets
  replicas local-commit after only *their own* sync and a global barrier is wanted later.
  That would be a fourth phase with an extra RTT of lock hold, so avoid it.

### 9.2 Design options (commit-protocol view)

| Option | Sync point | Local commit (visibility and lock release) | Durable-before-visible | Primary lock hold added (vs today's READ_BACKUP) | Changes |
|---|---|---|---|---|---|
| **D-A** | each replica in the linear COMMIT chain, before forwarding or local commit | as today (primary at COMMIT, backups at COMPLETE) | per operation only | + Σ sync over R replicas (serial) | LQH B1 + flag; takeover parking; takeover-ack fix |
| **D-B** (recommended for model B) | COMMIT/COMMITREQ on all replicas (parallel preferred) | **all replicas at COMPLETE** (primary deferred) | per transaction (TC barrier = all COMMITTED) | + max(sync) + 1 parallel round trip (COMPLETEREQ); read S-locks also held longer | LQH B1 + (a); force parallel path; takeover-ack fix |
| **D-C** (the original idea) | COMPLETE, before local commit | backups at COMPLETE after sync; **primary must also move to COMPLETE** | per replica only, not per transaction | + COMPLETE chain + Σ sync (linear) | LQH B2 + (a); takeover-ack fix |
| **D-D** (model A) | none per transaction; ack waits for "GCI durable" | unchanged | not needed under GCI-prefix recovery | none (only ack latency) | TC ack queue after `handleGcp`; GCP-side "durable GCI" notification |

Side effects of D-B and D-C (primary local commit moved to COMPLETE):

- Detached triggers (SUMA/binlog) fire later.
- The lock-free UK base-read temporary-error window now also applies on the primary.
- "Read your own writes" is unchanged, because the ack comes after COMPLETE.
- Micro-GCP completion is delayed by the sync time of its slowest transaction. A disk
  stall then stalls *epochs* (GCP_COMMIT), not just GCP_SAVE, which brings the
  epoch-timeout / GCP-stop monitors into play [I]. Coordinate with the GCP agent.

### 9.3 Lock-hold time and hot rows

The terms below are symbolic; no measurements were made.

Define:

- t_p — the prepare chain;
- t_c — one commit-chain hop or one parallel round trip;
- s — sync latency, after group-commit batching;
- R — the number of replicas.

Primary X-lock hold today (READ_BACKUP, linear) ≈ t_p + R·t_c. Under each option:

- D-A: ≈ t_p + R·(t_c + s);
- D-B (parallel): ≈ t_p + 2·t_c + s;
- D-C: ≈ t_p + R·t_c + R·(t_c + s).

Consequences:

- **Per-row throughput.** A single hot row is limited to about 1/hold. Group commit
  amortizes syncs *across* rows and transactions, but not along one row's lock chain.
- **Waiter limit.** The k-th waiter in the lock queue waits about k·hold. It is aborted
  (error 266) once k·hold exceeds `TransactionDeadlockDetectionTimeout` (default
  1200 ms). The tolerable queue depth therefore drops by the factor new_hold/old_hold;
  for example ×5–×20 if s is a millisecond-class cloud-disk sync, against a sub-0.2 ms
  hold today (illustrative).
- **Mitigations:**
  - make durability opt-in per table or transaction;
  - use the parallel path;
  - consider D-D (no change to lock hold) if the recovery model stays GCI-prefix.

---

## 10. Open questions

1. **Recovery model.** Will restart recover individually-synced transactions beyond the
   restorable GCI (model B), or will durability be achieved by making the GCI durable
   faster (model A)? This decides whether any lock retention is needed. For the REDO,
   restart and GCP agents.
2. Under model B, how does restart avoid partially recovering a transaction whose
   operations span LDMs and nodes that synced at different times? Is a
   transaction-level "durable" record needed, and where? The COMPLETE phase could write
   one.
3. Is "durable on all replicas" required, or is "durable on ≥1 replica of each
   fragment" enough? The answer changes whether parallel per-replica syncs need the TC
   barrier.
4. Granularity: a new table property (like READ_BACKUP, with an
   ALTER/`scan_for_read_backup`-style transition), a per-transaction API hint, or a
   cluster-wide setting? In every case it must be transaction-wide once any durable
   write is present.
5. Should durable transactions be forced onto the parallel COMMITREQ/COMPLETEREQ path?
   That trades CPU (unpacked signals) for latency (max vs Σ sync).
6. Takeover: confirm and fix TCKEY_FAILCONF being sent before COMPLETE. This already
   affects READ_BACKUP read-your-writes today. Should TCKEY_FAILCONF carry the GCI?
7. Exclusions and semantics for dirty writes, no-logging tables, and disk-data columns
   (UNDO/LGMAN ordering, owned by the REDO agent).
8. Detached triggers (SUMA/binlog) and the epoch timing change if the primary's local
   commit moves to COMPLETE. Is that acceptable for binlog latency and for the GCP-stop
   monitors?
9. Online upgrade: new packed COMMIT/COMPLETE type codes or COMMITREQ fields need version
   gating. Mixed-version node groups would have to fall back to non-durable behaviour,
   or refuse.
10. Large transactions: `commit020Lab` pipelines COMMITs (`ZMAX_OUTSTANDING_COMMIT_OPS`,
    `Dbtc.hpp:95-129`). With per-operation sync waits, is the window large enough to keep
    the log parts batching?
