# RONDB-1150 durable commits: the micro-GCP ("durable epochs") alternative

Research notes for planning. All paths are relative to `storage/ndb/`.
Citation tags: **[V]** = verified by reading the code at the cited lines;
**[I]** = inferred from the code (reasoning over several sites, or behaviour
of code not read in full). Line numbers refer to the tree at branch
`RONDB-1150-durable-commits` (base 26.10-main, commit 7128c75dca4).

Sibling documents in this directory cover the per-transaction REDO-sync
design (`research_commit_protocol.md`, `research_redo_log.md`) and system
restart (`research_system_restart.md`). This file covers the alternative
built on the epoch (micro-GCP) protocol.

---

## 0. Summary

* **The epoch boundary is already a consistent, dependency-closed cut.**
  `GCP_PREPARE` sets `cgckptflag` on every node, which queues every new
  commit (`DIVERIFYREQ`). The master sends `GCP_COMMIT` only after every node
  has confirmed `GCP_PREPARE`. So once any node has handed out epoch E+1, no
  node can still hand out epoch E or lower. Locks are taken before the commit
  point, and committed reads only see data after the writer's commit point.
  Together these mean: if T2 read or overwrote T1's write, then
  epoch(T2) >= epoch(T1), even across TC nodes. (Section 3. [V] for the
  mechanism, [I] for the proof.)
* **Epoch completion already means the epoch's REDO records are written.**
  An epoch completes (`GCP_NODEFINISH` from every node) only after every TC
  has fully committed and completed every transaction of that epoch. A commit
  record is always put into the REDO buffer before LQH reports COMMITTED. So
  when epoch E is complete, every commit record of E is in the REDO buffers
  of all live LDMs. What is missing is only (a) a sync, and (b) recording
  enough information to restart to E rather than to a gci_hi boundary.
  ([V], sections 2 and 4.)
* **The GCI is stored at gci_hi granularity almost everywhere that matters
  for restart.** The REDO commit record holds `gci_hi` only (9 words). The
  "completed GCI" REDO record holds the 32-bit gci_hi. The sysfile, the LCP
  metadata (`maxGciStarted`/`MaxGciWritten`) and SR replay filtering
  (`tcConnectptr.p->gci_hi > crestartNewestGci`) are all 32-bit. Rows keep
  gci_hi, plus optional `gci_lo` bits for tables with extra row-GCI bits.
  **SR cannot stop at an epoch today.** Doing so needs (1) gci_lo in the
  commit record, (2) a 64-bit "epoch synced" REDO marker, (3) a 64-bit
  restart point in `START_RECREQ`, REDO replay and LCP selection, and (4) a
  new step that picks the restart epoch from what each node has in its REDO
  log. (Section 4.)
* **Recommended shape ("Variant B, durable epochs"):**
  * After epoch E completes, the master sends a GCP_SAVEREQ-like
    `EPOCH_SYNCREQ(E)` to every node. Each LDM writes a 64-bit
    `COMPLETED_EPOCH` marker in each log part, forces the page out and syncs.
    The sysfile is **not** written.
  * When every live node has confirmed, the master broadcasts
    `EPOCH_DURABLE_REP(E)`.
  * TC holds `TC_COMMITCONF`, `TCKEYCONF(commit)` and `TCKEY_FAILCONF` for
    durable transactions until that report arrives. This generalises the
    existing `TF_LATE_COMMIT` mechanism.
  * At SR, the restart epoch is
    R = min over node groups of (max over the starting nodes in that group
    of D(n)), where D(n) is the node's last synced epoch marker. This is
    always >= the last GCP.
  * Locks are released at normal commit time. READ_BACKUP is not needed.
  * Durable and non-durable tables can be mixed, because SR still restores a
    consistent prefix of all transactions.
* **On-demand epochs are mostly there already.** Invalidating
  `m_micro_gcp.m_master.m_start_time` forces an immediate epoch
  (`DUMP 6099`, `WaitGCPReq::CompleteForceStart`, master takeover). The hard
  limits come from two built-in 10 ms delays (the `ZSTART_GCP` re-poll and
  the delay after `SUB_GCP_COMPLETE_ACK`), the 10 ms lower clamp on
  `TimeBetweenEpochs`, and the fact that epochs never overlap.
* **Latency.** Each durable commit pays for an epoch close, one sync round
  and a notification:
  * About 4 to 5 network RTT plus one fsync on top of the normal commit
    latency, if the epoch is closed on demand and the 10 ms delays are
    removed.
  * Today's code adds up to 2 x 10 ms on top of that.
  * With periodic epochs, add on average half the epoch interval.
* **Throughput.** Group commit comes for free: one sync per log part per
  epoch covers every transaction in it. The costs are:
  * a commit stall of about one RTT per epoch on every node (between
    `GCP_PREPARE` and `GCP_COMMIT`);
  * head-of-line blocking on the slowest transaction in each epoch;
  * more epochs per second for event subscribers. `MaxBufferedEpochs`
    (default 100) is counted in epochs and SUMA keeps
    `MAX_LDM_EPOCH_LAG = 50` slots for epochs not yet complete.
* **Node failure.** Nothing is persisted at node failure today. The failed
  node's `lastCompletedGCI` simply stops advancing, and the next GCP's
  `COPY_GCIREQ` makes that persistent. In Variant B nothing extra has to be
  persisted for correctness, provided:
  * epoch markers are written only by nodes that are full GCP participants;
  * `EPOCH_SYNCREQ(E)` is sent only after E has completed (so a node that
    failed during E never writes marker E);
  * the restart rule above is used.

  Two strongly recommended extras are to put the participant node set into
  each marker, which allows detecting "a starting set is missing the node
  holding the newest acknowledged data", and to force a full GCP right after
  a node failure. (Section 7.)

---

## 1. Configuration relevant to epochs and GCPs

| Parameter | Definition | Default / range | Use in DIH |
|---|---|---|---|
| `TimeBetweenGlobalCheckpoints` | `common/mgmcommon/ConfigInfo.cpp:1079-1081` [V] | 2000 ms, 20..32000 | clamped to 10..60000 and stored as `m_gcp_save.m_master.m_time_between_gcp` (`DbdihMain.cpp:25638-25643`) [V] |
| `TimeBetweenEpochs` | `ConfigInfo.cpp:1104-1106` [V] | 100 ms, 0..32000 | 0 disables micro-GCPs: every GCP becomes a save, the old protocol. Otherwise clamped to at most the GCP interval and at least **10 ms** (`DbdihMain.cpp:25656-25664`) [V] |
| `TimeBetweenEpochsTimeout` | `ConfigInfo.cpp:1108-1116` [V] | 0 (= use the GCP timeout) | `setGCPStopTimeouts` (`DbdihMain.cpp:25427-25481`) [V] |
| `TimeBetweenGlobalCheckpointsTimeout` | `ConfigInfo.cpp:1082-1090` [V] | 120000 ms | same |
| `MaxBufferedEpochs` | `ConfigInfo.cpp:1118-1122` [V] | 100 epochs | SUMA disconnects lagging subscribers (`suma/Suma.cpp:5569-5628`) [V] |
| `ODirectSyncFlag` | `ConfigInfo.cpp:1393-1395` [V] | false | O_DIRECT REDO writes are treated as synced (`DblqhMain.cpp:2781`) [I: makes FSSYNC cheap] |

GCI exhaustion: gci_hi is limited to `MAX_SAFE_GCI_VALUE = 0x7fffffff`
(`DbdihMain.cpp:18037`) [V]. The comment at `DbdihMain.cpp:25644-25650` [V]
already computes about 497 days at a 20 ms GCP interval. gci_lo is 32-bit
per gci_hi (`ndbrequire(Uint32(currGCI) != ~0)`, `DbdihMain.cpp:18167`) [V].

---

## 2. The GCP / micro-GCP protocol as implemented

### 2.1 State

* `MicroGcp` (`dbdih/Dbdih.hpp:2212-2241`) [V]:
  * `m_lock` is a seqlock read by TC threads in `DIVERIFYREQ`;
  * `m_old_gci`, `m_current_gci`, `m_new_gci` and `m_last_sent_gci` are
    64-bit;
  * participant state is `m_state` (IDLE / PREPARE / COMMIT / COMMITTED);
  * master state is `m_master.{m_state, m_new_gci, m_start_time,
    m_time_between_gcp}`, which adds COMPLETE.
* `GcpSave` (`Dbdih.hpp:2190-2207`) [V]:
  * `m_gci` is the 32-bit gci_hi;
  * participant states are IDLE / REQ / CONF / COPY_GCI;
  * master state is `m_master.{m_state, m_new_gci, m_start_time,
    m_saveConfNodes}`.
* `GcpMonitor` (`Dbdih.hpp:2243-2269`) [V] holds separate lag timers for
  GCP_SAVE and GCP_COMMIT.
* Commit blocking: `getBlockCommit()` = `c_blockCommit || cgckptflag`
  (`Dbdih.hpp:2663`) [V].

### 2.2 Master loop (`startGcpLab`, `DbdihMain.cpp:18076-18272`) [V]

1. The previous epoch's DIVERIFY queues must be drained
   (`c_diverify_queue[i].m_empty_done`). If not, re-poll after 10 ms
   (18085-18093).
2. Epoch waiters are woken (`emptyWaitGCPMasterQueue(... c_waitEpochMasterList)`).
3. If a starting node asked to block GCPs and no GCP_SAVE is running, take
   the `gcpBlockedLab` path (18098-18122). `cgcpOrderBlocked` causes a
   10 ms re-poll (18124-18129).
4. If less than `TimeBetweenEpochs` has elapsed since
   `m_micro_gcp.m_master.m_start_time`, re-poll after 10 ms (18137-18149).
   **An invalid start time forces an immediate epoch.**
5. `new_gci = current + 1` (18168). If a GCP save is due (GCP timer expired
   or start time invalid) **and** `m_gcp_save.m_master.m_state ==
   GCP_SAVE_IDLE`, gci_hi is switched instead:
   `new_gci = ((current >> 32) + 1) << 32` (18172-18199). **So a GCP save is
   started only when the previous save is idle; saves are never pipelined.**
6. `m_master.m_state = M_GCP_PREPARE`, then `GCP_PREPARE` is sent to all
   nodes with priority JBA (18213, 18271; `sendGCP_PREPARE` at 400-423).

### 2.3 Participant: GCP_PREPARE (`execGCP_PREPARE`, 18632-18722) [V]

* Under `m_lock.write_lock()` it sets `cgckptflag = true`,
  `m_state = M_GCP_PREPARE` and `m_new_gci = gci` (18685-18690).
* From now on `DIVERIFYREQ` returns "blocked" and the TC transaction is
  queued (17879-17910).
* `GCP_PREPARE` is forwarded to SUMA (JBB, 18711), then `GCP_PREPARECONF`
  is sent to the master (JBA, 18719-18720).
* There is no local wait. The node does not wait for anything except
  scheduling.

### 2.4 Master: all PREPARECONF received → GCP_COMMIT

`execGCP_PREPARECONF` → `gcpcommitreqLab` → `M_GCP_COMMIT`, then
`GCP_COMMIT` is sent to all nodes with priority JBA (18274-18312) [V].

### 2.5 Participant: GCP_COMMIT (`execGCP_COMMIT`, 18724-18829) [V]

* Under the write lock: `m_old_gci = m_current_gci`,
  `m_current_gci = gci`, `cgckptflag = false` (18808-18813).
* Each DIVERIFY queue is drained with `emptyverificbuffer` (18815-18819;
  25003-25055). Every queued transaction gets `m_current_gci`, which is the
  new epoch. The function dequeues one entry per `CONTINUEB` and ends with
  `synchronize_threads_for_blocks(DBTC)` before it sets `m_empty_done`.
* `GCP_NOMORETRANS(old_gci)` is sent to the local TC proxy (18821-18827).
  The proxy fans it out to every TC instance (`dbtc/DbtcProxy.cpp:479-510`)
  [V].

### 2.6 TC: GCP_NOMORETRANS → GCP_TCFINISHED (`dbtc/DbtcMain.cpp`) [V]

* `execGCP_NOMORETRANS` (12868-13060) marks the `GcpRecord` of the old
  epoch with `gcpNomoretransRec = ZTRUE`. If that epoch's
  `apiConnectList` is empty and no take-over is running, it calls
  `gcpTcfinished` at once. Otherwise it waits.
* A transaction leaves the list only at the very end of the COMPLETE phase:
  `execCOMPLETED` → `releaseTransResources` → `handleGcp` (9174-9437).
  `handleGcp` sends `GCP_TCFINISHED` when the list becomes empty
  (9411-9437).
* While take-over is running (`c_ongoing_take_over_cnt > 0`), completion
  is postponed. Take-over may also re-open an older epoch:
  `commitGciHandling` 7846-7871 logs "Reopening GCI".

### 2.7 Participant: GCP_TCFINISHED → GCP_NODEFINISH (18831-18899) [V]

* `synchronize_path(DBLQH, SUMA)` (18871-18878) makes sure every LDM and
  SUMA have processed everything sent before.
* The participant then goes to `M_GCP_COMMITTED` and sends
  `GCP_NODEFINISH(old_gci, tcFailNo)` to the master.

### 2.8 Master: all GCP_NODEFINISH received (`execGCP_NODEFINISH`, 18314-18455) [V]

* If the master's own `GCP_NODEFINISH` carries `tcFailNo < cMinTcFailNo`
  (a node failed after its TC reported), `GCP_NOMORETRANS` is sent again
  (18327-18347).
* `M_GCP_COMPLETE` is set. `SUB_GCP_COMPLETE_REP(old_gci,
  flags=IN_MEMORY)` is sent to all DIHs (18359-18400). On each node DIH
  sends it on to DBLQH (each LDM: `Dblqh::execSUB_GCP_COMPLETE_REP`
  34045-34051 passes it through TUP and on to SUMA), and acknowledges with
  `SUB_GCP_COMPLETE_ACK` (18901-18957).
* **A GCP save starts only if gci_hi changed** (`if (curr_hi == old_hi)
  return;`, 18418-18421). It then saves `old_hi` and sends
  `GCP_SAVEREQ(old_hi)` with priority JBB (18426-18454).
* On all `SUB_GCP_COMPLETE_ACK`: `M_GCP_IDLE`, then
  `CONTINUEB(ZSTART_GCP)` **with a 10 ms delay** (18457-18472).

### 2.9 GCP save

* **DIH participant** (`execGCP_SAVEREQ`, 18474-18522) [V] has idempotent
  takeover handling and forwards the request to the DBLQH proxy, which
  sends it to every LDM.
* **LDM** (`Dblqh::execGCP_SAVEREQ`, `DblqhMain.cpp:33749-33955`) [V]:
  * It refuses with `GCP_SAVEREF` during shutdown (`SL_STOPPING_4`), while
    REDO has not been replayed (`NodeRestartInProgress`), or before the
    first LCP (local sysfile path).
  * It sets `cnewestCompletedGci = gci` and calls `start_synch_gcp`
    (33957-33997), which for every log part either writes
    `ZCOMPLETED_GCI_TYPE(gci)` (2 words, `writeCompletedGciLog`
    43631-43662) or, if the part is busy, sets `waitWriteGciLog` so that
    the queue writes the record first.
  * `initGcpRecLab` (34074-34133) records the page and word of the record
    in each part and starts time supervision. That forces the partial
    32 KB page out (`timeSup` 34944-35067).
  * `checkGcpCompleted` (34141-34256) waits for the write to reach that
    position in **all** parts, then sends `FSSYNCREQ` for the current file
    of each part (34234-34253).
  * `execFSSYNCCONF` (34260-34301) collects all parts and sends
    `GCP_SAVECONF`.
* **Master** (`GCP_SAVEhandling`, 18578-18625) [V]:
  * sets `SYSFILE->newestRestorableGCI = gci`;
  * sets `lastCompletedGCI[n] = gci` **only for nodes that confirmed**
    (`m_saveConfNodes`, 18598-18608);
  * then runs `copyGciLab(GLOBAL_CHECKPOINT)` (19201-19264).
* **COPY_GCIREQ** carries the whole sysfile to every node
  (`sendCOPY_GCIREQ` 299-321). Each node writes `P0.sysfile` and then
  `P1.sysfile`, **one after the other, each with the sync flag set**
  (`writeRestorableGci` 27894-27936 with `setSyncFlag` at 27914;
  `writingCopyGciLab` 19542-19590). It then sends
  `SUB_GCP_COMPLETE_REP(flags=ON_DISK)` **to LGMAN only** (19573-19582),
  where it is a no-op ("NOT IMPLEMENTED YET", `lgman.cpp:3742-3760`) [V].
* **Master `COPY_GCICONF`** (19272-19374) [V] sets
  `c_newest_restorable_gci` and sends `RESTORABLE_GCI_REP` to BACKUP. It
  sets `GCP_SAVE_IDLE` and wakes `WAIT_GCP_REQ(Complete)` waiters
  (`emptyWaitGCPMasterQueue(... gci << 32, c_waitGCPMasterList)`, 19371).

### 2.10 Timers and GCP-stop detection

* `checkGcpStopLab` (24281-24423) [V] runs every 100 ms. It keeps two lag
  counters. GCP_SAVE lag is reset when `m_gcp_save.m_gci` changes; micro
  lag is reset when `m_current_gci` changes. Exceeding `m_max_lag_ms`
  calls `crashSystemAtGcpStop`.
* `setGCPStopTimeouts` (25427-25549) [V] computes
  `micro max lag = TimeBetweenEpochs + epochTimeout + max_failure_time`
  and `save max lag = GCP interval + max(gcpTimeout, epochTimeout) +
  max_failure_time`.

### 2.11 Master takeover (MASTER_GCPREQ)

* The new master sends `MASTER_GCPREQ` to all nodes. Each participant
  (`execMASTER_GCPREQ`, 11312-11491) [V] waits until it has processed
  NODE_FAILREP. It then replies with its micro state (READY /
  PREPARE_RECEIVED / COMMIT_RECEIVED / COMMITTED), its save state
  (IDLE / REQ / CONF / COPY_GCI), `newGCP_hi/lo`, `saveGCI` and its LCP
  info.
* The new master (`execMASTER_GCPCONF` 11493-11647, `MASTER_GCPhandling`
  11660-11760) [V]:
  * rebuilds the master state;
  * **invalidates both start times** (11663-11664);
  * re-sends `GCP_PREPARE` or `GCP_COMMIT` and re-sends `GCP_SAVEREQ` or
    `COPY_GCIREQ` as needed.
* Every participant handler is idempotent for a repeated request
  (`execGCP_PREPARE` 18662-18680, `execGCP_COMMIT` 18761-18791,
  `execGCP_SAVEREQ` 18485-18511, `Dblqh::execGCP_SAVEREQ` 33805-33846)
  [V].

### 2.12 Node failure during a micro-GCP (`checkGcpOutstanding`, 11047-11139) [V]

* Missing `PREPARECONF`, `GCP_SAVECONF` (faked as `GCP_SAVEREF
  FakedSignalDueToNodeFailure`), `COPY_GCICONF`, `MASTER_GCPCONF` and
  `SUB_GCP_COMPLETE_ACK` replies from the failed node are faked.
* `GCP_NODEFINISH` is special. The failed node is cleared from the
  counter, `cMinTcFailNo = cfailurenr` is set, and `GCP_NOMORETRANS` is
  sent again to the master's own TC. That TC takes over the failed TC's
  transactions, which may commit **into the epoch being closed**. The
  epoch completes only after take-over.

### 2.13 Sequence diagram (one epoch plus an optional GCP save)

```
 Master DIH                  every DIH (incl. master)    local TC (all inst.)   every LDM            SUMA
   | startGcpLab: timer / forced start (10 ms re-poll)
   |--GCP_PREPARE(E+1) JBA---->| cgckptflag=1 => DIVERIFY queued (commit stall begins)
   |                           |--GCP_PREPARE------------------------------------------------------->|
   |<--GCP_PREPARECONF---------|
   | (all nodes)
   |--GCP_COMMIT(E+1) JBA----->| current=E+1, old=E, cgckptflag=0, drain DIVERIFY queue
   |                           |   (queued commits get E+1; commit stall ends)
   |                           |--GCP_NOMORETRANS(E)--->| wait until every trans with gci==E
   |                           |                        | has finished COMMIT+COMPLETE
   |                           |<--GCP_TCFINISHED(E)----|
   |                           | synchronize_path(DBLQH,SUMA)
   |<--GCP_NODEFINISH(E)-------|
   | (all nodes)  => epoch E complete: all E commit records are in the REDO *buffers*
   |--SUB_GCP_COMPLETE_REP(E,IN_MEMORY)->|--------------------------------->|---(per LDM)------->| count LDMs,
   |<--SUB_GCP_COMPLETE_ACK----|                                                                 | send to
   | M_GCP_IDLE; CONTINUEB(ZSTART_GCP, 10 ms)                                                   | subscriber APIs
   |
   | only if hi(E+1) != hi(E) (GCP due and save idle; at most one save at a time):
   |--GCP_SAVEREQ(H=hi(E)) JBB->|--GCP_SAVEREQ(H)------------------------------>| write COMPLETED_GCI(H)
   |                           |                                               | in every log part,
   |                           |                                               | force page, FSSYNC
   |<--GCP_SAVECONF------------|<--GCP_SAVECONF--------------------------------|
   | sysfile: newestRestorableGCI=H, lastCompletedGCI[confirmed nodes]=H
   |--COPY_GCIREQ(sysfile)---->| write P0.sysfile (sync); then P1.sysfile (sync)
   |<--COPY_GCICONF------------| (also SUB_GCP_COMPLETE_REP ON_DISK -> LGMAN, a no-op)
   | GCP_SAVE_IDLE; wake WAIT_GCP(Complete) waiters
```

---

## 3. GCI assignment in DBTC and the consistent-cut argument

### 3.1 Where the GCI is assigned [V]

* `diverify010Lab` (`DbtcMain.cpp:7545-7627`) runs once every operation is
  prepared on every replica, so all write locks and all locked reads are
  held. It calls `c_dih->execDIVERIFYREQ` **directly from the TC thread**
  (7590-7591).
* DIH reads its state under the `m_micro_gcp.m_lock` seqlock. If commits
  are not blocked it returns `m_current_gci` at once. If they are blocked
  it queues the transaction and later answers with `DIVERIFYCONF` from
  `emptyverificbuffer` (`DbdihMain.cpp:17879-17910, 25003-25055`).
* TC keeps its own FIFO (`capiConnectPREPARE_TO_COMMITList`) so that
  commits stay in order even while `DIVERIFYCONF` signals are in flight
  (7592-7614).
* `execDIVERIFYCONF` (7710-7819) is **the commit point** (comment at
  7768-7774). `commitGciHandling` (7826-7882) sets
  `globalcheckpointid = Tgci` (64-bit) and links the transaction into the
  `GcpRecord` of that epoch. Records are kept sorted (`seizeGcp`
  7918-7960).
* Read-only transactions without locked reads (`lqhkeyreqrec == 0`) skip
  DIVERIFY and **get no GCI** (7616-7626). The NDB API confirms
  "Read(dirty) only transaction doesn't get GCI" (`ndbapi/NdbTransaction.cpp:2856-2861`).

### 3.2 Commit-blocking window [V]

* Between `GCP_PREPARE` and `GCP_COMMIT` on a node, every new commit is
  queued: `cgckptflag` is set at 18687 and cleared at 18812. The window
  lasts from the node's receipt of PREPARE to its receipt of COMMIT, which
  is about one master round trip plus master processing.
* No operation is blocked, only the transition to commit.

### 3.3 Proof sketch: epochs order dependent transactions [I, high confidence]

Claim: if T2 observes T1's write (locked read, committed read, or
overwrite), then epoch(T2) >= epoch(T1). The two transactions may be
coordinated by different TC nodes.

1. T1's write becomes visible to T2 at some LQH only after T1's commit at
   that replica. On the primary this is `localCommitLab` in the COMMIT
   phase. On a backup it happens in the COMPLETE phase: backups only change
   state and pass COMMIT on (`Dblqh::commitReplyLab`
   `DblqhMain.cpp:15617-15645`, primary `seqNoReplica == 0` →
   `localCommitLab` at 15266-15271) [V]. T1's commit at any LQH is caused
   by T1's COMMIT signal, which is sent after T1's commit point
   (DIVERIFYCONF on T1's TC node A).
2. T2's commit point (DIVERIFY on T2's TC node B) comes after all of T2's
   operations have returned, so it comes after T2 observed T1.
   Hence DIVERIFY(T1)@A happens-before DIVERIFY(T2)@B. The chain runs
   through signals, which carry memory barriers between threads.
3. Suppose epoch(T1) = E+1 and epoch(T2) <= E. Node A handed out E+1, so
   A had processed `GCP_COMMIT(E+1)`. The master sent that only after
   receiving `GCP_PREPARECONF(E+1)` from B. B sends that only after it has
   set `cgckptflag` under the seqlock. So B's `GCP_PREPARE(E+1)` happened
   before DIVERIFY(T1), and therefore before DIVERIFY(T2). After
   `GCP_PREPARE(E+1)` on B, a DIVERIFY on B either queues (and later gets
   at least E+1) or reads `m_current_gci >= E+1`. Contradiction.
4. A transaction with several operations on different TCs does not exist:
   one transaction has one TC. Its commit point is a single DIVERIFY. ✔
5. Take-over: a transaction committed by take-over keeps the GCI that was
   decided originally. `LQH_TRANSCONF` carries `gci_hi` and `gci_lo`
   (`DblqhMain.cpp:43448, 43455`) [V]. The re-opened epoch cannot complete
   before take-over has finished (`handleGcp` 9419-9436 and the
   `cMinTcFailNo` logic) [V]. Its dependants could only observe its writes
   after its commit at an LQH, so step 1 still holds.
6. **Commit records in each log part follow the same order.** T2's prepare
   and commit records on a replica are written after T2 got the lock there.
   That happens after T1 released it, which is after T1's commit record was
   written in T1's COMMIT phase.

**Consequence.** The set "all transactions with epoch <= E" is closed under
read-from and write-write dependencies. Restoring exactly that set gives a
state that some serial order could have produced. It contains every
transaction any durable transaction depends on.

Caveat on what clients can observe: read-only transactions get no epoch,
and committed reads never wait. A client can therefore *see* data from an
epoch that is later lost in a crash. This "early lock release" anomaly
exists in any design that releases locks before the sync (section 8.3).

---

## 4. GCI storage

| Where | Bits stored | Citation |
|---|---|---|
| REDO commit record `ZCOMMIT_TYPE` (9 words: type, tableId, schemaVersion, fragId, fileNo, startPageNo, pageIndex, stopPageNo, **gci_hi**) | gci_hi only | `writeCommitLog` `DblqhMain.cpp:43566-43621` (`gci = regTcPtr->gci_hi` at 43593); `ZCOMMIT_LOG_SIZE 9` `Dblqh.hpp:247` [V] |
| REDO prepare record | no GCI (the commit record points at the prepare) | `Dblqh.hpp:274-279`; see `research_redo_log.md` §2.1 |
| REDO `ZCOMPLETED_GCI_TYPE` (2 words) | 32-bit gci_hi (`cnewestCompletedGci`) | `DblqhMain.cpp:43656-43661`, `Dblqh.hpp:261` [V] |
| REDO page header words 2/3 (`ZPOS_MAX_GCI_COMPLETED`/`STARTED`) and per-MByte `logMaxGciCompleted/Started` | gci_hi | `initLogpage` 35577-35590; 36048-36051 [V] |
| Reading a commit record during SR | sets `gci_lo = 0` | `readCommitLog` 42763ff, `gci_lo = 0` at 42782/42802 [V] |
| Row header (`TR_RowGCI`) | gci_hi | `Dbtup::update_gci` `dbtup/DbtupCommit.cpp:640-651` [V] |
| Extra row GCI bits (`TR_ExtraRowGCIBits`, `m_extra_row_gci_bits`, conflict detection / `NDB$GCI64`) | truncated gci_lo | `DbtupCommit.cpp:603-608, 1480-1487` [V] |
| Page `max_gci`, LCP change detection (`m_lcp_start_gci`) | gci_hi | `DbtupCommit.cpp:621, 1476, 646-650` [V] |
| LCP: DIH `maxGciStarted/maxGciCompleted[lcpNo]`; ctl file `MaxGciWritten/MaxGciCompleted` | gci_hi | `DbdihMain.cpp:23376-23377`; `restore.cpp:1475-1530` [V] |
| Sysfile `newestRestorableGCI`, `lastCompletedGCI[node]`, crashed-replica `replicaLastGci` | gci_hi | `DbdihMain.cpp:18593-18608, 26561-26616` [V] |
| `LQH_TRANSCONF` (take-over), `COMMIT` signal, `TC_COMMITCONF`, `TCKEYCONF` | gci_hi + gci_lo | `DblqhMain.cpp:43448/43455`; `DbtcMain.cpp:8080-8086, 8326-8327, 7331-7400` [V] |

### 4.1 Can SR stop at an epoch today? No [V]

* SR replays until the `ZCOMPLETED_GCI_TYPE` record equal to `logLastGci`
  (= `crestartNewestGci`, a gci_hi). Its position becomes the new log head
  (`DblqhMain.cpp:39304-39350`). The stop MByte is found from
  `logMaxGciCompleted[mb] <= logLastGci` (`srLogLimits` 38671-38730).
* Commit records **before** that stop record whose `gci_hi >
  crestartNewestGci` are rewritten as `ZINVALID_COMMIT_TYPE` (39108-39131).
  Records of the next GCI interleave with the completed-GCI record of the
  previous one.
* Per fragment, replay runs over `[execSrStartGci, execSrLastGci]` in
  gci_hi (`checkIfExecLog` 40929-40955).
* DIH: SR restarts to `SYSFILE->lastCompletedGCI[master]`
  (`ndbStartReqLab` 2924-2962). A replica is a REDO source only if
  `stopGci <= lastCompletedGCI[node]` (`findLogNodes` 25076-25120). An LCP
  is usable only if `maxGciStarted <= stopGci` (`findStartGci` 25300-25335;
  `resetReplicaLcp` 20612-20640). `restore.cpp:1519-1530` rejects LCP ctl
  files with `MaxGciWritten > m_restored_gcp_id`: "we have no UNDO log for
  main memory data".

### 4.2 What epoch-granularity SR needs [I]

1. **A commit record with gci_lo.** This means a new 10-word record type,
   or using the reserved/version mechanism (`ZPOS_VERSION` is in every page
   header). Without it, the commit records of epochs (H, L+1..) that come
   before marker (H, L) cannot be told apart from records of (H, <= L).
   LQH already knows gci_lo at commit time: it arrives in `COMMIT`
   (`DbtcMain.cpp:8085`) and in `LQH_WRITELOG_REQ` (`DblqhMain.cpp:15282-15290`).
2. **A 64-bit epoch marker** (`ZCOMPLETED_EPOCH_TYPE`: type, hi, lo,
   optionally the participant bitmap). Optionally add 64-bit "max epoch
   synced" words to the page header. Words 4/5 and 22..31 are currently
   zeroed and unused [I] (`initLogpage` memsets the header at 35582). That
   makes the last durable epoch of a part readable from its last page.
3. **A 64-bit restart point** in `START_RECREQ`, `logLastGci` and the
   invalidation test.
   * The stop record becomes the epoch marker R, or the completed-GCI
     record when R is the last epoch of a gci_hi.
   * Invalidation becomes `epoch(commit) > R`.
   * Per-fragment ranges `[start, R.hi]` with the epoch test applied in
     the last gci_hi.
4. **LCP selection.** If R = (H, L) is not the last epoch of H, an LCP
   whose `maxGciStarted/MaxGciWritten == H` may contain row images from
   epochs after R, and there is no main-memory UNDO. Use `R.hi - 1` as the
   LCP validity bound, or record a 64-bit max epoch in the LCP ctl file.
   An older usable LCP should exist: old LCP files are deleted only after
   `RESTORABLE_GCI_REP >= maxGciWritten`, and the REDO tail cut waits for
   the restorable GCI (`DblqhMain.cpp:33999-34023`; `DbdihMain.cpp:1040`
   `check_cut_log_tail`) [I].
5. **A step that decides R from REDO contents** (section 7.3), plus
   NDBCNTR's restorable/not-restorable split done on the 64-bit D(n)
   (today `update_withLog`, `ndbcntr/NdbcntrMain.cpp:2721-2745` [V]).
6. **Disk data.** The UNDO log is applied back to the LCP start no matter
   what the restart GCI is, so REDO to R is enough [I]. LGMAN ignores
   `SUB_GCP_COMPLETE_REP` (`lgman.cpp:3742-3760`) [V].
7. **Node restart (NR) is unaffected.** A restarting node can keep using
   gci_hi granularity (its own `lastCompletedGCI`) and copy the rest from a
   live node. Copying rows with row-GCI >= H is conservative [I]. Only SR
   needs epoch granularity.

---

## 5. Durable-epoch design sketches

### Variant A0: no kernel change, the API forces a GCP

* `Dictionary::forceGCPWait(0)` sends `WAIT_GCP_REQ(CompleteForceStart)`
  (`ndbapi/NdbDictionaryImpl.cpp:7653-7695`). The master invalidates both
  start times and replies after the **next GCP save including
  COPY_GCI** (`DbdihMain.cpp:29736-29765`, 19371) [V].
* Latency is an epoch close plus a GCP_SAVE plus two sequential sysfile
  syncs per node, typically tens of ms.
* Serialised: only one save runs at a time. Each forced save burns one
  gci_hi.
* Useful as a test oracle and baseline, not as the feature.

### Variant A: "every epoch a GCP" (short `TimeBetweenGlobalCheckpoints`)

* Setting `TimeBetweenEpochs = 0` disables micro-GCPs, so every GCP is a
  save (`startGcpLab` 18178-18186) [V]. Alternatively set the GCP interval
  to 20 ms.
* TC holds commit acks until its gci_hi is saved. This needs a new
  "GCI saved" report to TCs; today only LGMAN gets `ON_DISK`.
* Pros: restart semantics unchanged, smallest kernel change.
* Cons:
  * a sysfile sync round (2 sequential syncs) on every node per GCP;
  * no pipelining;
  * gci_hi exhaustion: about 497 days at 20 ms and about 50 days at 2 ms
    (`MAX_SAFE_GCI_VALUE`);
  * LCP/REDO bookkeeping that runs per gci_hi gets 100x more GCIs.

### Variant B: durable epochs (REDO-only sync, recommended for evaluation)

1. **Close.** The epoch closes as today. TC reports in `GCP_TCFINISHED`
   (and DIH in `GCP_NODEFINISH`) whether epoch E contained durable writes.
2. **Sync.** On all `GCP_NODEFINISH(E)` with the durable flag, the master
   sends `EPOCH_SYNCREQ(E)`, or piggybacks a sync flag on
   `SUB_GCP_COMPLETE_REP(E)`, which already goes DIH → every LDM. Each LDM
   reuses the `start_synch_gcp` / `initGcpRecLab` / `checkGcpCompleted` /
   `FSSYNCREQ` machinery (section 2.9) with a 64-bit
   `ZCOMPLETED_EPOCH(E, participants)` record. It confirms with
   `EPOCH_SYNCCONF`. Only nodes that would answer `GCP_SAVECONF` (full
   participants, past REDO replay and first LCP) take part; others refuse.
3. **Declare.** When every live node has confirmed, set
   `m_durable_epoch = E` and broadcast `EPOCH_DURABLE_REP(E)` to all DIHs.
   Each DIH forwards it to the local TC proxy.
4. **Ack.** TC sends the held acks for epochs <= E (section 6.2).
5. **Pipelining.** At most one sync is outstanding. When it completes, the
   next sync covers the newest completed epoch, so the range
   `(last_synced, newest_completed]` is one group commit. Syncs overlap
   with the next epochs' PREPARE/COMMIT, exactly as GCP_SAVE does today
   (comments at `DbdihMain.cpp:29640-29660`).
6. **Existing GCPs remain.** GCPs keep running every
   `TimeBetweenGlobalCheckpoints` (sysfile, LCP, tail cut, NR all still
   work in gci_hi). A GCP save of H is the marker for (H, last).
7. **Master takeover.** `MASTER_GCPCONF` gets `syncState` and
   `lastSyncedEpoch`. The new master re-sends the sync for the highest
   epoch in flight. The participant must be idempotent, as for
   `GCP_SAVEREQ` (`DblqhMain.cpp:33805-33846`).
8. **Node failure.** Fake the confirmation for the failed node (as in
   `checkGcpOutstanding`). E is declared durable on the survivors. Its node
   group still has a survivor, otherwise the cluster would have crashed.
9. **Monitor.** Add a durable-lag monitor. A stuck sync stalls only the
   acks, not the epoch protocol.

### Variant B': on-demand epochs

* When TC holds its first durable ack for the current epoch, it sends
  `EPOCH_EXPEDITE_REQ` to the master, at most one outstanding per TC per
  epoch. The master invalidates `m_micro_gcp.m_master.m_start_time` only.
  `DUMP 6099` does exactly this (`DbdihMain.cpp:28684-28692`) [V].
  `WaitGCPReq::CompleteForceStart` also invalidates the GCP-save timer
  (29757-29762).
* To actually reach low latency, remove or shorten the two 10 ms delays:
  * `CONTINUEB(ZSTART_GCP)` re-poll (18143-18148);
  * delay after `SUB_GCP_COMPLETE_ACK` (18468-18470).
  If the master is idle, call `startGcpLab` directly from the expedite
  handler.
* Adaptive policy: periodic epochs at `TimeBetweenEpochs` when no durable
  commits are waiting, on-demand epochs otherwise. Cap the epoch rate,
  for example with a minimum interval of 1 ms, to protect SUMA and
  subscribers.

### Variant C: SR protocol for Variant B

See section 7.3.

### Variant D: who waits

* **D1, TC holds the ack (preferred).** Transparent to every client: NDB
  API, mysqld, RDRS, Rondis, ClusterJ.
* **D2, the API waits.** TC acks as today with the 64-bit GCI, which the
  API already knows from `TC_COMMITCONF` and `TCKEYCONF`. The API then
  waits until a "durable epoch" pushed to all API nodes is >= that GCI.
  This needs a new broadcast: today `SUB_GCP_COMPLETE_REP` goes only to
  `c_subscriber_nodes` (`Suma.cpp:6063-6076`) and carries `IN_MEMORY`.
  It also needs per-`Ndb_cluster_connection` state next to
  `m_latest_trans_gci` (`ndbapi/ndb_cluster_connection_impl.hpp:88,175`).
  Pros: no TC state, and the API can choose per transaction. Cons: every
  client library must change, and the API must handle data node failover
  of the durable-epoch stream.

---

## 6. API side

### 6.1 What the API sees today [V]

* `TC_COMMITCONF` carries `gci_hi` and `gci_lo` (`signaldata/TcCommit.hpp:53-67`,
  `DbtcMain.cpp:8326-8327`).
* `TCKEYCONF` carries `gci_hi` in the header and `gci_lo` after the
  operations (`signaldata/TcKeyConf.hpp:75`, `DbtcMain.cpp:7331-7400`).
* The API stores the GCI in `theGlobalCheckpointId` and in
  `*p_latest_trans_gci` (`NdbTransaction.cpp:2574-2590, 2850-2862`).
  `NdbTransaction::getGCI()` returns gci_hi, and `getGCI(Uint64*)` returns
  the full epoch (3040-3056).
* Completed epochs are pushed to API nodes only through
  `SUB_GCP_COMPLETE_REP`. SUMA sends it only to event subscribers, once
  every LDM has reported the epoch (`Suma.cpp:5630-5729, 5731-6100`). The
  API's ClusterMgr acknowledges it (`ClusterMgr.cpp:967-1000`).
* There is **no push of the saved or durable GCI to APIs**. They can only
  ask with `WAIT_GCP_REQ`: CurrentGCI, RestartGCI, Complete,
  CompleteForceStart, CompleteIfRunning, WaitEpoch (`DbdihMain.cpp:29555-29825`).

### 6.2 TC holding the ack [V for the existing mechanism, I for the extension]

* **The mechanism exists.** `TF_LATE_COMMIT` is set for writes to
  READ_BACKUP tables (`TR_DELAY_COMMIT`, `DbtcMain.cpp:1130-1137,
  5616-5627`). `sendApiCommitSignal` then turns `RS_TCKEYCONF` and
  `RS_TC_COMMITCONF` into `RS_NO_RETURN` (8299-8304). `copyApi` keeps the
  user ApiConnect in `CS_COMMITTING`, sets its timer to 0 and remembers the
  marker (8472-8504). The ack is sent from `execCOMPLETED` →
  `sendApiLateCommitSignal` (9131-9172, 9303-9308).
* **Extension.** Add a per-table `TR_DURABLE` flag that sets
  `TF_DURABLE_COMMIT`. At `execCOMPLETED`, instead of sending, move a small
  *pending-ack* entry to a per-epoch durable-wait list:
  * (apiConnect i, ndbapiBlockref, ndbapiConnect, transid, gci, marker
    flag, returnsignal type);
  * keep the user record in `CS_COMMITTING`, as `LATE_COMMIT` does.
  On `EPOCH_DURABLE_REP(E')`, send every ack with gci <= E'.
* **Avoid a deadlock.** The pending-ack list must not be the
  `GcpRecord::apiConnectList`. Otherwise the epoch could never reach
  `GCP_TCFINISHED`, because it would wait for acks that wait for
  durability, which waits for epoch completion.
* **Take-over.** The take-over TC reports a commit with `TCKEY_FAILCONF`
  (`DbtcMain.cpp:14844-14848`) [V]. That reply must also be held until the
  epoch is durable. If the TC node fails while acks are pending, the API
  gets the usual node-failure "unknown result" or a take-over FAILCONF.
  No new failure mode [I].
* **READ_BACKUP is not needed.** The durable ack is sent after the epoch,
  including the COMPLETE phase of every transaction in it, has finished on
  all replicas, and after all replicas' REDO is synced. So
  read-your-own-writes on backups is automatically satisfied, and
  durability does not depend on which replica is read [I].

### 6.3 mysqld binlog injector [V/I]

* The injector writes one binlog transaction per epoch, after
  `SUB_GCP_COMPLETE_REP(IN_MEMORY)`. After a reconnect or a cluster restart
  it writes an incident (`plugin/ha_ndbcluster_binlog.cc:6128-6162,
  7165-7191`) [V].
* Today the binlog can contain epochs that a cluster crash loses (any epoch
  after the last GCP). A "durable" flag on `SUB_GCP_COMPLETE_REP`
  (`ON_DISK`, `signaldata/SumaImpl.hpp:433`) would let the injector commit
  binlog epochs only when they are durable. That closes the "binlog ahead
  of cluster" gap [I].
* Costs:
  * on-demand short epochs mean many more, smaller binlog transactions and
    more `ndb_apply_status` updates on replicas;
  * `MaxBufferedEpochs` (counted in epochs, default 100) becomes a very
    short time window, so it should become time-based or scale with the
    epoch rate;
  * SUMA's `MAX_LDM_EPOCH_LAG = 50` (`suma/Suma.hpp:928`) limits how many
    epochs can be in flight between LDMs.

---

## 7. Node failures and what must be persisted

### 7.1 Today [V]

* At node failure the sysfile is **not** written.
  * `lastCompletedGCI[failed]` simply stops advancing, because only nodes
    that confirmed are advanced at the next GCP (`GCP_SAVEhandling`
    18598-18608).
  * The next `COPY_GCIREQ` makes that persistent on all survivors.
  * Crashed replicas get `replicaLastGci = lastCompletedGCI[node]`
    (`newCrashedReplica` 26561-26616). This is in memory and written to the
    distribution files later.
  * `activeStatus` changes only in the LCP context
    (`failedNodeLcpHandling` 10903-10945).
* SR:
  * The master restarts to its own `lastCompletedGCI`. Nodes that claim a
    higher GCI are made unusable (`ndbStartReqLab` 2924-2962).
  * `DIH_RESTARTREQ` takes the max per node group and has a one-GCI-behind
    fix-up (bug#29167, 1842-1924).
  * NDBCNTR marks nodes with `lastGci < latest` as `withLogNotRestorable`.
    They do a node restart after the SR (`NdbcntrMain.cpp:2721-2745`).

### 7.2 The 500 ms scenario

* Setup: node A fails 500 ms after GCP G. Its partner B in the same node
  group keeps syncing durable epochs (G+1, 1..k), and they are
  acknowledged. Then the whole cluster crashes before GCP G+1 is saved.
* Both sysfiles say `lastCompletedGCI[A] = lastCompletedGCI[B] = G`.
  **The sysfile cannot tell them apart.** Only the REDO markers can:
  D(A) = the last marker A wrote, which is <= (G+1, j) with j < k, and
  D(B) = (G+1, k).

### 7.3 Proposed SR rule for durable epochs [I]

* D(n) = the minimum over n's log parts of the last `COMPLETED_EPOCH` or
  `COMPLETED_GCI` marker found. A marker counts only if it is present in
  every part of the node.
* Choose **R = min over node groups g of max over starting nodes n in g of
  D(n)**.
* Why R is safe:
  * Every acknowledged epoch E was synced by every live node. Each node
    group always has a live node, so some starting node per node group has
    D >= E, as long as that node starts. Therefore R >= every acknowledged
    epoch.
  * R >= (G, last), because all GCP participants synced G.
* Why a node's REDO up to D(n) is consistent:
  * A node writes marker E only after the master asked. The master asks
    only after E completed, and E completes only after take-over of
    transactions of any node that failed during E.
  * A node that died during E (its REDO might hold commit records of
    transactions that take-over later aborted) never writes marker E. Its
    E records can come before its last marker, but they are invalidated by
    the epoch test (section 4.2 item 1).
  * Restarting nodes do not write markers until they are full participants
    (same condition as `GCP_SAVECONF` vs `GCP_SAVEREF`).
* Nodes with D(n) < R become "not restorable" and node-restart after the
  SR, generalising `update_withLog`. Nodes with D(n) > R truncate at
  marker R. Epochs above R were not acknowledged, or the rule would have
  chosen them.
* **Ordering problem.** NDBCNTR decides the starting set very early, from
  sysfile GCIs, while LQH reads the REDO log headers only in start phase 3
  (`startphase3Lab` 2454ff, `readSrLastMbyteLab` 36367-36420) [V]. D(n)
  therefore needs either:
  * an early, cheap REDO-tail probe, using the header words from section
    4.2 item 2; or
  * a new DIH round after LQH phase 1 that computes R and demotes nodes
    late.
  Late demotion of a node that NDBCNTR already counted as restorable is
  the riskiest new restart path.
* **Recommended extras.**
  1. Put the participant bitmap S(E) into each marker. At SR, if the
     largest D(n) among starting nodes has an S that includes an absent
     node, and that node's group cannot reach that epoch with the nodes
     present, then acknowledged data may be missing. Refuse the start
     unless forced. Today a sysfile from any surviving node gives similar
     protection for GCPs.
  2. After any node failure, invalidate `m_gcp_save.m_master.m_start_time`
     to force an immediate GCP save. That persists the new node set in the
     sysfile within about one GCP save (the same pattern as
     `MASTER_GCPhandling` 11663-11664).

---

## 8. Cost model

Notation: RTT is one data-node round trip; t_fs is one REDO page write plus
fsync, done in parallel across all log parts and nodes, so the cluster pays
the slowest one; t_drain is the time for the epoch's in-flight
transactions to finish COMPLETE.

### 8.1 Latency of one durable commit (Variant B + B') [I]

| Step | Cost |
|---|---|
| TC → master expedite | 0.5 RTT (0 if the epoch is periodic; then add on average half the interval) |
| Master: start delay | today up to 10 ms re-poll (18143-18148), plus 10 ms after the previous epoch's ACK (18468-18470); about 0 if removed |
| GCP_PREPARE round | 1 RTT (no local work) |
| GCP_COMMIT → NOMORETRANS → TCFINISHED (+ `synchronize_path`) → NODEFINISH | 1 RTT + t_drain + LDM-thread sync |
| EPOCH_SYNC round (or piggyback on SUB_GCP_COMPLETE_REP) | 1 RTT + t_fs (+ 32 KB partial-page rewrite per log part) |
| EPOCH_DURABLE_REP → TC → API ack | 0.5 RTT + 0.5 API RTT |
| **Total over the plain commit** | ≈ 4–4.5 RTT + t_drain + t_fs (+ up to 20 ms with today's timers) |

Examples, with assumed figures:

* NVMe with power-loss protection, t_fs ≈ 50–200 µs, and a 100 µs RTT:
  roughly 0.6–1.5 ms extra.
* Cloud block storage, t_fs ≈ 0.5–2 ms, and a 200–500 µs RTT: roughly
  2–4 ms extra.

The per-transaction REDO-sync design pays about t_fs plus about 0.5 RTT.
So the epoch design costs about 3 extra RTT per commit, but needs no
per-transaction sync bookkeeping.

### 8.2 Throughput [I]

* **Group commit.** One sync per log part per epoch covers every commit in
  it. The number of fsyncs per second is about epoch_rate x
  parts_per_node x nodes, independent of the commit rate.
* **Overhead at low load.** One small write still syncs every log part on
  every node. Optimisation: skip the fsync for parts that had no writes
  since their last synced marker. This needs care: a quiet part's last
  marker would cap D(n), so the node has to record "quiet through E" in
  some synced part.
* **Commit stall.** About 1 RTT per epoch on every node (section 3.2). At 1
  epoch per 2 ms with a 150 µs RTT this is about 7% of wall time during
  which new commits queue. They are released at `GCP_COMMIT`, one per
  `CONTINUEB` (`emptyverificbuffer` 25003-25055).
* **Head-of-line blocking.** Every ack in epoch E waits for the slowest
  transaction in E to finish COMPLETE (`handleGcp` 9419-9436). Very large
  transactions, with commits spread over real-time breaks, hurt everyone.
* **Epoch rate ceiling.** Epochs never overlap, since PREPARE(E+2) waits
  for IDLE after E+1. So the maximum rate is about
  1/(3 RTT + t_drain + timers). Today the timers alone cap it below about
  100 per second.
* **Event and replication side.** SUMA buffering and subscriber traffic
  per epoch, `MaxBufferedEpochs` in epochs, and `MAX_LDM_EPOCH_LAG = 50`.

### 8.3 Lock hold times and visibility [I]

* Locks are released at normal commit time: primary at COMMIT, backups at
  COMPLETE. The epoch cut handles dependencies (section 3.3), so durable
  writes cost **no extra lock hold time**. Hot-row throughput is
  unchanged.
* **Externalised reads of non-durable data.** A committed read (or a
  locked read-only transaction, which gets an epoch but has no REDO) can
  return data whose epoch is lost in a crash. Options:
  * accept it (standard early-lock-release semantics, same as InnoDB group
    commit);
  * offer "durable reads": LQH returns the row GCI64, which is already
    stored with extra row-GCI bits, and the API or TC delays the reply
    until the durable epoch >= the maximum row epoch read;
  * for locked read-only transactions, TC can hold the reply like a write.

---

## 9. Pros and cons versus per-transaction REDO sync at COMPLETE

| Aspect | Durable epochs (B/B') | Per-transaction REDO sync |
|---|---|---|
| Commit latency | + ≈ 4 RTT + t_fs + t_drain (worse) | + ≈ t_fs (+0.5 RTT) (better) |
| Throughput / group commit | free and cluster-wide; fsyncs per second follow the epoch rate | per log part leader/follower group commit needed (see `research_redo_log.md` §7.6) |
| Lock hold time | unchanged (locks released at normal commit) | depends: if locks are held until the sync, hot rows suffer; if released early, a recovery-cut argument is still needed |
| Recovery | needs epoch-granularity SR (commit record format, markers, R selection, LCP bound, NDBCNTR ordering): **significant** | if each acked transaction is synced on all replicas but SR still stops at a GCP, SR must go *past* the last GCP to a consistent point. The cut problem does not go away (see `research_system_restart.md`) |
| Consistency of the restored state | consistent prefix by construction (section 3.3) | must be argued separately (an order of synced commits across nodes is not automatically a cut) |
| READ_BACKUP requirement | none | likely needed for the ack after COMPLETE |
| Mixing durable and non-durable tables | natural; non-durable commits are restored when they lie in epochs <= R | natural for the sync; the restore cut must still include dependencies |
| Disk usage / wear | one 32 KB partial-page rewrite per log part per epoch | one partial-page rewrite per sync per log part |
| Blast radius | new GCP sub-protocol, SR changes, SUMA/binlog epoch-rate effects | LQH/TC local changes, smaller protocol surface |
| Failure handling | reuses GCP takeover/fake-CONF patterns; ack only after all live nodes synced | per transaction, the replicas involved; take-over must hold acks too |

---

## 10. Open questions

1. **SR ordering.** Where should D(n) be computed? Options: an early REDO
   tail probe using new page-header words, or a new DIH round after LQH
   phase 1 with late demotion of nodes. How do NDBCNTR's partial and
   partitioned start rules change when node-group maxima legitimately
   differ by one epoch?
2. **Commit record format.** A new 10-word `ZCOMMIT_TYPE_V2` with gci_lo.
   Upgrade/downgrade: is a REDO version gate enough, given that
   `ZPOS_VERSION` is in each page header? What about the
   `ZINVALID_COMMIT_TYPE` rewrite of the longer record?
3. **LCP validity when R is partial within gci_hi H.** Is using `H-1` as
   the bound always satisfiable? Equivalently, is an older ctl file or the
   previous LCP always retained when the newest has `MaxGciWritten == H`?
   Or should the ctl file get a 64-bit max epoch?
4. **What does the sysfile say after an SR to (H, L)?**
   `newestRestorableGCI = H` while the epochs of H after L no longer exist.
   Check all uses of "GCI H is complete": backup, NR copy thresholds, row
   GCI vs `m_lcp_start_gci`.
5. **Quiet log parts.** Can fsyncs be skipped without capping D(n)?
6. **Epoch-rate policy.** A minimum interval for on-demand epochs, how to
   remove the two 10 ms timers safely, and the impact on SUMA
   (`MAX_LDM_EPOCH_LAG`), `MaxBufferedEpochs` and the binlog injector.
7. **Head-of-line blocking.** Should durable acks be decoupled from
   non-durable stragglers in the same epoch? Not possible with an epoch
   cut. Mitigate by limiting the commit batch size of non-durable
   transactions?
8. **Durable reads.** Is this required for the product semantics? Cost of
   returning the row GCI64 from LQH and making the reply wait.
9. **Monitoring and timeouts.** What happens to held acks if syncing
   stalls: a GCP-stop-like crash, or return errors to the API after a
   timeout?
10. **Participant bitmap in markers, and the forced GCP after node
    failure.** Are both needed for the "starting set misses the node with
    the newest data" protection, or is the operational rule "start all
    nodes" (as today) acceptable?
11. **Variant A as stepping stone.** Is Variant A (20 ms GCPs, TC holds
    acks until the GCP is saved) acceptable as a first deliverable
    (simple, no SR change), with Variant B as a follow-up?
