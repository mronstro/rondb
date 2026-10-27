# RONDB-1150 durable commits: system restart and recovery research

Scope: how a system restart (SR) works today, and where and how an
"agree on the surviving transactions beyond the restorable GCI" phase
could be added. Other research documents cover the commit protocol, the
REDO write format and flushing, and the micro-GCP protocol.

Conventions:

- Paths are relative to `storage/ndb/src/kernel/blocks/` unless they are
  given in full. Line numbers are for the tree at commit `7128c75dca4`
  (branch RONDB-1150-durable-commits).
- **V** = verified in the code. **I** = inferred (by reasoning, from a
  comment, or from timing).
- **R** = the restorable GCI that an SR restores to today
  (`SYSFILE->newestRestorableGCI` as set by the SR master).
- **G'** = the highest GCI (gci_hi) whose transactions survive the new
  agreement phase. G' >= R.

---

## 1. Summary

1. **R is decided once and early.** The SR master is the node with the
   highest `lastCompletedGCI` in its own sysfile. QMGR elects it as
   president, and NDBCNTR and DIH use that same node as master. The master
   sets `R = SYSFILE->lastCompletedGCI[master]`. Every node that takes
   part in the SR must have exactly R. A node that is behind does not run
   its own REDO in the SR; it does a node restart (NR) afterwards (V,
   section 3).
2. **Every replica replays its own REDO, independently, up to R.** DIH
   tells each alive replica to restore its own LCP and run its own REDO
   from `maxGciCompleted(LCP)+1` to R (`findLogNodes`, V). Code exists to
   run REDO on another node (`EXEC_FRAGREQ` to the LQH of a log node,
   `MAX_LOG_EXEC` rounds), but NDBCNTR deliberately avoids it: nodes that
   would need it are sent to a node restart instead (V). Replicas are
   consistent after an SR only because each one replays exactly the
   committed operations of the GCIs <= R, and the GCP protocol guarantees
   that every node at R has the whole of R in its REDO.
3. **REDO beyond R is destroyed during the SR.**
   - Any commit record with `gci_hi > R` that is found before the stop
     point is overwritten in place with `ZINVALID_COMMIT_TYPE`, and the
     page is written back (`DblqhMain.cpp:39117-39132`, V).
   - The new log head is placed right after the `ZCOMPLETED_GCI_TYPE(R)`
     record (`DblqhMain.cpp:39304-39345`, V).
   - Everything after the new head is invalidated in the fourth phase
     (`invalidateLogAfterLastGCI`, `DblqhMain.cpp:39534ff`, V).
   - Durable commits must change all three, and must do so **before**
     anything is written.
4. **The REDO has no notion of a transaction.**
   - A prepare record holds hash, operation, lengths, rowid, key and
     attrinfo (`writeLogHeader`, `DblqhMain.cpp:14221-14254`, V).
   - A commit record holds table, schemaVersion, fragment, a pointer to
     the prepare record and gci_hi only (`readCommitLog`,
     `DblqhMain.cpp:42763-42806`, V).
   - No record carries a transaction id, and no record carries gci_lo
     (the epoch).
   - So an agreement on a set of transactions, or on an epoch cut, cannot
     be computed from today's REDO. The REDO format must change (that is
     covered elsewhere; this document lists what SR needs from it).
5. **What the sysfile cannot tell.** The sysfile is written only at GCP
   save, LCP start, SR and initial start. A node failure is not written to
   it until the next GCP save (V). If a node fails after R was saved and
   the cluster crashes before the next GCP save, then **all nodes look
   equal (lastCompletedGCI = R) in the SR**. The failed node's REDO beyond
   R stops at the moment it failed, while the survivors' REDO goes on.
   Replaying beyond R independently on each replica would then make the
   replicas diverge. This is the most important hazard found (section 7).
6. **Everything after SR assumes there is no data above R.** The first
   new GCI is R+2 (R+1 is saved but empty). Several places assume this:
   - LCP restore rejects LCP files with `MaxGciWritten > R`.
   - Backup requires `MaxGciWritten <= newestRestorableGci`.
   - Partial LCP uses the row GCI to detect changes.
   - Node-restart copy uses the row GCI.
   - NDB$EPOCH conflict detection uses the row GCI.
   - The next SR's REDO stop point is the GCI of a `ZCOMPLETED_GCI`
     record.

   So once G' > R is replayed, every "restorable GCI" variable must be
   raised to G', and that must be made durable, before new GCIs are
   handed out (section 9).
7. **A node failure during an SR kills the whole SR** (V). The agreement
   phase therefore needs no recovery while it runs. It does need to be
   repeatable: the decision must be persisted before any REDO record is
   changed, so that the next SR, possibly with a different set of nodes,
   cannot contradict it.
8. **Best place for the new phase.** It should be DIH-coordinated and run
   after the SR metadata is known (sysfile and table files) and REDO
   phase 1 (finding the end of the log) has completed. It should run
   before `START_RECREQ` is sent, so that it overlaps the LCP restore. It
   needs **one extra read pass over the REDO tail only**: from the MByte
   where GCI R was completed to the end of the log, a few GCPs' worth.
   The decision is then carried in `START_RECREQ`, and REDO execution
   uses it instead of `crestartNewestGci` as its filter and stop
   condition (section 10).

---

## 2. SR phase diagram (today)

```
 every node                       SR master node (QMGR president =
                                  NDBCNTR master = DIH master)
 ----------                       ---------------------------------
 NDBCNTR STTOR 1: READ_LOCAL_SYSFILE  (restorable flag, m_max_restorable_gci)
 NDBCNTR STTOR 2: DIH_RESTARTREQ ---> DIH reads P0/P1.sysfile
                  <--- DIH_RESTARTCONF(latest_gci = lastCompletedGCI[own])
 QMGR: CM_REGREQ(latest_gci) ----->  election: highest latest_gci wins,
                                     lowest node id breaks a tie;
                                     check_startup(): partial/partitioned,
                                     DIH_RESTARTREQ(direct) checks that
                                     every node group has a node at max GCI
 NDBCNTR: CNTR_START_REQ(lastGci) -> trySystemRestart():
                                     update_withLog(): lastGci < max
                                       => withLogNotRestorable (NR later)
                                     CheckNodeGroups on withLog set
                  <--- CNTR_START_CONF(startGci = R, starting nodes)
 NDB_STTOR phase 3 (LQH):
   REDO phase 1 per log part: open file 0, read page 0 of every
   MByte => lastLogfile, lastMbyte, logMaxGciCompleted[mb],
   logMaxGciStarted[mb], logLastPrepRef[mb]   (runs concurrently
   with everything below until srPhase3Start)
                                     DIH NDB_STARTREQ -> ndbStartReqLab:
                                       R = lastCompletedGCI[master];
                                       nodes with GCI > R => 0 (--initial)
                  <--- COPY_GCIREQ(RESTART)  (sysfile written on all nodes;
                                       m_current_gci = (R+1)<<32,
                                       setRestartOngoing)
                                     DICTSTARTREQ(restartGci=R) -> DICT
                                       restores schema; DIH reads table
                                       files, COPY_TABREQ to all
                                     per table: resetReplicaSr():
                                       invalidate LCPs (lcpId too new or
                                       maxGciStarted > R); new redo
                                       interval createGci = R+1;
                                       setup_create_replica() =>
                                       findStartGci + findLogNodes
                                       (failure => forced take-over)
                  <--- START_FRAGREQ (per fragment replica: lcpNo/lcpId,
                                       log nodes, startGci..lastGci = R,
                                       nodeRestorableGci)
 LQH: RESTORE_LCP_REQ per fragment (main memory only, LCP files with
      MaxGci > R rejected)                completeRestartLab():
                  <--- START_RECREQ(keepGci, lastCompletedGci = R, newestGci = R)
 LQH (when all fragments restored):
   START_RECREQ -> LGMAN (disk UNDO back to LCP start) -> TSMAN
   (extent bitmaps) -> SET_LOCAL_LCP_ID
   REDO round k (k = 0..3, csrPhasesCompleted):
     START_EXEC_SR per fragment -> EXEC_FRAGREQ to log-node LQH
     EXEC_SRREQ  ===== all-to-all barrier between SR nodes =====
     srPhase3Start/srGciLimits/srLogLimits: log part range
       [min startGci, R]; round 0 must reach the end, logLastGci = R
     execSr: scan log; COMMIT rec: gci > R -> ZINVALID_COMMIT_TYPE,
       else if fragment wants it -> read PREPARE -> LQHKEYREQ to TUP;
       COMPLETED_GCI(R) -> new head here (round 0), stop
     EXEC_SRCONF ===== all-to-all barrier between SR nodes =====
   REDO phase 4: set head/tail, open head file, invalidate pages after
     the head (lap check, scan at least 1 MB of unwritten pages)
   rebuild ordered indexes
                  ---> START_RECCONF ---> DIH master: all received ->
                                       take over m_to_nodes if needed ->
                                       NDB_STARTCONF
 NDB phase 5:                        master: LCP before any transaction
                                       ("Make On-line Database recoverable")
 NDB phase 6:                        startGcp(): first new gci_hi = R+2
                                       (R+1 is saved but empty)
 later: nodes in withLogNotRestorable / m_to_nodes do a node restart (copy)
```

Citations for the diagram:

- `NdbcntrMain.cpp:1843-1859` (DIH_RESTARTREQ), `1864-1932`
  (DIH_RESTARTCONF), `1943-1980` (local sysfile), `2155-2178`
  (CNTR_START_REQ), `2384-2500` (master side), `2721-2745`
  (update_withLog), `2747-2902` (trySystemRestart).
- `qmgr/QmgrMain.cpp:865-916` (latest_gci), `1566-1580` and `2279-2292`
  (president candidate by GCI), `2359-2689` (check_startup).
- `DbdihMain.cpp:1842-1925` (DIH_RESTARTREQ, both variants), `2918-2976`
  (ndbStartReqLab), `1088-1137` (COPY_GCIREQ RESTART on slaves),
  `19285-19305` (COPY_GCICONF -> DICTSTARTREQ), `20398-20561`
  (resetReplicaSr), `21127-21225` (startFragment), `21235-21250`
  (completeRestartLab), `468-514` (sendSTART_RECREQ), `21267-21412`
  (START_RECCONF), `2706-2737` (SR LCP), `2770-2790` (startGcp).
- `DblqhMain.cpp:2454-2512` (REDO phase 1 start), `36289-36461` (front
  page, last file, last MB), `36559-36625` (phase 1 done), `36646-36856`
  (START_FRAGREQ), `37619-37752` (START_RECREQ), `37756-37863`
  (UNDO/TSMAN then REDO), `38088-38458` (rounds and barriers),
  `38474-38875` (limits), `38962-39410` (execSr), `40409-40707`
  (phase 4 and completion).

All of it V.

---

## 3. Sysfile and the restorable GCI

### 3.1 Contents (`dbdih/Sysfile.hpp:74-179`, V)

| Field | Meaning |
|---|---|
| `systemRestartBits` | bit0 initial start ongoing, bit1 restart ongoing, bit2 LCP ongoing (`:185-226`) |
| `m_restart_seq` | incremented at every restart read (`DbdihMain.cpp:10002`) |
| `keepGCI` | oldest GCI whose REDO must be kept (log tail) |
| `oldestRestorableGCI` | oldest GCI that is restorable |
| `newestRestorableGCI` | newest GCI that is restorable (R) |
| `latestLCP_ID` | last LCP id |
| `lastCompletedGCI[node]` | last GCI that this node has GCP-saved |
| `nodeStatus[node]` (4 bit) | `NS_Active`, `NS_ActiveMissed_1/2`, `NS_NotActive_NotTakenOver`, `NS_TakeOver`, `NS_NotActive_TakenOver`, `NS_NotDefined`, `NS_Configured` |
| `nodeGroups[node]`, `takeOver[node]`, `lcpActive` | node groups, take-over and LCP-active bits |

- The sysfile is written to two files, P0 and P1. The first one that can
  be opened is read; if it fails, the other is tried
  (`DbdihMain.cpp:9937-10007`, `10127-10176`) (V).
- NDBCNTR also keeps a **local sysfile** with `m_restorable_flag` and
  `m_max_restorable_gci`. It decides whether the node can restore on its
  own:
  - `NODE_NOT_RESTORABLE_ON_ITS_OWN` gives
    `ST_SYSTEM_RESTART_NOT_RESTORABLE`.
  - `NODE_REQUIRE_INITIAL_RESTART` clears the file system.

  See `NdbcntrMain.cpp:1943-1980`, `6618-6690`. The distributed sysfile
  wins when it is newer (`:1907-1926`) (V).

### 3.2 How the values are maintained (V)

- **GCP save.** The master sends `GCP_SAVEREQ`, and each LQH writes a
  `ZCOMPLETED_GCI_TYPE(gci)` record in every log part and syncs it
  (`DblqhMain.cpp:33749-34000`, `43631-43662`). When all CONF/REF have
  arrived, `GCP_SAVEhandling` sets `newestRestorableGCI = gci`, and
  `lastCompletedGCI[n] = gci` **only for nodes that sent CONF**. It then
  sends `COPY_GCIREQ(GLOBAL_CHECKPOINT)` (`DbdihMain.cpp:18578-18626`).
  Nodes that sent REF (shutdown, restart in progress, or a REF faked for
  a failed node, `:11104-11105`) keep their old value.
- **Validation.** Before each `COPY_GCIREQ`, `validateCopyGci`
  `ndbrequire`s that `newestRestorableGCI` is the maximum of all
  `lastCompletedGCI`, and that every node group has a node whose
  `lastCompletedGCI == newestRestorableGCI` (`DbdihMain.cpp:19093-19158`).
- **keepGCI / oldestRestorableGCI** are computed at LCP start from the
  latest LCP of every replica (`findMinGci`, `DbdihMain.cpp:25250-25297`:
  keep = `maxGciCompleted`, oldest = `maxGciStarted`), and stored in
  `storeNewLcpIdLab` (`:22205-22252`).
- **When the sysfile is written** (`copyGciLab` callers):
  - `RESTART` (`:2975`)
  - `RESTART_NR`: sent only to the starting node, nothing is made durable
    (`:4749`, `:1176ff`)
  - `GLOBAL_CHECKPOINT` (`:18622`, and `:11735` at master takeover)
  - `LOCAL_CHECKPOINT` at LCP start (`:22252`)

  There is **no write on node failure** (enumerated with grep).

### 3.3 How R is chosen at SR (V)

1. Each node reports `latest_gci = SYSFILE->lastCompletedGCI[own]`
   (`DbdihMain.cpp:10091`). QMGR uses it for president election
   (`QmgrMain.cpp:1571-1578`, `2279-2292`). A node that is not restorable
   on its own reports `ZUNDEFINED_GCI_LIMIT` and can never be president
   (`:895-911`).
2. The master takes the larger of the node's own report and its own
   sysfile's view of that node (`NdbcntrMain.cpp:2464-2478`; the
   bug#29167 case at `DbdihMain.cpp:1876-1888`).
3. NDBCNTR `update_withLog` moves every node with `lastGci < master's` to
   `m_withLogNotRestorable`. The comment says this "makes it possible to
   always avoid using the remote REDO log execution code by always using
   node restart" (`NdbcntrMain.cpp:2721-2745`).
4. DIH `ndbStartReqLab`: `R = lastCompletedGCI[master]`. Nodes with a
   higher value (which cannot be alive here) get 0, so they must be
   started with `--initial`. An alive node with 0 is an error
   (`DbdihMain.cpp:2927-2961`).
5. `COPY_GCIREQ(RESTART)` sends the sysfile to all nodes. On each node:
   `m_micro_gcp.m_current_gci = (R+1)<<32`, `crestartGci = R`, restart
   ongoing set (`DbdihMain.cpp:1104-1120`). If an LCP was ongoing at the
   crash, that LCP's information is invalidated (`invalidateLcpInfoAfterSr`,
   `:19491`).

### 3.4 Partial and partitioned SR (V)

- `Qmgr::check_startup` (`QmgrMain.cpp:2359-2689`) waits for all nodes
  unless `StartPartialTimeout` or `StartPartitionedTimeout` allow
  otherwise.
- Every node group must have at least one starting node with a usable
  file system. Otherwise it fails with "Unable to start missing node
  group".
- The direct `DIH_RESTARTREQ` computes the maximum GCI per node group
  among the starting nodes. All node groups must have the same maximum,
  otherwise "Incomplete log for node group" (or it waits for more nodes
  while the partitioned timeout allows) (`DbdihMain.cpp:1858-1925`,
  `QmgrMain.cpp:2576-2603`, `2659-2689`).
- In NDBCNTR, `CheckNodeGroups` on the withLog set must give Win, or
  Partitioning when that is allowed (`NdbcntrMain.cpp:2771-2838`).
- The starting set is exactly the withLog nodes. All other nodes do a
  node restart afterwards (`:2835-2838`).

---

## 4. How DIH chooses, per fragment, the replica, the LCP and the REDO range

All of this is in `resetReplicaSr` (`DbdihMain.cpp:20398-20561`), run
once per table after the table files have been read (V).

1. `prepareReplicas` moves every replica to `oldStoredReplicas`.
2. `resetReplica` (`:20563-20610`):
   - It invalidates LCPs with `lcpId > SYSFILE->latestLCP_ID`.
   - It invalidates LCPs with `maxGciStarted > R`.
   - It calls `removeTooNewCrashedReplicas(R)` (`:27132-27156`), which
     drops crashed-replica intervals with `createGci > R`.
3. For each replica on an **alive** node with `NS_Active` or
   `NS_ActiveMissed_1/2`:
   - `newCrashedReplica`: the closed interval ends at
     `lastCompletedGCI[node]` (`:26561-26616`).
   - A new interval opens with `createGci = R+1`.
   - `resetReplicaLcp(R)` keeps the newest LCP with `maxGciStarted <= R`
     (`:20612-20641`).
   - `setup_create_replica` (`:27158-27245`) picks the LCP with
     `findStartGci(nodeStopGci = lastCompletedGCI[node])`: the newest
     valid LCP with `maxGciStarted <= stopGci`, and
     `startGci = maxGciCompleted+1` (`:25299-25350`). The comment at
     `:27172-27208` explains why an LCP newer than the node's own
     lastCompletedGCI must never be used: after an earlier partial SR the
     GCI numbers above R were used a second time, an "abandoned timeline".
   - `findLogNodes(startGci, stopGci = R)` (`:25076-25153`): the replica
     itself is the log node if
     `startGci >= createGci[noCrashed] && R <= replicaLastGci[noCrashed]
     && R <= lastCompletedGCI[node]`. Otherwise `findBestLogNode`
     searches the other SR replicas, stored or old, by REDO interval
     (`:25160-25248`), up to `MAX_LOG_EXEC` log nodes.
   - If no REDO can be found, the code logs "Forcing take-over of node %d
     due to insufficient REDO": the node leaves `m_sr_nodes`, joins
     `m_to_nodes`, and is set to `NS_NotActive_NotTakenOver`
     (`:20476-20500`).
4. If no stored replica is left for a fragment, it fails with "Nodegroup
   %u has not enough data on disk for restart" (`:20502-20540`).
5. `startFragment` sends one `START_FRAGREQ` per stored replica, each to
   its own node (`:21127-21225`, `27322-27370`). **Every replica restores
   and replays independently. SR never copies fragments, except for
   take-over nodes after the SR.**

---

## 5. LQH REDO execution in SR

### 5.1 Phase 1: finding the end of the log (`startphase3Lab`, V)

- It runs in NDB start phase 3, before the LCP restore and concurrently
  with it (`DblqhMain.cpp:2454-2512`).
- Page 0 of file 0 gives the file that was last open
  (`readSrFrontpageLab`, `:36289-36322`).
- Page 0 of every MByte in that file gives the last MByte, where the log
  lap drops. It also gives, per MByte, `logMaxGciCompleted`,
  `logMaxGciStarted` and `logLastPrepRef` (`readSrLastMbyteLab`,
  `:36367-36461`, fields at `:36384-36389`).
- Page 0 of earlier files gives the same per-MByte information for older
  MBytes (`readSrNextFileLab`, `:36471ff`).
- When done it sends `ZSR_PHASE3_START(ZSR_PHASE1_COMPLETED)`
  (`:36582-36625`).
- **Only headers are read; no log records.**

### 5.2 Phase 2: restoring fragments and collecting the ranges (V)

- `START_FRAGREQ` stores `srStartGci[i]`, `srLastGci[i]` and
  `srLqhLognode[i]`, and sets `crestartNewestGci = nodeRestorableGci`
  (`:36646-36856`, `:36792-36799`). The LCP restore uses
  `restoreGcpId = crestartNewestGci` (`:37009-37071`, from the disk-data
  subagent).
- `START_RECREQ`: `crestartOldestGci = keepGci`,
  `crestartNewestGci = lastCompletedGci`, `cnewestGci = R`,
  `c_backup->setRestorableGci(R)` (`:37643-37662`).
- When every fragment is restored:
  `LGMAN UNDO -> TSMAN -> SET_LOCAL_LCP_ID -> startExecSr`
  (`:37700-37863`).
- Per round, `START_EXEC_SR` sends `EXEC_FRAGREQ` for each fragment to
  the LQH of log node `srLqhLognode[csrPhasesCompleted]`
  (`:38110-38175`). The receiver records
  `execSrStartGci/LastGci/Blockref` per requester (`:38183-38204`).
- `complete_startExecSr` sends `EXEC_SRREQ`. The proxy collects it from
  all its LDMs and then broadcasts to all nodes in `m_sr_nodes`
  (`DblqhProxy.cpp:1990-2096`). When `EXEC_SRREQ` has arrived from all
  SR nodes, `ZSR_PHASE3_START(ZSR_PHASE2_COMPLETED)` is sent
  (`DblqhMain.cpp:38409-38458`).
- `srPhase3Start` waits for both phase 1 and phase 2 (`:38474-38518`).
  `restart_synch_state` is an additional barrier between the LDMs of one
  node (`:2979-3010`).

### 5.3 Phase 3: running the log (V)

- **Range per log part.**
  - `logStartGci` is the minimum `execSrStartGci`.
  - `logLastGci` is R in round 0 (`:38500-38506`). In later rounds it
    starts at 2 and is raised to the fragments' last GCI (`:38554-38566`).
  - Round 0 must reach the end of the log (`ndbrequire(csrPhasesCompleted
    != 0)` when a fragment wants more than R, `:38560-38565`).
- **`srLogLimits`** (`:38671-38875`) walks backwards from the last
  MByte.
  - The stop MByte is the first MByte with `logMaxGciCompleted <=
    logLastGci`.
  - The start MByte is the first MByte with `logMaxGciStarted <
    logStartGci`, moved back via `logLastPrepRef` so that it includes the
    prepare records.
  - It relies on `MAX_GCI_STARTED >= MAX_GCI_COMPLETED >= LAST_GCI`
    (`:38720-38727`).
- **`execSr`** (`:38962-39410`) handles each record type:

  | Record | Handling |
  |---|---|
  | `ZPREP_OP_TYPE` | skipped. It is executed only when a commit record points to it. |
  | `ZCOMMIT_TYPE` | `readCommitLog`, then: if `gci_hi > crestartNewestGci`, the word is overwritten with `ZINVALID_COMMIT_TYPE` and the page marked dirty, and `writeDirty` writes it back (`:39107-39132`, `43664ff`). Otherwise `checkIfExecLog` tests the fragment's `[execSrStartGci, execSrLastGci]` and schema version (`:40928-40955`). The prepare is then found by (fileNo, startPageNo, startPageIndex, stopPageNo), in the page cache or by a random read (`:39150-39190`). `execLogRecord` rebuilds an `LQHKEYREQ` and sends it to the replica's LQH (`execSrBlockref`, so it can go to another node) (`:39478-39516`). |
  | `ZABORT_TYPE` | skipped. |
  | `ZCOMPLETED_GCI_TYPE(g)` | if `g == logLastGci`: in round 0 the new head (file, page, index, lap) is recorded here and execution stops (`:39304-39345`). |
  | `ZNEXT_MBYTE_TYPE` in the stop MByte | crash: "end of log wo/ having found last GCI" (`:39258-39276`). **Today REDO execution cannot end except at a `ZCOMPLETED_GCI` record.** |

- **How commit records find their prepare records.** A commit record
  points to its prepare record. There is no matching by transaction:
  `transid` is set to a synthetic value
  (`transid[0] = logPartPtrP->ptrI + 65536`) (`:42804-42805`). Only
  `gci_hi` is in the commit record, and `gci_lo = 0` (`:42781-42782`).
  An operation without a commit record is never replayed.
- **End of a round.** `execLogComp`, then `srPhase3Comp` sends
  `EXEC_SRCONF` to all SR nodes. When all have arrived,
  `csrPhasesCompleted++` and the next round starts, up to `MAX_LOG_EXEC`
  (`:40260-40421`, `38250-38405`).

### 5.4 Phase 4: new head, tail and invalidation (V)

- Phase 4 starts with `logLastGci = crestartNewestGci` and
  `logStartGci = crestartOldestGci`. It runs `srLogLimits` again to find
  the tail (`:38349-38390`, `38842-38873`).
- `readSrFourthPhaseLab` sets `cnewestGci = cnewestCompletedGci = R`, or
  keepGci if that is larger (`:40499-40515`). It positions the write
  pointer at the head.
- `readSrFourthZeroLab` then starts invalidation at the head
  (`:40596-40620`).
- `invalidateLogAfterLastGCI` (`:39534ff`, comment at `:39587-39640`)
  invalidates every page after the head that has the current lap. It
  keeps searching until it finds an unwritten page 0 of a MByte, at least
  1 MB beyond the first page with an old lap. The reason is that up to
  1 MB of writes can be outstanding and can land on disk in any order.
- `continue_srFourthComp`, then ordered index rebuild, then
  `START_RECCONF` (`:40624-40707`).

### 5.5 REDO page integrity (V)

`calcPageCheckSum` returns the constant 37 unless the build has
`VM_TRACE` (`:46632-46639`). The checksum check on read is commented out
(`:40837-40845`). In release builds a torn or partially written REDO page
**cannot be detected**. This does not matter today, because replay never
goes past a `ZCOMPLETED_GCI` record that was synced long before the
crash. It matters for durable commits, which must replay up to the very
end of the log (section 10.4).

---

## 6. Disk data (from the disk-data subagent, spot-checked)

- **Order.** LCP restore (main memory only, disk attributes zeroed) runs
  first. Then the LGMAN UNDO pass rolls disk pages back to the LCP start
  (the cut is an LSN or LCP id, **not a GCI**). Then TSMAN rebuilds the
  extent bitmaps. Then REDO runs (`DblqhMain.cpp:37700-37863`;
  `lgman.cpp:4139-4160`, `5509-5747`, `5649-5700`, `6240-6322`;
  `tsman.cpp:1545-1770`). (V)
- **REDO writes to disk columns are UNDO-logged** as normal,
  non-abortable operations (`DbtupExecQuery.cpp:2475`, `3963`;
  `DbtupCommit.cpp:1042-1180`). (V)
- After UNDO, LGMAN writes a fake `UNDO_LOCAL_LCP_FIRST`, so a crash
  during REDO execution undoes back to the same point again
  (`lgman.cpp:6284-6306`). (V)
- **The UNDO log is not synced at GCP**
  (`lgman.cpp:3742-3753`, "NOT IMPLEMENTED YET"). The WAL rule is
  enforced by PGMAN through `sync_lsn` before a page write
  (`lgman.cpp:331-345`). (V)
- **TSMAN has no GCI logic.** The `m_gci` in UNDO records is never read
  when they are applied. (V)
- **Consequence for durable commits (I).** Replaying REDO beyond R does
  not break the UNDO/extent invariants by itself, since UNDO is keyed by
  LSN and LCP and REDO simply produces more UNDO. The risks are UNDO log
  space during a longer REDO run (error 1501, or a crash with the small
  REDO reserve), and the GCI-related checks in sections 8 and 9. The
  durable-commit protocol does **not** need to sync the UNDO log before
  acknowledging: the REDO record holds the full after-image, and the
  disk columns are rebuilt from REDO.

---

## 7. Partial cluster failures and when the sysfile is written

### 7.1 What a node failure records (V)

1. **In memory, master only.** If the failed node took part in an LCP,
   `failedNodeLcpHandling` changes its active status
   (`NS_Active -> NS_ActiveMissed_1`, `NS_ActiveMissed_2 ->
   NS_NotActive_NotTakenOver`) (`DbdihMain.cpp:10903-10960`). It becomes
   durable only at the next `COPY_GCIREQ`.
2. **GCP save after the failure.** `checkGcpOutstanding` fakes
   `GCP_SAVEREF(FakedSignalDueToNodeFailure)` for the failed node
   (`:11047-11110`). `lastCompletedGCI[failed]` stays at the last GCI
   that node saved (`:18600-18607`).
3. **Table files.** `removeNodeFromTables/removeNodeFromTable`
   (`:12045-12330`) runs on every DIH:
   - The failed node's replicas are moved to `oldStoredReplicas`.
   - `newCrashedReplica` closes the replica's REDO interval with
     `replicaLastGci = lastCompletedGCI[failed]` (`:27022-27034`,
     `26561-26616`).
   - The table description is then **written to disk**
     (`ZPACK_TABLE_INTO_PAGES`, `US_REMOVE_NODE`, `:12276-12320`,
     `24197`).

   The in-memory distribution that TC uses is updated before that file
   write completes, table by table (I).
4. **Sysfile.** There is no sysfile write on node failure (section 3.2).

### 7.2 Timing scenario: a node fails 500 ms after GCP save R

Setting: node X is in node group NG, with peer Y.

**Case A: the cluster saves at least one more GCP (R+1) before the full
crash.** (V, except the last point.)

- Sysfile on the survivors: `newestRestorableGCI = R+1` (or higher),
  `lastCompletedGCI[X] = R`. The table files show X's replicas as crashed
  with an interval ending at R.
- X's own sysfile still says R.
- At SR: QMGR elects a survivor as president. NDBCNTR puts X in
  `withLogNotRestorable`, so X does a node restart after the SR. X's REDO
  beyond R is never used.
- (I) Durable commits are fine here: every transaction acknowledged after
  X failed is in Y's REDO, and Y is an SR node.

**Case B: the full crash comes before the next GCP save (within about
2 s).** (V for the sysfile and DIH logic; the divergence is I.)

- Every node, X included, has `lastCompletedGCI = R` in every sysfile.
  NDBCNTR puts X in `withLog`, so X takes part in the SR.
- If the table files written at X's failure reached disk, DIH can see
  that X's replicas were crashed with `replicaLastGci = R`. Y's interval
  is still open (`ZINIT_REPLICA_LAST_GCI`). If those files did not reach
  disk, **nothing on disk shows that X failed**.
- Today this is harmless: both X and Y replay to R and stop.
- With durable commits it is not. Transactions in R+1 acknowledged after
  X failed are only in Y's REDO, and X's REDO for R+1 ends where X
  failed. If both replicas replayed their own REDO beyond R, **X's
  replica would miss acknowledged transactions and the replicas would
  diverge**.
- So the agreement phase needs to know, per replica, whether its REDO
  can be trusted beyond R. Options:
  - **(a)** Treat any replica whose last REDO interval is closed at R
    (crashed during R+1/R+2) as not trusted beyond R. Reuse the existing
    "Forcing take-over ... insufficient REDO" path (`m_to_nodes`,
    `DbdihMain.cpp:20476-20500`), so such nodes take over by copy after
    the SR. This helps only if the table files were written.
  - **(b)** Make the failure durable before any commit that leaves X out
    is acknowledged. Either DIH writes the sysfile synchronously on
    `NODE_FAILREP` with a new "failed after durable position" field, or
    every surviving LQH writes and syncs a "replica-set change" marker in
    its REDO.
  - **(c)** Detect it from REDO content: with transaction ids in commit
    records, a transaction that has a commit record on Y but none on X,
    where X's log ends early, shows that X is behind.

  (b) is the only one of the three that is safe without timing
  assumptions.

**Partial SR adds a further hazard (I).** In case B, a partial SR that
starts only X from NG (Y absent) would pass every current check, since X
has R. Acknowledged transactions that are only in Y's REDO would be lost.
So partial SR with durable commits needs (b), or must require every node
that could hold acknowledged transactions beyond R.

### 7.3 A lagging node that is down at SR (V)

- It does a node restart later, replaying its own REDO up to its own
  `lastCompletedGCI`.
- `START_RECREQ` carries `lastCompletedGCI[node]` (`DbdihMain.cpp:476-487`).
- LCPs are chosen against `lastCompletedGCI[node]` (`:8262-8330`).
- Copy-fragment then sends rows with GCI > the node's restorable GCI
  (`:9351-9366`).
- Its REDO beyond its own GCI is invalidated as in an SR. With durable
  commits nothing changes here, as long as the GCI numbers after the SR
  are higher than every replayed GCI (section 9).

---

## 8. How NDB handles today an SR where some node in a node group has REDO for a later GCI

This is item 7 of the task. All V.

1. **Election.** The president is the node with the highest
   `lastCompletedGCI` (`QmgrMain.cpp:1571-1578`). Its GCI becomes R.
2. **Who takes part.** Nodes with a lower lastGci do not take part with
   their REDO; they do a node restart afterwards
   (`NdbcntrMain.cpp:2721-2745`). Nodes not present that have a higher
   GCI in the master's view are zeroed and need `--initial`
   (`DbdihMain.cpp:2927-2949`).
3. **Fragment level.** A replica is a log node only if
   `R <= lastCompletedGCI[node]` and its REDO interval covers
   `[startGci, R]`. Otherwise it is forced into take-over
   (`DbdihMain.cpp:20476-20500`, `25103-25115`).
4. **REDO.** Every SR node stops at `ZCOMPLETED_GCI(R)`. Commit records
   with GCI > R before that point are turned into `ZINVALID_COMMIT_TYPE`.
   Everything after the head is invalidated. So the REDO a node has
   beyond R is **thrown away**. It is never used to bring a lagging peer
   forward (`DblqhMain.cpp:39117-39132`, `39304-39345`, `39534ff`).
5. **After the SR.** New GCIs start at R+2. GCI numbers in REDO or LCP
   files on absent nodes can be reused (the "abandoned timeline" comment
   at `DbdihMain.cpp:27172-27208`). That is why a node's own
   `lastCompletedGCI` bounds which of its LCPs and REDO can be used.

---

## 9. After SR: the new GCI and what depends on R

### 9.1 The first new GCI (V; from the dependents subagent, spot-checked)

- On every node, `COPY_GCIREQ(RESTART)` sets `m_old_gci = R<<32`,
  `m_current_gci = (R+1)<<32` and `crestartGci = R`
  (`DbdihMain.cpp:1104-1109`).
- `initCommonData` invalidates `m_gcp_save.m_master.m_start_time`
  (`:25635`), so the first `startGcpLab` forces a gci_hi boundary:
  `new = ((R+1)+1)<<32 = (R+2)<<32` (`:18166-18186`).
- GCP_COMMIT completes `(R+1)<<32`, and the first GCP_SAVE is R+1
  (`:18409-18428`). User transactions start at gci_hi R+2. R+1 is saved
  but normally empty (I).
- The SR LCP runs in NDB phase 5, **before** GCPs start in phase 6
  (`:2706-2737`, `2770-2790`).

### 9.2 What depends on R and what breaks if data with GCI > R is restored

| Dependent | Mechanism (file:line) | Effect if GCI G' > R is replayed and R is not raised |
|---|---|---|
| REDO stop and invalidation | `crestartNewestGci` in `execSr` `DblqhMain.cpp:39117`, head at `COMPLETED_GCI(logLastGci)` `:39316`, phase 4 `:38353` | The records are destroyed. Execution cannot end except at a `COMPLETED_GCI` record (`:39258-39276`). |
| GCI numbers used twice | `m_current_gci = (R+1)<<32` `DbdihMain.cpp:1109` | New commits get gci_hi values that already exist in REDO and in rows. The next SR's GCI-based filters become ambiguous. `GCP_SAVEREQ` `ndbrequire(gci >= cnewestCompletedGci)` (`DblqhMain.cpp:33808`) fires if LQH's `cnewestCompletedGci` is set to G' but DIH saves R+1. |
| LCP restore in a later SR | RESTORE rejects CTL files with `MaxGciWritten/MaxGciCompleted > restoreGcpId` (`restore.cpp:1519-1565`) | The SR LCP taken after the replay contains rows with GCI G'. A later SR that still restores to R would reject and delete those LCP files. |
| Backup LCP sanity | `ndbrequire(MaxGciWritten <= m_newestRestorableGci)` (`Backup.cpp:15204`), seeded through `setRestorableGci(R)` (`DblqhMain.cpp:37661`) | The assert fires on the SR LCP. |
| Partial LCP change detection | scan GCI = previous `MaxGciCompleted` (`Backup.cpp:14567`); TUP writes rows with GCI > scanGCI (`DbtupScan.cpp:1332-1400`) | If new GCIs are not greater than G', changes are silently left out of partial LCPs. |
| DIH replica intervals | new interval `createGci = R+1` (`DbdihMain.cpp:20465`), LCP validity `maxGciStarted <= R` (`:20583-20590`) | The REDO interval bookkeeping must start at G'+1. Otherwise the next SR invalidates the SR LCP and needs REDO the node no longer has. |
| Node-restart copy | copy rows with GCI > the starting node's restorable GCI (`DbdihMain.cpp:9351-9366`) | Works if G' < every new GCI. |
| Event API | `TE_CLUSTER_FAILURE`; `m_latestGCI = 0`; generation++ (`NdbEventOperationImpl.cpp:2887-2969`) | Already accepts epochs going backwards. Epochs of R+1 or R+2 may already have been delivered before the crash (they are delivered before GCP save) (I). |
| Binlog injector | cluster-disconnect incident on every reconnect (`ha_ndbcluster_binlog.cc:7165-7191`); epoch below the handled epoch means "older filesystem" (`:7661-7679`) | The incident is written in any case. Whether the binlog is complete for surviving transactions above R depends on the event protocol (other research). An epoch number used twice in `ndb_binlog_index` only logs a duplicate-key error (`:4605-4622`) (I). |
| NDB$EPOCH and `ndb_apply_status` | conflict when `ROW_GCI64 > max_rep_epoch` (`ndb_conflict.cc:1069-1080`) | Row GCIs must stay monotonic with new epochs. Replayed rows have `gci_lo = 0`. |
| Backup / `ndb_restore` | the backup uses GCP-saved GCIs (`Backup.cpp:5311-5404`) | No impact (I). |
| DICT | `gciToRestart` is stored but never read (`dbdict/Dbdict.cpp:4316`, `4567`); no GCI test in `checkSchemaStatus` (`:4614-4740`) | Objects created after R are not dropped; their data is empty or holds only rows with GCI <= R. |
| Tests | `test/ndbapi/testRestartGci.cpp:262` asserts that there are no rows newer than the restart GCI | Will fail by design. |

**Conclusion (I).** After the agreed replay, the "restorable GCI" must
become G' in every place listed below, and this must be **durable before
the SR LCP and before the first new GCP**:

- `SYSFILE->newestRestorableGCI`, and `lastCompletedGCI[n]` for the SR
  nodes
- `crestartGci` and `m_micro_gcp.m_current_gci/m_old_gci`
- LQH `crestartNewestGci` (for REDO only), `cnewestGci` and
  `cnewestCompletedGci`
- Backup `m_newestRestorableGci`
- NDBCNTR `m_max_completed_gci` and the local sysfile
  `m_max_restorable_gci`
- DIH `c_newest_restorable_gci`

The LCP restore, however, must still use **R** as its bound, because an
LCP that contains GCI R+1 can contain non-surviving transactions. So
today's single `crestartNewestGci` has to be split into
`lcpRestoreBoundGci` (R) and `redoStopGci/cut` (G' plus the survival
rule). In addition, each log part needs a `ZCOMPLETED_GCI_TYPE(G')`
record written and synced at the new head, so that the next SR finds a
stop point (I).

---

## 10. Where the agreement phase could go

### 10.1 Requirements (I)

1. **Same decision on every replica.** Every replica of every fragment
   must apply exactly the same set of operations above R. Each replica
   replays its own REDO, so a replica that lacks a surviving operation
   has to be fixed: by replaying from another node's REDO
   (`EXEC_FRAGREQ` to that log node exists but is unused today), by copy
   or take-over after the SR, or by excluding the transaction (only
   allowed if it was not acknowledged).
2. **Decide before mutating.** The decision must be known before any
   record above R is applied or invalidated, and before the head is
   moved.
3. **Persist the decision** (sysfile v3 field and/or local sysfile)
   before mutating, so that an SR repeated after a crash during this SR
   reuses it, even with a different set of nodes.
4. **Bounded size.** A set of transaction ids per node can be large
   (for example 100k tx/s over about 4 s is about 400k ids x 8 B, about
   3 MB per node). That favours a **cut**, a monotonic durable marker
   (epoch or a per-log-part durable LSN/marker), over an explicit set.
   It could be sent as long or fragmented signals.
5. **What the REDO must provide.** SR needs these from the REDO format
   (other research):
   - a transaction id, or a durable marker, in the commit record or in a
     new record type
   - gci_lo (epoch) if the cut is per epoch
   - a reliable end-of-log: page or record checksums, since release
     builds have no REDO checksum today (section 5.5)
   - optionally a "replica-set change" marker (section 7.2 (b))

### 10.2 Candidate insertion points

| # | Where | Signals and state | Pros | Cons |
|---|---|---|---|---|
| A | **DIH master between `startFragment` completion and `START_RECREQ`** (`completeRestartLab`, `DbdihMain.cpp:21235-21250`) | New `SR_DURABLE_SCAN_REQ(R)` to the LQH proxy of each node in `m_sr_nodes`. Each LDM scans the tail of its log parts and returns `SR_DURABLE_SCAN_CONF(summary)`. The master computes the cut, then persists it (`COPY_GCIREQ` with a new reason or field) and distributes it with the existing `START_RECREQ`, which gets new fields (`StartRecReq`). | DIH already has `m_sr_nodes`, the replica maps (it can apply rule 7.2(a)), the sysfile writer and the master role. The tail scan overlaps the LCP restore. The decision is final before UNDO and REDO. | Needs REDO phase 1 to be complete on every node (add a wait, or start the scan when phase 1 completes). Adds one `COPY_GCIREQ` round. |
| B | **LQH, piggy-backed on the `EXEC_SRREQ` barrier of round 0** (`DblqhMain.cpp:38088-38105`, `38409-38458`) | Extend `EXEC_SRREQ` with each node's summary. Every LQH computes the same deterministic cut, then `srGciLimits/srLogLimits` use it. | The existing all-to-all barrier needs no new coordinator. | No natural place to persist the decision except each node's local sysfile. DIH does not learn the cut, but it needs it to raise R, so another round would be needed. The LCP restore and UNDO are already done, so the tail scan becomes a serial delay. |
| C | **Extend REDO phase 1** (`startphase3Lab` to `closingSrLab`) to read the full tail MBytes, not only page 0 | Each LDM builds its tail summary during phase 1, then reports through A or B. | No separate pass; it starts earliest (NDB phase 3). | Phase 1 starts before R is known locally. It can derive R from the log (the last `ZCOMPLETED_GCI` it finds), or DIH can pass R once `COPY_GCIREQ(RESTART)` arrives (`DbdihMain.cpp:1104`). |

**Recommendation (I): A + C.**

1. LQH starts the tail scan as soon as phase 1 has finished and R is
   known. DIH can tell its local LQH right after `COPY_GCIREQ(RESTART)`.
2. DIH master collects the reports after `startFragment`.
3. DIH applies the replica-trust rule (7.2): a replica whose interval was
   closed at R is not trusted beyond R, and `m_to_nodes` is used for it.
4. DIH computes G' and the cut, and persists it with an extended
   `COPY_GCIREQ(RESTART_DURABLE_CUT)` (sysfile v3).
5. `START_RECREQ` then carries `{R, cut, G'}`.

### 10.3 Changes to REDO execution with a cut (I)

- **Range.** `srGciLimits`: round 0 runs to the end of the log, not to
  `COMPLETED_GCI(R)`. `srLogLimits`: the stop MByte becomes the last
  MByte, since every MByte has `logMaxGciCompleted <= R`.
- **`execSr` `ZCOMMIT_TYPE`.**
  - If `gci <= R`: as today.
  - If `R < gci` and the record is in the cut: execute it, if
    `checkIfExecLog` allows (the fragment's `execSrLastGci` becomes G').
  - Otherwise: `ZINVALID_COMMIT_TYPE`, as today, but with the cut
    instead of `crestartNewestGci` as the test.
- **Stop condition.** Instead of `COMPLETED_GCI(R)`, stop at the
  durable end: the last record covered by the cut, or the first invalid
  page after it. Record the head there and write a new
  `ZCOMPLETED_GCI_TYPE(G')` record (or a new "SR cut" record) before
  invalidation. The `ZNEXT_MBYTE_TYPE` crash (`DblqhMain.cpp:39258-39276`)
  and the head logic (`:39316-39345`) must change.
- **Phase 4.** It works as today from the new head. `cnewestGci` and
  `cnewestCompletedGci` must become G' (`:40499-40515`).
- **Prepare lookup.** Prepare records of surviving transactions above R
  can lie before the R stop MByte. `logLastPrepRef` already handles
  this.
- **Fragments with a replica that is not trusted** (7.2): either a
  remote REDO round, where the trusted peer's LQH executes its tail for
  the untrusted replica (`EXEC_FRAGREQ` with `srLqhLognode[1] = peer`,
  `startGci = R+1`, `lastGci = G'`), or a take-over after the SR. The
  take-over is simpler and already exists.
- **`dirty` page writes** of `ZINVALID_COMMIT_TYPE` must be synced
  before the sysfile raises R to G'.

### 10.4 Number of REDO scans (I)

- Today: one pass of page-0 headers (phase 1), plus one execution pass
  from the oldest LCP start to R per log part (more rounds only for
  remote log nodes), plus about 1-2 MB read in phase 4.
- New: **one extra sequential read of the tail only**, from the MByte
  where `logMaxGciCompleted` reaches R to the end of the log. That is at
  most about 2 GCP intervals of REDO (gci_hi R+1 and possibly R+2, since
  `gci_hi` switches only when a save is due and the previous save is
  idle, `DbdihMain.cpp:18170-18186`).
- The execution pass then reads the tail a second time. It could reuse
  the REDO page cache (`m_redo_page_cache`) if it is large enough.
- A single-pass alternative would buffer every record above R until the
  decision is made. It is not attractive: memory use is unbounded, and
  it would also defer the decision until after the LCP restore.

### 10.5 Failure handling during the SR (V for the facts, I for the design)

- Any node failure during the SR after start phase 2 makes the starting
  nodes exit: "Unhandled node failure ... during restart"
  (`NdbcntrMain.cpp:4187-4209`; QMGR `QmgrMain.cpp:6055-6071`). The new
  phase therefore needs no in-place recovery.
- Repeatability:
  - A crash **before** the cut is persisted: the next SR recomputes the
    cut, which is safe because nothing was changed.
  - A crash **after** it is persisted: the next SR must read the
    persisted cut, tied to R and `m_restart_seq`, and reuse it. It must
    refuse to start (or wait) if the starting nodes cannot provide what
    the cut needs.
  - A crash after some LQHs have invalidated records above R that are
    outside the cut is safe only because the cut was persisted first.
  - A crash during the SR LCP, after R was raised to G': a normal SR to
    G', which needs the `ZCOMPLETED_GCI(G')` record from section 9.

---

## 11. Open questions

1. **Transaction identity.** Which identifier will the REDO commit
   record (or a new record) carry so that SR can decide survival: a
   transaction id, a per-transaction durable marker, or an epoch? Can the
   cut be a single monotonic value (for example the "max fully durable
   epoch" agreed cluster-wide) rather than a set? This decides the signal
   sizes and whether the existing barriers are enough.
2. **Node failure after R, case B.** Will the commit protocol make a
   node failure durable (sysfile write or REDO marker) before
   acknowledging commits that leave the failed replica out? Without it,
   SR cannot tell that X's REDO is incomplete beyond R if the table files
   did not reach disk. That leads to divergent replicas, and to lost
   acknowledged data in a partial SR.
3. **End of log and torn pages.** REDO checksums are compiled out in
   release builds. The partially filled current page is rewritten again
   and again, and 32 KB pages are not written atomically. Which
   checksum or record format will the REDO work provide so that SR can
   find the true durable end and never read garbage after it?
4. **Partial SR policy.** Should partial or partitioned SR be disallowed
   when durable-commit tables exist, unless node-failure durability
   (question 2) is in place?
5. **Raising R.** Should G' be the real highest surviving gci_hi (R+1 or
   R+2), which keeps original row GCIs but makes these GCIs only
   partially present? Or should a new GCI G'' > G' be allocated and
   written as `ZCOMPLETED_GCI(G'')`? Either way, every consumer in
   section 9.2 must see a monotonic GCI.
6. **Epochs already delivered.** Event API and binlog subscribers may
   already have received epochs of R+1 or R+2 before the crash, some of
   whose transactions will not survive. Is "cluster disconnect incident
   plus surviving acknowledged transactions" acceptable, or must the
   binlog be reconciled? Replayed rows also get `gci_lo = 0`, which
   matters for NDB$EPOCH and ROW_GCI64.
7. **Scope.** Only READ_BACKUP=1 tables are durable. Can operations on
   tables without READ_BACKUP inside a surviving transaction above R be
   replayed too (transaction atomicity), or must the survival rule be
   per transaction across all tables? The latter needs every LQH
   involved to keep the information, not only READ_BACKUP ones.
8. **Remote REDO or take-over.** For replicas that cannot be trusted
   beyond R, revive the remote REDO execution (`EXEC_FRAGREQ` to a peer
   log node, `MAX_LOG_EXEC` rounds), which NDBCNTR avoids today, or
   always take over by copy after the SR? A take-over is simpler, but it
   lengthens the SR and lowers redundancy until it completes.
9. **UNDO log space** when the REDO run is longer (non-abortable UNDO
   with a 4-page reserve): is a check or extra reserve needed?
10. **`testRestartGci` and similar tests** assume nothing newer than the
    restart GCI survives. They need new expectations for durable tables.
