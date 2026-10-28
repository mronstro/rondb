# RONDB-1150 — Durable commits across a cluster restart: master plan

Status: **Revision 12, 2026-10-29. Decisions D0–D8 are settled (§11). The
first implementation step, the REDO log on persistent memory, is designed in
`pmem_redo_design.md` (planning subtask P2 done). The implementation plan
for all phases is `implementation_plan.md`; progress on step 1 is in
`step1_phases.md`.**
Branch: `RONDB-1150-durable-commits` (base 26.10-main, commit 7128c75dca4).
All paths are relative to `storage/ndb/`.

| Document | Content |
|---|---|
| `durable_commits_plan.md` | This file: the conclusion, configuration, commit protocol, cluster-restart algorithm and its ordering proof, subtasks and phases |
| `research_commit_protocol.md` | DBTC/DBLQH prepare, commit and complete; where locks are released and rows become visible; READ_BACKUP; TC takeover; hook points |
| `research_redo_log.md` | REDO layout, record formats, the write path, tail management |
| `research_system_restart.md` | System restart (SR) flow, the sysfile and the restorable GCI, REDO execution and invalidation, node-failure persistence, where an agreement phase fits |
| `research_micro_gcp.md` | The GCP/micro-GCP protocol and the consistent-cut proof (used in §6), the durable-epoch alternative (not pursued) |
| `research_literature.md` | 2PC variants, early lock release, epoch commit, how recovery cuts are computed in FoundationDB, Aurora, FaRM, CockroachDB and TiDB |
| `pmem_redo_design.md` | **Step 1 design:** the REDO log on persistent memory. Consolidates the four notes below and settles their conflicts (decisions E1–E20, steps S1–S7, questions Q1–Q8 answered) |
| `implementation_plan.md` | **Implementation plan:** order of the phases, milestones, step 1 split into pull requests, conventions, points settled between the detail plans, questions for the architect |
| `impl_step1_platform.md`, `impl_step1_lqh_write.md`, `impl_step1_recovery_test.md` | Step 1 work packages: platform (S1–S3), DBLQH write side (S4–S5), recovery and tests (S6–S7) |
| `impl_next_steps.md` | Work packages for X1 and X3–X8, new signals, design issues found |
| `research_pmem_hardware.md` | Failure atomicity, devices available in 2026, flush instructions and their cost, Linux DAX interfaces, CRC32C |
| `pmem_redo_format.md` | Record framing and checksum, write-once page header, every record layout, FILLER, space reservation and overhead |
| `pmem_redo_recovery.md` | Today's head and tail search traced through the code, end-of-log rule, invalidation by zeroing, torn-safe last-file slots |
| `pmem_redo_write_path.md` | Mapping the files, the persist primitive, barrier placement, shared log parts, mbyte and file switch, GCP save, config |

**Revision history.**

- **Revision 1** recommended durable epochs.
- **Revision 2** (review 1) switched to per-transaction recovery on PMEM,
  treating one COMMIT record as proof of commit. That needed recovery to
  find PREPAREs whose COMMIT never reached the replica.
- **Revision 3** (review 2). Those PREPAREs cannot be found: they can be
  gigabytes back, reachable only through a COMMIT's backward reference.
  Added a persistent COMPLETE record, and moved visibility and lock release
  to COMPLETE on every replica.
- **Revision 4** (review 3). Aligned with the conclusion in §0: two config
  variables with online activation at a GCI; SR phase 2 executes a
  transaction's COMMITs when its COMPLETE is found, and resolves the rest by
  an exchange between REDO log parts with no coordinator; decisions
  settled. Epoch markers dropped.
- **Revision 5** (review 4). The exchange carries only transid and a count;
  the fallback decides from counts per node group, so COMMIT records need
  no operation id. The tail is the last GCI (epochs are only for global
  replication). Transid reuse is prevented by holding back a failed API
  node id. A node failure in the tail GCI is recorded in a node-failure
  file (D3). D4 reframed: a node group with only stale nodes starting would
  half-apply transactions.
- **Revision 6** (review 5). A stale node takes no part in the cluster
  restart, not even phase 1; it joins by node restart afterwards, like
  today's not-restorable nodes. Recovery needs at least one non-stale node
  in each node group (D4 settled).
- **Revision 7** (review 6). The first implementation step is PMEM support
  for the REDO log. Four parallel notes and a consolidated design
  (`pmem_redo_design.md`): W = 64 bytes; a position-bound checksum (then
  CRC32C; XXH3 since step 1 phase 1, E4) on every record and page header;
  write-once page headers; a FILLER at every persist point; records built
  in DRAM and copied out with non-temporal stores;
  atomic COMMIT invalidation; two-slot "last file" pointer; invalidation by
  zeroing. §2.1, §7, §9 and §10 updated.
- **Revision 8** (review 7). "Immediately" defined: persist while handling
  the COMMIT or COMPLETE signal, before the next COMMIT, COMMITTED,
  COMPLETE or COMPLETED is sent, always. Both restart phases run in one
  scan. W = 64 fixed. An unsafe shutdown reported by the device makes the
  node stale. Target hardware: CXL 2.0 persistent memory, 200–2000 ns per
  persist.
- **Revision 9** (review 8). PMEM REDO refused with an encrypted file
  system in the first version. No REDO log buffer in PMEM mode, so an
  operation that cannot be logged aborts, as today. Each log part on the
  persistent memory closest to its LDM. All step-1 questions answered.
- **Revision 10** (review 9). Implementation plan for all phases
  (`implementation_plan.md` and four detail plans). PMEM mode without DAX is
  refused always, with hidden test modes for development. The step-B
  exchange gets three new signals, aggregated per node in the DBLQH proxy;
  the DONE signal carries each part's highest GCI so all parts agree on G'.
  Open design issues for the later steps (dirty writes, read locks, the
  takeover race) are listed in `implementation_plan.md` §3 and §5.
- **Revision 11** (review 10). PMEM mode, and durable commits, must run on
  normal DRAM through the test modes, release builds included, since no
  PMEM hardware is available; the persist code is the production code in
  every mode. `FileSystemPathRedoLog` is used only in PMEM mode; file mode
  keeps today's REDO placement. The read-buffer size for log execution
  (`ZMIN_READ_BUFFER_SIZE`) is fixed in both modes as a separate bug fix.
  The initial-start pages are written through the mapping, so the page-header
  checksum covers every header word. A hidden persist delay lets DRAM runs
  approximate the latency of CXL persistent memory.
- **Revision 12** (step 1, phase 1). The checksum of the REDO records, the
  page headers and the slots is XXH3 instead of CRC32C, chosen on measured
  timings: the body in one call, then a seeded hash of `w0` and `S`
  (`pmem_redo_design.md` E4, `step1_phases.md` decision 5). XXH3 chooses
  AVX2 at run time on x86-64. That also speeds up the hash of keys over
  240 bytes, with the same results.

---

## 0. Conclusion of the study

This is the conclusion from review 3. The rest of the plan elaborates it.

1. A config variable defines whether disk durable commits are used. It can
   be **activated online at a certain GCI**. It can never be deactivated
   online, only by a cluster restart (§2.2).
2. A config variable defines whether the REDO log uses **memory-mapped
   files**. Disk durable commits are supported only with memory-mapped
   files (§2.1), and only on persistent memory: otherwise the node refuses
   to start (D8).
3. With disk durable commits a **COMPLETE log record** is also written to
   the REDO log. It carries the transaction id. The **COMMIT record also
   gets the transaction id** (§7).
4. Both COMMIT and COMPLETE records are **synced** (persisted) when written
   (§3, invariants C and K).
5. **Locks are held until the COMPLETE record is synced** (§3, invariant L).
6. **Node restarts are not affected** (§8).
7. A cluster restart first runs the **normal recovery to the GCI made
   durable by the GCP protocol**, R_gcp (§5.1).
8. A cluster restart then runs a **second phase** for the GCIs above R_gcp,
   which hold a mix of committed and aborted transactions (§5.2). A hash
   table keyed by transaction id queues the COMMIT records in log order. A
   COMPLETE record executes the queued COMMITs. The transactions left
   without a COMPLETE are checked with all other REDO log parts; they
   commit if any part has seen a COMPLETE for them, and are aborted (their
   COMMIT records invalidated) otherwise. The preferred variant removes a
   transaction from the hash table once it is executed, and finds the
   remote COMPLETEs by a second scan; it needs less memory.

**Constraints from earlier reviews that still hold:**

| # | Constraint |
|---|---|
| C2 | Durability is cluster-wide; no per-table or per-transaction combinations. Every logged write is durable |
| C3 | Production uses persistent memory, and a REDO write is persisted synchronously, without a real-time break. No fsync, no NDBFS round trip, no group commit. Target hardware (review 7): CXL 2.0 persistent memory modules, about 200–2000 ns per persist |
| C5 | Recovery reaches a PREPARE only through the backward reference in a COMMIT record, so PREPAREs are never searched for. A PREPARE without a COMMIT record is never applied |
| — | The REDO format used with memory-mapped files is new, with checksums and a reliable end of log built in; today's REDO checksum problems are out of scope |

---

## 1. Goal

**Guarantees:**

- **G1.** An acknowledged commit survives a crash of all data nodes,
  including power loss.
- **G2.** The restored state contains only whole transactions and is closed
  under dependencies: if a restored transaction read or overwrote another
  transaction's data, that transaction is restored too.
- **G3.** All replicas of a fragment are identical after the SR (this needs
  the node-failure file, §5.4).
- **G4.** The cost on PMEM is one extra round of lock hold on the primary,
  plus one extra round of ack latency for tables without READ_BACKUP
  (§3.2, §3.3), plus two persists per replica on the commit path (0.4–4 µs
  per replica on CXL 2.0 persistent memory).

**Scope.** Every logged table. No-logging tables are emptied at SR as today.

---

## 2. Configuration and activation

### 2.1 Memory-mapped REDO (conclusion 2)

The full design is `pmem_redo_design.md`. In short:

- A new config variable (`RedoLogMode = file | pmem`, names to be decided)
  puts the REDO log parts in memory-mapped files on PMEM, with its own path
  (`FileSystemPathRedoLog`, PMEM mode only: file mode keeps today's REDO
  placement, review 10). Switching a node to it, or back, needs an
  initial node restart; a cluster switches by rolling initial node restarts.
- **Mapping.** NDBFS opens and maps every REDO file once at start
  (`MAP_SHARED_VALIDATE | MAP_SYNC`) and prefaults it; the files are fully
  written at initial start. NDBFS leaves the write path. `MAP_SYNC` failing
  means the file is not on DAX, and the node refuses to start in PMEM mode,
  with or without durable commits (D8; `implementation_plan.md` R8). Hidden
  test modes (`emulated`, `nodax`) let PMEM mode run on emulated memory or
  on any file, macOS included, without durability, for development and tests
  (review 10). Until PMEM hardware is available everything runs this way,
  release builds and durable commits included. A test mode changes only the
  map flags and the start checks; the persist code is the production code.
  On DRAM a commit survives a crash of every data-node process, since the
  page cache holds the mapped file, but not an OS crash or a power loss.
- **Geometry kept.** Files, 1 MB mbytes, 32 KB pages with a header on each
  page, the FD record in page 0, and today's head and tail search.
- **Write unit W = 64 bytes**, fixed and recorded in the page header.
- **Write path.** Records are built in DRAM log pages as today. At a persist
  point the new bytes are padded with a FILLER to the next 64-byte boundary
  and copied to the mapping with non-temporal stores, then `sfence`. The
  same code serves ADR, eADR and CXL; store + `clwb` is a benchmarked
  alternative. A persisted unit is not written again in that lap.
- **Without durable commits**, the log is persisted at GCP save, mbyte
  switch, file switch and page full, which keeps today's durability.
- **Checks at start:** `persistence_domain` (empty, as with `memmap=`
  emulation, is refused unless a test setting is on), the device's
  dirty-shutdown count, its bad-block list. PMEM REDO is refused with
  `EncryptedFileSystem` or `Diskless` in the first version (review 8).
- **Placement (review 8).** Each log part's files go on the persistent
  memory closest to the LDM that owns the part. `FileSystemPathRedoLog`
  takes one path per NUMA node.
- **REDO log full (review 8).** As today: there is no REDO log buffer in
  PMEM mode, only a few staging pages, so an operation that cannot be logged
  aborts (410 when log space is short). No queueing in PMEM mode.
- **Hardware.** The target is CXL 2.0 persistent memory modules, about
  200–2000 ns per persist (review 7). Linux reports them as
  `memory_controller`, so flushes are needed; non-temporal stores + `sfence`
  is the default barrier mode. Optane is discontinued and NVDIMM-N exists
  only for DDR4. No cloud offering was found, so the feature runs on bare
  metal.
- **Testing without PMEM hardware.** The Linux `memmap=` kernel parameter
  creates a RAM-backed `/dev/pmem` device that passes the DAX check. Data
  survives a process crash but not a reboot, which is enough for MTR and
  autotest. It can never catch a missing barrier; that needs the
  power-loss emulation of step S7.

### 2.2 Durable commits, activated online at a GCI (conclusion 1)

- A second config variable (name to be decided) turns durable commits on.
  It can be set online only once every data node runs memory-mapped REDO on
  PMEM.
- **Activation.** The DIH master picks an activation GCI g and distributes
  it with the GCP protocol (a flag in GCP_PREPARE/GCP_COMMIT), and records
  it in the sysfile. Every transaction whose GCI is ≥ g follows the durable
  protocol of §3. TC knows the GCI at DIVERIFYCONF, before it sends COMMIT,
  so it can choose the protocol per transaction; LQH gets the GCI in COMMIT.
- **When the guarantee starts.** A durable transaction with GCI ≥ g may
  depend on a non-durable one with GCI < g. The tail is closed under
  dependencies only once every GCI < g is restorable. So:
  - activation is reported complete (ndbinfo) once the GCP save of g − 1
    has completed;
  - at SR, phase 2 (§5.2) runs only if R_gcp ≥ g − 1, and only for records
    with GCI ≥ g. Records with R_gcp < GCI < g are invalidated as today.
- **Deactivation** only by a cluster restart: the new setting takes effect
  after that SR. The SR itself still runs phase 2 on the durable tail,
  because the mode recorded in the sysfile governs the tail, not the new
  config.
- A node that does a node restart while durable commits are active uses the
  durable protocol as soon as it takes part in commits.

---

## 3. Commit protocol (conclusions 3–5)

### 3.1 Invariants and the survival rule

| Id | Invariant | Where |
|---|---|---|
| **C** | A replica persists its COMMIT record, and with it the earlier PREPARE in the same log part, before it sends COMMITTED or forwards COMMIT (or COMMITCONF on the parallel path) | Barrier after `writeCommitLog` (`DblqhMain.cpp:15343`, `912`), before `commitReplyLab`. One fragment has one log part, so one barrier over the part's unpersisted range covers both |
| **K** | A replica persists a COMPLETE record before it makes the operation visible (TUP real commit, ACC_COMMITREQ) and before it forwards COMPLETE or sends COMPLETED. One COMPLETE record per operation (D7) | New `writeCompleteLog` in `execCOMPLETE`/`execCOMPLETEREQ` (`DblqhMain.cpp:15004-15017, 15120-15140`), before `localCommitLab` |
| **L** | No replica makes an operation visible, or releases its lock, before its COMPLETE record is persistent. The primary's local commit moves from COMMIT (`commitReqLab`, `15267`; twin at `921-927`) to COMPLETE (a seq-0 branch in `execCOMPLETE`, which today calls only `completeTransLastLab`, `15010-15013`) | `tupcommit_conf` (`15552-15615`) needs an operation flag to pick commit-reply or complete-last |
| **A** | The API ack (TCKEYCONF/TC_COMMITCONF, and TCKEY_FAILCONF after takeover) is sent only after the **last** COMPLETED (D6) | TF_LATE_COMMIT forced on in durable mode (`DbtcMain.cpp:5616-5627`, `9302-9307`). The takeover ack moves to `check_finished_complete_handling` (`15886-15915`) |
| **F** | If a participating node fails before TC has sent any COMPLETE for T, T is aborted (review 3, answer to D3). A replica that already persisted its COMMIT record for T persists an ABORT record carrying the transid before it drops the buffered commit and releases the lock | TC node-failure handling and takeover (P3). LQH needs an abort path from the committed state. The takeover TC must be able to tell whether any COMPLETE was sent, although LQH releases its operation record after COMPLETE |

TC sends COMPLETE only after every COMMITTED (or COMMITCONF). With C, K, L,
A and F:

- **COMPLETE ⇒ every COMMIT is executable.** If any replica has a COMPLETE
  record for T, every live replica of every T operation has a persistent
  COMMIT record, which points back to a persistent PREPARE.
- **Visible or acknowledged ⇒ a COMPLETE record exists** (K, L, A).
- **No COMPLETE ⇒ abort is safe.** Nobody saw T and the API was not told it
  committed.

**Survival rule:** T survives iff a COMPLETE record for T is found in some
starting REDO log part. In a partial SR the fallback of §5.5 also applies.

### 3.2 When are locks released?

**At COMPLETE, on every replica, after that replica's COMPLETE record is
persistent** (conclusion 5).
- Backups already release at COMPLETE today.
- The primary moves from COMMIT to COMPLETE.
- Locking, committed and backup reads all see a change only once it is
  guaranteed to survive.

**Primary X-lock hold** (t_p is the prepare chain, t_c one hop, R
replicas):

| Commit path | Today | Durable mode |
|---|---|---|
| Linear | ≈ t_p + R·t_c | ≈ t_p + 2R·t_c |
| Parallel COMMITREQ/COMPLETEREQ | ≈ t_p + t_c | ≈ t_p + 2·t_c |

On PMEM no sync time is added; the cost is one more round of message
latency on the primary. A hot row's throughput limit (about 1/hold) drops
accordingly, and so does the number of lock waiters that fit within
`TransactionDeadlockDetectionTimeout`.

**Side effects:**
- Detached triggers fire later on the primary. SUMA, the binlog and backup
  logging are delayed by one round.
- The lock-free unique-index base read gets
  `ZTUPLE_NOT_YET_COMMITTED_ERROR` in a wider window
  (`research_commit_protocol.md` §3).

### 3.3 When is the disk written, and is an extra round needed?

- **The rule (review 7):** the COMMIT or COMPLETE record is persisted as
  part of handling the COMMIT or COMPLETE signal, and before the next
  COMMIT, COMMITTED, COMPLETE or COMPLETED signal is sent. This holds
  always: a later optimisation may delay the sync, but then it delays the
  signal too. The local commit (visibility, lock release) also comes after
  the barrier. One barrier covers every record written while handling the
  signal, for example TUP's loop over the operations on one row
  (`pmem_redo_design.md` E8).
- Each barrier costs about 200–2000 ns on the target CXL 2.0 persistent
  memory. With 2 replicas the linear chain has 4 barriers in series, so
  0.8–8 µs more per transaction.
- **No new message round.** The existing COMPLETE phase is the round that
  says "the COMMITs can be executed".
  - For READ_BACKUP tables the ack point is unchanged.
  - For other tables the ack moves from after COMMITTED to after the last
    COMPLETED: one round more.
- Acking after the first COMPLETED is ruled out (D6): the primary now makes
  rows visible only at COMPLETE, so a client could read its own row and get
  the old value.

### 3.4 Paths to check against C, K, L, A and F (subtask P3)

- linear and parallel commit/complete;
- takeover COMMITREQ/COMPLETEREQ, and the abort decision of F;
- dirty writes, which commit at prepare time and need a COMPLETE record
  written along with their COMMIT;
- `AC_NR_COPY`, which commits at COMMIT during node restart;
- several operations on the same row (`LOG_COMMIT_WRITTEN_WAIT_SIGNAL`,
  `DbtupCommit.cpp:247-276`);
- queued commit-log writes (`DblqhMain.cpp:921-927`);
- unique-index, fully-replicated and reorg trigger operations;
- the replica applier;
- disk-data columns;
- operation-level aborts with `IgnoreError`.

---

## 4. Terms

| Term | Meaning |
|---|---|
| R_gcp | The restorable GCI from the sysfile (today's SR point) |
| g | The GCI at which durable commits were activated (§2.2) |
| tail | REDO records of a log part with GCI > R_gcp. Normally only the last GCI; it also holds the GCI before it if the crash came while that GCI's GCP save was still running. Epochs (gci_lo) matter only for global replication and play no part here |
| log part | A REDO log part on a starting node; the unit that scans, exchanges and executes in phase 2 |
| in-doubt (in a log part) | A transid with COMMIT records in that part's tail and no COMPLETE or ABORT record for it there |
| G' | The highest GCI applied in phase 2; the new restorable GCI |

---

## 5. Cluster restart

### 5.1 Phase 1: normal recovery to R_gcp (conclusion 7)

**As today:**
- LCP restore, with the bound at R_gcp;
- disk-data UNDO;
- each log part replays the COMMIT records with GCI ≤ R_gcp, following
  their backward references to the PREPAREs.

**Not done any more** for the durable tail:
- the `ZINVALID_COMMIT_TYPE` rewrite of commit records above R_gcp
  (`DblqhMain.cpp:39117-39132`);
- moving the head to `ZCOMPLETED_GCI(R_gcp)`;
- the phase-4 invalidation.

### 5.2 Phase 2: the durable tail (conclusion 8, preferred variant)

Runs in every log part of every starting node, on the tail records with
GCI ≥ g (§2.2).

**Where the scan starts.** The first COMMIT with GCI > R_gcp can come before
`COMPLETED_GCI(R_gcp)` in the log, so step A cannot start at that record.
Settled (review 7, `pmem_redo_design.md` E16): both phases run in one scan.
Step A runs inside today's execution scan, which starts at the start mbyte for
`logStartGci = R_gcp + 1`. COMMITs with GCI ≤ R_gcp are executed there as
today, the others go to the hash table, and the scan continues to the end
of log E. Step B's rescan starts at the same position. §6 shows this keeps
each row's order.

**Step A — first scan of the tail, in log order.**

| Record | Action |
|---|---|
| COMMIT | Append a reference to the record to the FIFO queue of its transid in the part's hash table (create the entry if needed) |
| COMPLETE, entry has COMMITs | Execute the queued COMMITs in FIFO order through their backward references, as today's replay does, using the record's GCI64. Remove the entry |
| COMPLETE, no entry | Ignore: a later operation's COMPLETE of a transaction already executed, or a transaction with GCI ≤ R_gcp |
| ABORT flagged `AF_AFTER_COMMIT` (F) | Remove the entry; its COMMIT records are invalidated in step C. An unflagged ABORT (a prepared operation aborted, for example with `IgnoreError`) is ignored |

- No COMMIT of T can follow a COMPLETE of T in the same log part, because
  COMPLETE is sent only after every COMMITTED. A violation is a crash
  (corrupt log).
- What remains at the end is the part's in-doubt set.
- The table holds a transaction only between its first COMMIT and its first
  COMPLETE in the log, about one round, so its size follows the number of
  transactions committing at the same time, not the tail length.

**Step B — exchange with the other log parts.**

1. Each part sends its in-doubt set to every other part. Each entry is the
   transid and the number of COMMIT records the part holds for it (used by
   the fallback in §5.5). The COMMIT records themselves stay local: they
   are executed or invalidated by the verdict.
2. A part that has received the in-doubt sets of all parts scans its tail
   again, looking only at COMPLETE and ABORT records. For one whose transid
   is in the received sets:
   - a COMPLETE whose transid is in the part's own in-doubt set means a
     corrupt log (step A would have executed it): crash;
   - otherwise send "T complete" (or "T aborted" for an ABORT flagged
     `AF_AFTER_COMMIT`) to each part that listed T, and remove T from the
     received set.
3. The part then sends "done" to every part. Signal order between two block
   instances is kept, so all of a part's "T complete" messages arrive
   before its "done". The done message also carries the part's highest
   executed GCI, so every part computes the same G'.

**Signals** (`implementation_plan.md` §3): `SR_TAIL_INDOUBT_REP`,
`SR_TAIL_HIT_REP` and `SR_TAIL_DONE_REP`, data-node only. They are
aggregated per node in the DBLQH proxy, so the message count grows with
the number of nodes, not with the square of the number of log parts.

**Step C — verdicts, once "done" has arrived from every part.**

For each transaction still in the part's in-doubt set:

| Condition | Verdict |
|---|---|
| "T complete" received | Commit: execute the queued COMMITs in FIFO order |
| Otherwise, fallback (§5.5): the counts received for T pass the node-group rule, and no "T aborted" was received | Commit, as above |
| Otherwise | Abort: mark T's COMMIT records invalidated in place, one atomic flag store each (`pmem_redo_design.md` E9) |

- Every part computes the verdict from the same exchanged data, so all parts
  agree with no coordinator (D2).
- Then the hash table is freed, and the phase ends once every part reports
  it finished.

**Properties.**
- PREPAREs without a COMMIT record are never touched.
- No REDO is written for the replay, there is no TC execution, no locking
  and no trigger firing. Ordered indexes are rebuilt after restore, as
  today.
- Work is linear in the tail (two scans; the second reads only COMPLETE
  records). Messages are O(k·L), where k is the number of in-doubt
  transactions and L the number of log parts.
- **Repeatable.** Nothing in the REDO changes before every part is done;
  after that only the COMMITs of aborted transactions are rewritten. A
  rerun after a crash during the SR reaches the same verdicts: an aborted
  transaction had no COMPLETE anywhere and fails the fallback again.

**Alternative variant** (first one in the conclusion, not preferred). Keep
each executed transid in the hash table with a "committed" flag, and answer
the other parts' queries from the table instead of rescanning. It avoids
the second scan, but the table holds every transaction of the tail.

### 5.3 Phase 3: raise the restorable GCI and resume

- Set the restorable GCI to G' durably, before the SR LCP and the first new
  GCP. All dependents must see it (`research_system_restart.md` §9.2): the
  sysfile, DIH, LQH, Backup, NDBCNTR and the DIH replica intervals.
- The LCP-restore bound stays at R_gcp.
- Place the new log head **after** the old tail, and write an SR-head
  record (R_gcp, G', restart sequence), so that a repeated SR finds the same
  state.
- New GCIs start above G'.

### 5.4 A node failure in the tail GCI (D3)

Review 4 agreed: a node failure in the tail GCI creates a problem that does
not exist without this feature. Rule F covers transactions in flight at the
failure; this is about transactions that **start after** it.

1. Node X fails. NODE_FAILREP removes X from the in-memory distribution;
   DIH starts writing the table files that mark X's replicas as crashed
   (`DbdihMain.cpp:12276-12320`), but TC already uses the new distribution.
2. New transactions on X's fragments run on its peer Y only, write COMMIT
   and COMPLETE on Y, and are acknowledged.
3. The whole cluster loses power before the GCP save of that GCI. Every
   sysfile still shows X as restorable at R_gcp
   (`research_system_restart.md` §7.2, case B).
4. At SR, X starts as a normal node. Phase 2 on Y executes the transactions
   of step 2. X never saw them: they are not in X's hash table, so the
   exchange does not reach X either. X's and Y's replicas differ.

**Fix: a node-failure file.**

- Each data node has a small file on the PMEM file system, beside the REDO
  but not part of any log part. It is a ring of records: failed node id,
  the GCI current at the failure, failure number.
- QMGR appends a record and issues a persist barrier before it sends
  PREP_FAILCONF (`QmgrMain.cpp:7636`, reached from `execPREP_FAILREQ`,
  `7359`). The president sends COMMIT_FAILREQ, and NODE_FAILREP is sent
  only from there, after every PREP_FAILCONF (`7647-7740`, `7807-7944`).
  So every survivor has the record before any TC or DIH can leave X out of
  a transaction. Cost: one PMEM write per node failure.
- Every survivor writes it, not only X's node-group peers, so that the
  failure is known as long as any node that was running at the time
  starts (needed for §5.5).
- **Why not in the REDO log:**
  - the fact is per node, not per log part, and the decision it feeds (may
    X's REDO be used in phase 2?) is taken per node by DIH before phase 2
    starts;
  - a REDO record would need a signal round to every LDM before
    PREP_FAILCONF;
  - it would be subject to the head and tail management of the log parts.
- Records with GCI ≤ R_gcp are obsolete: the GCP save after the failure
  already excludes X through `lastCompletedGCI`. They can be overwritten.
- **Stale node.** X is stale if some starting node recorded X's failure
  with GCI > R_gcp: X failed after the last GCP save, the cluster ran on
  without it, and no sysfile shows it.
- **X is also stale if its PMEM device reports an unsafe shutdown** since
  the last start (review 7). Its REDO is still readable up to its valid end,
  because the checksums cut off lost or torn last writes, but writes
  already acknowledged as persistent may be missing. How the flag is read,
  and whether it really means lost acknowledged writes, depends on the
  device (`pmem_redo_design.md` E17).
- **A stale node takes no part in the cluster restart at all**, neither
  phase 1 nor phase 2 (review 5). It is restarted by a node restart after
  the non-stale nodes have recovered. This is the existing path for a node
  that cannot be restored from its own REDO: NDBCNTR puts it in
  `m_withLogNotRestorable` (`NdbcntrMain.cpp:2730-2743`).
- So the node-failure records must reach the master before it fixes the
  node sets: each starting node sends them with its start request
  (CNTR_START_REQ, or a new signal in the same phase).
- **Recovery needs at least one non-stale node in each node group**
  (§5.5).

### 5.5 Partial SR

**Missing COMPLETE evidence (D5).**
- With linear complete, backup B writes COMPLETE and makes the row visible
  before primary P gets COMPLETE. If B's node does not start, no starting
  part may have a COMPLETE for T, although T was visible on B.
- COMMIT records carry `opCount`: the number of logged write operations of
  T. TC knows it when it sends COMMIT; the takeover TC rebuilds it from
  LQH_TRANSCONF.
- Every node of a node group holds a replica of the same fragments, and
  writes one COMMIT record per operation on them. So a node's count (the
  sum over its parts from step B) is the number of T's operations in its
  node group that it has COMMIT records for.
- **Fallback rule:** within each node group, every node taking part in the
  SR reports the same count, and the counts of the node groups add up to
  `opCount`. Then every operation has a COMMIT record on every replica in
  the SR, so every replica can execute T. No operation id is needed.
- This always holds once any COMPLETE was written, because COMPLETE comes
  after every COMMITTED.
- A transaction with every COMMIT but no COMPLETE may correctly go either
  way: the commit was decided and nobody saw it.
- A "T aborted" from step B (rule F) vetoes the fallback, so it never
  revives a transaction that was aborted at run time.

**A node group with only stale nodes starting (D4).**

Example: node group 0 is X and Y, node group 1 is Z and W.
1. X fails. T then writes row a on Y (node group 0) and row b on Z and W
   (node group 1), completes and is acknowledged.
2. The cluster crashes, and Y's machine does not come back.
3. Z and W have a COMPLETE for T, so phase 2 applies b. X never saw T, so a
   is not applied. **T would be half applied**: a broken transaction, not
   only a lost one.

**Rule (review 5):** recovery needs at least one non-stale node in each node
group. With the node-failure file, Z and W know that X is stale, so node
group 0 has no node that can recover, and the SR does not start until Y is
back. Whether to also offer a forced start, which would restore the whole
cluster to R_gcp (a consistent cut) and lose the acknowledged commits after
it, is not decided.

With a single node group (X and Y only), nothing can reveal that X is
stale: the only witness, Y, is gone. X recovers alone; only the commits on
Y are lost, and nothing is half applied.

---

## 6. Why no global transaction order is needed

**Claim.** Each log part executes the surviving transactions as in §5.1 and
§5.2. Every row then ends in the state that executing the survivors
serially in commit order would produce. No ordering across fragments or
transactions is needed, and the cost is linear.

### 6.1 Facts used

1. **After-images.** REDO records hold the values written. Interpreted
   updates and appends are logged as the ATTRINFO holding their resulting
   values (`DblqhMain.cpp:10865-10872`, `DbtupExecQuery.cpp:6695-6725`).
   Applying a record depends only on its own row's prior state.
2. **Locks are held to the COMPLETE record.** A fragment's REDO is one log
   part. On each replica a writer holds the row's X-lock from PREPARE until
   after its COMPLETE record for that operation is persistent (K, L), or
   until its ABORT record (F). The next writer's PREPARE, COMMIT and
   COMPLETE come after it gets the lock.
3. **GCI monotonicity.** If T2 read or overwrote T1's write, GCI(T2) ≥
   GCI(T1) (`research_micro_gcp.md` §3.3; commits are blocked between
   GCP_PREPARE and GCP_COMMIT, `DbdihMain.cpp:18687, 18812`).
4. **FIFO within a transaction.** T's COMMITs in a log part are executed in
   log order, so several operations of T on one row keep their order.

### 6.2 Proof

Take T1 before T2 on row r, on replica X.

1. By fact 2, X's log holds T1's COMPLETE(r) before T2's COMMIT(r).
2. If T1 has a COMPLETE in X's part, step A executes T1 at its first COMPLETE
   there, which is no later than COMPLETE(r). T2 is executed at its own
   first COMPLETE, after its COMMIT(r), or in step C, which is after the
   scan. Either way T1 runs first.
3. If T1 has no COMPLETE or ABORT in X's part, T1 still held its lock on r
   at the crash (fact 2), so no T2 follows it on r in X's log. If T1 has an
   ABORT record, it is aborted and never executed.
4. By fact 3, a row's GCI ≤ R_gcp writes all come before its tail writes,
   so phase 1 followed by phase 2 keeps the order.
5. By fact 1, a row's final state depends only on the sequence of surviving
   writes to it, and that sequence is preserved.

**Closure.** If T2 read T1's write, the write was visible, so T1 has a
COMPLETE record (K) and survives. If T2 overwrote T1 on X, T1's COMPLETE(r)
is in X's log, so T1 survives. ∎

**Comparison with executing through a TC.** Routing tail transactions to
TCs would throw away the order the log already holds and rebuild it (a
topological sort, O(n + e)), and would re-fire triggers, take locks and
ship row data. Only the commit-or-abort verdict needs coordination.

**Binlog.** An epoch reaches the binlog only once every transaction in it
has completed. Those transactions have COMPLETE records and survive, so
the binlog is never ahead of the cluster. Survivors from epochs that had
not completed are missing from the binlog; today's post-crash incident
event covers that.

---

## 7. REDO records

The memory-mapped REDO uses a new format (§2.1); the details are in
`pmem_redo_design.md` E3–E13 and `pmem_redo_format.md`.

**Framing.** Every record is 8-byte aligned with an even length. Word 0 holds
type, flags and length; word 1 a 32-bit XXH3 checksum (E4): the body is
hashed, then mixed with word 0 and a 16-byte suffix that is never stored:
lap, a reserved word, log part and file, and the position. So a record from
an earlier lap at the same offset never validates. The page header is
written once at page init with its own checksum and never updated; its GCI
fields keep their meaning as snapshots at page start. There is no
whole-page checksum and no fill index on PMEM.

| Record | Words | Content | Purpose |
|---|---|---|---|
| PREPARE | 8 + key + attrinfo, even | As today; the length moves into word 0, the checksum takes its slot | Reached only through the COMMIT back-reference |
| COMMIT | 12 | tableId, schemaVersion, fragId, the PREPARE reference packed into 2 words, gci_hi, **gci_lo**, **transid**, **opCount**. Flags: durable, invalidated | Phase 2 queue; exact row GCI64 (replay sets `gci_lo = 0` today); partial-SR fallback |
| **COMPLETE** (new) | 4 | transid. One per operation (D7) | Executes T's queued COMMITs |
| ABORT | 4 | transid. Flag `AF_AFTER_COMMIT` when written after a COMMIT (F) | Removes T from the phase-2 queue; only flagged ABORTs veto the fallback |
| COMPLETED_GCI | 4 | gci | As today |
| NEXT_MBYTE | 2 | — | As today, now with a checksum |
| **FILLER** (new) | 2 + n | — | Pads to the next 64-byte boundary at every persist point |
| SR_HEAD | 6 | R_gcp, G', restart sequence | Repeatable SR; stop point for the next SR |

- **Invalidating a COMMIT** sets a flag bit in word 0 with one aligned store;
  the bit is outside the checksum, so the record stays valid. A type rewrite
  would fail the checksum and cut the log there.
- **The "last file in use" pointer** in page 0 of file 0 becomes two
  checksummed slots, written alternately.
- The node-failure records (§5.4) are not REDO records; they live in a
  separate node-failure file.

**Space.** The per-operation reservation grows from 10 to 46 words: COMMIT,
COMPLETE or ABORT, and two FILLERs. A small update (2 key and 10 attrinfo
words) takes 192 bytes per replica instead of 116 today; a 100-word update
576 instead of 476. The default REDO size can stay.

---

## 8. What does not change

- **Node restarts** (conclusion 6). A starting node replays its own REDO up
  to its own restorable GCI and is brought up to date by copy-fragment, as
  today. Its REDO replay must recognise the new record types.
- The number of message rounds.
- The GCP/micro-GCP protocol, apart from carrying the activation GCI.
- LCP and the LCP-restore bound.
- The API and SQL semantics. The only visible effect is ack timing for
  tables without READ_BACKUP.
- **Changed:** the primary's local commit and lock release (§3.2), the ack
  point (A), and abort after COMMIT on node failure (F).

---

## 9. Risks

1. **Barrier correctness on PMEM.** ADR versus eADR. Several LDMs share a
   log part under `m_log_part_mutex`, so a barrier must cover the part's
   whole unpersisted range. A missing barrier is a silent bug; mitigate
   with a debug barrier check and power-loss emulation that keeps only what
   was written up to the last barrier.
2. **Moving the primary's local commit.** It touches the hottest commit
   code: the queued-log path, `tupcommit_conf`, the parallel and takeover
   paths.
3. **Longer lock hold on the primary.** One more round. Measure hot-row
   throughput and deadlock-timeout aborts (P6).
4. **Rule F.** Abort from the committed state is new in LQH, and the
   takeover TC must know whether any COMPLETE was sent.
5. **opCount on every path.** It must be right for trigger-generated
   operations, IgnoreError aborts and takeover. It matters only for the
   partial-SR fallback.
6. **Transid uniqueness.** Phase 2 assumes a transid occurs once in a tail.
   The API's transid counter is per process and starts again at 0 when the
   API process restarts (`ndb_cluster_connection.cpp:815`; prefix in
   `Ndbif.cpp:268-280`), so a restarted API can reuse transids. Fix
   (review 4): an API node id is not taken into use again until the GCI in
   which that node failed has been saved by GCP. All of the old process's
   transactions then have GCI ≤ R_gcp at any later SR and never share a
   tail with the new ones. Enforce it in QMGR's API_REGREQ handling, which
   already holds an API back until its failure handling is done (P3).
7. **Activation boundary.** Phase 2 must apply only to GCI ≥ g, and only
   when R_gcp ≥ g − 1 (§2.2).
8. **Testing.** Emulated PMEM (`memmap=`) for functional tests; power-loss
   emulation for barrier bugs. Tests on `memmap=` never catch a missing
   barrier.
9. **Fence cost at high rates.** On CXL 2.0 persistent memory a hot LDM at
   200k write operations per second would spend 8–80 % of its time in
   `sfence`. The adaptive scheme (`pmem_redo_design.md` §4), one fence per
   log part per scheduler round with the dependent signals held back until
   it is done, is the expected second iteration.
10. **Device health.** An unsafe shutdown reported by the device's
    dirty-shutdown count makes the node stale (§5.4); reading a bad block
    through the mapping kills the process. Both are checked at start, and
    the meaning of the dirty-shutdown flag must be verified per device.
11. **Hardware supply.** Optane is gone; CXL persistent memory is new and
    needs flushes. No cloud offering exists. Functional tests of the CXL
    path can use QEMU's emulated CXL Type 3 device with a persistent backend;
    performance needs real modules.
12. **REDO encryption** works on 32 KB units and cannot be combined with
    line-level persistence; refused in iteration 1.

---

## 10. Subtasks and phases

### 10.1 Planning subtasks

| ID | Subtask | Deliverable | Depends on |
|---|---|---|---|
| P0 | Research | five `research_*.md` | **DONE** |
| P1 | Decision record (§11) | this plan | **DONE** except D3 |
| P2 | Memory-mapped REDO, new format, PMEM persistence layer | `pmem_redo_design.md` (**DONE**, with four supporting notes) | P1 |
| P3 | Commit-path changes | `commit_path_design.md` | P2 |
| P4 | SR phases 1–3 | `sr_tail_resolution.md` | P2, P3 |
| P5 | Configuration and online activation | `config_activation.md` | P1 |
| P6 | Verification and benchmarks | `verification_plan.md` | P2–P5 |

What each design document covers:

- **P2 (done):** the formats in §7; DAX mapping and the start-up checks;
  the persist primitive and barrier placement; the shared log-part mutex;
  space reservations; end of log and invalidation at restart;
  `redoLogReader` for the new format. See `pmem_redo_design.md`.
- **P3:** invariants C, K, L, A and F on every path in §3.4; moving the
  primary's local commit; `writeCompleteLog`; opCount, including takeover;
  the forced late ack and the takeover-ack move; holding back a failed API
  node id; the node-failure file write in QMGR.
- **P4:** phase 1 without invalidation; phase 2 steps A–C, their signals
  and their place among the SR phases (`research_system_restart.md` §10);
  the count-based fallback; stale nodes from the node-failure file and the
  D4 start check; phase 3; the §6 proof written out with code references.
- **P5:** the two config variables; online activation at GCI g through the
  GCP protocol; the sysfile field; the R_gcp ≥ g − 1 rule; deactivation by
  cluster restart; ndbinfo status.
- **P6:** a TLA+ model of C/K/L/A/F plus phase 2, with node failure,
  takeover and partial SR; power-loss emulation and an acknowledged-commit
  ledger checker; ERROR_INSERT crash points (between COMMIT records on
  different replicas, between COMPLETE records, at takeover, in every SR
  step); MTR and autotest cases on emulated PMEM; benchmarks for commit
  latency, hot rows, and SR time against tail size.

### 10.2 Execution phases

| Phase | Content |
|---|---|
| X1 | Takeover-ack fix (TCKEY_FAILCONF after COMPLETE). Independent; it also fixes READ_BACKUP read-your-writes after takeover today |
| X2 | **First step: the REDO log on PMEM**, in steps S1–S7 of `pmem_redo_design.md` §3: portlib XXH3 checksum and PMEM helpers; config and start checks; NDBFS mapping; record writers; write path; recovery; power-loss testing. Ends with the REDO on PMEM at today's (GCP-based) durability |
| X3 | Test harness: ledger, crash of all nodes, power-loss emulation (losses beyond R_gcp expected until X5) |
| X4 | Commit path: barriers, primary local commit at COMPLETE, forced late ack, rule F, opCount, API node-id hold-back |
| X5 | SR phases 1–3. From here the ledger must show zero losses with all nodes starting |
| X6 | Node-failure file and stale nodes; partial SR fallback; the D4 start check |
| X7 | Online activation at a GCI; deactivation by cluster restart; ndbinfo |
| X8 | Performance, documentation (rondb-docs), `redoLogReader` |

```
X1 (independent)
X2 ── X3 ── X4 ── X5 ── X6 ── X7 ── X8
```

Sizes, milestones, the pull requests of step 1 and the work packages of
every phase are in `implementation_plan.md` (about 300 person-days in
total, of which step 1 is about 120).

---

## 11. Decisions

| # | Decision | Outcome |
|---|---|---|
| D0 | Recovery model and scope | **Settled:** per transaction, cluster-wide, persistent COMMIT + COMPLETE records |
| D1 | PMEM layout | **Settled:** the whole REDO in PMEM. Defaults: fsdax with `MAP_SYNC`; ADR and eADR both supported |
| D2 | Who decides in-doubt transactions | **Settled:** no coordinator; the log parts exchange in-doubt sets and COMPLETE hits, and each computes the same verdict (§5.2) |
| D3 | Detecting a replica that missed commits made after its node failed | **Settled (review 4):** the failure must be recorded. Proposed place: a node-failure file on PMEM, written by QMGR before PREP_FAILCONF (§5.4), rather than the REDO log |
| D4 | SR where a node group has only stale nodes starting | **Settled (review 5):** recovery needs at least one non-stale node in each node group; stale nodes stay out of the SR and join by node restart afterwards (§5.4, §5.5). Not decided: a forced start to R_gcp |
| D5 | Partial SR with the COMPLETE record only on a missing node | **Settled:** opCount fallback, decided from per-node counts per node group (§5.5) |
| D6 | Ack point | **Settled:** after the last COMPLETED |
| D7 | COMPLETE records | **Settled:** one per operation (one per transaction and log part works but is complex to implement) |
| D8 | Hardware without PMEM | **Settled:** durable commits require PMEM; otherwise the node refuses to start. Tests use emulated PMEM. Review 10: until hardware is available, test modes run PMEM mode and durable commits on normal DRAM, release builds included, with the production persist code |
