# RONDB-1150 durable commits: literature and systems survey

Status: research input for planning. Nothing here is a decision.
Date: 2026-10-27. Branch: `RONDB-1150-durable-commits` (tree at `7128c75dca4`).

Goal of the feature: an acknowledged commit survives a full cluster crash,
starting with `READ_BACKUP=1` tables. The two candidate directions are:

- **(A) Per-transaction durability.** Each participant forces its REDO before
  it acknowledges. Locks are kept until the transaction is durable. A system
  restart (SR) decides which transactions beyond the last GCP survive.
- **(B) Epoch-based durability.** Micro-GCPs (epochs) become durable. API acks
  wait until the transaction's epoch is durable, and SR restores to the last
  durable epoch.

The document has three parts:

- Part 0 collects the facts about NDB that the comparison depends on.
- Parts 1 to 5 survey the literature. Each entry gives the core idea, the lock
  release point, the forced writes and message rounds, the recovery or decision
  procedure, and a **RonDB note**.
- Part 6 is the synthesis and the recommendation.

How sources were checked:

- A claim followed by "(verified)" was read in the primary source during this
  survey.
- Other details come from well-known papers and are marked where I am less
  sure of them.
- Facts about RonDB carry a file reference and were checked in this tree.

---

## Part 0. NDB facts that matter for the design

These were checked in this tree. The paths are relative to
`storage/ndb/src/kernel/blocks/`.

1. **The REDO commit record has no transaction id and no micro-GCI.**
   `Dblqh::writeCommitLog()` (`dblqh/DblqhMain.cpp`) writes these words:
   `ZCOMMIT_TYPE, tableId, schemaVersion, fragId, fileNo, startPageNo,
   pageIndex, stopPageNo, gci`, with `gci = regTcPtr->gci_hi`.
   - So the commit record points at its prepare record by log position and
     carries only the 32-bit GCP number. The micro-GCP part (`gci_lo`) is not
     there.
   - The prepare record (`ZPOS_HASH_VALUE, ZPOS_SCHEMA_VERSION,
     ZPOS_TRANS_TICKET, ZPOS_OP_TYPE, ...` in `dblqh/Dblqh.hpp`) also has no
     participant information.
   - Consequences: REDO replay can only stop at a GCP boundary today, not at an
     epoch boundary. Nothing in REDO lets an SR group the records of one
     transaction across fragments or nodes, or tell whether a transaction's
     record set is complete.
2. **A "completed GCI" marker already exists.**
   - `ZCOMPLETED_GCI_TYPE` (8) is written by `Dblqh::writeCompletedGciLog()` into
     every log part when `GCP_SAVEREQ` arrives.
   - It carries the 32-bit `cnewestCompletedGci`.
   - This is the "final record containing *d*" of Silo (see 3.1), at GCP
     granularity.
3. **The commit GCI is assigned under a lock that the GCP protocol takes.**
   - At commit, `Dbdih::execDIVERIFYREQ` returns `m_micro_gcp.m_current_gci`
     to TC.
   - Between `GCP_PREPARE` and `GCP_COMMIT`, `getBlockCommit()` makes DIH
     queue the request (`dbdih/DbdihMain.cpp`).
   - This is the mechanism behind the **GCI monotonicity lemma** used in Part 6:
     if T2 observes or overwrites T1's committed write, or simply commits
     after T1 in real time, then `GCI(T2) >= GCI(T1)`. Every epoch boundary is
     therefore a consistent cut that is closed under dependencies.
4. **`TF_LATE_COMMIT`** (`dbtc/Dbtc.hpp`): "Wait sending apiCommit until
   complete phase done". This is how `READ_BACKUP` acks after the complete
   phase.
5. **Each row has a GCI.**
   - The `Tablerec::TR_RowGCI` bit, `get_mm_gci()` and `update_gci()` live in
     `dbtup/Dbtup.hpp`.
   - The `ROW_GCI` and `ROW_GCI64` pseudo-columns are in
     `include/kernel/AttributeHeader.hpp`.
   - A reader can therefore learn the GCI of the data it saw, which is
     equivalent to a per-tuple TID or `writeLV` in Silo or Taurus.
6. **Defaults** (`src/common/mgmcommon/ConfigInfo.cpp`):
   - `TimeBetweenGlobalCheckpoints`: default 2000 ms, minimum 20, maximum 32000.
   - `TimeBetweenEpochs`: default 100 ms, minimum 0, maximum 32000.
7. **TC take-over** (`LQH_TRANSREQ`) rebuilds a failed TC's transactions from
   the LQH states.
   - This is a *cooperative termination protocol* that runs in memory.
   - The SR decision procedure that (A) needs is the same protocol, run from
     REDO instead of from memory.

---

## Part 1. Atomic commit protocols

### 1.1 Classic 2PC

- **Sources:**
  - J. Gray, "Notes on Data Base Operating Systems", LNCS 60, 1978.
  - Bernstein, Hadzilacos, Goodman, *Concurrency Control and Recovery in
    Database Systems*, Addison-Wesley, 1987, ch. 7
    (free: https://www.microsoft.com/en-us/research/people/philbe/book/).
  - Gray and Lamport, TODS 2006 (cost table, see 1.8).
- **Core idea:**
  - Phase 1: the coordinator sends PREPARE. Each participant forces a prepare
    record and votes YES or NO.
  - Phase 2: the coordinator forces COMMIT or ABORT and sends the decision.
    Participants write commit records lazily and ACK, and the coordinator then
    writes an end record lazily.
- **Locks:** held until the participant learns the decision, which blocks if
  the coordinator fails while participants are prepared.
- **Forces and rounds:**
  - 4 message delays and 2 forced-write delays in sequence.
  - 3N−1 messages and N+1 stable writes. These counts are from Gray and
    Lamport, Fig. 4 (verified).
- **Recovery:**
  - Participants in doubt ask the coordinator.
  - The coordinator log is the authority for the decision.
- **RonDB note:**
  - NDB is 2PC *without the coordinator's forced decision* and without forced
    prepares. Durability is supplied separately by GCPs.
  - To get durable acks we must put a durable decision point back somewhere.
    The choices are participants' logs, a designated participant, or an epoch
    record. Paying the classic two sequential forces would double latency.

### 1.2 Presumed abort (PrA), presumed commit (PrC), new presumed commit

- **Sources:**
  - C. Mohan, B. Lindsay, R. Obermarck, "Transaction Management in the R*
    Distributed Database Management System", ACM TODS 11(4), 1986.
  - B. Lampson, D. Lomet, "A New Presumed Commit Optimization for Two Phase
    Commit", VLDB 1993.
- **Core idea:**
  - Under **PrA**, nothing is forced for aborts, and "no information" means
    abort. Aborts and read-only transactions cost no forces.
  - Under **PrC**, nothing is forced for commits, and "no information" means
    commit. The coordinator must then force a *collecting* record listing the
    participants before it sends PREPARE, so that it can tell "unknown"
    apart.
  - **NPC** (Lampson and Lomet) removes that initial force in the common case.
- **RonDB note:**
  - NDB at SR is naturally **presumed abort**: anything without a durable
    commit is dropped.
  - PrC's "durable participant list before prepare" is the same requirement
    that parallel commits (4.3) and FaRM (4.5) meet with a list stored in the
    transaction record or lock record.
  - Any design that decides commit *implicitly* from participant evidence must
    durably record the participant set somewhere.

### 1.3 Read-only optimisation

- **Source:** Mohan et al. 1986; Samaras et al. 1993/95 (see 1.5).
- **Core idea:** a participant that only read votes READ-ONLY, releases its
  locks at PREPARE, and leaves the second phase.
- **RonDB note:**
  - Read-only *participants* need no REDO force.
  - The danger is not the read-only participant. It is a **read-only
    *transaction* that returns data written by a transaction that is not yet
    durable** (2.4).
  - NDB's lockless `READ_COMMITTED` reads are the main exposure.

### 1.4 Early prepare, coordinator log, implicit yes-vote (IYV), 1PC

- **Sources:**
  - J. Stamos, F. Cristian, "A Low-Cost Atomic Commit Protocol", SRDS 1990
    (early prepare).
  - J. Stamos, F. Cristian, "Coordinator Log Transaction Execution Protocol",
    *Distributed and Parallel Databases* 1(4), 1993.
  - Y. Al-Houmaily, P. Chrysanthis, "An Atomic Commit Protocol for
    Gigabit-Networked Distributed Database Systems", *J. Systems Architecture*
    46(9), 2000 (IYV),
    https://db.cs.pitt.edu/assets/pdf/2000.jsa.Al-HoumailyC00.pdf.
  - Al-Houmaily and Chrysanthis, "1-2PC", ADBIS 2004.
- **Core idea:**
  - **Early prepare:** each participant enters the prepared state as it acks
    each operation, so the voting phase disappears.
  - **Coordinator log (CL):** participants do not force anything. They ship
    their redo to the coordinator, which forces one log for everyone and
    replays it to participants after a failure.
  - **IYV:** the ack of each operation is an implicit YES vote, which gives a
    one-phase protocol with forward recovery. 1-2PC falls back to PrC 2PC
    when needed.
- **Locks:** released at the (single) decision.
- **Forces:** one force per participant, overlapped with execution. The
  coordinator alone forces in CL.
- **RonDB note:**
  - **NDB already is an early-prepare / IYV protocol.** `LQHKEYCONF` per
    operation is the implicit vote, and there is no separate prepare round.
  - What NDB lacks is the *durable* part: the prepare records are not forced.
  - CL is not attractive for NDB, because the TC has no disk log and is not
    a natural place to centralise logging. The lesson to keep is that one
    log can serve as the decision authority.

### 1.5 Last-agent optimisation and Oracle's commit point site

- **Sources:**
  - G. Samaras, K. Britton, A. Citron, C. Mohan, "Two-Phase Commit
    Optimizations and Tradeoffs in the Commercial Environment", ICDE 1993.
  - The journal version: "...in a Commercial Distributed Environment",
    *Distributed and Parallel Databases* 3(4), 1995.
  - Oracle Database Administrator's Guide, "Distributed Transactions
    Concepts" (commit point site), e.g.
    https://docs.oracle.com/cd/A97630_01/server.920/a96521/ds_txns.htm.
- **Core idea:**
  - The coordinator prepares all participants except one (the "last agent").
    It then hands the decision to that one, which commits and logs it.
  - In Oracle, the *commit point site* never prepares. Its commit record
    decides: the transaction "is considered committed even though some
    participating nodes may still be only in the prepared state". It is "not
    committed if the commit has not been logged at the commit point site".
    These are quotes from Oracle's documentation as returned by search.
- **Forces:** saves one round and one force at the cost of sequencing.
- **RonDB note:**
  - This is the "anchor participant" idea. One participant's REDO holds the
    decision record, and the others hold only prepares.
  - In NDB the anchor could be the LQH that already holds the TC's *commit
    ack marker* state. The anchor's replicas give the record NDB's normal
    replication: it is Paxos-Commit-like with all replicas acting as acceptors.

### 1.6 Linear (chained) 2PC and the NDB design

- **Sources:**
  - Gray 1978 (linear commit).
  - M. Ronström, *Design and Modelling of a Parallel Data Server for Telecom
    Applications*, PhD thesis, Linköping University, Dissertation No. 520,
    1998 (title confirmed via
    https://www.it.uu.se/research/group/udbl/Theses/).
- **Core idea:**
  - Prepare travels down a chain and commit travels back. This needs fewer
    messages than a centralised 2PC but has more latency (2(n−1) hops).
  - NDB uses the chain *per operation* (primary → backups) inside a
    TC-centric 2PC across operations, and it has no TC log.
- **RonDB note:**
  - **Forcing the REDO at every hop of a chain serialises the fsyncs:** the
    latency becomes (replicas × fsync).
  - Any per-operation force in (A) should be "forward first, then force". The
    LQH forwards to the next replica immediately and reports only when its own
    force *and* the downstream ack are done.
  - Better still, force only in the commit phase, where the TC can send to all
    participants in parallel. Part 6 uses this.

### 1.7 Three-phase commit and the cooperative termination protocol

- **Sources:**
  - D. Skeen, "Nonblocking Commit Protocols", SIGMOD 1981.
  - Bernstein et al. 1987, ch. 7 (cooperative termination).
- **Core idea:**
  - 3PC adds a PRE-COMMIT state so that survivors can terminate without the
    coordinator, assuming synchronous failure detection.
  - The cooperative termination protocol lets in-doubt participants ask each
    other. If any of them knows the decision, or has not voted, the
    transaction can be terminated.
- **RonDB note:**
  - NDB's TC take-over is cooperative termination in memory. The new TC
    gathers every LQH's state for each transaction and decides.
  - **For SR under (A) we need exactly this, run over REDO tails.** FaRM's
    recovery-vote rules (4.5) are the most concrete published model.
  - 3PC itself buys nothing here, because NDB's membership protocol already
    serves as the synchronous failure detector.

### 1.8 Paxos Commit

- **Source:** J. Gray, L. Lamport, "Consensus on Transaction Commit", ACM TODS
  31(1), 2006 (MSR-TR-2003-96),
  https://www.microsoft.com/en-us/research/publication/consensus-on-transaction-commit/.
- **Core idea:**
  - Each participant's prepared/aborted vote is the subject of its own Paxos
    instance, run on 2F+1 acceptors. The transaction commits iff every
    instance chose Prepared.
  - 2PC is the F = 0 case (verified).
- **Cost** (Fig. 4, verified):

  | Protocol | Message delays | Stable-write delays | Stable writes | Messages (no co-location) |
  |---|---|---|---|---|
  | 2PC | 4 | 2 | N+1 | 3N−1 |
  | Paxos Commit | 5 | 2 | N+F+1 | (N+1)(F+3)−4 |
  | Faster Paxos Commit | 4 | 2 | N+F+1 | N(2F+3)−1 |

  Section 6 handles a *dynamically joining* set of resource managers through
  a registrar. The participant set must be part of the agreed state.
- **RonDB note:**
  - Paxos Commit shows that the coordinator's stable storage can be replaced
    by **replicated acceptors**.
  - NDB's node-group replicas are natural acceptors for a decision record,
    with "all live replicas" instead of a majority, because NDB relies on
    arbitration rather than quorums.
  - The registrar point matters for NDB: operations join a transaction
    incrementally, so the final participant set is known only at commit. It
    must be recorded with the decision (see 4.3 and 4.5).

---

## Part 2. Group commit, early lock release, and observing non-durable data

### 2.1 Pre-commit and group commit

- **Sources:**
  - D. DeWitt, R. Katz, F. Olken, L. Shapiro, M. Stonebraker, D. Wood,
    "Implementation Techniques for Main Memory Database Systems", SIGMOD 1984.
  - P. Helland, H. Sammer, J. Lyon, R. Carr, P. Garrett, A. Reuter, "Group
    Commit Timers and High Volume Transaction Systems", HPTS 1987 (LNCS 359).
- **Core idea:**
  - A transaction *pre-commits* once its commit record is in the log buffer.
    It can release its locks then, but it must not answer the client until the
    record is on disk.
  - Group commit amortises one force over many transactions.
  - Helland et al. study the timer and size policies that decide when to
    flush.
- **RonDB note:**
  - With many LDM threads, each NDB log part is its own group-commit domain.
  - Group commit per log part is the obvious mechanism for (A). For (B), the
    epoch *is* the group.

### 2.2 When ELR is correct

- **Source:** E. Soisalon-Soininen, T. Ylönen, "Partial Strictness in
  Two-Phase Locking", ICDT 1995. Cited in Aether.
- **Conditions** (quoted in Aether, verified):
  1. Every dependent transaction's commit record reaches disk *after* that of
     the pre-committed transaction it depends on.
  2. If the pre-committed transaction aborts, its dependents abort too.
- **RonDB note:**
  - With a **single serial log**, condition 1 holds for free.
  - **With many logs (NDB has nodes × log parts), condition 1 no longer
    holds automatically.** It must be enforced by dependency tracking (Taurus,
    3.4) or by epoch ordering (Silo, COCO, NDB GCI).

### 2.3 Aether (VLDB 2010)

- **Source:** R. Johnson, I. Pandis, R. Stoica, M. Athanassoulis, A. Ailamaki,
  "Aether: A Scalable Approach to Logging", PVLDB 3(1), 2010,
  doi:10.14778/1920841.1920928, https://infoscience.epfl.ch/record/149436.
- **Core idea:**
  - **ELR:** locks are released once the commit record is in the buffer. The
    paper reports speedups of up to 35× under skew in TPC-B.
  - **Flush pipelining:** agent threads "detach from transactions during log
    flush … resuming the transaction once the flush is completed". A daemon
    flushes on "every X transactions, L bytes logged, or T time elapsed".
  - The paper says that combined with ELR this gives "the same throughput as
    asynchronous commit without sacrificing any safety".
  - **Consolidation array:** used for log-buffer inserts.
  - All of these were verified in the text.
- **Locks:** at pre-commit. **Forces:** one group flush per batch. **Recovery:**
  standard ARIES.
- **RonDB note:**
  - DBTC/DBLQH are signal-driven and therefore *already* pipelined. A
    transaction waiting for durability is just a record in a queue, so there
    is no thread to block.
  - The pattern to copy is a **per-log-part (or per-epoch) "pending durable
    ack" queue**, which Aurora also uses (4.2).

### 2.4 The read-only anomaly

- **Sources:**
  - H. Kimura, G. Graefe, H. Kuno, "Efficient Locking Techniques for Databases
    on Modern Hardware", ADMS@VLDB 2012. Details from memory.
  - The CLV abstract, verified: ELR "was incorrect with respect to read-only
    transactions".
- **The problem:**
  - A read-only transaction R reads data from T1, which has pre-committed
    but is not durable. R writes no log record, so nothing orders R after T1
    in the log.
  - R can return T1's data to the client before T1 is durable. After a crash,
    the client has seen a state that never existed.
  - The fix (Kimura et al.'s SX-ELR, as I recall it, and CLV) is to have R
    wait until the commit LSN of the lock or data it consumed is durable.
- **RonDB note (central):**
  - In NDB this is not limited to read-only transactions under ELR.
    **`READ_COMMITTED` reads take no locks at all** and see any committed
    version as soon as TUP commit has run.
  - So under (A) visibility must be deferred until durable, or readers must
    wait. Under (B) read-only readers must be gated by row GCI (Part 6).
  - Read-write transactions are protected by the GCI monotonicity lemma: their
    own commit GCI is at least the GCI of anything they read.

### 2.5 Controlled Lock Violation (SIGMOD 2013)

- **Source:** G. Graefe, M. Lillibridge, H. Kuno, J. Tucek, A. Veitch,
  "Controlled Lock Violation", SIGMOD 2013, pp. 85–96,
  doi:10.1145/2463676.2465325. Related patent US 9,396,227,
  https://patents.google.com/patent/US9396227.
- **Core idea:**
  - Locks stay in the lock table until the transaction is durable, but others
    may *violate* them while the commit record is being flushed.
  - A violator takes a **commit dependency**, tracked in the lock table rather
    than through ELR's tags.
  - Violating a read lock creates no dependency. A read-only transaction that
    violated an update lock must wait until the holder's commit record is
    stable (verified via the patent text).
- **Distributed 2PC** (verified via the patent text):
  - Lock violation is allowed from the moment the participant "has received
    the request for the first commit phase". That is during **pre-commit**,
    before the coordinator's decision.
  - "T2 incurs a commit dependency on T1 and thus on T0", where T0 is the
    coordinator. The dependency is a pointer from T1's state to T2 plus a
    reference count in T2.
  - "If either of those fail, T2 must roll back", which means cascading
    abort. ELR, by contrast, applies only to the final commit phase.
- **RonDB note:**
  - CLV gives the lowest lock hold time for (A). The cost is a commit
    dependency graph *across nodes* and cascading aborts: if T1 aborts, every
    LQH must find and abort its dependents.
  - NDB has neither. A full crash during pre-commit also makes the dependents
    in-doubt at SR, which pushes us back to the problem of a recovery cut that
    is closed under dependencies.
  - **CLV is a good optimisation layer for later, not a foundation.** A
    cheaper relative of it is already present: NDB's GCI order *is* a
    conservative commit-dependency order (Part 6).

### 2.6 Related ways of lending uncommitted data

- **OPT.** R. Gupta, J. Haritsa, K. Ramamritham, "Revisiting Commit Processing
  in Distributed Database Systems", SIGMOD 1997, doi:10.1145/253260.253366.
  Transactions may borrow data from transactions that are *prepared*. A
  borrower cannot commit (or, in the paper, cannot enter prepare) until the
  lender resolves, which limits aborts to one level.
- **H-Store speculation.** E. Jones, D. Abadi, S. Madden, "Low Overhead
  Concurrency Control for Partitioned Main Memory Databases", SIGMOD 2010,
  doi:10.1145/1807167.1807233. Partitions execute later transactions
  speculatively while a multi-partition transaction waits for 2PC. Results
  are held back, and the speculative work cascades on abort.
- **Hekaton commit dependencies.** P.-Å. Larson et al., "High-Performance
  Concurrency Control Mechanisms for Main-Memory Databases", PVLDB 5(4), 2011.
  A transaction may read a version from a transaction that is preparing. It
  then takes a commit dependency and cannot commit or return before the
  provider does.
- **Bamboo.** Z. Guo et al., "Releasing Locks As Early As You Can", SIGMOD 2021,
  https://arxiv.org/abs/2103.09906. It violates 2PL even during execution.
  The paper notes that CLV tracks dependencies in the lock table, whereas ELR
  uses tags (verified).
- **RonDB note:** all of these need dependency tracking plus cascading aborts.
  NDB's lockless committed read is the "lend after commit" case, which is the
  benign one, provided readers do not reveal non-durable data (2.4).

---

## Part 3. Epoch-based commit and durability

### 3.1 Silo (SOSP 2013)

- **Source:** S. Tu, W. Zheng, E. Kohler, B. Liskov, S. Madden, "Speedy
  Transactions in Multicore In-Memory Databases", SOSP 2013,
  doi:10.1145/2517349.2522713,
  https://people.csail.mit.edu/stephentu/papers/silo.pdf.
- **Core idea** (verified):
  - "Durability is a transitive property: a transaction is durable if all its
    modifications are recorded on durable storage and all transactions
    serialized before it are durable."
  - Epoch boundaries are consistent with the serial order, so whole epochs are
    the units of durable commit.
  - "The results of transactions in epoch e are not released to clients until
    all transactions with epochs ≤ e have been stored durably." This also
    applies to read-only transactions. Snapshot read-only transactions instead
    read an older consistent snapshot.
- **Mechanism:**
  - Each logger computes its local durable epoch `d = epoch(min ctid_w) − 1`.
  - It writes the buffers **plus a final record containing d**, waits for the
    I/O, and publishes `d_l`.
  - The global value is `D = min d_l`.
- **Recovery:** compute `D = min d_l` from the logs and replay only epochs ≤ D.
  - The paper says "Not recovering more is crucial … the serial order within an
    epoch is not recoverable from the information we log, so replaying a
    subset of an epoch's transactions might produce an inconsistent state."
- **Locks:** released at commit, which amounts to ELR. Results are held back.
- **RonDB note:** this is **almost exactly (B) for NDB**.
  - `ZCOMPLETED_GCI_TYPE` is Silo's "final record containing d".
  - The restorable GCI is D.
  - The missing pieces are micro-GCI granularity (`gci_lo` in the commit record
    and in the marker) and a per-epoch flush.
  - Silo's warning about partial epochs is the main hazard for (A). If an SR
    replays a *subset* of an epoch, that subset must still be closed under
    dependencies. That holds only if locks and visibility were strict until
    durability.

### 3.2 SiloR (OSDI 2014)

- **Source:** W. Zheng, S. Tu, E. Kohler, B. Liskov, "Fast Databases with Fast
  Durability and Recovery Through Multicore Parallelism", OSDI 2014,
  https://www.usenix.org/system/files/conference/osdi14/osdi14-paper-zheng_wenting.pdf.
- **Core idea** (verified):
  - Several loggers write to several disks, so "no single log contains enough
    information for recovery".
  - A distinguished logger computes `ep = min{e_l} − 1`, writes it to a
    **`pepoch` file**, and fsyncs it. Results are released only after that.
  - The paper notes that the scheme costs "two fsyncs (one for the log file and
    one for pepoch)", and that "It would be possible to extract this
    information from all logs".
  - It uses value logging, which allows parallel replay.
- **RonDB note:** the `pepoch` file is NDB's sysfile (`COPY_GCIREQ` writes the
  restorable GCI on every node). That gives the same design choice:
  - **(B-i)** write sysfile per durable epoch, which costs two sequential
    fsyncs and one more round, or
  - **(B-ii)** derive the durable epoch at SR from the REDO markers in all log
    parts on all nodes. This is the "extract from all logs" option, as Silo
    and FoundationDB do it.

### 3.3 COCO (VLDB 2021)

- **Source:** Y. Lu, X. Yu, L. Cao, S. Madden, "Epoch-based Commit and
  Replication in Distributed OLTP Databases", PVLDB 14(5):743–756, 2021,
  doi:10.14778/3446095.3446098,
  https://www2.cs.arizona.edu/~caolei/papers/COCO.pdf.
- **Core idea** (verified):
  - "An epoch is the basic unit at which transactions commit and recover —
    either all or none of the transactions in an epoch commit."
  - "A transaction releases its locks immediately after execution finishes,
    and logging to persistent storage occurs in the background and is only
    enforced at the boundary of epochs."
  - "The writes of a transaction are visible to other transactions as soon as
    it commits but they may disappear if a failure occurs … a transaction does
    not release the result to the end user until the current epoch commits."
- **Protocol per epoch** (default 10 ms):
  1. An *epoch coordinator* sends PREPARE. This coordinator is distinct from
     transaction coordinators and can be replicated with Paxos or Raft.
  2. Each participant logs all writes of transactions ready to commit, then
     **force-logs a prepared record with the TIDs and the epoch number**, then
     acks.
  3. The coordinator **force-writes a commit record for the epoch**, increments
     the epoch, and sends COMMIT. Participants then release results to users.
- **Rounds and forces:** 2 rounds and 2 sequential forces per *epoch*, so zero
  per transaction.
- **Failure handling:**
  - Before the commit record is written, all transactions of the epoch abort
    and are re-executed automatically.
  - After it is written, they count as committed.
  - Rollback uses **two versions per tuple**: the latest one and the last one
    as of the last committed epoch.
  - Recovery replays "an epoch … only if the commit record indicates
    committed".
- **Limitations** (the paper's own): it adds a few ms of latency, and "a single
  long-running transaction can stop a whole batch of transactions from
  committing". Reads at replicas are validated with TIDs. The paper reports up
  to 4× better throughput than 2PC with synchronous replication, and less
  sensitivity to durable-write latency.
- **RonDB note:** this is the closest published match to (B). Differences that
  help NDB:
  - NDB does not need to abort an epoch on a node failure. The survivors finish
    it through TC take-over and replicas.
  - NDB already has the per-epoch GCP rounds (`GCP_PREPARE`, `GCP_COMMIT`,
    `GCP_NODEFINISH`, `SUB_GCP_COMPLETE_REP`). Only the flush and the durable
    record are new.
  - COCO's straggler limitation applies to NDB unchanged: `GCP_NODEFINISH`
    waits for every transaction with that GCI to complete.

### 3.4 Taurus (VLDB 2021): parallel logging with LSN vectors

- **Source:** Y. Xia, X. Yu, A. Pavlo, S. Devadas, "Taurus: Lightweight Parallel
  Logging for In-Memory Database Management Systems", PVLDB 14(2):189–201,
  2021, doi:10.14778/3425879.3425889, https://arxiv.org/abs/2010.06760.
- **Core idea** (verified):
  - Each transaction carries an **LSN vector (LV)** with one entry per log
    stream.
  - On each lock acquisition, `T.LV = max(T.LV, tuple.writeLV)`. A write also
    takes `max(T.LV, tuple.readLV)`.
  - The log record contains the redo and a copy of `T.LV`.
  - After commit, the transaction updates the tuple's readLV and writeLV and
    **releases its locks (ELR)**.
  - It then commits asynchronously once **`PLV ≥ T.LV`**. PLV is the persistent
    LSN vector, the flushed position of each log.
- **Recovery:** replay the transactions whose `T.LV ≤ ELV`, where ELV holds the
  durable ends of the logs. Replay follows the partial order, which amounts to
  a parallel topological sort.
- The paper's challenges #2 and #3 (verified) are the problem we have:
  - "if T2 is in the log but T1 is not, then the DBMS should not process T2"
  - "must recover T1 before T2".
  - The paper notes that LV size grows with the number of logs. It uses
    compression and SIMD to cope.
- **RonDB note:**
  - Taurus is **exact dependency tracking for (A) with ELR**.
  - For NDB the vector would need (nodes × log parts × replicas) entries, which
    is far too wide.
  - **Collapsing the vector to a scalar epoch gives (B)**: the GCI is the
    "compressed LV". This makes it clear that (B) is not a downgrade. It is the
    standard approximation of (A) with ELR.

### 3.5 DPR and CPR (Microsoft FASTER)

- **Source (DPR):** T. Li, B. Chandramouli, J. Faleiro, S. Madden, D. Kossmann,
  "Asynchronous Prefix Recoverability for Fast Distributed Stores", SIGMOD
  2021, doi:10.1145/3448016.3458454,
  https://www.microsoft.com/en-us/research/uploads/prod/2021/06/dpr-sigmod2021.pdf.
- **DPR core idea** (verified):
  - Each shard commits local *versions*. A **DPR-cut** is a set of versions
    that is closed under the precedence graph.
  - The **exact** algorithm stores the version dependencies durably and has a
    stateless coordinator compute "the maximal transitive closure".
  - The **approximate** algorithm makes versions monotone in the manner of a
    Lamport clock: a client carries the highest version it has seen, and a
    shard advances before it serves the request. The cut is then
    `V_min = min persisted version`, because "no versions can depend on larger
    versions".
  - A hybrid runs the approximate algorithm as the fallback after the
    coordinator fails.
- **Source (CPR):** G. Prasaad, B. Chandramouli, D. Kossmann, "Concurrent
  Prefix Recovery: Performing CPR on a Database", SIGMOD 2019. Threads switch
  versions *without a global commit pause*, and the state is recoverable at a
  prefix.
- **RonDB note:**
  - The NDB GCI is DPR's monotone version, and the global GCP gives that
    monotonicity without any client involvement.
  - DPR's approximate cut, `V_min`, is (B)'s restart rule.
  - DPR's exact algorithm shows what (A) with ELR would require: a durable
    dependency graph.
  - CPR is relevant if NDB epochs become very short. The block on
    `GCP_PREPARE` → `GCP_COMMIT` (`getBlockCommit()`) costs one master round
    trip of commit stall *per epoch*. CPR and Chandy–Lamport (4.9) show how to
    switch epochs without that stall.

### 3.6 Deterministic and command logging: Calvin, Aria, VoltDB

- **Sources:**
  - A. Thomson et al., "Calvin: Fast Distributed Transactions for Partitioned
    Database Systems", SIGMOD 2012.
  - Y. Lu et al., "Aria", PVLDB 13(11), 2020.
  - N. Malviya, A. Weisberg, S. Madden, M. Stonebraker, "Rethinking Main Memory
    OLTP Recovery", ICDE 2014.
  - VoltDB docs, https://docs.voltdb.com/UsingVoltDB/CmdLogConfig.php.
- **Core idea:**
  - Log (and replicate) the *inputs* of transactions in batches before running
    them. Deterministic execution then removes 2PC, and recovery replays the
    input log from a checkpoint.
  - VoltDB's synchronous command logging makes transactions "wait until they
    are logged to disk". The asynchronous default writes on a time or count
    frequency.
- **RonDB note:** little direct relevance. NDB transactions are interactive and
  not deterministic stored procedures. VoltDB's synchronous and asynchronous
  frequency knobs are a useful model for user-facing settings, such as per-table
  or per-session "durable" versus "fast" acks.

---

## Part 4. Computing a recovery cut from many logs without a coordinator log

### 4.1 FoundationDB (SIGMOD 2021)

- **Source:** J. Zhou et al., "FoundationDB: A Distributed Unbundled
  Transactional Key Value Store", SIGMOD 2021, doi:10.1145/3448016.3457559,
  https://www.foundationdb.org/files/fdb-paper.pdf.
- **Commit path** (verified):
  - Proxies send each commit's log data, tagged with a global LSN (version),
    to the LogServers. Each request piggybacks the proxy's **KCV** (known
    committed version).
  - Each log record is synchronously replicated on k = f+1 LogServers. "Only
    when all k have replied with successful persistence can the Proxy send back
    the commit response."
- **Recovery** (verified):
  - Each LogServer keeps the max KCV it received and its **DV**, the durable
    version, which is the maximum persisted LSN.
  - After stopping the old LogServers and getting more than m−k replies, the
    Sequencer sets **PEV = max KCV** (everything up to PEV is fully
    replicated) and **RV = min DV**.
  - It copies `[PEV+1, RV]` to the new LogServers and discards everything
    above RV.
  - Versions between PEV and RV may never have been acked but are kept. That
    is safe because they form a prefix.
- **RonDB note:** this is the template for (B-ii).
  - "DV" corresponds to the max completed micro-GCI durable in a node's log
    parts (the min over its log parts).
  - "KCV" corresponds to the last epoch the master declared durable, which is
    what clients may have been acked for.
  - RV corresponds to the restorable epoch the SR computes, taking per node
    group the max over the replicas that are available.
  - The FDB argument also settles a policy question: restoring epochs that are
    durable everywhere but were never acked (between KCV and RV) is fine.

### 4.2 Amazon Aurora (SIGMOD 2017, 2018)

- **Sources:**
  - A. Verbitski et al., "Amazon Aurora: Design Considerations for High
    Throughput Cloud-Native Relational Databases", SIGMOD 2017,
    doi:10.1145/3035918.3056101.
  - "Amazon Aurora: On Avoiding Distributed Consensus for I/Os, Commits, and
    Membership Changes", SIGMOD 2018, doi:10.1145/3183713.3196937,
    https://www.cs.purdue.edu/homes/bb/cs542-20Spr/readings/impl/sigmod-18-amazon-aurora-avoiding-consensus.pdf.
- **Core idea** (verified, 2018):
  - **SCL** (segment complete LSN) is the inclusive upper bound of gap-free log
    records at one segment. It is sent with each write ack.
  - **PGCL** advances when 4 of 6 segments show SCL above a point.
  - **VCL** (volume complete LSN) is the highest point at which *all* earlier
    records reached quorum across all protection groups.
  - **VDL** is the last LSN below VCL that ends a mini-transaction. The 2017
    paper calls the MTR boundaries CPLs.
  - "A commit is acknowledged … once … the commit redo record … (SCN) is below
    VCL. No flush, consensus, or grouping is required." Worker threads put the
    transaction on a **commit queue**, and a commit thread acks when VCL
    advances.
- **Crash recovery:**
  - The instance re-establishes read quorum, recomputes PGCL and VCL from the
    SCLs, and "snips off the ragged edge" by durably recording a **truncation
    range** above the new VCL.
  - Late async writes in that range are then ignored, and new LSNs are
    allocated above it.
- **RonDB note:** the Aurora vocabulary maps cleanly onto (B).

  | Aurora | RonDB |
  |---|---|
  | segment | log part |
  | SCL | completed-GCI marker |
  | PGCL | per node group |
  | VCL / VDL | durable epoch |
  | commit queue | DBTC's per-GCI pending-ack queue |

  Two further lessons:
  - **Truncation range.** After an SR to epoch E, the REDO that is physically
    above E in each log part must be invalidated durably before new work
    starts. NDB already invalidates REDO in SR
    (`Dblqh::invalidateLogAfterLastGCI`), so that mechanism should be checked
    to confirm it can cut at epoch granularity rather than at a GCP boundary.
  - **No consensus on the write path.** Consistency points come from local
    bookkeeping, which suggests LQHs could push "durable up to epoch e" reports
    instead of being polled.

### 4.3 CockroachDB parallel commits

- **Sources:**
  - N. VanBenschoten, "Parallel Commits: An atomic commit protocol for
    globally distributed transactions", Cockroach Labs blog, 2019,
    https://www.cockroachlabs.com/blog/parallel-commits/.
  - R. Taft et al., "CockroachDB: The Resilient Geo-Distributed SQL Database",
    SIGMOD 2020, doi:10.1145/3318464.3386134.
- **Core idea** (verified from the blog):
  - At COMMIT, the coordinator writes a **STAGING** transaction record *in
    parallel* with the remaining intent writes. The record "lists the key of
    each of these in-progress writes".
  - The transaction is **implicitly committed** iff the record is STAGING and
    all the listed writes have reached consensus, at a timestamp no higher than
    the record's.
  - The client is acked as soon as all of these succeed. The explicit COMMITTED
    write happens afterwards and asynchronously, so the protocol costs one
    consensus latency instead of two.
- **Recovery** ("transaction status recovery procedure"):
  - A conflicting reader checks every listed write.
  - If one is missing, it uses the timestamp cache "to prevent the missing
    write from ever succeeding in the future" and then aborts the transaction.
  - Otherwise it marks the transaction committed.
  - This procedure runs only when the coordinator has died.
- **RonDB note:** this is the canonical model for an **implicit commit decision
  with no coordinator log** in (A).
  - The NDB equivalent of the STAGING record is an *anchor* REDO record. It
    holds the TransId, the GCI64, and the **participant summary**: the
    `(fragment, #ops)` list or a total operation count.
  - At SR there are no concurrent writers, so the "prevent future success" step
    is trivial: SR simply does not replay the missing pieces.

### 4.4 Percolator, and TiDB async commit and 1PC

- **Sources:**
  - D. Peng, F. Dabek, "Large-scale Incremental Processing Using Distributed
    Transactions and Notifications", OSDI 2010.
  - TiKV async commit design,
    https://github.com/tikv/sig-transaction/blob/master/design/async-commit/initial-design.md.
  - TiDB 5.0 release notes, https://docs.pingcap.com/tidb/stable/release-5.0.0/.
- **Core idea:**
  - In Percolator, the commit of the **primary** lock is the commit point.
    Secondaries point to the primary and are resolved lazily.
  - In TiDB async commit (verified from the design doc), the primary lock
    "include[s] all keys locked by the transaction". Every prewrite returns a
    `min_commit_ts`, and `commit_ts` is the maximum of them.
  - TiDB reports success "after receiving success responses for all prewrite
    messages", which moves the commit point to the end of prewrite.
- **Resolution:**
  - A reader that finds a lock runs `CheckTxnStatus` on the primary to get the
    secondaries, then `CheckSecondaryLocks`.
  - If all of them are prewritten, the transaction commits at the maximum
    `min_commit_ts`. If any is missing or rolled back, it is rolled back.
- **1PC:** a transaction with a single prewrite uses `min_commit_ts` as its
  commit ts, with no commit message.
- **RonDB note:** this is the same pattern as 4.3, plus two NDB-relevant
  points.
  - **The commit timestamp is computed from participant evidence.** The NDB
    analogue is that the GCI is fixed at the TC by `DIVERIFYREQ`, so it needs
    no computation. That is simpler.
  - **1PC for single-participant transactions.** A transaction touching one
    fragment, meaning one node group, needs no anchor or participant list: its
    commit records *are* the decision. This could be a cheap first step for (A).
  - Caution: the GitHub issue tidb#24384 (a v5.0 bug) shows how easily an
    implicit-commit resolver goes wrong when the lock that *names* the
    participants is missing. In NDB, if the anchor record is not durable, the
    transaction must be aborted at SR. It must never be inferred committed from
    the secondaries alone.

### 4.5 FaRM (SOSP 2015): recovery votes from participant logs

- **Source:** A. Dragojević et al., "No Compromises: Distributed Transactions
  with Consistency, Availability, and Performance", SOSP 2015,
  https://pdos.csail.mit.edu/6.824/papers/farm-2015.pdf.
- **Core idea** (verified):
  - There is **no coordinator log**. Logs live in each machine's non-volatile
    (battery-backed) DRAM.
  - LOCK and COMMIT-BACKUP records contain the written objects *and* "the list
    of all regions with written objects".
  - The commit sequence is LOCK at the primaries, VALIDATE, COMMIT-BACKUP at all
    backups (hardware ack), and then COMMIT-PRIMARY. The client is acked after
    the first COMMIT-PRIMARY ack. Primaries unlock and expose the writes on
    COMMIT-PRIMARY, and log truncation is lazy.
- **Recovery decision** (verified):
  - A recovery coordinator, chosen by consistent hashing, collects a
    RECOVERY-VOTE from the primary of each region the transaction modified.
  - Each region votes:
    - *commit-primary* if any replica saw COMMIT-PRIMARY or COMMIT-RECOVERY;
    - otherwise *commit-backup* if any replica saw COMMIT-BACKUP and no
      ABORT-RECOVERY;
    - otherwise *lock* if any replica saw LOCK;
    - otherwise *abort*;
    - and *truncated* or *unknown* when it holds no records.
  - **Decision:** commit if any region votes commit-primary. Otherwise wait for
    all regions, and commit if at least one voted commit-backup and all the
    others voted lock, commit-backup, or truncated. Otherwise abort.
- **RonDB note:** **this is the most directly usable model for (A)'s SR
  decision procedure.** FaRM's per-replica logs play the role of NDB's
  per-replica REDO, and its participant list in every record answers "who else
  should have records".
  - Put a participant summary in every commit record, or in the anchor's.
  - Have each node scan its REDO tail beyond the base cut and send one vote per
    (TransId, fragment) to the SR master.
  - Decide with FaRM-like rules. With strict visibility the rule is simpler:
    commit iff all participants have a durable commit record on at least one
    replica.
  - FaRM can expose writes at COMMIT-PRIMARY because all COMMIT-BACKUPs were
    already durable. That is "durable everywhere before visible anywhere",
    which is exactly the strictness (A) needs.

### 4.6 OceanBase 2PC (VLDB 2022)

- **Source:** Z. Yang et al., "OceanBase: A 707 Million tpmC Distributed
  Relational Database System", PVLDB 15(12), 2022,
  https://www.vldb.org/pvldb/vol15/p3385-xu.pdf.
- **Core idea** (verified):
  - Each participant is a Paxos group. "The first participant of each
    distributed transaction is the coordinator".
  - "The state of the coordinator does not persist in OceanBase 2PC"; it is
    "dynamically construct[ed] … through the local state of all the
    participants during a disaster recovery".
  - "When all prepare logs of a transaction are persisted on a majority of the
    corresponding Paxos group, all states of the transaction are persisted",
    and the commit latency drops to one Paxos synchronization.
  - Recovery continues the transaction "according to whether all participants
    of the transaction have completed the prepare phase". For this, each
    participant must know the participant set. I believe the prepare log
    carries it, but that detail was not visible in the extracted text.
- **RonDB note:** this is a production system that uses the rule "**all
  prepares durable ⇒ committed**", with no coordinator log. It is the (A2)
  variant in Part 6.

### 4.7 Spanner commit wait

- **Source:** J. Corbett et al., "Spanner: Google's Globally-Distributed
  Database", OSDI 2012.
- **Core idea:**
  - 2PC runs over Paxos groups. Participant leaders log a prepare record
    through Paxos, and the coordinator leader logs the commit record through
    Paxos.
  - **Commit wait:** the coordinator waits until `TT.after(s)` before letting
    any participant apply the commit or release locks, which gives external
    consistency.
- **RonDB note:** in (B), the API ack also waits for a condition that is not
  about the transaction's own work, namely that the epoch is durable. Spanner
  *holds locks* during that wait.
  - (B) does not need to hold locks, because GCI order already makes the
    restored cut dependency-closed.
  - The wait can overlap other work, as in Spanner, where commit wait overlaps
    the Paxos write.

### 4.8 YugabyteDB

- **Source:**
  https://docs.yugabyte.com/preview/architecture/transactions/distributed-txns/.
- **Core idea** (verified):
  - Provisional records ("intents") on each tablet are invisible to readers
    until the transaction commits.
  - A Raft-replicated **transaction status tablet** holds the status and "the
    list of participating tablets".
  - Commit means appending *committed* to the status tablet's Raft log. That
    makes all the writes "atomically visible", and they are cleaned up
    asynchronously.
- **RonDB note:** the status tablet is a replicated coordinator log. NDB would
  have to add such a component, which is contrary to its design. The relevant
  takeaway is that the **participant list belongs in the decision record**.

### 4.9 Consistent cuts: Chandy–Lamport

- **Source:** K. M. Chandy, L. Lamport, "Distributed Snapshots: Determining
  Global States of Distributed Systems", ACM TOCS 3(1), 1985.
- **Core idea:** marker messages define a consistent cut without stopping the
  system.
- **RonDB note:**
  - The NDB GCP is a *blocking* coordinated cut: commits stall during
    `GCP_PREPARE` → `GCP_COMMIT`.
  - At today's 100 ms epochs the stall is negligible. At 1 to 5 ms durable
    epochs, the stall of one master round trip per epoch becomes a measurable
    throughput tax.
  - A Chandy–Lamport or CPR style switch could remove it. For example, each TC
    switches on receipt, and the GCI order is kept by having a TC that has
    already switched stamp its messages to LQH, so that an LQH that sees a
    newer-GCI commit forces later local commits to be newer as well. This
    needs careful analysis, and it is a later optimisation.

---

## Part 5. Other systems directly on point

### 5.1 MySQL/InnoDB binlog group commit and XA crash recovery

- **Sources:**
  - MySQL 8.4 Reference Manual, "The Binary Log",
    https://dev.mysql.com/doc/refman/8.4/en/binary-log.html.
  - MySQL 8.4 Reference Manual, "InnoDB Recovery",
    https://dev.mysql.com/doc/refman/8.4/en/innodb-recovery.html.
  - "Binary Log Group Commit in MySQL 5.6", https://planet.mysql.com/entry/?id=33467.
- **Core idea:**
  - The binlog acts as the **transaction coordinator's log** for an internal
    XA between itself and InnoDB.
  - InnoDB *prepares*, and its redo is flushed in the "flush" stage.
  - The binlog is written and fsynced as a group in the "sync" stage. That
    fsync is the commit decision.
  - InnoDB then commits in binlog order in the "commit" stage
    (`MYSQL_BIN_LOG::ordered_commit`).
- **Recovery** (verified, manual): "at restart after a crash, after doing a
  rollback of transactions, the MySQL server scans the latest binary log file
  to collect transaction xid values and calculate the last valid position …
  tells InnoDB to complete any prepared transactions that were successfully
  written to the binary log, and truncates the binary log to the last valid
  position."
- **RonDB note:**
  - This is the textbook restart rule: "one log is the authority, others hold
    prepares, commit in-doubt prepares iff the authority has the XID, and
    truncate the authority's ragged tail".
  - For (A) the authority would be the anchor REDO record. For (B) it is the
    durable-epoch marker.
  - There is also a direct RonDB interaction: the **ndb_binlog injector** writes
    an epoch to the MySQL binlog when it receives `SUB_GCP_COMPLETE_REP`, which
    happens *before* that epoch is durable in the cluster. After a full crash,
    the binlog can therefore contain epochs that the cluster no longer has.
  - With (B), the injector, or SUMA's epoch-completion report, could be gated
    on the durable epoch, so that replication never ships epochs that may be
    lost. Whether that is desirable is an open question (Part 6).

### 5.2 SAP HANA scale-out 2PC

- **Sources:**
  - J. Lee et al., "SAP HANA Distributed In-Memory Database System:
    Transaction, Session, and Metadata Management", ICDE 2013. Not retrieved.
  - SAP patent US 8,442,962, "Distributed transaction management using
    two-phase commit optimization", https://patents.google.com/patent/US8442962
    (verified).
- **Core idea** (from the patent):
  1. **Early commit acknowledgement.** The master writes its commit entry in
     phase 1 and acks the client "prior to entry into the second phase". The
     slaves commit asynchronously. A session-level "last CID" check hides the
     brief lag in visibility.
  2. **Skipping prepare-log writes.** The participant does not write a prepare
     record. The coordinator compares a *transaction-last-LSN*, returned to the
     client with each update and attached to the commit request, against each
     slave's *log-disk-last-LSN*. If the slave's log is already flushed past the
     transaction, no prepare force is needed. The price is a larger in-doubt
     list at recovery, resolved by "asking the transaction master".
  3. **A lazy, batched second phase**, processed in CID order per slave.
- **RonDB note:** idea 2 fits NDB well for (A).
  - Each LQH log part periodically pushes "durable up to file and page X" to
    the TCs, and each operation's `LQHKEYCONF` or `COMMITTED` reports the log
    position of its record.
  - The TC can then often decide "already durable" **without a dedicated force
    request**. This is the Aurora SCL bookkeeping idea again.

### 5.3 Oracle RAC (brief)

- Each instance writes its own redo *thread*. Instance or crash recovery
  merges the threads by SCN. A distributed transaction's decision lives at the
  commit point site (1.5), and in-doubt branches are resolved by the RECO
  background process.
- **RonDB note:** "merge many redo streams by a global sequence number" is what
  NDB does implicitly with GCI. The commit point site is the anchor idea.

---

## Part 6. Synthesis for RonDB

### 6.1 The correctness conditions

Let **Acked** be the set of transactions acknowledged as durable before the
crash. Let **R** be the set that SR restores. Then R must satisfy all of the
following:

- **Ack:** Acked ⊆ R. This is the feature itself.
- **Atomicity:** for every T in R, all of T's operations on all fragments are
  restored.
- **Dependency closure:** if T2 ∈ R and T2 depends on T1 (read-from,
  overwrite, or anti-dependency through a lock), then T1 ∈ R. This is Silo's
  "durability is transitive".
- **No phantom observations:** no client observed T1's effects unless T1 ∈ R.
  This is the read-only problem from 2.4. It can be relaxed if we document it.
- **Optional epoch atomicity:** R is a union of whole epochs. Event and
  replication consumers (SUMA, ndb_binlog, global replication) rely on this.

NDB gives two properties for free:

1. **GCI monotonicity.** From Part 0 item 3: `T2` depends on `T1` (or commits
   after it in real time) ⇒ `GCI(T2) ≥ GCI(T1)`. So every prefix
   `{T : GCI(T) ≤ E}` is dependency-closed and epoch-atomic.
2. **Per-fragment replay order.** A fragment's REDO is in a single log part,
   so replay order within a fragment is log order.

### 6.2 Direction (B): durable epochs

The idea is to make micro-GCPs durable and gate API acks on "epoch durable".

Literature fit: Silo, SiloR, and COCO are near-exact precedents. FoundationDB
and Aurora show how to compute the cut at restart from local markers. DPR's
`V_min` and Taurus' collapsed LV explain why the result is correct.

**Lock release:** unchanged, at commit or complete. This is ELR made safe by
epoch ordering.

#### B0: prototype with no REDO format change

- Make the *full GCP* frequent, for example `TimeBetweenGlobalCheckpoints` of
  20 to 50 ms. The minimum is 20.
- Have DBTC hold `TCKEYCONF`/`apiCommit` for durable tables until DIH reports
  `restorable GCI ≥ gci_hi(T)`.
- This needs a new local signal from DIH to TC when the restorable GCI
  advances, which happens after `COPY_GCIREQ` completes.
- It reuses the existing `GCP_SAVEREQ`, `ZCOMPLETED_GCI_TYPE`, the sysfile, and
  SR unchanged.
- Costs per GCP: a REDO flush on every log part, then a sysfile write on every
  node. These are two sequential fsyncs plus rounds. Latency is about GCP
  interval / 2 + epoch completion + 2 fsyncs + about 3 master rounds.
- It is good for measuring the real latency and throughput, and the
  GCP-stop/timeout behaviour, before any format work.

#### B2: durable micro-GCPs

This is the target design.

**REDO records:**

- A *commit record carrying the 64-bit GCI*, either as a new record type or as
  a `gci_lo` word added to `ZCOMMIT_TYPE`.
  - It is needed because the commit records of epoch e+1 interleave with late
    commit records of epoch e in the same log part, so replay must filter by
    the value in each record (Silo stores the epoch in every TID for the same
    reason).
- A *completed-GCI64 marker* per durable micro-GCP in every log part. This
  extends `ZCOMPLETED_GCI_TYPE`.

**Rounds per epoch e** (pipelined with e+1 running):

1. The existing `GCP_PREPARE` and `GCP_COMMIT` switch the epoch.
2. The existing epoch completion runs: `GCP_NODEFINISH` from all TCs. This is
   where COCO's straggler problem shows up.
3. New: the master sends a request (or LQH proactively sends a report) to all
   LDMs: write the completed-GCI64(e) marker and fsync each log part, then
   confirm. This step is one force per log part per epoch.
4. New: the master broadcasts `DURABLE_GCI_REP(e)` to all TCs, and optionally
   to API nodes. TCs release the pending acks of transactions with `GCI ≤ e`,
   using a per-GCI pending queue as Aurora's commit queue does.
5. The sysfile is updated lazily, for example on the existing 2 s cadence, as a
   floor.

**Restart rule** (the FoundationDB and Aurora shape):

1. In an early SR phase, every node reports `DV_node`, the min over its log
   parts of the max completed-GCI64 marker found in the REDO tail.
2. The master computes
   `E = min over node groups ( max over available nodes in group DV_node )`,
   and also takes the max of that with the sysfile's restorable GCI.
3. Restore LCP, then REDO with `GCI64 ≤ E`.
4. Durably record a truncation or invalidation of REDO above E, as Aurora does.
5. Nodes whose DV is below E for their node group recover by node-restart
   copy, as nodes behind the restorable GCI do today.

Ack rule choices:

- **Strict:** the epoch is acked when *all* live nodes have flushed. Any
  replica can then be the restore source.
- **Tail-tolerant:** the epoch is acked when *one node per node group* has
  flushed, like Aurora's 4/6 quorum. The restart then needs the max-per-group
  rule.

**Read-only and lockless reads:**

- Read-write transactions are covered by GCI monotonicity.
- Lockless `READ_COMMITTED` reads in read-only transactions can return data
  from epochs that are not durable. The options are:
  - **(R1)** document that reads may observe data that is acknowledged-pending
    (weaker, cheapest);
  - **(R2)** gate read results on `ROW_GCI64` against the durable epoch at the
    API, or at the TC for `TCKEYCONF`/`SCAN_TABCONF`. NDB already stores the
    row GCI (Part 0 item 5). This is the analogue of Silo's and CLV's
    read-only wait;
  - **(R3)** let the session opt in to "durable reads".

**Mixed durable and non-durable tables** work naturally. Every transaction is
in the same epoch order, and only the *ack delay* differs per table or
transaction.

**Cost and risk:**

- Latency is about epoch/2 + completion + 1 fsync + about 2 hops. COCO reports
  that 10 ms epochs are acceptable for most OLTP.
- An **on-demand epoch** reduces latency at low load, in the style of the
  group-commit timers of Helland et al. and Aether's flush policies: start the
  next micro-GCP as soon as a durable-ack waiter exists and the previous one
  has finished.
- The per-epoch commit stall (`getBlockCommit`) limits how short epochs can
  be (4.9).
- Straggler transactions delay everyone.
- The LCP-selection and SR code paths work in units of `gci_hi`. They must be
  checked to confirm they accept a restore point in the middle of a GCP
  (`hi`, `lo`) (open question Q3).

### 6.3 Direction (A): per-transaction durability

Literature fit:

- The decision procedure follows FaRM, parallel commits, OceanBase, TiDB async
  commit, and the binlog XA model.
- ELR in a multi-log setting needs Taurus' or CLV's dependency tracking, which
  is too heavy for NDB. So (A) should be **strict**: no transaction becomes
  visible anywhere until it is durable on all participants.

#### A1: force at commit, visibility at complete

This is the variant that fits `READ_BACKUP=1`.

- **Prepare:** unchanged, with no force.
- **Commit round:** each participant LQH, on every replica, writes the commit
  record and waits for a group-commit force of that log part. It then replies.
  The write is *not yet* visible and the locks are still held.
- **TC:** when all participants are durable, the transaction is committed and
  durable.
- **Complete round:** make the write visible with TUP commit, release the
  locks, and free the records. Then ack the API, as `TF_LATE_COMMIT` already
  does.
- Compared with today's `READ_BACKUP` path, this keeps the **same number of
  message rounds** and adds **one parallel fsync** (amortised per log part).
  Lock hold time grows by one fsync plus one round.
- SAP's LSN-comparison idea (5.2) can skip the wait when the log part is
  already flushed past the record.
- **Why visibility must wait for *all* participants:**
  - Suppose one replica made T visible as soon as its *own* commit record was
    durable.
  - A reader could then see T while another participant has not yet flushed
    T's prepare or commit records.
  - After a crash, T would be incomplete and dropped, but the reader would
    already have observed it.
  - This is the 2.4 anomaly through lockless reads. FaRM applies the same rule:
    COMMIT-BACKUP must be durable everywhere before COMMIT-PRIMARY exposes the
    write.

**REDO records for A1:**

- A **TransId** (64-bit) and **GCI64** in every commit record. Neither is
  present today (Part 0 item 1).
- A **participant summary** so that SR can check completeness. There are two
  options:
  - **(a) Counting.** Every commit record carries `(TransId, opIndex,
    totalWriteOps)`. At SR, the transaction is complete iff the distinct
    `opIndex` values found across all nodes' durable tails cover
    `0..totalWriteOps-1`, with replicas deduplicated. This is compact and needs
    no anchor. It works because NDB knows the full operation list at commit
    time, which is Paxos Commit's registrar point.
  - **(b) Anchor record.** One participant, for example the LQH with the commit
    ack marker, writes a transaction record with the full `(fragment, #ops)`
    list. This works like the STAGING record or the commit point site.
- Abort records are unchanged.

**SR decision procedure** (FaRM-like, run over REDO):

1. Compute the base cut E as today, or as the (B) durable epoch if B2 exists.
2. Each node scans each log part's tail above E. For each (TransId, opIndex)
   whose commit record is durable, it sends a vote to the master, batched.
3. The master marks T committed iff its record set is complete. Under
   strictness, the closure property follows: anything T read or overwrote was
   durable on all participants before T could see it, so it passes the same
   test. Otherwise T is aborted (presumed abort).
4. The master distributes the set of committed TransIds beyond E. REDO
   execution applies records with `GCI ≤ E` plus those of the committed set,
   in per-fragment log order.
5. The ragged tail is invalidated durably.

**The mixed-mode hazard:**

- A durable-mode transaction T can read or overwrite data that a *non-durable*
  transaction T0 made visible early, for example a table without the option or
  a `READ_BACKUP=0` table, in an epoch that is not durable.
- T would then be durable while T0 is lost.
- **Remedy:** T records a `depGCI`, the max `ROW_GCI64` of the rows written by
  non-durable transactions that it read or overwrote.
  - T's ack waits until `durable epoch ≥ depGCI`. This needs (B) or the
    existing GCP.
  - SR includes T only if `depGCI ≤ E`.
- Without (B), that wait is up to 2 s. **So A1 really needs B underneath**, or
  it needs every table that a durable transaction touches to be durable-mode.

#### A2: forced prepare with implicit commit

This is the OceanBase and parallel-commits style.

- Prepares are forced, either per operation using "forward then force" in the
  chain, or with one FLUSH round at commit.
- An anchor transaction record is forced.
- "All prepares and the anchor durable" means committed, so the ack can come
  before the commit round.
- **For `READ_BACKUP=1` this gains nothing**, because the ack must wait for
  visibility on the backups (complete phase) anyway.
- It also adds a force to every interactive `execute()` round trip, unless the
  FLUSH round is used.
- It is useful only for `READ_BACKUP=0` tables later on.

#### A3: ELR, CLV or Taurus dependency tracking

- Release or violate locks before durability and track the dependencies across
  nodes, with cascading aborts.
- This gives the best lock hold times but is the highest-complexity option. It
  is not recommended as the foundation.

### 6.4 Comparison

| | B0 (frequent GCP) | B2 (durable micro-GCP) | A1 (strict, force at commit) | A2 (forced prepare) |
|---|---|---|---|---|
| Ack latency | GCP/2 + 2 fsync + rounds (~15–40 ms at 20 ms GCP) | epoch/2 + 1 fsync + ~2 hops (≈5–15 ms at 10 ms; less with on-demand) | today's READ_BACKUP + 1 fsync (sub-ms on NVMe with PLP) | as A1 (no gain for READ_BACKUP=1) |
| Forces | 2 per GCP per node | 1 per log part per epoch | 1 per touched log part per txn (group-committed) | 1+ per txn per participant |
| Lock hold | unchanged | unchanged | +fsync +1 round | +fsync per execute() |
| Read-only safety | row-GCI gate | row-GCI gate | by construction (deferred visibility) | by construction |
| REDO format change | none | GCI64 in commit records + GCI64 marker | TransId, GCI64, participant summary, depGCI | same + anchor record |
| SR change | none | compute E from markers; truncate | + distributed vote/decision pass | same |
| Epoch atomicity | yes | yes | no (partial epoch beyond E) | no |
| Mixed durable/non-durable | trivial | trivial | needs depGCI + B | same |
| Stragglers | delay all | delay all | isolated | isolated |

### 6.5 Recommendation

**Build B first and treat A1 as an optional low-latency mode layered on B.**

1. **B0 now, as a measurement prototype.** Gate the ack on the restorable GCI,
   with a small `TimeBetweenGlobalCheckpoints`. It requires no format change,
   and it shows the real cost of GCP frequency, sysfile writes, and GCP-stop
   margins.
2. **B2 as the product.** Durable micro-GCPs with:
   - GCI64 in commit records and in the completed marker;
   - an SR rule computed from REDO markers in the style of FoundationDB and
     Aurora (the max per node group, then the min across node groups);
   - a durable truncation of REDO above the cut;
   - a `DURABLE_GCI_REP` signal to TC with per-GCI pending-ack queues;
   - an on-demand or adaptive epoch trigger;
   - `ROW_GCI64` gating as an option for lockless reads.

   Locks are unchanged, there is no new decision protocol, and epoch atomicity
   for replication is preserved. This matches NDB's structure: consistent cuts
   already exist, and B only makes them durable.
3. **A1 later, if B2's latency is too high for some workloads.** Strict
   visibility, a commit-time force, and a FaRM-style SR vote that uses
   per-commit-record `(TransId, opIndex, totalWriteOps, GCI64, depGCI)`. B2
   remains the base cut and the bound on depGCI.
   - Start with **single-node-group transactions**, where TiDB-style 1PC gives
     completeness by construction. That avoids most of the distributed vote
     machinery.

### 6.6 Open questions

1. **Latency target.** Is about 5 to 15 ms per durable ack acceptable for the
   intended `READ_BACKUP` workloads (feature store, Rondis)? This decides
   whether A1 is ever needed.
2. **Epoch-switch stall.** What does `getBlockCommit()` cost at 1 to 10 ms
   epochs? Can the switch be made non-blocking in the CPR or Chandy–Lamport
   style without breaking GCI monotonicity?
3. **LCP and SR in GCI-hi units.** Do LCP selection, `maxGciCompleted` and
   `maxGciWritten`, and the REDO start and stop logic accept a restore point at
   `(hi, lo)`? Or should B2 restore to whole GCPs but make each GCP short?
4. **Ack rule for node groups.** Should an epoch count as durable when all
   replicas have flushed, or when one per node group has? The answer changes
   both latency and the SR source selection.
5. **Lockless-read semantics.** Is (R1), documenting that reads may see data
   that is acknowledged-pending, acceptable for the first release? Or must
   `READ_COMMITTED` results be gated by `ROW_GCI64`? Where should the gate sit:
   in the API (it needs the durable epoch broadcast to API nodes) or in the TC?
6. **Replication.** Should SUMA and the ndb_binlog injector wait for the
   durable epoch? That would keep the binlog from running ahead of a cluster
   after a full crash. Is the extra replication lag acceptable?
7. **Straggler policy.** How should one huge or slow transaction be stopped
   from holding back every durable ack in its epoch? COCO accepts it. NDB might
   bound the size of a durable transaction or use A1 for it.
8. **Disk data tables.** Their undo and LGMAN log interacts with REDO
   durability. Is that in scope for the first release?
9. **The fsync path.** Check how NDBFS issues REDO writes and syncs (O_DIRECT,
   fdatasync) and what group-commit cadence each LDM log part can sustain on
   the target cloud disks. EBS-class latency (≈0.5–1 ms) makes per-transaction
   forces in A1 much less attractive than on local NVMe.
10. **Node failure during a durable epoch.** Confirm that TC take-over and
    `GCP_NODEFINISH` handling never let the master declare epoch e durable
    while a take-over is still writing commit records of e.
