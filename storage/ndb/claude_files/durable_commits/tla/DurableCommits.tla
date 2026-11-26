--------------------------- MODULE DurableCommits ---------------------------
(***************************************************************************)
(* RONDB-1150 X3.4: durable commits across a crash of every data node.     *)
(*                                                                         *)
(* The commit protocol of X4 with invariants C, K, L, A and F (plan        *)
(* s.3.1): linear and parallel commit and complete, node failures, rule F  *)
(* in TC and in the takeover, the takeover's "was a COMPLETE sent?"        *)
(* (X4.9, DI-7), dirty writes with CPF_SELF (X4.13, DI-1), and the         *)
(* node-failure file (plan s.5.4). Every data node can crash at any state: *)
(* each log part keeps the records up to its last barrier, and with        *)
(* LazyComplete any of the COMPLETEs written after it, in log order; a     *)
(* cluster restart reads what is kept. The invariants run the restart's    *)
(* phase 2 (plan s.5.2, X5.3-X5.5: step A, the exchange of step B, the     *)
(* verdicts of step C with the count rule) on the logs of the starting     *)
(* nodes that are not stale, and check G1-G3 of plan s.1 against what was  *)
(* acknowledged, seen and ordered at run time.                             *)
(*                                                                         *)
(* Abstractions (README.md): one REDO log part per node; every row is a    *)
(* fragment of its own; a transaction writes a row at most once; every     *)
(* modelled transaction is in the durable tail (GCI > R_gcp, >= g), and    *)
(* OldTxn, with a GCI <= R_gcp, only puts records before the tail; TC sees *)
(* the replicas' states instead of counting COMMITTED and COMPLETED; the   *)
(* takeover TC does not fail; phase 2 is one function of the logs.         *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Nodes,            \* data nodes, each with one REDO log part
    NG,               \* NG[n]: the node group of node n
    Rows,             \* rows, each a fragment of its own
    Chain,            \* Chain[r]: the replicas of row r, primary first
    Txns,             \* transactions
    TxnRows,          \* TxnRows[t]: the rows that t writes, one operation each
    TC,               \* TC[t]: the node of t's transaction coordinator
    Dirty,            \* transactions that are one dirty write each
    TransId,          \* TransId[t]: transaction id, also of OldTxn
    OldTxn,           \* a transaction with a GCI <= R_gcp (DI-2)
    OldLog,           \* OldLog[n]: OldTxn's records in n's log, before the tail
    Paths,            \* commit paths, a subset of {"linear", "parallel"}
    MaxFailures,      \* node failures before every node crashes
    RuleF,            \* rule F on (DUMP 2561 1)
    TakeoverFCommitted,
                      \* the takeover aborts by rule F also when every
                      \* operation reports Committed, unless it finds a
                      \* COMPLETE sent (X4 as coded); FALSE: it completes
                      \* then, as without rule F (finding 1)
    DropLateComplete, \* X4.9: LQH drops a COMPLETE, but the takeover's, for
                      \* an operation reported to the takeover (DI-7)
    LateFromFailedTc, \* a signal from a failed node may run after
                      \* LQH_TRANSREQ
    DI2Rule,          \* X5.4: step B counts a COMPLETE or ABORT of T only
                      \* after a tail COMMIT of T in the same part
    PartialSR,        \* also check restarts where only some nodes start
    LazyComplete,     \* a COMPLETE is not fenced: the next barrier of its
                      \* log part persists it, as the commit point is the
                      \* last COMMIT persisted
    SkipDirty,        \* phase 2 skips a dirty write in the tail and step C
                      \* invalidates its COMMIT (best effort, DI-1); else
                      \* its CPF_SELF COMPLETE applies it (X4.13)
    Fallback,         \* step C commits by the count rule too, not only on
                      \* "T complete" (D5; off only to show it is needed)
    GroupLoss,        \* X6.3: the last live node of a node group may fail;
                      \* the survivors record it and the cluster stops
    RefinedStale,     \* X6.3: a recorded failure makes its node stale only
                      \* if a node of its node group outlived it; FALSE:
                      \* any recorded failure does (the rule of X6.1-X6.4)
    JointFail,        \* X6.9: nodes may fail together, in one failure
                      \* round, and record nothing of each other
    WholeGroup        \* X6.9: a restart needs every node of some node
                      \* group (CheckNodeGroups::Win); FALSE: a node of each
                      \* node group that is not stale suffices

NoTxn == "none"

VARIABLES
    alive,      \* nodes running
    failCount,  \* node failures so far
    nfRec,      \* nfRec[n]: <<x, k>> in n's node-failure file: node x
                \* failed in the k-th failure
    tcState,    \* tcState[t]: TC's state of t, or the takeover's
    path,       \* path[t]: "linear" or "parallel"
    seenFail,   \* seenFail[t]: failed participants TC has reacted to
    rep,        \* rep[t][r][n]: the operation record of t on row r at node n
    lock,       \* lock[r][n]: the transaction holding the row lock
    hist,       \* hist[r][n]: the transactions that got the lock, in order
    abortRel,   \* abortRel[t]: <<r, n>> whose lock an abort released after
                \* the commit decision
    learnedBy,  \* learnedBy[t]: the transactions that took a row lock where
                \* an abort of t after the commit decision had released it
    vis,        \* vis[t]: a write of t was visible on some replica
    api,        \* api[t]: what the API was told
    log,        \* log[n]: the REDO records of node n, in the order written
    pers,       \* pers[n]: the records of log[n] up to its last barrier
    msgs,       \* COMMIT and COMPLETE signals in flight
    reports,    \* reports[t]: <<r, n, state>> from LQH_TRANSCONF
    markers,    \* markers[t]: nodes with a commit-ack marker of t at the scan
    scanned,    \* scanned[t]: nodes that answered the takeover's LQH_TRANSREQ
    lqhCrash    \* an ndbrequire in DBLQH failed

failVars == <<alive, failCount, nfRec>>
toVars == <<reports, markers, scanned>>
logVars == <<log, pers>>
vars == <<failVars, tcState, path, seenFail, rep, lock, hist, abortRel,
          learnedBy, vis, api, logVars, msgs, toVars, lqhCrash>>

-----------------------------------------------------------------------------
(* Replicas and records *)

NodeGroups == {NG[n] : n \in Nodes}
RowNodes(r) == {Chain[r][i] : i \in 1..Len(Chain[r])}
Pos(r, n) == CHOOSE i \in 1..Len(Chain[r]) : Chain[r][i] = n

\* The nodes with an operation record of t on r since its prepare
Parts(t, r) == {n \in RowNodes(r) : rep[t][r][n] # "none"}
LiveParts(t, r) == Parts(t, r) \cap alive
AllParts(t) == UNION {Parts(t, r) : r \in TxnRows[t]}

\* The live participants before n in the chain, towards the primary
Before(t, r, n) == {m \in LiveParts(t, r) : Pos(r, m) < Pos(r, n)}
PrevLive(t, r, n) ==
    CHOOSE m \in Before(t, r, n) :
        \A k \in Before(t, r, n) : Pos(r, k) <= Pos(r, m)
LastLive(t, r) ==
    CHOOSE m \in LiveParts(t, r) :
        \A k \in LiveParts(t, r) : Pos(r, k) <= Pos(r, m)

\* opCount: the logged write operations of t; 0 for a dirty write (X4.13)
OpCount(t) == IF t \in Dirty THEN 0 ELSE Cardinality(TxnRows[t])

Rec(type, t, r, opc, self, tl) ==
    [type |-> type, tid |-> TransId[t], txn |-> t, row |-> r,
     opc |-> opc, self |-> self, tail |-> tl]
CommitRec(t, r) == Rec("COMMIT", t, r, OpCount(t), FALSE, TRUE)
CompleteRec(t, r, self) == Rec("COMPLETE", t, r, 0, self, TRUE)
AbortRec(t, r) == Rec("ABORT", t, r, 0, FALSE, TRUE)  \* AF_AFTER_COMMIT

\* A signal from node from to node n; fwd: passed on along the chain
Msg(type, t, r, from, n, fwd) ==
    [type |-> type, txn |-> t, row |-> r, from |-> from, to |-> n, fwd |-> fwd]

Reported(t) == {<<k[1], k[2]>> : k \in reports[t]}

TcStates == {"prepare", "committing", "completing", "done", "aborted",
             "abortingF", "abortedF", "takeover", "toAbort", "toAbortF",
             "toCommit", "toComplete", "lost"}
\* States in which a failure of the TC's node leaves t to a takeover
Active == {"prepare", "committing", "completing", "abortingF"}

-----------------------------------------------------------------------------
(* Initial state *)

Init ==
    /\ alive = Nodes
    /\ failCount = 0
    /\ nfRec = [n \in Nodes |-> {}]
    /\ tcState = [t \in Txns |-> "prepare"]
    /\ path = [t \in Txns |-> "linear"]
    /\ seenFail = [t \in Txns |-> {}]
    /\ rep = [t \in Txns |-> [r \in Rows |-> [n \in Nodes |-> "none"]]]
    /\ lock = [r \in Rows |-> [n \in Nodes |-> NoTxn]]
    /\ hist = [r \in Rows |-> [n \in Nodes |-> <<>>]]
    /\ abortRel = [t \in Txns |-> {}]
    /\ learnedBy = [t \in Txns |-> {}]
    /\ vis = [t \in Txns |-> FALSE]
    /\ api = [t \in Txns |-> "none"]
    /\ log = OldLog
    /\ pers = [n \in Nodes |-> Len(OldLog[n])]
    /\ msgs = {}
    /\ reports = [t \in Txns |-> {}]
    /\ markers = [t \in Txns |-> {}]
    /\ scanned = [t \in Txns |-> {}]
    /\ lqhCrash = FALSE

-----------------------------------------------------------------------------
(* Prepare: the chain takes the row locks, primary first. A lock taken    *)
(* where an abort after the commit decision released it lets the new      *)
(* writer learn of that abort.                                            *)

Prepare(t, r, n) ==
    /\ t \notin Dirty
    /\ tcState[t] = "prepare"
    /\ TC[t] \in alive
    /\ r \in TxnRows[t]
    /\ n \in alive \cap RowNodes(r)
    /\ rep[t][r][n] = "none"
    /\ \A m \in RowNodes(r) \cap alive :
           Pos(r, m) < Pos(r, n) => rep[t][r][m] = "prepared"
    /\ lock[r][n] = NoTxn
    /\ rep' = [rep EXCEPT ![t][r][n] = "prepared"]
    /\ lock' = [lock EXCEPT ![r][n] = t]
    /\ hist' = [hist EXCEPT ![r][n] = Append(@, t)]
    /\ learnedBy' = [u \in Txns |->
                       IF <<r, n>> \in abortRel[u] THEN learnedBy[u] \cup {t}
                                                   ELSE learnedBy[u]]
    /\ UNCHANGED <<failVars, tcState, path, seenFail, abortRel, vis, api,
                   logVars, msgs, toVars, lqhCrash>>

\* An abort before the commit decision (deadlock timeout, node failure):
\* no REDO record of t exists
PrepareAbort(t) ==
    /\ t \notin Dirty
    /\ tcState[t] = "prepare"
    /\ TC[t] \in alive
    /\ tcState' = [tcState EXCEPT ![t] = "aborted"]
    /\ api' = [api EXCEPT ![t] = "aborted"]
    /\ rep' = [rep EXCEPT ![t] =
                  [r \in Rows |-> [n \in Nodes |->
                      IF rep[t][r][n] = "prepared" THEN "aborted"
                                                   ELSE rep[t][r][n]]]]
    /\ lock' = [r \in Rows |-> [n \in Nodes |->
                   IF lock[r][n] = t THEN NoTxn ELSE lock[r][n]]]
    /\ UNCHANGED <<failVars, path, seenFail, hist, abortRel, learnedBy, vis,
                   logVars, msgs, toVars, lqhCrash>>

-----------------------------------------------------------------------------
(* The commit phase: DIVERIFYCONF, then COMMIT to the last replica of     *)
(* each row (linear) or COMMITREQ to every replica (parallel).            *)

CommitMsgs(t, p) ==
    IF p = "linear"
    THEN {Msg("COMMIT", t, r, TC[t], LastLive(t, r), TRUE) :
              r \in TxnRows[t]}
    ELSE UNION {{Msg("COMMIT", t, r, TC[t], n, FALSE) : n \in LiveParts(t, r)}
                    : r \in TxnRows[t]}

StartCommit(t, p) ==
    /\ t \notin Dirty
    /\ tcState[t] = "prepare"
    /\ TC[t] \in alive
    /\ p \in Paths
    /\ \A r \in TxnRows[t] :
           /\ Parts(t, r) # {}
           /\ Parts(t, r) \subseteq alive
           /\ \A m \in RowNodes(r) \cap alive : rep[t][r][m] = "prepared"
    /\ tcState' = [tcState EXCEPT ![t] = "committing"]
    /\ path' = [path EXCEPT ![t] = p]
    /\ msgs' = msgs \cup CommitMsgs(t, p)
    /\ UNCHANGED <<failVars, seenFail, rep, lock, hist, abortRel, learnedBy,
                   vis, api, logVars, toVars, lqhCrash>>

\* C: the COMMIT record is persistent before COMMITTED or the COMMIT passed
\* on. L: no replica commits locally at COMMIT. A COMMIT for an operation
\* already aborted or gone is dropped, as LQH finds no record.
DeliverCommit(m) ==
    /\ m \in msgs
    /\ m.type = "COMMIT"
    /\ LET t == m.txn
           r == m.row
           n == m.to
       IN IF n \in alive /\ rep[t][r][n] = "prepared"
          THEN /\ rep' = [rep EXCEPT ![t][r][n] = "committed"]
               /\ log' = [log EXCEPT ![n] = Append(@, CommitRec(t, r))]
               /\ pers' = [pers EXCEPT ![n] = Len(log[n]) + 1]
               /\ msgs' = (msgs \ {m}) \cup
                     (IF m.fwd /\ Before(t, r, n) # {}
                      THEN {Msg("COMMIT", t, r, n, PrevLive(t, r, n), TRUE)}
                      ELSE {})
          ELSE /\ msgs' = msgs \ {m}
               /\ UNCHANGED <<rep, logVars>>
    /\ UNCHANGED <<failVars, tcState, path, seenFail, lock, hist, abortRel,
                   learnedBy, vis, api, toVars, lqhCrash>>

-----------------------------------------------------------------------------
(* The complete phase: only after every live replica has its COMMIT.      *)

CompleteMsgs(t, p) ==
    IF p = "linear"
    THEN {Msg("COMPLETE", t, r, TC[t], LastLive(t, r), TRUE) :
              r \in TxnRows[t]}
    ELSE UNION {{Msg("COMPLETE", t, r, TC[t], n, FALSE) :
                    n \in LiveParts(t, r)} : r \in TxnRows[t]}

AllCommitted(t) ==
    \A r \in TxnRows[t] : \A n \in LiveParts(t, r) :
        rep[t][r][n] = "committed"
AllDone(t) ==
    \A r \in TxnRows[t] : \A n \in LiveParts(t, r) : rep[t][r][n] = "done"

CommitPhaseDone(t) ==
    /\ tcState[t] = "committing"
    /\ TC[t] \in alive
    /\ AllCommitted(t)
    /\ tcState' = [tcState EXCEPT ![t] = "completing"]
    /\ msgs' = msgs \cup CompleteMsgs(t, path[t])
    /\ UNCHANGED <<failVars, path, seenFail, rep, lock, hist, abortRel,
                   learnedBy, vis, api, logVars, toVars, lqhCrash>>

\* K and L: the COMPLETE record is persistent before the local commit, the
\* lock release and the COMPLETE passed on. X4.9 (DI-7): a COMPLETE for an
\* operation reported to the takeover is dropped; the takeover's own
\* COMPLETEREQ is TOCompleteAt.
DeliverComplete(m) ==
    /\ m \in msgs
    /\ m.type = "COMPLETE"
    /\ LET t == m.txn
           r == m.row
           n == m.to
       IN IF /\ n \in alive
             /\ rep[t][r][n] = "committed"
             /\ ~(DropLateComplete /\ <<r, n>> \in Reported(t))
          THEN /\ rep' = [rep EXCEPT ![t][r][n] = "done"]
               /\ log' = [log EXCEPT ![n] =
                             Append(@, CompleteRec(t, r, FALSE))]
               /\ pers' = IF LazyComplete THEN pers
                         ELSE [pers EXCEPT ![n] = Len(log[n]) + 1]
               /\ lock' = [lock EXCEPT ![r][n] = NoTxn]
               /\ vis' = [vis EXCEPT ![t] = TRUE]
               /\ msgs' = (msgs \ {m}) \cup
                     (IF m.fwd /\ Before(t, r, n) # {}
                      THEN {Msg("COMPLETE", t, r, n, PrevLive(t, r, n),
                                TRUE)}
                      ELSE {})
          ELSE /\ msgs' = msgs \ {m}
               /\ UNCHANGED <<rep, logVars, lock, vis>>
    /\ UNCHANGED <<failVars, tcState, path, seenFail, hist, abortRel,
                   learnedBy, api, toVars, lqhCrash>>

\* A: the API is acknowledged after the last COMPLETED
CompletePhaseDone(t) ==
    /\ tcState[t] = "completing"
    /\ TC[t] \in alive
    /\ AllDone(t)
    /\ tcState' = [tcState EXCEPT ![t] = "done"]
    /\ api' = [api EXCEPT ![t] = "committed"]
    /\ UNCHANGED <<failVars, path, seenFail, rep, lock, hist, abortRel,
                   learnedBy, vis, logVars, msgs, toVars, lqhCrash>>

-----------------------------------------------------------------------------
(* A participant fails while TC runs (X4.8). In the commit phase rule F  *)
(* aborts; without it TC sends COMMITREQ to the replicas left. In the     *)
(* complete phase TC sends COMPLETEREQ to the replicas left.              *)

FailReaction(t) ==
    /\ tcState[t] \in {"committing", "completing"}
    /\ TC[t] \in alive
    /\ (AllParts(t) \ alive) \ seenFail[t] # {}
    /\ seenFail' = [seenFail EXCEPT ![t] = @ \cup (AllParts(t) \ alive)]
    /\ CASE tcState[t] = "committing" /\ RuleF ->
              /\ tcState' = [tcState EXCEPT ![t] = "abortingF"]
              /\ UNCHANGED <<path, msgs>>
         [] tcState[t] = "committing" /\ ~RuleF ->
              /\ path' = [path EXCEPT ![t] = "parallel"]
              /\ msgs' = msgs \cup
                    UNION {{Msg("COMMIT", t, r, TC[t], n, FALSE) :
                               n \in {k \in LiveParts(t, r) :
                                         rep[t][r][k] = "prepared"}}
                              : r \in TxnRows[t]}
              /\ UNCHANGED tcState
         [] OTHER ->
              /\ path' = [path EXCEPT ![t] = "parallel"]
              /\ msgs' = msgs \cup
                    UNION {{Msg("COMPLETE", t, r, TC[t], n, FALSE) :
                               n \in {k \in LiveParts(t, r) :
                                         rep[t][r][k] = "committed"}}
                              : r \in TxnRows[t]}
              /\ UNCHANGED tcState
    /\ UNCHANGED <<failVars, rep, lock, hist, abortRel, learnedBy, vis, api,
                   logVars, toVars, lqhCrash>>

\* F: ABORTREQ with FLAG_AFTER_COMMIT. A replica with a COMMIT record
\* persists an ABORT with AF_AFTER_COMMIT before it releases the lock. The
\* takeover sends it only to the operations reported to it.
AbortFAt(t, r, n) ==
    /\ tcState[t] \in {"abortingF", "toAbortF"}
    /\ tcState[t] = "abortingF" => TC[t] \in alive
    /\ r \in TxnRows[t]
    /\ tcState[t] = "toAbortF" => <<r, n>> \in Reported(t)
    /\ n \in alive
    /\ rep[t][r][n] \in {"prepared", "committed"}
    /\ rep' = [rep EXCEPT ![t][r][n] = "aborted"]
    /\ lock' = [lock EXCEPT ![r][n] = NoTxn]
    /\ abortRel' = [abortRel EXCEPT ![t] = @ \cup {<<r, n>>}]
    /\ log' = IF rep[t][r][n] = "committed"
              THEN [log EXCEPT ![n] = Append(@, AbortRec(t, r))]
              ELSE log
    /\ pers' = IF rep[t][r][n] = "committed"
               THEN [pers EXCEPT ![n] = Len(log[n]) + 1]
               ELSE pers
    /\ UNCHANGED <<failVars, tcState, path, seenFail, hist, learnedBy, vis,
                   api, msgs, toVars, lqhCrash>>

AbortTargets(t) ==
    IF tcState[t] = "toAbortF"
    THEN {k \in Reported(t) : k[2] \in alive}
    ELSE {k \in TxnRows[t] \X alive : rep[t][k[1]][k[2]] # "none"}

\* The API is told after every live replica has aborted (268, 4031)
AbortFDone(t) ==
    /\ tcState[t] \in {"abortingF", "toAbortF"}
    /\ tcState[t] = "abortingF" => TC[t] \in alive
    /\ \A k \in AbortTargets(t) :
           rep[t][k[1]][k[2]] \notin {"prepared", "committed"}
    /\ tcState' = [tcState EXCEPT ![t] = "abortedF"]
    /\ api' = [api EXCEPT ![t] = "aborted"]
    /\ UNCHANGED <<failVars, path, seenFail, rep, lock, hist, abortRel,
                   learnedBy, vis, logVars, msgs, toVars, lqhCrash>>

-----------------------------------------------------------------------------
(* A node failure. Every survivor records it in its node-failure file    *)
(* before NODE_FAILREP (plan s.5.4), so before any TC or DIH leaves the   *)
(* node out, with the number of the failure. A node group keeps a live   *)
(* node: else the cluster stops, which is the crash of every node; with   *)
(* GroupLoss the survivors record the failure of the last node first     *)
(* (NodeFailLast). A transaction whose TC was on the node goes to a       *)
(* takeover.                                                              *)

NodeFail(x) ==
    /\ failCount < MaxFailures
    /\ x \in alive
    /\ \E y \in alive \ {x} : NG[y] = NG[x]
    /\ alive' = alive \ {x}
    /\ failCount' = failCount + 1
    /\ nfRec' = [n \in Nodes |->
                    IF n \in alive' THEN nfRec[n] \cup {<<x, failCount'>>}
                    ELSE nfRec[n]]
    /\ tcState' = [t \in Txns |->
                     IF TC[t] = x /\ tcState[t] \in Active
                     THEN (IF t \in Dirty THEN "lost" ELSE "takeover")
                     ELSE tcState[t]]
    /\ api' = [t \in Txns |->
                 IF TC[t] = x /\ tcState[t] \in Active /\ t \in Dirty
                 THEN "unknown" ELSE api[t]]
    /\ msgs' = {m \in msgs : m.to # x}
    /\ UNCHANGED <<path, seenFail, rep, lock, hist, abortRel, learnedBy, vis,
                   logVars, toVars, lqhCrash>>

\* X6.3: the last live node of a node group fails; the survivors record
\* it before PREP_FAILCONF, and then the cluster stops: every node crashes
\* before anything commits without it
NodeFailLast(x) ==
    /\ GroupLoss
    /\ failCount < MaxFailures
    /\ x \in alive
    /\ ~\E y \in alive \ {x} : NG[y] = NG[x]
    /\ alive' = {}
    /\ failCount' = failCount + 1
    /\ nfRec' = [n \in Nodes |->
                    IF n \in alive \ {x}
                    THEN nfRec[n] \cup {<<x, failCount'>>}
                    ELSE nfRec[n]]
    /\ msgs' = {}
    /\ UNCHANGED <<tcState, path, seenFail, rep, lock, hist, abortRel,
                   learnedBy, vis, api, logVars, toVars, lqhCrash>>

\* X6.9: nodes fail together, in one failure round, as when they lose the
\* power at once: the survivors record each with the same number, and the
\* failed nodes record nothing of each other. Each node group keeps a live
\* node. As NodeFail for each of them, one after the other, but for the
\* records.
NodeFailJoint(X) ==
    /\ JointFail
    /\ Cardinality(X) >= 2
    /\ failCount + Cardinality(X) <= MaxFailures
    /\ X \subseteq alive
    /\ \A g \in NodeGroups : \E y \in alive \ X : NG[y] = g
    /\ alive' = alive \ X
    /\ failCount' = failCount + Cardinality(X)
    /\ nfRec' = [n \in Nodes |->
                    IF n \in alive'
                    THEN nfRec[n] \cup {<<x, failCount + 1>> : x \in X}
                    ELSE nfRec[n]]
    /\ tcState' = [t \in Txns |->
                     IF TC[t] \in X /\ tcState[t] \in Active
                     THEN (IF t \in Dirty THEN "lost" ELSE "takeover")
                     ELSE tcState[t]]
    /\ api' = [t \in Txns |->
                 IF TC[t] \in X /\ tcState[t] \in Active /\ t \in Dirty
                 THEN "unknown" ELSE api[t]]
    /\ msgs' = {m \in msgs : m.to \notin X}
    /\ UNCHANGED <<path, seenFail, rep, lock, hist, abortRel, learnedBy, vis,
                   logVars, toVars, lqhCrash>>

\* A signal that a failed node had not sent yet is lost with it
LoseMsg(m) ==
    /\ m \in msgs
    /\ m.from \notin alive
    /\ msgs' = msgs \ {m}
    /\ UNCHANGED <<failVars, tcState, path, seenFail, rep, lock, hist,
                   abortRel, learnedBy, vis, api, logVars, toVars, lqhCrash>>

-----------------------------------------------------------------------------
(* The takeover (X4.9). LQH_TRANSREQ to every live node: each operation  *)
(* record reports Prepared or Committed, and is then NEW_FROM_TC. A node  *)
(* with a commit-ack marker reports it; markers are kept on every node    *)
(* that has a COMMIT of t. Without LateFromFailedTc a signal from a failed *)
(* node runs before LQH_TRANSREQ, or is lost.                             *)

TakeoverScan(t, n) ==
    /\ tcState[t] = "takeover"
    /\ n \in alive \ scanned[t]
    /\ \/ LateFromFailedTc
       \/ ~\E m \in msgs : m.txn = t /\ m.to = n /\ m.from \notin alive
    /\ reports' = [reports EXCEPT ![t] = @ \cup
                     {<<r, n, rep[t][r][n]>> :
                         r \in {s \in TxnRows[t] :
                                   rep[t][s][n] \in {"prepared", "committed"}}}]
    /\ markers' = [markers EXCEPT ![t] =
                     IF \E r \in TxnRows[t] :
                            rep[t][r][n] \in {"committed", "done"}
                     THEN @ \cup {n} ELSE @]
    /\ scanned' = [scanned EXCEPT ![t] = @ \cup {n}]
    /\ UNCHANGED <<failVars, tcState, path, seenFail, rep, lock, hist,
                   abortRel, learnedBy, vis, api, logVars, msgs, lqhCrash>>

\* takeOverCompleteSent(): fewer logged writes reported than the opCount,
\* or a reported operation with a replica on a node that answered without
\* reporting it. LQH frees an operation record only at COMPLETE, or at an
\* abort.
CompleteSent(t) ==
    LET R == Reported(t)
        repRows == {k[1] : k \in R}
    IN \/ Cardinality(repRows) < OpCount(t)
       \/ \E k \in R : \E m \in Parts(t, k[1]) :
              m \in scanned[t] /\ <<k[1], m>> \notin R

\* Rule F in the takeover when every operation reports Committed
AbortFCommitted(t) == RuleF /\ TakeoverFCommitted /\ ~CompleteSent(t)

\* CS_FAIL_PREPARED aborts; CS_FAIL_COMMITTING commits, or aborts by rule F;
\* CS_FAIL_COMMITTED completes, or with TakeoverFCommitted aborts by rule F
\* unless a COMPLETE was sent; markers alone (CS_FAIL_COMPLETED) acknowledge.
\* A transaction the takeover does not find gets 4010 from TAKE_OVERTCCONF:
\* unknown.
TakeoverDecide(t) ==
    /\ tcState[t] = "takeover"
    /\ alive \subseteq scanned[t]
    /\ LET Pr == {k \in reports[t] : k[3] = "prepared"}
           Co == {k \in reports[t] : k[3] = "committed"}
           next == CASE reports[t] = {} /\ markers[t] # {} -> "done"
                     [] reports[t] = {} /\ markers[t] = {} -> "lost"
                     [] reports[t] # {} /\ Co = {} -> "toAbort"
                     [] Co # {} /\ Pr # {} ->
                            (IF RuleF THEN "toAbortF" ELSE "toCommit")
                     [] OTHER -> (IF AbortFCommitted(t) THEN "toAbortF"
                                                         ELSE "toComplete")
       IN /\ tcState' = [tcState EXCEPT ![t] = next]
          /\ api' = [api EXCEPT ![t] = CASE next = "done" -> "committed"
                                          [] next = "lost" -> "unknown"
                                          [] OTHER -> api[t]]
    /\ UNCHANGED <<failVars, path, seenFail, rep, lock, hist, abortRel,
                   learnedBy, vis, logVars, msgs, toVars, lqhCrash>>

\* ABORTREQ without the flag: LQH aborts a Prepared operation; for a
\* Committed one abortStateHandlerLab requires NEW_FROM_TC and stops the
\* node (ndbrequire), so the abort goes no further
TOAbortAt(t, r, n) ==
    /\ tcState[t] = "toAbort"
    /\ <<r, n>> \in Reported(t)
    /\ n \in alive
    /\ rep[t][r][n] \in {"prepared", "committed"}
    /\ IF rep[t][r][n] = "committed"
       THEN /\ lqhCrash' = TRUE
            /\ UNCHANGED <<rep, lock, abortRel>>
       ELSE /\ rep' = [rep EXCEPT ![t][r][n] = "aborted"]
            /\ lock' = [lock EXCEPT ![r][n] = NoTxn]
            /\ abortRel' = [abortRel EXCEPT ![t] = @ \cup {<<r, n>>}]
            /\ UNCHANGED lqhCrash
    /\ UNCHANGED <<failVars, tcState, path, seenFail, hist, learnedBy, vis,
                   api, logVars, msgs, toVars>>

TOAbortDone(t) ==
    /\ tcState[t] = "toAbort"
    /\ \A k \in Reported(t) :
           k[2] \in alive => rep[t][k[1]][k[2]] \notin {"prepared", "committed"}
    /\ tcState' = [tcState EXCEPT ![t] = "aborted"]
    /\ api' = [api EXCEPT ![t] = "aborted"]
    /\ UNCHANGED <<failVars, path, seenFail, rep, lock, hist, abortRel,
                   learnedBy, vis, logVars, msgs, toVars, lqhCrash>>

\* COMMITREQ to the operations reported Prepared, as a durable COMMIT
TOCommitAt(t, r, n) ==
    /\ tcState[t] = "toCommit"
    /\ <<r, n>> \in Reported(t)
    /\ n \in alive
    /\ rep[t][r][n] = "prepared"
    /\ rep' = [rep EXCEPT ![t][r][n] = "committed"]
    /\ log' = [log EXCEPT ![n] = Append(@, CommitRec(t, r))]
    /\ pers' = [pers EXCEPT ![n] = Len(log[n]) + 1]
    /\ UNCHANGED <<failVars, tcState, path, seenFail, lock, hist, abortRel,
                   learnedBy, vis, api, msgs, toVars, lqhCrash>>

TOCommitDone(t) ==
    /\ tcState[t] = "toCommit"
    /\ \A k \in Reported(t) :
           k[2] \in alive => rep[t][k[1]][k[2]] # "prepared"
    /\ tcState' = [tcState EXCEPT ![t] = "toComplete"]
    /\ UNCHANGED <<failVars, path, seenFail, rep, lock, hist, abortRel,
                   learnedBy, vis, api, logVars, msgs, toVars, lqhCrash>>

\* COMPLETEREQ of the takeover, which LQH executes also for an operation
\* reported to it
TOCompleteAt(t, r, n) ==
    /\ tcState[t] = "toComplete"
    /\ <<r, n>> \in Reported(t)
    /\ n \in alive
    /\ rep[t][r][n] = "committed"
    /\ rep' = [rep EXCEPT ![t][r][n] = "done"]
    /\ log' = [log EXCEPT ![n] = Append(@, CompleteRec(t, r, FALSE))]
    /\ pers' = IF LazyComplete THEN pers
              ELSE [pers EXCEPT ![n] = Len(log[n]) + 1]
    /\ lock' = [lock EXCEPT ![r][n] = NoTxn]
    /\ vis' = [vis EXCEPT ![t] = TRUE]
    /\ UNCHANGED <<failVars, tcState, path, seenFail, hist, abortRel,
                   learnedBy, api, msgs, toVars, lqhCrash>>

\* X1: TCKEY_FAILCONF after the complete phase
TOCompleteDone(t) ==
    /\ tcState[t] = "toComplete"
    /\ \A k \in Reported(t) :
           k[2] \in alive => rep[t][k[1]][k[2]] # "committed"
    /\ tcState' = [tcState EXCEPT ![t] = "done"]
    /\ api' = [api EXCEPT ![t] = "committed"]
    /\ UNCHANGED <<failVars, path, seenFail, rep, lock, hist, abortRel,
                   learnedBy, vis, logVars, msgs, toVars, lqhCrash>>

-----------------------------------------------------------------------------
(* Dirty writes (X4.13, Q-B1): each replica in chain order writes PREPARE,*)
(* COMMIT with opCount 0 and COMPLETE with CPF_SELF behind one barrier,   *)
(* then commits locally and passes the write on.                          *)

DirtyWrite(t, r, n) ==
    /\ t \in Dirty
    /\ tcState[t] = "prepare"
    /\ TC[t] \in alive
    /\ r \in TxnRows[t]
    /\ n \in alive \cap RowNodes(r)
    /\ rep[t][r][n] = "none"
    /\ \A m \in RowNodes(r) \cap alive :
           Pos(r, m) < Pos(r, n) => rep[t][r][m] = "done"
    /\ lock[r][n] = NoTxn
    /\ rep' = [rep EXCEPT ![t][r][n] = "done"]
    /\ hist' = [hist EXCEPT ![r][n] = Append(@, t)]
    /\ learnedBy' = [u \in Txns |->
                       IF <<r, n>> \in abortRel[u] THEN learnedBy[u] \cup {t}
                                                   ELSE learnedBy[u]]
    /\ vis' = [vis EXCEPT ![t] = TRUE]
    /\ log' = [log EXCEPT ![n] =
                  @ \o <<CommitRec(t, r), CompleteRec(t, r, TRUE)>>]
    /\ pers' = [pers EXCEPT ![n] = Len(log[n]) + 2]
    /\ UNCHANGED <<failVars, tcState, path, seenFail, lock, abortRel, api,
                   msgs, toVars, lqhCrash>>

DirtyDone(t) ==
    /\ t \in Dirty
    /\ tcState[t] = "prepare"
    /\ TC[t] \in alive
    /\ \A r \in TxnRows[t] :
           /\ Parts(t, r) # {}
           /\ \A m \in RowNodes(r) \cap alive : rep[t][r][m] = "done"
    /\ tcState' = [tcState EXCEPT ![t] = "done"]
    /\ api' = [api EXCEPT ![t] = "committed"]
    /\ UNCHANGED <<failVars, path, seenFail, rep, lock, hist, abortRel,
                   learnedBy, vis, logVars, msgs, toVars, lqhCrash>>

-----------------------------------------------------------------------------

Next ==
    \/ \E t \in Txns, r \in Rows, n \in Nodes :
          \/ Prepare(t, r, n)
          \/ AbortFAt(t, r, n)
          \/ TOAbortAt(t, r, n)
          \/ TOCommitAt(t, r, n)
          \/ TOCompleteAt(t, r, n)
          \/ DirtyWrite(t, r, n)
    \/ \E t \in Txns :
          \/ PrepareAbort(t)
          \/ \E p \in Paths : StartCommit(t, p)
          \/ CommitPhaseDone(t)
          \/ CompletePhaseDone(t)
          \/ FailReaction(t)
          \/ AbortFDone(t)
          \/ TakeoverDecide(t)
          \/ TOAbortDone(t)
          \/ TOCommitDone(t)
          \/ TOCompleteDone(t)
          \/ DirtyDone(t)
          \/ \E n \in Nodes : TakeoverScan(t, n)
    \/ \E m \in msgs : DeliverCommit(m) \/ DeliverComplete(m) \/ LoseMsg(m)
    \/ \E x \in Nodes : NodeFail(x) \/ NodeFailLast(x)
    \/ \E X \in SUBSET Nodes : NodeFailJoint(X)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* The cluster restart's phase 2 on the logs (plan s.5.2, X5.3-X5.5).     *)

Range(s) == {s[i] : i \in DOMAIN s}

\* The elements of s that are in S, in order
RECURSIVE Keep(_, _)
Keep(s, S) ==
    IF s = <<>> THEN <<>>
    ELSE (IF Head(s) \in S THEN <<Head(s)>> ELSE <<>>) \o Keep(Tail(s), S)

TxnSeq(s) == [i \in 1..Len(s) |-> s[i].txn]

Tids == {TransId[t] : t \in Txns \cup {OldTxn}}

\* Step A, in log order. q: the hash table, a FIFO of COMMIT records per
\* transid; applied: the COMMITs executed; alist: the COMMITs invalidated
\* in step C without a verdict, those that an ABORT with AF_AFTER_COMMIT
\* took out and, with SkipDirty, a dirty write's (opCount 0). fl: the
\* transids whose COMMITs in this part are invalidated (RF_INVALIDATED)
\* by an earlier restart, never queued or counted. A record of OldTxn
\* (GCI <= R_gcp) is phase 1's.
InitA == [q |-> [x \in Tids |-> <<>>], applied |-> <<>>, alist |-> {}]

StepA(rec, fl, st) ==
    IF ~rec.tail THEN st
    ELSE CASE rec.type = "COMMIT" ->
                (IF rec.tid \in fl THEN st
                 ELSE IF SkipDirty /\ rec.opc = 0
                 THEN [st EXCEPT !.alist = @ \cup {rec}]
                 ELSE [st EXCEPT !.q[rec.tid] = Append(@, rec)])
           [] rec.type = "COMPLETE" /\ rec.self /\ SkipDirty -> st
           [] rec.type = "COMPLETE" /\ rec.self /\ ~SkipDirty ->
                \* CPF_SELF: only the dirty write's own COMMIT (DI-1)
                (LET own == {c \in Range(st.q[rec.tid]) : c.row = rec.row}
                 IN [st EXCEPT !.applied = @ \o Keep(st.q[rec.tid], own),
                               !.q[rec.tid] = Keep(@, Range(@) \ own)])
           [] rec.type = "COMPLETE" /\ ~rec.self ->
                [st EXCEPT !.applied = @ \o st.q[rec.tid],
                           !.q[rec.tid] = <<>>]
           [] rec.type = "ABORT" ->
                [st EXCEPT !.alist = @ \cup Range(st.q[rec.tid]),
                           !.q[rec.tid] = <<>>]
           [] OTHER -> st

RECURSIVE ScanA(_, _, _)
ScanA(L, fl, st) ==
    IF L = <<>> THEN st ELSE ScanA(Tail(L), fl, StepA(Head(L), fl, st))

\* Step B's rescan: "T complete" for a COMPLETE (not CPF_SELF) and "T
\* aborted" for an ABORT. With DI2Rule a record counts only after a tail
\* COMMIT of T in the same part; an invalidated COMMIT still counts there,
\* so that a restart that runs again keeps the hits.
RECURSIVE ScanB(_, _, _)
ScanB(L, seen, acc) ==
    IF L = <<>> THEN acc
    ELSE LET rec == Head(L)
             counts == ~DI2Rule \/ rec.tid \in seen
             seen2 == IF rec.tail /\ rec.type = "COMMIT"
                      THEN seen \cup {rec.tid} ELSE seen
             acc2 == CASE rec.type = "COMPLETE" /\ ~rec.self /\ counts ->
                            [acc EXCEPT !.c = @ \cup {rec.tid}]
                       [] rec.type = "ABORT" /\ counts ->
                            [acc EXCEPT !.a = @ \cup {rec.tid}]
                       [] OTHER -> acc
         IN ScanB(Tail(L), seen2, acc2)

RECURSIVE SumOver(_, _)
SumOver(S, f) ==
    IF S = {} THEN 0
    ELSE LET g == CHOOSE h \in S : TRUE IN f[g] + SumOver(S \ {g}, f)

\* Phase 2 on the logs L of the nodes P. Step C: commit on "T complete",
\* or when no "T aborted" came and every node of each node group counts the
\* same (none = 0), the node groups adding up to opCount (X5.5, the
\* fallback of D5).
Phase2(L, P, fl) ==
    LET A == [n \in P |-> ScanA(L[n], fl[n], InitA)]
        B == [n \in P |-> ScanB(L[n], {}, [c |-> {}, a |-> {}])]
        CH == UNION {B[n].c : n \in P}
        AH == UNION {B[n].a : n \in P}
        U == UNION {{x \in Tids : A[n].q[x] # <<>>} : n \in P}
        Opc(x) == (CHOOSE c \in UNION {Range(A[n].q[x]) : n \in P} : TRUE).opc
        Cnt(n, x) == Len(A[n].q[x])
        CountRule(x) ==
            /\ \A n1, n2 \in P : NG[n1] = NG[n2] => Cnt(n1, x) = Cnt(n2, x)
            /\ SumOver(NodeGroups,
                       [g \in NodeGroups |->
                           Cnt(CHOOSE n \in P : NG[n] = g, x)]) = Opc(x)
        Committed ==
            {x \in U : x \in CH \/ (Fallback /\ x \notin AH /\ CountRule(x))}
        Queued(n) == UNION {Range(A[n].q[x]) : x \in Tids}
        StepC(n) == Keep(L[n], {c \in Queued(n) : c.tid \in Committed})
    IN [final |-> [n \in P |-> A[n].applied \o StepC(n)],
        committed |-> Committed,
        queued |-> [n \in P |-> Queued(n)],
        alist |-> [n \in P |-> A[n].alist]]

SRTxns(res) ==
    {c.txn : c \in UNION {Range(res.final[n]) : n \in DOMAIN res.final}}
RowSeq(res, n, r) ==
    TxnSeq(Keep(res.final[n], {c \in Range(res.final[n]) : c.row = r}))

\* A node that some starting node recorded as failed is stale: it takes no
\* part (plan s.5.4). With RefinedStale only if that node's file shows a
\* node of its node group that outlived the failure: the recording node
\* itself, one with no failure recorded, or one that failed later (X6.3,
\* NodeFailFile::outlived()). Every node is restorable to R in the model,
\* and a failed node does not come back. The restart needs a node that is
\* not stale in every node group (D4, X6.4), and with WholeGroup every node
\* of some node group (X6.9), so that the nodes not starting cannot have
\* been the last to run.
Max(K) == CHOOSE m \in K : \A k \in K : k <= m
LatestFail(n, x) ==
    LET K == {p[2] : p \in {q \in nfRec[n] : q[1] = x}}
    IN IF K = {} THEN 0 ELSE Max(K)
Outlived(n, x) ==
    \E y \in Nodes \ {x} :
        /\ NG[y] = NG[x]
        /\ \/ y = n
           \/ LatestFail(n, y) = 0
           \/ LatestFail(n, y) > LatestFail(n, x)
Stale(S) ==
    {x \in Nodes : \E n \in S :
        LatestFail(n, x) > 0 /\ (RefinedStale => Outlived(n, x))}
SRNodes(S) == S \ Stale(S)
WholeGroupIn(S) ==
    \E g \in NodeGroups : \A n \in Nodes : NG[n] = g => n \in S
SRAllowed(S) ==
    /\ WholeGroup => WholeGroupIn(S)
    /\ \A g \in NodeGroups : \E n \in SRNodes(S) : NG[n] = g
SRStarts ==
    {S \in (IF PartialSR THEN SUBSET Nodes ELSE {Nodes}) : SRAllowed(S)}
NoFlags == [n \in Nodes |-> {}]
SR(L, S) == Phase2(L, SRNodes(S), NoFlags)

\* The crash keeps of each log part a prefix that holds at least the
\* records up to its last barrier: the restart's end of log is the first
\* position that is not a valid record, and nothing after it is read
\* (pmem_redo_design.md E11)
RECURSIVE CutFns(_)
CutFns(N) ==
    IF N = {} THEN {[n \in {} |-> 0]}
    ELSE LET x == CHOOSE y \in N : TRUE
         IN {[n \in N |-> IF n = x THEN k ELSE f[n]] :
                k \in pers[x]..Len(log[x]), f \in CutFns(N \ {x})}
CrashLogs ==
    {[n \in Nodes |-> SubSeq(log[n], 1, c[n])] : c \in CutFns(Nodes)}

-----------------------------------------------------------------------------
(* Invariants. Each holds for a crash of every node in any state.         *)

TypeOK ==
    /\ alive \subseteq Nodes
    /\ tcState \in [Txns -> TcStates]
    /\ api \in [Txns -> {"none", "committed", "aborted", "unknown"}]

\* DBLQH never fails an ndbrequire
NoLqhCrash == ~lqhCrash

\* X6.3: with every node starting, each node group has a node that is not
\* stale, also after a node group was lost (GroupLoss): its last node to
\* fail restores it
FullRestartAllowed == SRAllowed(Nodes)

\* In a log part no COMMIT of T follows a COMPLETE of T (plan s.5.2 step A)
CommitBeforeComplete ==
    \A n \in Nodes : \A i, j \in 1..Len(log[n]) :
        (/\ i < j
         /\ log[n][i].tail /\ log[n][j].tail
         /\ log[n][i].type = "COMPLETE" /\ ~log[n][i].self
         /\ log[n][j].type = "COMMIT")
        => log[n][i].tid # log[n][j].tid

\* A COMPLETE and a rule-F ABORT of T exclude each other (plan s.5.6)
CompleteExcludesAbort ==
    \A t \in Txns :
        ~(/\ \E n \in Nodes : \E c \in Range(log[n]) :
                 c.tail /\ c.type = "COMPLETE" /\ ~c.self /\ c.txn = t
          /\ \E n \in Nodes : \E c \in Range(log[n]) :
                 c.type = "ABORT" /\ c.txn = t)

\* G1: an acknowledged commit survives; a dirty write is best effort
G1 ==
    \A L \in CrashLogs : \A S \in SRStarts :
        LET res == SR(L, S) IN
        \A t \in Txns \ Dirty : api[t] = "committed" => t \in SRTxns(res)

\* G2: whole transactions; every starting replica of each row of T has T
G2Whole ==
    \A L \in CrashLogs : \A S \in SRStarts :
        LET res == SR(L, S) IN
        \A t \in SRTxns(res) : \A r \in TxnRows[t] :
            \A n \in SRNodes(S) \cap RowNodes(r) :
                t \in Range(RowSeq(res, n, r))

\* G3: the starting replicas of a row are identical
G3Same ==
    \A L \in CrashLogs : \A S \in SRStarts :
        LET res == SR(L, S) IN
        \A r \in Rows : \A n1, n2 \in SRNodes(S) \cap RowNodes(r) :
            RowSeq(res, n1, r) = RowSeq(res, n2, r)

\* Plan s.6: each row gets the surviving writes in the order of its locks
RowOrder ==
    \A L \in CrashLogs : \A S \in SRStarts :
        LET res == SR(L, S) IN
        \A r \in Rows : \A n \in SRNodes(S) \cap RowNodes(r) :
            RowSeq(res, n, r) = Keep(hist[r][n], SRTxns(res))

\* Plan s.5.6, "the right side": a transaction the API was told aborted, or
\* whose abort a later writer of its row saw where that writer is applied,
\* is not applied. A reader that saw the row without T read it before T,
\* which a later commit of T does not contradict while no write of T was
\* visible (VisibleStays).
AbortStays ==
    \A L \in CrashLogs : \A S \in SRStarts :
        LET res == SR(L, S) IN
        \A t \in Txns :
            (api[t] = "aborted" \/ learnedBy[t] \cap SRTxns(res) # {}) =>
                t \notin SRTxns(res)

\* ... and a transaction that was visible on a replica is applied, but a
\* dirty write, which is best effort
VisibleStays ==
    \A L \in CrashLogs : \A S \in SRStarts :
        LET res == SR(L, S) IN
        \A t \in Txns \ Dirty : vis[t] => t \in SRTxns(res)

\* Plan s.5.6: the next restart, at R = G' after phase 3, replays the old
\* tail's COMMITs that step C did not invalidate, in log order, and gets
\* the same rows as phase 2
NextSR ==
    \A L \in CrashLogs : \A S \in SRStarts :
        LET res == SR(L, S) IN
        \A n \in SRNodes(S) :
            LET flagged == {c \in res.queued[n] : c.tid \notin res.committed}
                               \cup res.alist[n]
                replay == Keep(L[n], {c \in Range(L[n]) :
                                         c.tail /\ c.type = "COMMIT"}
                                     \ flagged)
            IN replay = res.final[n]

\* X5.5: in-doubt transactions committed in step C share no row in a part
NoSharedRowInDoubt ==
    \A L \in CrashLogs : \A S \in SRStarts :
        LET res == SR(L, S) IN
        \A n \in SRNodes(S) :
            \A c1, c2 \in {c \in res.queued[n] : c.tid \in res.committed} :
                c1.row = c2.row => c1.tid = c2.tid

\* Plan s.5.6, a crash during step C: with any of the aborted transactions'
\* COMMITs invalidated, the restart that runs again gives the same result
FlagPairs(P, res) ==
    {p \in P \X Tids :
        \/ \E c \in res.alist[p[1]] : c.tid = p[2]
        \/ \E c \in res.queued[p[1]] :
               c.tid = p[2] /\ p[2] \notin res.committed}

Repeatable ==
    \A L \in CrashLogs : \A S \in SRStarts :
        LET P == SRNodes(S)
            res == Phase2(L, P, NoFlags)
        IN \A F \in SUBSET FlagPairs(P, res) :
               LET fl == [n \in Nodes |-> {p[2] : p \in {q \in F : q[1] = n}}]
                   res2 == Phase2(L, P, fl)
               IN /\ res2.committed = res.committed
                  /\ res2.final = res.final

=============================================================================
