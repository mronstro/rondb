# RONDB-1150 X3.4: the TLA+ model of durable commits

`DurableCommits.tla` models the commit path as X4 built it and the cluster
restart's phase 2 as X5 plans it, and checks the guarantees G1-G3 of the
plan (`../durable_commits_plan.md` §1) for a crash of every data node in
any reachable state. It was written before X5 is coded, to check rule F,
the takeover's "was a COMPLETE sent?" (DI-7), dirty writes (DI-1) and the
DI-2 rule of step B (`../impl_next_steps.md` §13).

**Decided (2026-11-24), after the two runs below:** rule F is dropped
(plan revision 14), as it caused findings 1 and 2 and the guarantees hold
without it; the code no longer has it, nor X4.9's drop of a late COMPLETE.
The model keeps both as switches, and their configurations as the
evidence. Dirty writes are best effort: phase 2 skips a dirty write in the
tail and step C invalidates its COMMIT, so its replicas never differ
(finding 3, DI-1). Finding 4 is upstream's race; it gets a ticket of
its own, outside RONDB-1150 (decided 2026-11-25).

**To check (2026-11-24): the COMPLETE without a fence.** Without rule F
the commit point is the last COMMIT persisted: after it every restart
commits T by the count rule. A COMPLETE then needs no fence before the
row is visible; it only lets step A decide T in its own log part. The
`MC_lazy*` configurations check that, with every crash cut of the log
parts; `MC_lazy_nofallback` is the control. The fourth run passed, and
the code follows it since plan revision 15: the `MC_lazy*` configurations
are X4 as committed, the `MC_x4*` ones the fenced COMPLETE before.

## Running it

TLC needs Java 11 or later and `tla2tools.jar`:

```
cd storage/ndb/claude_files/durable_commits/tla
curl -L -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
./run_tlc.sh                      # every configuration
./run_tlc.sh MC_x4.cfg MC_rulef.cfg
```

The script parses the modules with SANY, runs TLC on each configuration
with `-deadlock` (finished runs are not deadlocks) and prints TLC's verdict
next to the expected one. The logs, with the trace of a violation, are in
`$TLC_OUT` (default `/tmp/durable_commits_tlc`). `tla2tools.jar` is not
committed.

## What the model holds

| Part | In the model | In the code |
|---|---|---|
| Cluster | 2 node groups × 2 replicas; row a on n1 (primary), n2; row b on n3 (primary), n4; one REDO log part per node | `MC.tla` |
| t1 | writes a and b; TC on n3 | |
| t2 | writes a; TC on n2, the backup of a, which gets the linear COMMIT and COMPLETE first | |
| td | a dirty write of b (only in `MC_dirty`) | X4.13 |
| t0 | GCI ≤ R_gcp, the transid of t1; its COMMIT and COMPLETE of a lie before the tail in n1's and n2's logs, where X4.11's hold-back puts them | DI-2 |
| `Prepare` | the LQHKEYREQ chain, primary first, row locks | |
| `StartCommit` | DIVERIFYCONF; COMMIT to the last replica (linear) or COMMITREQ to all (parallel) | `commit020Lab`, `sendCommitLqh` |
| `DeliverCommit` | the COMMIT record, persistent before anything is sent (C); no local commit (L) | `execCOMMIT`, `commitReqLab`, `redoPersistOp` |
| `CommitPhaseDone` | COMPLETE after every live replica's COMMIT | `complete010Lab` |
| `DeliverComplete` | the COMPLETE record (K), then the local commit and lock release (L); a COMPLETE for an operation reported to a takeover is dropped (`DropLateComplete`) | `execCOMPLETE`, `redoCompleteDurable` |
| `CompletePhaseDone` | the ack after the last COMPLETED (A) | `sendApiLateCommitSignal` |
| `FailReaction`, `AbortFAt`, `AbortFDone` | a participant fails: rule F aborts in the commit phase, with an ABORT `AF_AFTER_COMMIT` where a COMMIT record exists; else COMMITREQ/COMPLETEREQ to the replicas left | X4.8, X4.10 |
| `NodeFail` | survivors record the failure in the node-failure file before NODE_FAILREP | plan §5.4, X6.1 |
| `LoseMsg` | a signal a failed node had not sent yet is lost | |
| `TakeoverScan`, `TakeoverDecide`, `TO*` | LQH_TRANSREQ reports (operation records, commit-ack markers); CS_FAIL_PREPARED/COMMITTING/COMMITTED/COMPLETED; `takeOverCompleteSent()`; COMMITREQ, COMPLETEREQ, ABORTREQ | X4.9 |
| `DirtyWrite` | PREPARE, COMMIT (opCount 0) and COMPLETE `CPF_SELF` behind one barrier, local commit, then the next replica | X4.13 |
| `Phase2` | step A (hash table, COMPLETE executes the queue, `CPF_SELF` its own COMMIT or, with `SkipDirty`, a dirty write's COMMIT invalidated; ABORT takes the queue out), step B (hits, with the DI-2 rule), step C (verdicts with the count rule) | plan §5.2, X5.3-X5.5 |
| `CrashLogs` | what a crash leaves of each log part: a prefix holding at least the records up to its last barrier (`pers`) | design E11 |
| `SRStarts` | the starting nodes; stale ones (recorded by a starting node) take no part; at least one non-stale node per node group | plan §5.4-5.5, X6.3-X6.4 |

A COMMIT (C), a rule-F ABORT (F) and a dirty write are fenced before the
signal that depends on them, which persists their log part up to them;
so is a COMPLETE (K), unless `LazyComplete`. Each invariant is checked in
every state, for every crash cut: each log part keeps a prefix that holds
at least its persisted records, as the restart's end of log is the first
position that is not a valid record.

Constants that switch parts on and off: `RuleF`, `TakeoverFCommitted`
(the takeover aborts by rule F also when every operation reports
Committed, unless `takeOverCompleteSent()`, as X4 codes it; FALSE is the
candidate fix of finding 1), `DropLateComplete`, `LateFromFailedTc` (a
signal received from a failed node may run after LQH_TRANSREQ; without it,
it runs before or is lost), `DI2Rule`, `PartialSR`, `MaxFailures`,
`Dirty`, `LazyComplete` (a COMPLETE is not fenced; the next barrier of its
log part persists it), `SkipDirty` (phase 2 skips a dirty write in the
tail and step C invalidates its COMMIT; else its `CPF_SELF` COMPLETE
applies it) and `Fallback` (step C's count rule; off only in a control).
G1 and `VisibleStays` do not cover dirty writes, which are best effort.

## Invariants

| Invariant | Checks |
|---|---|
| `G1` | an acknowledged transaction survives |
| `G2Whole` | a surviving transaction is on every starting replica of each of its rows |
| `G3Same` | the starting replicas of a row are identical |
| `RowOrder` | each row has the surviving writes in the order of its locks (plan §6) |
| `AbortStays` | a transaction the API was told aborted, or whose abort a later writer of its row saw where that writer survives, does not survive (plan §5.6; see the first run) |
| `VisibleStays` | a transaction that was visible on any replica survives (plan §5.6) |
| `NextSR` | the next restart, replaying the old tail's COMMITs that step C left valid, gets the same rows (plan §5.6) |
| `Repeatable` | a restart that crashes in step C with any of its invalidations done, and runs again, gets the same result (plan §5.6) |
| `NoSharedRowInDoubt` | in-doubt transactions committed in step C share no row in a part (X5.5) |
| `CompleteExcludesAbort` | no transaction has both a COMPLETE and a rule-F ABORT (plan §5.6) |
| `CommitBeforeComplete` | no COMMIT of T follows a COMPLETE of T in a log part |
| `NoLqhCrash` | no ndbrequire of DBLQH fails |

## Configurations and expected results

The expected results of the first run came from traces worked out by
hand; four were wrong (below). Since the third run's configurations
follow the code without rule F (2026-11-24): X4.9's drop is off in all
but the rule-F ones, `MC_repeatable` runs without rule F, and `MC_x4_late`
is new. A violation where none is expected is a
finding, and so is a run that finds none where one is expected.

| Configuration | Settings | Expected |
|---|---|---|
| `MC_x4` | X4 of plan revision 14 (no rule F, no drop of a late COMPLETE, the COMPLETE fenced), full restart | no error |
| `MC_x4_partial` | as `MC_x4`, partial restarts too (X6) | no error |
| `MC_x4_twofail` | as `MC_x4`, 2 node failures, all but `NoLqhCrash` | no error |
| `MC_x4_twofail_partial` | as `MC_x4_twofail`, partial restarts too | no error |
| `MC_x4_late` | as `MC_x4`, late signals from a failed node, all but `NoLqhCrash` | no error |
| `MC_repeatable` | as `MC_x4`, `Repeatable` only (slower) | no error |
| `MC_twofail_lqh` | as `MC_x4`, 2 node failures, `NoLqhCrash` only | violated: finding 4 without late signals |
| `MC_rulef` | rule F on, `TakeoverFCommitted = FALSE` (evidence) | no error |
| `MC_rulef_visible` | rule F on, the takeover as X4 codes it, `VisibleStays` only | violated: finding 1 |
| `MC_rulef_twofail` | as `MC_rulef`, 2 node failures, all but `NoLqhCrash` | `G2Whole` violated: finding 2 |
| `MC_late_drop` | rule F on, the takeover as X4 codes it, late signals from a failed node, X4.9's drop; all but `NoLqhCrash` (finding 4), `VisibleStays` and `CompleteExcludesAbort` (finding 1) | no error |
| `MC_no_drop_complete` | as `MC_late_drop` without the drop | `AbortStays` violated: the drop of X4.9 is needed |
| `MC_dirty` | a dirty write that phase 2 applies (X4.13 as coded), as the evidence | `G2Whole` violated: finding 3 |
| `MC_dirty_skip` | a dirty write that phase 2 skips (decided 2026-11-24) | no error |
| `MC_lazy` | as `MC_x4`, the COMPLETE not fenced: X4 as committed since plan revision 15 | no error |
| `MC_lazy_late` | as `MC_x4_late`, the COMPLETE not fenced | no error |
| `MC_lazy_twofail_partial` | as `MC_x4_twofail_partial`, the COMPLETE not fenced | no error |
| `MC_lazy_repeatable` | as `MC_repeatable`, the COMPLETE not fenced | no error |
| `MC_lazy_dirty` | as `MC_dirty_skip`, the COMPLETE not fenced | no error |
| `MC_lazy_nofallback` | as `MC_lazy` without the count rule: a control that the crash cuts lose COMPLETEs and that the count rule then decides | `VisibleStays` violated |
| `MC_late_tc` | late signals from a failed node | `NoLqhCrash` violated: finding 4 |
| `MC_no_di2` | without the DI-2 rule | `G2Whole` violated: the DI-2 rule is needed |

### First run (2026-11-24)

TLC 2.19, about a second per configuration (`MC_x4_twofail` 11 s and
456,004 distinct states). With rule F off every configuration passed, with
one and two node failures and partial restarts: within the model G1-G3
hold without rule F, the node-failure file keeping a failed replica's
COMMITs out of the count rule. Findings 1, 3 and 4 (one failure) and the
need for the DI-2 rule were confirmed with the traces described below.
Four results differed from the hand traces, none of them a new finding:

- `MC_rulef`, `MC_late_drop` and `MC_no_drop_complete` stopped at finding 1,
  which breaks `CompleteExcludesAbort` as well as `VisibleStays`: n2 has
  t2's COMPLETE, n1 the takeover's ABORT. `TakeoverFCommitted` now
  separates the takeover's rule F; these configurations take the
  candidate fix or leave out the invariants finding 1 breaks.
- `MC_rulef_twofail` stopped at `AbortStays`, which was too strict. t1's
  rule-F abort released row a on n1 (no COMMIT there yet, so no ABORT
  record), t2 took the lock there, n1 failed, and the count rule committed
  t1 from its COMMITs on n2 and n3. t2 could not commit, as n2 still held
  t1's lock. `AbortStays` counted any lock taken after the abort; it now
  counts a writer that survives (`learnedBy`). Plan §5.6 says a rule-F
  abort can be learned "only once every live replica persisted its ABORT":
  each replica releases its lock after its own ABORT, so a reader can see
  the row without T before that. This is harmless while no write of T was
  visible; a writer needs the lock on every live replica.

### Second run (2026-11-24)

Every configuration gave the expected result but `MC_rulef_twofail`, which
found finding 2 by a shorter trace than the hand one (`G2Whole`, below).
`MC_x4_twofail_partial` passed in 57 s: with rule F off no error, also with
two node failures and partial restarts. `MC_twofail_lqh` confirmed finding
4 with two failures and no late signal, and `MC_no_drop_complete` that
X4.9's drop is needed while the takeover can abort a transaction whose
operations all report Committed.

### The expected violations

1. **Rule F in the takeover aborts a visible transaction.** t2's TC is on
   n2, the backup of a. The linear COMPLETE reaches n2 first: n2 writes
   its COMPLETE and makes the row visible (a committed read of a
   READ_BACKUP table can see it), then fails before its COMPLETE to n1
   leaves. The takeover gets "Committed" from n1 and nothing else:
   t2's only operation is reported, and its other replica is on the failed
   node, so `takeOverCompleteSent()` says no COMPLETE was sent, and rule F
   aborts t2. With rule F off the takeover completes it. This matters for
   X5, which is to turn rule F on. Confirmed (`MC_rulef_visible`); it
   breaks `CompleteExcludesAbort` too. Candidate fix
   (`TakeoverFCommitted = FALSE`): the takeover aborts by rule F only when
   an operation reports Prepared (CS_FAIL_COMMITTING), where no COMPLETE
   can have been sent, as TC sends the first COMPLETE after every live
   replica's COMMITTED. When every operation reports Committed it
   completes, as without rule F, and needs no `takeOverCompleteSent()`.
2. **A takeover completes a transaction that a rule-F abort had begun.**
   n2 fails while t1 is in its commit phase; its TC on n3 starts the rule-F
   abort, and n1 writes its ABORT and frees the operation. Then n3 fails.
   The takeover finds only b on n4, Committed: fewer operations reported
   than the opCount, which `takeOverCompleteSent()` reads as a COMPLETE
   sent, so it completes t1 and acknowledges it. The restart finds "T
   complete" on n4 and the ABORT on n1, and applies t1 to b and not to a.
   An operation freed by an abort looks the same to the takeover as one
   freed at COMPLETE. The candidate fix of finding 1 does not help, as the
   takeover sees only Committed operations. Confirmed by a shorter trace:
   n2 fails while t1's COMMITs are on their way; TC on n3 starts the rule-F
   abort, and n1, which has no COMMIT yet, frees its Prepared operation and
   writes nothing. n3 fails; its COMMIT to n4 runs before LQH_TRANSREQ, so
   the takeover finds only b, Committed, completes t1 and acknowledges it.
   t1 is applied to b and not to a while the cluster runs, not only after a
   restart. No log holds the abort, so `G2Whole` finds it, not
   `CompleteExcludesAbort`; `takeOverCompleteSent()` also says "complete"
   (one operation reported of two).
3. **A dirty write is on one replica only.** The primary persists the
   dirty write with its `CPF_SELF` COMPLETE and commits it before the
   backup gets it. A crash in between leaves it on the primary, where
   step A applies it, and not on the backup. Q-B1's other variant, dirty
   writes turned into normal writes in durable mode, does not have this.
   Confirmed.
4. **A COMMIT after LQH_TRANSREQ.** The takeover may see every operation
   Prepared and send a plain ABORTREQ to one that a COMMIT made Committed
   after it answered LQH_TRANSREQ: `abortStateHandlerLab` stops the node
   on `ndbrequire(abortState == NEW_FROM_TC)`. With one node failure this
   needs a COMMIT from the failed node that runs after LQH_TRANSREQ
   (`MC_late_tc`), which NDB's signal order may exclude (DI-7). With two
   it does not: the TC's node fails, the backup commits and sends COMMIT
   to the primary, the primary answers LQH_TRANSREQ as Prepared, the
   backup fails before it answers, and the COMMIT arrives. The code is as
   before durable commits, so upstream has the same race; the two-failure
   configurations leave `NoLqhCrash` out so that it does not hide the
   rest. Confirmed with one failure (`MC_late_tc`) and with two
   (`MC_twofail_lqh`).

### A choice the model makes for X5

Step B's DI-2 rule counts a COMPLETE or ABORT of T only after a tail
COMMIT of T in the same part. The model counts an invalidated COMMIT
(`RF_INVALIDATED` by an earlier run of step C) there too, so that a
restart that runs again keeps its "T aborted" hits (`Repeatable`). Without
rule F there are no ABORTs after a COMMIT and no "T aborted" hits, and a
COMPLETE of T never sits in a part whose COMMITs of T were invalidated, so
the choice no longer matters for X5.4.

## Not in the model

Node restarts and `AC_NR_COPY`; several operations of a transaction on one
row; queued REDO writes; unique indexes and triggers; schema changes in
the tail; GCIs, phase 1, G' and phase 3 (every modelled transaction is in
the tail); the exchange's signals and their order (phase 2 is one function
of the logs); a takeover TC that fails; unsafe shutdowns; one node group,
where a stale node's only witness can be absent (plan §5.5); transid reuse
other than t0's records before the tail.
