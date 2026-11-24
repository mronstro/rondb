# RONDB-1150 X3.4: the TLA+ model of durable commits

`DurableCommits.tla` models the commit path as X4 built it and the cluster
restart's phase 2 as X5 plans it, and checks the guarantees G1-G3 of the
plan (`../durable_commits_plan.md` §1) for a crash of every data node in
any reachable state. It was written before X5 is coded, to check rule F,
the takeover's "was a COMPLETE sent?" (DI-7), dirty writes (DI-1) and the
DI-2 rule of step B (`../impl_next_steps.md` §13).

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
| `Phase2` | step A (hash table, COMPLETE executes the queue, `CPF_SELF` its own COMMIT, ABORT takes the queue out), step B (hits, with the DI-2 rule), step C (verdicts with the count rule) | plan §5.2, X5.3-X5.5 |
| `SRStarts` | the starting nodes; stale ones (recorded by a starting node) take no part; at least one non-stale node per node group | plan §5.4-5.5, X6.3-X6.4 |

Every REDO record is persistent when it is written: the barriers of C, K
and F come before the signal that depends on the record, so a record
written and not persisted is the same as one not written. Each invariant
is checked in every state, as the logs a crash would leave.

Constants that switch parts on and off: `RuleF`, `DropLateComplete`,
`LateFromFailedTc` (a signal received from a failed node may run after
LQH_TRANSREQ; without it, it runs before or is lost), `DI2Rule`,
`PartialSR`, `MaxFailures`, `Dirty`.

## Invariants

| Invariant | Checks |
|---|---|
| `G1` | an acknowledged transaction survives |
| `G2Whole` | a surviving transaction is on every starting replica of each of its rows |
| `G3Same` | the starting replicas of a row are identical |
| `RowOrder` | each row has the surviving writes in the order of its locks (plan §6) |
| `AbortStays` | a transaction the API was told aborted, or whose abort a later writer of its row could see, does not survive (plan §5.6) |
| `VisibleStays` | a transaction that was visible on any replica survives (plan §5.6) |
| `NextSR` | the next restart, replaying the old tail's COMMITs that step C left valid, gets the same rows (plan §5.6) |
| `Repeatable` | a restart that crashes in step C with any of its invalidations done, and runs again, gets the same result (plan §5.6) |
| `NoSharedRowInDoubt` | in-doubt transactions committed in step C share no row in a part (X5.5) |
| `CompleteExcludesAbort` | no transaction has both a COMPLETE and a rule-F ABORT (plan §5.6) |
| `CommitBeforeComplete` | no COMMIT of T follows a COMPLETE of T in a log part |
| `NoLqhCrash` | no ndbrequire of DBLQH fails |

## Configurations and expected results

The expected results come from traces worked out by hand while the model
was written; TLC has not run yet. A violation where none is expected is a
finding, and so is a run that finds none where one is expected.

| Configuration | Settings | Expected |
|---|---|---|
| `MC_x4` | rule F off (as X4 is committed), full restart | no error |
| `MC_x4_partial` | rule F off, partial restarts too (X6) | no error |
| `MC_x4_twofail` | rule F off, 2 node failures, all but `NoLqhCrash` | no error |
| `MC_rulef` | rule F on (X5's default), all but `VisibleStays` | no error |
| `MC_repeatable` | rule F on, `Repeatable` only (slower) | no error |
| `MC_late_drop` | rule F on, late signals from a failed node, X4.9's drop | no error |
| `MC_rulef_visible` | rule F on, `VisibleStays` only | violated: finding 1 |
| `MC_rulef_twofail` | rule F on, 2 node failures, all but `NoLqhCrash` | `CompleteExcludesAbort` violated: finding 2 |
| `MC_dirty` | a dirty write | `G2Whole` violated: finding 3 |
| `MC_late_tc` | late signals from a failed node | `NoLqhCrash` violated: finding 4 |
| `MC_no_drop_complete` | as `MC_late_drop` without the drop | `AbortStays` violated: the drop of X4.9 is needed |
| `MC_no_di2` | without the DI-2 rule | `G2Whole` violated: the DI-2 rule is needed |

### The expected violations

1. **Rule F in the takeover aborts a visible transaction.** t2's TC is on
   n2, the backup of a. The linear COMPLETE reaches n2 first: n2 writes
   its COMPLETE and makes the row visible (a committed read of a
   READ_BACKUP table can see it), then fails before its COMPLETE to n1
   leaves. The takeover gets "Committed" from n1 and nothing else:
   t2's only operation is reported, and its other replica is on the failed
   node, so `takeOverCompleteSent()` says no COMPLETE was sent, and rule F
   aborts t2. With rule F off the takeover completes it. This matters for
   X5, which is to turn rule F on.
2. **A takeover completes a transaction that a rule-F abort had begun.**
   n2 fails while t1 is in its commit phase; its TC on n3 starts the rule-F
   abort, and n1 writes its ABORT and frees the operation. Then n3 fails.
   The takeover finds only b on n4, Committed: fewer operations reported
   than the opCount, which `takeOverCompleteSent()` reads as a COMPLETE
   sent, so it completes t1 and acknowledges it. The restart finds "T
   complete" on n4 and the ABORT on n1, and applies t1 to b and not to a.
   An operation freed by an abort looks the same to the takeover as one
   freed at COMPLETE.
3. **A dirty write is on one replica only.** The primary persists the
   dirty write with its `CPF_SELF` COMPLETE and commits it before the
   backup gets it. A crash in between leaves it on the primary, where
   step A applies it, and not on the backup. Q-B1's other variant, dirty
   writes turned into normal writes in durable mode, does not have this.
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
   rest.

### A choice the model makes for X5

Step B's DI-2 rule counts a COMPLETE or ABORT of T only after a tail
COMMIT of T in the same part. The model counts an invalidated COMMIT
(`RF_INVALIDATED` by an earlier run of step C) there too, so that a
restart that runs again keeps its "T aborted" hits (`Repeatable`). X5.4
should do the same.

## Not in the model

Node restarts and `AC_NR_COPY`; several operations of a transaction on one
row; queued REDO writes; unique indexes and triggers; schema changes in
the tail; GCIs, phase 1, G' and phase 3 (every modelled transaction is in
the tail); the exchange's signals and their order (phase 2 is one function
of the logs); a takeover TC that fails; unsafe shutdowns; one node group,
where a stale node's only witness can be absent (plan §5.5); transid reuse
other than t0's records before the tail.
