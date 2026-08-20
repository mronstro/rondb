# RONDB-732 — Post-boot roadmap + Step 1 detailed plan (congestion path)

Status context: Phase 1 boot is stable (see `phase1_status.md`), verified by
the passing `ndb.ndb_fibers` MTR test. This document plans the remaining
Phase 1 work and details Step 1.

## Roadmap (order of work)

| Step | What | Gate to next step |
|---|---|---|
| **1** | **Exercise + fix the job-buffer congestion path under fibers** (`handle_full_job_buffers`). Stress test first, then the fiber-aware fix. Detailed below. | Congestion stress test passes at M=2 with no `sleeploop 10!!` spam and no non-base fiber parking the OS thread while a sibling is runnable. |
| **2** | **Wider stability**: `RONDB_FIBERS_PER_THREAD=2 ./mtr --suite=ndb` slices, prioritizing node-restart / system-restart / LCP tests (recovery paths untested; the boot hang lived in start phases). Known-by-design failures: tests whose ThreadConfig LDM count is not divisible by 2 (e.g. `large_txn_non_mt`, ldm=1) fail config validation. | No fiber-attributable failures in the chosen slices. |
| **3** | **Phase 1 measurement** (plan.md §7): single-LDM benchmark, M=1 vs M=2, boundary yield only — quantify pure switch overhead. Set `RONDB732_FIBER_DEBUG` to `0` (mt.cpp ~1370) first: the per-signal counters and 1/s reports are cheap but not free, and must not pollute the numbers. | Overhead within expectation (noise on CPU-bound, ≤5 % on memory-bound). |
| **4** | **M=4 smoke**: second cnf (`ldm={count=4}` + `RONDB_FIBERS_PER_THREAD=4` → still 1 OS thread), rerun steps 1–2 selectively. | M=4 boots and passes the same tests. |
| → | **Phase 2** (plan.md §7): `PREFETCH_AND_YIELD` at the DBACC bucket-head load; Rondis PK-read bench; pass criterion ≥10 % at M=2. | — |

Steps 2 and 4 are mostly test-running (user-driven); Step 1 and 3 have real
engineering content. Step 1 must precede Step 3: the congestion fix changes
scheduler behavior under load, and benchmarking before it would measure a
code path we know we are about to change.

---

# Step 1 — detailed plan: congestion path under fibers

> **STEP 1 COMPLETE (2026-08-20).** The ladder is implemented and verified:
> `ndb.ndb_fibers_jb_squeeze` (fiber-only JB view-squeeze 18, armed at
> SL_STARTED) passes with enter=144-190/fiber, yready>0, bounded waits
> only, zero sleeploop — see phase1_status.md for the full verification
> record and the three failure modes found on the way (500k GCP abort,
> from-boot squeeze start stall, global-squeeze QMGR starvation). ysib=0
> remains unexercised (LDM→LDM traffic absent in the workload) — accepted.
> Next: roadmap Step 2 (wider stability), Step 3 (Phase 1 measurement with
> RONDB732_FIBER_DEBUG set to 0).

## 1.1 The mechanism today (all code in `mt.cpp`)

Producer-side congestion control: each block thread computes a per-job-buffer
signal quota. When a target thread's in-queue toward us is FULL, the quota
`m_max_signals_per_jb` drops to 0 and the main loop calls
`handle_full_job_buffers()` (~8490, called from `mt_job_thread_main` ~8955
and from the recv-thread loop ~8417). Inside its while-loop it:

1. Picks a congested target via `get_congested_job_queue()` (~5166, from
   `m_congested_threads_mask`).
2. Escapes for self-congestion (`congested == selfptr`) and for
   `has_full_in_queues()` (must drain own in-queues with reserved quota).
3. Otherwise `do_send(...)` then a **timed** wait:
   `yield(&congested->m_congestion_waiter, 1ms, check_full_job_queue, q)`
   — a real `pthread_cond_wait` with **1 ms timeout**, on the *congested
   thread's* waiter.
4. Wakeup source: the congested thread's `execute_signals()` calls
   `wakeup_all(&selfptr->m_congestion_waiter)` (~7196) whenever it releases
   a consumed job-buffer page.
5. Escape hatch: after `sleeploop >= 10` (≈10 ms of waiting) it logs
   `"sleeploop 10!!"` and returns; the caller recalculates quotas and the
   thread proceeds with a small/reserved quota (solves circular waits).

Because of the 1 ms timeout + sleeploop escape, this is **never a permanent
deadlock** — the hazard under fibers is *bounded livelock*: repeated whole-OS-
thread stalls, missed overlap, and `sleeploop 10!!` spam. This matches the
evidence that the start hang was fixed elsewhere and this path never fired in
the passing smoke run (`fulljb enter=0`).

## 1.2 Why fibers break it — three failure modes

Let F0/F1 be fibers sharing one OS thread; only the OS thread can cond_wait.

- **(a) Congested target is a sibling fiber — the fatal-by-design case.**
  If F1's out-queue toward F0 is FULL, the consumer that must drain it is F0
  — *suspended on the same OS thread*. F1 cond_waiting on
  `F0->m_congestion_waiter` parks the only CPU F0 could run on. Progress
  happens only via the 1 ms timeout, so the queue drains at ~1 signal-batch
  per 1 ms + `sleeploop 10!!` spam. This is the fiber analogue of the
  existing `congested == selfptr` self-wait check, and it is not handled.
- **(b) Non-base fiber waits on a remote target while a sibling is
  runnable.** The whole OS thread parks ≤1 ms on `m_congestion_waiter`
  although a sibling has signals to execute. Also, *new* ordinary work
  routed to any fiber of this OS thread wakes `m_waiter` (via
  `m_waiter_ptr`) — not the foreign congestion waiter — so it cannot
  interrupt the wait. Fibers exist precisely to fill stalls with sibling
  work; this wastes the mechanism.
- **(c) Base fiber has the same problem as (b).** Waiting on the congestion
  waiter while F1 could run is equally wasteful; fiber id doesn't matter.

## 1.3 Sub-step A — stress test that drives the path (write and run FIRST)

Goal: a repeatable MTR test that makes LDM fibers enter
`handle_full_job_buffers` (observable via `fulljb[enter>0]` and
`FULLJB-WAIT` markers, `RONDB732_FIBER_DEBUG` is still on). Run it BEFORE
the fix to characterize the failure, and keep it as the regression test.

**Test vehicle**: the large-transaction load from `ndb.large_txn`, which was
written to provoke exactly this ("Job buffer full due to commit/abort not
limiting number of outstanding signals", plus historical `sleeploop 10!` /
oversleep issues). Do **not** `--source large_txn.test` wholesale:
it is gated `have_nodebug.inc` (skipped on debug builds — our current build
is debug) and its second half (Bug#34189965 unique-lock section) is
prohibitively slow under debug. Inline only the large-transaction section.

**New files** (mirroring `ndb_fibers.*`):

`mysql-test/suite/ndb/t/ndb_fibers_large_txn.cnf`:

```
!include suite/ndb/my.cnf

[cluster_config.1]
# 2 logical LDM workers packed onto 1 OS LDM thread (M=2), as ndb_fibers.cnf
ThreadConfig=main={count=1},tc={count=1},ldm={count=2},io={count=1},rep={count=1},recv={count=1},send={count=1}
# Scale-up for large transactions, copied from large_txn.cnf:
DataMemory = 256M
NoOfReplicas = 1
MaxNoOfConcurrentOperations = 512K
NoOfFragmentLogFiles = 16

[ENV]
RONDB_FIBERS_PER_THREAD= 2
```

`mysql-test/suite/ndb/t/ndb_fibers_large_txn.test` (sketch):

```
--source include/have_ndb.inc
# assert_grep preamble on both ndbd.log files for
#   "NDBMT: RONDB_FIBERS_PER_THREAD=2"  (copy from ndb_fibers.test)

create table t1 (a int primary key) engine=ndb;
create table t2 (a int primary key) engine=ndb;
# do_insert procedure copied from large_txn.test (32-row batched inserts)
begin; call do_insert(500000); rollback;
begin; call do_insert(500000); commit;
begin; insert into t2 select * from t1; rollback;
begin; insert into t2 select * from t1; commit;
begin; delete from t2; commit;
begin; delete from t1; commit;
# cleanup
```

Rationale for the load: the giant commit/rollback floods TC→LQH and
LQH→TC signal chains through the single OS LDM thread's two fiber queues;
`insert into t2 select * from t1` adds an LDM-side scan producing toward TC
while TC produces toward both LDM fibers. Replicas=1 (as in `large_txn.cnf`)
keeps DataMemory fits; two data nodes still give cross-node traffic.

**Run** (user):

```
cd mysql-test && ./mtr --suite=ndb ndb_fibers_large_txn
```

**Observation checklist** (in `var/mysql_cluster.1/ndbd.{1,2}/ndbd.log`):

| Observation | Meaning |
|---|---|
| `RONDB732 FULLJB-WAIT ... fiber_id!=0` lines | Failure modes (a)/(b) reproduced from a fiber — the target case. Note the `congested thr_no` in the line: `thr_no<2` ⇒ sibling target = mode (a). |
| `fulljb[enter>0]` only on `thr_no>=2` (TC/main) | Congestion happened but only non-fiber producers hit it; escalate the load (see below). |
| `sleeploop 10!!` lines | The escape hatch is firing — quantifies the livelock severity; count them for the before/after comparison. |
| Test wall-clock time | Baseline for the after-fix comparison (expect the fix to reduce it). |

**Escalation levers if the fiber path doesn't trigger**: (1) run two
concurrent connections doing `do_insert` into separate tables
(`--send`/`--reap` in mysqltest) to double producer pressure; (2) raise the
row count; (3) `tc={count=2}` for a second TC producer. Apply in that order;
stop at first trigger.

Record the before-fix findings in `phase1_status.md`.

## 1.4 Sub-step B — the fix in `handle_full_job_buffers`

**Principle**: a fiber must never cond_wait while any sibling on its OS
thread can make progress — and if the congested target *is* a sibling,
running that sibling is itself the cure (it is the consumer of the full
queue).

**Decision ladder** replacing the unconditional timed wait, applied only
when `selfptr->m_num_fibers > 1` (all other threads — recv caller at ~8417,
TC/MAIN, LDM with fibers off — keep today's behavior bit-for-bit):

After the existing `do_send(...)` (unchanged — produced signals must reach
remote consumers regardless of which branch we take):

```c
if (selfptr->m_num_fibers > 1) {
  const int cong_fid = fiber_fid_of(selfptr, congested);   // new helper
  if (cong_fid >= 0) {
    /* Mode (a): the consumer of the FULL queue is a sibling fiber on this
     * OS thread. Waiting would park the only CPU it can run on — run it. */
    fiber_yield_to(selfptr, (Uint32)cong_fid);
    recheck_congested_job_buffers(selfptr);
    continue;
  }
  if (fiber_yield_if_ready(selfptr) || fiber_yield_if_pending_work(selfptr)) {
    /* Modes (b)/(c): remote congestion, but a sibling can run — overlap the
     * wait with sibling execution instead of parking the OS thread. */
    recheck_congested_job_buffers(selfptr);
    continue;
  }
  /* No sibling can run: fall through to the bounded 1 ms cond_wait below.
   * Parking the OS thread is now exactly what the base fiber would do; the
   * only loss vs m_waiter is that fresh ordinary work waits ≤1 ms, same as
   * the pre-fiber semantics of this path. Any fiber may take this wait. */
}
/* existing: yield(&congested->m_congestion_waiter, 1ms, ...) */
```

New helper next to the other fiber helpers (~7035):

```c
static inline int
fiber_fid_of(const thr_data *selfptr, const thr_data *other) {
  for (Uint32 fid = 0; fid < selfptr->m_num_fibers; fid++)
    if (selfptr->m_my_fibers[fid] == other) return (int)fid;
  return -1;
}
```

(`m_my_fibers[]` and `m_num_fibers` are populated on *every* fiber slot,
base and non-base — see thr_data comment ~1454 — so this works from any
fiber. M ≤ MAX_NUM_FIBERS, the loop is trivially cheap.)

**Loop-escape rework (required for correctness of the ladder)**: today the
escape is `sleeploop >= 10`, counting only real waits (~1 ms each ⇒ ~10 ms).
Fiber switches are ~10 ns, so ladder iterations that switch instead of wait
would never advance `sleeploop` — the while-loop could spin hot for as long
as the congestion lasts, and conversely counting switches as sleeploop would
fire the escape after microseconds. Fix: time-bound the loop. Take
`const NDB_TICKS enter = NdbTick_getCurrentTicks();` before the loop; at the
loop top treat `NdbTick_Elapsed(enter, now).milliSec() >= 10` identically to
`sleeploop >= 10` (same log + `return true`). Keep `sleeploop` for the wait
branch (whichever bound hits first wins). The 10 ms constant keeps the
existing escape semantics.

**Accounting**: unchanged. `add_buffer_full_nanos_sleep` is only reached in
the cond_wait branch and is already Stage-1 gated (fiber 0 records). Fiber-
switch time in the new branches is sibling *exec* time and must NOT be
recorded as buffer-full sleep — the ladder naturally never brackets it.
(Stage 2's recording token will attribute it properly later; plan.md §7.5.)

**Watchdog**: `fiber_yield_to` already parks the counter at
`WD_FIBER_SUSPENDED`; the cond_wait branch keeps `m_watchdog_counter = 18`.
The `m_watchdog_counter = 16` at function entry stays.

**Debug instrumentation updates** (still behind `RONDB732_FIBER_DEBUG`):

- Reword the `FULLJB-WAIT` marker: post-fix, a non-base fiber taking the
  timed wait is *legitimate* (no runnable sibling). Keep a throttled marker
  only for the should-now-be-impossible case — about to cond_wait when
  `fiber_fid_of(selfptr, congested) >= 0` — as a canary; it firing means the
  ladder regressed.
- New counters on thr_data: `m_dbg_fulljb_yield_sibling` (mode-a switches),
  `m_dbg_fulljb_yield_ready` (mode-b/c switches); add both to the 1/s
  `fiber_dbg_report` line. These prove in Sub-step C that the new branches
  actually ran.

**Explicitly out of scope for this fix**: routing congestion sleeping
through the base `m_waiter` (option (b) from the old status doc). Rejected
because the congestion-release wakeup (`execute_signals` ~7196) targets
`m_congestion_waiter`; rerouting the sleep would need a second wakeup path
or folding congestion state into `check_all_fiber_queues_empty`, a much
bigger change for no additional safety once the ladder guarantees no
runnable sibling exists at wait time.

## 1.5 Sub-step C — verification (user runs, I analyze)

1. Rebuild (debug, `RONDB732_FIBER_DEBUG` still 1).
2. `./mtr --suite=ndb ndb_fibers ndb_fibers_large_txn large_txn` —
   - `ndb_fibers`: must still pass (boot/DML regression).
   - `ndb_fibers_large_txn`: must pass; compare wall-clock vs the before-fix
     baseline; expect **zero** `sleeploop 10!!` from LDM thr_nos and zero
     canary markers; expect `m_dbg_fulljb_yield_sibling`/`_ready` > 0 in the
     dbg reports (proves the new branches were exercised — if both are 0 the
     load regressed and the test needs re-escalation, not a pass stamp).
   - `large_txn` (M=1 path, if the build is non-debug; else skip): guards
     the fibers-off path — code there is untouched by construction
     (`m_num_fibers > 1` gate), so any change is a red flag.
3. Read both nodes' `ndbd.log`: per-fiber `sigs` still advancing and
   near-balanced during the heavy phase; `fulljb[enter>0, wait=N]` with N
   small.
4. Update `phase1_status.md`: hazard section → resolved, with counter
   evidence; then proceed to roadmap Step 2.

## 1.6 Risks / notes

- **Hot ping-pong window**: when a fiber is output-congested toward a
  remote thread and its sibling has pending input work, the ladder switches
  instead of waiting — the pair can ping-pong at full CPU until the remote
  drains (µs–ms scale) or the 10 ms time-bound fires. This is spin-priced
  progress, deliberately chosen over parking the OS thread; the dbg
  counters make it observable if it ever matters.
- **Debug-build timing**: 500 k-row transactions under a debug build are
  slow; if runtime is impractical, halve the row count *after* confirming
  the FULLJB markers still fire (the before/after comparison must use the
  same count).
- **`insert into t2 select * from t1` scan batching** may self-limit
  congestion; the two-connection escalation lever is the reliable fallback.
- The recv-thread caller (~8417) and all non-fiber threads see zero
  behavioral change; the entire fix is inside the `m_num_fibers > 1` gate
  plus the (behavior-preserving) time-bound escape.
