# RONDB-732 Phase 1 — status

> Continuation note: the Claude auto-memory dir
> (`~/.claude/projects/.../memory`) is **local to one machine and is not in
> git**. Everything needed to continue is in this file, `plan.md`, and the
> commit messages on branch `RONDB-732`. On another computer: pull
> `RONDB-732` and start here.

## Start hang at M=2 — RESOLVED (2026-08-19)

The M=2 start hang (node reached start phase 2, no progress, death by
heartbeat) **no longer reproduces** after the readiness-based fiber
scheduling + sleep-gate rework (commit `9f96fac0820`). Verified via the new
MTR test:

```
cd mysql-test && ./mtr --suite=ndb ndb_fibers   # PASSES
```

Evidence from the passing run
(`debug_build/mysql-test/var/mysql_cluster.1/ndbd.{1,2}/ndbd.log`):

- Both nodes log `NDBMT: RONDB_FIBERS_PER_THREAD=2 (env override)` and both
  fibers print `RONDB732 DBG first loop reached` within ~70 ms of boot.
- Per-second sibling reports show **both fibers executing continuously and
  near-balanced** (e.g. node 1 final sample: fiber 0 `sigs=37919`, fiber 1
  `sigs=37354`, both advancing every sample).
- Zero `FULLJB-WAIT` lines; `fulljb[enter=0 wait=0]` throughout.

What actually fixed it was never pinpointed to one line — the fix landed as
the 9f96fac rework bundle (readiness-based switching, base-fiber-only sleep
gate guarded by `check_all_fiber_queues_empty()`, sibling start/drain in the
base fiber, fiber-aware thread accounting in Configuration/thrman/proxies).

## MTR reproduction / regression test (in tree)

`mysql-test/suite/ndb/t/ndb_fibers.{test,cnf}` + `r/ndb_fibers.result`:

- `.cnf` packs 2 logical LDM workers onto 1 OS LDM thread per node
  (`ThreadConfig ldm={count=2}` + `RONDB_FIBERS_PER_THREAD=2` via `[ENV]`,
  which MTR exports before spawning ndbmtd; restored after the test).
- `.test` asserts the env override reached both node logs (assert_grep),
  then runs PK-read / index-read / range-scan / update / delete DML.
- Fibers are still env-var-only (`Configuration.cpp` ~1896); there is no
  config.ini parameter yet.

## Congestion path — fix IMPLEMENTED and VERIFIED (Step 1 CLOSED 2026-08-20)

**Final verification run**: `ndb.ndb_fibers_jb_squeeze` (fiber-only view
squeeze 18, armed post-start) PASSED in 4.4 s with, per fiber,
`fulljb[enter=144-190]`, `yready>0` on 3 of 4 fibers, `wait=3-16` — every
wait a bounded <=1 ms cond_wait taken only with no runnable sibling
(FULLJB-WAIT markers show fiber 1, non-base, waiting on remote thr_no=2:
the exact scenario once feared as the start-hang suspect, now routine) —
and **zero** `sleeploop 10!!` on both nodes. `ysib=0` is expected: LDM
fibers essentially never send to each other in this workload; the branch
is code-verified only and would need a synthetic LDM→LDM load to fire.
Supporting evidence from the failed global-squeeze runs: the ladder also
survived two multi-minute sessions of PERMANENT congestion
(enter=4.7k/wait=38k) with no scheduler hang.

## Original fix notes (2026-08-19)

The `handle_full_job_buffers` fiber hazard (a fiber cond_waiting on a
foreign `m_congestion_waiter` parks the whole OS thread; worst case the
congested target is a *sibling fiber* whose only CPU is the one being
parked) is now fixed by a decision ladder in `handle_full_job_buffers`
(`mt.cpp`, gated on `m_num_fibers > 1`, fibers-off path untouched):

1. Congested target is a sibling fiber → `fiber_yield_to()` it (the
   consumer of the FULL queue runs and drains it directly).
2. Otherwise a runnable sibling exists → yield to it (overlap the wait).
3. Otherwise → the original bounded 1 ms cond_wait (legit for any fiber).

Companion change: the sleeploop-10 escape is now also time-bounded
(10 ms elapsed) in fiber mode, since fast fiber switches would otherwise
never advance the wait counter. New dbg counters `ysib`/`yready` in the
1/s report prove the ladder branches run. Full design rationale:
`congestion_plan.md` §1.4. **Not yet verified under load** — see next steps.

Stress test in tree: `ndb.ndb_fibers_large_txn` (M=2 cnf + the
large-transaction section of `ndb.large_txn` inlined, since that test is
have_nodebug-gated and would skip on debug builds). Note
`ndb.large_txn_non_mt` cannot run with M=2 (ldm=1 not divisible — config
validation error by design).

## TRIAGE UPDATE (2026-08-20, later) — collapse is (mostly) NOT fiber-specific

The no-fiber control `ndb_large_txn_2ldm` was ALSO very slow and then
**crashed node 1**: `Dbtc::checkGcpFinished()` `ndbabort()` (DbtcMain.cpp
~9348) — TC's GCP-stall watchdog, which kills the node when a GCP epoch
waits more than a **hardcoded 60 s** for its transactions to complete.
Preserved logs: `var/log/ndb.ndb_large_txn_2ldm/`. Conclusions:

- The 500k-op transaction load is **incompatible with debug builds**,
  fibers or not — completion phases stall GCP past the 60 s abort. This is
  evidently why upstream `ndb.large_txn` is have_nodebug-gated; porting the
  load past that gate was the mistake. Both stress tests are now sized to
  **50k ops** with a comment documenting the 60 s constraint.
- The post-rollback crawl seen in the fiber run is therefore probably the
  same debug-build giant-txn pathology (upstream test header even lists
  "handling of many locks not scaling well" as a provoked issue), possibly
  worsened by fibers — the 50k-sized A/B pair (`ndb_large_txn_2ldm` vs
  `ndb_fibers_large_txn`) now measures exactly that delta.
- Confounder to control for: a **parallel mtr run from another tree
  (rondb_1056, var/3 + var/4 workers) was live on this machine** during the
  control run — several debug clusters competing for CPU inflate all
  timings and can themselves push a slow phase past the 60 s GCP abort.
  Rerun benchmarks/tests without other mtr runs active.
- Branch-code audit for the non-fiber control path: with the env override
  unset, the RONDB-732 changes are behavior-neutral (fiber ladder gated on
  m_num_fibers>1; thread-accounting math degenerates to identity at M=1;
  do_send wrapper is timing-only) — so the crash is with high confidence a
  pre-existing debug-build pathology, not a branch regression.

## PREVIOUS ANALYSIS (2026-08-20, earlier) — post-rollback throughput collapse at M=2

Observed on the **pre-congestion-fix** binaries running
`ndb.ndb_fibers_large_txn` (user aborted after ~7 min; logs preserved in
`var/log/ndb.ndb_fibers_large_txn/`):

- **Not the congestion path**: `fulljb[enter=0 wait=0]` throughout, zero
  FULLJB-WAIT, zero `sleeploop 10!!`. The congestion fix is orthogonal.
- The first `do_insert(500000)` ran at **~41k signals/s** and finished in
  ~30 s. From the **rollback** onwards, throughput collapsed ~25× to
  **1-3k signals/s and never recovered** — the subsequent
  count(*) (correct, 0) and the second do_insert crawled. Both nodes
  identical. So: crawl, not hang; results stay correct.
- During the crawl fiber 0 samples `wd=6` ("Performing Send") in ~90 % of
  the 1/s reports, runs only **~12 main-loop iterations/s** (~67 signals
  per iteration, ~80 ms per iteration), and evidently rarely sleeps.
  Caveat: wd is last-set, and the fiber spin path doesn't set wd, so wd=6
  may be *stale* from a do_send — the thread could be spin/switch-looping.
- **Ruled out**: thrman adaptive send delay — `MaxSendDelay` defaults to 0
  (not set in MTR cnf) so `handle_send_delay()` always writes
  min_send_delay=0; `extend_send_delay` no-ops when g_min_send_delay==0.
- Open suspects: (a) do_send/assist-send churn in the fiber loop (the
  fiber spin path calls `do_send(true,true)` every 16 spin checks; the
  sleep gate may rarely be reached), (b) fiber-distorted load inputs to
  send/sleep decisions (Stage 1 accounting duplicates fiber 0's numbers
  to both slots; also `thrman handle_send_delay` skips nodes with
  `m_num_threads < 6` — fiber inflation lifts this config to exactly 6),
  (c) the slow party being TC/API rather than LDM (LDM report only covers
  LDM fibers; ~80 ms bursts could be demand-side).

Instrumentation added for the next run (in the DBG report line):
`dosend[n=<calls> ms=<total ms inside do_send>] sleeps=<real m_waiter
waits> spins=<fiber spin-loop entries>` — this splits iteration time into
send vs spin vs sleep and directly discriminates (a)/(b)/(c). do_send is
now wrapped (`do_send_impl`) under RONDB732_FIBER_DEBUG for the timing.

Control test added: `ndb.ndb_large_txn_2ldm` — identical config/load with
**fibers off** (2 real LDM OS threads). If it also collapses post-rollback,
the issue is not fiber-specific.

## Next steps

> Detailed roadmap and the full Step 1 plan are in **`congestion_plan.md`**;
> the list below is the summary. The 500k throughput-collapse scare is
> resolved (debug giant-txn pathology, not fibers — see triage above).

0. **A/B at 50k — DONE (2026-08-20), both PASS**:
   `ndb_fibers_large_txn` 10.7 s vs `ndb_large_txn_2ldm` 8.3 s (mtr TIME,
   includes cluster restart). M=2 on ONE LDM OS thread within ~29 % of two
   real LDM threads on this load — no crawl, no GCP abort. Confirms the
   500k collapse/crash was the debug giant-txn pathology, not fibers.
   Note: `do_insert(50000)` inserts in 32-row batches ⇒ **50016** rows;
   the result baselines carry 50016 (user-corrected).
1. **Exercise + verify the congestion ladder** (user runs):
   1a. `ndb_fibers_congestion` — recv-heavy shape (`main=0,rep=0,tc on
   recv`, ldm=2 fibers on 1 OS thread) + 50k load: **RAN 2026-08-20,
   PASSED (13.8 s)** — and that never-before-booted shape boots fine
   (wider-stability point). But STILL `fulljb[enter=0]` on all fibers:
   one producer thread cannot outrun 2 LDM workers, period. Bonus data
   from the new counters: ~1.3M do_send calls totalling only 130-207 ms
   (~100 ns/call — send is not a bottleneck; retroactively weakens the
   wd=6 reading of the 500k crawl), fiber 0 sleeps=30k/spins=41k, fiber 1
   sleeps=0/spins=0 (correct: only the base fiber sleeps), fibers
   perfectly balanced.
   1b. **NEW deterministic vehicle — `ndb_fibers_jb_squeeze`** (in tree):
   same test + `RONDB732_TEST_JB_SQUEEZE` env hook. The hook (debug
   macro only) makes `calc_fifo_free()` (mt.cpp) subtract N fake in-use
   JB pages so FULL/congestion fires under this light load. First run at
   N=12 passed but STILL `fulljb[enter=0]` — FULL needed ~7 real in-flight
   pages and the lock-step load never queues that. Second run at **N=16**
   (the cap, applied from boot): cluster start FAILED (start-protocol
   timeout → node failure, error 2308) — **but the boot-stall logs are the
   first at-scale proof of the ladder**: node 1 fiber 0
   `fulljb[enter=4251 wait=34918 yready=46]`, fiber 1
   `[enter=1246 wait=5106 yready=588]`, both fibers still executing
   (~1.18M sigs) and fiber 0 still reaching real sleeps (11.8k) under
   PERMANENT congestion — no deadlock, no scheduler hang, bounded 1 ms
   waits throughout. `ysib=0` as predicted (LDM→LDM traffic is rare; that
   branch needs a targeted trigger if we ever want it exercised).
   Fix applied: the squeeze is now parsed into `g_dbg_jb_squeeze_target`
   and **armed only at `SL_STARTED`** (checked in `fiber_dbg_report()`),
   so boot runs unsqueezed; the rep_init log line says "armed" and the
   activation line "active" appears post-start (test asserts the "armed"
   line). Test load cut to 20k ops (exactly 20000 rows — divisible by
   32). Third run (armed post-start, still global): boot passed, ladder
   ran hot for 2.5 min (enter=4730/wait=37811/yready=576, fibers healthy
   throughout) — then **QMGR starved**: the global squeeze zeroed the
   recv thread's own execution quota (its out-queues toward the fibers
   read FULL), heartbeats missed ~120 s, node death via "thread 2 stuck
   in: Handling node stop" watchdog. Fix: the squeeze is now
   **fiber-only** — `calc_fifo_free()` (moved below thr_data) applies it
   only when the calling thread's TLS thr_data has `m_num_fibers > 1`,
   so only fibers throttle and ladder; recv/tc/QMGR run unsqueezed. The
   waiting fiber's wait predicate evaluates on its own OS thread with the
   same TLS, keeping producer view and predicate consistent.
   Fourth run (fiber-only, S=16): **PASSED (4.4 s) but enter=0 again** —
   with consumers unsqueezed the real queues drain instantly, so the 3
   in-flight pages S=16 requires never accumulate; the squeeze only
   changes the fibers' *view*, it cannot create real backlog. Escalated
   to **S=18** (FULL from ONE real in-flight page; cap raised 16→18 in
   `dbg_init_jb_squeeze`). S>=19 is degenerate: even empty queues read
   FULL and `has_full_in_queues()` short-circuits
   `handle_full_job_buffers()` before the ladder (reserved-quota trickle
   only) — so 18 is the end of this road: if enter is STILL 0 at 18, the
   view-squeeze approach cannot exercise the ladder and the fallback is a
   consumer-slowdown hook (delay the recv thread's consumption of fiber
   output so real pages accumulate). **Requires rebuild** (mt.cpp only). Env parsed by the static
   `dbg_init_jb_squeeze()` called from `rep_init()` — everything stays
   inside mt.cpp because unit-test binaries link libndbkernel
   (Configuration.cpp) without mt.cpp, so no cross-library mt_ symbol is
   allowed for this (first attempt broke the *-t links). Capped at
   SIZE/2, logs "RONDB732 TEST: jb squeeze active" (the test asserts that
   line, so it cannot silently no-op; retire the test when the debug
   macro goes to 0). **Requires rebuild.** Run:
   `./mtr --suite=ndb ndb_fibers_jb_squeeze`, then read
   `fulljb[enter/wait/ysib/yready]` in ndbd.log. Verified = pass +
   `enter>0` + `ysib`/`yready` advancing + no LDM `sleeploop 10!!` storm.
2. **Wider stability**: run bigger slices of the ndb suite with fibers on:
   `RONDB_FIBERS_PER_THREAD=2 ./mtr --suite=ndb ...`. Caveat: tests whose
   ThreadConfig LDM count is odd (e.g. `large_txn_non_mt`, ldm=1) fail
   config validation by design. Include node-restart/system-restart tests —
   the start hang lived in start phases; recovery paths are untested.
3. **Phase 1 measurement** (plan §7): single-LDM benchmark M=1 vs M=2 with
   only the boundary yield (no intra-signal yields) — quantify pure switch
   overhead. Set `RONDB732_FIBER_DEBUG` to `0` (mt.cpp ~1370) before
   benchmarking to remove counter/log overhead.
4. **M=4**: repeat the MTR smoke with `ldm={count=4}` + fibers=4 (and/or a
   second cnf) once M=2 stability is trusted.
5. Then **Phase 2**: `PREFETCH_AND_YIELD` at the DBACC bucket-head load,
   Rondis PK-read bench, pass criterion ≥10 % at M=2 (plan §7).

## Debug instrumentation (in tree, behind a macro)

`mt.cpp` start-hang instrumentation gated by `#define RONDB732_FIBER_DEBUG 1`
(just before `struct thr_data`, ~line 1370). Set to `0` for zero cost.
Per-fiber `Uint64` counters on `thr_data` (`m_dbg_loops`,
`m_dbg_exec_signals`, `m_dbg_fiber_yields`, `m_dbg_fulljb_enter`,
`m_dbg_fulljb_wait`, `m_dbg_first_loop_done`, `m_dbg_last_report`),
incremented at: `mt_fiber_main` loop top, `execute_signals` per-signal,
`fiber_yield`, and `handle_full_job_buffers` (enter + before the congestion
cond_wait).

Log lines in the node out-log (MTR: `var/mysql_cluster.1/ndbd.N/ndbd.log`):

1. `RONDB732 DBG first loop reached: ... fiber_id=N` — once per fiber on
   first main-loop iteration. Missing ⇒ that fiber never scheduled.
2. `RONDB732 DBG thr_no=.. fiber=.. wd=.. loops=.. sigs=.. yields=..
   fulljb[enter=.. wait=..]` — fiber 0 dumps every sibling ~once/second.
   Frozen `loops`/`sigs` across samples ⇒ starved.
   `wd=4294967295` = `WD_FIBER_SUSPENDED` (parked at sample time; normal
   for an idle sibling).
3. `RONDB732 FULLJB-WAIT ...` — a fiber takes the bounded 1 ms congestion
   cond_wait (first 50 times per fiber). Post-fix this is legitimate: it
   only fires when the congested target is remote AND no sibling can run.
   Fiber-relevant congestion activity shows up instead as `ysib`/`yready`
   in the per-second report line.

## Historical: ruled out during the hang investigation

- **Producer-side wakeup target was correct all along.** `thr_init_fiber`
  (`mt.cpp` ~9990) points every fiber's `m_waiter_ptr` at the base fiber's
  `m_waiter`; all wakeup sites use `dstptr->m_waiter_ptr`.
- **Stage 1 perf-timer accounting** (fiber-0-only recording) — pure
  accounting, no control flow.
- **Main-sleep lost-wakeup race** — real bug, fixed in `fe26c82488c`
  (base fiber sleeps only when `check_all_fiber_queues_empty()`), but was
  not the cause of the hang.

## Key code locations (`storage/ndb/src/kernel/vm/mt.cpp`)

- `mt_job_thread_main` (drives fiber 0 + sibling cleanup): ~8470
- `mt_fiber_main` loop + sleep decision: ~8540; base-fiber sleep predicate: ~8616
- Readiness switching: `fiber_yield_to` / `fiber_yield_if_ready` /
  `fiber_yield_if_pending_work`; forced switch every
  `FIBER_SIGNAL_FORCE_SWITCH_INTERVAL` (16) signals
- `fiber_yield`: ~6855
- `check_queues_empty`: ~6700; `fiber_has_pending_work` /
  `check_all_fiber_queues_empty`: ~6712
- `handle_full_job_buffers` congestion `yield()`: ~8335  ← latent hazard
- Fiber init / `m_waiter_ptr` / thr_no layout: `thr_init_fiber` ~9990;
  `is_ldm_thread` ~1135
- Env override: `Configuration.cpp` ~1896 (`RONDB_FIBERS_PER_THREAD`)
- Perf-timer report redirect: `mt_getPerformanceTimers` ~9110
