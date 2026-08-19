# RONDB-732 Phase 1 — debug status (start hang at M=2)

> Continuation note: the Claude auto-memory dir
> (`~/.claude/projects/.../memory`) is **local to one machine and is not in
> git**. Everything needed to continue is in this file, `plan.md`, and the
> commit messages on branch `RONDB-732`. On another computer: pull
> `RONDB-732` and start here.

## Symptom (open)

- Config: **1 LDM thread, `theNumberOfFibersPerThread = 2` (M=2)**.
- Node starts, **no crash**, but **start phase 2 makes no progress**;
  eventually the node dies from a **heartbeat error** (heartbeat timeout
  between nodes).
- **M=1 (fibers off) is fine.** The bug is specific to having ≥2 fibers
  cooperatively sharing the LDM OS thread.

## Committed on this branch (newest first)

| Commit | What | Effect on hang |
|---|---|---|
| (this) phase1_status.md | This status doc | docs only |
| (this) lost-wakeup fix | Base fiber sleeps only when **all** fibers' queues are empty (`check_all_fiber_queues_empty`), re-checked inside `yield()` after the sleep-intent barrier. Read-only sibling peek `fiber_has_pending_work` (no `scan_zero_queue` cross-fiber). | Real correctness fix (closes a genuine lost-wakeup race) but **does NOT resolve the start hang** — tested M=2, still hangs. Kept because the race is real. |
| ce85d516 | Stage 1 perf-timer accounting: only fiber 0 records sleep/spin/send/buffer-full. | Pure accounting, cannot affect control flow / the hang. |

## Ruled out (with evidence)

- **Producer-side wakeup target is correct.** `thr_init_fiber`
  (`mt.cpp` ~9990) sets every fiber's `m_waiter_ptr → base fiber's
  m_waiter`. LDM thr_no layout: `is_ldm_thread` (~1135) ⇒ LDM section is
  `thr_no ∈ [0, ndbMtLqhThreadFibers)`, base `= thr_no % ndbMtLqhThreads`,
  siblings strided by `ndbMtLqhThreads`. All wakeup call sites use
  `dstptr->m_waiter_ptr` (9357, 9537, 9696, 9851, 11267). ⇒ **waking any
  fiber wakes the OS thread (fiber 0).**
- **Stage 1 accounting is not the cause.** It only gates counter `+=` on
  `m_fiber_id == 0`; no control-flow effect.
- **Consumer-side main-sleep lost-wakeup is not (the whole) cause.**
  Fixing it (this commit) did not change the symptom.

## Prime suspect — `handle_full_job_buffers` blocks the OS thread

`handle_full_job_buffers` (`mt.cpp` ~8335) is called from the main loop by
**every** fiber, and inside it does:

```c
yield(&congested->m_congestion_waiter, nano_wait_1ms,
      check_full_job_queue, congested_queue);
```

This is a **real `pthread_cond_wait` on a *different* waiter**
(`m_congestion_waiter`), not the OS thread's `m_waiter`. If a **non-base
fiber** reaches this, it blocks the **entire OS thread** parked on
`m_congestion_waiter`. Producers that route work to this OS thread wake
`m_waiter` (via `m_waiter_ptr`) — **not** `m_congestion_waiter` — so the OS
thread is not roused by ordinary work; it only wakes when the congested
peer calls `wakeup_all(&...m_congestion_waiter)` (execute_signals ~6936) on
buffer release. Circular waits across the now-blocked OS thread are
possible. **This is the strongest remaining candidate for the start hang.**

Fix direction (not yet done): non-base fibers must **not** block the OS
thread in a cond_wait. Either (a) make `handle_full_job_buffers` use the
fiber drain/`fiber_yield` path for `m_num_fibers > 1` instead of a raw
`yield()`, or (b) route all OS-thread sleeping through the single base
`m_waiter` and detect congestion as part of the unified sleep condition.

## Other hypotheses (not yet checked)

2. **Does fiber 1 ever run during start?** Fiber 1 first runs only when
   fiber 0 hits the boundary yield (`execute_signals` ~6963, fires when it
   executes ≥1 signal) or the pre-sleep drain. If fiber 0 loops/spins
   during start without either, fiber 1 starves. Add per-fiber "first run"
   + loop/exec counters.
3. **Watchdog / `WD_FIBER_SUSPENDED` sentinel** (see commit e5a8fcbe) might
   be masking a genuine stall — confirm it isn't.
4. **Heartbeat is QMGR on the MAIN thread (not fiberized).** Its timeout
   implies either the node-wide start protocol is stuck waiting on an LDM
   fiber, or main itself is blocked (it shouldn't be). Disambiguate.

## Instrumentation added this session (in tree, behind a macro)

`mt.cpp` now has start-hang instrumentation gated by
`#define RONDB732_FIBER_DEBUG 1` (defined just before `struct thr_data`,
~line 1370). Set it to `0` to remove all of it at zero cost. Per-fiber
`Uint64` counters on `thr_data` (`m_dbg_loops`, `m_dbg_exec_signals`,
`m_dbg_fiber_yields`, `m_dbg_fulljb_enter`, `m_dbg_fulljb_wait`,
`m_dbg_first_loop_done`, `m_dbg_last_report`), incremented at:
`mt_fiber_main` loop top, `execute_signals` per-signal, `fiber_yield`,
and `handle_full_job_buffers` (enter + before the congestion cond_wait).

Three log signals to read in `ndb_<node>_out.log`:

1. **`RONDB732 DBG first loop reached: ... fiber_id=N`** — emitted once per
   fiber on its first main-loop iteration. **If fiber 1 never prints this,
   it was never scheduled** (answers open hypothesis #2). 
2. **`RONDB732 DBG thr_no=.. fiber=.. wd=.. loops=.. sigs=.. yields=..
   fulljb[enter=.. wait=..] [(never-ran)]`** — fiber 0 dumps every sibling
   ~once/second. A sibling with **frozen `loops`/`sigs`** across samples is
   starved; the `wd=` (watchdog code) shows where it is parked
   (`12`/`16`/`18`/`21`/`WD_FIBER_SUSPENDED=4294967295`).
3. **`RONDB732 FULLJB-WAIT ... <== NON-BASE FIBER PARKS OS THREAD ...`** —
   the **smoking gun**. Printed only when a `fiber_id != 0` fiber is about
   to `cond_wait` on a sibling's `m_congestion_waiter` (first 50 times).
   **If the out-log goes silent right after this line, suspect #1 is
   confirmed** — the OS thread is parked on a waiter ordinary work won't
   signal.

Interpretation matrix:

| Observation | Conclusion |
|---|---|
| No `FULLJB-WAIT` line, fiber 1 `loops` frozen, `wd=WD_FIBER_SUSPENDED` | fiber 1 starved — scheduling/dispatch bug, not congestion |
| `FULLJB-WAIT` (fiber!=0) then silence | suspect #1 confirmed: fix `handle_full_job_buffers` for fibers |
| Both fibers' counters keep advancing but start phase 2 still stalls | stall is upstream (block instance routed to a fiber that isn't draining a specific JBB); cross-check hypothesis #4 |

Build (user) with the macro on, reproduce M=2, then read the out-log.

## Next steps to localize the stall (do this first)

1. **Attach lldb to the hung `ndbmtd`; `thread backtrace all`.** Find where
   the LDM OS thread is parked:
   - cond_wait on base `m_waiter` → main-sleep path (already hardened),
   - cond_wait on `m_congestion_waiter` → confirms suspect #1,
   - elsewhere → new lead.
   This single observation is the fastest disambiguator.
2. Read `ndb_<node>_out.log`: last watchdog action, highest start phase
   reached, last active block instance.
3. Temporary `g_eventLogger` prints in `mt_fiber_main` loop entry
   (`thr_no`, `fiber_id`, `sum`) and at each `fiber_yield`/`SwitchFiber`,
   gated to the LDM OS thread, to see the switch pattern during start.
4. Confirm which fiber (`thr_no`) owns the LDM block instances addressed in
   start phase 2 (DBLQH/DBDIH proxies). If start sends to fiber 1's
   instances and fiber 1 is never scheduled, that is the stall.

## Key code locations (`storage/ndb/src/kernel/vm/mt.cpp`)

- `mt_job_thread_main` (drives fiber 0 + sibling cleanup): ~8470
- `mt_fiber_main` loop + sleep decision: ~8540; base-fiber sleep predicate: ~8616
- Boundary fairness yield: `execute_signals` ~6963
- `fiber_yield`: ~6855
- `check_queues_empty`: ~6700; `fiber_has_pending_work` /
  `check_all_fiber_queues_empty`: ~6712
- `handle_full_job_buffers` congestion `yield()`: ~8335  ← suspect
- Fiber init / `m_waiter_ptr` / thr_no layout: `thr_init_fiber` ~9990;
  `is_ldm_thread` ~1135
- Perf-timer report redirect: `mt_getPerformanceTimers` ~9110

## How to reproduce

Build (user handles kernel builds), start a node configured with 1 LDM and
`theNumberOfFibersPerThread = 2`. Observe start stall in phase 2 →
heartbeat timeout. Compare against M=1 (works).
