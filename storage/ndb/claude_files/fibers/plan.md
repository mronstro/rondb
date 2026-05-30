# RonDB Fibers — Prototype Plan (RONDB-732)

## 1. Goal in one sentence

Exploit memory-level parallelism in the data node: at known cold-load points
inside hot signal handlers, prefetch the line we're about to need and yield
to a sibling fiber on the same OS thread while the miss resolves, so DRAM
latency is overlapped instead of stalling the core.

## 2. Execution model — fiber = block thread

After working through alternatives (inner-loop coroutines, stackless C++20
co_await, hand-rolled state machines), the model that actually fits NDB's
signal-dispatch architecture is the one the first stab already chose:

- Each OS LDM thread runs M fibers (start with M = 2; explore M = 4).
- Each fiber is a block-thread to the rest of the kernel — its own
  `thr_data` slot, its own job buffer, its own jam, its own scan/operation
  state. Signal routing addresses fibers as separate thread IDs.
- The OS thread cooperatively multiplexes its fibers. Only the OS thread
  sleeps / wakes / spins (one `m_waiter` per OS thread, shared by all
  fibers via `m_waiter_ptr`).
- Switches happen at two places — see §3.

Why not inner-loop interleaving (revised view): the natural unit of parallelism
in NDB is the signal. Inside a single `execXxxREQ` there is rarely a batch of
K independent probe keys to run in parallel. The cases where there are
(multi-range scan, DBSPJ child probes) are theoretically possible but
require DBTUX re-entrant walks and shared-row-cap arbitration, which is
significant restructuring. Defer to follow-up.

Why not stackless C++20 coroutines: signature contagion up the
`execXxxREQ(Signal*)` chain, heap-allocated coroutine frames per
instantiation (default), style mismatch with the conservative C++17,
no-exceptions, manual-lifetime NDB code base. Cost saving over stackful
(~5–15 ns vs ~10 ns per switch) is small relative to the ~80–300 ns DRAM
miss we're hiding.

## 3. Switch mechanism — counter-gated yield

Two switch sites, governed by a per-`thr_data` counter `m_intra_yields`.

### 3.1 Intra-signal yield at known cold loads

A macro placed just before known cold-load sites:

```c
#define PREFETCH_AND_YIELD(addr, n_lines)                              \
  do {                                                                 \
    for (Uint32 _i = 0; _i < (n_lines); _i++) {                        \
      NDB_PREFETCH_READ((const char*)(addr) + 64u * _i);               \
    }                                                                  \
    selfptr->m_intra_yields++;                                         \
    tiny_fiber::SwitchFiber(selfptr->m_fiber_context[my_fiber],        \
                            selfptr->m_fiber_context[next_fiber]);     \
  } while (0)
```

`n_lines` chosen to cover the structure being loaded (see §4).

### 3.2 Signal-boundary fairness yield

At the dispatch boundary in `execute_signals()` (currently a
`/* SWITCH_FIBER */` comment), before pulling the next signal off the job
buffer:

```c
if (selfptr->m_intra_yields == 0) {
  tiny_fiber::SwitchFiber(selfptr->m_fiber_context[my_fiber],
                          selfptr->m_fiber_context[next_fiber]);
}
selfptr->m_intra_yields = 0;
```

Effect:

- Memory-bound signals yield several times intra-signal, where the misses
  actually are. The signal-boundary yield is suppressed because the thread
  has already been shared.
- CPU-bound signals (no intra yields) take exactly one fairness yield per
  signal at the boundary, so no fiber monopolises the thread.
- A wholly cache-hot run pays one ~33-cycle switch per signal — negligible
  (≤0.5 % at 100k signals/s/thread).

The next-fiber selection is round-robin over the M fibers on this OS
thread, skipping any fiber that's blocked waiting for an external event
(if such a state exists; for the prototype assume all fibers are
runnable).

## 4. Yield sites for the first prototype

Targeted at the cold-load points already known to the developers (most are
already prefetched with no intervening work, i.e. wasted prefetch — we'll
turn them into real overlap).

| # | Site | Location | `n_lines` | Skip condition |
|---|---|---|---:|---|
| 1 | DBACC bucket head load | inside `execACCKEYREQ` PK probe | 2 (bucket ~110–120 B) | none |
| 2 | DBACC → row read (fixed part) | after PK match, before tuple-fixed-part load | 1–2 | none |
| 3 | DBTUX → row read (fixed part) | leaf-entry follow into row | 1–2 | walk path is near tree root |
| 4 | DBTUX T-tree node read during walk | node descent | 4 (`MAX_TTREE_NODE_SIZE = 64 words = 256 B`) | walk path is near tree root |

For #3 and #4, "near root" means the walk has touched fewer than some
constant number of node levels since the search started — top of the tree
is essentially always hot in cache, so yielding there pays switch cost for
no overlap. Start with a depth threshold (e.g. yield only when depth ≥ 2)
and tune.

Productionising adds a "fragment is big enough to matter" guard at each
site (e.g. yield only when the table fragment row count exceeds a
constant — small fragments fit in cache and the yield is overhead).
The prototype skips this guard so the upside is visible isolated.

## 5. What needs fixing in the first stab before measurement

The first stab (`6b5ab6007cb`) has plumbing in place but several real
defects:

1. `tiny_fiber::CreateFiber(stack_size, mt_fiber_main, &fiber_handle)` in
   `thr_init_fiber` passes `&fiber_handle` *before* `fiber_handle` is
   assigned, and ignores `CreateFiber`'s return value. The handle stored in
   `selfptr->m_fiber_handle` is uninitialised. Fix: capture the return
   value.
2. The `SwitchFiber()` at the signal-execute boundary is a comment marker
   only. Wire in the counter-gated call from §3.2.
3. **Watchdog**: each fiber holds the watchdog counter via
   `*watchDogCounter`. A fiber that yields mid-signal stops ticking from the
   watchdog's perspective. The watchdog must observe progress from *any*
   fiber on the OS thread, or accept that mid-signal yield extends the
   apparent stall. Cheapest fix: watchdog observes the OS-thread-level
   counter, not the per-fiber one, and a per-fiber "we are about to yield"
   bump keeps it ticking.
4. **Signal ordering**: route each block instance to exactly one fiber,
   so FIFO order on a block instance is naturally preserved by the
   per-fiber job buffer. Confirm `mt_add_thr_map` does this — instance
   mapping currently treats fiber IDs as thread IDs, which incidentally
   gives the property we want, but it should be made explicit and tested.
5. Stack stays at the ~1–2 MB range. Phase 0 stack-size sweep confirmed
   no throughput penalty up to 2 MB (M2 Pro), and scan paths can be deep.

## 6. Benchmark design

The data node is hard to drive to the bottleneck — at normal LDM counts
the NDB API side runs out before the data node does. So we constrain the
data node to amplify the signal:

- **Single LDM thread**. Configure the node with exactly one LDM and
  `theNumberOfFibersPerThread = 2`, then `= 4`. The one LDM thread becomes
  the bottleneck, and any overlap fibers extract shows up as a clean
  throughput win.
- **Working set well above per-core L2**. Many rows per fragment, so a
  primary-key probe genuinely misses to DRAM rather than hitting cache.
- **Two workloads**:
  - **Rondis** (Redis-protocol PK reads via the `rondb-cli` / Rondis
    server path). Exercises DBACC + DBTUP. Hits yield sites #1 and #2.
  - **ndbcrunch** (MySQL-frontend range-scan benchmark). Exercises DBTUX
    walk + tuple fetch. Hits yield sites #3 and #4 (and #2 secondarily).
- **Baselines**: M = 1 (fibers off), M = 2, M = 4. Report
  throughput (ops/s), p50/p99 latency, and `perf stat -e
  cache-references,cache-misses` on Linux if available.

## 7. Phased plan

### Phase 0 — primitive cost (DONE, M2 Pro)

`claude_files/fibers/bench/` has `bench_switch`, `bench_stack`, `bench_mlp`.
Headlines:

- `SwitchFiber` ≈ 9.5 ns (~33 cycles at 3.5 GHz on M2 Pro). Affordable.
- Stack size from 64 KB to 2 MB makes no measurable throughput
  difference under the round-robin yield pattern. Keep the ~1–2 MB
  default for scan-depth safety with no cost.
- Synthetic pointer-chase MLP: 5.5× at n = 8 on a 1 GB working set.
  Floor is 2 × switch cost; switch is the limit, not memory. This is
  a *primitive-cost sanity check* — it shows the switch is cheap enough
  to be useful, not what the in-NDB gain will be (which will be smaller
  because real signals are mixed work, not back-to-back DRAM misses).
- Crossover (fibers helpful → harmful) is around 16–64 MB working set,
  i.e. where the average load actually misses to DRAM. Below that,
  interleaving is a net loss. This is why production needs a per-site
  fragment-size guard.
- Detailed numbers in Appendix A.

### Phase 1 — fix the first stab + wire signal-boundary yield (1 week)

- Items 1–5 from §5.
- Wire `SwitchFiber` at the signal boundary, counter-gated per §3.2.
- No intra-signal yields yet. Just measure: does the signal-boundary
  fairness yield by itself hurt throughput? (Expect: noise on
  CPU-bound, ≤ 5 % on memory-bound — no overlap, just switch cost.)

### Phase 2 — add yield site #1 (DBACC bucket) (3–5 days)

- Add `PREFETCH_AND_YIELD(bucket_addr, 2)` at the DBACC bucket-head
  load in `execACCKEYREQ`.
- Single-LDM Rondis PK-read benchmark with large keyspace.
- Compare M = 1 vs M = 2 vs M = 4. Pass criterion: M = 2 shows ≥ 10 %
  throughput gain on the memory-bound workload.

### Phase 3 — add yield sites #2, #3, #4 (1 week)

- Add #2 (DBACC → row fixed part) — extend Rondis bench.
- Add #3, #4 (DBTUX node + row) with the near-root depth gate.
  ndbcrunch range-scan bench is the test vehicle.
- Decision point: cumulative gain at M = 2 across both workloads vs
  M = 1 with all sites enabled.

### Phase 4 — follow-up only if Phases 2–3 win (open)

- Per-site fragment-size guards (production gate).
- Multi-range scan interleaving inside DBTUX (the theoretically-possible
  case from earlier discussion — requires K parallel walk states and
  shared row-cap arbitration).
- DBSPJ child-probe interleaving for pushdown joins (synergises with
  RONDB-733 work in this same tree).
- Revisit the per-fiber `thr_data` model: the job-buffer matrix is
  O(N²) in block-thread count, so M = 4 with 16 LDMs scales the LDM
  section from 16 to 64 slots. Probably fine for M = 2 on small
  installs but should be measured.
- **Scheduler per-event timers under fibers** (see §7.5): Stage 1
  (only fiber 0 records) is done; Stage 2 (per-OS-thread recording
  token) is deferred.
- **Thrman + two-step scheduling** (see §7.6). Substantial change;
  needs Phase 1 fully stable first.

### 7.5 Scheduler per-event timers under fibers

The scheduler records "time between events" — the wall-clock time the OS
thread spends in each non-execution state — into four `thr_data` counters:
`m_nanos_sleep`, `m_measured_spintime_ns`, `m_buffer_full_nanos_sleep`,
`m_nanos_send`. Thrman reads them via `mt_getPerformanceTimers()` to derive
CPU load (`exec = elapsed − sleep − spin − send − buffer_full`).

These cannot be measured independently per fiber: M fibers share one
physical CPU, so an interval bracketed by `NdbTick` across a `SwitchFiber`
boundary includes time a sibling ran. Summing siblings' intervals would
multiply-count the single core.

#### Stage 1 — only fiber 0 records (DONE)

Every recording site is gated on `m_fiber_id == 0` (the OS-thread owner).
Non-base fibers skip recording; `mt_getPerformanceTimers()` already
redirects each sibling to fiber 0's counters, so all M fibers on an OS
thread report one shared load figure. Non-fiber threads (TC/MAIN/recv, or
LDM with fibers off) have `m_fiber_id == 0` and are unaffected.

Implemented in `mt.cpp`: helper methods `thr_data::add_nanos_sleep` /
`add_spintime_ns` / `add_buffer_full_nanos_sleep` / `add_nanos_send`
(self-gating) replace the raw `+=` at the fiber-reachable sites in
`check_yield`, `do_send`, and `handle_full_job_buffers`; the two
`mt_fiber_main` sleep sites carry an explicit `m_fiber_id == 0` guard
because they bundle `wait_time_tracking()`. The `check_recv_yield` /
recv-loop sites are left raw (recv is never fiberized).

Known approximation: send-assist done by a non-base fiber is attributed to
exec, not send. Bounded, and removed by Stage 2.

#### Stage 2 — per-OS-thread recording token (deferred)

Give each OS thread a single *recording slot* (held on fiber 0's thr_data,
reachable by all siblings via `m_my_fibers[0]`): a state
`{IDLE, RECORDING}`, the owning fiber id, the start tick, and a per-fiber
"pending recorder" flag. The slot is a cooperative token, not a lock —
there is no contention because the fibers never run concurrently.

- A fiber about to enter a measured state tries to take the token:
  - **IDLE** → claim it (state = RECORDING, owner = me, start = now),
    run the activity, and on completion add `now − start` to the
    OS-thread counter, then hand off.
  - **RECORDING** (a sibling owns it) → set my "pending recorder" flag
    ("in a recording state, but recording hasn't started") and do *not*
    bracket my own interval.
- Fiber 0 is **not** special: it also defers if another fiber already
  holds the token.
- On completion the owner records its interval, then **hands the token
  to a waiting sibling**: if any fiber has its pending flag set, transfer
  ownership and set that fiber's `start = now` (begin measuring it from
  this instant), clearing the flag; otherwise set IDLE.

Effect: the measured intervals tile the timeline with no overlap and no
gap, so the OS-thread counters equal the union of all fibers' measured
activity — no double-count (Stage 1's send approximation goes away) and no
loss. It also fixes the subtle case where a sibling surfaces work during
fiber 0's pre-sleep drain: that exec time transfers to the sibling's slot
instead of being mislabeled as fiber 0 sleep.

### 7.6 Thrman OS-thread CPU measurement + two-step scheduling (deferred)

Stage 2 above tiles the *scheduler's own* timers correctly, but Thrman's
CPU-load model and the load-aware scheduler still treat each fiber slot as
an independent thread. The right model is the one Mikael proposed:

1. **Thrman measures CPU usage at the OS-thread level** — total CPU
   time consumed by the OS thread that owns this LDM group, attributed
   equally across the M fibers on it. All siblings then carry the same
   load weight by construction.
2. **Scheduling becomes two-step**: when something needs to pick a
   target LDM thread for a signal (e.g. round-robin dispatch, load-aware
   placement), step 1 picks an *OS thread* using the OS-thread-level
   load metric, then step 2 round-robins among that OS thread's M
   fibers. This avoids the failure mode where the scheduler treats two
   siblings as independent low-load targets and floods the OS thread
   they share.

Why this is non-trivial:

- Thrman currently runs per-block-instance (one Thrman per thr_no).
  With M fibers per OS thread, there are M Thrman instances per OS
  thread; they need to coordinate on OS-thread-level measurements
  rather than each measure independently.
- The "OS-thread CPU usage" measurement itself isn't free — `clock_gettime`
  with CLOCK_THREAD_CPUTIME_ID per OS thread, summed across whatever
  sample window thrman uses, with care that the sampling itself happens
  on a known fiber (so we don't measure "current fiber" but "current
  OS thread").
- Every place that uses thrman load output for routing (mt_get_addressable_threads,
  TC instance maps, send-thread balancing) needs to learn the two-step
  pattern. Some places may already work because they iterate by
  thr_no — but they iterate over every fiber slot, which compounds the
  attribution error.

Sequencing — do this only **after** Phase 1 is stable (cluster boots,
runs basic workloads, M=1 = M=2 behaviour for non-fiber paths). Doing
both restructures concurrently makes the result impossible to bisect.

## 8. Risks

- **Watchdog interaction** (§5 item 3). Has to be designed correctly
  before Phase 2 or we'll see spurious "thread stalled" reports.
- **Apple Silicon vs x86 server MLP** differs sharply. Phase 0 numbers
  are M2 Pro; the in-NDB measurement must be re-run on the actual
  target hardware before any production decision.
- **Signal ordering** (§5 item 4). If we accidentally let two fibers
  serve the same block instance, FIFO breaks for that block. The
  instance-to-fiber map must be one-to-one.
- **NDB API bottleneck masking gains**. Mitigated by single-LDM bench
  setup (§6), but worth double-checking with `perf` that the LDM thread
  is actually CPU-saturated.
- **Job-buffer matrix blow-up** at higher M (§7 Phase 4).

## 9. Out of scope

- Replacing signal dispatch with a green-thread runtime.
- Fibers in TC, REP, MAIN, or RECV threads (LDM only for the prototype).
- Removing thread affinity / NUMA pinning.
- Cross-language (NDB API client) fibers.
- C++20 stackless coroutines anywhere in the kernel.

## Appendix A — Phase 0 results (Apple M2 Pro)

Hardware: Apple M2 Pro, ARM64, macOS 14 (Darwin 24.6.0), Apple clang 17,
`-O3 -std=c++17`. L1d 64 KB, L2 4 MB per cluster, no exposed L3.
Benchmark sources under `claude_files/fibers/bench/`.

### A.1 Switch latency (`bench_switch`)

100 M iterations, no-op work between switches.

| Operation                              | ns/op |
|----------------------------------------|------:|
| empty direct function call             | 2.08  |
| empty indirect function call           | 1.91  |
| `tiny_fiber::SwitchFiber` (per switch) | 9.53  |

At ~3.5 GHz that is ~33 cycles per stackful switch — in line with the
literature (20–50 cycles) and the asm-level expectation (only callee-saved
registers + SP/PC are saved).

### A.2 Stack working-set cost (`bench_stack`)

Each fiber writes one byte per 64 B cacheline across 4 KB (= 64 lines) of
its own stack, then yields. Round-robin schedule across N fibers,
5 M iterations per fiber.

| N | stack 64 KB | stack 1 MB | stack 1.5 MB | stack 2 MB |
|--:|------------:|-----------:|-------------:|-----------:|
| 1 | 39.6 ns     | 39.5 ns    | 39.5 ns      | 39.8 ns    |
| 2 | 42.8 ns     | 42.5 ns    | 42.4 ns      | 42.7 ns    |
| 4 | 41.5 ns     | 41.1 ns    | 41.2 ns      | 41.3 ns    |
| 8 | 43.0 ns     | 43.7 ns    | 43.4 ns      | 43.0 ns    |

Stack size has no measurable effect from 64 KB up to 2 MB at this access
pattern. Keep the conservative ~1–2 MB default for scan-depth safety.

### A.3 MLP via fiber interleaving (`bench_mlp`)

Random pointer chase through a permutation of 64 B nodes.

- V0: serial, no prefetch.
- V1: serial with one-ahead `__builtin_prefetch`.
- V2: N independent chases, each yields after issuing prefetch on its
  next node.

Working-set sweep (ns per chase step, smaller is better):

| Working set | V0    | V1    | V2 n=2 | V2 n=4 | V2 n=8 |
|------------:|------:|------:|-------:|-------:|-------:|
|     2 MB    |   6.5 |   6.9 |  22.0  |  21.3  |  21.7  |
|    16 MB    |  15.7 |  12.7 |  21.9  |  22.6  |  21.7  |
|    64 MB    |  88.6 |  94.0 |  51.5  |  27.9  |  21.5  |
|   256 MB    | 111.3 | 112.4 |  57.4  |  31.6  |  23.4  |
|     1 GB    | 117.4 | 116.5 |  59.2  |  30.5  |  21.3  |

Speedup of V2(n=8) vs V0:

| Working set | speedup |
|------------:|--------:|
|     2 MB    |  0.30×  *(loss: data fits in L2)* |
|    16 MB    |  0.72×  *(loss: partial L2 hits)* |
|    64 MB    |  4.13×  |
|   256 MB    |  4.76×  |
|     1 GB    |  5.51×  |

Three things to carry forward:

1. **Cold-DRAM regime: ~5× speedup at n = 8** with the stackful primitive.
   The switch is cheap enough to use.
2. **V1 (one-ahead prefetch on a self-dependent chain) gives nothing** —
   the prefetch instruction can't run ahead when each address is itself a
   load result. Independent chains (different fibers) is what wins.
3. **Asymptotic floor ≈ 21 ns/step ≈ 2 × switch cost.** Switch overhead
   is the limit at the high end, not memory.
4. **Crossover between fibers-help and fibers-hurt is roughly L2-resident
   vs DRAM-bound.** Below the working-set crossover, interleaving is a
   net loss. Production must guard each yield site by a "data is
   likely cold" condition (fragment size, T-tree depth, etc).

These are primitive-cost numbers. The in-NDB win will be smaller because
real signals are mixed work (cache-hot computation around a few cold
loads), not back-to-back DRAM misses.
