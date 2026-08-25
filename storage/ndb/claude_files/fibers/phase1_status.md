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

## Step 2 findings (wider stability sweep, 2026-08-20, IN PROGRESS)

**Finding #1 — `ndb.ndb_TCtakeover_stall` timeout: COPY_FRAGREQ scan
stalls on a non-base fiber during node restart.** Full-suite run with
`RONDB_FIBERS_PER_THREAD=2` (default suite config ⇒ 4 logical LDM workers
on 2 OS threads). Evidence chain (logs preserved in
`var/log/ndb.ndb_TCtakeover_stall/`):

- The test's own TC-takeover logic PASSED ("Test succeeded, no GCP
  stall"); the 900 s timeout came from `ndb_waiter` waiting for the killed
  node to rejoin. Node 2 stalled in **start phase 5** for ~14 minutes; the
  final watchdog kills on both nodes are mtr-teardown artifacts.
- Node 2 (joiner): all four "LDM(N): Starting to copy fragments" at
  11:18:47; local LCP started on instances 1, 2, 4 — **never on
  instance 3** (= thr_no 2, a NON-BASE fiber). All empty fragments
  (INS 0 rows) copied fine; the stall is on the data-carrying tab(11).
- Node 1 (copy source) dumps every 10 s: `COPY_FRAGREQ Scan has stalled
  for 117310 ms, last seen on line 17496` — `(3)Dblqh::ScanRecord[9]:
  state=9 (WAIT_LQHKEY_COPY), type=2 (COPY), complOps=75, concurrOps=0,
  scanNodeId=2`. Line 17496 = `exec_next_scan_conf` (row fetched from
  ACC/TUP); the scan then waits forever for a copy-row LQHKEYCONF.
- Both endpoints of the stalled exchange are LDM instance 3 = a
  **non-base fiber on each node**. All four fibers on both nodes remain
  scheduler-healthy throughout (loops/sigs advancing, fulljb all zero) —
  so this is a **lost/stuck signal in the copy protocol**, not a
  scheduler starvation.
- Hypothesis space (unconfirmed): (a) a fiber's flushed-but-unsent
  transporter data stranded when the OS thread sleeps (per-fiber
  pending_send guards LOOK sound on code reading — mid-execution
  suspension is covered by m_fiber_processing_signals, and each fiber
  self-guards pending_send before its sleep path — but send-thread
  wakeup accounting (m_outstanding_send_wakeups) was not audited);
  (b) the loss is on node 2's applying side (also a fiber);
  (c) an execution-order bug in the copy state machine under fiber
  scheduling. Needs a live repro.

**Deep-dive (2026-08-20, after 2nd deterministic repro).** The stall's
terminal state in both runs: `copyCountWords` wedged at/over the limit
(`cmaxWordsAtNodeRec` = DEF 6000; runs wedged at 6000 and 8000 — overshoot
is normal check-then-add) with `concurrOps=0`, so
`is_ok_to_send_next_record()` stays false forever and nothing re-drives
the scan. The arithmetic is exact in BOTH runs: residual = complOps × 80
words (75×80=6000, 100×80=8000), and 80 = `8 + MAGIC_CONSTANT(56), +25%`
— the fixed cost of a **copy DELETE-by-ROWID** op (DblqhMain ~26457).
So: N delete-by-rowid ops each debited 80 words and NONE were credited,
while their (or other ops') completions advanced complOps. The joiner-side
handler for our case (row absent — these rowids are the source's
rolled-back inserts) is `handle_nr_copy` **Case 7** → `update_gci_ignore:`
which calls **`upgrade_to_exclusive_frag_access()`** before completing.
That resolves to `handle_acquire_exclusive_frag_access()` (DblqhMain
~8634) which spins ~50 µs then parks the WHOLE OS THREAD in a
**timeout-less `NdbCondition_Wait(frag_write_cond)`** waiting for
concurrent readers (query threads / scans) to release the fragment —
under fibers, if the holder is a suspended sibling fiber, that is a
permanent OS-thread deadlock (same hazard class as the congestion
cond_wait fixed in mt.cpp). Caveat: the joiner's fiber counters kept
advancing in the repro logs, so the wedge may instead be an op parked
waiting for a grant, or the deletes may not have reached the joiner at
all — undetermined which link breaks.

**Instrumentation added (DblqhMain.cpp, throttled to first 40 events
each, needs rebuild)**: `COPY-SEND-DEL` (source delete send: rowid, words,
running count), `COPY-CONF` (source credit: words received),
`COPY-CONF-SEND` (joiner conf to remote DBLQH: echoed words, packed?),
`NR-DEL-CASE7` (joiner receipt of delete-by-rowid, row absent),
`COPY-STALL flowctl` (added to the 10 s stall dump: countWords, cmax,
active copies, halted flag, scan state), `FRAG-EXCL-WAIT` (entry to the
timeout-less cond wait: tab/frag, reader/scan counts).

**Instrumented run #3 (2026-08-20): PASSED — and the pass is itself
evidence.** The hot fragment landed on **instance 1 (a BASE fiber)** this
run and the whole chain worked (SEND-DEL → CASE7 → CONF-SEND(packed=1) →
CONF credits, all words=80, zero FRAG-EXCL-WAIT). Both failures had it on
**instance 3 (a NON-base fiber)** — fragment placement varies per run, so
the test is a coin flip over which instance hosts the busy fragment, and
pass/fail correlates exactly with base vs non-base so far. Bonus insight:
the delete burst runs far past the 6000 gate (countWords peaked 28240) —
the gate only throttles further fetching; batches send in bulk, credits
then drain the counter. In the failures credits stopped MID-STREAM (75
resp. 100 arrived, then silence): a **tail loss** — which the first-40
throttled logs can never show. Tracing upgraded accordingly: per-instance
running totals (g_dbg_copy_del_sent/credit/conf_sent/nr_del7) surfaced in
the COPY-STALL dump (`del_sent_total`/`credit_total`) and as every-256th
breadcrumb logs on CONF / CONF-SEND / CASE7.

**Repeat run #1 (2026-08-20, instrumented binary): 6/6 PASSED — wedge did
not reproduce.** A live-caught "stall" mid-run was a false positive: the
test INTENTIONALLY stalls the copy scan on the held row lock
(scanState=1/WAIT_NEXT_SCAN_COPY with an ACC lock op queued,
check_lcp_stop polling — that IS the test's setup); it cleared at
rollback and the rep passed. The real wedge signature is
**scanState=9 (WAIT_LQHKEY_COPY) at the flow-control limit**, or any
copy stall persisting well past the rollback (>100 s). Watcher retuned
accordingly (`scratchpad/watch_stall.sh` v2). Possible reasons for
non-repro: fragment-placement luck, or the first-40 trace logs during
the delete burst perturbing the race (heisenbug risk — if many clean
repeats accumulate, quiet the first-40 logs and keep only counters +
breadcrumbs + stall dump).

Also verified statically meanwhile: LQH instance N maps to thr N-1 (the
fiber slot itself) in mt_add_thr_map — routing, m_instance_list and
m_send_packer all registered on the fiber; SendPacked::pack() runs every
registered block unconditionally each loop, so the fiber's packed
containers DO get flushed every fiber loop. (Note: the fiber
instance-list propagation at mt.cpp ~7966 OVERWRITES the sibling's own
m_instance_list with fiber 0's — its comment claiming "send_packer
registration stays on fiber 0" is wrong, registration is on the fiber;
list consumers are THRConfig lookups (nosend, send-assist assignment),
worth a later audit but not obviously the copy bug.)

**Repeat run #2 (--repeat=20): 20/20 PASSED.** 26 consecutive passes on
the instrumented binary vs 2 failures in ~3 runs before it — the
first-40 g_eventLogger calls (mutex + I/O) inside the delete burst were
evidently perturbing the race. **Tracing quieted (2026-08-20)**: all
first-40 logs removed; silent per-instance counters + every-256th
breadcrumbs + stall-dump totals + FRAG-EXCL-WAIT remain. Requires
rebuild.

**Repeat run #3 (quiet tracing, --repeat=20, 2026-08-21): 20/20 PASSED.**
46 consecutive passes since instrumentation vs 2 failures in ~3 runs
before it. Both original failures had a parallel mtr from another tree
loading the machine; all passes since were on a quiet box — machine
contention is the remaining race-enabler hypothesis.

**REPRODUCED WITH CANARIES (2026-08-21, full-suite run = machine under
load — confirming load as the race enabler).** Same signature: instance
3 (non-base fiber), scanState=9, copyCountWords=7280 >= cmax 6762. The
canaries delivered the ledger: source `del_sent_total=3196` vs
`credit_total=3108` (~88 responses missing); breadcrumbs in perfect
lockstep through op 3072 (identical row (0,7820) on both nodes);
`FRAG-EXCL-WAIT=0` (joiner never parked in the RAL wait — that suspect
is eliminated for this bug). Remaining ambiguity: the 256-granularity
breadcrumbs cannot split the two tail-loss candidates — ~88 REQUESTS
stuck in the source fiber's send path (joiner totals would be 3108) vs
~88 CONFS lost on the packed return path (joiner totals would be 3196)
— and the joiner's exact totals died with its process. Fix applied:
**COPY-TOTALS canary** — the ZCHECK_SYSTEM_SCANS tick (~10 s, both
nodes) logs each instance's del_sent/credit/case7/conf_sent totals
whenever they changed, so the first tick after the tail loss preserves
the exact final values in the log. Next repro answers the question
outright: joiner case7 = 3108-like ⇒ source send-tail loss; = 3196-like
⇒ conf return-path loss. Needs rebuild; reproduce via suite runs /
loaded machine (single-test repeats on a quiet box don't trigger it).

**ROOT CAUSE IDENTIFIED (2026-08-21, repro #4 with COPY-TOTALS canary,
caught live in a suite run, worker var/2): SOURCE-SIDE SEND-TAIL LOSS AT
THE MULTI-TRANSPORTER SWITCH.** The ledger settled the fork: source
inst 3 `del_sent=3180 credit=3108`; joiner inst 3 `case7=3105
conf_sent=3108`; source credited exactly 3108 — **the return path is
lossless; ~75 REQUESTS never reached the wire**. And the same node log
shows the multi-transporter machinery mid-restart: `m_num_multi_trps=4`
(= fiber-inflated ndbMtLqhWorkers, QmgrMain ~517), GET_NUM_MULTI_TRP
REF/retry, and "Ignored connection attempt ... multi transporter
instance 1/2/3 is not in range" (connect-vs-create race). Mechanism:
the SWITCH_MULTI_TRP protocol achieves quiescence by freezing all block
threads, but commit 9f96fac exempted fiber slots from
FREEZE_THREAD_REQ (they share the OS thread with their base) — so a
non-base fiber streaming the copy burst at the switch instant has
send-buffer state the switch's per-frozen-thread handling never sees;
its tail strands on the old transporter assignment, permanently.
Explains every observation: node-restart-only (switch runs then),
mid-burst cutoff at an arbitrary op, always a NON-base instance, load/
timing dependence (burst must overlap the switch), and the idle-at-
switch reverse direction surviving. FRAG-EXCL-WAIT=0 in all captures —
the RAL cond-wait is exonerated for this bug.

**Workaround in tree (2026-08-21, QmgrMain.cpp, needs rebuild)**:
`m_num_multi_trps` forced to 1 when `theNumberOfFibersPerThread > 1`
(logged "forcing NodeGroupTransporters=1 under LDM fibers"). This
skips the switch entirely. It is ALSO the confirming experiment: if
suite runs under load no longer wedge ndb_TCtakeover_stall, the theory
is proven. TODO (real fix, before fibers meet production): make the
multi-trp switch fiber-safe — either include fiber slots' send state in
the freeze/switch handling, or freeze at OS-thread granularity with
per-fiber send-buffer flush before the switch. Also revisit whether
m_num_multi_trps should be sized by logical workers (4) or physical
LDM threads (2) under fibers.

**WORKAROUND VERIFIED / SECOND BUG SPLIT OUT (2026-08-21, suite run
WITH the workaround)**: the failing run's log shows "NodeGroupTransporters
set to: 1" — and the state=9 flow-control wedge is GONE (ledger clean:
del_sent=3105, credit=3108). Bug A (multi-trp switch send-tail loss) is
thereby CONFIRMED and masked. `ndb_TCtakeover_stall` still fails on a
DIFFERENT shape — **Bug B**: scanState=1, copyCountWords=0, the copy scan
waiting forever on a row lock the TC-takeover abort should have released
(same shape seen 2026-08-20 pre-workaround, so Bug B is not multi-trp
related). NEXT FOCUSED TASK (user decision): make FREEZE_THREAD_REQ
fiber-safe and lift the workaround — full plan in
**`freeze_fiber_plan.md`** (protocol walkthrough, the three gaps, the
flush-on-behalf design + cooperative-drain fallback, audit list,
verification gates incl. the Bug-B entanglement).
**Option C IMPLEMENTED 2026-08-21** (see the plan's header note):
`mt_flush_fiber_send_buffers()` called from `Thrman::wait_all_stop()`
at the all-parked point; QMGR workaround removed; FREEZE-FLUSH canary
proves engagement. Needs rebuild + suite-under-load verification —
expect: no state=9 wedges, FREEZE-FLUSH lines with nonzero counts in
restart tests, balanced COPY-TOTALS; Bug B (stuck row lock) may still
fail ndb_TCtakeover_stall independently.

**Prior status: PARKED AS MONITORED (2026-08-21).** The wedge is real (two
full log captures, exact flow-control arithmetic) but not currently
reproducible. Canaries stay in permanently while RONDB732_FIBER_DEBUG
is on: silent copy-protocol counters, every-256th breadcrumbs, the
COPY-STALL flowctl dump (fires within ~20 s of any wedge and contains
the full diagnosis), and FRAG-EXCL-WAIT. Any future occurrence — e.g.
during Step 2 sweeps, which themselves load the machine — self-
documents: compare source `del_sent_total` vs `credit_total` and the
joiner's CASE7 / CONF-SEND breadcrumbs (CASE7 ≪ del_sent =
source→joiner loss; CONF-SEND ≪ CASE7 = joiner parked, check
FRAG-EXCL-WAIT; CONF-SEND ≈ del_sent with credit short = packed return
path). Watcher: `scratchpad/watch_stall.sh` (session-local, recreate
from this description if lost). Open theory candidates, in order:
machine-load-dependent race in the fiber sleep/wakeup tail; packed
container tail flush; the timeout-less frag-access NdbCondition_Wait
(fiber-hostile by construction and worth fixing on principle
regardless).

**Finding #2 — DISSECTED (2026-08-21, 2nd repro): most likely a
TEST-DESIGN LOAD RACE, not a fiber bug.** Per-child map of the angel log
shows: error insert 1028 does not crash the node — it ORDERS another
system restart at each sysfile write, so while armed the cluster loops
(SR completes → ~9 s uptime → ordered restart; children 2/3/6 completed
SRs at GCI 40/45/82, children 4/5 never finished theirs). The test's
`ndb_waiter` must catch the short started-window to let `all error 0`
disarm — under machine load it keeps missing, sysfile writes keep
getting zapped (every start shows "Local sysfile ... gci: 0"), and
eventually BOTH nodes negotiate an INITIAL start (child 7) = data wipe
= the observed "Unknown table t1". Fibers' only role: contributing to
machine slowness. VERIFY by running ndb_restart2 fibers-off under the
same load — if it fails identically, drop it from the fiber list (it
would then be an upstream test-robustness issue on slow machines).
FIBERS-OFF DATA POINT (2026-08-25, accidental baseline sweep — shell
env forgotten): ndb_restart2, ndb_TCtakeover_stall and
ndb_scan_protocol_timeout all PASSED fibers-off under comparable
machine load; the only fibers-off failures were the 0-LDM ThreadFibers
invariant bug (fixed same day). One pass is not proof, but it shifts
Finding #2 back toward fiber involvement and reconfirms Bug A / Bug B /
Finding #3 as fiber-linked. Bonus confirmation: the ndb_fibers* tests
self-arm via their cnf [ENV] sections, so they exercised fibers (and
passed) even inside the fibers-off sweep.

**Original preliminary record:**
The test crashes the SR mid-sysfile-write via error insert 1028 (fires
once; the insert dies with the process) and expects the next SR to
recover. In the failing attempt the cluster instead went through ~20
restart cycles over ~9 minutes (20× "Start phase 1 completed" in
ndbd.1's log, redo-apply at 10:50 → final start 10:59) and eventually
came up as an **initial start** — data wiped, so the test's DROP TABLE
found no table. mtr's retry (fresh cluster) passed → timing-dependent.
No multi-trp signature in the log (0 hits) and no clean shutdown
markers, so this is likely a DIFFERENT fiber SR bug than Finding #1 —
possibly ~19 independent SR failures (crash or hang per cycle) until
angel/DIH escalated to initial. NOT yet investigated: what killed each
cycle (the accumulated ndbd.log needs per-cycle dissection). Revisit
after the suite finishes and after the multi-trp workaround rebuild —
re-sweep first; whatever still fails then is the true Finding-#2 class.

Sweep-noise instance (2026-08-21): `ndb_alter_table_column_online`
attempt-1 "cluster start failed" = both ndbmtd unable to reach mgmd
(localhost:13000) for 60 s under machine load; never fetched config,
never booted; retry-passed twice. Infrastructure flake, not fibers.

**Finding #3 (2026-08-21, suite run, PRELIMINARY): `ndb.ndb_scan_protocol_timeout`
— PK lookup times out (4012) after an induced scan timeout.** The test
arms error insert 5112 to make an ordered scan time out, closes it, then
verifies all ApiConnectRecords are reusable via a PK-lookup sweep — one
of those lookups hung. Node logs clean (no watchdog/stall lines): a
protocol-level wedge (stuck TC/LQH record after scan-timeout cleanup).
**Family hypothesis**: Bug B (TC-takeover abort never releases a row
lock on a fiber instance) and this finding look like the same class —
ERROR/CLEANUP-path signal handling involving LDM fiber instances
misbehaving while normal-path traffic is fine. Candidate common cause:
a cleanup fanout (abort, scan close, timeout handling) that iterates or
addresses LQH instances using physical-thread-derived counts somewhere.
Investigate after the config-guard rebuild: if it persists, drill this
test (it is error-insert-deterministic, likely a better repro vehicle
than TCtakeover for the family).

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
   `RONDB_FIBERS_PER_THREAD=2 ./mtr --suite=ndb ...`. Include
   node-restart/system-restart tests — recovery paths are the least
   tested (see Finding #1). Sweep behavior (2026-08-20, needs rebuild):
   a non-divisible LDM count now **ignores the env override with a
   warning** ("running with fibers off") instead of a fatal config error,
   so odd-LDM tests (`large_txn_non_mt`, `ndb_add_partition`,
   `ndb_blob_big`, `ndb_fk_addnode`, `ndb_full_data_memory_restart`,
   `ndb_load`, `ndb_one_fragment`) run normally fibers-off. Configuration
   logs a definitive "NDBMT: LDM fibers active: N logical workers on M OS
   threads" line when fibers engage; the fiber MTR tests now assert THAT
   line (parse-time env logging no longer implies fibers are on).
   AutomaticThreadConfig noise RESOLVED BY DESIGN CHANGE (2026-08-21,
   user decision): the auto path now PACKS exactly like explicit
   ThreadConfig — the auto-chosen LDM count is the LOGICAL worker count,
   run on count/M OS threads (NumCPUs=16 → 8 workers on 4 OS threads at
   M=2). Both paths unified in Configuration.cpp with the same
   divisibility fallback. Previously the auto path MULTIPLIED
   (configured×M slots), which oversubscribed the machine — confirmed
   casualty: `ndb_big_signals_atc` (16 auto-sized LDM slots on a laptop)
   died in startphase 1 with DBTC STTOR pool-init outrunning the
   watchdog. That test should behave like fibers-off after rebuild.
   **ROOT CAUSE DEEPENED (2026-08-25)**: `ndb_basic_mix_numcpus` and
   `ndb_query_thread_mrr` reproduced the start-hang **with fibers OFF**
   (no env in those processes) — the real bug is 9f96fac's invariant
   break, independent of the fiber flag: `ndbMtLqhThreadFibers` was set
   to `ldm_workers`, which in 0-dedicated-LDM shapes equals the RECV
   thread count, and every consumer that 9f96fac switched from
   `ndbMtLqhThreads` to `ThreadFibers` (mt_add_thr_map's
   num_lqh_threads == 0 special layouts, DbtcProxy first TC instance,
   SimulatedBlock round-robin, thrman naming, malloc sizing) then
   treated recv threads as LDM slots → block instances mapped onto
   nonexistent LDM threads → nodes hang forever after "Send START_ORD"
   ("Unknown place 0"). FIXED: `ndbMtLqhThreadFibers = ldm_threads ×
   fibers` — 0 in 0-LDM shapes (restoring the exact pre-branch value at
   every consumer), unchanged (= ldm_workers) in dedicated shapes. The
   earlier fibers-off guard stays as belt-and-suspenders.
   SECOND consumer of the same invariant found by the retest (2026-08-25,
   crash at mt.cpp add_thr_map `require(thr_no < glob_num_threads)`):
   `ndbMtQueryWorkers = ldm_workers + tc + main + recv` double-counted
   the recv threads in 0-LDM shapes (one query worker too many for the
   thread array). Fixed to use ndbMtLqhThreadFibers as the LDM term —
   reduces to upstream's `ldm_threads + ...` when fibers are off and to
   the 9f96fac logical count in dedicated fiber shapes.
   Related REAL bug found via `ndb_basic_mix_numcpus` (NumCPUs=2/4 ⇒
   auto config chooses **0 dedicated LDM threads**, LDM work on recv
   threads): the fiber env override stayed armed, making
   ndbMtLqhThreadFibers (= recv worker count) exceed ndbMtLqhThreads
   (0) — the fiber-slot range check then classified thr 0 as a fiber
   slot and spawn arithmetic (thr_no % ndbMtLqhThreads) misfired; nodes
   hung at start with never-started threads ("Unknown place 0").
   FIXED (2026-08-21): no-dedicated-LDM shapes force fibers off with a
   warning, same graceful pattern as the divisibility fallback.
   Open design note (user, 2026-08-21): AutomaticThreadConfig with
   **NumCPUs = 0** (true host auto-detect, can yield many LDMs; no MTR
   test uses it) currently gets the same pack treatment but will likely
   want SPECIAL treatment later — e.g. keeping all auto-detected cores
   as LDM OS threads and deriving logical workers as cores×M — decide
   when fiber benchmarking reaches real server hardware (Phase 2+).
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
