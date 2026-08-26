# RONDB-732 — Plan: fiber-safe FREEZE_THREAD_REQ (lift the multi-trp workaround)

> **IMPLEMENTED (Option C, 2026-08-21) — verification pending.** Audit
> §4.1-4 all passed: `flush_send_buffer(thr, trp)` uses only the passed
> thr_data (no TLS/pool ops; single-producer queue slots are race-free
> under freeze quiescence); the parked fiber's stale pending bookkeeping
> is a benign post-unfreeze no-op; and QMGR's FREEZE_ACTION_REQ handler
> (QmgrMain ~10941) confirms the loss mechanism — it sends a LAST signal
> on the old transporter and write-shuts its socket, so post-unfreeze
> fiber flushes are dropped — and confirms flush-to-queue-before-action
> is sufficient (the socket drain transmits everything queued before the
> last signal). Landed: `mt_flush_fiber_send_buffers()` (mt.cpp, after
> mt_getNumFreezeThreads; FREEZE-FLUSH canary), mt.hpp declaration,
> call in `Thrman::wait_all_stop()` at the all-parked point before
> FREEZE_ACTION_REQ, and the QmgrMain NodeGroupTransporters=1 force
> REMOVED. Needs rebuild; verify per §6 (mind the Bug-B entanglement).
>
> **VERIFICATION ROUND 1 (2026-08-21): FAILED — mechanism theory
> incomplete.** With the fix in and multi-trp re-enabled, the state=9
> wedge reproduced (del_sent=3205, credit=3108, joiner case7 frozen at
> 3105) and the FREEZE-FLUSH canary fired ZERO times: nothing was in the
> fiber's thread-local buffers at freeze time. Razor timeline: the copy
> stream SURVIVED switch #2 (flowing 115 ms after it), idled, then
> pumped ~100 sends bracketing switch #3 (11:35:14) — all lost at the
> source side (never reached the joiner). So the loss is POST-unfreeze:
> sends routed onto a transporter during a window where its send buffer
> was disabled — and mt.cpp's enable_send_buffer()/disable_send_buffer()
> DISCARD BY DESIGN anything buffered in that window (their own comments
> say so; the design assumes upper layers never send meaningful data
> then — an assumption the switch sequencing evidently violates, at
> least under fiber timing). The freeze-flush fix stays (it closes a
> real, if not THE, gap). New canaries: SB-DISCARD-ENABLE /
> SB-DISCARD-DISABLE log trp + bytes at both shredders — next repro
> shows exactly which discard eats the ~32 KB and when, pinning the
> enable/routing-flip ordering bug to fix.
>
> **Round-2 instrumentation (2026-08-21), testing the hypothesis that the
> disable/enable state change does not reach fibers as it should:**
> TRP-CHOICE canary in both mt_send_remote variants — logs whenever a
> thread's chosen trp for a data node CHANGES (per-thr
> m_dbg_last_trp_to_node tracker) and any non-OK prepareSend
> (TRP-SEND-FAIL). Discrimination matrix for the next repro:
> - SB-DISCARD-DISABLE on the OLD trp with the fiber's TRP-CHOICE never
>   flipping → fiber routed via stale state (state didn't reach fibers).
> - SB-DISCARD-ENABLE on the NEW trp, with TRP-CHOICE flipping on all
>   threads at the same instant → global ordering window (routing flips
>   before the new trp's send buffer is enabled) — not fiber-state, just
>   fiber-traffic-timing exposing it.
> - TRP-SEND-FAIL burst from the fiber thr → prepareSend refuses (trp
>   state observed as down) and callers drop silently — a third variant.
>
> **ROUND-2 VERDICT (2026-08-25 capture, fully-canaried binary): BOTH
> prior mechanisms REFUTED — and the model reframed.** Ledger identical
> (source del_sent=3188 credit=3108; joiner case7=3105 conf_sent=3108;
> return path lossless). SB-DISCARD-* = 0 on both nodes (nothing was
> shredded from any send buffer); TRP-CHOICE shows the fiber slots (thr
> 0-3) actively flipping onto the multi trps 17-20 at the switch — no
> stale routing. FREEZE-FLUSH = 0 (nothing thread-local at freeze).
> New facts: THREE multi-trp activation cycles in 75 s (initial start,
> node-2 rejoin, and a SECOND rejoin = join #2 failed and retried);
> in-flight TCP data dies traceless at each trp teardown (it already
> left the send buffers — no local shredder can see it). And the
> decisive observation: the source's wedged copy scan SURVIVED the
> target's re-restart for 14 minutes — node-failure handling should
> have aborted it.
>
> **REFRAME**: transient in-flight signal loss around restarts is
> semi-normal and recoverable BY DESIGN — node-failure/cleanup handling
> is the recovery. The fiber bug class is that CLEANUP FANOUTS MISS
> FIBER INSTANCES, converting transient losses into permanent wedges.
> One mechanism would then explain Bug A's permanence (copy-scan
> node-failure cleanup missed on the fiber instance), Bug B (TC-takeover
> abort never releasing the fiber instance's row lock) and Finding #3
> (scan-timeout cleanup). Prime suspect: an instance fanout bound using
> physical LDM threads (2) where logical instances (4) exist. Next dig:
> the takeover/cleanup fanout paths — DblqhProxy::execLQH_TRANSREQ's
> worker loop, DBTC's takeOverInstanceId iteration bound, DBLQH
> node-failure copy-scan cleanup (closeCopyLab / execNODE_FAILREP), and
> DBTC scan-close fanout — audit every instance-count source against
> ndbMtLqhWorkers (logical).
>
> **CASCADE RECONSTRUCTION (capture #4, 2026-08-25) — three stacked
> anomalies:**
> 1. PRIMARY (fiber-suspect, JOINER side): during rejoin #2 the joiner
>    stopped consuming instance-3 copy traffic while alive (~23 s:
>    receipts frozen at case7=3105 from 15:23:57, node up until
>    15:24:20) — echoes capture #1 where the joiner's "(3)Starting local
>    LCP" never appeared. Something wedges the joiner's fiber instance
>    during its own phase 5.
> 2. SECONDARY (by design): restart supervision crash-ordered the
>    stalled joiner (NDB_TAMPER error 9999 into CMVMI at 15:24:16, death
>    15:24:20; the test kills node 2 only ONCE, at 15:23:42 — the 9999
>    is internal). The in-flight tail (del_sent 3106-3188) died with the
>    node — normal, recoverable loss.
> 3. TERTIARY (fiber bug, SOURCE side): failure #2's cleanup never
>    closed instance 3's copy scan — wedged WAIT_LQHKEY_COPY for 14 min.
>    Audited so far: closeCopyRequestLab has exactly ONE caller — the
>    LQH_TRANSREQ takeover scan (DblqhMain ~16776: gates are
>    transactionState not IDLE/TC_NOT_CONNECTED, tcScanRec set,
>    scanNodeId == failed node). DblqhProxy fans LQH_TRANSREQ via
>    LocalProxy c_workers = mt_get_instance_count = ndbMtLqhWorkers
>    (logical, 4) — fanout bound SOUND. DBTC round bounds
>    (maxInstanceId) discovered from real op records — SOUND. So the
>    miss is either LQH_TRANSREQ not reaching/executing on the fiber
>    instance after failure #2, or a gate mismatch on the copy record —
>    NEXT: canary in Dblqh::execLQH_TRANSREQ (per-instance receipt log)
>    + in the COPY-branch close, to see which on the next repro.
>
> **CAPTURE #5 (2026-08-25 18:37, pre-canary binary): DIGIT-IDENTICAL to
> #4** — source del_sent=3180 credit=3108 scanState=9; joiner
> case7=3105 conf_sent=3108; 9999 crash-order on node 2 again. The
> joiner's receipt stream stops at EXACTLY case7=3105 in every capture:
> **the primary anomaly is DETERMINISTIC, wedging on a specific
> operation (~overall op 3108/3109), not a timing race.** New canaries
> for the next repro: NR-DEL-CASE7 logs every op in the 3090..3130
> window; NR-COPY-OP (new, case-agnostic at handle_nr_copy entry) logs
> every op in 3090..3140 with type+rowid — the last logged entry names
> the wedging op regardless of which copy case it takes.
>
> **FANOUT AUDIT COMPLETE (background sweep + manual)**: all
> cleanup/failure fanouts verified SOUND (logical counts everywhere:
> LocalProxy c_workers, remote m_lqh_workers via QMGR CmNodeInfo,
> getInstanceNo family, SUMA GCP, DIH copy paths) — the tertiary leak
> is NOT an iteration-bound bug. Two adjacent real bugs found and
> FIXED: (1) Thrman::update_query_distribution used physical
> ndbMtLqhThreads to segment the logical query-distribution index space
> — fiber slots were weighted as TC threads in the committed-read
> routing weights (possible contributor to the joiner-deaf primary);
> now getNumLDMInstances(). (2) sendSYNC_THREAD_REQ off-by-one
> (pre-existing upstream): thr_no bits addressed as THRMAN instances —
> thread 0 never synced (proxy echo), highest thread never synced, rest
> shifted; now instance+1. Guards the LQH fragment-array switch sync.
> Noted, not fixed: benign Backup fragWorkers bit-0/count desync.
>
> **CAPTURE #6 (2026-08-25 19:17, canaried binary): TERTIARY SOLVED,
> PRIMARY NARROWED.**
> - Tertiary ROOT CAUSE (latent upstream, now FIXED): the node-failure
>   copy close (closeCopyRequestLab) caught the scan in a locally-active
>   state, marked scanCompletedStatus, and cleared copyCountWords. The
>   response path did not check the marker before handling fetched rows,
>   so the scan sent 8 more deletes to the DEAD node (del_sent
>   3188→3196), re-inflating copyCountWords, and ended parked forever
>   behind closeCopyLab's copyCountWords>0 wait. Canaries proved
>   LQH_TRANSREQ reached ALL instances and TAKEOVER-COPY-CLOSE ran on
>   instance 3 (scanState=1 at close). FIX: check
>   scanCompletedStatus at nextScanConfCopyLab entry before handling any
>   fetched row; when set, zero copyCountWords, discard the record, and
>   close immediately. Upstream-reportable.
> - PRIMARY NARROWED: NR-COPY-OP named the wedging op — after 3107
>   in-order deletes, op n=3108 = INSERT (op=2) at row(0,0) with
>   rowidFlag=1 = the FIRST REAL-ROW copy of the data-bearing fragment
>   (test.t1). It enters handle_nr_copy and never confs. The joiner is
>   otherwise fully healthy afterwards (other fragments complete,
>   TRP-CHOICE flows, FRAG-EXCL-WAIT=0) — ONE fragment's copy wedges
>   mid-op on the fiber instance; phase 5 waits on it; supervision
>   9999-kills the node. The thrman query-distribution fix was IN this
>   binary and did NOT cure it. Next dig: instrument the INSERT-copy
>   path stages (handle_nr_copy case taken; ACC/TUP entry vs completion)
>   for the window ops to find where op 3108 parks — suspects: DBACC
>   lock/insert on the restored row, nr_copy_delete_row internals,
>   disk-data path, or a lost intra-op signal on the fiber.
> - With the tertiary fix, the cascade should now degrade gracefully
>   (source cleans up on the 9999 kill; joiner retries) — but the
>   deterministic primary may turn the test into a join-retry loop
>   until it passes/fails by timeout; observe next run.

Next focused task (chosen 2026-08-21). Goal: make the thread-freeze
protocol correct when LDM fibers are enabled, so the temporary
`NodeGroupTransporters=1` force in QmgrMain.cpp can be removed and
multi-transporters work under fibers.

## 1. Evidence and status

- **Bug A (send-tail loss at the multi-trp switch) is CONFIRMED.** With
  the workaround active ("NodeGroupTransporters set to: 1" in the failing
  run's log), the state=9/flow-control wedge is GONE and the copy ledger
  is clean (del_sent=3105, credit=3108 — every request delivered, every
  conf credited). The freeze gap described below is its mechanism.
- **Bug B (distinct, still open)**: with the workaround active,
  `ndb_TCtakeover_stall` STILL fails — but with a different shape:
  `scanState=1` (WAIT_NEXT_SCAN_COPY), `copyCountWords=0` — the copy scan
  waits forever on a ROW LOCK that the TC-takeover abort should have
  released. Separate investigation track (see §7); it gates the
  end-to-end verification of this plan because the same test is the
  regression vehicle for both.

## 2. The freeze protocol today (code walkthrough)

Single user today: QMGR's multi-transporter SWITCH during node restart
(QmgrMain ~10933 sends `FREEZE_THREAD_REQ` to THRMAN_REF; the block
comment at ~10132 diagrams the protocol). Flow:

1. `ThrmanProxy::execFREEZE_THREAD_REQ` (thrman ~5190) fans the signal
   out to every worker instance — **skipping fiber slots** via
   `mt_isBlockThreadFiber(thr_no)` (9f96fac).
2. Each non-main THRMAN instance (thrman ~5026): `flush_send_buffers()`
   — which flushes **only its own thr_data's** thread-local transporter
   send buffers — then `wait_freeze(false)`: parks the OS thread in a
   `NdbCondition_WaitTimeout(g_freeze_condition)` loop, after
   incrementing `g_freeze_waiters`.
3. The main THRMAN instance `wait_all_stop()`s until `g_freeze_waiters`
   reaches `mt_getNumFreezeThreads()` (physical threads only — 9f96fac),
   performs the requested change (transporter switch), then broadcasts
   the condition to unfreeze.

Correctness contract (from the code comment): the switch must be able to
assume **no in-flight data remains committed to the old transporter set**
and signal order is preserved across the switch.

## 3. The defect, precisely

Three gaps for an OS thread carrying M fibers:

- **G1 — unflushed sibling send buffers (the proven data-loss bug).**
  Only the base fiber's THRMAN receives the freeze; its
  `flush_send_buffers()` covers base thr_data only. Sibling fibers'
  thread-local send buffers can hold pages already committed to
  *specific old trps*. The base then parks the OS thread — siblings can
  never run (cooperative), so their tails survive the switch buffered
  for transporters that will never be sent again. Observed as ~75 copy
  LQHKEYREQs vanishing (Finding #1 ledger).
- **G2 — siblings park at "dirty" yield points.** A sibling can be
  suspended at a boundary yield mid-burst: accumulated `send_sum`,
  unflushed local signal buffers, packed containers. Analysis: local
  job-buffer signals are intra-node (switch-irrelevant) and packed
  containers flush post-unfreeze as *new* traffic on the *new* trp set
  (ordering handled by the switch protocol) — only the transporter send
  buffers (G1) strictly violate the contract. G2 must be re-audited
  whenever Phase 2 adds intra-signal yields (a sibling could then park
  MID-SIGNAL, which strengthens the case for the drain design below).
- **G3 — why the naive fix deadlocks (for the record).** Fanning the
  freeze out TO fiber slots cannot work: the first sibling to execute it
  would park the shared OS thread inside `wait_freeze`, the base fiber
  never runs its own freeze, `g_freeze_waiters` never reaches the
  target. The 9f96fac skip was necessary; it just left G1 open.

## 4. Design options

**Option C (recommended) — flush-on-behalf under full quiescence.**
Once ALL freeze-eligible threads are parked (`wait_all_stop` satisfied),
every fiber slot is provably suspended (its OS thread is parked in
`wait_freeze`) and will stay suspended until unfreeze. The main THRMAN
thread can then safely walk the fiber-slot thr_datas and flush their
thread-local transporter send buffers into the global per-trp queues,
and issue a final send on the affected trps, before performing the
switch. Pure mt.cpp/transporter-layer work — no block code executed on
behalf of another instance.

- New mt.cpp API: `mt_flush_fiber_send_buffers()` — iterate thr_no in
  the fiber-slot range (`ndbMtLqhThreads <= thr_no <
  ndbMtLqhThreadFibers`), for each: `flush_send_buffer(thr, trp)` for
  every trp in its `m_pending_send_mask` / non-empty `m_send_buffers`,
  then force-send those trps (reuse the `do_send(must_send)` internals
  or `performSend` directly under the send locks).
- Call site: `Thrman::wait_all_stop()` after the waiter count is
  reached, before replying to QMGR / before the switch proceeds.
- Canary: log per-fiber flushed byte/page counts when nonzero
  ("RONDB732 FREEZE-FLUSH thr=N trp=T pages=P") — proves both that the
  gap was real and that the fix engages in verification runs.

**Audit list for Option C (must check before coding):**
1. `flush_send_buffer()` thread-locality assumptions: it moves pages
   from `selfptr->m_send_buffers[trp]` to the global
   `thr_repository::send_buffer` under `m_buffer_lock` — verify no
   TLS/selfptr-identity dependency beyond the passed pointer.
2. `m_send_buffer_pool` page release: releasing on behalf of another
   thread touches its `thread_local_pool` — either leave pool balances
   untouched (only move pages, don't release) or verify
   `release_global(..., m_send_instance_no)` is safe cross-thread under
   quiescence.
3. The parked sibling's bookkeeping (`m_pending_send_mask`,
   `m_pending_send_count`) after its buffers were flushed behind its
   back: post-unfreeze it will re-run do_send on now-empty buffers —
   verify that path is a benign no-op (it should be; flush of empty is
   a no-op).
4. Send-thread interaction: flushed trps must be alerted/sent before
   the switch neutralizes them — confirm where the switch does its
   final send of old trps and hook before it.

**Option A (fallback) — cooperative sibling drain before base parks.**
Base fiber's THRMAN freeze handler, before `wait_freeze`: set a
per-sibling `m_freeze_drain` flag and `fiber_yield_to` each sibling;
the sibling's scheduler loop (flag checked at loop top and at the
boundary-yield gate) stops executing new signals, runs its own
`sendpacked` + `flush_all_local_signals_and_wakeup` + `do_send(true)`,
clears the flag, yields back. Base verifies all siblings clean, then
flushes its own and parks. Pros: each fiber flushes via its own code
paths (no on-behalf auditing); also drains packed containers and local
buffers (covers G2 fully, future-proof for Phase 2 intra-signal
yields). Cons: scheduler surgery (drain flag in two hot spots),
mid-signal fiber switches from inside a THRMAN handler (legal — same
mechanism Phase 2 will use — but new today). Choose A if the Option C
audit finds a blocker, or adopt A later as part of Phase 2 hardening.

**Rejected — count fibers into the freeze fan-out**: deadlocks (G3).

## 5. Implementation steps (Option C)

1. Audit items §4.1-4 (read `flush_send_buffer`, `do_send` internals,
   pool release paths, and QMGR's switch-side final-send).
2. Implement `mt_flush_fiber_send_buffers()` (mt.hpp export — note the
   libndbkernel link lesson: thrman.cpp IS linked with mt.cpp in ndbmtd
   and in *-t binaries?? VERIFY: thrman calls mt_ functions already
   (mt_getNumFreezeThreads, mt_isBlockThreadFiber) so the symbol
   precedent exists — safe).
3. Hook into `Thrman::wait_all_stop()` + the FREEZE-FLUSH canary log.
4. Remove the QmgrMain.cpp `NodeGroupTransporters=1` force (keep the
   log line inverted: log multi-trp active under fibers).
5. Rebuild; verification per §6.

## 6. Verification

Gate 0 (before this fix can be end-to-end verified): Bug B must be
fixed or the test's Bug-B failure mode must be distinguishable — the
regression vehicle `ndb_TCtakeover_stall` currently fails on Bug B even
with multi-trp disabled. Options: fix Bug B first (§7), or verify Bug A
via the canaries only (state=9 wedge absent + FREEZE-FLUSH lines
present + ledger clean) while tolerating Bug-B failures.

1. Suite run (machine under load — the proven reproducer conditions)
   with the workaround removed: `RONDB_FIBERS_PER_THREAD=2 ./mtr
   --suite=ndb`. Success = zero state=9 copy wedges; FREEZE-FLUSH
   canary lines appear with nonzero pages in restart tests (proves the
   gap fires and is closed); COPY-TOTALS ledgers stay balanced.
2. Repeat `ndb_TCtakeover_stall` under load (watcher v3).
3. Fibers-off regression: default suite slice must be untouched
   (mt_flush_fiber_send_buffers no-ops when ndbMtLqhThreadFibers ==
   ndbMtLqhThreads).

## 7. Parallel track — Bug B (stuck row lock after TC-takeover abort)

Not this plan's scope, but gates §6. Shape: copy scan on a fiber
instance waits forever in WAIT_NEXT_SCAN_COPY on a row lock the
taken-over transaction's abort should have released; flow-control
ledger clean. Next diagnostic step: canary in the abort path — count
ABORT/ABORTED (or LQH_TRANSREQ takeover completions) per LQH instance,
periodic totals like COPY-TOTALS, so the next capture shows whether the
abort reached the lock-holding fiber instance at all. The
lock-never-released shape was also seen once WITHOUT the workaround
(2026-08-20 "third shape"), so Bug B predates the workaround and is not
multi-trp related.

## 8. Risks

- Flush-on-behalf touches send-buffer internals under assumptions
  (quiescence) that hold only inside the freeze window — guard the new
  API with a require() that the freeze is active.
- The freeze protocol is generic; future users inherit the fix only if
  the flush lives in wait_all_stop (not in QMGR) — place it there.
- Phase 2 intra-signal yields will park siblings mid-signal — G2
  becomes real then; revisit Option A at that point.
- MAX_NDBMT_LQH_WORKERS-sized iterations and thr_no arithmetic must use
  the fiber layout helpers (base = thr_no % ndbMtLqhThreads) — the
  instance-list overwrite wart (mt.cpp ~7966) shows how easy it is to
  get fiber-slot bookkeeping subtly wrong; do not trust m_instance_list
  for fiber slots.
