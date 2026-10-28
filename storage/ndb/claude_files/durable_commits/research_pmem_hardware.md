# RONDB-1150: persistent-memory hardware and OS behaviour for a PMEM REDO log

Scope: what the hardware and Linux guarantee and cost when the REDO log is
written directly to persistent memory (fsdax files mapped with `MAP_SYNC`),
and what that means for the write unit, the filler record, checksums and the
flush sequence. The record format, recovery and write path are covered in
`pmem_redo_format.md`, `pmem_redo_recovery.md` and `pmem_redo_write_path.md`.

Tags: **[V]** = verified from a cited source or from the code.
**[I]** = inferred. Sources are listed in §7 as [S1]..[S36].
Code references are relative to `storage/ndb/` unless marked "(repo root)".
Date of research: 2026-10-28.

---

## 0. Summary

* **Atomicity.** Only an aligned 8-byte store is failure-atomic on x86
  [V S5]. A 64-byte line is "very likely" but not guaranteed to persist as a
  unit, except with `MOVDIR64B` [V S6, S7]. Optane's 256-byte XPLine is a
  media unit, not an atomicity unit [V S1].
* **Rewriting a partly persisted unit is safe** on all known devices: the
  read-modify-write buffers sit inside the power-fail domain [V S1, S3], and
  unchanged bytes are rewritten with the same values [I]. A filler is not
  needed for correctness, but pays for itself in performance (§1.3).
* **Lines persist in any order** within a barrier interval [V S35]. Recovery
  must stop at the first bad record, and the CRC must be seeded with lap and
  restart sequence (§1.4).
* **Devices in 2026.** Optane is end of life [V S10]; NVDIMM-N is DDR4-only
  [V S12]; CXL NV-CMM modules passed compliance in January 2026 [V S11].
  Linux reports CXL PMEM as `memory_controller`, so flushes are needed
  [V S15]. No mainstream cloud offers power-fail-safe PMEM [I].
* **Cost.** One store + `clwb` + `sfence` takes 86 ns on DRAM and 94–353 ns
  on Optane [V S2, S4]; re-persisting a line in flight costs up to ~1 µs
  [V S3]; rare Optane outliers reach 50 µs [V S1].
* **Linux.** `MAP_SYNC` fails with `EOPNOTSUPP` on non-DAX files [V S18].
  Write faults on dirty metadata cost ~108 µs [V S21]: create files fully
  written and prefault them. PMDK was archived in November 2025 [V S24]:
  carry our own helper.
* **Checksums.** NDB has no CRC32C helper [V]. CRC32C costs ~5 ns per
  COMPLETE and ~10 ns per COMMIT [I from V S31].
* **Recommendation.** W = 64 bytes, fixed. Pad every persist with a filler.
  Write whole units with non-temporal stores from a DRAM staging copy, then
  `sfence`. Expect 100–400 ns per COMMIT or COMPLETE persist on ADR
  hardware (§9).

---

## 1. Failure atomicity and torn writes

### 1.1 What is atomic on power loss

| Unit | Guarantee | Source |
|---|---|---|
| Aligned 8-byte store (x86) | Failure-atomic. "Any store to memory has an atomicity guarantee of only eight bytes" | [V S5, S35] |
| Larger store, `memcpy` | "Not power-fail atomic and may result in a torn write" | [V S5] |
| 64-byte cache line, written back by `clwb`/eviction | "Very likely" atomic on modern server CPUs, "not architecturally guaranteed" (Rudoff, 2022) | [V S6] |
| 64-byte `MOVDIR64B` direct store | "64-byte write-completion atomicity", destination 64-byte aligned, weakly ordered (needs `sfence`) | [V S7] |
| Optane 256-byte XPLine | Media access unit. Smaller writes become read-modify-write inside the DIMM. Not exposed to software as an atomicity unit | [V S1] |
| 4 KB sector | Only with the BTT driver (sector mode), never with DAX | [V S30, S35] |
| ARM | Single-copy atomicity of aligned 8-byte stores; no larger persistence-atomic unit is defined [I] | — |

Unflushed stores may become persistent in any order and at any time,
because the cache may evict a line at any time. Each aligned 8-byte chunk is
not torn [V S35, S6].

### 1.2 What a torn write looks like

| Device | Persistence path | Torn write after power loss |
|---|---|---|
| Optane DCPMM (100/200/300) | Cache → iMC WPQ (ADR) → DIMM XPBuffer (ADR) → 3D XPoint media | Any subset of the 64-byte lines written since the last completed barrier, each line torn at worst at 8-byte granularity [I]. The XPBuffer is in the ADR domain: "all updates that reach the XPBuffer are already persistent" [V S1, S3] |
| NVDIMM-N (DDR4) | Cache → WPQ (ADR) → DRAM; on power loss the module copies DRAM to flash | Same as above. The image is the DRAM content after the WPQ drained [I] |
| CXL NV-CMM | Cache → host → CXL link → device DRAM; GPF and an on-module energy source save DRAM to NAND [V S11, S14] | Same as above, if GPF completes. If it fails, the device logs a dirty shutdown [V S14, S15] |
| Samsung CMM-H (prototype) | Host 64-byte requests → device DRAM cache → NAND (4 KB); battery-backed flush in persistent mode [V S13] | Device-internal; same contract claimed [I] |
| eADR platforms | Caches are inside the power-fail domain [V S34] | Every store that is globally visible survives; ordering still needs `sfence` [V S34] |

In every case the software model is the same: bytes written since the last
completed barrier may persist partly, in any order, at 8-byte granularity.

### 1.3 Can rewriting a partly filled unit damage bytes already persisted?

This is the question behind the filler record.

* **Architecture.** No source guarantees or excludes it. The programming
  model is "once a store reaches the power-fail protected domain, it is
  persistent" [V S5]. A later write to other bytes of the same line sends the
  persisted bytes again with **the same values**. Even if that write is torn
  at 8-byte granularity, those chunks end up with their old value [I].
* **Optane.** The 256-byte read-modify-write is done by the XPController
  from the XPBuffer. Both the WPQ and the XPBuffer are inside the ADR domain
  [V S1, S3], and the DIMM drains them on power loss with its own energy
  store [V via S1 "ADR domain"; capacitor detail I]. An in-flight
  read-modify-write is therefore completed by design [I].
* **NVDIMM-N / NV-CMM.** DRAM with a whole-image save. The host writes whole
  64-byte lines; there is no device-visible read-modify-write [I].
* **When the contract fails** (energy source dead, firmware bug), any data
  can be lost, old or new. The device then increments its dirty shutdown
  count [V S29, S15]. A filler cannot protect against this. Detection must
  use the dirty shutdown count (§4.4).
* **Software is the real risk.** If a persisted byte is rewritten with a
  *different* value (a page checksum, a fill index, an end-of-log marker), a
  torn write leaves a mix of old and new. Records already acknowledged may
  then depend on a damaged field [I]. Hence the write-once rule in §1.5.

**Conclusion.** A filler is not needed to protect persisted bytes. It is
useful for three other reasons [I, based on V sources]:

1. On Cascade Lake, `clwb` invalidates the line like `clflushopt` [V S9].
   The next append into the same line then misses, and reading or writing a
   line still being persisted costs up to ~2,500 cycles [V S3].
2. Repeated writes to one line are the extreme "hot spot". Optane's rare
   50 µs outliers increase when writes concentrate in a small area [V S1].
3. With a filler, every unit is written exactly once per lap. Whole-unit
   non-temporal stores need no read-for-ownership, and the recovery scan
   can treat a unit as the scan step.

### 1.4 Ordering inside one barrier interval

* Between two completed barriers, lines persist in any order [V S35].
* Example: records R1 (lines 1–2) and R2 (line 3) are flushed together and
  power fails before the `sfence` returns. Line 3 may be persistent and
  line 2 not. R1 fails its CRC; R2 passes [I].
* Neither record was acknowledged, so discarding both is correct. Recovery
  must **stop at the first invalid record** and treat the rest of the log as
  garbage [I].
* That garbage stays in PMEM. After the restart, new records overwrite it
  from the stop point. If a later crash tears the new tail, an old R2 that
  happens to start at a record boundary can look valid again [I].
  Countermeasures, for `pmem_redo_recovery.md`: seed the CRC with the lap
  *and* the restart sequence (the plan's SR head record, §7 of the plan), or
  invalidate the units after the stop point before writing.
* The same applies to records from an earlier lap of the ring: they have a
  valid CRC unless the CRC covers the lap and position [I].
* Fresh fsdax blocks read as zeros [I]. Record type 0 must be invalid
  (today type 0 is the unused NEW_PREP, `research_redo_log.md` §2.5), and the
  CRC must use the standard non-zero init/xor-out so that an all-zero unit
  fails [I].

### 1.5 Consequences for the format (input to `pmem_redo_format.md`)

* **Write-once.** No byte that an acknowledged record depends on is
  rewritten until the ring wraps. No in-place fill index (today's
  `ZCURR_PAGE_INDEX`), no page checksum updated per append, no "last
  record" pointer updated per append [I].
* A page or MByte header written once, in the same persist as the first
  record of that page, is fine [I].
* Fields that a reader must see whole (type, length) should sit in one
  aligned 8-byte word [I from V S5].
* 8-byte record alignment keeps the smallest gap at 8 bytes, so a filler
  header always fits (§9 item 2) [I].

---

## 2. Devices available in 2026

| Device | Status in 2026 | Persistence domain | Linux `persistence_domain` | Media/transfer unit | Persist latency |
|---|---|---|---|---|---|
| Intel Optane PMem 100 (Cascade Lake) | Discontinued; last shipments Dec 2023 [V S10]. Installed base, used market | ADR | `memory_controller` [I] | 64 B transfer, 256 B XPLine [V S1] | 94–353 ns [V S2, S4] |
| Optane PMem 200 (Ice Lake) | Last order Dec 2024, last shipment Dec 2025 [V S10] | ADR, or eADR where the platform enables it [V S34] | `memory_controller` or `cpu_cache` | as above | ADR as above; eADR ≈ `sfence` only [I] |
| Optane PMem 300 (Sapphire Rapids, DDR5) | Was still shipping when the 200-series EOL was announced [V S10]; no later status found [I] | ADR/eADR | as above | as above | not measured in sources found |
| NVDIMM-N | JEDEC standard JESD245E covers **DDR4 only** [V S12]; SMART still had a DDR4 datasheet in 2024 [V S12]. No DDR5 NVDIMM-N found [I] | ADR | `memory_controller` [I] | 64 B | ≈ DRAM, ~86 ns [V S2 DRAM figure] |
| CXL NV-CMM (SMART Modular / Penguin, E3.S, CXL 2.0, x8 Gen5, DDR4 + NAND + energy source) | Sampling to tier-1 OEMs from March 2025; passed CXL compliance January 2026 [V S11] | GPF (CXL 2.0) [V S14] | `memory_controller` (the kernel sets `ND_REGION_PERSIST_MEMCTRL` for every CXL PMEM region) [V S15] | 64 B line per CXL.mem write [I] | CXL loads 200–400 ns, tails > 700 ns [V S33]; persist similar [I] |
| Samsung CMM-H (CXL, NAND + DRAM cache, battery) | FPGA prototype; persistent mode exists [V S13] | Device flush on power loss [V S13] | not known [I] | 64 B host, 4 KB NAND [V S13] | not known |
| Cloud | Google's Optane VMs were an alpha in 2018 [V S36]; VMware drops PMem from VCF 9.0 [V S36]. No current offering found [I] | — | virtio-pmem regions are async and refuse `MAP_SYNC` [V S22] | — | — |
| ARM servers | Linux arm64 supports PMEM through `DC CVAP` [V S32]. No ARM server with NVDIMMs or persistent CXL found [I] | — | — | — | — |

Notes:

* **GPF is not eADR.** Phase 1 flushes CPU and device caches, phase 2 the
  device buffers to media [V S14]. A 2025 paper calls GPF's guarantees "much
  weaker than eADR's" [V S14]. Linux reports `memory_controller`, so
  software flushes anyway, which is the safe side [V S15]. Code written for
  NVDIMMs "still works correctly" on CXL PMEM [V S14, SNIA deck].
* **Practical consequence.** Durable commits (D8: PMEM only) will run on
  bare metal: Optane servers, DDR4 NVDIMM-N servers, CXL NV-CMM on CXL 2.0
  hosts [I].

---

## 3. Instructions and their cost

### 3.1 x86

| Instruction | What it does | Notes |
|---|---|---|
| `clflush` | Write back and invalidate one line; ordered with other `clflush` | Serialised, one line after another [V S5]. Do not use |
| `clflushopt` | Same, weakly ordered | Needs `sfence` [V S5] |
| `clwb` | Write back; the line "may be retained" (a hint) [V S8] | Equivalent to `clflushopt` on Cascade Lake; retains the line on Ice Lake and later [V S9]. Works on a line in any cache of the coherence domain [V S8]. CPUID.(7,0):EBX[24] [V S8] |
| `movnti` (8 B), `movntdq` (16 B), `vmovntdq` ymm/zmm (32/64 B) | Non-temporal store through a write-combining buffer; no read-for-ownership | Needs `sfence` to be visible and persistent [V S34]. A 64-byte zmm store fills the line in one instruction [I] |
| `MOVDIR64B` | 64-byte direct store, WC protocol, atomic as one 64-byte write [V S7] | Destination 64-byte aligned; source read not atomic [V S7]. Present on Sapphire Rapids and later Intel servers [I] |
| `sfence` | Orders and waits for prior flushes and NT stores of **this core** | "Stall[s] the CPU until all inflight flushes are completed" [V S4] |

On eADR the caches are persistent, so flushes are not needed. An `sfence`
is still used for ordering and to drain write-combining buffers [V S34,
S25]. libpmem2 defaults to `clwb`, falls back to `clflushopt` then
`clflush`, and uses NT stores above a size threshold [V S25].

### 3.2 ARM

* `DC CVAP` (ARMv8.2, FEAT_DCPoP): clean to the point of persistence.
  `DC CVADP` (ARMv8.5): clean to the point of deep persistence [V S32].
* Linux: `arch_wb_cache_pmem()` = `dmb(osh)` + `dcache_clean_pop()` (a
  `DC CVAP` loop) [V S32]. The completion barrier is `dsb` (`__wmb()` is
  `dsb(st)`) [V S32].
* Detect with `getauxval(AT_HWCAP) & HWCAP_DCPOP` [I].
* There is no ARM equivalent of a guaranteed non-temporal path to PoP; `STNP`
  is only a hint [I].

### 3.3 Measured latency

| Measurement | Value | Source |
|---|---|---|
| Optane random 8-byte load (idle) | 305 ns (DRAM 81 ns) | [V S2] |
| Optane sequential load | 169 ns | [V S2] |
| store + flush + fence, one line | 94 ns Optane, 86 ns DRAM | [V S2] |
| one `clwb` + one `sfence`, line in L1D, Cascade Lake + Optane | 353 ns | [V S4] |
| Access to a line still being persisted (read-after-persist), G1 Optane | up to 2,500 cycles local, 3,200 remote; up to 10× the normal cost (2× on DRAM) | [V S3] |
| Optane write outliers | up to 50 µs, 0.006 % of writes, more with small hot spots | [V S1] |
| Single Optane DIMM bandwidth | 6.6 GB/s read, 2.3 GB/s write | [V S2] |
| XPBuffer | ~16 KB per DIMM, coalesces writes over up to 64 XPLines | [V S1] |
| Remote-socket Optane writes | 2.53× the local latency | [V S1] |
| fsdax log append via libpmem (Intel WAL article) | average < 3 µs, P99.99 < 11 µs for a whole WAL append path | [V S30] |
| CXL memory loads | 200–400 ns local; p99.99 > 700 ns on some devices | [V S33] |

For stores, "the memory store and fence instructions commit once the data
reaches the ADR at the iMC", so DRAM and Optane look similar [V S1]. The
spread between 94 and 353 ns is likely methodology (warm versus cold line,
one versus many outstanding flushes) [I].

### 3.4 Guidance from the papers, applied to a log

| Guideline | Source | For the REDO |
|---|---|---|
| "Avoid random accesses smaller than 256 B" | [V S1] | Log appends are sequential; the XPBuffer merges sequential 64 B writes. Not a reason for W = 256 [I] |
| "Use non-temporal stores when possible for large transfers"; for micro-buffering the NT/normal crossover was 1 KB | [V S1] | Small records: test both (§3.5). Large PREPARE copies: NT stores [I] |
| `clwb` after a store "must load the cache line" first, costing DIMM bandwidth | [V S1] | Cold log lines cost a PMEM read with cached stores; NT stores avoid it [I] |
| "Limit the number of concurrent threads accessing a 3D XPoint DIMM"; peak at 1–4 threads per DIMM, 12 for interleaved store+`clwb` | [V S1] | One writer per log part; up to 32 log parts per node. Measure in P6 [I] |
| Keep the persist working set small; avoid re-persisting the same XPLine under strict persistency | [V S3] | Filler; one write per unit [I] |

### 3.5 Two ways to write a unit

**A. Cached stores in place + `clwb` per line + `sfence`.**
* The current code style: `writeLogWords` writes straight into the mapped page.
* Each cold line is read from PMEM first (read-for-ownership) [V S1].
* On Cascade Lake every `clwb` evicts, so the next record in the same line
  misses again and may hit the read-after-persist stall [V S3, S9].

**B. DRAM staging copy + whole-unit non-temporal stores + `sfence`.**
* Records are built in DRAM (today's 32 KB in-memory log pages can serve as
  the staging copy [I]).
* At a persist point the new bytes, padded to W by the filler, are copied
  to PMEM with 64-byte NT stores (one zmm store, or 2 × ymm, or 4 × 16 B),
  or with `MOVDIR64B`.
* No read of PMEM, no cache pollution, one write per unit, identical on ADR,
  eADR and CXL [I].
* For small writes, NT stores were measured slower than store + `clwb`
  [V S1, S2]. The sources do not say whether the lines were cold, as they
  are in a log [I].

Both are correct. Recommendation: implement B as the default and A behind a
switch, and choose with a P6 microbenchmark on each target platform (§9 item 5).

### 3.6 Several LDMs on one log part

* `sfence` waits only for **this core's** flushes and NT stores [V S4, S8].
  Write-combining buffers are per core and are not snooped [V S34].
* Under `m_log_part_mutex` (`research_redo_log.md` §1.1), if LDM A writes a
  record with NT stores and LDM B persists the part's range, B's `sfence`
  does not cover A's WC buffer [I].
* Rule: a thread that issued NT stores executes `sfence` before it releases
  the log-part mutex or publishes the new end offset [I].
* With cached stores, B's `clwb` of A's lines works, because `clwb` acts on
  the whole coherence domain and A's stores are visible after the mutex
  hand-over [V S8; I for the mutex part].

---

## 4. Linux interfaces

### 4.1 fsdax with `MAP_SYNC`

* Mount ext4 or xfs with `-o dax=always` (`-o dax` is a legacy alias that
  "may be removed") or set `FS_XFLAG_DAX` per file with `dax=inode` [V S20].
* Map with `MAP_SHARED_VALIDATE | MAP_SYNC` (Linux 4.15+). On a non-DAX
  file this fails with `EOPNOTSUPP` [V S18]. `MAP_SHARED` alone silently
  ignores `MAP_SYNC` [V S18].
* The guarantee: data written through the mapping "will be visible in the
  same file at the same offset even after the system crashes" [V S18]. It
  covers file-system metadata; the data itself still needs the CPU flush.
* **Fault cost.** Pages whose metadata is dirty are mapped read-only; the
  first write faults, the kernel commits the metadata, then makes the page
  writable [V S21]. Measured: 108 µs average per fault with `MAP_SYNC`
  versus 23 µs without, on an empty file [V S21].
* Therefore [I]:
  * create REDO files fully written (write zeros or a format pattern;
    neither sparse files nor `fallocate` unwritten extents), as today's
    `InitFragmentLogFiles=full`;
  * prefault with a write to every page at start (a read-only
    `MAP_POPULATE` does not make shared pages writable [I]);
  * prefer 2 MB-aligned extents (namespace `--align 2M`, xfs
    `extsize`) so the kernel can use PMD mappings.
* A file's DAX state changes only when all processes have closed it [V S20].

### 4.2 devdax and detecting DAX

* devdax (`/dev/daxX.Y`) has no file system, so no metadata faults and no
  `MAP_SYNC` [I]. RonDB would have to lay out the log parts in one device.
  A later option; v1 uses fsdax [I].
* `statx()` reports `STATX_ATTR_DAX` (Linux 5.8+) [V S19, S20]. A
  successful `MAP_SHARED_VALIDATE | MAP_SYNC` mmap proves the file is DAX on
  a synchronous device [V S18, S22]. The mmap is the decisive check for D8
  [I]. `persistence_domain` (§4.3) gives the barrier mode.

### 4.3 `persistence_domain`

* `cpu_cache` if `ND_REGION_PERSIST_CACHE`, else `memory_controller` if
  `ND_REGION_PERSIST_MEMCTRL`, else an empty line [V S16]. The two NFIT bits
  are nested: cache-flush capable implies memory-controller capable
  [V S17].
* **`memmap=` regions report an empty line**: the e820 driver sets only
  `ND_REGION_PAGEMAP` [V S16].
* **CXL PMEM regions always report `memory_controller`** [V S15].
* An NFIT region without a Platform Capabilities structure also reports
  empty [I].
* libpmem2 treats the platform as eADR only if *every* region on the system
  reports `cpu_cache` [V S26].

Recommended rule [I]:

| Value for the REDO's region(s) | Barrier |
|---|---|
| `cpu_cache` everywhere | eADR: stores (or NT stores) + `sfence` |
| `memory_controller` | ADR: `clwb` per line (or NT stores) + `sfence` |
| empty | Treat as ADR. With durable commits, refuse to start unless an explicit "emulated PMEM" test setting is on (for MTR on `memmap=`) |

Map the REDO file to its region through `st_dev` → `/sys/dev/block/M:m` →
namespace → region, or use the libpmem2 rule (all regions) for simplicity
[I].

### 4.4 Dirty shutdown and bad blocks

* **Dirty shutdown count.** NVDIMMs expose `nmemX/nfit/dirty_shutdown`
  (PAPR: `nmemX/papr/dirty_shutdown`) [V S29]. CXL PMEM exposes
  `dirty_shutdown`; the kernel sets the dirty state expecting the device to
  clear it after a successful GPF [V S15]. A dirty shutdown means "NVDIMMs
  can lose cached writes" [V S29].
* RonDB should record the count in the REDO file header and compare it at
  start [I]. If it increased, the node's durable tail cannot be trusted. For
  the SR this node then behaves like a stale node for the tail (input to
  `pmem_redo_recovery.md`) [I].
* **Bad blocks.** A process that touches a bad block through a DAX mapping
  is killed with SIGBUS [V S28]. libpmem2 and ndctl can list and clear bad
  blocks [V S28].
* For the recovery scan: check the bad-block list first, or read the REDO
  with `pread()` instead of loads from the mapping, so that a media error
  becomes an error code instead of a crash [I].

### 4.5 libpmem2 / PMDK, or our own helper?

* Intel wound down PMDK feature work in November 2022 [V S23]. The
  `pmem/pmdk` repository was archived on 2025-11-12; the new home
  (`daos-stack/pmdk`) states "The only supported user is the DAOS Project"
  [V S24].
* libpmem2 offers `pmem2_get_persist_fn` (= flush + drain),
  `pmem2_get_flush_fn`, `pmem2_get_drain_fn`, and granularities
  `PMEM2_GRANULARITY_BYTE` (eADR: no flush needed), `CACHE_LINE` (ADR) and
  `PAGE` (needs `msync`) [V S25].
* RonDB needs only a small part of that: CPU feature detection, a region
  check, flush-range, drain, a 64-byte NT unit copy. About 200 lines [I].
* A local helper also gives the hooks the plan's risk 1 asks for: a debug
  barrier checker and power-loss emulation that keeps only what was flushed
  and fenced [I].
* **Recommendation: carry our own helper**, borrowing logic from libpmem2
  where useful (BSD-3) [I].
* Note: `is_avx2_supported()` (`src/common/portlib/NdbHW.cpp:507-510`)
  returns `avx2_supported`, which is initialised to 0 at line 56 and never
  set [V]. The helper must add real CPUID / `getauxval` checks: SSE4.2,
  CLWB, CLFLUSHOPT, AVX-512F, MOVDIR64B, and on ARM CRC32 and DCPOP [I].
* Helper functions [I]: `map_redo()` (`MAP_SYNC` or fail), `domain()`
  (ADR/eADR from sysfs), `stream_units()` (64-byte NT copy), `flush()`
  (`clwb` loop, no-op on eADR), `drain()` (`sfence` / `dsb`).

### 4.6 `memmap=` emulation and what it proves

* `memmap=nn[KMG]!ss[KMG]` reserves RAM as `/dev/pmemN`; it passes the DAX
  and `MAP_SYNC` checks; data is lost at reboot; not for benchmarks
  [V S27].
* **It proves:** the DAX and `MAP_SYNC` path, fault behaviour, the new
  format, and recovery after a process crash (`kill -9` of ndbmtd), since
  the RAM survives the process [I].
* **It does not prove:** power-fail durability, or that barriers are in the
  right place. After a process crash the CPU caches are still coherent and
  intact, so a missing `clwb` or `sfence` is invisible [I]. Latency is DRAM
  latency, not Optane or CXL [V S27].
* Barrier bugs need power-loss emulation: a test mode where the helper keeps
  a shadow image that receives only flushed-and-fenced lines, plus random
  partial application of unfenced lines at 8-byte granularity, then
  recovery runs on the shadow image [I]. This matches the plan's risk 1.

### 4.7 NUMA

A PMEM region belongs to one socket. Remote Optane writes cost 2.53× [V S1].
On a two-socket node each LDM's log parts should live on its own socket's
PMEM. NDB today places all REDO files under one `FileSystemPath`; a
per-socket path is an open question (§8) [I].

---

## 5. Checksums

### 5.1 What the tree has

| Helper | Algorithm | Hardware | Where |
|---|---|---|---|
| none in NDB | CRC32C | — | grep of `storage/ndb/src`, `storage/ndb/include` finds only a benchmark table row in `include/util/ndb_xxhash.h:76` [V] |
| zlib `crc32()` | CRC-32 (IEEE) | software on x86 [I] | `src/common/util/ndbxfrm_file.cpp:1339` (file checksums) [V] |
| `my_checksum()` | CRC-32 (IEEE), **not** CRC32C | ARMv8 `__crc32d`, zlib on x86 | `include/my_checksum.h:49-126` (repo root) [V] |
| `ut_crc32` | CRC32C | SSE4.2 and ARMv8 | `storage/innobase/include/ut0crc32.h:160-207` (repo root); InnoDB only, not linked by NDB [V] |
| `absl::ComputeCrc32c` | CRC32C | yes | `extra/abseil/abseil-cpp-20230802.1/absl/crc/crc32c.h:89` (repo root); bundled for protobuf (`cmake/protobuf.cmake:80`); NDB does not link it [V] |
| XXH3 | 64-bit hash | SSE2/AVX2 | `include/util/ndb_xxhash.h`, used via `src/common/util/rondb_hash.cpp:41-51` [V] |

A new `include/util/ndb_crc32c.h` of about 40 lines is enough:
`_mm_crc32_u64` under `target("sse4.2")`, `__crc32cd` under `target("+crc")`,
a slicing-by-8 fallback, and a runtime check [I].

### 5.2 Cost of CRC32C on REDO-sized records

The x86 `crc32` instruction has latency 3 and throughput 1 cycle on every
Intel CPU since Nehalem [V S31]. A single dependent chain processes 8 bytes
per 3 cycles. The table assumes 3 GHz and includes ~10 cycles of overhead
[I].

| Record | Bytes | 8-byte steps | Cycles | ≈ ns |
|---|---|---|---|---|
| COMPLETE (3 words) | 12 | 1 + 4-byte tail | ~16 | ~5 |
| COMMIT (13 words) | 52 | 6 + 4-byte tail | ~31 | ~10 |
| One 64-byte unit | 64 | 8 | ~34 | ~11 |
| Header | 128 | 16 | ~58 | ~19 |
| Typical PREPARE | 200 | 25 | ~85 | ~28 |
| Large PREPARE | 1024 | 128 | ~394 serial, ~140 with 3-way interleave [V S31] | ~45–130 |

* ARMv8 `CRC32CX` is a similar single instruction; exact Neoverse timings
  were not verified [I].
* A software slicing-by-8 CRC costs roughly 1–1.5 cycles per byte, about
  60–80 cycles for a COMMIT [I].
* Next to a 100–400 ns persist barrier, the CRC of a COMMIT or COMPLETE is
  1–10 % of the cost [I].

### 5.3 Alternatives

* **XXH3-64** is already in the tree [V]. The xxHash benchmark table in the
  tree rates its "small data velocity" at 133 against 57.9 for SSE4.2
  CRC32C (`include/util/ndb_xxhash.h:59-76`) [V]. So XXH3 may be about 2×
  faster on small records. That saves ~5 ns on a COMMIT, which is noise
  next to the barrier [I].
* For torn-write detection every good 32-bit check gives a 2^-32 false
  accept rate on random garbage [I]. CRC32C has single-instruction support
  on both x86 and ARM, a 32-bit result that fits one word, and is the usual
  choice for storage formats (iSCSI, ext4, btrfs) [I].
* **Recommendation: CRC32C.** XXH3 (truncated to 32 bits) is an acceptable
  alternative if P6 shows the CRC matters.

### 5.4 What the CRC must cover

* The whole record, header included [I].
* A seed made of log part, lap, and the SR restart sequence, so that stale
  records from earlier laps or from before an SR fail (§1.4) [I].
* Standard init and xor-out (`~0`), so all-zero units fail [I].
* The filler record too, so a stale filler is not trusted [I].

---

## 6. Comments on the architect's guidance

| # | Guidance | Assessment |
|---|---|---|
| 1 | Whole-page checksums are not a good idea on PMEM | **Agree, and stronger**: no persisted field may be updated in place. A torn update of a page checksum or fill index can make already acknowledged records unreadable (§1.3, §1.5) |
| 2 | CRC per record, including page headers | **Agree.** Add: the CRC must be seeded with lap and restart sequence, and recovery must stop at the first bad record, because lines persist out of order within a barrier interval (§1.4) |
| 3 | Keep the MByte headers; page GCI fields need thought | **Agree.** Hardware-wise any header written once, in the same persist as the first record it describes, is fine. Today's `ZCURR_PAGE_INDEX` cannot exist in PMEM |
| 4 | Write unit of 64, 128 or 256 bytes; a filler | **Partly agree.** 64 bytes is the only unit that matters on every current device. 128 bytes has no meaning for x86 persistence. 256 bytes helps only Optane media efficiency, which the XPBuffer already gives sequential appends; it would quadruple the padding of a COMPLETE. The filler is not needed to protect persisted bytes, but it pays for itself in performance. **Risk:** making W configurable per installation; it is a format property, so fix it at 64 and record it in the file header |
| 5 | Persist COMMIT and COMPLETE immediately in v1 | **Agree.** Cost: two barriers per operation per log part, plus padding. On ADR Optane a hot LDM at 500 k operations/s would stall ~20 % of its time in `sfence` [I: 500 k × 2 × 200 ns] |

Further risks not in the guidance: `MAP_SYNC` faults (§4.1), bad blocks and
dirty shutdowns (§4.4), no PMEM in clouds (§2), NT stores across LDMs
(§3.6), and REDO encryption, which uses XTS with the 32 KB page as data unit
(`research_redo_log.md` §4) and does not fit 64-byte persists (§8).

---

## 7. Sources

| Id | Source |
|---|---|
| S1 | Yang, Kim, Hoseinzadeh, Izraelevitz, Swanson, "An Empirical Guide to the Behavior and Use of Scalable Persistent Memory", FAST 2020. https://www.usenix.org/conference/fast20/presentation/yang (PDF https://www.usenix.org/system/files/fast20-yang.pdf, preprint https://arxiv.org/abs/1908.03583) |
| S2 | Izraelevitz et al., "Basic Performance Measurements of the Intel Optane DC Persistent Memory Module", 2019. https://arxiv.org/abs/1903.05714 |
| S3 | Xiang, Zhao, Rao, Jiang, Jiang, "Characterizing the Performance of Intel Optane Persistent Memory: A Close Look at its On-DIMM Buffering", EuroSys 2022. https://ranger.uta.edu/~jrao/papers/eurosys22.pdf |
| S4 | Haria, Hill, Swift, "MOD: Minimally Ordered Durable Datastructures for Persistent Memory". https://arxiv.org/abs/1908.11850 |
| S5 | Intel, Persistent Memory FAQ. https://www.intel.com/content/www/us/en/developer/articles/troubleshooting/persistent-memory-faq.html |
| S6 | A. Rudoff, "Partial cache line writebacks", pmem list, 2022-11-06. https://groups.google.com/g/pmem/c/TYBKnfmbMKU |
| S7 | MOVDIR64B (SDM extract). https://www.felixcloutier.com/x86/movdir64b |
| S8 | CLWB (SDM extract). https://www.felixcloutier.com/x86/clwb |
| S9 | "cascade lake doesn't support CLWB?", pmem list. https://groups.google.com/g/pmem/c/DRdYIc70RHc ; also https://groups.google.com/g/pmem/c/P6VV8e7tAgs |
| S10 | Intel PCN 118156 (Optane 200 discontinuance). https://cdrdv2-public.intel.com/799668/PCN118156-00.pdf ; https://www.servethehome.com/intel-optane-100-dimms-product-discontinuance/ ; https://www.3dtested.com/pc-components/ssds/intel-schedules-the-end-of-its-200-series-optane-memory-dimms-shipments-to-draw-to-an-end-in-late-2025 |
| S11 | SMART Modular / Penguin NV-CMM E3.S. https://www.penguinsolutions.com/products/smart-modular/cxl-memory-module-nv-cmm-e3s ; https://www.businesswire.com/news/home/20260114434969/en/Penguin-Solutions-SMART-Modular-CXL-NV-CMM-E3.S-2T-Memory-Module-Achieves-CXL-Compliance ; https://www.nasdaq.com/press-release/smart-modular-technologies-introduces-its-non-volatile-cxl-e3s-memory-module-2025-03 |
| S12 | JEDEC NVDIMM-N JESD245E (DDR4). https://www.jedec.org/taxonomy/term/2458?page=1 ; JEDEC DDR5/NVDIMM-P. https://www.jedec.org/node/8636 ; SMART Modular DDR4 NVDIMM datasheet (2024). https://en.sekorm.com/doc/522935946.html |
| S13 | Samsung CMM-H. https://arxiv.org/abs/2503.22017 ; https://semiconductor.samsung.com/news-events/tech-blog/samsung-cxl-solutions-cmm-h/ |
| S14 | CXL GPF: Oliveira, Gonçalves, Matos, "Rethinking PM Crash Consistency in the CXL Era", 2025, https://arxiv.org/abs/2504.17554 ; CXL Consortium FAQ, https://computeexpresslink.org/blog/questions-from-the-cxl-1-1-vs-cxl-2-0-whats-the-difference-webinar-1135/ ; Rudoff, Douglas, Kasanicky, "Persistent Memory in CXL", SNIA 2021, https://www.snia.org/sites/default/files/PM-Summit/2021/snia-pm-cs-summit-Rudoff-PM-in-CXL-2021.pdf |
| S15 | Linux `drivers/cxl/pmem.c`. https://github.com/torvalds/linux/blob/master/drivers/cxl/pmem.c |
| S16 | Linux `drivers/nvdimm/region_devs.c` and `e820.c`. https://github.com/torvalds/linux/blob/master/drivers/nvdimm/region_devs.c ; https://github.com/torvalds/linux/blob/master/drivers/nvdimm/e820.c |
| S17 | D. Williams, "libnvdimm, nfit: fix persistence domain reporting", 2018. https://lkml.iu.edu/hypermail/linux/kernel/1803.2/06259.html |
| S18 | mmap(2). https://man7.org/linux/man-pages/man2/mmap.2.html |
| S19 | statx(2). https://man7.org/linux/man-pages/man2/statx.2.html |
| S20 | Linux DAX documentation. https://docs.kernel.org/filesystems/dax.html |
| S21 | J. Kara, "dax, ext4: Synchronous page faults" (RFC v2, fault timings), https://lwn.net/Articles/731588/ ; J. Corbet, "Two more approaches to persistent-memory writes", https://lwn.net/Articles/731706/ |
| S22 | P. Gupta, virtio-pmem: disable `MAP_SYNC` for async flush. https://patchwork.kernel.org/comment/22602653 ; https://lkml.iu.edu/hypermail/linux/kernel/1907.0/05235.html |
| S23 | "Update on PMDK and our long term support strategy", 2022. https://pmem.io/blog/2022/11/update-on-pmdk-and-our-long-term-support-strategy/ |
| S24 | https://github.com/pmem/pmdk (archived 2025-11-12) ; https://github.com/daos-stack/pmdk |
| S25 | libpmem2(7) and pmem2_get_persist_fn(3). https://pmem.io/pmdk/manpages/linux/master/libpmem2/libpmem2.7/ ; https://pmem.io/pmdk/manpages/linux/master/libpmem2/pmem2_get_persist_fn.3/ |
| S26 | libpmem2 `auto_flush_linux.c`. https://github.com/daos-stack/pmdk/blob/master/src/libpmem2/auto_flush_linux.c |
| S27 | Emulating PMEM with `memmap=`. https://pmem.io/blog/2016/02/how-to-emulate-persistent-memory/ ; https://docs.pmem.io/persistent-memory/getting-started-guide/creating-development-environments/linux-environments/linux-memmap |
| S28 | Bad blocks. https://pmem.io/blog/2018/11/bad-blocks ; https://pmem.io/pmdk/manpages/linux/v2.0/libpmem2/pmem2_badblock_context_new.3/ |
| S29 | Dirty shutdown count in sysfs (NFIT/PAPR). https://lists.ozlabs.org/pipermail/linuxppc-dev/2021-May/229756.html |
| S30 | Intel, "Optimizing Write Ahead Logging with Intel Optane Persistent Memory", 2020. https://www.intel.com/content/www/us/en/developer/articles/technical/optimizing-write-ahead-logging-with-intel-optane-persistent-memory.html |
| S31 | CRC32 instruction timing. https://www.corsix.org/content/fast-crc32c-4k ; https://uops.info/html-instr/CRC32_R64_R64.html |
| S32 | ARM DC CVAP/CVADP in Linux. https://mailweb.openeuler.org/archives/list/kernel@openeuler.org/thread/MTHQIIUYRZXTEEWMDH47T5GGCCQDPQH4/ ; https://github.com/torvalds/linux/blob/master/arch/arm64/mm/flush.c ; https://github.com/torvalds/linux/blob/master/arch/arm64/include/asm/barrier.h |
| S33 | CXL memory latency. https://arxiv.org/abs/2409.14317 ; https://people.cs.vt.edu/jinshu/docs/slides/Melody-ASPLOS25-split.pdf |
| S34 | eADR and fences. https://community.intel.com/t5/Intel-Optane-Persistent-Memory/Extended-Asynchronous-DRAM-Refresh-eADR-DRAM-Intel-Optane/m-p/1523265 ; https://groups.google.com/g/pmem/c/SXt7zKExbpU ; https://groups.google.com/g/pmem/c/_DJCFGylfVE ; https://hn.svelte.dev/item/44860847 |
| S35 | A. Rudoff, "8 byte atomicity & larger store operations", pmem list. https://groups.google.com/g/pmem/c/6_5daOuEI00 ; https://groups.google.com/g/pmem/c/MpBbJ13k3VQ |
| S36 | Google Cloud Optane alpha, 2018. https://atmarkit.itmedia.co.jp/ait/articles/1811/01/news087.html ; Broadcom, vSphere support for Optane PMem. https://knowledge.broadcom.com/external/article/326910/vspherevsan-support-for-intels-optane-pe.html |

---

## 8. Open questions

1. **Which hardware will RonDB customers run?** Optane installed base,
   DDR4 NVDIMM-N, or CXL NV-CMM. The answer decides what P6 must benchmark.
   Do any CXL 2.0 hosts implement GPF fully for persistent devices?
2. **NT stores versus `clwb` for cold 64-byte log units.** Not measured in
   the sources. Needs a P6 microbenchmark per platform (§3.5).
3. **Per-socket REDO placement.** NDB has one `FileSystemPath` for REDO.
   Does a two-socket node need a per-log-part or per-LDM path?
4. **REDO encryption** (`EncryptedFileSystem`, XTS with 32 KB data units)
   on PMEM: drop it for the PMEM format, or encrypt per 64-byte unit?
5. **Dirty shutdown policy.** Is "the durable tail is not trustworthy, act as
   a stale node for the tail" acceptable to the SR design
   (`pmem_redo_recovery.md`)?
6. **Emulated PMEM for MTR.** What config name allows a `memmap=` region with
   an empty `persistence_domain` while D8 refuses it in production?
7. **ARM.** Is ARM in scope for durable commits at all, given no ARM PMEM
   hardware was found?
8. **Space.** With W = 64 and immediate persists, each operation uses at
   least 128 bytes for COMMIT + COMPLETE, against 36 bytes for today's
   COMMIT. Does the REDO sizing guidance (`FragmentLogFileSize`,
   `NoOfFragmentLogFiles`) need a new rule?

---

## 9. Recommendations

1. **W = 64 bytes, fixed.** Store it in the file header as a format field,
   so a later version could test 256 on Optane. Do not detect it and do not
   make it a config variable: no OS interface reports a media write unit
   [I], and it changes the format.
2. **Records 8-byte aligned.** The smallest gap is then 8 bytes, so a filler
   header always fits. COMMIT (52 bytes) plus a 4-byte CRC is exactly 56
   bytes; COMPLETE (12 bytes) plus CRC is 16 bytes [I; format is for
   `pmem_redo_format.md`].
3. **A filler at every persist point**, padding to the next 64-byte boundary.
   It is a normal record with its own CRC. Reason: performance and a simple
   scan, not protection of persisted bytes (§1.3).
4. **Write-once.** No persisted byte that an acknowledged record depends on
   is rewritten before the ring wraps (§1.5).
5. **Flush approach in v1** (every COMMIT and COMPLETE persisted at once):
   * build records in the DRAM log page as today;
   * at a persist point, copy the new bytes, padded by the filler, to PMEM
     as whole 64-byte non-temporal stores (or `MOVDIR64B`), then `sfence`;
   * the same sequence on ADR, eADR and CXL; on ARM use stores +
     `DC CVAP` per line + `DSB`;
   * keep store + `clwb` + `sfence` as an alternative behind a switch and
     choose per platform in P6;
   * a thread that used NT stores executes `sfence` before releasing
     `m_log_part_mutex` (§3.6).
6. **Platform checks:** `MAP_SYNC` at start (D8); barrier mode from
   `persistence_domain`, empty treated as ADR and refused unless an
   emulation test setting is on (§4.3); files fully written and prefaulted
   (§4.1); dirty shutdown count recorded and checked, bad blocks checked or
   `pread()` used in the recovery scan (§4.4).
7. **CRC32C** in a new `include/util/ndb_crc32c.h`, seeded with log part,
   lap and restart sequence (§5). **Own PMEM helper** instead of libpmem2,
   with a power-loss emulation mode for tests (§4.5, §4.6).
8. **Expected latency per persist** (one or two 64-byte units, CRC
    included) [I, from §3.3]:

    | Platform | COMMIT persist | COMPLETE persist |
    |---|---|---|
    | eADR (Optane 200 with eADR) | ~20–60 ns | ~20–60 ns |
    | NVDIMM-N (DDR4, ADR) | ~90–150 ns | ~90–150 ns |
    | Optane 100/200, ADR | ~100–350 ns typical; ~1 µs if a line is re-persisted; rare 50 µs | same |
    | CXL NV-CMM (`memory_controller`) | ~250–600 ns | ~250–600 ns |
    | `memmap=` emulation | DRAM speed; not representative | same |

    The plan's C3 ("well under a microsecond") holds for the median on all
    of these, not for Optane's tail.
9. **Adaptive scheme later (brief).** "Flush early, fence late": issue the
    NT stores or `clwb` as each record is written, and execute one `sfence`
    per LDM scheduler round, just before the thread sends the signals that
    depend on persistence (COMMITTED, COMPLETED, the ack to TC). Under load
    one fence then covers many records; at low load the fence comes at once.
    Track a per-log-part persisted offset so that a waiter whose range is
    already covered skips the fence. This needs a check of the send path in
    `vm/mt.cpp` [I].
