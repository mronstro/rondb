# RONDB-1150 step 1: the REDO log on persistent memory

Status: **design, 2026-10-28, with the architect's answers to Q1–Q8 folded
in (§5). No code has been changed.** This is the
deliverable of planning subtask P2 and the design for execution phase X2,
the first implementation step. It consolidates four notes written in
parallel and settles where they disagree:

| Note | Content |
|---|---|
| `research_pmem_hardware.md` | Failure atomicity, devices available in 2026, flush instructions and their cost, Linux DAX interfaces, CRC32C cost |
| `pmem_redo_format.md` | Record framing and checksum, page header, layouts of every record type, FILLER, space reservation and overhead, `redoLogReader` |
| `pmem_redo_recovery.md` | Today's head and tail search traced through the code, what breaks on PMEM, the end-of-log rule, invalidation, node restart |
| `pmem_redo_write_path.md` | Mapping the files, the persist primitive, barrier placement, FILLER cost, shared log parts, mbyte and file switch, GCP save, config |

All paths are relative to `storage/ndb/`. Where a decision below rests on
one note, the reference says so; the notes hold the `file:line` evidence.

---

## 0. The architect's guidance for this step

1. PMEM differs from files. Writing 32 KB pages is not an efficient use of
   PMEM, so checksums on whole pages are likely not a good idea.
2. Writes to PMEM can still be half-baked, so put a checksum on each REDO
   record, including the page headers.
3. The recovery code that finds the head and tail must still work: keep the
   MByte headers; the page GCI may need some thought.
4. The minimum write size should fit the hardware, likely 64, 128 or
   256 bytes, with a FILLER record when a unit cannot be filled.
5. Persist COMMIT and COMPLETE immediately if that is efficient, otherwise
   adaptively. **In the first iteration they are always persisted
   immediately**; optimisation comes later.

All four notes confirm points 1, 2, 3 and 5. Point 4 is refined (E2).
They add four things the guidance did not cover, each needed for
correctness (E4, E9, E10, E12).

---

## 1. Decisions

### E1. Keep the geometry and the recovery structure

- Files, 1 MB mbytes, 32 KB pages with a header on every page, the FD
  record in page 0 of every file. The restart's phase 1 → 3 → 4 structure
  and the mbyte-header search (`srLogLimits`) stay (recovery §1, §11).
- Recovery reads few header fields: the lap of every page, the GCI fields
  and the last-prepare reference of the first page of each mbyte, and two
  words of page 0 of file 0. Their meaning survives incremental
  persistence (recovery §1.6, §2.3).
- Correction of an earlier assumption: the FD page is **not** rewritten at
  every mbyte switch. `writeFileDescriptor` only updates memory; page 0 of
  each file is written once per lap. Only page 0 of file 0 is rewritten in
  place today (recovery §0).

### E2. Write unit W = 64 bytes, fixed (settled, Q3)

- Only an aligned 8-byte store is failure-atomic on x86. A 64-byte line is
  "very likely" but not guaranteed to persist as a unit; `MOVDIR64B` is the
  exception. Optane's 256-byte XPLine is internal to the DIMM, not a unit
  software can rely on (hardware §1.1).
- 64 is the flush granularity. 128 has no meaning for x86 persistence.
  256 would quadruple the padding of a COMPLETE and roughly double the REDO
  volume of small operations (format §8, write path §4.3).
- W is a compile-time constant recorded in every page header, not a config
  variable and not detected: it changes the format, and no OS interface
  reports a media write unit. A later version can test 256 on Optane.

### E3. Record framing

Every record is 8-byte aligned, has an even length in words, and starts
with two words (format §3):

| Word | Content |
|---|---|
| `w0` | type (bits 0–7), flags (8–15), length in words (16–31) |
| `w1` | CRC32C |

Type 0 is unwritten memory and means "no record here". An old-format
reader stops at the first record ("Invalid logword"), so the formats cannot
be mixed by accident.

### E4. What the checksum covers (needed for correctness)

```
CRC32C( (w0 without the RF_INVALIDATED bit) || w2 .. w(len-1) || S )
S = [ lap, 0 (reserved), (logPartNo << 16) | fileNo, pageNo * 8192 + pageIndex ]
```

- `S` is 16 bytes and is never stored. The reader knows it from the
  position and from the page header.
- **Why:** a plain per-record CRC is not enough. Fillers make record starts
  recur at the same offsets in every lap, so an intact record from the
  previous lap is likely to sit right where the log now ends. Binding the
  CRC to lap, part, file and position rejects it at no space cost. All three
  code-reading notes reached this independently (format §3.3, recovery
  §3.2, write path R-1), and the hardware note agrees (§5.4).
- Page headers inside a spanning record are skipped by the record's CRC;
  they carry their own. A record is valid only if every page header it
  crosses is valid with the same lap (format §6.2).
- Every record has a CRC, including FILLER (header only), NEXT_MBYTE, FD and
  COMPLETED_GCI. A stale 1-word NEXT_MBYTE from the previous lap would
  otherwise let the scan jump over garbage (recovery §11).
- The second word of `S` is reserved for a restart generation (E12) and is
  0 in iteration 1.

### E5. The page header: written once, never updated

- Written at page init with a CRC32C over words 1–31, and never updated
  (format §4).
- **Unchanged and write-once:** lap, max GCI completed, max GCI started,
  last prepare reference, version, number of files, number of log parts.
- **Page GCI.** Words 2 and 3 are snapshots taken when the page starts.
  They are lower bounds, which is exactly what `srLogLimits` needs, so they
  need no update and keep their meaning (format §4.3, recovery §2.3).
- **Moved to DRAM** (0 on PMEM): the fill index `ZCURR_PAGE_INDEX`, the page
  links, the dirty flag and the per-write debug words 12–20. Recovery never
  reads the fill index from disk; it walks the records.
- **New fields:** format magic, log part number, W, node id, and the page's
  own page and file number (identity).
- A restart must **not** re-initialise the header of the head page, as it
  does today (`DblqhMain.cpp:40525`): a torn rewrite would invalidate the
  records already in that page (recovery §2.3).
- The write path stages pages in DRAM. Its first copy of each page writes
  the clean PMEM header image, not the DRAM header with its fill index and
  links (format §11.4).

### E6. FILLER at every persist point

- At each persist point the writer pads to the next 64-byte boundary with a
  FILLER record (2 + n words; the CRC covers only its header). At the end of
  an mbyte, NEXT_MBYTE closes the unit instead (format §7).
- So a persisted 64-byte unit is never written again in that lap, except by
  the two deliberate atomic stores of E9 and E10.
- **Why:** rewriting a partly persisted unit is safe on every known device
  (hardware §1.3), so the filler is not needed for correctness. It is kept
  for performance and simplicity: the copy never reads PMEM, every unit is
  written whole with non-temporal stores, the same line is never flushed
  twice (on Cascade Lake `clwb` evicts the line), and correctness does not
  depend on how a device handles a torn rewrite.
- Because records are 8-byte aligned with even lengths, a gap is never one
  word, so a FILLER always fits.

### E7. Write path: build in DRAM, copy out at persist points

- Records are built in DRAM log pages as today, so the record writers and
  the position fields stay. `currentLogpage` does not point into PMEM
  (write path §2.3).
- At a persist point the new bytes plus the FILLER are copied to the
  mapping as whole 64-byte non-temporal stores (or `MOVDIR64B`), followed by
  `sfence`. The same code works on ADR, eADR and CXL. Store + `clwb` +
  `sfence` is kept behind a switch and chosen per platform by a benchmark
  (P6). On ARM: stores, `DC CVAP` per line, `DSB` (hardware §9).
- **One primitive**, `redoPersist(part)`, called with the log-part mutex
  held: pad, copy, `sfence`, advance the part's persisted position. Each
  operation keeps the end position of its last record that must be
  persistent. `redoPersistOp(op)` persists only if that position is beyond
  the part's persisted position (write path §2.4).
- **Every copy is fenced by the thread that made it before the mutex is
  released**, page-full copies included. A fence on one core does not drain
  another core's write-combining buffers; without this, one LDM's fence
  could advance the persisted position over another LDM's copies that have
  not reached PMEM.
- Pages are never copied in the middle of a record (an end-of-record hook
  copies filled pages), so the CRC can be finished before any byte of the
  record is copied.
- **Debug check:** in durable mode, assert at every send that depends on
  persistence (COMMITTED, COMPLETED, forwarded COMMIT/COMPLETE, the
  COMMITCONF/COMPLETECONF paths) and at the start of `localCommitLab` that
  the operation's end position is persisted.

### E8. Where the barriers go (C, K, F)

**The rule (settled, Q1):** the COMMIT or COMPLETE record is persisted as
part of handling the COMMIT or COMPLETE signal, and **before the next
COMMIT, COMMITTED, COMPLETE or COMPLETED signal is sent**. This holds
always: a later optimisation may delay the sync, but then it delays the
signal too; a dependent signal is never sent before its record is
persistent. A local commit (TUP real commit, ACC lock release) also comes
after the barrier. One barrier covers every record written while handling
the signal (write path §3).

| Path | Barrier | Invariant |
|---|---|---|
| `commitReqLab` | After TUP's `TUP_WRITELOG_REQ` loop over the operations on the row, before the branch at `DblqhMain.cpp:15267` | C |
| Queued commit, `handle_queued_log_write` | After `writeCommitLog` (`912`), before the unlock | C |
| Dirty write, `doWritePrepareLog` | Once for PREPARE + COMMIT + COMPLETE, before the unlock at `13579` | C, K |
| `execCOMPLETE` | New `writeCompleteLog` + barrier before the branch at `15004` | K |
| `execCOMPLETEREQ` | Same, before the branch at `15120` | K |
| ABORT after COMMIT | `writeAbortLog` with `AF_AFTER_COMMIT` + barrier before the lock is released | F |
| Abort of a prepared operation | None: a PREPARE without a COMMIT is never applied | — |

The barriers run only for durable transactions (GCI ≥ g). They arrive with
X4; step 1 provides the primitive (S5 adds a benchmark switch to persist
every COMMIT early, so the cost can be measured before X4).

### E9. COMMIT invalidation: one atomic store (needed for correctness)

- Today a COMMIT above the restart GCI is rewritten to type 9. With a
  per-record CRC that would make the record invalid, and since the log ends
  at the first invalid record, **everything after it would be lost**
  (recovery §2.4, write path R-5).
- So: a flag bit `RF_INVALIDATED` in `w0`, excluded from the CRC, set by one
  aligned 4-byte store, then flush and fence. The record stays valid and is
  read as invalidated. Type 9 is retired (format §5.2).
- Used both by today's non-durable invalidation and by phase 2 step C of the
  durable restart (plan §5.2).

### E10. "Last file in use": two checksummed slots (needed for correctness)

- Today a word in page 0 of file 0 is rewritten in place at every file
  change, lap change and restart end.
- The three notes proposed three answers. Decision: **two slots
  `{seq64, lastFileNo, lap, crc}` in a control area**, each in its own
  64-byte line (recovery §2.4). Write the slot `seq & 1` with seq + 1, flush,
  fence. Read both and use the valid one with the higher seq; if neither is
  valid, stop with a clear message.
- **Where:** the last 256 bytes of page 0 of file 0 (at least 124 words
  are unused after the FD record). The lap-change rewrite of that page
  writes only the header and the FD record, never the control area.
- **Rejected:**
  - *Drop the word and find the last file from the page-0 headers of all
    files* (format §4.3): this breaks when a restart moves the head back,
    because later files keep page-0 headers of the current lap.
  - *One aligned store into the FD record* (write path §6.2): the FD record
    now has a CRC, which that store would break.
- The control area also holds static configuration (magic, version, number
  of parts and files, file size, W) for a start-up check.

### E11. End of log

- A scan runs forward from the first record of an mbyte. A position is
  valid if the page header passes (CRC, lap, file, page, part), the type and
  length are within bounds and the record ends inside the mbyte, every
  spanned page passes, the CRC matches, and the structure holds (FD only at
  word 32 of page 0, FILLER ends on a W boundary, nothing after NEXT_MBYTE).
  **E is the first position that is not valid** (recovery §3.2).
- Phase 1 finds E exactly by scanning only the last mbyte (≤ 1 MB). Every
  later scan stops at E.
- **The REDO is always recoverable.** If some of the last writes did not
  reach PMEM, or were torn, the checksums cut them off: the log ends at E,
  and everything before E is a valid log. No state of the tail makes a
  restart fail.
- **An invalid record before E stops the node** with a clear message. This
  can only happen if a later scan disagrees with phase 1, that is, if the
  media changed during the restart. The log is never shortened silently.
- Lines persist in any order between two barriers, so after a crash a valid
  record can follow an invalid one. Recovery never skips a bad record: the
  barrier covers a contiguous range, so nothing after the first bad record
  was acknowledged (hardware §1.4).

### E12. Invalidation by zeroing (needed for correctness)

- The CRC rejects torn data and data from the previous lap. It does **not**
  reject records of the current lap left after a hole (an ADR eviction or a
  torn copy), or the abandoned region when a restart moves the head back.
  If writing resumes and a later crash ends the log exactly on an old record
  boundary, the scan would continue into those records (recovery §4.1).
- **Zero `[E, end of mbyte(E))` in phase 1 of every restart.** That is
  enough because no persist crosses an mbyte boundary and NEXT_MBYTE is
  fenced before any byte of the next mbyte is stored (W2).
- **When the head moves back to H** (node restart; system restart without
  durable commits), zero `[H, E)` backwards in phase 4, page 0 of each file
  excepted, and write the last-file slot last.
- **Durable-mode SR never moves the head back.** It writes the SR-head
  record and `COMPLETED_GCI(G')` at E after the zeroing (plan §5.3).
- Zeroing is `memset` + flush + fence, idempotent, and takes about a
  millisecond per MB. The order keeps every crash point repeatable
  (recovery §4.3).
- **Rejected for iteration 1:** a restart generation in the CRC seed with
  writing resumed at a fresh mbyte (format §4.4). It would make zeroing
  optional, but zeroing is cheap and keeps today's structure. The seed word
  stays reserved.

### E13. Record layouts

Sizes in 32-bit words, including `w0` and `w1` (format §5):

| Record | Type | Size | Notes |
|---|---|---|---|
| PREPARE | 1 | 8 + key + attrinfo, rounded up to even | Header stays 8 words: the length moves into `w0`, the CRC takes the old length slot. Flag `PF_TRANSID` (2 more words) reserved, off in iteration 1 |
| COMMIT | 2 | 12 | tableId, schemaVersion, fragId, prepare reference packed into 2 words (all four fields are `Uint16`), gci_hi, gci_lo, transid1, transid2, opCount. Flags `CF_DURABLE`, `RF_INVALIDATED` |
| COMPLETE | 11 | 4 | transid1, transid2 |
| ABORT | 3 | 4 | transid1, transid2. Flag `AF_AFTER_COMMIT` for rule F, so an `IgnoreError` abort of one operation does not veto the phase-2 fallback |
| COMPLETED_GCI | 8 | 4 | gci, pad |
| NEXT_MBYTE | 7 | 2 | Uses today's 2-word `ZNEXT_LOG_SIZE` reserve |
| FILLER | 10 | 2 + n | Pads to the next W boundary, or to the page end after the FD |
| FD | 4 | 4 + 3·nFD·fileSizeMb (+ pad) | At word 32 of page 0, followed by a FILLER to the page end |
| SR_HEAD | 12 | 6 | R_gcp, G', restart sequence (content owned by P4) |
| NEXT_LOG_RECORD, INVALID_COMMIT | 6, 9 | — | Retired |

- **Space reservation per operation:** COMMIT + max(COMPLETE, ABORT) + two
  FILLERs = `12 + 4 + 2·(W/4 − 2) + 2` = 46 words at W = 64, against 10
  today. Released in two steps: at COMMIT and at COMPLETE or rule-F ABORT
  (format §7.3).
- Side finding: a PREPARE can span 4 pages, not 3 (22096 attrinfo words
  plus 1023 key words); `ZMIN_READ_BUFFER_SIZE = 3` and its comment are
  stale (format §6.3).

### E14. Mapping the files

- NDBFS opens and maps each REDO file with a new open flag `OM_MAP_SYNC`
  through a new portlib helper (`ndb_pmem`): `mmap` with
  `MAP_SHARED_VALIDATE | MAP_SYNC`, then prefault the whole range for
  write. FSOPENCONF returns the address; DBLQH keeps it in `LogFileRecord`
  (write path §2.1).
- All files of every part are mapped once at start and stay mapped. No file
  is opened at run time.
- **`MAP_SYNC` failing (`EOPNOTSUPP`) means the file is not on DAX.** That
  is the start-up check of D8.
- Files are fully written at initial start (force
  `InitFragmentLogFiles=full`) and prefaulted at start: write faults on a
  `MAP_SYNC` mapping cost about 100 µs each (hardware §4.1).
- Recovery reads by copying from the mapping into the existing DRAM
  buffers, so the parser stays unchanged and the mapping is written only by
  the explicit updates of E9, E10 and E12 (recovery §11).

### E15. What disappears and what changes in PMEM mode

| Today | PMEM mode |
|---|---|
| FSWRITEREQ/FSWRITECONF and LFOs for REDO writes, 8-page batching | Gone; `redoPersist` copies |
| `timeSup` partial-page rewrites at every GCP save | Gone; a unit is persisted once |
| `checkGcpCompleted`, FSSYNCREQ | GCP_SAVEREQ = COMPLETED_GCI + `redoPersist` per part, GCP_SAVECONF in the same signal |
| File-change state machine, `P_FILE_CHANGE_PROBLEM`, `P_REDO_IO_PROBLEM` | File switch is synchronous: end of the old file, new FD, slot, each with a barrier |
| RedoBuffer of up to 64 MB per part, buffer-full queueing, error 1221 | No REDO log buffer: about 8 staging pages per part plus what SR needs. Pages are copied out and released at the end of the record that fills them, so the buffer cannot fill |
| REDO log space short (`P_TAIL_PROBLEM`) | As today: the operation aborts with 410, no queueing (settled, Q7) |

**REDO-full behaviour (Q7).** Do what is done today: with no REDO log
buffer, an operation that cannot be logged aborts. A buffer would allow
some operations to be queued, but aborting is simpler and is the choice for
PMEM mode. The queueing code stays for file mode.

**Without durable commits** (memory-mapped REDO on, durable commits off):
persist at GCP save, mbyte switch, file switch and page full. That keeps
today's durability: a GCI is durable once it is GCP-saved.

### E16. The durable restart on this layout

- The first COMMIT with GCI > R_gcp can come **before**
  `COMPLETED_GCI(R_gcp)` in the log, so phase 2 step A cannot start there
  (recovery §6).
- **Settled (Q2): both phases run in one scan.** Step A runs inside
  today's execution scan, which already starts at the start mbyte for
  `logStartGci = R_gcp + 1`. COMMITs with GCI ≤ R_gcp are executed as
  today; COMMITs with GCI > R_gcp (and ≥ g) go to the hash table. The scan
  continues past `COMPLETED_GCI(R_gcp)` to E. Step B's rescan starts at the
  same position.
- The ordering argument of plan §6 makes this safe: a later writer of a
  row never has a lower GCI.

### E17. Platform checks at start

| Check | Action |
|---|---|
| `MAP_SYNC` fails | Not DAX: refuse to start when durable commits are configured (D8) |
| `persistence_domain` | `cpu_cache` → eADR; `memory_controller` → ADR (CXL always reports this); empty (`memmap=` emulation) → refuse unless a test setting is on |
| Dirty-shutdown count | Record it in the control area. If the device reports an unsafe shutdown since, the node's REDO is still read up to its valid end E (the checksums cut off lost or torn writes), but writes already acknowledged as persistent may be missing, so the node is **reported stale** for the durable tail (Q4): it stays out of the restart and joins by node restart. How the flag is read, and whether it means lost acknowledged writes, is device-specific and is verified per device in P6 |
| Bad blocks | Check the device's bad-block list before the scan, or read with `pread()`; touching a bad block through the mapping kills the process with SIGBUS |
| `EncryptedFileSystem` | Refuse PMEM REDO in the first version (settled, Q5): XTS works on 32 KB units, which cannot be persisted line by line |
| NUMA placement | Warn if a log part's file is not on the memory node closest to the LDM that owns the part (E20) |
| `Diskless` | Refuse |
| Control area | Magic, version, part and file counts, file size and W must match the config |

### E18. Libraries

- **CRC32C:** NDB has none. `my_checksum.h` is IEEE CRC-32; InnoDB's
  `ut_crc32` and abseil's CRC32C exist in the tree but NDB links neither.
  Add `ndb_crc32c` (port of InnoDB's hardware path: SSE4.2 and ARMv8). Cost
  is about 5 ns per COMPLETE and 10 ns per COMMIT, which is noise next to
  the barrier (hardware §5).
- **Flush and fence:** PMDK was archived on 2025-11-12. Carry a small
  helper of our own (about 200 lines) with a power-loss emulation mode for
  tests.
- **CPU features:** real detection is needed for `clwb`, `MOVDIR64B` and
  the CRC instructions. Side finding: `is_avx2_supported()` always returns
  0 (`src/common/portlib/NdbHW.cpp:56,507`).

### E19. Configuration

- `RedoLogMode = file | pmem`: the memory-mapped REDO variable of
  conclusion 2 (names to be decided). Changing it needs an initial node
  restart.
- `FileSystemPathRedoLog`: the REDO can only live under `FileSystemPath`
  today; PMEM needs its own path. It takes one path per NUMA node, for the
  placement of E20.
- ndbinfo: barriers, bytes copied, filler bytes and a persist-latency
  histogram per part, next to `logspaces` and `logbuffers`.

### E20. Each log part on the closest persistent memory (settled, Q8)

- Each log part's files go on the persistent memory closest to the LDM
  thread that owns the part: the CXL module, or PMEM region, attached to
  that LDM's NUMA node. Remote persists cost more, and CXL modules attach
  per socket.
- The owner of part p is LDM worker `p % numLDM`
  (`research_redo_log.md` §1.1). Its NUMA node comes from the CPUs the
  thread is bound to (thread configuration, or the automatic thread
  configuration).
- `FileSystemPathRedoLog` takes one path per NUMA node; part p's files are
  created under the path of its owner's node. When several LDMs share a part
  (parts not a multiple of LDMs), the owning LDM decides.
- If an LDM is not bound to CPUs, or a node has no path, use the first path
  and warn. At start, check the memory node of each mapping (for example
  with `get_mempolicy` or `move_pages` in query mode) and warn on a
  mismatch.

---

## 2. Cost

**Space per replica** for one write operation, durable mode, COMMIT and
COMPLETE each persisted at once (format §8):

| Update | Today | W = 64 | W = 128 | W = 256 | No fillers |
|---|---|---|---|---|---|
| Small (2 key + 10 attrinfo words) | 116 B | 192 B (1.66×) | 256 B (2.21×) | 512 B (4.41×) | 144 B |
| Large (100 attrinfo words) | 476 B | 576 B | 640 B | 768 B | 504 B |

The default REDO size (16 files × 1 GB per part) can stay; document the
multiplier and report filler bytes in ndbinfo.

**Latency per persist** (one or two 64-byte units, published figures, not
measured here; hardware §9):

| Platform | Per persist |
|---|---|
| **CXL 2.0 persistent memory module (target, Q6)** | **~200–2000 ns** (architect's figure) |
| eADR | ~20–60 ns |
| NVDIMM-N (DDR4, ADR) | ~90–150 ns |
| Optane 100/200, ADR | ~100–350 ns typical; ~1 µs if a line is re-persisted; rare 50 µs outliers |

**On the target hardware:**
- Linux reports CXL persistent memory as `memory_controller`, so flushes
  are needed: non-temporal stores + `sfence` is the default barrier mode.
- Each write operation persists twice per replica, so about **0.4–4 µs of
  LDM time per write operation per replica**, almost all of it `sfence`
  stalls.
- **Commit latency.** The COMMIT and COMPLETE barriers are on the critical
  path at every replica of the linear chain: 2R persists in series, so
  0.8–8 µs more per transaction with 2 replicas. That is small next to the
  message rounds.
- **Throughput.** A hot LDM at 200k write operations per second would spend
  8–80 % of its time in `sfence`. The adaptive scheme (§4) is therefore
  more than an optimisation on this hardware; it is the expected second
  iteration.
- Constraint C3 ("well under a microsecond") does not hold for the upper
  half of this range. The design does not depend on it; only the cost does.
- Functional tests of the CXL path (region set-up, `persistence_domain`,
  `MAP_SYNC`) can use QEMU's emulated CXL Type 3 device with a persistent
  memory backend; performance needs the real modules.

**Hardware in 2026** (hardware §2): Optane's last shipments were in
December 2025. NVDIMM-N exists only for DDR4. The new option is CXL
non-volatile memory (for example SMART/Penguin NV-CMM, which passed CXL
compliance in January 2026); Linux reports it as `memory_controller`, so
flushes are needed. No mainstream cloud offering was found, and virtio-pmem
refuses `MAP_SYNC`, so the feature runs on bare metal.

---

## 3. Implementation steps

Execution phase X2 split into steps. Each ends in something that can be
tested on its own.

| Step | Content | Test |
|---|---|---|
| **S1** | portlib: `ndb_crc32c`; `ndb_pmem` (map, prefault, non-temporal copy, `clwb`, `sfence`, ARM variant, power-loss emulation mode); CPU feature detection | Unit tests: CRC vectors, copy and persist on a plain file, emulation that keeps only what was fenced |
| **S2** | Config: `RedoLogMode`, `FileSystemPathRedoLog` with one path per NUMA node (E20), the refusals of E17; ndbinfo counters | Config unit tests; refusal messages |
| **S3** | NDBFS: `OM_MAP_SYNC`, address in FSOPENCONF, full initialisation of the files at initial start in the new format | Initial start on `memmap=` PMEM; refusal on a non-DAX path |
| **S4** | Record writers: common header and CRC, write-once page header, FILLER, NEXT_MBYTE, FD, COMMIT (12 words; transid, gci_lo, opCount filled with what LQH has, opCount = 0 until X4), ABORT, COMPLETED_GCI, space reservation | Unit tests of each layout; `redoLogReader` reads them (S6) |
| **S5** | Write path: `redoPersist`, copy-out from staging pages, bypass of LFOs, FSWRITEREQ, `timeSup` and the file-change state machine; GCP save; mbyte and file switch; persist rules without durable commits (E15). A benchmark switch that persists every COMMIT at once (E8) | Traffic plus `kill -9` and restart on `memmap=` PMEM; persist-latency histogram |
| **S6** | Recovery: header and record validity, end E in phase 1, slots (E10), zeroing (E12), reading through the mapping, `execSr` on the new types, no head-page re-init, node restart path; `redoLogReader` for the new format | Synthetic logs with torn, stale-lap and orphan records; SR and NR in MTR and autotest |
| **S7** | Power-loss testing: an ERROR_INSERT that copies a random subset of the lines of the last copy and then crashes; the emulation mode of S1; a checker of acknowledged writes | Repeated crash and restart with zero lost GCP-saved data |

```
S1 ── S3 ── S4 ── S5 ── S6 ── S7
S2 ───────────────┘
```

After S7 the REDO runs on PMEM with today's durability (GCP-based). The
durable-commit protocol (X4) and the restart phase 2 (X5) build on it.

**Tests on `memmap=` emulation** prove the format, the write path and the
recovery logic, and survive `kill -9` because the pages stay in RAM. They
can never catch a missing barrier; only the power-loss emulation of S1 and
S7 can (hardware §4.6).

---

## 4. Later: an adaptive scheme (outline)

"Flush early, fence late": issue the non-temporal stores as each record is
written, and execute one `sfence` per log part per LDM scheduler round,
just before the thread sends the signals that depend on persistence
(COMMIT, COMMITTED, COMPLETE, COMPLETED). Under load one fence covers many
records and fewer fillers are written; at low load the fence comes at once.

The Q1 rule still holds: delaying the sync means holding back the
dependent signals until the fence is done. No dependent signal is ever
sent before its record is persistent.
First try one barrier per `execPACKED_SIGNAL`, then one per round at
`execSEND_PACKED` (write path §8, hardware §9). The send path in
`vm/mt.cpp` must be checked first.

---

## 5. Questions for the architect

| # | Question | Status |
|---|---|---|
| Q1 | What does "persist immediately" mean? | **Answered:** as part of handling the COMMIT or COMPLETE signal, before the COMMIT, COMMITTED, COMPLETE or COMPLETED signal is sent; always before the signal is sent, even when later changes delay the sync (E8, §4) |
| Q2 | Run phase 2 step A inside today's execution scan? | **Answered:** yes, both phases in one scan (E16) |
| Q3 | W fixed at 64? | **Answered:** yes (E2) |
| Q4 | What to do when the device reports an unsafe shutdown | **Answered:** report the node as stale; how the flag is read and what it means is device-specific. The REDO itself must always be recoverable, with the checksums protecting against failed last writes (E11, E17) |
| Q5 | Refuse PMEM REDO with `EncryptedFileSystem` in iteration 1? | **Answered:** yes, refused in the first version (E17) |
| Q6 | Which PMEM hardware is the target? | **Answered:** no specific product; CXL 2.0 persistent memory modules with 200–2000 ns latency first (§2) |
| Q7 | REDO full in PMEM mode: abort the operation instead of queueing it? | **Answered:** do as today. With no REDO log buffer the operation aborts; a buffer would allow some queueing, but simply aborting is best (E15) |
| Q8 | NUMA: should each log part's files sit on the PMEM of the socket that runs its LDM? | **Answered:** yes, use the closest memory (E20) |
