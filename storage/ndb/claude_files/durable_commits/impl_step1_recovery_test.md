# RONDB-1150 step 1: recovery (S6), power-loss testing (S7), and the test plan

Status: implementation plan, 2026-10-28. Planning only; no code changed.
Input: `pmem_redo_design.md` (E1–E20, S1–S7, §5), `durable_commits_plan.md`
rev 9, `pmem_redo_recovery.md`, `pmem_redo_format.md`,
`research_pmem_hardware.md`. Sibling plans written in parallel:
`impl_step1_platform.md` (S1–S3), `impl_step1_lqh_write.md` (S4–S5),
`impl_next_steps.md`.

Conventions:
- Paths are relative to `storage/ndb/`. `DblqhMain.cpp` and `Dblqh.hpp` are
  in `src/kernel/blocks/dblqh/`; `DbdihMain.cpp` in `src/kernel/blocks/dbdih/`.
- [V] = verified by reading the code at `bf6848d754f`; [I] = inferred.
- Line numbers are those of today's tree; they move once S4/S5 land.
- Position p = (fileNo, pageNo, pageIndex) in a log part. E = end of the
  valid log (E11). H = position right after `COMPLETED_GCI(R)` (today's head).
  `ceilW(p)` = next 64-byte boundary at or after p.

---

## 0. Summary

- **Step 1 keeps today's restart semantics on PMEM**: phase 1 finds the
  last file and mbyte, and now also the exact end E; phase 3 replays
  COMMITs with GCI ≤ R and invalidates the others by the flag bit; phase 4
  moves the head back to H, zeroes `[ceilW(H), E)` and writes the
  last-file slot.
- **Reads go through the existing state machines.**
  - The platform plan's S3.6 already turns `openFileRw` and `closeFile`
    into self-sent CONF signals ("virtual open and close").
  - S6.1 adds the same for the three read functions: they copy from the
    mapping into the DRAM pages and send FSREADCONF to the block itself.
  - Phase 1 is the exception: it reads page headers straight from the
    mapping.
- **The reader side of the shared format code.** The write plan's
  `PmemRedoFormat.hpp` holds the constants and the checksum. S6.2 adds:
  - the full V1–V5 checks in `PmemRedoFormat.hpp`;
  - `PmemRedoScan.{hpp,cpp}`: the end-of-log scan, position arithmetic,
    and the control-area and slot codecs.
  DBLQH, `redoLogReader` and the unit tests all use them.
- **Power-loss testing has three layers:**
  - M1: a DBLQH torn-copy injector at crash error inserts. It works on any
    PMEM-mode host and tests recovery.
  - M2: the `ndb_pmem_emul_*` pre-image journal plus a hook in
    `NdbShutdown`. It catches missing fences and flushes.
  - M3: debug assertions at every point that claims persistence.
- **The GCP-saved checker extends `testRestartGci.cpp`**, which already
  records GCIs and checks them against `getRestartGCI` [V].

---

## 1. Interfaces with the sibling plans

Names follow `impl_step1_platform.md` (P) and `impl_step1_lqh_write.md`
(W) where they already fix them.

| I need | From | Why |
|---|---|---|
| `c_redo_pmem`, set from `RedoLogMode` | P S2.3 | Every branch below |
| All files of a part mapped in `startphase3Lab` (state `OPENING_PMEM_MAP_ALL`, counter `m_pmem_files_to_map`); `LogFileRecord::m_pmem_base` and `m_pmem_fileRef`; virtual open and close (P S3.6) | P S3.4, S3.6 | When a part's counter reaches 0, P S3.6 virtual-opens file 0 into `OPEN_SR_FRONTPAGE`. Once S6.4 lands, that hand-off sends `ZPMEM_SR_PHASE1` instead |
| Bad-block check of the REDO files before phase 1 | P S2.5 | Phase 1 loads through the mapping, and a bad block gives SIGBUS (E17) |
| `ndb_pmem_copy_nt`, `ndb_pmem_zero`, `ndb_pmem_store32/64`, `ndb_pmem_flush`, `ndb_pmem_drain` | P S1.3 | Zeroing, the flag store, the slot write. Every PMEM write goes through them (P §1), or the emulation is blind |
| `ndb_pmem_dirty_shutdown(int fd, Uint64 *count)`, returning `ENOTSUP` if absent | P S2.5 | Recorded in the slot (S6.3) |
| `ndb_pmem_emul_*` (P S1.5), plus the two additions listed in S7.3 | P S1.5 | S7.3 |
| `__RedoLogPmemTestMode=emulated` (`memmap=`) or `nodax` (macOS ARM64, Linux without `memmap=`); `__RedoLogPmemPowerLossEmulation=1` | P S2.7 | MTR and autotest without real PMEM (§4) |
| `PmemRedoFormat.hpp` (namespace `PmemRedo`): constants, `w0` packing, suffix S, checksum accumulator, header image with `DRAM_ONLY_MASK` | W §3.1, S4.1 | The reader must hash exactly what the writer hashed |
| Initial images, written by `redoPmemInitFile()` with the S6.3 builders: the control area; a valid page-0 header and FD in **every** file; `COMPLETED_GCI(1)` + FILLER at words 32–47 of page 1 of file 0 | W S4.8, P S3.5 | Phase 1 checks every page 0 it reads. `initFourth` puts the head at word 48 (W §7.2) |
| The page-0 copy stops at the unit holding the FILLER header, so it never stores words ≥ 8128 | W S5.3, D4 | The slots in file 0 survive every lap |
| The file switch calls `redoWriteLastFileSlot(part, fileNo, lap)` after the new FD is persistent and before the first record of the file | W S5.3, §7.2 | W3; replaces the page-0 rewrite at `35197` and `35303` [V] |
| The resume functions `writeFillerPmem`, `writeNextMbytePmem`/`changeMbyte`, `redoCopyOut`, `redoInitWritePosition` | W S4.5, S5.1, §7.2 | S6.6 |
| A marked hook site in `redoCopyOut` between the copies and the drain, plus hook sites in `writeNextLog` (`43801`), the file switch and `start_synch_gcp` (`33957`) | W §7.2 | S7.1 |
| A RedoBuffer of at least 43 pages per part until phase 4 ends | W D3 | `readExecSr` window (`ZMAX_MM_BUFFER_SIZE` 32), `readExecLog` (`LOG_PAGE_ARRAY_SIZE` 9, `Dblqh.hpp:2556`), page 0 and the head page [V]. W asks for 32 for writing, so SR sets the size |

| I provide | To |
|---|---|
| The V1–V5 checks (`PmemRedo::pageHeaderOk`, `recordOk`, extended); `PmemRedoScan`; control-area and slot layout and builders | W, P S3.5, `redoLogReader`, tests |
| `redoWriteLastFileSlot()` | W (file switch) |
| `redoPmemCrashPoint()`, `redoPmemCopyTorn()` | W (hook sites) |
| `m_pmem_end` (E) and the X5 hooks in §7 | X5 |
| The GCP-progress observable that W asks for (its Q9): DUMP 2369 prints the last persisted `COMPLETED_GCI` and the persisted LSN per part | W S5.4 |

---

## 2. S6, recovery

### S6.1 Restart reads from the mapping

**Goal.** Phases 3 and 4 run unchanged on PMEM. Their reads complete at
once from the mapping: pages are copied into the existing DRAM pages, so
the parser and its scratch header words stay as they are (design E14,
recovery §3.5).
- Opens and closes are P S3.6's virtual open and close, the same pattern
  as `openFileRw_cache` (`47350-47352`) [V].
- P S3 keeps the files open in NDBFS, so FSREADREQ would still work.
  S6.1 is what E14 asks for, and it removes the I/O-thread round trip.

**Functions** [V for every line number]:

| Function | Change in PMEM mode |
|---|---|
| `readSinglePage` `43112`, `readExecSr` `42893`, `readExecLog` `42814` | Seize the LFO and pages as today, call `redoPmemCopyPages()`, and send GSN_FSREADCONF with `theData[0]=lfoPtr.i` to self on JBB. `initFsrwconf` (`34859`) uses only `theData[0]` (`34880`) and the LFO |
| `writeDirty` `43669`, `writeSinglePage` `36203` | `ndbrequire(!c_redo_pmem)` on the restart callers. S6.5 and S6.6 replace their only restart uses (`38995`, `39854`, `40148`) |

**New** (`Dblqh.hpp`, private):
```
void redoPmemCopyPages(LogFileRecord *f, Uint32 firstFilePage, Uint32 n,
                       const Uint32 *pageI, LogPartRecord *part); // memcpy 32 KB each
void redoPmemSendReadConf(Signal*, Uint32 lfoI);
```
Pages go in the order of `lfoPtr.p->logPageArray[]` (`42915`, `42835`).

**File mode unchanged:** each change is an `if (c_redo_pmem)` before the
FSREADREQ is built.
**Tests:** every SR and NR test in PMEM mode (M1, A1–A4). A debug counter
checks that `m_redoWorkStats.m_pagesRead` equals the pages copied.
**Depends on:** P S3.4, S3.6. **Size:** S, 1.5 days.
**Risks and review points:**
- A self-sent CONF is queued on JBB like a real one, so the order seen by
  the state machines is unchanged.
- The memcpy costs about 20–50 µs per 256 KB in the LDM thread [I].
- A media error becomes SIGBUS; this relies on P S2.5's bad-block check.

### S6.2 The reader side of the shared format code

**Goal.** One implementation of the validity rules (V1–V5), the end-of-log
scan, position arithmetic and the control-area and slot codecs. It is
usable from DBLQH, `ndb_redo_log_reader` and unit tests: plain C++, with
no `SimulatedBlock` dependencies.

**Files:**
- `src/kernel/blocks/dblqh/PmemRedoFormat.hpp` (W §3.1, header-only,
  namespace `PmemRedo`). Extend `pageHeaderOk` and `recordOk` with spanned
  pages and the structure rules, as W §7.2 expects.
- New `src/kernel/blocks/dblqh/PmemRedoScan.hpp` and `.cpp` for the rest.
  Add the `.cpp` to `ndbblocks` (`src/kernel/blocks/CMakeLists.txt:97-102`)
  and to `ndb_redo_log_reader` (`src/kernel/blocks/dblqh/CMakeLists.txt`).
- Unit tests `pmem_redo_scan-t` and `pmem_redo_slot-t` with
  `NDB_ADD_TEST`, as `ndb_trpman-t` is (`src/kernel/blocks/CMakeLists.txt:192`)
  [V]. W's `pmem_redo_format-t` covers the writer side.
- Constants come from W §3.1: `W_WORDS`, `HDR_FORMAT_MAGIC 22` … `HDR_NODE_ID
  26`, `FORMAT_MAGIC`, the sizes, `RF_INVALIDATED`, `DRAM_ONLY_MASK`,
  `CONTROL_AREA_WORD 8128`. Type names are in `Dblqh.hpp:253-262` (W
  §3.1). This plan adds `SLOT0_WORD 8160`, `SLOT1_WORD 8176`, `CTRL_MAGIC`
  and `SLOT_MAGIC` (S6.3).

**Signatures** (namespace `PmemRedo`, `PmemRedoScan.hpp`):
```
struct Pos  { Uint32 fileNo, pageNo, pageIndex, lap; };
struct Geom { Uint32 noFiles, fileSizeMb, logPartNo, nodeId; };
struct PartView {                     // DBLQH: m_pmem_base of every file
  Geom g;
  const Uint8 *const *fileBase;       // fileBase[fileNo]
  const Uint32 *page(Uint32 f, Uint32 p) const;
};
enum Reason { R_OK, R_HDR_MAGIC, R_HDR_CHECKSUM, R_HDR_IDENTITY, R_HDR_LAP,
  R_TYPE_ZERO, R_TYPE_UNKNOWN, R_LEN, R_CROSSES_MBYTE, R_SPAN_HDR, R_CHECKSUM,
  R_FD_POS, R_FILLER_ALIGN, R_AFTER_NEXT_MBYTE, R_NEXT_MBYTE_HDR };
struct RecInfo { Uint32 type, flags, len; Pos end; };
struct ScanResult { Pos end; Uint32 reason; Uint32 records;
                    bool crossedIntoNextFile; bool corruptAfterDrop; };

Uint32 checkRecord(const PartView&, Pos p, Uint32 expectedLap, RecInfo *out); // V1–V5
ScanResult findEnd(const PartView&, Uint32 fileNo, Uint32 mbyte, Uint32 lap);
Uint32 expectedLap(Pos end, Uint32 fileNo);   // ≤ end.fileNo → end.lap, else end.lap−1
Pos    ceilUnit(const Geom&, Pos);            // carries across page, mbyte, file
// control area and slots: S6.3
```

**Rules implemented** (V1–V5 of E11 and format §3.4, in this order; bounds
always come before the checksum):
1. V1. The page header has the magic. Its checksum over words 1–31, with
   `DRAM_ONLY_MASK` words read as 0 (W D1), is valid. Words 15, 16 and 24
   match (page, file, part). The lap equals the expected lap.
2. V2. `p` is 8-byte aligned and `≥ 32` inside its page. The type is
   known; 0 is invalid. `len` is even and within the bounds of the type.
   The record ends inside the mbyte.
3. V3. Every page the record crosses passes V1 with the same lap.
4. V4. The checksum of E4 matches `w1`: `H` = XXH3 of `w2..w(n−1)`, one
   piece per page, chained through the seed; `w1` = the low 32 bits of the
   seeded XXH3 of `(w0 & ~RF_INVALIDATED) ‖ S` with seed `H`, where
   `S = [lap, 0, part<<16|file, page*8192+index]`. For a FILLER, `n = 2`
   and `H` is the hash of no bytes, `0x2D06800538D394C2`.
5. V5. FD only at word 32 of page 0. FILLER ends on a W boundary.
   Nothing follows NEXT_MBYTE in its mbyte.

**The scan `findEnd`.**
- Start at the first record position of `(file, mbyte)`. This is word 32
  of page `mb*32`; for mbyte 0 it is the FD.
- Loop: check the record at p. If it is invalid, E = p and the reason is
  returned. If it is valid, p = its end.
- After a valid NEXT_MBYTE, look at the next mbyte. If it is in the same
  file, E = its first record position: its header must be invalid or have
  an older lap, or phase 1 would have chosen it. If it is mbyte 0 of the
  next file, the scan goes on there when page 0 passes V1 with the
  expected lap (+1 when the next file is 0). This covers a file switch
  whose slot write did not complete (recovery §3.3, row "FD of next file
  torn").
- In page 0 the FD is followed by a FILLER to the page end (E13), so no
  special rule for the control area is needed (S6.3).

**File mode unchanged:** the module is only called under `c_redo_pmem`.

**Tests:** U2–U5 (§4).
**Depends on:** P S1.2 (`ndb_xxh3`), W S4.1 (header).
**Size:** L, 7 days including the unit tests and the synthetic-log
generator (the generator uses W's writer functions).
**Risks and review points:**
- The writer and the reader must hash the same bytes in the same pieces:
  use W's accumulator, one `piece` per page.
- The `fileBase[]` array avoids the O(N) `findLogfile` walk (`41219`) [V].
- The false-pass rate is 2⁻³² per torn record.
- The scan must never read outside the mbyte: check `len` before the
  checksum.

### S6.3 Control area, two-slot last-file pointer and start-up checks

**Goal.** E10 and E17 for everything that needs the log: config check,
last file and lap, dirty-shutdown record, refusal of the other mode's
files.

**Layout** (page 0 of file 0, words 8128–8191, four 64-byte lines; it lies
in the dead body of the FILLER that follows the FD):

| Line | Words | Content |
|---|---|---|
| Config | 8128–8143 | [0] magic `'RCTL'`, [1] format version, [2] NoOfFragmentLogParts, [3] logPartNo, [4] NoOfFragmentLogFiles, [5] FragmentLogFileSize in MB, [6] W, [7] node id, [8–14] 0, [15] checksum of [0–14]: the low 32 bits of `ndb_xxh3_64` of those 60 bytes. Written once at initial start by W's `redoPmemInitFile()` with `PmemRedo::buildCtrlConfig` |
| Reserved | 8144–8159 | 0. For X5/X6 (SR generation, stale marker) |
| Slot 0, slot 1 | 8160–8175, 8176–8191 | [0] magic `'RSLT'`, [1–2] seq64, [3] lastFileNo, [4] lap, [5] logPartNo, [6–7] recorded dirty-shutdown count, [8] flags (bit 0 count valid, bit 1 unsafe shutdown seen at that start, bits 8–15 slot index), [9–14] 0, [15] checksum of [0–14], as for the config line |

The FD ends at word 8068 or earlier. It starts at word 32, has 4 header
words and at most `8192−32−128` array words (capacity rule `2833-2834`
[V]). A pad word and the FILLER header then end before 8080, so the
FILLER's header unit never touches the control area. Add a
`static_assert` on this.

**Module functions:**
```
void   PmemRedo::buildCtrlConfig(Uint32 out[16], const PmemRedo::Geom&, Uint32 noParts);
Uint32 PmemRedo::checkCtrlConfig(const Uint32 *line, const PmemRedo::Geom&,
                                   Uint32 noParts, char *msg, size_t sz);
void   PmemRedo::buildSlot(Uint32 out[16], Uint64 seq, Uint32 fileNo, Uint32 lap,
                            Uint32 partNo, Uint64 dsc, Uint32 flags, Uint32 slotIdx);
int    PmemRedo::pickSlot(const Uint32 *s0, const Uint32 *s1, Uint32 partNo,
                           Uint32 noFiles, PmemRedo::Slot *out); // 0, 1, or −1 if none valid
```

**DBLQH functions:**
- `void redoPmemReadControlArea(LogPartRecord*)`, called from S6.4 step A.
  It replaces the checks of `readSrFrontpageLab` (`36295-36308`) in PMEM
  mode.
  - Config mismatch: `progError(NDBD_EXIT_INVALID_CONFIG)` with the same
    style of message as `36300-36305`, naming the field.
  - No magic: "REDO log was not written in PMEM mode; changing
    RedoLogMode needs an initial node restart".
  - Node id mismatch: refuse.
  - Neither slot valid: `progError(NDBD_EXIT_SR_REDOLOG)` "both last-file
    slots of log part p are invalid".
- **Write interface for S5 and S6.6:**
```
// Precondition: page 0 (header + FD) of fileNo is fenced.
// Caller: the thread that owns the part's write state; under the part
// mutex at a file switch; the LDM thread in phase 4.
// Postcondition: the new slot is fenced (one 64-byte NT store + drain).
void Dblqh::redoWriteLastFileSlot(LogPartRecord *part, Uint32 fileNo, Uint32 lap);
```
  It writes `seq = m_pmem_slot_seq + 1` into slot `seq & 1`, together with
  the current `m_pmem_dsc_recorded` and flags, then sets
  `m_pmem_slot_seq = seq`. Error inserts 5162 and 5163 apply (S7.1).
- **Dirty-shutdown count** (E17, Q4).
  - Read it per part with `ndb_pmem_dirty_shutdown(fd of file 0, &count)`
    (P S2.5). Compare it with the slot's recorded count. `ENOTSUP`
    (`memmap=`, `nodax`) clears the "count valid" flag and is logged once.
  - If it increased: log a warning and send a cluster log event ("PMEM
    device reported an unsafe shutdown; acknowledged REDO writes may be
    lost; this node's REDO tail is stale"), and set
    `m_pmem_unsafe_shutdown`.
  - Record the new count in the phase-4 slot.
  - Step 1 only records and reports it. The stale handling is X6.
- **File mode reading PMEM files:** in `readSrFrontpageLab` (`36289`), file
  path: if `logPageWord[22] == PmemRedo::FORMAT_MAGIC`, refuse ("REDO log is in
  PMEM format; changing RedoLogMode needs an initial node restart"). Word
  22 is 0 on every file-mode page, because `initLogpage` clears the header
  (`35582`) [V]. This is the only change on the file-mode path.

**New fields** (`LogPartRecord`, `Dblqh.hpp:1864`): `Uint64 m_pmem_slot_seq`,
`Uint64 m_pmem_dsc_recorded`, `Uint32 m_pmem_dsc_flags`,
`bool m_pmem_unsafe_shutdown`. Block: `bool c_redo_pmem_unsafe_shutdown`
(any part).

**Tests:** U5; every restart (M1, A1–A4); A5 (mode switch refused, then
accepted with `--initial`); crash tests 5162/5163; the reader prints both
slots (M3).
**Depends on:** S6.2, P S1.3 and S2.5 (`ndb_pmem_*`, dirty-shutdown query), W S4.8 (initial
format writes the control area).
**Size:** M, 3 days.
**Risks and review points:** the slot is the single point that moves the
end of the log back (step 4 of recovery §4.3); review its ordering at
every caller.

### S6.4 Phase 1 on the mapping: last file, last mbyte, exact E, zeroing

**Goal.** Recovery §3.4: phase 1 reads only the mapping. It finds E
exactly by scanning the last mbyte and zeroes `[E, end of mbyte(E))`.

**Functions:**
- `startphase3Lab` `2454`, loop `2485-2493` [V]. P S3.6 maps every file
  of every part there and, when a part's `m_pmem_files_to_map` reaches 0,
  virtual-opens file 0 into `OPEN_SR_FRONTPAGE`. Once the format is the
  PMEM one (S4 and S6.4 in), that hand-off sends CONTINUEB
  `ZPMEM_SR_PHASE1(part, step 0)` instead. The file-mode phase 1 is then
  not entered.
- New `void redoPmemSrPhase1(Signal*, Uint32 partI, Uint32 step)`, one
  CONTINUEB per step:
  - **A.** `redoPmemReadControlArea` (S6.3) gives f and L. Build the part
    view (`fileBase[]`).
  - **B.** Replaces `readSrLastFileLab` `36332` and `readSrLastMbyteLab`
    `36367`.
    - Page 0 of f must pass V1 with lap L, and its FD must pass V4;
      otherwise `progError` ("corrupt page 0 of the last file"), since W3
      guarantees it.
    - Copy page 0 to a seized DRAM page and call `initGciInLogFileRec`
      (`42279`) unchanged.
    - For each mbyte of f, read the 32-word header from the mapping.
      Invalid or lap < L marks the drop: `lastMbyte = mb − 1`, as at
      `36371-36373`. A valid lap-L header after the drop sets
      `corruptAfterDrop` and the node stops (recovery §3.4 step 3).
    - The arrays get the header values when the header checksum passes, and 0
      otherwise; 0 is what a zeroed page gives today.
  - **C.** Step back through earlier files' page 0, as `36427-36455` and
    `readSrNextFileLab` `36471` do, but synchronously.
    - Each page 0 must pass its header checksum and identity, with lap ≤ L.
    - If lap ≥ 1, the FD must pass V4. A lap-0 page (never written) gives
      zeros.
    - Copy each page to DRAM and call `initGciInLogFileRec`.
  - **D.** `PmemRedo::findEnd(view, f, lastMbyte, L)` gives E. Store
    `m_pmem_end` and `m_pmem_end_reason`. Log one line per part: "PMEM
    REDO part p: end of log at file/page/index, reason".
  - **E.** `redoPmemZero(part, E, end of mbyte(E), forward)`, page 0 of a
    file excepted, then drain. Error inserts 5172 (before) and 5167
    (during).
  - **F.** `srPhase1PartCompleted(signal, part)`: this is the code of
    `closingSrLab` `36582-36627`, moved into a function that both modes
    call (no change in behaviour).
- **New zeroing primitive**, shared with S6.6:
```
// Zero [from, to) of one part, page 0 of every file excepted; at most
// budgetPages pages per call; ndb_pmem_zero + one drain per mbyte
// and at the end. Returns true when done; *next is where to continue.
bool Dblqh::redoPmemZero(LogPartRecord*, PmemRedo::Pos from, PmemRedo::Pos to,
                         bool backwards, Uint32 budgetPages, PmemRedo::Pos *next);
```
- PMEM phase 1 opens no file (no virtual open either). It needs P S3.6 to
  leave mapped files logically `CLOSED`, which is what the file-mode phase
  1 leaves behind (`36561`) [V]; confirm with P.

**New fields** (`LogPartRecord`): `PmemRedo::Pos m_pmem_end`,
`Uint16 m_pmem_end_reason`, `PmemRedo::Pos m_pmem_zero_next`,
`PmemRedo::Pos m_pmem_zero_stop`, `const Uint8 **m_pmem_file_base` (filled
in step A). CONTINUEB codes `ZPMEM_SR_PHASE1`, `ZPMEM_SR_ZERO`: the next
free numbers, 62 and 63 in today's `Dblqh.hpp` [V; recheck at merge].

**File mode unchanged:** the file-mode phase 1 (`36275-36628`) is not
touched apart from the move of its tail into `srPhase1PartCompleted`.

**Tests:** U3/U4 (scan rule), A1/A2 (SR, NR), S7 torn-tail and crash
tests, 5167/5172, `RestartFD` from testRedo (few FDs per page: many step-C
reads).
**Depends on:** S6.2, S6.3, P S3.6.
**Size:** M, 4 days.
**Risks and review points:**
- Real time: at most 1 MB scanned and 1 MB zeroed per part. Steps D and E
  run in slices of 8 pages per signal.
- E may be in the next file when the slot lags. mbyte(E) is then mbyte 0
  of that file.
- The NodeStartLog report stays in `srPhase1PartCompleted`.

### S6.5 Phase 3 on the new layouts

**Goal.** `execSr`, `readCommitLog`, `readLogHeader` and `execLogRecord`
read the 64-byte-unit format. Every record before E is checked, a COMMIT
above R is invalidated by the flag bit, and an invalid record before E
stops the node.

**`execSr` (`38962`).** A PMEM block is inserted just before
`readLogword` at `39083`. The file-mode `switch` stays byte-identical, in
the `else` branch.
1. **End check.** If the record start (file, `currentFilepage`,
   `ZCURR_PAGE_INDEX`) equals E, stop: this is the existing "end of log
   wo/ having found last GCI" crash (`39279-39282`), with "(PMEM end E,
   reason r)" added. If `c_redo_pmem_unsafe_shutdown` is set, the message
   also says "the PMEM device reported an unsafe shutdown; restart this
   node with --initial".
2. **Validity.** Call `PmemRedo::checkRecord(view, p,
   PmemRedo::expectedLap(E, file))`. This is full V1–V5 for every record
   (open question 2). If it fails:
   `progError(NDBD_EXIT_SR_REDOLOG, "corrupt REDO record before end of log")`
   with the position and reason. Never treat it as the end (E11).
3. **Dispatch** on `type = w0 & 0xFF`, `len = w0 >> 16`:

| Type | Action (today's code it replaces or shares) |
|---|---|
| PREPARE | `stepAhead(len − 1)`. Today `39089-39094` reads the length from `w1`, which is now the checksum |
| COMMIT with `RF_INVALIDATED` | `stepAhead(len − 1)`; replaces type 9 (`39099-39103`) |
| COMMIT | Shared case `39108-39195` with two branches: `readCommitLogPmem` instead of `readCommitLog`; and for `gci_hi > crestartNewestGci` the call `redoPmemInvalidateCommit(part, file, prevFilepage, savePageIndex)` instead of the DRAM type write and `ZPOS_DIRTY` (`39126-39132`). `prevFilepage` and `savePageIndex` locate `w0` (`39053`, `39017`) [V] |
| ABORT | `stepAhead(len − 1)` (`39200-39205`) |
| FD | Index after `w0` must be 33 (`39224-39230` with the PMEM offset), then `stepAhead(len − 1)` |
| FILLER | `stepAhead(len − 1)`; after the FD it runs to the page end, so `readLogword` moves to the next page |
| NEXT_MBYTE | Shared logic `39253-39298`, moved into `execSrNextMbyte()`, which both modes call |
| COMPLETED_GCI | Skip `w1`, read gci from `w2`, skip `w3`, then the shared logic `39304-39351` (moved into `execSrCompletedGci()`). The head is recorded after all 4 words |
| COMPLETE, SR_HEAD | `stepAhead(len − 1)`. X5 hooks |

- `ZPOS_DIRTY` and `writeDirty` (`38983-39013`) are unreachable in PMEM
  mode: `ndbrequire`.
- `ZMIN_READ_BUFFER_SIZE` (`Dblqh.hpp:185`) is 3, but a PREPARE can span 4
  pages (E13). It becomes 4 in both modes, as a separate bug fix
  (Design issue 5; `implementation_plan.md` pull request 0, Q-A6).

**`readCommitLog` (`42763`).** The PMEM variant `readCommitLogPmem` reads
`w2..w11`. It unpacks `w5` into fileNo (high 16) and startPageIndex, and
`w6` into startPageNo and stopPageNo. `tableref`, `schemaVersion`,
`fragmentid` and `gci_hi` go to the TC record as today. The synthetic
transid (`42804-42805`) and `gci_lo = 0` (`42782`, `42802`) stay for
replay (format R7; open question 1). New `CommitLogRecord` fields
(`Dblqh.hpp:3357`) carry the real flags, `gci_lo`, transid and opCount
for X5.

**`readLogHeader` (`43000`).** Offsets 2–7 are unchanged [V against format
§5.1], so only `ndbrequire(!(w0 & PF_TRANSID))` is added; the flag is off
in iteration 1. The pad word after an odd key + attrinfo is skipped
through `len`.

**`execLogRecord` (`39478`).** Before `readLogHeader` (`39501`), check the
record at the back reference: type PREPARE, V1–V5 with the lap of the
PREPARE's file (format R6). Otherwise stop with "COMMIT back reference
does not point to a valid PREPARE".

**COMMIT invalidation** (E9):
```
// One aligned 4-byte store of w0|RF_INVALIDATED (ndb_pmem_store32) and a
// flush of its line; the drain comes later (batch).
void Dblqh::redoPmemInvalidateCommit(LogPartRecord*, LogFileRecord*,
                                     Uint32 pageNo, Uint32 pageIndex);
```
- Count in `m_pmem_inval_pending`. Drain at `LES_EXEC_LOG_COMPLETED`
  (`39021`) and again at the start of S6.6.
- A rerun after a crash repeats the stores, because the same records lead
  to the same decisions (recovery §4.3).
- A later round reads the flag from its fresh copy and skips the record.
- Error insert 5169.

**File mode unchanged:** branches only. The NEXT_MBYTE and COMPLETED_GCI
code moves into helpers that both modes call, with the same statements.

**Tests:** U2 (layouts); A1 (SR replay); A4 (`testRestartGci`: rows and
ROW_GCI64); 5169; M1.
**Depends on:** S6.1, S6.2, S6.4 (E), W S4.3–S4.4 (layouts).
**Size:** L, 5 days.
**Risks and review points:**
- `execSr` is long and stateful; keep the PMEM block a pure
  pre-dispatch.
- The checks read the mapping while the parser reads the copy. Both see
  the same bytes, because nothing writes below E during phase 3 except
  the flag, which the checksum excludes [I].
- jam coverage; the cost of the checksum per record (about 12 ns for a
  COMMIT, 28 ns for a 1000-byte PREPARE on x86-64 with AVX2;
  `step1_phases.md`, Timings).

### S6.6 Phase 4: head, zeroing `[ceilW(H), E)`, writer resume, slot

**Goal.** Recovery §4.2 and §4.3 for step 1 (the head moves back), with E5
(no re-initialisation of the head page) and W7 (the unit at the head is
closed by a FILLER before writing resumes).

**Functions:**
- `readSrFourthPhaseLab` `40474`, PMEM branch:
  - Check the head page header (`PmemRedo::pageHeaderOk`). If it is valid,
    keep it and skip `initLogpage` (`40525`). If it is invalid (H at word
    32 of a page whose header never persisted), call `initLogpage`.
  - `logLap = PmemRedo::expectedLap(E, headFileNo)` instead of the header
    word (`40521`).
  - Zero the DRAM copy from `headPageIndex` to 8192, so that stale
    records never become FILLER dead bytes.
  - Keep `40499-40531` otherwise: the writer state that W §7.2 expects
    (`currentLogfile`, `currentLogpage`, `currentFilepage`,
    `ZCURR_PAGE_INDEX = H`, `remainingWordsInMbyte`, `logLap`).
  - Set `m_pmem_persisted_lsn = lsn(H)`: the bytes below H are on PMEM.
    If the header was re-initialised, set it to the page start instead,
    so that the first copy also stores the new header (Design issue 4).
- `readSrFourthZeroLab` `40596`, PMEM branch: after loading `logPageZero`
  as today, drain pending invalidations and start `redoPmemSrFourth`
  instead of `readFileInInvalidate(…, 3, …)` (`40616`).
- New `redoPmemSrFourth(Signal*, Uint32 partI)` (CONTINUEB
  `ZPMEM_SR_ZERO`):
  1. Zero `[ceilW(H), E)` backwards with `redoPmemZero(…, backwards, 32
     pages)`, page 0 of every file excepted, one drain per mbyte (as
     today's sync per mbyte, `39834-39848`). If `ceilW(H) ≥ E`, there is
     nothing to zero; `[E, …)` was zeroed in phase 1. Error insert 5168.
  2. Error insert 5170.
  3. Close the unit at H, as in the write plan's resume contract (W §7.2):
     - If H is W-aligned, there is nothing to do.
     - If `[H, ceilW(H))` is the last unit of the mbyte, call
       `changeMbyte`. It stores NEXT_MBYTE at H through
       `writeNextMbytePmem`, persists it, and switches mbyte, or file with
       FD and slot, synchronously.
     - Otherwise call `writeFillerPmem(len = ceilW(H) − H)` and then
       `redoCopyOut`.

     The bytes below H are identical to PMEM, because the DRAM page was
     copied from it. The FILLER header is identical to the one GCP save
     wrote there: same position, length and checksum. W zeroes the body. Then
     call `redoInitWritePosition(part)`, which checks that the head is
     W-aligned and that the filled list is empty.
  4. `redoWriteLastFileSlot(part, currentLogfile.fileNo, logLap)`
     (5162/5163).
  5. Send `ZSR_FOURTH_COMP`, as `execFSWRITECONF` does at `34750-34756`.
- Not used in PMEM mode: `invalidateLogAfterLastGCI` `39534`,
  `writeFileInInvalidate` `39782`, `invalidateCloseFile` `39860`,
  `readFileInInvalidate` `39882`, `exitFromInvalidate` `40100`. E is
  exact, so no lap search is needed.
- `initFourth` `40438` (initial start; also runs phase 4) [V]:
  `headPageIndex = ZPAGE_HEADER_SIZE + 16` in PMEM mode (`40451`; today
  +2). That is after `COMPLETED_GCI(1)` and the FILLER that W S4.8 writes,
  as agreed in W §7.2. Set `m_pmem_end = H`, so there is nothing to zero
  and nothing to close.

**Order and repeatability** (recovery §4.3):

| Crash after | Next restart |
|---|---|
| Phase 1 zeroing (partial) | E unchanged, zeroing redone |
| Flag stores (partial) | The same COMMITs are found again and stored again |
| Step 1 (partial, backwards) | The slot still names the old last file, whose page 0 was never zeroed. E' ≤ E. Phase 3 stops at H, before every zeroed byte. `[ceilW(H), E')` is zeroed again |
| Step 3 | As above. The FILLER or NEXT_MBYTE at H is identical |
| Step 4 | Phase 1 starts in H's file and finds the zeroed mbytes as the lap drop. E = `ceilW(H)` |

**File mode unchanged:** branches only; the invalidation functions are
untouched.

**Tests:** U4 (the same procedure in the model), A1/A2, 5168/5170,
5162/5163 during restart, A4 ledger.
**Depends on:** S6.4, S6.5, W S4.5 and S5.1 (`writeFillerPmem`,
`writeNextMbytePmem`, `redoCopyOut`, `redoInitWritePosition`), W S5.3
(the file switch that writes the slot).
**Size:** M, 4 days.
**Risks and review points:**
- The handoff of writer state (S5 interface).
- H at the start of a page whose header was not persisted.
- A closer at H that triggers a file switch: the writer writes page 0 of
  the next file and a slot, then S6.6 writes the slot again. That is
  harmless: seq + 1, same content.

### S6.7 Node restart path

**Goal.** NR runs the same PMEM code with R = the node's own GCI
(recovery §5).

- DIH: `nr_run_redo` (`DbdihMain.cpp:8474`) and `sendSTART_RECREQ` (`468`)
  are unchanged [V]. They send `lastCompletedGCI[node]` and a keepGci
  adjusted to `startGci`.
- LQH: `execSTART_RECREQ` (`37619`) sets `crestartNewestGci` (`37648`) [V].
  Phases 1, 3 and 4 then run the PMEM code of S6.4–S6.6 for
  `ST_NODE_RESTART`, which `startphase3Lab` already covers (`2463`) [V].
- The file-mode special case for non-initial starts in
  `readFileInInvalidate` step 7 (`40070-40090`) is not needed, because E
  is exact.
- An initial node restart is the initial-start path (S3 formats the files,
  `initFourth`).

**Tests:** A2 (testNodeRestart list), `GciLedgerNR`, Bug44952 (crash at
the mbyte boundary, then crashes during the restart).
**Size:** S, 1.5 days (review and tests).
**Risks:** none in code; the risk is test coverage of an NR that crashes
in phase 4.

### S6.8 `redoLogReader` for the PMEM format

**Goal.** Format §10: checksum checks, printing, end of the valid log, the
control area. The old path stays unchanged.

**Files:**
- `redoLogReader/reader.cpp`: in `main` (`156`), after the open (`210-223`),
  read page 0. If header word 22 holds the PMEM magic, call
  `pmem_reader_main()`.
- New `redoLogReader/pmem_reader.cpp`; it uses `PmemRedoFormat.hpp` and
  `PmemRedoScan`.
- `dblqh/CMakeLists.txt` target `ndb_redo_log_reader`: add the two sources.
  `ndb_xxh3` is in `ndbgeneral`, which the target links already.

**Behaviour:**
- Page headers: checksum ok or bad, lap, identity, W, node, part.
- Records: checksum ok or bad. COMMIT unpacked (prepare reference, gci_hi,
  gci_lo, transid, opCount, `INVALIDATED` and `DURABLE` flags). COMPLETE.
  ABORT with `AF_AFTER_COMMIT`. COMPLETED_GCI, NEXT_MBYTE, FD (new
  offsets), SR_HEAD. FILLER only with `--dump`.
- Per mbyte: "END OF VALID LOG at mb:page:index reason=…". The expected
  lap of an mbyte is the lap of its first page header.
- File 0: the config line and both slots, and which slot is chosen.
- New `--find-end=<dir>`: reads `S0..S(N−1).FragLog`, picks the slot and
  calls `PmemRedo::findEnd`, so it prints the E that phase 1 would find.
- New `--transid=T1,T2`. `--in-doubt` is left for X5/X8 (open question
  12).
- With `--check`, exit with a non-zero code when an invalid record is
  followed by valid ones in an mbyte that is not the last. That is not a
  proof of corruption for a single file, so it is reported, not enforced.
- I/O: plain reads, no `ndbxfrm`. PMEM files are never encrypted (Q5), so
  `--file-key` with a PMEM file is an error.

**File mode unchanged:** the old code path is entered as today when the
magic is absent.
**Tests:** M3 (MTR); the U4 generator writes images to files and the
reader must report the same E (optional U6).
**Depends on:** S6.2. **Size:** M, 4 days.
**Risks:** keep the old reader's output byte-identical; the existing MTR
test `ndb_redo_log_reader` guards it.

---

## 3. S7, power-loss testing

### Why `kill -9` on `memmap=` proves little

The RAM survives the process, and the CPU caches stay coherent, so every
store issued before the kill is in the "media". A missing `sfence` or
`clwb` is invisible (hardware §4.6). Under the copy-out design every
persist is fenced before the part mutex is released, so a crash can tear
at most the one persist in flight per part. That never happens with
`kill -9` on emulated PMEM. Torn states and missing barriers therefore
need the three mechanisms below.

### S7.1 Crash error inserts

All of them crash with `progError(NDBD_EXIT_ERROR_INSERT)` through
`redoPmemCrashPoint(code)`. That function first applies M1 (if the
journal is off) or M2 (if it is on) to the persist in flight.
- The extra value is a seed (0 = derive from the time) and, for 5169 and
  5171, a count.
- Restart-time codes are set while the nodes are in NOSTART, with
  `CmvmiSetRestartOnErrorInsert`, as `runBug44952` does
  (`test/ndbapi/testNodeRestart.cpp:4303`) [V].

**Free numbers.** `Next DBLQH 5155` (`src/kernel/blocks/ERROR_codes.txt:197`);
5160 is in use (`:548`); 5155–5159 and 5161–5199 are free in `src/kernel`,
`test` and `mysql-test/suite/ndb*` [V by grep]. The write plan leaves the
numbers from 5155 to this plan (W F16, Q5) and the platform plan takes none.
**Proposal:** 5155–5159 and 5161–5172 (5160 is skipped), then `Next DBLQH 5173`.

| Code | Site (today's code where S5 or S6 places it) | Effect |
|---|---|---|
| 5155 | `redoPersist` copy-out, any persist | Torn copy of this persist's units, no fence, crash |
| 5156 | `writeNextLog` (`43801`) after NEXT_MBYTE is fenced (`43824-43826` today) | Crash before the next mbyte's header is stored |
| 5157 | First copy into a new mbyte (header unit) | Torn header unit, crash |
| 5158 | File switch, after the old file's end is fenced (`43845` area) | Crash before the new FD page is copied |
| 5159 | File switch, FD page copy (`writeFileHeaderOpen` `36073`) | Torn page-0 copy, crash |
| 5161 | File switch, after the FD is fenced | Crash before the slot write |
| 5162 | `redoWriteLastFileSlot` | Random subset of the slot's 8-byte chunks stored, no fence, crash (file switch and phase 4) |
| 5163 | After the slot fence | Crash before the first record of the new file, or before `ZSR_FOURTH_COMP` |
| 5164 | `start_synch_gcp` (`33957`), after `writeCompletedGciLog` in all parts | Crash before any persist |
| 5165 | GCP save, one part's persist | Torn copy of that part's persist, crash |
| 5166 | GCP save, all parts persisted | Crash before GCP_SAVECONF (`33828`, `33909`, `34298`) |
| 5167 | Phase 1 zeroing (S6.4 E) | Crash after a random prefix, last batch not drained |
| 5168 | Phase 4 zeroing (S6.6 step 1) | Crash after a random number of pages, backwards |
| 5169 | `redoPmemInvalidateCommit` | Crash after the N-th flag store, before its drain (N = extra, default 1) |
| 5170 | Phase 4 after zeroing | Crash before the close at H |
| 5171 | Any `ndb_pmem_drain` on this node | Crash at the K-th drain after arming, just before it (K = extra, else random 1–1000); full effect needs M2 |
| 5172 | Phase 1, E found | Crash before the zeroing: the next run must find the same E |

**DUMP codes** (2368 is taken by W S5.8; 2369 and 2370 are free [V,
`include/kernel/signaldata/DumpStateOrd.hpp` ends at 2367 for LQH]):
- `LqhPmemRedoInfo = 2369`: print per part the control area, the chosen
  slot, E with its reason, the persisted LSN and the pending flag stores.
- `LqhPmemPowerLoss = 2370 [seed]`: M2 power loss now, then crash. Used
  to crash all nodes at once.

**Files:** `ERROR_codes.txt`, the DBLQH sites above,
`include/kernel/signaldata/DumpStateOrd.hpp`, `execDUMP_STATE_ORD`
(`DblqhMain.cpp:44200`).
**File mode unchanged:** all hooks sit in PMEM-only code.
**Tests:** `GciLedgerCrashPoints` (S7.4) loops over every code.
**Size:** M, 3 days. **Depends on:** W S5.2–S5.4 hook sites, S6.
**Risk:** codes from 5128 on are also delivered to DBQLQH instances
(`ERROR_codes.txt:58-64`) [V]. That is harmless here, because query
threads never run REDO code.

### S7.2 M1 torn-copy injector and M3 debug checks (DBLQH only)

**M1.**
```
// For each 64-byte line of [dst, dst+len): skip (old bytes stay), copy,
// or tear (each 8-byte chunk old or new), chosen by a seeded PRNG.
// No fence. Used by 5155, 5157, 5159, 5162, 5165 when M2 is off.
void Dblqh::redoPmemCopyTorn(Uint8 *dst, const Uint8 *src, Uint32 len, Uint64 seed);
```
It produces exactly the A2 state: holes followed by valid data, orphans,
torn records and torn headers. It works on `memmap=` and on the non-DAX
test mode, because the stores stay in RAM after the crash.

**M3** (VM_TRACE / ERROR_INSERT builds):
- `redoPmemAssertPersisted(part, lsn)` before every GCP_SAVECONF send and
  before ZSR_FOURTH_COMP.
- `redoPmemVerifyCopy(part, fromLsn, toLsn)` after each `redoPersist`: a
  memcmp of mapping against DRAM staging. It catches a persisted LSN that
  was advanced over bytes never copied, a bug M2 cannot see.
- After zeroing: assert that the range reads as zero.

**Size:** M, 3 days. **Depends on:** W S5.2. **File mode:** untouched.

### S7.3 M2 power-loss emulation with `ndb_pmem_emul_*`

**What the platform plan provides** (P S1.5, an undo log per thread) [V
against `impl_step1_platform.md`]:
- `ndb_pmem_emul_enable(max_pending)`, run before the first map when
  `__RedoLogPmemPowerLossEmulation=1`.
- `ndb_pmem_emul_active()`.
- `ndb_pmem_emul_pending()`: this thread's unpersisted lines.
- `ndb_pmem_emul_power_fail(seed, keep_permille, tear_permille)`: keeps,
  restores or tears every pending line of every thread.
- `ndb_pmem_emul_on_crash()`, `ndb_pmem_emul_get_stats()`.
- NT copies and zeroing persist at drain; `store32/64` need flush + drain.
- A line pending in two threads is reported.

**Two additions requested from P:**

| Function | Why |
|---|---|
| `ndb_pmem_emul_freeze()`: every later write primitive blocks, and the call returns when no thread is inside one (timeout 1 s, then log the threads that did not park) | Without it, other LDM threads keep persisting while `power_fail` walks the lists, and the result is not a single instant |
| `ndb_pmem_emul_range_pending(const void *p, size_t len)`: any thread has a pending line in the range | The GCP_SAVECONF assertion below covers ranges that another LDM copied (W1) |

**Hooks owned here:**
- `NdbShutdown` (`src/kernel/ndbd.cpp:1443`) [V] is the one funnel for:
  - `progError`, `ndbrequire` and `ndbabort`, through
    `ErrorReporter::handleAssert` and `handleError`
    (`error/ErrorReporter.cpp:257`, `306`);
  - the signal handler `handler_error` (`ndbd.cpp:677`), through
    `ERROR_SET_SIGNAL` → `handleError`;
  - restart and abort (`blocks/cmvmi/Cmvmi.cpp:1017`);
  - the watchdog (`vm/WatchDog.cpp:396`) [V].
- So **one hook at the entry of `NdbShutdown`** replaces the three points
  P suggests, and also covers abort restarts and the watchdog:
  `if (ndb_pmem_emul_active() && type != NST_Normal) { freeze;
  power_fail(seed, keep, tear); }`. The seed comes from DUMP 2370 or the
  error insert's extra value, otherwise from the time.
- Every in-process crash or abort restart of an emulated node then becomes
  a power loss, including `NdbRestarter::restartAll(abort=true)`. Only an
  external `kill -9` stays a plain process crash.
- Deterministic checks (`ndb_pmem_emul_pending() == 0`):
  - W S5.7 already checks at `unlock_log_part`;
  - this plan adds the end of `redoWriteLastFileSlot`, after each zeroing
    drain, and after the flag-store drain;
  - `ndb_pmem_emul_range_pending()` over `[old persisted, new persisted)`
    of every part before each GCP_SAVECONF.

**How it catches a missing barrier.**
- A store, `memset` or copy with no drain before the claim fails the
  assertion at once, with the call stack.
- Without the assertion, the next crash reverts those lines. Possible
  results:
  - a slot that names a file whose FD reverted;
  - zeroed orphans that come back;
  - a COMPLETED_GCI that is gone after GCP_SAVECONF.
  The ledger (S7.4), "corrupt before E" or "end of log without last GCI"
  then reports it.
- Error insert 5171 puts the crash point at random drains: page-full
  copies, mbyte and file switches, GCP save, zeroing and flag stores are
  all hit over many runs.

**What M2 cannot catch:**
- `ndb_pmem_drain` not emitting `sfence` or `dsb` (the emulator trusts the
  call; review the asm and test it on real hardware);
- device firmware behaviour;
- an `sfence` on one core that does not drain another core's
  write-combining buffers (the journal is per thread, so a cross-thread
  claim shows up in `range_pending`, but the hardware effect itself is
  not modelled).

**Size:** M, 3 days on top of the platform's journal. **Depends on:** P S1.5.
**Risk:** the freeze must not deadlock the shutdown path. The waiting
thread is the one in `NdbShutdown`, and it times out after 1 s and logs
which threads did not park.

### S7.4 GCP-saved writes checker (ledger), in `testRestartGci.cpp`

**Existing pieces to reuse** [V]:
- `test/ndbapi/testRestartGci.cpp` records the GCI of every insert
  (`runInsertRememberGci` `107`, via `getGCI`), restarts all nodes with
  abort (`runRestartAll` `185`), reads R (`runDetermineRestartGci` `259`,
  `Dictionary::getRestartGCI`), and checks that every row with GCI ≤ R
  exists, that none above does, and that ROW_GCI64 is right
  (`runVerifyInserts` `286`).
- The test lib: `HugoOperations` (`pkInsertRecord`, `pkUpdateRecord` with
  `updatesValue`, `pkDeleteRecord`), `HugoCalculator::getUpdatesValue`,
  `UtilTransactions::selectCount`, `NdbRestarter` (`restartAll`,
  `insertErrorInAllNodes`, `dumpStateAllNodes`, `waitClusterNoStart`).
- The pattern of `runSR_DD_UndoHole` (`testSystemRestart.cpp:2578`): update
  until the node dies, restart, verify, then a clean restart.

**New**, in the same file:
- Per-step ledger `Vector<TxnRec>`, `TxnRec = {gci64, firstRow, nRows, op,
  updatesValue, state}`. Each step owns a key range, so the order on a row
  is known.
- Operations: insert, update (with `updatesValue`), delete, and multi-row
  transactions (1–8 rows).
- `state`: committed (execute OK, GCI read); aborted (temporary or
  permanent error); **indeterminate** (`NdbError::UnknownResult`). After an
  indeterminate result the step stops writing to those rows until
  verification.
- **Verification after the restart** (R = `getRestartGCI`, the compare
  value as in `259-278`):
  - For each row, the expected state is the last committed transaction
    with `gci_hi ≤ R`.
  - An indeterminate transaction allows either the before or the after
    state.
  - Check existence, `updatesValue` and ROW_GCI64, with the rounding rule
    of `runVerifyInserts`.
  - A multi-row transaction must be all-or-nothing. That follows from the
    per-row checks, and it is reported per transaction.
- Report the "acknowledged but lost" count. It is legal in step 1 for GCI
  > R, and it is the X3/X5 ledger's measure.

**New test cases:**

| Case | Steps |
|---|---|
| `GciLedgerSR` | Writers for T s; `restartAll(abort)`; wait started; verify; loop |
| `GciLedgerNR` | Writers; abort-restart one random node; verify after it rejoins; then a full SR and verify |
| `GciLedgerTornTail` | Writers; `insertErrorInAllNodes(5155)` (each node crashes at its next persist with a torn copy); SR; verify; clean SR; verify |
| `GciLedgerCrashPoints` | For each code in {5155–5172} except 5160: arm it (in NOSTART for restart-time codes); drive until it fires; restart; verify; clean restart; verify |
| `GciLedgerPowerLoss` | Needs M2. Writers; DUMP 2370 to all nodes, or 5171 with a random K; SR; verify. 200 loops in the weekly run |

The checker runs in file mode as well, so validate it on today's code
first: `GciLedgerSR` must pass in file mode before any PMEM code lands.

**Size:** M, 5 days. **Depends on:** nothing for file mode; S7.1/S7.3 for
the PMEM cases.
**Risk:** false failures from the indeterminate state; keep the ledger
strict but log every indeterminate transaction.

### S7.5 Test configurations and lists

**MTR:**
- New `mysql-test/suite/ndb/pmem_redo.cnf` (pattern:
  `suite/ndb/encrypted_filesystem.cnf`) [V]:
  ```
  [cluster_config]
  RedoLogMode=pmem
  __RedoLogPmemTestMode=nodax     # P S2.7
  FragmentLogFileSize=16M
  ```
- New `mysql-test/suite/ndb/pmem_redo_dax.cnf`: `RedoLogMode=pmem` and
  `__RedoLogPmemTestMode=emulated` (empty `persistence_domain` on
  `memmap=`). A third, `pmem_redo_powerloss.cnf`, adds
  `__RedoLogPmemPowerLossEmulation=1`.
- `mysql-test/lib/My/ConfigFactory.pm`: add `{ 'FileSystemPathRedoLog' =>
  \&fix_redo_log_path }` to `@ndbd_rules` (`477`) [V]. The rule returns
  `$ENV{MTR_NDB_PMEM_DIR}/<vardir basename>/ndbd.<idx>` when that variable
  is set and the effective `RedoLogMode` is pmem, and `undef` otherwise.
  `undef` sets nothing (`run_rules_for_group`, `718-736`) [V].
- New `mysql-test/suite/ndb/pmem_redo.skip`:
  - `ndb_encrypted_filesystem_*` (refused, Q5);
  - `ndb_redo_log_reader` (file format);
  - `ndb_fragmented_redo_log_buffer` and its encrypted variant (no REDO
    buffer in PMEM mode);
  - `ndbinfo` and `ndbinfo_backup` (their `logbuffers` and `logspaces`
    output changes; record PMEM results later);
  - tests whose `.cnf` sets `Diskless=1` or `EncryptedFileSystem=1` (grep
    finds `ndb_blob_big`, `ndb_setup_large`, `ndb_setup_ronsql`,
    `ndb_secretsfile_*`; check each).
- New tests in `suite/ndb/t/` (each with a `.cnf` that includes
  `pmem_redo.cnf`):
  - `ndb_pmem_redo_reader.test` (M3);
  - `ndb_pmem_restart_gci.test`, through `suite/ndb/include/run_ndbapitest.inc`
    with `testRestartGci -n InsertRestartGci` and `-n GciLedgerSR`;
  - `ndb_pmem_torn_tail.test` (`-n GciLedgerTornTail`, `-n
    GciLedgerCrashPoints -l 1`).

**Autotest:**
- Reuse P S3.6's `test/run-test/conf-pmem-nodax.cnf` (`RedoLogMode=pmem`,
  `__RedoLogPmemTestMode=nodax`, small REDO). Add
  `conf-pmem-emulated.cnf` for `memmap=` hosts
  (`__RedoLogPmemTestMode=emulated`,
  `FileSystemPathRedoLog=CHOOSE_pmem_dir`). Each has a `.2node` and a
  `.4node` cluster, copied from `conf-autotest.cnf` (`40`) [V], with
  `NoOfFragmentLogFiles=6` and `FragmentLogFileSize=64M`.
- New lists `pmem-redo-tests.txt` (run before pushes) and
  `pmem-redo-long-tests.txt` (run before milestones); there is no CI, so
  they are named by content, not by schedule
  (§4.1). They extend P S3.6's short list (`SR1`, `SR2`, `NoLoad`,
  `RestartOK`, `RestartFDSR`, `CheckNextRedoFileOpened`), which runs before
  S4. `CheckNextRedoFileOpened` drops out once S5 makes the file switch
  synchronous.

**Size:** M, 3 days.

---

## 4. Test plan for step 1

### 4.1 Tests

Levels:
- U: unit (`NDB_ADD_TEST`, run by `ctest`).
- M: MTR.
- A: autotest (atrt).
- H: real hardware.

Hardware column:
- "no": runs on any build host, using the non-DAX test mode.
- "dax": needs Linux with `memmap=` or QEMU.
- "real": needs a CXL or NVDIMM device.

Commands assume a build directory `$B` and `cd mysql-test` for MTR.

| # | Test | Lvl | What it proves | Command | HW |
|---|---|---|---|---|---|
| U1 | `ndb_xxh3-t` (S1) | U | XXH3 of no bytes = `0x2D06800538D394C2`; every implementation (scalar, SSE2, AVX2, NEON) equals the header's XXH3 for all lengths 0–2100 and some long ones, at every alignment, with and without seed | `cd $B && ctest -R ndb_xxh3 --output-on-failure` | no |
| U2 | `pmem_redo_format-t` (W S4.1) and the validator cases of `pmem_redo_scan-t` | U | Framing per type (bounds, odd and 0 length, type 0, unknown type, crossing an mbyte); checksum bound to lap, part, file and position (the same bytes at another position fail); `RF_INVALIDATED` excluded; header validity; PREPARE spanning 1–4 pages, its body hashed one piece per page; torn spanned header; FD only at page 0 word 32; FILLER alignment; nothing after NEXT_MBYTE | `ctest -R pmem_redo --output-on-failure` | no |
| U3 | `pmem_redo_scan-t`, cases | U | Every row of recovery §3.3: torn last record; previous-lap record at E; unwritten or torn page header; torn mbyte header; FILLER at end; zeroed region; next file's FD torn with the slot lagging (E in the next file); orphans after a hole, then zero `[E, mbyte end)`, append, crash at an old record boundary, rescan: no orphan accepted | `ctest -R pmem_redo_scan` | no |
| U4 | `pmem_redo_scan-t --random` | U | Random logs with persist points. Crash model A2 after a random barrier B (lines skipped, copied or torn at 8 bytes). Then E ≥ B and the prefix is intact. The restart procedure (zero, head H or E, FILLER, append), a second crash and a rescan accept no stale record. 10⁴ seeded iterations, `--seed` to replay | `$B/runtime_output_directory/pmem_redo_scan-t --random --loops=10000` | no |
| U5 | `pmem_redo_slot-t` | U | Higher seq wins; all 256 subsets of a torn slot's 8-byte chunks leave the other slot chosen; neither valid gives an error; wrong part; config mismatch messages | `ctest -R pmem_redo_slot` | no |
| U6 | `ndb_pmem_emul-t` (S1) | U | The journal keeps only fenced lines; ADR vs eADR rules; `range_pending` across threads | `ctest -R ndb_pmem` | no |
| M1 | ndb suite in PMEM mode, non-DAX | M | All DBLQH paths end to end; SR/NR in MTR tests; file mode untouched for the rest | `./mtr --suite=ndb --defaults-extra-file=suite/ndb/pmem_redo.cnf --skip-test-list=suite/ndb/pmem_redo.skip --force --parallel=4` | no |
| M2 | ndb suite in PMEM mode on DAX | M | M1 plus `MAP_SYNC`, prefault, start checks on `memmap=` | `MTR_NDB_PMEM_DIR=/mnt/pmem0/mtr ./mtr --suite=ndb --defaults-extra-file=suite/ndb/pmem_redo_dax.cnf --skip-test-list=suite/ndb/pmem_redo.skip --force --parallel=2` | dax |
| M3 | `ndb_pmem_redo_reader` | M | The reader parses PMEM files, prints both slots and reports E equal to the node's log line | `./mtr ndb_pmem_redo_reader` | no |
| M4 | `ndb_pmem_restart_gci` | M | GCI ≤ R present, > R absent, ROW_GCI64 correct, in PMEM mode | `./mtr ndb_pmem_restart_gci` | no |
| M5 | `ndb_pmem_torn_tail` | M | Torn tails and every crash point recover with zero loss of GCP-saved data | `./mtr ndb_pmem_torn_tail` | no |
| M6 | `testNodeRestartGcpSaveAndFileChange` | M | GCP save during a file switch (slot ordering) | `./mtr --defaults-extra-file=suite/ndb/pmem_redo.cnf testNodeRestartGcpSaveAndFileChange` | no |
| M7 | ndb suite in file mode | M | File mode is unchanged (regression) | `./mtr --suite=ndb --force --parallel=4` | no |
| A1 | testSystemRestart in PMEM mode | A | SR replay, head, tail, invalidation under load and partial SRs. Cases: `SR1 T1`, `SR1 T6`, `SR2 T1`, `SR3 T6`, `SR4 T6`, `SR6 T1`, `SR7 T1`, `SR8 T1`, `SR9 T1`, `SR_UNDO T1`, `Bug24664`, `Bug27434 T1`, `Bug28770 T1`, `Bug29167 T1`, `Bug46651 T1`, `Bug54611 T1`, `basic T1`, `to T1`, `PLCP_1..5 T17`, `SR_DD_1 D2`, `SR_DD_2b D2` | `atrt` with `conf-pmem-nodax.cnf` (or `conf-pmem-emulated.cnf`), `--clusters=.2node --testcase-file=pmem-redo-tests.txt` | no/dax |
| A2 | testNodeRestart in PMEM mode | A | NR on the same code. Cases: `Bug44952 T1`, `GCPSaveAndFileChange T3`, `RestartRandomNode`, `RestartRandomNodeError T6 T13`, `RestartAllNodesAbort T6 T13`, `NF_Hammer -r 5 T1`, `GCP T1`, `GcpStop`, `LateCommit`, `pnr_lcp`, `Bug57522 T1`; with 4 nodes `Bug36199`, `Bug36245`, `Bug36276` | as A1 (`--clusters=.4node` for the 4-node cases) | no/dax |
| A3 | testRedo in PMEM mode | A | Many FD pages (`RestartFD -l 2`, `RestartFDSR`), `RestartOK`, `RedoFull` (expect 410 aborts, no queueing, Q7), `Bug36500`, `Latency410`, `CheckLCPStartsAfterSR`, `CheckLCPStartsAfterNR`. Not `CheckNextRedoFileOpened` or `RedoStallRecover` (file-mode only) | as A1 | no/dax |
| A4 | testRestartGci in PMEM mode | A | `InsertRestartGci T1`, `InitialNodeRestartUpdate T1`, `GciLedgerSR -l 20`, `GciLedgerNR -l 10`, `GciLedgerTornTail -l 20`, `GciLedgerCrashPoints -l 3` | as A1 | no/dax |
| A5 | New `testSystemRestart -n PmemRedoModeSwitch` | A | Changing `RedoLogMode` without an initial restart is refused with the message, in both directions; with an initial node restart it works (config change as `testRedo` `resizeRedoLog` does) | as A1 | no |
| A6 | `GciLedgerPowerLoss -l 200` (weekly) | A | No missing fence or flush (M2 assertions plus random power loss at drains) | as A1 plus `__RedoLogPmemPowerLossEmulation=1`, `--testcase-file=weekly-pmem--01-tests.txt` | no |
| A7 | File-mode regression lists | A | Regression: the A1–A4 cases in file mode, from the existing `daily-basic--*` lists | run by the pusher | no |
| Q1 | QEMU CXL Type 3 smoke | A | CXL region set-up, `persistence_domain` = `memory_controller` gives the ADR barrier mode, `MAP_SYNC` on CXL fsdax, region `numa_node` for the E20 warning; then `testRestartGci -n GciLedgerSR -l 3` | §4.4 | dax (QEMU) |
| H1 | Power cut with ledger | H | Real persistence: IPMI power-off of all data-node hosts under ledger load, then SR and verify (P6/X8) | `ipmitool -H <bmc> chassis power off` on every host, then A4 verify | real |
| H2 | Dirty-shutdown semantics | H | What the device's count means after a GPF failure (Q4, device-specific) | per device (P6) | real |

### 4.2 Non-DAX test mode (macOS ARM64, and Linux without `memmap=`)

- Set `RedoLogMode=pmem` and `__RedoLogPmemTestMode=nodax` (P S2.7). The
  REDO files are then ordinary files mapped `MAP_SHARED` without
  `MAP_SYNC`. The domain, bad-block and dirty-shutdown checks are skipped.
  `ndb_pmem` still uses its NT-store and fence code (ARM: `STNP`,
  `DC CVAP`, `DSB`), on macOS ARM64 too (platform S1.3).
- A process crash keeps everything in the page cache, so it behaves like
  `memmap=` for every test except the DAX checks.
- M2 (journal) works the same, because it is software.

### 4.3 `memmap=` on a Linux test host

Kernel options needed: `CONFIG_X86_PMEM_LEGACY`, `CONFIG_LIBNVDIMM`,
`CONFIG_BLK_DEV_PMEM`, `CONFIG_FS_DAX`, `CONFIG_ZONE_DEVICE`. Stock RHEL,
Fedora and Ubuntu kernels have them [I].

```
sudo dmesg | grep -i e820                      # pick a usable RAM range
sudo grubby --update-kernel=ALL --args="memmap=16G!16G"   # RHEL/Fedora
#   Debian/Ubuntu: add memmap=16G!16G to GRUB_CMDLINE_LINUX, then sudo update-grub
sudo reboot
ls -l /dev/pmem0 && ndctl list -RN             # region0 / namespace0.0
cat /sys/bus/nd/devices/region0/persistence_domain   # empty for memmap=  [V hw §4.3]
# if the namespace shows mode "raw":
sudo ndctl create-namespace -f -e namespace0.0 -m fsdax --map=mem    # [I]
sudo mkfs.xfs -f -m reflink=0 /dev/pmem0       # or: sudo mkfs.ext4 /dev/pmem0
sudo mkdir -p /mnt/pmem0 && sudo mount -o dax=always /dev/pmem0 /mnt/pmem0
findmnt -o TARGET,OPTIONS /mnt/pmem0           # must show dax=always
sudo chown $USER /mnt/pmem0 && mkdir -p /mnt/pmem0/mtr
xfs_io -f -c "truncate 4m" -c "mmap -S -rw 0 4m" /mnt/pmem0/probe  # -S = MAP_SYNC [I]
```

- **Sizing:** parallel workers × data nodes × parts × files × file size.
  MTR with `pmem_redo.cnf` (4 parts × 4 files × 16 MB) needs 256 MB per
  node; `--parallel=2` with 2 nodes needs 1 GB. The autotest config (6 ×
  64 MB × 4 parts) needs 1.5 GB per node.
- The data is lost at reboot, which is fine for tests.
- Also raise `InitialNoOfOpenFiles` (27 in `include/default_ndbd.cnf` [V]),
  because every REDO file stays open (S3).

### 4.4 QEMU emulated CXL Type 3 (the CXL set-up path)

```
truncate -s 4G /var/tmp/cxl-pmem0.raw; truncate -s 256M /var/tmp/cxl-lsa0.raw
qemu-system-x86_64 -machine q35,cxl=on -enable-kvm -smp 8 -m 8G,maxmem=16G,slots=4 \
  -drive file=guest.qcow2,if=virtio \
  -object memory-backend-file,id=cxl-pmem0,share=on,mem-path=/var/tmp/cxl-pmem0.raw,size=4G \
  -object memory-backend-file,id=cxl-lsa0,share=on,mem-path=/var/tmp/cxl-lsa0.raw,size=256M \
  -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxl.1 \
  -device cxl-rp,port=0,bus=cxl.1,id=root_port13,chassis=0,slot=2 \
  -device cxl-type3,bus=root_port13,persistent-memdev=cxl-pmem0,lsa=cxl-lsa0,id=cxl-pmem0 \
  -M cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=4G
# guest: kernel >= 6.x with CXL_BUS, CXL_PCI, CXL_ACPI, CXL_MEM, CXL_PORT,
#        CXL_PMEM, CXL_REGION, LIBNVDIMM, BLK_DEV_PMEM, FS_DAX; cxl-cli/ndctl >= 75
cxl list -M -D
cxl create-region -m -t pmem -d decoder0.0 -w 1 mem0
ndctl create-namespace -m fsdax -r region0
cat /sys/bus/nd/devices/region0/persistence_domain   # expect memory_controller [V hw §4.3]
cat /sys/bus/nd/devices/region0/numa_node
mkfs.xfs -f -m reflink=0 /dev/pmem0 && mount -o dax=always /dev/pmem0 /mnt/pmem0
```
The property names (`persistent-memdev`, `cxl-fmw`) are those of QEMU 8
and later [I]; check them against the QEMU in use. Whether QEMU emulates
a dirty-shutdown count is [I].

### 4.5 What emulation can and cannot prove

| Environment | Proves | Does not prove |
|---|---|---|
| Unit tests (U2–U5) | Format, checksum binding, the scan rule, slots and the restart procedure on synthetic logs, including torn, stale-lap and orphan records | That DBLQH calls them right |
| Non-DAX test mode | Every DBLQH path; recovery after `kill -9` and after injected torn tails (M1); the ledger | The DAX and `MAP_SYNC` path; `persistence_domain` |
| `memmap=` | The above, plus DAX, `MAP_SYNC`, prefault, fault cost and the empty-`persistence_domain` check | Power-fail durability; barrier placement (caches stay coherent); real latency |
| M2 journal | No missing fence or flush in RonDB code under the model "8-byte atomic, any order between fences"; torn persists at every point | That `ndb_pmem` actually emits the fence; device and firmware behaviour; real ADR/eADR |
| QEMU CXL | Region set-up, ADR mode on CXL, `MAP_SYNC` on CXL fsdax, NUMA attribution | Performance; real GPF and dirty shutdown |
| Real CXL/NVDIMM (H1, H2) | Durability across a real power cut; latency; dirty-shutdown meaning | — |

---

## 5. Order of the packages

```
S6.2 ──┬── S6.3 ── S6.4 ── S6.5 ── S6.6 ── S6.7
       │     ▲
S6.1 ──┼─────┘ (S6.1 needed from S6.5 on)
       └── S6.8
S7.4 (in file mode, at once) ─────────────────────────────┐
S7.2, S7.1 (after S5 and S6.6) ── S7.3 (after S1 journal) ─┴── S7.5
```

1. **S7.4** first, in file mode. It validates the checker on today's code
   and needs nothing new.
2. **S6.2** with U2–U5, as soon as S4's constants exist. Shared work with
   S4 on the header.
3. **S6.1, S6.3**.
4. **S6.4, S6.5, S6.6** in order. The first SR in PMEM mode works after
   S6.6.
5. **S6.7, S6.8**.
6. **S7.2, S7.1**, then **S7.3** once the platform journal exists.
7. **S7.5** lists and configs; M1/A1–A4 join the tests run before every
   push of PMEM code.

| Package | Size | Days |
|---|---|---|
| S6.1 restart reads from the mapping | S | 1.5 |
| S6.2 reader module and unit tests | L | 7 |
| S6.3 control area, slots, start-up checks | M | 3 |
| S6.4 phase 1, E, zeroing | M | 4 |
| S6.5 phase 3 layouts, flag invalidation | L | 5 |
| S6.6 phase 4, head, resume, slot | M | 4 |
| S6.7 node restart | S | 1.5 |
| S6.8 redoLogReader | M | 4 |
| S7.1 crash error inserts | M | 3 |
| S7.2 M1 injector, M3 checks | M | 3 |
| S7.3 M2 integration | M | 3 |
| S7.4 ledger checker | M | 5 |
| S7.5 test configs and lists | M | 3 |
| **Total** | | **≈ 47** |

---

## 6. New symbols and error inserts

| Kind | Symbol | Where |
|---|---|---|
| Module | In `PmemRedoFormat.hpp` (W): extended `PmemRedo::pageHeaderOk`, `recordOk`. New `PmemRedoScan.{hpp,cpp}`: `PmemRedo::Pos`, `Geom`, `PartView`, `Reason`, `RecInfo`, `ScanResult`, `checkRecord`, `findEnd`, `expectedLap`, `ceilUnit`, `buildCtrlConfig`, `checkCtrlConfig`, `buildSlot`, `pickSlot` | `src/kernel/blocks/dblqh/` |
| Constants | `PmemRedo::SLOT0_WORD` (8160), `SLOT1_WORD` (8176), `CTRL_MAGIC`, `SLOT_MAGIC`. The rest (`W_WORDS`, `HDR_*`, `FORMAT_MAGIC`, sizes, flags, `CONTROL_AREA_WORD`) is W §3.1 | `PmemRedoFormat.hpp` |
| DBLQH functions | **End-of-log scan:** `redoPmemSrPhase1`. **Slot read and write:** `redoPmemReadControlArea`, `redoWriteLastFileSlot`. **Zeroing:** `redoPmemZero`, `redoPmemSrFourth`. Others: `redoPmemCopyPages`, `redoPmemSendReadConf`, `readCommitLogPmem`, `redoPmemInvalidateCommit`, `execSrNextMbyte`, `execSrCompletedGci`, `srPhase1PartCompleted`, `redoPmemCrashPoint`, `redoPmemCopyTorn`, `redoPmemAssertPersisted`, `redoPmemVerifyCopy` | `Dblqh.hpp`, `DblqhMain.cpp` |
| `LogPartRecord` fields | `m_pmem_end`, `m_pmem_end_reason`, `m_pmem_file_base`, `m_pmem_zero_next`, `m_pmem_zero_stop`, `m_pmem_slot_seq`, `m_pmem_dsc_recorded`, `m_pmem_dsc_flags`, `m_pmem_unsafe_shutdown`, `m_pmem_inval_pending` | `Dblqh.hpp:1864` |
| `LogFileRecord` field | `m_pmem_base`, `m_pmem_fileRef` (P S3.4; used here) | `Dblqh.hpp:2310` |
| `CommitLogRecord` fields | `flags`, `gci_lo`, `transid1`, `transid2`, `opCount` | `Dblqh.hpp:3357` |
| Block fields | `c_redo_pmem_unsafe_shutdown` | `Dblqh.hpp` |
| CONTINUEB | `ZPMEM_SR_PHASE1` (62), `ZPMEM_SR_ZERO` (63) | `Dblqh.hpp` |
| Error inserts | 5155–5159, 5161–5172 (§S7.1); `Next DBLQH 5173` | `ERROR_codes.txt` |
| DUMP | `LqhPmemRedoInfo` 2369, `LqhPmemPowerLoss` 2370 | `DumpStateOrd.hpp` |
| Hook | power loss at `NdbShutdown` entry | `src/kernel/ndbd.cpp:1443` |
| Tests | `pmem_redo_format-t`, `pmem_redo_scan-t`, `pmem_redo_slot-t`; `testRestartGci` cases `GciLedger*`; `testSystemRestart -n PmemRedoModeSwitch`; MTR `ndb_pmem_*`; `pmem_redo*.cnf`, `pmem_redo.skip`; `pmem-redo-tests.txt`, `pmem-redo-long-tests.txt`; `ConfigFactory.pm` rule `fix_redo_log_path` | — |

---

## 7. Hooks that X5 needs (not planned here)

- **E from phase 1** (`m_pmem_end`) and an `m_pmem_scan_start` recorded
  in round 0 at `openExecSrStartLab` (`38855`), so that step B can rescan
  from the same place (E16).
- **The COMMIT dispatch in `execSr`** in one function, so that X5 can
  replace "gci > R → invalidate" with "gci ≥ g → hash table".
  `CommitLogRecord` already carries the real transid, `gci_lo`, opCount
  and flags.
- **COMPLETE, ABORT with `AF_AFTER_COMMIT`, SR_HEAD**: the validator
  already accepts them; the dispatch slots exist.
- **Stop rule**: the COMPLETED_GCI stop and the stop-mbyte crash
  (`39264-39283`) sit behind a predicate that X5 turns off, so the scan
  goes to E.
- **Phase 4 durable branch** in `redoPmemSrFourth`: no zeroing below E.
  The unit at E is closed with S6.6 step 3, applied at E: this is the
  "FILLER from E to the next W boundary" of W7, over the zeros of phase 1.
  Then SR_HEAD and `COMPLETED_GCI(G')`. GCI values are set to G' in `readSrFourthPhaseLab`
  (`40499-40515`).
- **`redoPmemInvalidateCommit`** reused for step C.
- **Stale marker**: `m_pmem_unsafe_shutdown`, the slot flags and the
  reserved control-area line.

---

## 8. Design issues found

1. **The page-0 copy can overwrite the control area.**
   - E13 says the FD is followed by a FILLER to the page end, and E10
     puts the slots in the last 256 bytes of page 0 of file 0. Both hold
     only if the writer never stores the FILLER's dead body.
   - The write-path note says the file switch "copies the 32 KB page into
     the mapping" (`pmem_redo_write_path.md` §6.2).
   - For file 0 the DRAM page is `logPageZero`, which is reused at every
     lap (`DblqhMain.cpp:43885-43896`) [V]. Its control area is the stale
     image loaded at the last restart.
   - A full-page copy would write old, valid slots with lower or equal
     seq. Phase 1 could then pick a slot that names an older file and cut
     the log there.
   - **Resolved in W** (D4, S5.3): the page-0 copy stops at the FILLER
     header's unit. Keep an `ndbrequire` that no copy into page 0 of file
     0 reaches word 8128, and correct the write-path note.
2. **E6 lists too few exceptions.** "A persisted unit is never written
   again except E9 and E10" also needs:
   - the zeroing of E12;
   - the restart's close of the head unit, which rewrites the FILLER or
     NEXT_MBYTE at H identically in step 1, and writes over zeros at E in
     X5.
   All are safe by hardware §1.3; the list should say so.
3. **W7 is stated for E, but step 1 resumes at H.** The same rule applies
   at H (S6.6 step 3). Zeroing starts at `ceilW(H)`, and the order is
   "zero, then close, then slot".
4. **The persisted position when the head page header was not
   persisted.**
   - If `COMPLETED_GCI(R)` ends exactly at a page end, H is word 32 of
     the next page, whose header may exist only in DRAM.
   - W's resume contract sets `m_pmem_persisted_lsn = appendLsn`, which
     is word 32 (`redoInitWritePosition`, W S5.1). The next copy would
     then start after the header, and the header would never reach PMEM.
   - **Proposal:** when recovery re-initialises the head page header, it
     sets the persisted position to the page start. W's first copy of the
     page then stores the header image (W D2). `redoInitWritePosition`
     must accept that case.
5. **`ZMIN_READ_BUFFER_SIZE = 3` is too small.** A PREPARE can span 4 pages
   (E13 side finding), and `execSr` waits for only 3 pages
   (`Dblqh.hpp:185`, `DblqhMain.cpp:39054-39081`) [V]. File mode has the
   same issue. **Answered (Q-A6):** 4 in both modes, as a separate bug fix
   (`implementation_plan.md` pull request 0).
6. **Where the dirty-shutdown count is recorded.** E17 says "record it in
   the control area". An in-place update of one field would need its own
   torn-write protection. It is stored in each slot instead (S6.3), and so
   is written torn-safe with every slot write.
7. **Who owns the control-area layout.** P §1 says "layout from S4"; W
   §7.2 says "recovery owns the slot layout". This plan owns it (S6.3) and
   provides the builders; W's `redoPmemInitFile()` calls them.
8. **A valid page 0 in every file.** Phase 1 checks every page 0 it reads
   (FD checksum, as `pmem_redo_recovery.md` §9 asks). W S4.8 writes page 0 of
   every file at initial start. Recovery also treats lap 0 as "never
   written", for robustness.
9. **Wording of V4 in `pmem_redo_recovery.md`.** Its V4 first said "seeded
   with magic, part number, LSN"; it now follows E4. Its "type rewritten to
   9, checksum computed as if COMMIT" is superseded by E9. Implement E4/E9
   only.

---

## 9. Open questions

1. **`gci_lo` in replay.** Today the replayed row's `gci_lo` is 0
   (`42782`, `42802`) [V]; `testRestartGci` tolerates the resulting
   rounding. Keep 0 in step 1 (behaviour unchanged), or use the logged
   `gci_lo` and make `ExactGCI` hold after every SR? Recommendation: keep
   0; X5 decides.
2. **V4 on every record in phase-3 scans** (recommended: simplest and
   strongest; XXH3 at about 12 ns per small record and 22 to 43 GB/s on the
   largest on x86-64, `step1_phases.md` Timings) or only on records acted upon
   (E11 allows it)? Measure on a 16 GB tail.
3. **Real time.** Phase 1 runs in slices of 8 pages and phase 4 zeroing in
   slices of 32 pages per signal. Is that acceptable for the watchdog and
   the other LDM work during restart?
4. **Split of the shared format code.** W's `PmemRedoFormat.hpp`
   (header-only) gets the extended `pageHeaderOk` and `recordOk`; the scan
   and the codecs go to `PmemRedoScan.{hpp,cpp}`. Agree, or should
   everything stay header-only?
5. **Resume details (Design issue 4).** Can `redoInitWritePosition` accept
   a persisted position at the page start when the head page header is
   new? And does `redoCopyOut` take `m_pmem_persisted_lsn = lsn(H)` as
   set by recovery before `writeFillerPmem`?
6. **M2 hook in `NdbShutdown`.** Excluding `NST_Normal` is proposed. Should
   graceful restarts also count as power loss? It is harmless, because
   the journals are empty then. The platform plan's three hook points all
   lead to `NdbShutdown`, so one hook replaces them.
7. **Fix `ZMIN_READ_BUFFER_SIZE` in file mode too?** (Design issue 5.)
   **Answered (Q-A6):** yes, a separate bug fix for both modes.
8. **Error-insert numbers.** 5155–5172 (skipping 5160) assume the write
   plan takes none, as W F16 says; confirm when merging. DUMP 2369 and
   2370 here, 2368 in W.
9. **CONTINUEB numbers 62 and 63.** Check them at merge against the CTE
   branches, which add codes.
10. **Media errors during the scan** (recovery Q6). Step 1 relies on the
    bad-block check before phase 1; SIGBUS handling is not planned.
11. **Delete statements in the ledger.** Are deletes of rows owned by
    another step needed to cover lock interactions, or are per-step key
    ranges enough for step 1? Proposal: enough.
12. **`redoLogReader --in-doubt`.** Step 1 or X8? Proposal: X8, with
    `--transid` in step 1.
