# RONDB-1150 step 1: implementation plan, DBLQH write side (S4, S5)

Status: implementation plan, 2026-10-28. No code has been changed. This is
one of four parallel plans for execution phase X2 (`pmem_redo_design.md`
§3). The others are `impl_step1_platform.md` (portlib, config, NDBFS),
`impl_step1_recovery_test.md` (restart reading, control area, zeroing, crash
tests) and `impl_next_steps.md`.

Paths are relative to `storage/ndb/`. Short names: `DblqhMain.cpp`,
`Dblqh.hpp`, `DblqhInit.cpp` are in `src/kernel/blocks/dblqh/`. Line numbers
are from commit bf6848d754f and were checked by reading the code.
Tags: **[V]** verified in the code, **[I]** inferred.

Scope: S4 (record writers) and S5 (write path). Step 1 ends with the REDO on
PMEM at today's durability (GCP based). The COMMIT and COMPLETE barriers of
invariants C and K are wired in X4. Step 1 adds the persist primitive, its
debug checks and a benchmark switch.

---

## 0. Summary

| Item | Plan |
|---|---|
| Branching | Separate PMEM functions for every record body, entered by one `if (c_redo_pmem)` at the top of today's writer. Small `if (c_redo_pmem)` blocks only in shared control flow (`checkNewMbyte`, `completedLogPage`, `writeNextLog`, `start_synch_gcp`, `writeSinglePage`, the reservation helpers). File-mode bodies stay byte for byte as today (§2) |
| Format code | A new header-only `PmemRedoFormat.hpp` with constants, `w0` packing, the suffix S, the CRC accumulator, the page-header image and minimal decoders. DBLQH, unit tests and `redoLogReader` (S6) share it |
| Fixed-size records | Built in a stack array, CRC finished, then appended with one `writeLogWords`. No fast and slow path per record |
| PREPARE | Header on the stack with a `w1` slot; key and attrinfo CRC'd per section chunk inside `writeKey`/`writeAttrinfoLab`; pad word; `w1` stored last |
| Persist | `redoCopyOut` = copy + `ndb_pmem_drain` + advance + release, always together. `redoPersist` = `redoPadToUnit` + `redoCopyOut` |
| Persist points in step 1 | GCP save, mbyte switch, file switch, page full (at record end). Plus, with the benchmark switch, at the X4 places of invariant C |
| Benchmark switch | `DUMP 2368 1` (works in release builds), block variable `c_redo_pmem_persist_commit` |
| Size | S4 about 14.5 person-days, S5 about 18.5; 4 pull requests (§8) |

---

## 1. Code facts that shape the plan

| # | Fact | Where | Consequence |
|---|---|---|---|
| F1 | Every append runs under `lock_log_part`, and a whole record is written in one critical section | `13381`/`13567`/`13579`, `15310`/`15345`, `17106`/`17125` [V] | Copy-out at record end never sees half a record, also with shared parts |
| F2 | Writers reach `LogFileRecord`s through `logPartPtrP->my_block` (the owner's arrays), because another LDM may write a shared part | `43571-43573`, `13479-13480` [V] | All new helpers must do the same, also for `m_pmem_base` |
| F3 | A full page is linked to the file's filled list by `completedLogPage`; it writes only at 8 pages or for `ZENFORCE_WRITE`/`ZLAST_WRITE_IN_FILE` | `41045-41065` [V] | PMEM mode keeps the link and returns |
| F4 | `writeLogWord`/`writeLogWords` complete a page and start the next one inside the record writer | `43729-43738`, `43754-43774` [V] | The CRC of a spanning record must skip page headers: CRC the source words, not the page |
| F5 | `initLogpage` runs before `currentFilepage++` in `writeLogWord`/`writeLogWords` (`43735-43737`, `43767-43769`) but after it in `writeNextLog` (`43882`, `43896`) and before it in `writeFileHeaderOpen` (`36157-36159`) [V] | | `initLogpage` cannot know the page number reliably. Page identity and header CRC are set when the PMEM image is built at the first copy (§10, D2) |
| F6 | NEXT_MBYTE is stored at the fill index without advancing it; the page is then linked as a partial "filled" page | `43824-43826`, `43845`, `43866` [V] | `redoCopyOut` copies each filled page up to its own fill index, not to 8192 |
| F7 | The new mbyte 0 of the next file has one page less (page 0 is the FD) | `43827-43833` [V] | `research_redo_log.md` §1.2 says "the last mbyte"; the code reduces the first mbyte of the next file. No change needed |
| F8 | `writeSinglePage` sets `ZNEXT_PAGE = RNIL` (`36212`) and stamps debug words and the checksum (`36214-36217`); `releaseLfoPages` walks `ZNEXT_PAGE` after FSWRITECONF (`35915-35926`) [V] | | A page written by file I/O cannot hold the clean PMEM header image during the write (§10, D1) |
| F9 | `count_free_log_pages` reports "buffer full" below `ZMIN_LOG_PAGES_OPERATION` = 10 free pages; `writePrepareLog` then queues or aborts with 1221 | `991`, `Dblqh.hpp:186`, `13383-13384` [V] | The staging budget must be at least 10 + the pages in use (§10, D3) |
| F10 | `initFirstPageLab` sets the header lap to 1 after `initLogpage`, while `logLap` is still 0 during initialisation (set to 1 at `35472`) | `35409-35410` [V] | The lap in S is read from the header of the page that holds `w0`, not from `logLap` |
| F11 | Initial-start head is `ZPAGE_HEADER_SIZE + 2`, after the 2-word COMPLETED_GCI(1) | `40449-40451` [V] | PMEM: head at word 48 (4-word record + 12-word FILLER) |
| F12 | `cmaxLogFilesInPageZero = (8192-32-128)/(3*clogFileSize)`, capped at 40 | `2833-2834` [V] | The PMEM FD ends at word 8069 or earlier; with the FILLER header the copy ends by word 8080, below the control area at word 8128 |
| F13 | `m_committed_log_space` is a `Uint8` flag (0/1); release asserts it is 0 | `Dblqh.hpp:3221`, `47888-47909`, `15738` [V] | Becomes a 3-state value in PMEM mode (§4, S4.7) |
| F14 | ERROR_INSERT is compiled only in debug builds or with `WITH_ERROR_INSERT` | `CMakeLists.txt:210-235`, `src/kernel/vm/pc.hpp:249-281` [V] | The benchmark switch is a DUMP code, so it works in release builds |
| F15 | No collision for the new names (`RF_INVALIDATED`, `ZFILLER_TYPE`, ...) in `storage/ndb`, `sql`, `include` | grep [V] | Names kept as given |
| F16 | DBLQH DUMP codes 2368-2379 are unused; DBLQH error inserts 5155-5159 are free, "Next DBLQH 5155" | `include/kernel/signaldata/DumpStateOrd.hpp:174-205`, `src/kernel/blocks/ERROR_codes.txt:197` [V] | This plan takes DUMP 2368; the test subtask takes error inserts from 5155 |
| F17 | Unit tests in kernel blocks use `NDB_ADD_TEST` | `src/kernel/blocks/dbtup/CMakeLists.txt:28,32` [V] | Same for `pmem_redo_format-t` |

---

## 2. File mode and PMEM mode: how the writers branch

**Recommendation: separate PMEM functions for record bodies, one dispatch
line each; `if (c_redo_pmem)` blocks only in shared control flow.**

Reasons from the code:

1. **Every word offset changes.** Today's COMMIT has `tableId` in word 1
   (`43611`); PMEM has the CRC there, packs four fields into two, and is 12
   words instead of 9. An `if` per word would touch every line of the file
   writer.
2. **Each writer has two paths.** A fast path into the page and a
   word-by-word path (`14234-14254`, `43597-43619`). In-line `if`s would have
   to be repeated in both.
3. **Each size appears four times** per writer: the mbyte check
   (`43578`), `m_total_written_words` (`43594`), `remainingWordsInMbyte`
   (`43595`) and the fast-path bound (`43597`). A separate function uses its
   own constant in all four.
4. **Review.** The file-mode diff of a writer is one line, so "file mode
   unchanged" can be checked by reading the diff.
5. **Cost.** One perfectly predicted branch on a block constant per record.

Shared helpers stay shared and unchanged: `writeLogWord`, `writeLogWords`,
`changeMbyte`, `writeFileDescriptor`, `initLogpage`. `writeKey` and
`writeAttrinfoLab` get an optional CRC accumulator (nullptr in file mode),
because they are generic section copiers; their bytes do not change.

| Function | `DblqhMain.cpp` | File mode | PMEM mode |
|---|---|---|---|
| `doWritePrepareLog` | `13529-13538` | three calls as today | `writePrepareLogPmem` |
| `writeCommitLog` | `43566` | unchanged body | `writeCommitLogPmem` |
| `writeAbortLog` | `43542` | unchanged body | `writeAbortLogPmem(flags)` |
| `writeCompletedGciLog` | `43631` | unchanged body | `writeCompletedGciLogPmem` |
| `writeFileHeaderOpen` | `36073` | unchanged body | `writeFileHeaderOpenPmem` |
| `writeCompleteLog` (new) | — | not called | PMEM only |
| `checkNewMbyte` | `14188-14189` | today's size | `PmemRedo::prepareLen` |
| `completedLogPage` | `41057` | unchanged | link only, return |
| `writeNextLog` | `43824`, `43846`, `43867`, `43883`, `43898-43926` | unchanged | NEXT_MBYTE record, copy-out, sync file switch |
| `start_synch_gcp`, `initGcpRecLab` | `33988`, `33996`, `34074` | unchanged | persist, GCP_SAVECONF at once |
| `writeSinglePage` | `36214-36217` | unchanged | no debug stamp, no page checksum |
| `increment_/decrement_committed_mbytes` | `47888`, `47899` | unchanged | 46 words, two-step release |

---

## 3. Data structures

### 3.1 New header `src/kernel/blocks/dblqh/PmemRedoFormat.hpp`

Header-only. Depends on `ndb_types.h` and `util/ndb_crc32c.h` (S1). No block
types, so DBLQH, the NDBFS-thread callback `Dblqh::execFSWRITEREQ`, unit
tests and `redoLogReader` can all include it.

```cpp
namespace PmemRedo {
// Geometry (E2)
constexpr Uint32 W_BYTES = 64, W_WORDS = 16;
constexpr Uint32 CONTROL_AREA_WORD = 8192 - 64;  // last 256 B of page 0 (E10), content owned by recovery
// w0 (E3)
constexpr Uint32 TYPE_MASK = 0xFF, LEN_SHIFT = 16;
inline Uint32 w0(Uint32 type, Uint32 flagBits, Uint32 len) { return type | flagBits | (len << LEN_SHIFT); }
inline Uint32 type(Uint32 w) { return w & TYPE_MASK; }
inline Uint32 len(Uint32 w) { return w >> LEN_SHIFT; }
// Sizes in words (E13)
constexpr Uint32 PREP_HEAD = 8, COMMIT = 12, ABORT = 4, COMPLETE = 4,
                 COMPLETED_GCI = 4, NEXT_MBYTE = 2, SR_HEAD = 6, FILLER_MIN = 2,
                 FD_HEADER = 4, FD_POS_NO_FD = 2, FD_POS_FILE_NO = 3;
constexpr Uint32 FILLER_MAX = W_WORDS - 2;                       // 14
constexpr Uint32 RESERVE = (COMMIT + FILLER_MAX) + (COMPLETE + FILLER_MAX) + 2;  // 46
constexpr Uint32 RESERVE_AT_COMMIT = COMMIT + FILLER_MAX;        // 26
// Page header (format §4.1)
constexpr Uint32 HDR_FORMAT_MAGIC = 22, HDR_RESTART_GEN = 23, HDR_LOG_PART_NO = 24,
                 HDR_WRITE_UNIT = 25, HDR_NODE_ID = 26;
constexpr Uint32 FORMAT_MAGIC = 0x504D5231;                      // "PMR1", version 1
// Words of the 32-word header that live in DRAM only; 0 in the image and in the CRC (D1)
constexpr Uint32 DRAM_ONLY_MASK = (1u<<4)|(1u<<5)|(1u<<8)|(1u<<9)|(1u<<11)|
    (1u<<12)|(1u<<13)|(1u<<14)|(0xFu<<17)|(0x1Fu<<27);
// Suffix S (E4), never stored
struct Suffix { Uint32 lap, gen, partFile, pos; };
inline Suffix suffix(Uint32 lap, Uint32 part, Uint32 file, Uint32 page, Uint32 idx)
  { return Suffix{lap, 0, (part << 16) | file, page * 8192 + idx}; }
// CRC accumulator: CRC32C(w0 & ~RF_INVALIDATED || w2..w(n-1) || S)
struct RecCrc {
  Uint32 crc; Uint32 *w1; Suffix s;
  void begin(Uint32 w0v, Uint32 *w1p, const Suffix &sx);   // CRC of masked w0
  void add(const Uint32 *p, Uint32 nWords);                // body words in logical order
  void finish();                                           // add S, store *w1
};
inline Uint32 padWords(Uint32 pageIdx) { return (W_WORDS - (pageIdx % W_WORDS)) % W_WORDS; }
inline Uint32 prepareLen(Uint32 key, Uint32 ai, bool transid)
  { Uint32 n = PREP_HEAD + (transid ? 2 : 0) + key + ai; return n + (n & 1); }
inline Uint32 fdLen(Uint32 nFD, Uint32 fileSizeMb)
  { Uint32 n = FD_HEADER + 3 * nFD * fileSizeMb; return n + (n & 1); }
// Header image and decoders (decoders are minimal here; S6 extends them)
void buildPageHeader(Uint32 img[32], const Uint32 dramHdr[32], Uint32 fileNo,
                     Uint32 pageNo, Uint32 logPartNo, Uint32 nodeId);
bool pageHeaderOk(const Uint32 hdr[32], Uint32 fileNo, Uint32 pageNo, Uint32 logPartNo);
bool recordOk(const Uint32 *rec, Uint32 maxWords, const Suffix &s);  // record inside one page
}  // namespace PmemRedo
```

Type and flag names in `Dblqh.hpp`, next to the type codes at
`Dblqh.hpp:253-262` [V], so they read like today's constants:

```cpp
#define ZFILLER_TYPE 10
#define ZCOMPLETE_TYPE 11
#define ZSR_HEAD_TYPE 12
#define RF_INVALIDATED  (1u << 8)   // w0 flag bit 0, COMMIT, outside the CRC
#define CF_DURABLE      (1u << 9)   // COMMIT
#define AF_AFTER_COMMIT (1u << 9)   // ABORT (rule F)
#define PF_TRANSID      (1u << 9)   // PREPARE, off in iteration 1
```

`PmemRedoFormat.hpp` uses the same numeric values (one source; `Dblqh.hpp`
includes the header and defines the macros from it). Types 6
(`ZNEXT_LOG_RECORD_TYPE`) and 9 (`ZINVALID_COMMIT_TYPE`) stay for file mode
and are never written in PMEM mode. The dead `ZPOS_*` record offsets at
`Dblqh.hpp:265-307` are not reused.

### 3.2 `Dblqh.hpp` fields

| Struct | Field | Type | Meaning | Set by |
|---|---|---|---|---|
| `LogPartRecord` (`1864`) | `m_pmem_persisted_lsn` | `Uint64` | Every byte of the part's log below it is persistent. Changed only under `m_log_part_mutex`. Always a multiple of W | S5 |
| | `m_pmem_persist_count` | `Uint64` | Barriers (`redoCopyOut` calls) | S5 |
| | `m_pmem_bytes_copied` | `Uint64` | Bytes stored to PMEM | S5 |
| | `m_pmem_filler_words` | `Uint64` | FILLER words written (not FD fillers) | S4 |
| | `m_pmem_persist_hist[16]` | `Uint32` | Persist latency, bucket `log2(ns)` | S5 |
| | `m_pmem_unfenced` | `Uint32` | Debug: bytes copied and not yet fenced; 0 at every unlock | S5 |
| `LogFileRecord` (`2310`) | `m_pmem_base` | `Uint8 *` | Start of the file's mapping; nullptr in file mode | platform, from FSOPENCONF |
| `TcConnectionrec` (`2904`) | `m_redo_end_lsn` | `Uint64` | End LSN of the op's newest record that must be persistent (COMMIT; COMPLETE and rule-F ABORT from X4). 0 = none | S4 writers |
| | `m_committed_log_space` (`3221`, existing) | `Uint8` | 0 none, 1 full reservation, 2 tail only (PMEM, between COMMIT and COMPLETE, from X4) | S4.7 |
| `Dblqh` | `c_redo_pmem` | `bool` | PMEM mode | platform (`execREAD_CONFIG`) |
| | `c_redo_pmem_persist_commit` | `Uint32` | Benchmark switch, 0 or 1 | S5.8 (DUMP 2368) |

Cost: 8 bytes more per `TcConnectionrec` (one per concurrent operation) and
about 100 bytes per log part. `m_redo_end_lsn` is set to 0 in the
`TcConnectionrec` constructor (`Dblqh.hpp:3004`, beside `logWriteState(NOT_STARTED)`), in `seizeTcrec`
(`DblqhMain.cpp:7519`, beside `m_committed_log_space = 0`) and in
`execLQHKEYREQ` (`10040`, beside `logWriteState = NOT_STARTED`).

### 3.3 Positions and LSN

```
fileBytes   = Uint64(clogFileSize) << 20
lsn(lap, f, p, w) = (Uint64(lap) * noLogFiles + f) * fileBytes + p * 32768 + w * 4
appendLsn(part)   = lsn(logLap, curFile.fileNo, curFile.currentFilepage,
                        curPage[ZCURR_PAGE_INDEX])
address(f, p, w)  = file(f).m_pmem_base + p * 32768 + w * 4
```

- Monotonic within a run: `logLap` grows only when the head wraps to file 0
  (`43847-43854`) [V], and the persist before every switch keeps the
  persisted LSN and the append end in the same file and mbyte (§5, S5.3).
  So `redoCopyOut` only maps LSN to (page, word) inside the current file.
- A restart that moves the head back lowers the LSN. Recovery calls
  `redoInitWritePosition(part)` after it sets the head (§7.2).
- Overflow needs `lap * noLogFiles * fileBytes ≥ 2^64`, about 2^30 laps of
  16 GB. Not a concern [I].
- "Nothing new to persist": `appendLsn == m_pmem_persisted_lsn`, or the
  current page holds only its header (`ZCURR_PAGE_INDEX == 32`) and the
  persisted LSN is that page's start.

---

## 4. S4: record writers

### S4.1 `PmemRedoFormat.hpp` and its unit test

- **Goal.** One tested definition of the bytes: `w0`, CRC with suffix,
  page-header image, padding, sizes, reservation.
- **Files.** New `src/kernel/blocks/dblqh/PmemRedoFormat.hpp` (§3.1); new
  `src/kernel/blocks/dblqh/pmem_redo_format-t.cpp`; add
  `NDB_ADD_TEST(pmem_redo_format-t pmem_redo_format-t.cpp LIBS ndbgeneral ndbportlib)`
  to `src/kernel/blocks/dblqh/CMakeLists.txt` (after line 35).
- **Header image** (`buildPageHeader`): zero all 32 words; copy words 1, 2,
  3, 6, 7, 10, 21 from the DRAM header (lap, GCI snapshots, version, files,
  last prepare ref, parts); set 15 = pageNo, 16 = fileNo, 22 = magic,
  23 = 0 (reserved restart generation, E12), 24 = logPartNo, 25 = 64,
  26 = nodeId; word 0 = CRC32C over words 1-31 with the `DRAM_ONLY_MASK`
  words read as 0. With the mask (D1) a header written by file I/O at
  initial start, with `ZNEXT_PAGE = RNIL` in word 4, is still valid.
- **File mode.** Not included by any file-mode path.
- **Tests.**
  `ctest -R pmem_redo_format-t --output-on-failure` (from the build directory):
  - CRC32C("123456789") = `0xE3069283` through `RecCrc` with an empty
    suffix (catches a wrong chaining convention of `ndb_crc32c`, Q1);
  - each record type built and accepted by `recordOk`; one changed body
    word, one changed suffix word (lap, part, file, position) → rejected;
  - `RF_INVALIDATED` set on a COMMIT → still accepted;
  - FILLER: CRC covers only `w0` and S; changing a body word → accepted;
  - header: changing any of words 1-3, 6, 7, 10, 15, 16, 21-26 → rejected;
    changing a `DRAM_ONLY_MASK` word → accepted; zero page → rejected;
  - `padWords(idx)` for every even idx in [32, 8190]: result even, < 16,
    idx + result is a multiple of 16;
  - `prepareLen` even and ≤ 23130 for the limits of `ndb_limits.h`;
    `fdLen(2, 1024)` = 6148; `fdLen` ≤ 8037 for every `clogFileSize` in
    [4, 1024] with `nFD = min(40, 8032/(3*size))`; `RESERVE` = 46.
- **Depends on.** S1 `ndb_crc32c`.
- **Size.** M, 3 days.
- **Review points.** The mask list must match recovery's reader (S6), which
  should use this same header. Little-endian word order of the CRC input
  (format §3.3).

### S4.2 Framing helpers in DBLQH

- **Goal.** One way to frame a record at the current position.
- **Functions (new, `DblqhMain.cpp`, beside `writeLogWords` at `43746`):**
  - `void redoRecBegin(PmemRedo::RecCrc &c, LogPartRecord *part, LogFileRecord *file, LogPageRecord *page, Uint32 w0, Uint32 *w1)`:
    S from `page->logPageWord[ZPOS_LOG_LAP]` (F10), `part->logPartNo`,
    `file->fileNo`, `file->currentFilepage`, `page->logPageWord[ZCURR_PAGE_INDEX]`.
  - `void redoAppendFixed(Signal*, LogPartRecord*, Uint32 *rec, Uint32 len)`:
    for COMMIT, ABORT, COMPLETE, COMPLETED_GCI and SR_HEAD (recovery). Order:
    mbyte check `len + ZNEXT_LOG_SIZE > remainingWordsInMbyte → changeMbyte`
    (as `43578-43582`); take the position; `RecCrc` over `rec`; store
    `rec[1]`; `writeLogWords(rec, len)`; `remainingWordsInMbyte -= len`;
    `m_total_written_words += len`; `redoEndOfRecord`.
- **File mode.** Not called.
- **Tests.** Through S4.3-S4.5 and the debug self-check of S5.2.
- **Size.** S, 1.5 days.
- **Review points.** S is taken after the mbyte check, never before
  (`changeMbyte` moves the position).

### S4.3 PREPARE writer

- **Goal.** PREPARE with the length in `w0` and the CRC in `w1` (format §5.1).
- **Changes.**
  - `doWritePrepareLog` `DblqhMain.cpp:13529-13538`: `if (c_redo_pmem)
    writePrepareLogPmem(...) else { writeLogHeader; writeKey; writeAttrinfoLab; }`.
    The start position (`13517-13525`) and `logStopPageNo` (`13548-13553`)
    stay as they are.
  - New `void writePrepareLogPmem(Signal*, const TcConnectionrec*, LogPageRecordPtr&, LogFileRecordPtr&, LogPartRecord*)`:
    build words 0-7 on the stack (`w0 = PmemRedo::w0(ZPREP_OP_TYPE, 0, len)`,
    `w1 = 0`, then hashValue, operation, aiLen, keyLen, rowid as
    `14239-14244`); remember `w1p = &page[idx + 1]` (`w0` is at an even
    index, so `w1` is on the same page); `redoRecBegin`; CRC words 2-7;
    `writeLogWords(hdr, 8)`; `writeKey(..., &c)`; `writeAttrinfoLab(..., &c)`;
    if `keyLen + aiLen` is odd, append and CRC one 0 word; `c.finish()`
    (stores `*w1p` last); `m_total_written_words += len`;
    `redoEndOfRecord`.
  - `writeKey` `14262` and `writeAttrinfoLab` `14286`: new last parameter
    `PmemRedo::RecCrc *crc = nullptr`; in the chunk loops (`14273-14276`,
    `14303-14306`) add `if (crc) crc->add(srcPtr, length);`. The CRC reads
    the section chunk, so interleaved page headers are skipped by
    construction (F4).
  - `checkNewMbyte` `14188-14189`: `ttotalLogSize = c_redo_pmem ?
    PmemRedo::prepareLen(primKeyLen, currTupAiLen, false) : <today>`.
  - Declarations at `Dblqh.hpp:4164-4170`, `4230`.
- **File mode.** `writeKey`/`writeAttrinfoLab` get `nullptr`; one branch
  per section chunk, no change of bytes. `checkNewMbyte` keeps today's
  expression.
- **Tests.** Unit: S4.1 PREPARE vectors. Integration: the debug self-check
  (S5.2) on every PREPARE in MTR on PMEM; large rows (attrinfo > 2 pages)
  with `ndb_bulk_load`-style inserts of 14000-byte rows; `redoLogReader`
  (S6) on the files.
- **Depends on.** S4.1, S4.2.
- **Size.** M, 2 days.
- **Risks.** The pointer `w1p` must stay valid until `finish`: the page is
  on the filled list or current, and pages are released only by
  `redoCopyOut`, which runs after `finish` (S5.2). `PF_TRANSID` is never set.

### S4.4 COMMIT, ABORT, COMPLETED_GCI and COMPLETE

- **Goal.** The fixed-size records of format §5.2-§5.5.
- **Changes.**
  - `writeCommitLog` `43566`: first line `if (c_redo_pmem) { writeCommitLogPmem(signal, regTcPtr, logPartPtrP, false); return; }`.
    New `writeCommitLogPmem(Signal*, TcConnectionrec*, LogPartRecord*, bool durable)`:
    `rec = { w0(ZCOMMIT_TYPE, durable ? CF_DURABLE : 0, 12), 0, tableref,
    schemaVersion, fragmentid, (logStartFileNo << 16) | logStartPageIndex,
    (logStartPageNo << 16) | logStopPageNo, gci_hi, gci_lo, transid[0],
    transid[1], 0 /* opCount, X4 */ }`; `redoAppendFixed`;
    `op->m_redo_end_lsn = appendLsn(part)`; `release_committed_words(part,
    op, AT_COMMIT, durable)` (S4.7). Step 1 always passes `durable = false`.
  - `writeAbortLog` `43542`: dispatch to new `writeAbortLogPmem(Signal*,
    TcConnectionrec*, LogPageRecordPtr&, LogFileRecordPtr&, LogPartRecord*, Uint32 flags)`:
    `{ w0(ZABORT_TYPE, flags, 4), 0, transid[0], transid[1] }`; release
    `AT_ABORT`. Today's callers (`898`, `17123`) pass 0. With
    `AF_AFTER_COMMIT` it also sets `m_redo_end_lsn`; that caller comes with
    X4 (rule F).
  - `writeCompletedGciLog` `43631`: dispatch to `writeCompletedGciLogPmem`:
    `{ w0(ZCOMPLETED_GCI_TYPE, 0, 4), 0, cnewestCompletedGci, 0 }`. Keep
    error insert 5051 (`43640-43643`), the debug print and
    `logPartNewestCompletedGCI = cnewestCompletedGci` (`43661`).
  - New `void writeCompleteLog(Signal*, TcConnectionrec*, LogPartRecord*)`:
    `ndbrequire(c_redo_pmem)`; `{ w0(ZCOMPLETE_TYPE, 0, 4), 0, transid[0],
    transid[1] }`; sets `m_redo_end_lsn`; release `AT_COMPLETE`.
    **Format only: no caller in step 1.** X4 calls it from `execCOMPLETE`
    and `execCOMPLETEREQ`.
  - Declarations at `Dblqh.hpp:4150-4157`.
- **File mode.** One dispatch line per writer.
- **Tests.** Unit vectors (S4.1). In MTR on PMEM: the self-check on every
  record; an IgnoreError transaction to hit `writeAbortLog` from
  `abortCommonLab` (`17123`); a GCP every 100 ms (`TimeBetweenGlobalCheckpoints=100`)
  for many COMPLETED_GCI records. `writeCompleteLog` and the
  `AF_AFTER_COMMIT` path are tested only by the unit test until X4.
- **Depends on.** S4.1, S4.2, S4.7.
- **Size.** M, 2 days.
- **Review points.** `gci_lo` is set before every `writeCommitLog` call
  (`15203`, `15290`) [V]; for the dirty-write call at `13577` it is
  whatever LQHKEYREQ set [I], as the design allows ("what LQH has").

### S4.5 FILLER, NEXT_MBYTE and the pad

- **Goal.** Close a write unit (format §5.6, §5.7, §7.1).
- **Changes.**
  - New `void writeFillerPmem(Signal*, LogPartRecord*, LogPageRecordPtr&, LogFileRecordPtr&, Uint32 len)`:
    `ndbrequire(len >= 2 && len % 2 == 0)`; `w0(ZFILLER_TYPE, 0, len)`,
    CRC over `w0 || S`; zero the body in DRAM, so the copied unit is
    deterministic (the body is not interpreted); `writeLogWords`;
    `remainingWordsInMbyte -= len`; `m_pmem_filler_words += len`. Not
    counted in `m_total_written_words`. Does not call `redoEndOfRecord`
    (only `redoPersist` writes fillers; its copy follows at once).
  - New `void writeNextMbytePmem(LogPartRecord*, LogFileRecord*, LogPageRecord*)`:
    at `idx = ZCURR_PAGE_INDEX`, store `w0(ZNEXT_MBYTE_TYPE, 0, 2)` and the
    CRC; zero words up to the next W boundary; set `ZCURR_PAGE_INDEX` to that
    boundary so the copy includes the unit (F6). The `ZNEXT_LOG_SIZE = 2`
    reserve (`Dblqh.hpp:245`) guarantees room [V].
  - `redoPadToUnit` (S5.2) decides between them with `PmemRedo::padWords`.
- **File mode.** Not called.
- **Tests.** Unit: `padWords` table. MTR on PMEM: a test that writes enough
  to cross 3 mbytes and 2 files with small files (`FragmentLogFileSize=4M`,
  `NoOfFragmentLogFiles=3`), then `DUMP 2368 3` (verify, S5.8).
- **Size.** S, 1 day.

### S4.6 Page header image and the FD writer

- **Goal.** The write-once header (E5) and the FD record with a FILLER to
  the page end (format §5.8).
- **Changes.**
  - `initLogpage` `35577-35605`: **no change.** It fills the DRAM header as
    today; the image is built from it at the first copy (F5, D2).
  - New `void redoPmemHeaderImage(Uint32 img[32], const LogPageRecord*, Uint32 fileNo, Uint32 pageNo, const LogPartRecord*)`:
    wrapper over `PmemRedo::buildPageHeader` with `getOwnNodeId()`.
  - `writeFileHeaderOpen` `36073`: dispatch to new
    `writeFileHeaderOpenPmem(Signal*, Uint32 wmoType, LogPageRecordPtr&, LogFileRecordPtr, LogPartRecord*)`:
    - FD at word 32: `w0(ZFD_TYPE, 0, fdLen)`, word 34 = nFD, word 35 =
      own fileNo (never rewritten), arrays from word 36 with today's loop
      (`36104-36125`, base `ZPAGE_HEADER_SIZE + PmemRedo::FD_HEADER`), pad
      word if odd;
    - CRC over the words in the page with S = (header lap, part, fileNo,
      page 0, index 32);
    - FILLER from the FD end to word 8192 (only `w0` and `w1` are stored;
      the body is neither zeroed nor copied, D4);
    - `ndbrequire(fdEnd + 2 <= PmemRedo::CONTROL_AREA_WORD)` (F12);
    - `ZCURR_PAGE_INDEX = 8192`;
    - I/O: `ZNORMAL` → `redoCopyPageZero` (S5.3); `ZINIT` → S4.8.
  - `writeDbgInfoPageHeader` (`46750`) and `calcPageCheckSum` are never
    called in PMEM mode (`completedLogPage` returns first, S5.2;
    `writeSinglePage` skips them, S4.8).
- **File mode.** One dispatch line.
- **Tests.** Unit: header image vectors, `fdLen` bounds. MTR on PMEM: file
  switch test of S4.5, then `DUMP 2368 3`, which checks page 0 of each
  file it reaches. After S6: `ndb_redo_log_reader` on every file.
- **Size.** M, 2 days.
- **Risks.** The control area must never be stored by this path (D4); the
  `ndbrequire` and the S5.3 copy bound enforce it.

### S4.7 Space reservation, two-step release

- **Goal.** Reserve 46 words per logged prepare in PMEM mode (E13,
  format §7.3).
- **Changes** (`DblqhMain.cpp:47881-47909`):
  - `increment_committed_mbytes` `47888`: PMEM: `m_committed_words +=
    PmemRedo::RESERVE`; `m_committed_log_space = 1`. File mode unchanged.
  - `decrement_committed_mbytes` `47899`: file mode unchanged; its PMEM
    callers use the new
    `void release_committed_words(LogPartRecord*, TcConnectionrec*, RedoRelease what, bool durable)`:

    | Event | State before | Released | State after |
    |---|---|---|---|
    | COMMIT, non-durable (all of step 1) | 1 | 46 | 0 |
    | COMMIT, durable (X4) | 1 | 26 | 2 |
    | COMPLETE (X4) | 2 | 20 | 0 |
    | ABORT, normal | 1 | 46 | 0 |
    | ABORT, rule F (X4) | 2 | 20 | 0 |

  - The release assert at `15738` stays. From X4 it also checks that every
    durable operation wrote its COMPLETE or rule-F ABORT.
- **File mode.** Untouched.
- **Tests.** Unit: the arithmetic. MTR on PMEM: after a test, `DUMP 2368 2`
  prints `m_committed_words`, which must be 0 when no transaction is open.
- **Size.** S, 1 day.
- **Review points.** The tail-problem limit (`43976-43977`) reacts earlier:
  1 million operations in flight reserve 46 × 4 B = 184 MB per part [I].

### S4.8 Initial-start images (DBLQH side of S3)

- **Goal.** At initial start the files hold the new format. NDBFS creates,
  zeroes and maps the files (platform, S3); DBLQH builds the bytes.
- **Changes.**
  - `execFSWRITEREQ` `35733-35790` (runs in an NDBFS thread): for mbyte
    first pages and the last page (`35767-35783`), in PMEM mode build the
    header with `PmemRedo::buildPageHeader(img, hdr, fileNo, page_no, ...)`
    (pure, no block state) instead of `calcPageCheckSum`.
  - `writeFileHeaderOpenPmem(ZINIT)` (called from `initWriteEndLab`
    `35394`): after building FD + FILLER, put the header image into words
    0-31 of the page, keeping `ZNEXT_PAGE = RNIL` (F8; valid because of
    the mask, D1), then `writeSinglePage` as today.
  - `writeSinglePage` `36214-36217`: `if (!c_redo_pmem) { writeDbgInfoPageHeader(...); ...calcPageCheckSum...; }`.
  - `initFirstPageLab` `35409-35414`: PMEM: after `ZPOS_LOG_LAP = 1`,
    append COMPLETED_GCI(1) (4 words) and a 12-word FILLER at words 32-47
    with the framing helpers, header image into words 0-31, then
    `writeSinglePage`.
  - `initFourth` `40451`: PMEM head index `ZPAGE_HEADER_SIZE + 16`. This
    line is in the restart code; agreed with recovery (§7.2).
- **Alternative.** If the platform maps the files before these writes, use
  the run-time copy path instead of `writeSinglePage`. The masked CRC makes
  both work.
- **Decided** (`implementation_plan.md` R2 and §5.1, Q-A4 answered):
  the alternative. The platform plan (S3.5) maps every file at open with
  `OM_INIT`, and `redoPmemInitFile()` writes page 0 of every file and
  page 1 of file 0 through the mapping, with no LFO and no FSWRITEREQ. The
  header CRC then covers all of words 1–31 and `DRAM_ONLY_MASK` goes; the
  S4.1 test "changing a `DRAM_ONLY_MASK` word → accepted" becomes
  "changing any of words 1–31 → rejected".
- **File mode.** Every change is under `if (c_redo_pmem)`.
- **Tests.** Initial start on `memmap=` PMEM (S3 test), then `DUMP 2368 3`.
  After S6: `ndb_redo_log_reader` on a freshly initialised file.
- **Depends on.** S3 (NDBFS full init, `OM_INIT` forced), S4.1, S4.6.
- **Size.** M, 2 days.

---

## 5. S5: write path

### S5.1 Positions, LSN and the new fields

- **Goal.** §3.2 and §3.3 in code.
- **Changes.** Fields of §3.2 in `Dblqh.hpp`; inline helpers in `Dblqh.hpp`
  after `unlock_log_part` (`6648`): `Uint64 redoLsn(const LogPartRecord*, Uint32 fileNo, Uint32 pageNo, Uint32 word)`,
  `Uint64 redoAppendLsn(LogPartRecord*)`, `Uint8 *redoPmemAddr(LogFileRecord*, Uint32 pageNo, Uint32 word)`,
  `bool redoHasUnpersisted(LogPartRecord*)`. New
  `void redoInitWritePosition(LogPartRecord*)`: sets `m_pmem_persisted_lsn
  = appendLsn` and checks that it is W-aligned and that the filled list is
  empty. Called by recovery at the resume point (§7.2).
- **File mode.** Fields unused.
- **Tests.** Unit test of the LSN formula in `pmem_redo_format-t` (pure
  arithmetic copied into the header as `PmemRedo::lsn`).
- **Size.** S, 1 day.

### S5.2 The persist primitive

- **Goal.** Write path §2.4 with the fence rule of E7.
- **Functions** (new, `DblqhMain.cpp`, a "PMEM REDO" section after
  `writeNextLog` at `44003`; declarations near `Dblqh.hpp:3991`). All run
  with `lock_log_part(part)` held.

```
redoCopyOut(part, filledOnly)          // copy + drain + advance; the only PMEM store path
  file = current file (via part->my_block, F2)
  (page, word) = position of m_pmem_persisted_lsn in file   // word % 16 == 0
  for p in filled list, then (unless filledOnly) the current page:
     end = p[ZCURR_PAGE_INDEX]          // 8192 for full pages, unit end for NEXT_MBYTE (F6)
     if word == 0: skip p if it holds only its header; else
        redoPmemHeaderImage(img, p, fileNo, page); ndb_pmem_copy_nt(addr(page,0), img, 128); word = 32
     ndb_pmem_copy_nt(addr(page, word), &p[word], (end - word) * 4)
     m_pmem_unfenced += bytes; page++; word = 0
  [S7 hook: torn-copy error insert, owned by the test subtask]
  ndb_pmem_drain(); m_pmem_unfenced = 0
  release the copied filled pages; firstFilledPage = lastFilledPage = RNIL; noLogpagesInBuffer = 0
  m_pmem_persisted_lsn = filledOnly ? lsn(current page, 0) : appendLsn(part)
  counters, latency bucket (NdbTick around copy + drain)
  VM_TRACE: walk the records just copied, in DRAM, with PmemRedo::recordOk

redoPadToUnit(signal, part)
  g = PmemRedo::padWords(curPage[ZCURR_PAGE_INDEX]); if g == 0 return
  if file.remainingWordsInMbyte == g: changeMbyte(...)   // NEXT_MBYTE closes the unit, persists itself
  else writeFillerPmem(..., g)

redoPersist(signal, part)
  if !redoHasUnpersisted(part) return
  redoPadToUnit(signal, part)
  if redoHasUnpersisted(part) redoCopyOut(part, false)

redoPersistOp(signal, op)              // takes the lock itself
  part = op->m_log_part_ptr_p; lock_log_part(part)
  if op->m_redo_end_lsn > part->m_pmem_persisted_lsn: redoPersist(signal, part)
  unlock_log_part(part)

redoEndOfRecord(part, file)            // called by every writer except FILLER and NEXT_MBYTE
  if file->firstFilledPage != RNIL: redoCopyOut(part, true)
```

- **`remainingWordsInMbyte == g` is exact** [V/I]: after any record at
  least `ZNEXT_LOG_SIZE` words remain, and the mbyte end is a W boundary,
  so `remaining ≥ g`, with equality only when the boundary is the mbyte
  end. In VM_TRACE assert that `remaining` equals the words to the mbyte
  end computed from the position.
- **`completedLogPage`** `41035`: after `noLogpagesInBuffer++` (`41057`)
  add `if (c_redo_pmem) { ndbassert(noLogpagesInBuffer < ZMAX_PAGES_WRITTEN); return; }`.
  No LFO, no FSWRITEREQ. The `lfoPtr` output is unused by the PMEM callers
  (`43732`, `43764`, `43845`, `43866`) [V].
- **Why the persisted LSN may stop mid-record** (`filledOnly`): it is a
  byte-prefix property. A crash then leaves the first part of the record
  with the next page's header invalid; recovery rejects the record (format
  §3.4 rule 5).
- **File mode.** `completedLogPage` gets one `if`; the rest is new.
- **Tests.** MTR on PMEM: every test runs with the VM_TRACE self-check.
  `DUMP 2368 3` re-reads the PMEM range of the current mbyte up to the
  persisted LSN through the mapping and checks headers and records with
  `PmemRedo::pageHeaderOk`/`recordOk`; the test fails on any message
  "PMEM REDO verify failed". Power-loss emulation (S1 mode) in S7.
- **Depends on.** S1 (`ndb_pmem_copy_nt`, `ndb_pmem_drain`), S3
  (`m_pmem_base`), S4.1-S4.6.
- **Size.** L, 5 days.
- **Risks and review points.** (1) No other function stores to the
  mapping, except recovery's slot, invalidation and zeroing, each fenced
  inside its own function. (2) Pages are released only in `redoCopyOut`,
  after the fence. (3) `redoCopyOut` → `changeMbyte` recursion cannot
  happen: only `redoPadToUnit` calls `changeMbyte`, and `writeNextLog`
  calls `redoCopyOut`, never `redoPersist`.

### S5.3 Mbyte switch and synchronous file switch

- **Goal.** W2 and W3 of the recovery note: NEXT_MBYTE fenced before any
  byte of the next mbyte; old file end, new FD, last-file slot, each with a
  barrier.
- **Changes in `writeNextLog` `43801-44003`:**

| Line | PMEM change |
|---|---|
| `43824-43826` | `writeNextMbytePmem(...)` instead of the 1-word store |
| after `43846` (last mbyte of file) | `redoCopyOut(part, false)`, before `logLap++` (`43853`) and before `logFilePtr` moves (`43855-43857`) |
| after `43867` (other mbytes) | `redoCopyOut(part, false)` |
| after `43883` (new position set) | `m_pmem_persisted_lsn = redoLsn(part, fileNo, currentFilepage, 0)`: the dead space after NEXT_MBYTE is never stored |
| `43898-43926` (new file) | `ndbrequire(logFilePtr.p->m_pmem_base != nullptr)`; `writeFileHeaderOpen(ZNORMAL)` (PMEM: FD + FILLER, `redoCopyPageZero`); then `redoWriteLastFileSlot(part, fileNo, logLap)` (recovery); `fileChangeState = NOT_ONGOING`; no `openNextLogfile`, no `fileRef == RNIL` branch |
| `43983-43997` (error insert 5058) | `if (!c_redo_pmem && ERROR_INSERTED(5058) ...)`: suspending NDBFS files means nothing on PMEM |

- **New `void redoCopyPageZero(LogPartRecord*, LogFileRecord*, LogPageRecord*)`:**
  header image + words 32 up to the end of the unit that holds the FD
  FILLER's header (`roundup16(fdEnd + 2)`), `ndb_pmem_drain`;
  `m_pmem_persisted_lsn = lsn(file, 1, 0)`. Stores nothing at or after
  word 8128, so the control area of file 0 is never touched (E10).
- **`writeFileHeaderOpenPmem(ZNORMAL)`** then releases page 0 unless it is
  file 0's `logPageZero` (as `35137-35140`), seizes page 1, `initLogpage`,
  `currentFilepage = 1`, `filePosition = 1` (as `36149-36159`).
- **Unchanged.** Tail and head check (`43927-43951`), free space,
  `force_lcp`, P_TAIL_PROBLEM (`43968-43981`), `writeFileDescriptor` after
  `writeNextLog` in `changeMbyte` (`40866-40867`).
- **File mode.** Every change under `if (c_redo_pmem)`.
- **Tests.** MTR on PMEM with `FragmentLogFileSize=4M`,
  `NoOfFragmentLogFiles=3`: write about 40 MB per part, which wraps the log
  more than 3 times (needs LCPs to cut the tail; use a small table updated
  in a loop and `TimeBetweenLocalCheckpoints=6`), then `DUMP 2368 3`.
  Error insert 5059 (`43999`, crash at mbyte 4) followed by restart once
  S6 exists.
- **Depends on.** S5.2, S4.5, S4.6; recovery's slot writer (stub until S6:
  a no-op that logs once).
- **Size.** M, 3 days.
- **Risks.** The order in the file-switch branch: copy the old file before
  `logLap++`, or the LSN of the old file's end is computed with the new lap.

### S5.4 GCP_SAVEREQ

- **Goal.** COMPLETED_GCI + `redoPersist` per part, GCP_SAVECONF in the
  same signal (E15).
- **Changes.**
  - `start_synch_gcp` `33957-33997`: after `writeCompletedGciLog` (`33988`)
    `if (c_redo_pmem) redoPersist(signal, logPartPtr.p);` (lock held,
    `33968`). After the loop: `if (tlogActive) return;` (as `33992-33995`),
    then `if (c_redo_pmem) { sendGcpSaveConf(signal); return; }`, else
    `initGcpRecLab`.
  - New `void sendGcpSaveConf(Signal*)`: the code of `execFSSYNCCONF`
    `34292-34300` (GCP_SAVECONF on JBA, `ccurrentGcprec = RNIL`), which then
    calls it too.
  - `initGcpRecLab` `34074` (reached through `ZINIT_GCP_REC`, `42662`, when a
    part was ACTIVE): `if (c_redo_pmem) { for each part: lock; redoPersist;
    unlock; sendGcpSaveConf(signal); return; }`. Unreachable in PMEM mode
    without error inserts (S5.5), kept correct.
  - Not used in PMEM mode: `startTimeSupervision`, `timeSup`,
    `checkGcpCompleted`, FSSYNCREQ, `execFSSYNCCONF` for GCP.
- **Unchanged.** `execGCP_SAVEREQ` restart branches and the local sysfile
  (`33925-33952`), `sendRESTORABLE_GCI_REP` (`33900`), the callers at
  `37592` and `37607`.
- **File mode.** `execFSSYNCCONF` calls the extracted function; same bytes
  on the wire.
- **Tests.** MTR on PMEM with `TimeBetweenGlobalCheckpoints=100`: GCPs
  must keep advancing during DML, and `DUMP 2368 2` must show one barrier
  per part per GCP at least (the observable is Q9). File mode: the full
  `ndb` MTR suite, since `execFSSYNCCONF` changed.
- **Size.** S, 1.5 days.

### S5.5 Bypassed and unreachable paths

| Path | Today | PMEM mode | Change |
|---|---|---|---|
| `timeSup` `34944` | partial-page write at GCP save | never started | `ndbrequire(!c_redo_pmem)` |
| `checkGcpCompleted` `34141` | on FSWRITECONF | no FSWRITECONF | `ndbassert(!c_redo_pmem)` |
| `writeLogfileLab` `35069`, `firstPageWriteLab` `35130`, `lastWriteInFileLab` `35206`, `writePageZeroLab` `35313` | FSWRITECONF and page-0 rewrite of file 0 | no LFO writes | `ndbassert(!c_redo_pmem)` |
| `openNextLogfile` `35798`; `initFsopenconf` wait states `34834-34853` | run-time open | all files mapped at start | `ndbassert(!c_redo_pmem)` |
| IO tracker tick `timer_handling` `5755-5769` | sets P_REDO_IO_PROBLEM | no IO | `if (!c_redo_pmem)` around the tick |
| `writePrepareLog` `13383-13431` | buffer full → queue or 1221 | staging never short (D3) | `ndbassert(!c_redo_pmem || !out_of_log_buffer)`; P_TAIL_PROBLEM still aborts with 410 (`13406-13416`), as Q7 says |
| `writePrepareLog` `13433-13453` | part ACTIVE → queue | ACTIVE only through queues | unchanged |
| `execLQH_WRITELOG_REQ` `15311-15342`, `abortCommonLab` `17107-17121` | commit/abort queued | complete queue empty, pages free | unchanged |
| `queued_log_write` `1010`, `handle_queued_log_write` `856`, `send_handle_queued_log_write` `770`, `logNextStart` `42576` | queue runner | only with error inserts 5083/5032 | unchanged; they call the dispatched writers, so they work in PMEM mode |
| `send_handle_queued_log_write` booked sizes `781`, `792`, `802`, `812-815` | file-mode sizes | approximate in PMEM mode | unchanged (page-level booking, `978-980`, absorbs a few words) |

- **Staging budget.** Pages in use at once per part in PMEM mode: the
  current page, up to 3 filled pages of one PREPARE (format §6.3), file 0's
  `logPageZero` (`40599`), page 0 of a new file during a switch: at most 6
  [I]. With `ZMIN_LOG_PAGES_OPERATION` = 10 the part needs at least 16
  pages. **Requirement to the platform:** RedoBuffer in PMEM mode at least
  1 MB (32 pages) per part, or what SR needs if more (recovery). DBLQH
  checks `logPageCount >= 32` per part at start in PMEM mode
  (`DblqhInit.cpp:388`, where `noOfFreeLogPages = logPageCount`).
- **Tests.** Error inserts 5083 and 5032 in PMEM mode (queue path, and
  1221 abort), with `DUMP 2368 3` after. Autotest `testBasic -n
  PkUpdate` with `RedoBuffer=1M`.
- **Size.** S, 1.5 days.

### S5.6 Shared log parts

- **Rule.** Every function that stores to a mapping ends with
  `ndb_pmem_drain()` before it returns (`redoCopyOut`, `redoCopyPageZero`,
  recovery's slot, invalidation and zeroing). So every copy is fenced by the
  thread that made it, before `unlock_log_part`.
- **Check.** In VM_TRACE builds `unlock_log_part` (`Dblqh.hpp:6643`, `6723`)
  asserts `logPartPtrP->m_pmem_unfenced == 0`. In release builds the inline
  functions are unchanged.
- **Access.** All new helpers use `part->my_block` for `LogFileRecord` and
  `clogFileSize` (F2). `c_redo_pmem` and `c_redo_pmem_persist_commit` are
  read from `this` (same value in every LDM: config, and DUMP goes to all
  instances).
- **Tests.** MTR and autotest on PMEM with 3 LDMs and 4 log parts
  (`ThreadConfig=ldm={count=3},...`, `NoOfFragmentLogParts=4`), so
  `set_use_mutex_for_log_parts` (`13305-13349`) turns the mutex on; run
  with the benchmark switch on and off, then `DUMP 2368 3`.
- **Size.** S, 1 day.

### S5.7 Debug assertion for dependent sends

- **Goal.** Catch a dependent send whose record is not persistent (E7,
  plan §9 risk 1). Step 1 provides the helper and its call sites; X4 makes
  it fire for durable operations.
- **New** `void redoCheckPersisted(const TcConnectionrec *op, Uint32 line)`,
  empty unless VM_TRACE or ERROR_INSERT: if `c_redo_pmem` and
  `op->m_redo_end_lsn != 0` and the operation needs persistence (step 1:
  `c_redo_pmem_persist_commit != 0`; X4: durable), lock the part and
  `ndbrequire(op->m_redo_end_lsn <= m_pmem_persisted_lsn)`.
- **Call sites** [V]: `sendCommitLqh` `6901`, `sendCompleteLqh` `6955`,
  `sendCommittedTc` `7004`, `sendCompletedTc` `7049`, COMMITCONF at `14908`
  and `15643`, COMPLETECONF at `15083` and `15709`, `commitReplyLab`
  `15617`, start of `localCommitLab` `15358`.
- **File mode.** The helper returns at once.
- **Tests.** With the benchmark switch on, all MTR tests pass the checks.
  A negative test: a debug-only DUMP sub-command (`DUMP 2368 4`) that skips
  the next barrier; the next COMMITTED must hit the `ndbrequire`
  (autotest, crash expected).
- **Size.** S, 1 day.

### S5.8 Benchmark switch, counters and DUMP 2368

- **Goal.** Measure the cost of persisting every COMMIT before X4.
- **Switch.** `c_redo_pmem_persist_commit`. When set, a barrier runs at the
  three C places of E8, which are exactly where X4 puts them:

| Path | Place | Call |
|---|---|---|
| `commitReqLab` | before the branch at `15267` | `redoPersistOp(signal, regTcPtr)` (one barrier after TUP's loop over the operations on one row, `15219`) |
| `handle_queued_log_write` | after `writeCommitLog` `912`, before `unlock_log_part` `914` | `redoPersist(signal, part)` |
| `doWritePrepareLog` (dirty write) | after `removeLogTcrec` `13578`, before `unlock_log_part` `13579` | `redoPersist(signal, part)` |

  X4 replaces the condition with "durable operation" and keeps the calls.
- **DUMP 2368** (`DumpStateOrd::LqhRedoPmem = 2368`, in
  `DumpStateOrd.hpp` after `LqhGroupTableSizeHints` at `205`; handled in
  `execDUMP_STATE_ORD` `44200`): `2368 0|1` switch off/on; `2368 2` print
  counters and the latency histogram per part to the cluster log;
  `2368 3` verify the persisted range (S5.2); `2368 4` (debug builds only)
  skip the next barrier (S5.7).
- **Counters** of §3.2 feed the ndbinfo table of S2 (platform).
- **Tests and benchmark.** `ndb_mgm -e "ALL DUMP 2368 1"`, run the
  workload, `ndb_mgm -e "ALL DUMP 2368 2"`; repeat with `2368 0`. Workload:
  `flexAsynch` update phase or sysbench `oltp_update_index` through
  mysqld, on real or emulated PMEM. Emulated PMEM gives the code-path cost,
  not the device cost.
- **Size.** S, 1.5 days.

### S5.9 Test wiring

- **Goal.** The PMEM cases above in the test subtask's suite (S7 and the
  `memmap=` set-up are theirs).
- **Cases this plan needs** (MTR suite on PMEM, names to be agreed):
  `pmem_redo_basic` (initial start, DML, `DUMP 2368 3`); `pmem_redo_wrap`
  (S5.3); `pmem_redo_gcp` (S5.4); `pmem_redo_shared_parts` (S5.6);
  `pmem_redo_queue` (S5.5, error inserts 5083/5032); `pmem_redo_bench_switch`
  (S5.8 on, all checks pass). Autotest: `testBasic`, `testIndex`,
  `testTransactions` with `RedoLogMode=pmem` in the atrt config.
- **File-mode regression** (every PR): `./mtr --suite=ndb --parallel=auto`,
  `./mtr --suite=rondis`, autotest `testSystemRestart -n SR1 T1` and
  `testNodeRestart -n NoLoad T1`, and `ndb_redo_log_reader` on a file-mode
  log.
- **Size.** M, 3 days (shared with the test subtask).

---

## 6. What is called in step 1 and what waits for X4

| Code | Step 1 | X4 |
|---|---|---|
| PREPARE, COMMIT (12 words), ABORT, COMPLETED_GCI, FILLER, NEXT_MBYTE, FD writers | Called | Same |
| `writeCompleteLog` | Defined, unit tested, no caller | Called from `execCOMPLETE`/`execCOMPLETEREQ` before the branches at `15004`/`15120` |
| `writeAbortLogPmem(AF_AFTER_COMMIT)` | Supported, no caller with the flag | Rule-F abort path |
| `CF_DURABLE`, `opCount` | Always 0 | Set for GCI ≥ g |
| Reservation | 46 reserved, all released at COMMIT | 26 at COMMIT, 20 at COMPLETE / rule-F ABORT |
| `redoPersistOp` at C | Only with the benchmark switch | Durable operations |
| K barriers | None | After `writeCompleteLog` |
| `redoCheckPersisted` | Fires only with the switch | Fires for durable operations |

---

## 7. Interfaces with the other subtasks

### 7.1 From the platform subtask (`impl_step1_platform.md`)

| Item | What this plan needs |
|---|---|
| `ndb_crc32c(Uint32 crc, const void*, size_t)` | zlib-style chaining: start with 0, pass the previous result, the function applies the initial and final inversion (Q1). Pure and thread-safe (used from the NDBFS thread in `execFSWRITEREQ`) |
| `ndb_pmem_copy_nt(void *dst, const void *src, size_t len)` | Non-temporal copy, no fence inside. `dst` 64-byte aligned, `len` a multiple of 64; `src` 64-byte aligned (DRAM pages and an `alignas(64)` stack image) |
| `ndb_pmem_drain()` | `sfence` (x86) / `DSB` (ARM). Drains this thread's copies |
| Power-loss emulation (S1) | Must see every PMEM store, so DBLQH stores to the mapping only through `ndb_pmem_copy_nt` |
| `c_redo_pmem` | Set in `Dblqh::execREAD_CONFIG` (near `2766-2801`) before any log initialisation; same in every LDM |
| `LogFileRecord::m_pmem_base` | Set from FSOPENCONF for every file before the first run-time write, that is before `readSrFourthPhaseLab` (`40474`) sets the head |
| RedoBuffer in PMEM mode | At least 32 pages per part (S5.5) |
| `InitFragmentLogFiles=full` forced in PMEM mode | So `m_use_om_init = 1` (`2766-2778`) and `execFSWRITEREQ` formats every mbyte header (S4.8) |
| ndbinfo (S2) | Reads the §3.2 counters under the part lock |

**Provided:** `PmemRedoFormat.hpp` with `PmemRedo::buildPageHeader` for
the NDBFS-thread callback.

### 7.2 From the recovery-and-tests subtask (`impl_step1_recovery_test.md`)

| Item | Contract |
|---|---|
| `void redoWriteLastFileSlot(LogPartRecord*, Uint32 fileNo, Uint32 lap)` | Recovery owns the slot layout and writes it with store + flush + `ndb_pmem_drain` inside. This plan calls it in `writeNextLog` after the new file's FD is persistent and before the first record of the file. Until S6 lands, a stub |
| Control area | Last 256 bytes of page 0 of file 0, `PmemRedo::CONTROL_AREA_WORD = 8128`. This plan never stores there (S5.3) |
| Resume | Recovery sets `currentLogfile`, `currentLogpage` (DRAM copy of the head page), `currentFilepage`, `ZCURR_PAGE_INDEX`, `remainingWordsInMbyte`, `logLap`, writes the FILLER from E (or H) to the next W boundary (recovery W7) with `writeFillerPmem` + `redoCopyOut`, and then calls `redoInitWritePosition(part)`. The head index it hands over is W-aligned. No head-page header re-init (`40525`) |
| Initial start head | `initFourth` `40451` = `ZPAGE_HEADER_SIZE + 16` in PMEM mode (S4.8 writes COMPLETED_GCI(1) + FILLER there) |
| File switch redo | If E is at a file start, recovery may position at the old file's end and call `changeMbyte`; in PMEM mode it persists and switches synchronously |
| SR_HEAD | Recovery fills the content; framing through `redoAppendFixed` with `ZSR_HEAD_TYPE`, 6 words |
| Validators | S6 extends `PmemRedo::pageHeaderOk`/`recordOk` (spanning records, structure rules) in the same header, so writer and reader share one definition |
| Torn-copy hook (S7) | A marked place in `redoCopyOut` between the copies and the drain; the test subtask adds its error insert there |
| Numbers | This plan takes DUMP 2368. Error inserts for crash tests start at 5155 (test subtask) |

**Provided:** all writers, `redoCopyOut`, `redoPersist`, `redoPersistOp`,
`redoInitWritePosition`, `writeFillerPmem`, `redoAppendFixed`, the LSN
helpers and the constants.

---

## 8. Order and pull requests

```
S4.1 ─ S4.2 ─┬─ S4.3 ─┐
             ├─ S4.4 ─┤ (S4.7 before S4.4)
             ├─ S4.5 ─┼─ S5.1 ─ S5.2 ─ S5.3 ─ S5.4 ─ S5.5 ─ S5.6 ─ S5.7 ─ S5.8
             └─ S4.6 ─┘                 │
S3 (platform) ─────────── S4.8 ─────────┘
```

| PR | Packages | Testable by | Needs |
|---|---|---|---|
| PR1 "PMEM REDO format" | S4.1 | unit test | S1 CRC |
| PR2 "PMEM REDO writers" | S4.2-S4.7, S5.1 | unit test; file-mode regression (writers dispatch, `c_redo_pmem` false) | PR1 |
| PR3 "PMEM REDO write path" | S4.8, S5.2-S5.5 | initial start and DML on `memmap=` PMEM, `DUMP 2368 3` | PR2, S1-S3 |
| PR4 "PMEM REDO checks and benchmark switch" | S5.6-S5.9 | shared-part and benchmark tests | PR3 |

Commits inside a PR follow the package IDs. Every PR runs the file-mode
regression of S5.9. Restart tests (SR, NR, `kill -9`) need S6 and come with
the recovery PRs.

Total about 33 person-days: S4 ≈ 14.5 (3 + 1.5 + 2 + 2 + 1 + 2 + 1 + 2),
S5 ≈ 18.5 (1 + 5 + 3 + 1.5 + 1.5 + 1 + 1 + 1.5 + 3).

---

## 9. New symbols

| Symbol | Kind | Where | Package |
|---|---|---|---|
| `PmemRedoFormat.hpp`, namespace `PmemRedo` (constants, `w0`, `Suffix`, `RecCrc`, `buildPageHeader`, `pageHeaderOk`, `recordOk`, `padWords`, `prepareLen`, `fdLen`, `lsn`) | header | `src/kernel/blocks/dblqh/` | S4.1 |
| `pmem_redo_format-t` | unit test | same | S4.1 |
| `ZFILLER_TYPE` 10, `ZCOMPLETE_TYPE` 11, `ZSR_HEAD_TYPE` 12 | macro | `Dblqh.hpp:~263` | S4.1 |
| `RF_INVALIDATED`, `CF_DURABLE`, `AF_AFTER_COMMIT`, `PF_TRANSID` | macro | `Dblqh.hpp` | S4.1 |
| `LogPartRecord::m_pmem_persisted_lsn` | `Uint64` | `Dblqh.hpp` | S5.1 |
| `LogPartRecord::m_pmem_persist_count`, `m_pmem_bytes_copied`, `m_pmem_filler_words`, `m_pmem_persist_hist[16]`, `m_pmem_unfenced` | counters | `Dblqh.hpp` | S5.1 |
| `LogFileRecord::m_pmem_base` | `Uint8 *` | `Dblqh.hpp` (set by platform) | S5.1 |
| `TcConnectionrec::m_redo_end_lsn` | `Uint64` | `Dblqh.hpp` | S5.1 |
| `Dblqh::c_redo_pmem_persist_commit` | `Uint32` | `Dblqh.hpp` | S5.8 |
| `redoRecBegin`, `redoAppendFixed` | method | `DblqhMain.cpp` | S4.2 |
| `writePrepareLogPmem`, `writeCommitLogPmem`, `writeAbortLogPmem`, `writeCompletedGciLogPmem`, `writeCompleteLog` | method | `DblqhMain.cpp` | S4.3, S4.4 |
| `writeFillerPmem`, `writeNextMbytePmem` | method | `DblqhMain.cpp` | S4.5 |
| `redoPmemHeaderImage`, `writeFileHeaderOpenPmem` | method | `DblqhMain.cpp` | S4.6 |
| `release_committed_words`, enum `RedoRelease { AT_COMMIT, AT_COMPLETE, AT_ABORT }` | method | `DblqhMain.cpp` | S4.7 |
| `redoLsn`, `redoAppendLsn`, `redoPmemAddr`, `redoHasUnpersisted`, `redoInitWritePosition` | method | `Dblqh.hpp` / `DblqhMain.cpp` | S5.1 |
| `redoCopyOut`, `redoPadToUnit`, `redoPersist`, `redoPersistOp`, `redoEndOfRecord` | method | `DblqhMain.cpp` | S5.2 |
| `redoCopyPageZero` | method | `DblqhMain.cpp` | S5.3 |
| `sendGcpSaveConf` | method | `DblqhMain.cpp` | S5.4 |
| `redoCheckPersisted` | method | `DblqhMain.cpp` | S5.7 |
| `DumpStateOrd::LqhRedoPmem` = 2368 | enum | `include/kernel/signaldata/DumpStateOrd.hpp` | S5.8 |
| `redoWriteLastFileSlot` | method (recovery) | `DblqhMain.cpp` | consumed |

---

## 10. Design issues found

| # | Issue | Evidence | Proposal |
|---|---|---|---|
| D1 | E5 says the header CRC covers words 1-31. At initial start, page 0 of every file and page 1 of file 0 are written by `writeSinglePage` through an LFO, which needs `ZNEXT_PAGE = RNIL` in the page during the I/O and stamps words 0 and 12-20 (F8). That page cannot carry the clean image | `36212-36217`, `35915-35926` [V] | Define the header CRC over words 1-31 with the DRAM-only words (4, 5, 8, 9, 11, 12-14, 17-20, 27-31) read as 0; the reader masks the same words. Run-time copies still store zeros there. No space cost. Alternative: write those pages through the mapping after S3 maps the files. **Decided** (Q-A4, `implementation_plan.md` R2, §5.1): the alternative, since S3.5 already maps the files at open and writes these pages with `redoPmemInitFile()`; no mask |
| D2 | E5 says the header is "written at page init with a CRC". `initLogpage` cannot know the page number (F5) | `43735-43737`, `43882`, `43896`, `36157-36159` [V] | Build the image, identity and CRC at the first copy, from the copy position. Same bytes on PMEM; `initLogpage` unchanged |
| D3 | E15 says "about 8 staging pages per part". With fewer than 10 free pages `count_free_log_pages` reports "buffer full", and every prepare would queue or fail with 1221 (F9) | `991`, `13383-13431` [V] | At least 16 pages for writing; ask for 32 (1 MB) per part, or SR's need if larger |
| D4 | The FD is followed by "a FILLER to the page end" (E13), and the control area is in the last 256 bytes of page 0 of file 0 (E10), inside that FILLER's body. The write-path note zeroes filler bodies before the copy, which would overwrite the control area | design E10, E13; write path §4.1 | The FD FILLER body is never stored: the page-0 copy stops at the unit holding the FILLER header (S5.3). Other FILLERs (≤ 14 words) lie inside one unit and are zeroed in DRAM. Say this in the format note |
| D5 | The design reserves 46 words per prepare. In step 1 no COMPLETE is written, so the second half must also be released at COMMIT, or `m_committed_words` grows without bound | `47888-47909` [V] | S4.7: release everything at COMMIT for non-durable operations |
| D6 | The design's "benchmark switch (an error insert …)": ERROR_INSERT is not compiled in release builds, where benchmarks run (F14) | `pc.hpp:249-281` [V] | Use DUMP 2368 |
| D7 | `research_redo_log.md` §1.2: "the last mbyte of a file has one page less". The code reduces the first mbyte of the next file (F7) | `43827-43833` [V] | Correct the note; no code impact |
| D8 | The initial-start head index (`ZPAGE_HEADER_SIZE + 2`) and the 2-word COMPLETED_GCI(1) image are not covered by the design's step list (F11) | `35409-35414`, `40451` [V] | S4.8 here, `initFourth` agreed with recovery |

---

## 11. Open questions

1. **`ndb_crc32c` convention** (platform): zlib-style chaining assumed. The
   unit test of S4.1 fails if it is not.
2. **Header CRC mask (D1)**: accept, or require initial-start writes through
   the mapping? **Answered (Q-A4, `implementation_plan.md` §5.1):** through
   the mapping, no mask.
3. **Who owns the initial-start images** (S4.8 here, NDBFS part in S3):
   confirm the split with the platform plan.
4. **Benchmark switch granularity**: one barrier per COMMIT signal at the
   X4 places (TUP's loop on one row shares it), as planned; or one per
   COMMIT record inside `writeCommitLogPmem`? The first measures what X4
   will cost; the second is an upper bound.
5. **DUMP 2368** and error inserts from 5155 for the test subtask: confirm.
6. **Staging size**: 1 MB per part, or more if SR reads into the same
   buffer (recovery decides).
7. **Persist-latency histogram**: `NdbTick_getCurrentTicks` costs a clock
   read per barrier (tens of ns [I]). Always on, or only with the
   benchmark switch?
8. **CRC outside the lock** (format W8): the body CRC of PREPARE could be
   computed before `lock_log_part`, adding only S under the lock. Not in
   step 1; worth it if the shared-part mutex shows up in profiles.
9. **GCP progress check in MTR** for S5.4: which observable does the test
   subtask prefer (cluster log GCP lines, ndbinfo, or a DUMP)?
