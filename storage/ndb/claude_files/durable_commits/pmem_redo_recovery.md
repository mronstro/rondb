# RONDB-1150 — PMEM REDO: finding the head and the tail at restart

Status: design for step 1 (PMEM support for the REDO log), 2026-10-28.
No code has been changed.

Scope: how a system restart (SR) and a node restart (NR) find the end (head)
and the start (tail) of each REDO log part, and read the log, when the whole
REDO is on persistent memory (fsdax files mapped with `MAP_SYNC`) and records
are persisted in small units of W bytes. Three documents are written in
parallel and are not read here: `research_pmem_hardware.md` (atomicity,
ADR/eADR), `pmem_redo_format.md` (record layout) and `pmem_redo_write_path.md`
(append and persist). What this design needs from them is stated as
requirements in §7 and §8.

Conventions:

- [V] = verified in the code (tree at `7128c75dca4` plus the plan commit).
  [I] = inferred.
- Paths are relative to `storage/ndb/`. `DblqhMain.cpp` stands for
  `src/kernel/blocks/dblqh/DblqhMain.cpp`, `Dblqh.hpp` for
  `src/kernel/blocks/dblqh/Dblqh.hpp`, `DbdihMain.cpp` for
  `src/kernel/blocks/dbdih/DbdihMain.cpp`.
- R is the GCI the restart restores to (`crestartNewestGci`): R_gcp in an SR,
  the node's own `lastCompletedGCI` in an NR.

Terms used below:

| Term | Meaning |
|---|---|
| position | (lap, fileNo, pageNo, wordIdx) inside one log part |
| LSN | a linear word position: `((lap·N + fileNo)·F·32 + pageNo)·8192 + wordIdx`, N files, F mbytes per file. Monotone across laps |
| mbyte header | the 32-word header of the first page of an mbyte (for mbyte 0 it is page 0 of the file, which also holds the FD record) |
| barrier | the persist operation of the write path: `clwb` of the lines plus `sfence` (ADR) or `sfence` only (eADR) |
| unpersisted range | the bytes of a log part stored since the end of the last barrier |
| E | the end of the valid log: the first position where no valid record starts (§3) |
| H | the head chosen by an SR or NR that moves it back: right after the `COMPLETED_GCI(R)` record |
| orphan | a record of the current lap that is valid by itself but lies after E |

---

## 0. Summary

1. **Today the head is found in three steps, none of them exact by
   itself.** Phase 1 reads only page headers: page 0 of file 0 gives the
   last file, the lap drop in the mbyte headers of that file gives the last
   mbyte. Phase 3 finds the record `COMPLETED_GCI(R)` and puts the new head
   right after it. Phase 4 finds the old head again, at page granularity,
   by a lap search, and zeroes every page between the two. [V]
2. **Recovery reads few header fields.** From page headers it reads only
   the lap (every page), and the GCI fields and `ZLAST_LOG_PREP_REF` of the
   first page of each mbyte. From page 0 of file 0 it reads
   `ZPOS_NO_LOG_PARTS` and the "last file" word. `ZCURR_PAGE_INDEX`, the page
   checksum, `ZPOS_VERSION`, `ZPOS_NO_LOG_FILES` and the debug words are never
   read from disk. [V]
3. **The mbyte-header GCI values are start-of-mbyte values, and that is
   what recovery needs.** `srLogLimits` and `setLogTail` need bounds that
   hold at the start of the mbyte. Writing them once at page init is
   correct on PMEM. No "by the end of the page" value is needed. [V for the
   use, I for the argument, §2.3]
4. **What breaks on PMEM:** the in-place rewrites of page 0 of file 0 (file
   change, lap change, end of restart); the whole-page checksum and the
   header words written at write time (`ZCURR_PAGE_INDEX`, debug words); the
   `ZINVALID_COMMIT_TYPE` rewrite of a record now covered by a checksum; the
   re-initialisation of the head page's header at restart; and the
   invalidation, which never touches the head page, so orphans there survive.
5. **End-of-log rule.** Scanning forward from an mbyte start, E is the
   first position whose page header or record fails a check: header
   checksum, header lap and position, record type and length, record
   checksum seeded with the record's LSN. Phase 1 finds E exactly by
   scanning the last mbyte (≤ 1 MB). Every later scan stops at E. An invalid
   record before E means corruption, and the node stops; it never silently
   shortens the log.
6. **Lap and position checks are not enough.** A hole can be followed by
   valid records of the current lap: lines evicted under ADR, or part of a
   torn non-temporal copy. They must be zeroed before anything is written
   at E. The write path must not let one persist cross an mbyte boundary
   (W2 in §8). Then these records lie in the mbyte that contains E, and
   zeroing `[E, end of that mbyte)` is enough: at most 1 MB, a
   sub-millisecond job on PMEM.
7. **Torn-safe in-place updates.** The "last file" pointer becomes two
   checksummed slots with sequence numbers, in a control area that the lap
   change never rewrites. The COMMIT invalidation is one aligned store of
   the type word, with the checksum computed as if the type were COMMIT.
   Zeroing is idempotent. All other headers are written once per lap.
8. **NR uses the same code** with R = the node's own GCI. The head moves
   back to H, so `[H, end of the mbyte of E)` is zeroed, page 0 of each
   file excepted, as today.
9. **Phase 2 of the durable SR** gets a reliable end: E from phase 1. Both
   of its scans must start no later than the first record with GCI > R_gcp.
   That record can come **before** `COMPLETED_GCI(R_gcp)`, so the scans
   cannot start at that record.

---

## 1. Today's head and tail search

### 1.1 The layout that recovery depends on [V]

- A log part is a ring of N files. A file has F mbytes of 32 pages. A page
  has 8192 words, with a 32-word header (`Dblqh.hpp:177-212`).
- Page 0 of every file holds the header and the FD record at word 32:
  `[ZFD_TYPE, nFD, fileNo, per-mbyte arrays…]`, then `ZNEXT_LOG_RECORD_TYPE`.
  Page 0 holds no log records (`writeFileHeaderOpen`,
  `DblqhMain.cpp:36073-36161`).
- The FD arrays are `logMaxGciCompleted[]`, `logMaxGciStarted[]` and
  `logLastPrepRef[]` for this file and up to `cmaxLogFilesInPageZero − 1`
  earlier files. The entries for this file are stale, so only fd ≥ 1 is
  read (`42279-42320`). The capacity is
  `min(40, (8192−32−128)/(3F))` (`2833-2847`, `2865`). With 1 GB files it
  is 2, so each FD page describes only the one previous file.
- In file 0, the FD's fileNo word (word 34) doubles as "last file in use".
  It is rewritten at every file change (`35197`, `35303`) and at the end of
  every restart (`40146`).
- The first page of each mbyte is initialised by `initLogpage`
  (`35577-35605`, called from `writeNextLog`, `43896`). It holds the lap,
  `logPartNewestCompletedGCI`, `cnewestGci` and the oldest live prepare,
  all taken at mbyte start. `writeFileDescriptor` copies the same values
  into the in-memory arrays (`36019-36066`). It writes nothing to disk.
- No record spans an mbyte boundary. Records may span pages.
- The lap is incremented when the writer enters file 0 (`43847-43854`).
  Initial start formats every mbyte header with lap 0 (`35766-35781`), sets
  lap 1 in page 0 of file 0 (`35384-35387`), writes `COMPLETED_GCI(1)` in
  page 1 of file 0 (`35397-35420`) and sets the head there (`40449-40451`).

### 1.2 Phase 1: last file and last mbyte (headers only)

Runs in NDB start phase 3 for both SR and NR, concurrently with the LCP
restore (`startphase3Lab`, `2454-2495`).

| Step | What happens | Where |
|---|---|---|
| 1 | Open file 0 of each log part | `2485-2493` |
| 2 | Read page 0 of file 0 | `openSrFrontpageLab`, `36275-36281` |
| 3 | Check `ZPOS_NO_LOG_PARTS` against the config. Read `fileNo = word[32+ZPOS_FILE_NO]`. Close file 0 | `readSrFrontpageLab`, `36289-36322` |
| 4 | Open the last file, read its page 0 | `closingSrFrontPage` `36530-36557`, `openSrLastFileLab` `36324-36330` |
| 5 | `logLap = page0[ZPOS_LOG_LAP]` of the last file. Fill the arrays of earlier files from its FD | `readSrLastFileLab`, `36332-36365` |
| 6 | Read page 0 of every mbyte of the last file. The first mbyte with lap < `logLap` gives `lastMbyte = mb − 1`; with no drop, `lastMbyte = F − 1`. Each header fills that mbyte's arrays | `readSrLastMbyteLab`, `36367-36412` |
| 7 | Step back `cmaxValid` files at a time, reading FD pages, until every file's arrays are filled | `36427-36455`, `readSrNextFileLab` `36471-36528` |
| 8 | When all files are closed: `ZSR_PHASE3_START(ZSR_PHASE1_COMPLETED)` | `closingSrLab`, `36559-36628` |

The result is only (lastLogfile, lastMbyte); no record is read. The comment
at `36283-36288` asks to check whether the next file is the last one; no
such check exists, and none is needed. Page 0 of file 0 is updated only
after the new FD page and the old file's last write are on disk
(`35130-35311`), and GCP completion waits for that too (`35076-35082`).

### 1.3 Phase 3: limits, the scan, the exact head

| Step | What happens | Where |
|---|---|---|
| 1 | Round 0: `logLastGci = crestartNewestGci` (R). Later rounds start at 2 | `srPhase3Start`, `38500-38510` |
| 2 | `logStartGci = min execSrStartGci` over the part's fragments. Only later rounds may go beyond R | `srGciLimits`, `38554-38568` |
| 3 | A part with no fragment to run gets start = last = R | `continue_srGciLimits`, `38625-38637` |
| 4 | Walk back from (lastLogfile, lastMbyte). **Stop mbyte**: the first with `logMaxGciCompleted[mb] ≤ logLastGci`. **Start mbyte**: then the first with `logMaxGciStarted[mb] < logStartGci`, moved back to its `logLastPrepRef[mb]`. A full wrap is an error | `srLogLimits`, `38688-38791`, `38775-38777` |
| 5 | Open the start file. Read 8 pages from the start of the start mbyte | `38812-38823`, `openExecSrStartLab` `38855-38882`, `readExecSrNewMbyte` `42877-42886`, `readExecSr` `42893-42958` |
| 6 | The first page's `ZCURR_PAGE_INDEX` is **reset** to 32. The on-disk value is not used | `readExecSrLab`, `38907` |
| 7 | The record loop | `execSr`, `38962-39409` |
| 8 | Done: `execLogComp`, then `EXEC_SRCONF` | `40260-40318`, `40409-40422` |

The record loop handles each type as follows. The page cursor is the
in-memory `ZCURR_PAGE_INDEX` (`readLogword` `43054-43074`, `stepAhead`
`43514-43537`).

| Record | Handling |
|---|---|
| PREPARE | skipped by its length (`39089-39094`) |
| INVALID_COMMIT | skipped (`39099-39103`) |
| COMMIT, gci > R | type word set to `ZINVALID_COMMIT_TYPE` in the buffer, page marked `ZPOS_DIRTY` (`39117-39132`); `writeDirty` writes the whole page back with sync (`38983-39013`, `43669-43716`) |
| COMMIT, gci ≤ R | `checkIfExecLog`, then the prepare by `findPageRef` or a random read, then `execLogRecord` → LQHKEYREQ (`39142-39189`, `39478-39519`) |
| ABORT | skipped (`39200-39205`) |
| FD | must be at word 33 after the type word; skipped (`39210-39238`) |
| NEXT_LOG_RECORD | skip to the next page (`39243-39248`) |
| NEXT_MBYTE | if this is the stop mbyte: crash "end of log wo/ having found last GCI". Otherwise go to the next mbyte or file (`39253-39298`) |
| COMPLETED_GCI(g), g = logLastGci | round 0: record the head (file, page, index after the record, lap of the page). Stop (`39304-39351`) |
| anything else | crash "Invalid logword" (`39353-39365`) |

**The scan has no end-of-data test.** It ends only at
`COMPLETED_GCI(R)`. It never checks a page checksum: the check is
commented out (`40836-40845`) and the checksum is the constant 37 in
release builds (`46632-46639`). [V]

### 1.4 Phase 4: tail, new head, invalidation

| Step | What happens | Where |
|---|---|---|
| 1 | After the last round: `logLastGci = R`, `logStartGci = keepGci`, `srLogLimits` again | `continue_execSrCompletedLab`, `38348-38375` |
| 2 | Tail = start mbyte. Open the head file | `srLogLimits` phase-4 branch, `38840-38851` |
| 3 | Read the head page. `cnewestGci = cnewestCompletedGci = max(R, keepGci)`. `logLap` = lap of the head page. **`initLogpage` re-initialises the head page's header**; `ZCURR_PAGE_INDEX = headPageIndex` | `readSrFourthPhaseLab`, `40499-40531` |
| 4 | Load page 0 of file 0 into `logPageZero`. Start the invalidation at the head | `readSrFourthZeroLab`, `40596-40618` |
| 5 | Search forward, file by file (page 1 of each file), then page by page, for the first page with an old lap. Keep going about 2 mbytes, to an old-lap mbyte start | `readFileInInvalidate` `39882-40098`, `invalidateLogAfterLastGCI` `39638-39704` |
| 6 | Zero pages **backwards**, from the last one found down to `headPageNo + 1`, with a sync at mbyte and file boundaries. **The head page and page 0 of every file are never zeroed** | `39737-39775`, `writeFileInInvalidate` `39782-39858` |
| 7 | Write page 0 of file 0 with `ZPOS_FILE_NO = headFileNo`, with sync | `exitFromInvalidate`, `40141-40153` |
| 8 | `ZSR_FOURTH_COMP`, then index rebuild, then `START_RECCONF` | `34750-34756`, `srFourthComp` `40624-40673` |

The comment at `39577-39636` explains the reason for step 5. Up to 1 MB of
writes can be outstanding (NDBFS auto-sync) and can reach disk in any
order, and an mbyte switch skips pages. Pages after the true end can
therefore carry the current lap. If they are not destroyed, a later restart
can "connect new log pages to old invalid log pages".

### 1.5 Node restart [V]

- Phase 1 is the same code; `startphase3Lab` covers `ST_NODE_RESTART`
  (`2463-2495`).
- DIH runs `nr_run_redo` (`DbdihMain.cpp:8473-8502`). It sets `m_sr_nodes`
  to the starting node alone and sends `START_RECREQ` with
  `lastCompletedGci = SYSFILE->lastCompletedGCI[node]`
  (`sendSTART_RECREQ`, `DbdihMain.cpp:468-514`).
- LQH sets `crestartNewestGci` to that GCI (`DblqhMain.cpp:37643-37648`).
  Phases 3 and 4 then run as in an SR: stop at `COMPLETED_GCI(own GCI)`,
  head after it, invalidate everything after.

### 1.6 Header fields: written, read, used

Header word numbers are from `Dblqh.hpp:188-211`.

| Field | Written | Read in recovery | Used for |
|---|---|---|---|
| `ZPOS_CHECKSUM` (0) | at every page write (`36217`, `43679`, `completedLogPage`) | never; check commented out (`40836-40845`) | nothing (constant 37 in release builds) |
| `ZPOS_LOG_LAP` (1) | `initLogpage` `35583`; initial format `35769`, `35385`, `35410`; zeroed pages get 0 | `36335` last file's lap; `36371` lap drop → lastMbyte; `39335` head's lap; `39555`, `39639`, `39681` invalidation search; `40521` lap after the restart | end of log (mbyte granularity), lap of the head |
| `ZPOS_MAX_GCI_COMPLETED` (2) | `initLogpage` `35584` (value at page init) | `36386`, first page of each mbyte of the last file only. Earlier files: from the FD (`42309`) | stop mbyte (`38691`) |
| `ZPOS_MAX_GCI_STARTED` (3) | `initLogpage` `35586` | `36388`; FD (`42310`) | start mbyte (`38729`); tail cut at run time `setLogTail` (`33526`) |
| `ZNEXT_PAGE`, `ZPREV_PAGE` (4, 5) | in-memory links | overwritten on read (`40818-40855`) | in-memory page chain |
| `ZPOS_VERSION` (6) | `35588` | never | — |
| `ZPOS_NO_LOG_FILES` (7) | `35589` | never | — |
| `ZCURR_PAGE_INDEX` (8) | every append; on disk it is the fill index of a partial page (`timeSup`, `35017`) | **never from disk**: reset at `38907`, `39470`, `40526` | in-memory cursor only |
| `ZLAST_LOG_PREP_REF` (10) | `initLogpage` `35596-35603` | `36390`; FD (`42311`) | start file and mbyte (`38751-38755`); tail (`33602-33605`) |
| `ZPOS_DIRTY` (11) | in memory, `39132` | in memory, `38983` | which page `writeDirty` writes back |
| debug words (12-20) | at write time, `writeDbgInfoPageHeader` `46750-46760` | `ZPOS_PAGE_NO` in an `ndbassert` only (`43675`) | diagnostics |
| `ZPOS_NO_LOG_PARTS` (21) | `initLogpage` `35591` | page 0 of file 0, `36295` | config check |
| FD `ZPOS_FILE_NO` (word 34), file 0 | file open `36083`; file change `35197`, `35303`; end of restart `40146` | `36308` | which file is last |
| FD arrays (word 35…) | file open `36104-36129` | `initGciInLogFileRec` `42279-42320` | per-mbyte arrays of earlier files |
| `NEXT_MBYTE` record | `43825-43826` | `39253-39298` | mbyte end; stop-mbyte error |
| `COMPLETED_GCI` record | `43631-43662`, initial `35411` | `39304-39351` | exact restart head |

### 1.7 Facts that matter for the PMEM design

1. The precise old head (last written word) is never computed. Only the
   last mbyte (phase 1) and the first old-lap page (phase 4) are found.
   [V]
2. The scan trusts every record up to `COMPLETED_GCI(R)`. This is safe today
   only because that record was synced long before the crash. [V]
3. Recovery modifies header words of the pages it reads (`ZCURR_PAGE_INDEX`,
   `ZNEXT_PAGE`, `ZPREV_PAGE`, `ZPOS_DIRTY`), and `writeDirty` writes those
   modified pages back. On a mapping this must not happen. [V]
4. Page 0 of a file is never zeroed. Only the "last file" word moves the
   end of the log back. [V]
5. The head page is never zeroed. Its words after `headPageIndex` keep the
   old content until new records overwrite them. [V]

---

## 2. What breaks on PMEM

### 2.1 Model and assumptions

These were written before the hardware and write-path documents existed.
A late check against both found no conflict; the notes below say where.

- **A1 (hardware).** An aligned 8-byte store is failure-atomic. A 64-byte
  line is **not** assumed atomic. [I; `research_pmem_hardware.md` §1 agrees]
- **A2 (hardware).** Bytes stored after the last completed barrier can
  reach PMEM in any subset and order, torn at 8-byte granularity. With
  ordinary stores under ADR this comes from eviction. With non-temporal
  copies it comes from the copy in flight. After a power failure there can
  be holes followed by valid data. [I; `research_pmem_hardware.md` §1.2
  agrees]
- **A3 (write path).** Records reach the mapping by stores or by copies
  from DRAM. The write-path design chose copies: non-temporal stores, each
  copy ended by `sfence` (`pmem_redo_write_path.md` §2.3-2.4). A barrier is
  issued when a COMMIT or COMPLETE must be persistent, at GCP save, and at
  the mbyte and file switches (§8). It persists the whole unpersisted range
  of the log part. [I, plan §9 risk 1]
- **A4 (format).** The file, mbyte and page geometry stay. Page headers and
  the FD record stay. Each record and each header gets a checksum (§7).

### 2.2 Field by field

"Incremental" means that a page is filled and persisted in W-byte units,
and its header is written once, when the writer enters the page.

| Field | Correct when written once at page start? | Verdict |
|---|---|---|
| Page checksum over 32 KB | No. It would have to be rewritten at every unit | Replace by a header checksum (header words only) plus one checksum per record |
| `ZPOS_LOG_LAP` | Yes, it is constant for a page within a lap | Keep. Cover it by the header checksum |
| `ZPOS_MAX_GCI_COMPLETED`, `ZPOS_MAX_GCI_STARTED` | Yes; the start value is the one recovery needs (§2.3) | Keep in the first page of each mbyte. Unused elsewhere |
| `ZLAST_LOG_PREP_REF` | Yes (start value) | Keep in the first page of each mbyte |
| `ZCURR_PAGE_INDEX` | No. Keeping it current means rewriting the header at every append | Drop from the persistent header. It stays as a DRAM cursor. Recovery never read it (§1.6) |
| `ZPOS_DIRTY`, `ZNEXT_PAGE`, `ZPREV_PAGE` | In-memory only | Not persistent; outside the header checksum |
| Debug words 12-20 | No, they are written at write time | Drop, or set at init only. Keep fileNo and pageNo as real identity fields |
| `ZPOS_VERSION`, `ZPOS_NO_LOG_FILES`, `ZPOS_NO_LOG_PARTS` | Yes | Move the static config into the control area (§2.4) and check it at start |
| FD record (page 0) | Yes, it is written once per lap at file open | Keep; give it a record checksum |
| "Last file" word, page 0 of file 0 | No, it is updated in place | Two slots (§2.4) |

### 2.3 Page GCI: start of page or end of page?

Recovery needs the values **at the start of the mbyte**. The values at
the end of the page are not needed. [I, argued from the code]

- **Stop mbyte** (`38691`): the first mbyte, walking back, with
  `maxGciCompleted(start) ≤ lastGci`. If the start value is < lastGci, the
  record `COMPLETED_GCI(lastGci)` comes at or after the start of this
  mbyte. If it is equal, the record came earlier and the scan meets it
  before the stop mbyte. Either way the stop mbyte is a correct "no later
  than" bound. That needs the start value.
- **Start mbyte** (`38729`): if `maxGciStarted(start) < startGci`, every
  record before this mbyte has a GCI < startGci, because `cnewestGci` is at
  least every GCI logged so far (it is raised at commit, `15298`). That
  needs an upper bound that holds at the start, and the start value is
  one. The prepares are reached through `lastPrepRef(start)`, the oldest
  live prepare at the start.
- **Tail cut** (`setLogTail`, `33526`, `33602-33605`): the same argument as
  for the start mbyte.
- Values in headers of other pages are never read (§1.6).

So the header written once at page init is exactly right. One thing must
change. After a restart, today's code re-initialises the header of the
head page with R as both GCI values (`40525`). On PMEM this is an in-place
rewrite of a header that covers valid records. A torn rewrite would make
the whole page invalid and lose records before the head. **The restart
must keep the existing header.** Its start values remain true for the same
mbyte start. The in-memory arrays already hold those values from phase 1.
A header is written only when it is invalid (W7 in §8).

### 2.4 In-place updates and torn-safe variants

| In-place update today | Where | On PMEM |
|---|---|---|
| "Last file" word in page 0 of file 0, at every file change | `35197`, `35303` | Two-slot record in a control area (below) |
| "Last file" word at the end of each restart | `40146` | Same slots |
| Page 0 of file 0 rewritten in full at every lap change (new lap, new FD) | `43885-43896`, `36145` | Leave the control area alone. Rewrite only the header and the FD record (§7 F7) |
| Page 0 of other files, once per lap | `36145` | Safe by ordering: the slot points to the file only after its FD is persistent (W3) |
| Partial page rewritten at every GCP save (`timeSup`) | `35017-35060` | Gone. A unit is persisted once and never rewritten (W5) |
| `ZINVALID_COMMIT_TYPE` page rewrite (`writeDirty`) | `39117-39132`, `43669-43716` | One aligned store of the type word plus a line flush. The checksum is computed as if the type were COMMIT (F5) |
| Zeroing pages after the head | `39849-39857` | `memset` plus flush. Idempotent (§4) |
| Head page header re-initialised | `40525` | Not done any more (§2.3) |

**The last-file slots.** Each log part has a control area. It holds
static config (format magic and version, NoOfFragmentLogParts, the part
number, NoOfFragmentLogFiles, FragmentLogFileSize, W) and two slots. Each
slot is `{seq (64 bit), lastFileNo, lap of that file, crc}` and fits in
one 64-byte line.

- **Write:** take seq = current seq + 1, store the slot `seq & 1`, flush
  it, `sfence`.
- **Read:** check both slots. Use the valid one with the higher seq. If
  neither is valid, the log part is corrupt: stop with a clear message.
- **Why it is safe:** only one slot is written at a time. A torn write
  leaves the other slot, which still names a file whose FD is persistent.
  This holds whatever A1 turns out to be. If A1 holds, one aligned 8-byte
  word `{fileNo:16, seq:32, check:16}` would also do; two slots are still
  preferred because they depend on no hardware claim.
- **Where:** the format document decides. One option needs no layout
  change: page 0 has at least 124 unused words at its end (the FD stops at
  word 8067 or earlier, by the capacity rule at `2833-2834`). The last
  256 bytes of page 0 of file 0 can hold the control area, provided the
  lap-change rewrite of that page writes only the header and the FD.
  A separate small control file per log part is the other option.

The control area also removes the need for page 0 of file 0 to be valid
in phase 1, except when file 0 is the last file. Then its FD page is
persistent by ordering (W3).

The write-path design (§6.2, step 3) updates `ZPOS_FILE_NO` with one
aligned store in place. That is atomic, but word 34 lies inside the FD
record. If the FD record has a checksum (F1), that store invalidates the
FD of file 0. So the word must either be left out of the FD's checksum or
moved into the control area. The slots of this section do the latter.

---

## 3. End-of-log detection

### 3.1 Why the valid log is a prefix

The rule in §3.2 assumes this invariant:

> At a crash, every byte stored before the end of the last barrier is
> persistent. After that point, any subset of lines may be persistent.

It holds if the write path follows W1-W8 (§8). The consequences are:

1. The last barrier ended at some position B. Everything before B is valid.
   E ≥ B.
2. Every acknowledged COMMIT and COMPLETE is before B (invariants C and K,
   plan §3.1). So is every `COMPLETED_GCI(g)` with g ≤ R_gcp (W6).
3. Records in `[B, E)` are valid but were not covered by a barrier. Using
   them is safe. A COMPLETE among them means TC had all COMMITTED, so every
   COMMIT of the transaction is persistent (plan §3.1). A COMMIT among them
   was not acknowledged.
4. Records after E (orphans) were not covered by a barrier either.
   Ignoring them is safe for the same reason.
5. **Mbyte order.** With W2, a valid mbyte header proves that the previous
   mbyte is complete, NEXT_MBYTE included. So E lies in the last mbyte
   with a valid current-lap header, or right at the start of the next one.
   Bytes after E can only be in the mbyte that contains E. Call it
   mbyte(E): it is lastMbyte, or lastMbyte + 1 when E is at its start.

### 3.2 The rule

A scan runs forward from the first record of an mbyte. It knows the
expected lap of every file. If L is the lap of the last file f, then files
0..f have lap L and files f+1..N−1 have lap L−1 (lap 0 means never
written). A position p where a record should start is **valid** if all
of these hold:

| Check | Condition |
|---|---|
| V1 page | The header of the page holding p passes its checksum. Its lap, fileNo, pageNo and log part number match the expected ones |
| V2 header | The type is a known type; type 0 is invalid. The length is within the bounds of the type. The record ends inside the mbyte |
| V3 spanned pages | Every further page that the record spans passes V1 |
| V4 checksum | The CRC over the record (page headers in between left out, COMMIT and INVALID_COMMIT hashed alike) seeded with (magic, part number, LSN(p)) equals the stored CRC |
| V5 structure | FD only at word 32 of page 0; FILLER ends on a W boundary; nothing follows NEXT_MBYTE in its mbyte |

After a valid record the next position is p + length, skipping page
headers. After NEXT_MBYTE it is the first record position of the next mbyte,
or of the next file, with lap + 1 when that file is 0.

**E is the first position in this sequence that is not valid.** If the
NEXT_MBYTE at the end of the last mbyte is valid but the next mbyte's
header is not, E is the first record position of that next mbyte; it may
be in the next file.

### 3.3 The cases

| Case | What the scan sees | Result |
|---|---|---|
| Torn last record | some words new, some old; V4 fails (false pass about 2⁻³²) | E = start of that record |
| Record of the previous lap at p | V4 fails: the CRC was seeded with an older LSN. V1 also fails if the page header is old | E = p |
| Page header torn or not yet written | V1 fails for the page, or V3 for a record that spans into it | E = the first record that touches the page |
| Mbyte header torn or old | phase 1 sees the lap drop there (an invalid header counts as "lap < L") | E = the first record position of that mbyte |
| Filler at the end | the filler is valid and ends on a unit boundary; the next unit holds old data or zero, and V1 or V4 fails | E = that unit boundary |
| Zeroed region | type 0 fails V2; a zero header fails V1 | E = start of the zeroed region |
| FD of the next file torn | the last-file slot still names the old file; NEXT_MBYTE of its last mbyte is valid; the next file's header fails | E = start of the next file. The writer redoes the file switch (§3.4 step 5) |
| Orphans after a hole | not detected by V1-V5 | must be zeroed (§4) |

The 2⁻³² false-pass rate is per torn record, so a few per crash at most.
A 64-bit checksum would lower it, at a cost in space and time (§10 Q4).

### 3.4 Phase 1 on PMEM

All files of the part are mapped. Reads are loads from the mapping.

1. Read the control area. Check the static config against the node's
   config: this replaces the check of `ZPOS_NO_LOG_PARTS` (`36295-36306`).
   Pick the last-file slot. That gives the last file f and its lap.
2. Read page 0 of f. Its header and FD record must be valid; if not, the
   log is corrupt. Fill the arrays of earlier files from the FD, as today
   (`initGciInLogFileRec`). Optionally read every mbyte header of every
   file directly instead (it costs a few milliseconds); the FD then becomes
   redundant.
3. Read every mbyte header of f. The first one that is invalid or has lap
   < L gives `lastMbyte = mb − 1`; with no drop, `lastMbyte = F − 1`, as
   today. A header that is valid and current but comes after the drop
   would contradict W2: it is reported as corruption.
4. Scan lastMbyte from its first record with the rule of §3.2, verifying
   every record in full, PREPARE bodies included. The result is E. Store
   it in the log part record (new fields `endFileNo/endPageNo/endPageIndex`).
   The scan costs at most 1 MB of reads.
5. Zero `[E, end of mbyte(E))`, page 0 of a file excepted, and issue a
   barrier (§4.2). When E is the first record position of lastMbyte + 1,
   this zeroes records that persisted under a header that did not. The
   writer initialises that header, or redoes the file switch, when it
   resumes there.
6. Continue with `ZSR_PHASE3_START(ZSR_PHASE1_COMPLETED)` as today.

Step 4 makes the exact end known early, before the LCP restore. Every later
scan uses the stored E.

### 3.5 Scans after phase 1

- Every scan (phase 3, phase 2 steps A and B, NR) stops at E. Reaching E
  without the record it needs (`COMPLETED_GCI(R)` in phase 3) is the
  existing error "end of log without last GCI".
- **An invalid record or header before E is corruption.** By §3.1 every
  mbyte before lastMbyte is complete, and lastMbyte was verified up to E.
  The node stops with a message naming the position. It must never treat
  such a record as the end: that would silently drop records that may be
  acknowledged.
- For speed, scans before lastMbyte may check V1, V2 and V5 for every
  record but V4 only for the records they act on (COMMIT, COMPLETE,
  ABORT, COMPLETED_GCI, NEXT_MBYTE, FD). A PREPARE's V4 is checked when it
  is executed through a COMMIT's back reference. A debug option can verify
  everything.
- **Reading** (answers the write path's R-6). Pages are copied from the
  mapping into the existing `LogPageRecord` buffers instead of read by
  `FSREADREQ`. The scratch header words then change only in the copy (§1.7
  item 3). Checksums are verified on the copy first. The SR then needs per
  part the execution window of `ZMAX_MM_BUFFER_SIZE` = 32 pages
  (`Dblqh.hpp:182`, `DblqhMain.cpp:42692`) plus 3 pages for a PREPARE read
  through a back reference. The RedoBuffer must keep at least that much
  until the restart ends, even if the write path shrinks it to a few
  staging pages afterwards. The redo page cache (`47191-47323`) only saves
  disk reads and can be skipped on PMEM. [I]

---

## 4. Invalidation on PMEM

### 4.1 Is the lap and position check enough?

V1-V5 reject data of the previous lap, zeroed space and space never
written. They do not reject records of the current lap at their true
positions: orphans after a hole (A2), and the abandoned region `[H, E)`
when a restart moves the head back. COMMITs with GCI > R before H are a
separate matter: they are inside the valid log and must not be executed
later.

**No, it is not enough.** An orphan has the same lap and position as the record the new
writer will later put there. Suppose the restart resumes at E and writes
new records. A later crash leaves the new end at E2 < old orphan end. If E2
falls on a record boundary of the old stream, the scan continues into the
orphans and accepts them. Records from the old run would then be applied.
With GCI numbers reused after the SR, that corrupts data. This is the same
"connect new log pages to old invalid log pages" problem that today's
invalidation solves (`39632-39635`). [I]

### 4.2 What must be invalidated, and how

| Restart kind | New head | Zero | In-place type rewrite |
|---|---|---|---|
| SR with durable commits (phase 2 runs) | E (plan §5.3) | `[E, end of mbyte(E))`, in phase 1 | COMMITs of transactions aborted in phase 2, step C |
| SR without durable commits, or with R_gcp < g − 1 | H, after `COMPLETED_GCI(R)` | `[E, end of mbyte(E))` in phase 1, then `[H, E)` in phase 4, **page 0 of each file excepted** | COMMITs with GCI > R found before H (as today) |
| NR | H, after `COMPLETED_GCI(own GCI)` | as the line above | as the line above |

- **Zeroing** is a `memset` of the range plus `clwb` of each line and one
  `sfence`. 1 MB takes well under a millisecond. The `[H, E)` range of a
  non-durable restart is the log written since the last GCP save, normally
  a few MB. Zeroing it costs milliseconds.
- **Page 0 of each file is kept,** as today. Until the slot is moved back,
  phase 1 must find a valid FD in the file the slot names.
- **The head page is zeroed from H** (or from E), not skipped as today.
  Orphans in that page are covered too.
- **The type rewrite** is one aligned 4-byte store per COMMIT, then
  `clwb`; one `sfence` after a batch. It needs F5. Without F5 the record
  would fail its checksum, and the next scan would end the log there.
  Everything after it would be lost.

The bound `end of mbyte(E)` rests on W2: no persist crosses an mbyte
boundary, and the NEXT_MBYTE of an mbyte is fenced before any byte of the
next one is stored. The write-path design meets W2: its copy stops after
NEXT_MBYTE (`pmem_redo_write_path.md` §6.1). It also bounds the bytes
after E to one copy, a few pages (its R-8). Zeroing the rest of mbyte(E)
covers that and does not depend on the copy size.

### 4.3 Order and repeatability

1. Phase 1 zeroes `[E, end of mbyte(E))`. The bytes were never part of
   the valid log, so this is safe whatever this SR decides later.
2. Phase 3 (and phase 2) rewrite COMMIT type words, then issue a barrier.
3. A non-durable restart zeroes `[H, E)` **backwards**, from E down to H,
   with a barrier at the end.
4. A non-durable restart then writes the last-file slot, naming H's file.
5. The restart record and `COMPLETED_GCI(G')` (or the next GCP's record)
   are appended at the new head, followed by a barrier.

A crash at any point leaves a state that the next restart handles:

- **Crash in step 1.** E is unchanged, since zeroing starts at E and E
  stays invalid. Zeroing is redone.
- **Crash in step 2.** Rewritten words are valid INVALID_COMMIT records.
  The rest are rewritten again, because the same records lead to the same
  decisions (plan §5.2 "Repeatable").
- **Crash in step 3.** The slot still names the old last file, whose page
  0 is intact. Phase 1 finds an end E' no later than the old E. The scan
  stops at H again, because R has not changed, and H lies before every
  zeroed byte, so the "invalid before E" rule of §3.5 is not triggered.
  `[H, E')` is zeroed again. The durable branch never zeroes before E.
- **Crash after step 4.** The next phase 1 starts in H's file and finds
  the zeroed mbytes as the lap drop.

The order "zero first, slot last" keeps today's order
(`exitFromInvalidate` runs last, `40141-40153`). Moving the slot first would
leave orphans in later files with the current lap. The writer would reach
them later.

### 4.4 Alternative: a restart generation

Each record could carry a 32-bit restart generation, raised at every
restart before the first write, with the rule that the generation never
decreases along the log. Orphans would then fail the check and need no
zeroing. This costs a word per record and a durable generation counter, and
the reader must learn the generation at its start position. Zeroing is
bounded and cheap on PMEM, and it keeps today's structure. **Zeroing is
recommended for step 1.** The generation stays an option for later.

---

## 5. Node restart

The same head and tail logic serves an NR without change. [V for the
flow, I for PMEM]

- **Phase 1** is the same code (`2463-2495`), so E and the zeroing of
  `[E, end of mbyte(E))` come for free.
- **Phase 3** gets R = the node's own `lastCompletedGCI` from `nr_run_redo`
  (`DbdihMain.cpp:8473-8502`, `476`, `487`). The scan stops at
  `COMPLETED_GCI(own GCI)`, which is before E by W6. COMMITs with GCI > own
  GCI before it are rewritten as INVALID_COMMIT (F5).
- **Phase 4** moves the head back to H, zeroes `[H, E)` (page 0 of each
  file excepted) and moves the slot. That is the non-durable line of the
  §4.2 table.
- **Durable mode.** NR does not run phase 2 (plan §8). The node's
  transactions after its own GCI are in the survivors' data and come back
  by copy-fragment. A node with a durable tail from an earlier SR is
  covered too: that SR raised its restorable GCI to G' and invalidated the
  aborted COMMITs, so an NR to a GCI ≥ G' executes exactly the survivors.
- **Stale node** (plan §5.4). It joins by NR with its old restorable GCI.
  Its REDO beyond that GCI is invalidated or zeroed like any other NR.

---

## 6. The durable tail (phase 2, plan §5.2)

What phase 2 needs from the head and tail design:

1. **Start of step A.** The first COMMIT with GCI > R_gcp can come
   **before** `COMPLETED_GCI(R_gcp)`. Commits of R+1 start before
   `GCP_SAVEREQ(R)` arrives; that is why `execSr` invalidates them today
   (`39117-39132`). A COMPLETE of an R+1 transaction can also come before
   that record. So step A cannot start at `COMPLETED_GCI(R)`. Two options:
   - **Merge step A into the phase-3 scan of round 0.** Round 0 starts at
     the start mbyte, which is before every record with GCI ≥ logStartGci,
     and logStartGci ≤ R + 1 (§2.3). In durable mode a COMMIT with GCI > R
     (and ≥ g) is queued instead of invalidated. The scan goes on past
     `COMPLETED_GCI(R)` to E. This is the simpler option.
   - **A separate scan** from the last mbyte M with
     `logMaxGciStarted[M] ≤ R`, found by the `srLogLimits` walk with
     `logStartGci = R + 1`.
2. **Start of step B.** COMPLETE records carry no GCI (plan §7), so step B
   cannot filter by GCI. It must start where step A started. Store that
   position per log part.
3. **End.** E from phase 1 for both scans. E is computed once and the
   media before E does not change during the SR, except for type-word
   rewrites, which keep records valid (F5). Both scans therefore see the
   same records.
4. **Stop rules change in durable mode.** The crash at NEXT_MBYTE of the
   stop mbyte (`39264-39283`) no longer applies; the scan stops at E.
   Phase 4 does not move the head back (plan §5.1). It appends the
   SR-head record and `COMPLETED_GCI(G')` at E, after the zeroing of §4.3
   step 1, and `readSrFourthPhaseLab` must set the GCI values to G', not R
   (`40499-40515`).
5. **Stale `COMPLETED_GCI` records in the tail** are harmless. In each
   log part every COMMIT with GCI ≤ g precedes `COMPLETED_GCI(g)` (research
   `research_redo_log.md` §5). A later SR that stops at an older
   `COMPLETED_GCI(G')` from the tail has already passed every COMMIT
   ≤ G'. [I]

The head and tail design gives phase 2 a reliable end: E is exact,
deterministic and repeatable. An invalid record before E stops the node
instead of shortening the tail.

---

## 7. Requirements on the record format (`pmem_redo_format.md`)

| # | Requirement | Why |
|---|---|---|
| F1 | Every record has a CRC32C over its type, length and body. That includes NEXT_MBYTE, FILLER, FD, COMPLETED_GCI, the restart record and any page-skip record. The CRC is seeded with (format magic, log part number, LSN of the record start). Page headers that a record spans are left out | V4; previous-lap records fail; a misparsed offset fails |
| F2 | Records start on 8-byte boundaries and have an even word length. The first 8 bytes hold the type and the length | the type and length are one failure-atomic unit (A1); fillers always fit |
| F3 | Type 0 is invalid. An all-zero record or header never passes (non-zero seed) | zeroed and never-written space ends the log |
| F4 | Each type has length bounds. No record spans an mbyte (as today) | V2, V5 |
| F5 | The COMMIT type word sits alone in an aligned 4-byte slot. The CRC is computed with INVALID_COMMIT read as COMMIT. The same applies to any record later rewritten in place | invalidation by one atomic store keeps the record valid |
| F6 | Page header: written once per lap; holds magic and version, part number, lap, fileNo, pageNo, and in the first page of each mbyte `maxGciCompleted`, `maxGciStarted`, `lastPrepRef` (start values); has a CRC seeded with its position. `ZCURR_PAGE_INDEX`, `ZNEXT_PAGE`, `ZPREV_PAGE`, `ZPOS_DIRTY` and the debug words are either outside the persistent header or outside the CRC and never stored after init. Keeping the 32-word layout lets recovery reuse its buffers | V1; no header rewrite |
| F7 | A control area per log part that the lap-change rewrite never touches: static config plus two last-file slots `{seq64, lastFileNo, lap, crc}` | torn-safe last-file pointer (§2.4) |
| F8 | FILLER: a checksummed header, a length that ends it on a W boundary; the body may be left out of the CRC | V5; a filler costs one 8-byte store |
| F9 | Optional: an explicit lap (or LSN) tag in each record | diagnostics in `redoLogReader`; tells "old lap" from "torn" |
| F10 | Optional: a 64-bit checksum | lowers the 2⁻³² false-pass rate |

## 8. Requirements on the write path and on the hardware

**Write path (`pmem_redo_write_path.md`):**

| # | Requirement | Used in |
|---|---|---|
| W1 | A barrier persists every byte stored in the log part since the previous barrier, by all LDMs. It completes only when every record before its end position is fully stored. If records are reserved under the log-part mutex and copied outside it, the barrier must wait for the contiguous "fully stored" frontier | §3.1. Otherwise an acknowledged COMMIT can sit after a hole, and the end-of-log rule discards it |
| W2 | No persist (copy plus fence) crosses an mbyte boundary. The NEXT_MBYTE of mbyte M is fenced before any byte of M+1 is stored. Met by `pmem_redo_write_path.md` §6.1 | §3.1 item 5; bounds orphans to mbyte(E) (§4.2) |
| W3 | File switch: persist the old file's end; copy the new FD page and fence; write the last-file slot and fence; only then records. All files are mapped at start, so nothing is opened ahead. Met by `pmem_redo_write_path.md` §6.2, if its step 3 writes the slot of §2.4 | §2.4, §3.3 |
| W4 | A page header is stored when the writer enters the page, and never again in that lap | V1; no torn header over valid records |
| W5 | Bytes before the end of the last barrier are not modified in the current lap, except: a COMMIT type word (F5), the control-area slots, and restart zeroing at or after E (or H) | §2.4 |
| W6 | `COMPLETED_GCI(g)` is persisted by a barrier before `GCP_SAVECONF` | §3.1 item 2; the phase-3 stop record is before E |
| W7 | After a restart, store a FILLER from E to the next W boundary and append from there, in the existing page, without touching a valid header. Records in `[B, E)` stay, because a COMPLETE there may have decided a phase-2 verdict. This satisfies the write path's R-7, since the unit holding E was never covered by a barrier. A header is initialised only if it fails V1. If E is at a file start, the file switch is redone | §2.3, §3.1 |
| W8 | No stores ahead of the write position except zeros. Non-temporal stores, if used, are fenced before the barrier counts | §3.1 |

**Hardware (`research_pmem_hardware.md`), to be confirmed:**

| # | Assumption |
|---|---|
| H1 | Aligned stores of up to 8 bytes are failure-atomic. A 64-byte line is not |
| H2 | Under ADR, stored lines can persist early and in any order (holes). Under eADR, ordinary stores persist in store order |
| H3 | Flushing a line again, whose bytes before the append point are unchanged, cannot corrupt those bytes on power loss. This is needed when appending at E in the middle of a line, and for the type-word rewrite |
| H4 | A poisoned line (media error) gives a machine check / `SIGBUS` on load. Recovery must turn that into a corruption stop with the position, not a crash without context |

---

## 9. Recovery code changes, function by function

| Function (today) | Change |
|---|---|
| `readSrFrontpageLab` `36289` | Read the control area: config check, last-file slot |
| `readSrLastFileLab` `36332`, `readSrLastMbyteLab` `36367` | Verify header CRC and identity. An invalid mbyte header counts as a lap drop. Then scan lastMbyte for E, store E, zero `[E, end)` |
| `initGciInLogFileRec` `42279` | Verify the FD record's CRC first |
| `readExecSr` `42893`, `readExecLog` `42814`, `readSinglePage` `43112` | Copy from the mapping instead of `FSREADREQ`. Verify checksums on the copy |
| `execSr` `38962` | Track the expected lap per file. Check V1, V2, V5 per record and V4 for interpreted records. Stop at E. Invalid before E → corruption stop. NEXT_MBYTE in the stop mbyte is no error in durable mode |
| `execSr` COMMIT gci > R `39117-39132`; `writeDirty` `43669` | Store the type word in the mapping, `clwb`; one `sfence` per batch. No page write |
| `readSrFourthPhaseLab` `40474` | Do not re-initialise a valid head-page header. GCI values G' in durable mode |
| `readFileInInvalidate`, `invalidateLogAfterLastGCI`, `writeFileInInvalidate` `39534-40098` | Replace the lap search by the known range `[H, E)`: E is exact. Zero backwards, page 0 of each file excepted, from H inside the head page |
| `exitFromInvalidate` `40100` | Write a last-file slot instead of the whole page 0 |
| `redoLogReader` | Learn the new checks; report E and the reason for the stop |

---

## 10. Open questions

1. **Q1. Where does the control area live?** At the end of page 0 of file 0
   (no layout change, but the lap-change rewrite must skip it), or in a
   separate control file per log part? Format subtask.
2. **Q2. Zero range.** The write path bounds the bytes after E to one copy
   (its R-8). Should recovery zero only `[E, E + max copy)` instead of the
   rest of mbyte(E)? The mbyte bound is simpler, needs no shared constant,
   and costs under a millisecond.
3. **Q3. W1 with shared log parts.** Answered by the write path: copies
   run under the part mutex and each ends with its own `sfence`
   (`pmem_redo_write_path.md` §2.4). W1 must stay true if a later design
   copies outside the mutex.
4. **Q4. CRC32C or a 64-bit checksum?** The rate is 2⁻³² per torn record.
   A false pass at E would accept one garbage record. It would most likely
   be a PREPARE, since it is the last record.
5. **Q5. Later simplifications.** Should phase 1 read every mbyte header
   directly (N·F line reads, milliseconds), so that the FD record becomes a
   cross-check only? Should a restart generation (§4.4) be added as
   defence in depth?
6. **Q6. Media errors (H4).** Should the node stop at a poisoned line
   before E, or treat it as the end when it lies in mbyte(E)?
7. **Q7. Testing.** The power-loss emulator (plan §10.1 P6) must reproduce
   A2. It must keep everything up to the last fence. For the copy in
   flight, it must drop or keep each later line at random and tear lines
   at 8-byte granularity. A plain `kill -9` never produces holes, so
   orphans would never be tested.

## 11. Recommendations

1. **Keep the geometry, the mbyte headers, the FD record and the
   phase 1 → 3 → 4 structure.** Recovery reads few fields, and their
   semantics survive incremental persistence (§1.6, §2.3).
2. **Make the exact end E a phase-1 result.** Scan the last mbyte with the
   §3.2 rule, store E, and bound every later scan by it. Treat an invalid
   record before E as corruption.
3. **Zero `[E, end of mbyte(E))` in phase 1 of every restart**, and
   `[H, E)` in phase 4 when the head moves back. Zero backwards. Never zero
   page 0 of a file. Write the slot last.
4. **Replace the in-place page-0 rewrite** by two checksummed slots in a
   control area that the lap change never touches.
5. **Make COMMIT invalidation a single atomic type-word store**, with the
   CRC computed as if the type were COMMIT (F5). Without it, today's
   invalidation and phase 2's step C would truncate the log.
6. **Stop re-initialising the head page's header** at restart (W7).
7. **Require W1-W8 from the write path**, above all W1 (barrier frontier)
   and W2 (no persist across an mbyte boundary). The write-path design
   meets both as written.
8. **In durable mode, merge phase 2 step A into the phase-3 scan** and
   start step B at the same position. Neither may start at
   `COMPLETED_GCI(R_gcp)`.
9. **Read by copying from the mapping into the existing buffers** for
   step 1, so that the parser and its scratch header words stay unchanged
   and the mapping is written only by the explicit updates of §2.4.

**On the architect's guidance.** Points 1, 2, 4 and 5 hold. Point 3
holds too: the mbyte headers keep working, and the page GCI fields need no
change beyond not rewriting the head page. Four gaps come with it:

- Page 0 of file 0 is also rewritten in place; the "last file" pointer
  needs a torn-safe form (§2.4).
- Per-record checksums conflict with today's in-place COMMIT invalidation
  unless the checksum ignores the type change (F5).
- Checksums detect torn and previous-lap data, but not orphans after a
  hole, which are of the current lap (§4.1). Bounded zeroing, which rests
  on W2, is still required.
- The filler and the NEXT_MBYTE record must be checksummed, position-seeded
  records too. A 1-word NEXT_MBYTE left from the previous lap would
  otherwise let the scan jump over garbage.
