# RONDB-1150: the REDO write path on persistent memory

Status: design, first iteration. No code has been changed.
Input to plan subtask P2 (`durable_commits_plan.md` §10.1).
Companion documents written in parallel (not read when this was written):
`research_pmem_hardware.md`, `pmem_redo_format.md`, `pmem_redo_recovery.md`.
Where this design depends on them, the dependency is stated as an
assumption (A-n) or a requirement (R-n), collected in §11.

Paths are relative to `storage/ndb/`. Short names:
`DblqhMain.cpp` = `src/kernel/blocks/dblqh/DblqhMain.cpp`,
`Dblqh.hpp` = `src/kernel/blocks/dblqh/Dblqh.hpp`,
`DblqhInit.cpp` = `src/kernel/blocks/dblqh/DblqhInit.cpp`,
`ConfigInfo.cpp` = `src/common/mgmcommon/ConfigInfo.cpp`
(the task text says `src/mgmsrv/`; the file lives in `src/common/mgmcommon/`).
Line numbers are from commit a597bbd216f.

Tags: **[V]** verified by reading the code at the cited lines.
**[I]** inferred, or a published figure not measured here.

---

## 0. Summary

1. **Records are still built in DRAM log pages.** At each persist point the
   new bytes are copied into the DAX mapping with non-temporal stores
   (ntstores) and fenced with `sfence`. `currentLogpage` does not point into
   PMEM. The record writers, positions and mbyte logic stay as they are.
2. **One primitive, `redoPersist(part)`**, called with the part mutex held:
   pad to the write unit W with a FILLER record, copy every complete byte
   since the part's persisted LSN, `sfence`, advance the persisted LSN.
   Every copy into PMEM ends with an `sfence` by the copying thread, so
   "persisted LSN" is always a true prefix property, also when several LDMs
   share a part.
3. **Barriers (first iteration, immediate).** After the COMMIT record(s) are
   appended and before COMMITTED, COMMITCONF or a forwarded COMMIT (C).
   After the COMPLETE record is appended and before local commit, a
   forwarded COMPLETE, COMPLETED or COMPLETECONF (K). Exact places in §3.
4. **Filler: pad, then persist.** W = 64 bytes by default (a compile-time
   constant that can be 64, 128 or 256). A persisted unit is never written
   again. This costs about W bytes of log per operation (§4).
5. **Mapping by NDBFS** with a new open flag (`MAP_SHARED_VALIDATE |
   MAP_SYNC`); the failure of `MAP_SYNC` is the DAX check. DBLQH owns the
   address. All files of a part are mapped once, at start.
6. **What disappears in PMEM mode:** FSWRITEREQ/FSWRITECONF and LFOs for
   REDO writes, page batching, `timeSup` partial-page writes, FSSYNCREQ,
   `checkGcpCompleted`, the file-change state machine, run-time file opens,
   P_FILE_CHANGE_PROBLEM, P_REDO_IO_PROBLEM, buffer-full queueing and error
   1221. The RedoBuffer shrinks to a few staging pages (plus what SR needs).
7. **GCP_SAVEREQ** becomes COMPLETED_GCI + `redoPersist` per part, then
   GCP_SAVECONF in the same signal.
8. **Cost** on Optane-class PMEM: about 0.3-0.5 µs of LDM time per write
   operation per replica, two `sfence` waits included [I].

---

## 1. Today's write path

### 1.1 Append

| Step | Where | What happens |
|---|---|---|
| One word | `writeLogWord`, `DblqhMain.cpp:43721-43739` | Store at `logPageWord[ZCURR_PAGE_INDEX]`, advance. A full page calls `completedLogPage(ZNORMAL, sync=false)`, seizes and inits a new page, `currentFilepage++` [V] |
| Many words | `writeLogWords`, `43746-43785` | `MEMCOPY_NO_WORDS` per page, same page break [V] |
| PREPARE | `writeLogHeader` `14221-14255` (fast path `14234-14244`), `writeKey` `14262-14279`, `writeAttrinfoLab` `14286..` | Header written directly into the page when the 8 words fit [V] |
| COMMIT | `writeCommitLog`, `43566-43621` (fast path `43607-43619`) | 9 words directly; word-by-word if it crosses a page [V] |
| ABORT, COMPLETED_GCI | `writeAbortLog` `43542-43559`, `writeCompletedGciLog` `43631-43662` | Word by word [V] |
| Mbyte check | `checkNewMbyte` `14172-14214`; inline in `43578-43582`, `43546-43550`, `43634-43638` | A record plus `ZNEXT_LOG_SIZE` must fit `remainingWordsInMbyte`, else `changeMbyte` first. No record spans an mbyte [V] |

Every append runs under `lock_log_part`, and a whole record is written in
one critical section: `writePrepareLog` locks at `13381` and the record is
complete before the unlock at `13567`/`13579`; `execLQH_WRITELOG_REQ` locks
at `15310`, writes at `15343`, unlocks at `15345` [V].

### 1.2 Page completion, batching, LFOs and FSWRITEREQ

- `completedLogPage` (`41035-41159`) links the page onto the file's filled
  list and returns, unless `noLogpagesInBuffer == ZMAX_PAGES_WRITTEN` (8,
  `Dblqh.hpp:184`) or the type is `ZENFORCE_WRITE`/`ZLAST_WRITE_IN_FILE`
  (`41057-41065`) [V].
- When it writes: `seizeLfo` (`41075`), debug header and checksum per page
  (`41088-41092`; the checksum is the constant 37 in release builds), one
  FSWRITEREQ with up to 15 pages on JBA (`41116`). Sync iff last write in
  file or `sync_flag` (`41109-41110`). `filePosition += n` (`41158`) [V].
- `writeSinglePage` (`36203-36258`) writes one page with its own LFO; used
  for page 0, init pages and the `timeSup` copy [V].
- There are only three FSWRITEREQ send sites in DBLQH: `36241`
  (`writeSinglePage`), `41116` (`completedLogPage`), `43700` (`writeDirty`,
  SR invalidation) [V].
- `userReference` is the part owner's `myRef` (`41104`), so FSWRITECONF
  always returns to the owning LDM [V].

### 1.3 Completion

`execFSWRITECONF` (`34686-34764`) → `initFsrwconf` (`34859-34931`: takes the
part lock, clears in-writing flags, IO tracker) → switch on the LFO state →
`writeLogfileLab` (`35069-35104`: `checkGcpCompleted` if
`fileChangeState == NOT_ONGOING`, else remember the last written page and
word) → `releaseLfoPages` and `releaseLfo`. The lock is released at
`34763` [V].

### 1.4 Partial pages: `timeSup`

- `timeSup` (`34944-35067`) copies the current page into a seized page
  (`35017-35022`) and writes the copy, either with the pending full pages
  (`35024-35038`, with `lfoWordWritten` = real last word and
  `filePosition--`) or alone with sync (`35056-35059`). The original page
  keeps filling and is written again later at the same offset [V].
- On the last page of an mbyte it calls `changeMbyte` instead
  (`35003-35010`). With P_FILE_CHANGE_PROBLEM it retries in 50 ms
  (`34977-34999`) [V].
- It runs only from `initGcpRecLab` → `startTimeSupervision`
  (`34121`, `34055-34067`), once per GCP_SAVEREQ [V].

### 1.5 Mbyte switch

`changeMbyte` (`40863-40868`) = `writeNextLog` + `writeFileDescriptor`.

- `writeNextLog` (`43801-43980`) stores ZNEXT_MBYTE at the current index
  without advancing it (`43825-43826`).
- Not the last mbyte of the file: `completedLogPage(ZENFORCE_WRITE,
  sync=true)` (`43866`), i.e. a synced write per MB.
- Last mbyte: `completedLogPage(ZLAST_WRITE_IN_FILE, sync=true)` (`43845`),
  `logLap++` when the next file is file 0 (`43847-43854`), switch file.
- New position (`43880-43883`), new page (file 0, mbyte 0 reuses
  `logPageZero`, `43885-43895`), `initLogpage` (`43896`).
- Head meets tail → crash (`43927-43951`). Free-space checks: `force_lcp`
  and P_TAIL_PROBLEM (`43968-43980`) [V].
- `writeFileDescriptor` (`36019-36066`) fills the in-memory per-mbyte
  arrays `logMaxGciCompleted/Started` and `logLastPrepRef` [V].

### 1.6 File switch

- At the start of a new file, `writeFileHeaderOpen` (`36073-36161`) builds
  the FD record in page 0 and writes it with sync (`36145-36147`), then
  seizes the first data page. `openNextLogfile` (`35798-35884`) opens the
  file after it with FSOPENREQ (bound IO thread). State
  `BOTH_WRITES_ONGOING` (`43922-43924`), or `WAIT_FOR_OPEN_NEXT_FILE` plus
  P_FILE_CHANGE_PROBLEM if the file is not open yet (`43913-43920`) [V].
- `firstPageWriteLab` (`35130-35204`) and `lastWriteInFileLab`
  (`35206-35311`): when both the last write of the old file and page 0 of
  the new file are done, `ZPOS_FILE_NO` in page 0 of **file 0** is updated
  and that page is rewritten with sync (`35197-35201`, `35303-35307`) [V].
- `writePageZeroLab` (`35313-35341`) clears P_FILE_CHANGE_PROBLEM, sets
  `NOT_ONGOING` and runs the `checkGcpCompleted` that was held back [V].

### 1.7 GCP_SAVEREQ

`execGCP_SAVEREQ` (`33749-33955`) → `start_synch_gcp` (`33957-33997`): an
IDLE part writes COMPLETED_GCI at once (`33988`); an ACTIVE part sets
`WWGL_TRUE` and the queue runner writes it (`logNextStart` `42576-42666`,
then `ZINIT_GCP_REC`) → `initGcpRecLab` (`34074-34132`) records the target
per part and forces the partial page through `timeSup` →
`checkGcpCompleted` (`34141-34258`) on write completions; when all parts
are on disk it sends FSSYNCREQ per part (`34232-34252`) →
`execFSSYNCCONF` (`34260-34301`) → GCP_SAVECONF [V].

### 1.8 RedoBuffer, queueing, error 1221, commit reservation

- **Pool.** Per part, `allocChunks(RG_FILE_BUFFERS)` (`DblqhInit.cpp:312-365`).
  Size from `globalData.theRedoBuffer`, rounded to half MB, times the
  number of parts; `clfoFileSize = logPageFileSize` (`DblqhMain.cpp:2716-2743`).
  Automatic size `numLDM*32MB/parts`, capped at 64 MB per part
  (`src/kernel/vm/Configuration.cpp:1005-1024`) [V].
- **Free pages.** `count_free_log_pages` (`947-1008`) subtracts booked
  cross-LDM space; below `ZMIN_LOG_PAGES_OPERATION` (10, `Dblqh.hpp:186`)
  the buffer counts as full [V].
- **Queueing.** `writePrepareLog` (`13376-13458`): on a problem the prepare
  aborts (always for P_TAIL_PROBLEM, `13406-13416`; also when
  QueueOnRedoProblem is off), otherwise it is queued as LOG_QUEUED; a part
  that is not IDLE also queues (`13433-13453`). `execLQH_WRITELOG_REQ`
  queues the commit as LOG_COMMIT_QUEUED[_WAIT_SIGNAL] when the complete
  queue is non-empty or no page is free (`15311-15342`). The queue runner
  is `queued_log_write` (`1010-1129`) → `handle_queued_log_write`
  (`856-945`), or `send_handle_queued_log_write` (`770-835`) with booked
  space and `ZCONTINUE_WRITE_LOG` (`1408-1425`) when the head of the queue
  belongs to another LDM [V].
- **Error 1221** (`ZTEMPORARY_REDO_LOG_FAILURE`) when out of buffer and not
  queueing (`writePrepareLog_problems`, `13587-13616`) [V].
- **Commit reservation.** `increment_committed_mbytes` adds
  `ZCOMMIT_LOG_SIZE+1` words per logged prepare (`47888-47897`, called at
  `13477`); `decrement_committed_mbytes` at `43620` and `43558`; the tail
  check uses `get_committed_mbytes` (`47881-47886`, `43976-43977`) [V].

### 1.9 Shared log parts

`set_use_mutex_for_log_parts` (`13305-13368`) turns the mutex on unless the
number of parts is a multiple of the LDM count (or there are 1 or 2 LDMs).
`lock_log_part` is a no-op otherwise (`Dblqh.hpp:6636-6648`) [V].

### 1.10 Creating and initialising the files (initial start)

- `openLogfileInit` (`35674-35731`): `OM_CREATE | OM_TRUNCATE`, plus
  `OM_INIT` for `InitFragmentLogFiles=full` or `OM_SPARSE_INIT` for
  `sparse` (`35698-35704`; config read at `2766-2778`; default `sparse`,
  `ConfigInfo.cpp:1150-1152`) [V].
- Sparse: `openFileInitLab` writes the last page to set the size
  (`35358-35364`), and `writeInitMbyte` writes the first page of each
  mbyte (`36172-36184`) [V].
- Full: NDBFS allocates, zeroes and formats the whole file in the IO thread
  (`src/kernel/blocks/ndbfs/AsyncFile.cpp:381-470`), calling back into
  `Dblqh::execFSWRITEREQ` across threads to format each page
  (`DblqhMain.cpp:35733-35790`) [V].
- Then `initWriteEndLab` (`35371-35395`: file 0 page 0 with lap 1),
  `writeFileHeaderOpen(ZINIT)`, `initFirstPageLab` (`35397-35420`: page 1
  of file 0 holds COMPLETED_GCI(1)), and `checkInitCompletedLab`
  (`35459-35513`) [V].

---

## 2. The PMEM write path

### 2.1 Who maps the files and who owns the mapping

**Decision: NDBFS opens and maps; DBLQH owns the address range.**

- A new open flag, for example `FsOpenReq::OM_MAP_SYNC` (bit `0x20000000`
  is free, `include/kernel/signaldata/FsOpenReq.hpp:112-146`) [V].
- The NDBFS IO thread opens the file as today (`OM_READWRITE |
  OM_CHECK_SIZE`), then calls a new portlib helper,
  `ndb_pmem_map(fd, size, &addr)` in `include/portlib/ndb_pmem.h` and
  `src/common/portlib/ndb_pmem.cpp`. It does
  `mmap(PROT_READ|PROT_WRITE, MAP_SHARED_VALIDATE|MAP_SYNC)` and pre-faults
  the whole range for write. No such helper exists today (grep for
  `MAP_SYNC`, `clwb`, `pmem` in portlib, vm and ndbfs finds nothing) [V].
- `mmap` with `MAP_SYNC` fails with `EOPNOTSUPP` when the file is not on a
  DAX mapping [I]. That failure is the DAX check (§10).
- FSOPENCONF returns the address in two extra words
  (`include/kernel/signaldata/FsConf.hpp:83-100` has room after
  `file_size_lo`) [V]. Open with `OM_THREAD_POOL` so that no bound IO thread
  is created per file (`src/kernel/blocks/ndbfs/Ndbfs.cpp:587`) [V].
- DBLQH stores `Uint8 *m_pmem_base` in `LogFileRecord`. FSCLOSEREQ unmaps.

Why NDBFS and not DBLQH directly:
- NDBFS builds the path (`FileSystemPath`, `D8..D39/DBLQH/S<n>.FRAGLOG`)
  and handles errors and creation; DBLQH only knows file numbers.
- `mmap` plus pre-faulting 1 GB takes tens to hundreds of ms [I]; it should
  not run in an LDM thread.
- NDBFS leaves the write path (plan §2.1), but keeps open, map and close.

**When.** All files of every part the LDM owns are opened and mapped once:
after the initial-start initialisation (`checkInitCompletedLab`) and, for
other starts, before SR phase 1 reads page 0 of file 0 (start phase 3,
`DblqhMain.cpp:2484-2493`). They stay mapped until the node stops. No file
is opened at run time. Virtual address space is parts × files × size, for
example 4 × 16 × 1 GB = 64 GB with the defaults (`ConfigInfo.cpp:1134-1148`)
[V]; this is no problem on 64-bit.

**Access.** Any LDM that holds the part mutex may write the mapping; this is
the same rule as for `LogFileRecord` and the log pages today, which other
LDMs reach through `logPartPtrP->my_block` [V].

### 2.2 Position, address and LSN

- Address of word `w` of page `p` of file `f`:
  `f.m_pmem_base + p*32768 + w*4`. This assumes the PMEM format keeps the
  32 KB page grid inside 1 MB mbytes inside fixed-size files (A-1). If the
  format drops 32 KB page headers, positions become (file, byte offset) and
  the address is `base + offset`; nothing else in this design changes.
- **LSN** (bytes, Uint64, per part):
  `((logLap * noLogFiles + fileNo) * clogFileSize << 20) + p*32768 + w*4`.
  It is monotonic across laps (`logLap` grows when the head wraps,
  `43853`) [I].
- New state:
  - `LogPartRecord::m_pmem_persisted`: every byte below is persistent.
    Changed only under the part mutex.
  - `TcConnectionrec::m_redo_end_lsn`: end LSN of the operation's newest
    record that must be persistent (COMMIT, COMPLETE, or ABORT after
    COMMIT). 0 if none.
- The append end is derived from `currentLogfile`, `currentFilepage` and
  `ZCURR_PAGE_INDEX` of the current page, as today.

### 2.3 Write straight into the mapping, or build in DRAM and copy?

| | **Option 1:** `currentLogpage` points into PMEM | **Option 2:** DRAM pages, copy at persist points |
|---|---|---|
| Record writers | `LogPageRecordPtr` must become a raw PMEM pointer; ~52 uses of `ZCURR_PAGE_INDEX` [V by grep] and every `ptrCheckGuard(logPagePtr, …)` change | Unchanged |
| Fill index in page header | Updated in PMEM on every record, so the header line is flushed again and again | Stays in DRAM; masked when the header is copied (§2.5) |
| Stores to PMEM | Regular stores: a store miss reads the line from PMEM first (RFO). Optane read latency is about 170-300 ns [I] | Only ntstores of whole lines; no reads from PMEM |
| ADR barrier | `clwb` per line + `sfence`. On Cascade Lake `clwb` evicts the line [I], so the next append into the same line misses again | `sfence` only (ntstores bypass the caches) |
| eADR barrier | `sfence` only; cheap if the lines are cached (needs `prefetchw` ahead) | `sfence`, same as ADR |
| Copy cost | None | ~0.1 ns/byte from L1/L2, ~20-40 ns per operation [I] |
| Natural eviction | Dirty lines reach PMEM at random times; partial records can become persistent at any time (harmless with R-1/R-2, but harder to test) | Nothing reaches PMEM except through `redoPersist` |
| Power-loss testing | Needs cache-loss emulation | `kill -9` on emulated PMEM gives exactly the persisted state, except a torn copy (§12, Q9) |
| SR reading | Parse in place | Parse in place or `memcpy` into DRAM pages (recovery's choice) |

**Decision: Option 2 for the first iteration.** It keeps the record code,
avoids PMEM reads on the write path, and makes ADR and eADR the same code
(`ntstore + sfence`; this is what PMDK's `pmem_memcpy_persist` does [I]).
Option 1 with `prefetchw` may win on eADR hardware later; the barrier
primitive hides the choice.

### 2.4 The persist primitive

```
// Caller holds lock_log_part(part). Synchronous; no signal, no wait queue.
void Dblqh::redoPersist(Signal*, LogPartRecord *part)
{
  if (part->m_pmem_persisted == appendLsn(part)) return;   // nothing new
  redoPadToUnit(part);        // FILLER to the next W boundary (§4); may
                              // instead switch mbyte if no room is left
  redoCopyOut(part);          // ntstore whole units from m_pmem_persisted
                              // up to the append end: filled pages first,
                              // then the current page
  ndb_pmem_drain();           // sfence
  part->m_pmem_persisted = appendLsn(part);
}

void Dblqh::redoPersistOp(Signal *s, TcConnectionrec *op) // C and K points
{
  LogPartRecord *part = op->m_log_part_ptr_p;
  lock_log_part(part);
  if (op->m_redo_end_lsn > part->m_pmem_persisted) redoPersist(s, part);
  unlock_log_part(part);
}
```

- `redoCopyOut` walks the filled list (`firstFilledPage..lastFilledPage`,
  kept from today) and then the current page. Each page remembers how far
  it was copied. The first copy of a page writes its PMEM header (§2.5). A
  filled page is released right after its copy.
- **Every copy ends with `sfence` by the copying thread**, also the
  page-full copies below. A fence on one core does not drain another
  core's write-combining buffers [I], so a fence-less copy by LDM A
  followed by a barrier on LDM B could advance the persisted LSN over
  bytes that are still in A's buffers. Fencing every copy removes that
  case at a cost of one extra `sfence` per 32 KB.
- **End of record hook** `redoEndOfRecord(part)`, called by every writer
  when its record is complete (end of `writeAttrinfoLab`, `writeCommitLog`,
  `writeAbortLog`, `writeCompletedGciLog`, the new `writeCompleteLog`): it
  finishes the record checksum (R-1) and, if the filled list is not empty,
  copies and fences those pages and releases them. Pages are therefore
  never copied in the middle of a record, so the checksum may sit in the
  record header (R-3).
- `completedLogPage` in PMEM mode only links the page to the filled list
  (no LFO, no FSWRITEREQ). The `sync_flag` and `ZENFORCE_WRITE`/
  `ZLAST_WRITE_IN_FILE` arguments map to a `redoPersist` call by the caller
  (`writeNextLog`, §6).
- Staging need per part: the current page, up to three pages of one
  PREPARE record (`research_redo_log.md` §2.1), `logPageZero` of file 0.
  Eight pages (256 KB) are enough for writing [I]; SR may need more (R-6).

### 2.5 Page headers and checksums (interface with the format)

- `initLogpage` (`35577-35605`) writes the header in DRAM when a page
  starts. In PMEM mode the header must be final at that point (R-4): a
  persisted unit is never written again, and the header is in the first
  unit of the page.
- DRAM-only header words (`ZCURR_PAGE_INDEX`, `ZNEXT_PAGE`, `ZPREV_PAGE`,
  `ZPOS_IN_WRITING`, `ZPOS_IN_FREE_LIST`, the debug words 12-20 from
  `writeDbgInfoPageHeader` `46750-46760`) are zeroed in the PMEM copy, and
  the header checksum is computed over the copy. This keeps the DRAM page
  layout, and all code that uses it, unchanged.
- `calcPageCheckSum` (`46632-46639`) is not used in PMEM mode. Per-record
  checksums replace it (guidance item 2, format subtask).

### 2.6 What disappears and what stays (PMEM mode)

| Disappears | Today at |
|---|---|
| FSWRITEREQ for normal REDO writes; LFOs for them | `41075-41158`, `36209-36241` |
| FSWRITECONF handling for normal writes (`writeLogfileLab`, `lastWriteInFileLab`, `firstPageWriteLab`, `writePageZeroLab`) | `34686-34764`, `35069-35341` |
| Batching of 8 pages | `41057-41065` |
| `timeSup`, `startTimeSupervision`, `ZTIME_SUPERVISION` | `34944-35067`, `34055-34067`, `1545-1549` |
| `checkGcpCompleted`, FSSYNCREQ/FSSYNCCONF for GCP | `34141-34301` |
| `fileChangeState` machine, run-time `openNextLogfile`, P_FILE_CHANGE_PROBLEM (1220) | `43913-43960`, `35798-35884` |
| IO tracker and P_REDO_IO_PROBLEM (1234) | `5756-5768`, `41120`, `34915` |
| `OM_AUTOSYNC`, `ODirect`, `ODirectSyncFlag`, `OM_WRITE_BUFFER` for REDO | `35621-35639`, `35838-35853` |
| Large RedoBuffer; "buffer full" queueing; error 1221 | `947-1008`, `13383-13431`, `15311-15342` |

| Stays | Note |
|---|---|
| Record writers and their fast paths | Plus checksum and `redoEndOfRecord` |
| Positions (file, page, word), `logStart*`/`logStopPageNo` in operations | Uint16 fields still fit 1 GB files |
| Mbytes, NEXT_MBYTE, `remainingWordsInMbyte`, FD info per mbyte, page 0 per file | Guidance item 3 |
| File ring, lap, tail management, CUT_REDO_LOG_TAIL_REQ, `force_lcp`, P_TAIL_PROBLEM (410), head-meets-tail crash | Unchanged |
| Part mutex and shared parts | §5 |
| Commit reservation | Grows, §6.4 |
| Queue code | Unreachable in PMEM mode (§6.4), kept for file mode |
| NDBFS file creation and full init | §10 |

---

## 3. Persisting COMMIT and COMPLETE immediately

Rule: the barrier runs after the last record of the step is appended and
before the first externally visible effect of that step. A visible effect
is a signal that tells another replica or TC that the record exists, or a
local commit (TUP real commit, ACC lock release). Placement relative to
today's lines; plan subtask P3 moves the primary's local commit (invariant
L) and adds `writeCompleteLog`.

| # | Path | Barrier position | Inv. |
|---|---|---|---|
| 1 | Normal COMMIT, `commitReqLab` (`15196-15274`) | After `c_tup->execTUP_WRITELOG_REQ` returns (`15219-15227`) and before the branch at `15267` to `localCommitLab`/`commitReplyLab`: `redoPersistOp(op)`. TUP calls `execLQH_WRITELOG_REQ` once per operation on the row (`dbtup/DbtupCommit.cpp:247-276`) [V]; one barrier after the loop covers all of these COMMIT records | C |
| 2 | Sibling operation on the same row, state `LOG_COMMIT_WRITTEN_WAIT_SIGNAL` (`15259-15261`) | Same call before `15267`. Normally a no-op, because the sibling's barrier already covered this record | C |
| 3 | Queued commit, `handle_queued_log_write` (`909-938`) | After `writeCommitLog` (`912`), before `unlock_log_part` (`914`): `redoPersist(part)` with the lock already held; then `localCommitLab`/`commitReplyLab` (`921-928`). Unreachable in PMEM mode (§6.4), but kept correct | C |
| 4 | Dirty write, `doWritePrepareLog` (`13566-13584`) | PREPARE, COMMIT (`13577`) and, in durable mode, COMPLETE are appended back to back; one `redoPersist` before `unlock_log_part` (`13579`), so before `localCommitLab` (`13583`) | C, K |
| 5 | `AC_NR_COPY`, which commits at COMMIT (`15267-15271`) | Covered by #1 | C |
| 6 | COMMITREQ on an operation already COMMITTED (`14891-14912`) | None. The state COMMITTED is set only after the barrier (`commitReplyLab`, `15622`). Debug assertion | C |
| 7 | `execCOMPLETE`, state COMMITTED (`14988-15019`) | New `writeCompleteLog` plus `redoPersist` under one lock, before the three-way branch at `15004`: before `localCommitLab` (backup), `completeTransLastLab` (primary; P3 adds the local commit there) or `completeTransNotLastLab` | K |
| 8 | `execCOMPLETEREQ`, state COMMITTED (`15092-15099`) | Same, before the branch at `15120` | K |
| 9 | `execCOMPLETEREQ`, state `WAIT_TUP_COMMIT` (`15103-15114`) | None: the local commit already in progress was preceded by #7 or #8. The COMPLETE record is written once per operation (a flag on the operation) | K |
| 10 | ABORT after COMMIT (rule F, P3) | `writeAbortLog` plus `redoPersist` before the lock is released and before LQH_TRANSCONF/ABORTED | F |
| 11 | Normal abort of a prepared operation | None. A PREPARE without a COMMIT is never applied (plan C5) | – |

**Debug check** (plan §9, risk 1). In durable mode assert
`op->m_redo_end_lsn <= part->m_pmem_persisted` in `commitReplyLab`
(`15617`), before every COMMITCONF/COMPLETECONF send, in
`sendCommitLqh` (`6901`), `sendCompleteLqh` (`6955`), `sendCommittedTc`
(`7004`), `sendCompletedTc` (`7049`), and at the start of `localCommitLab`
(`15358`). The check catches a path that misses its barrier.

**Durable flag.** Barriers #1-#10 run only for operations of durable
transactions (GCI ≥ g, plan §2.2; the flag comes in COMMIT/COMMITREQ, P3/P5).
Others use the non-durable rules of §7.

---

## 4. The write unit W and the FILLER record

### 4.1 Two options

**A. Pad, then persist.** `redoPersist` first appends a FILLER record that
reaches the next W boundary, then copies and fences. The persisted LSN is
always W-aligned; the next record starts in a fresh unit; a unit is copied
to PMEM exactly once. Padding *after* the persist is pointless: the unit
would have to be flushed again anyway.

**B. Re-flush.** No filler. The next record is appended into the partly
persisted unit, and the next barrier copies that whole line again
(ntstores write whole lines), persisted bytes included, with the same
values.

Details for A:
- The filler must stay inside the mbyte and keep the `ZNEXT_LOG_SIZE`
  reserve. If it does not fit, `redoPersist` calls `changeMbyte` instead;
  NEXT_MBYTE then ends the mbyte (`43825-43826`).
- W divides 32 KB, so unit boundaries never cross pages; the 128-byte page
  header is part of the first unit of a page.
- If the format needs at least 2 words for a filler (type/length and a
  checksum), a 1-word gap is extended by one unit (A-2).
- The filler body is zeroed in DRAM before the copy, so PMEM content is
  deterministic (helps `redoLogReader`).
- `remainingWordsInMbyte` is reduced by the filler size.

### 4.2 The hardware question (H1)

**H1:** when a cache line that holds persisted bytes is written to PMEM
again with those bytes unchanged, a power failure during that write can
corrupt only the changed bytes.

- At the CPU level, aligned 8-byte stores are failure-atomic, and an
  unchanged 8-byte chunk is the same value whether the old or new write
  survives [I].
- Optane writes the media in 256-byte XPLines with read-modify-write in the
  DIMM; that buffer is power-fail protected [I].
- `research_pmem_hardware.md` decides. **This design does not depend on
  H1** with option A. Option B is correct only if H1 holds.

### 4.3 Cost of padding

Record sizes from the task: COMMIT ≈ 52 bytes, COMPLETE 12 bytes
(add 4 bytes each if the checksum is a separate word).

Each record persisted alone in a fresh unit:

| Record | W = 64 | W = 128 | W = 256 |
|---|---|---|---|
| COMMIT 52 B | 64 B (×1.23, +12) | 128 B (×2.46, +76) | 256 B (×4.92, +204) |
| COMPLETE 12 B | 64 B (×5.3, +52) | 128 B (×10.7, +116) | 256 B (×21.3, +244) |

One write operation, one client, PREPARE 200 B; the C barrier persists
PREPARE + COMMIT (252 B), the K barrier the COMPLETE:

| | raw | W = 64 | W = 128 | W = 256 |
|---|---|---|---|---|
| Bytes per operation per replica | 264 | 320 (+21%) | 384 (+45%) | 512 (+94%) |

Many transactions in flight: a barrier ends at a random offset, so the
expected waste is about (W−4)/2 per barrier, or about W per operation
(two barriers): +60, +124 or +252 bytes [I]. The numbers are close to the
single-client case.

Today's file format writes about 236 B for the same operation
(PREPARE 200 + COMMIT 36). Durable mode with W = 64 writes about 320 B
(+36%), of which COMPLETE, the larger COMMIT and checksums account for
28 B and the fillers for the rest.

### 4.4 Decision

- **Option A, W = 64 by default.** A compile-time constant
  (`ZPMEM_WRITE_UNIT_WORDS`) that allows 16, 32 or 64 words, so that 128
  and 256 can be measured on real hardware (P6).
- W = 256 would match the Optane media unit, but ntstores already write
  whole lines and the XPBuffer combines sequential lines [I]. Doubling the
  REDO volume costs log space (tail pressure, LCP frequency) and PMEM
  bandwidth for no clear gain.
- If `research_pmem_hardware.md` confirms H1, option B (no filler) is a
  switch in `redoPadToUnit`; the fillers then only appear where the
  format needs them.

---

## 5. Shared log parts

Several LDMs write one part under `m_log_part_mutex` when `ndbLogParts` is
not a multiple of the LDM count (§1.9).

- **Barrier inside the mutex.** `redoPersist` pads, copies and fences while
  holding the mutex. It therefore persists records appended by other LDMs
  too: the copy reads them from the shared DRAM pages, and `sfence` on the
  copying core drains its own ntstores, which are the only stores to PMEM
  in that range.
- **No half-written records from other LDMs.** A writer appends a whole
  record in one critical section (§1.1) [V]. While the barrier holds the
  mutex, no other LDM is in the middle of a record, and the copy stops at
  the append end, which is a record end.
- **The prefix property.** Every copy into PMEM is fenced by the same
  thread before the mutex is released (§2.4). So all bytes below
  `m_pmem_persisted` are persistent no matter which LDM copied them.
- **Torn copies.** Power can fail during a copy. Then the PMEM range beyond
  `m_pmem_persisted` holds a mix of new and stale lines. Per-record
  checksums bound to the record's position and lap make every such record
  invalid (R-1), and the log ends at the first invalid record (R-2). Since
  barriers are contiguous, nothing after that point was acknowledged.
- **No cross-LDM wake-ups.** The thread that needs persistence makes it
  itself, synchronously. FSWRITECONF to the owner, waiter lists and
  `send_handle_queued_log_write`-style signals (`research_redo_log.md`
  §7.7) are not needed.
- **Cost.** Other LDMs wait for one copy and one `sfence` (~0.1-0.3 µs [I])
  while the mutex is held. This adds to the existing mutex cost of these
  configurations.
- **Later.** Fence outside the mutex needs a per-part count of copies in
  flight, so that no thread advances the persisted LSN over another
  thread's unfenced copy. Not worth it before measurements.

---

## 6. Mbyte switch, file switch, GCP_SAVEREQ and REDO-full handling

### 6.1 Mbyte switch

`writeNextLog` keeps its logic. Its `completedLogPage(ZENFORCE_WRITE,
sync=true)` (`43866`) becomes "link page, then `redoPersist`". The copy
stops after the NEXT_MBYTE word; the rest of the mbyte is not copied
(readers skip it). The new mbyte's first page header is written in DRAM by
`initLogpage` (`43896`) and reaches PMEM with the first copy in that mbyte,
before any record of the mbyte. SR finds the last mbyte from these headers
(`research_system_restart.md` §5.1); the prefix property makes the header
persistent before anything after it. The persist per MB is kept in both
modes: it is cheap and bounds what a non-durable crash can lose.

### 6.2 File switch

Done synchronously inside `writeNextLog`, in this order, each step ended by
a barrier:

1. last records of the old file (`43845`: `redoPersist`);
2. page 0 (FD record) of the new file: `writeFileHeaderOpen` copies the
   32 KB page into the mapping and fences instead of `writeSinglePage`
   (`36145-36147`);
3. `ZPOS_FILE_NO` in page 0 of file 0: one aligned ntstore of that word
   plus `sfence` (today `35197-35201`, `35303-35307`).

`fileChangeState` stays `NOT_ONGOING`; `openNextLogfile` is not called.
Step 3 completes before the first record of the new file is appended, so a
record in the new file is never persistent while page 0 of file 0 still
names the old file. Today that gating is done asynchronously by
`writePageZeroLab` (`35313-35341`). Step 3 is an in-place update of
persisted data, so it must be failure-atomic (R-5).

### 6.3 GCP_SAVEREQ

`start_synch_gcp` (`33957-33997`): for each part, under the lock,
`writeCompletedGciLog` (`33988`) then `redoPersist`. When no part is ACTIVE,
send GCP_SAVECONF at once (the code of `34292-34300`) and set
`ccurrentGcprec = RNIL`. `initGcpRecLab`, `timeSup`, `checkGcpCompleted` and
FSSYNCREQ are not used. If a part is ACTIVE (not reachable in PMEM mode,
§6.4), `logNextStart` writes the record as today, and `ZINIT_GCP_REC` leads
to an `initGcpRecLab` that only runs `redoPersist` per part and replies.
The restart branches of `execGCP_SAVEREQ` (`33925-33952`, local sysfile)
are unchanged.

In durable mode every COMMIT ≤ g is already persistent; the barrier then
only covers the COMPLETED_GCI record, PREPAREs, and non-durable records.
GCP save latency on a node drops from a few ms (two IO waits per part) to
µs [I].

### 6.4 REDO-full handling

| Condition | PMEM mode |
|---|---|
| Buffer full (`ZMIN_LOG_PAGES_OPERATION`, 1221) | Gone. Pages are copied and released at the end of the record that fills them; at most a few staging pages are in use |
| P_REDO_IO_PROBLEM (1234) | Gone. No IO |
| P_FILE_CHANGE_PROBLEM (1220) | Gone. All files mapped, switch is synchronous |
| P_TAIL_PROBLEM (410) | Unchanged; prepares abort, never queue (`13406-13416`) [V] |
| Head meets tail | Unchanged crash (`43927-43951`) |

So in PMEM mode a part never becomes ACTIVE: prepares only queue on a
problem other than P_TAIL_PROBLEM or when the part is not IDLE, and commits
only queue on a full buffer or a non-empty complete queue (§1.8) [V/I]. The
queue code stays for file mode and error inserts 5083/5032.

**Commit reservation.** `increment_committed_mbytes` must reserve, per
logged prepare, the COMMIT record, the larger of COMPLETE and ABORT, and two
worst-case fillers (W−4 bytes each). With W = 64 and a 14-word COMMIT that is
about 14 + 4 + 2·15 = 48 words instead of 10; with W = 256 about 144 words.

**Log volume.** Durable mode writes about 36% more per small operation at
W = 64 (§4.3). `NoOfFragmentLogFiles`/`FragmentLogFileSize` should be sized
for it; P_TAIL_PROBLEM is reached sooner otherwise.

---

## 7. Memory-mapped REDO without durable commits

Two choices:

| | Persist at GCP save, mbyte switch, file switch, page full | Persist per record |
|---|---|---|
| Semantics | Same as today: durable up to the last GCP save | Stronger than needed: without COMPLETE records and phase 2 the tail is invalidated at SR anyway |
| Cost | One barrier per 32 KB page plus one per GCP and per MB | Two barriers per operation plus fillers |

**Decision: persist at GCP save, mbyte switch, file switch and page full.**
Page-full copies happen anyway (staging is small), and each ends with its
fence (§2.4), so between GCP saves at most one partial page per part is
not persistent.

Online activation (plan §2.2): the format is the same in both modes;
whether barriers #1-#10 run is decided per operation from the durable flag.
No switch of the writer is needed at GCI g.

---

## 8. Later: an adaptive scheme (outline)

**Idea.** Do not persist at each C and K point. Park the operation, and do
one barrier per dirty log part at the end of the LDM's execution round,
before the packed signals leave.

- The scheduler calls every block's `execSEND_PACKED` after
  `run_job_buffers` in each loop (`src/kernel/vm/mt.cpp:7883-7892`, also
  `8260-8269`) and from `handle_scheduling_decisions`
  (`mt.cpp:6703-6719`) [V]. `Dblqh::execSEND_PACKED` (`DblqhMain.cpp:6511-6571`)
  sends the LQH and TC packed containers.
- COMMIT, COMPLETE, COMMITTED and COMPLETED go through packed containers of
  at most 25 words, flushed early when full (`sendCommitLqh` `6940-6946`,
  `sendCompleteLqh` `6986-6992`, `sendCommittedTc` `7030-7036`,
  `sendCompletedTc` `7075-7081`) [V].

**Steps.**
1. At a C or K point: append the record, set the part's bit in a per-LDM
   `m_redo_dirty_parts` mask, put the operation on a per-LDM list with a
   new state (`WAIT_REDO_PERSIST`), and return without sending or local
   commit.
2. At the start of `execSEND_PACKED`: for each dirty part, lock,
   `redoPersist`, unlock. Then resume the parked operations
   (`commitReplyLab`, `localCommitLab`, `completeTrans*Lab`); their signals
   go into the containers; then the existing send loop runs. Resume a
   bounded number per call and continue with CONTINUEB.
3. Any other send of a dependent signal (COMMITCONF, COMPLETECONF, the
   unpacked paths, takeover answers) first checks `m_redo_end_lsn` and
   persists synchronously if needed.
4. A small first step: one barrier per `execPACKED_SIGNAL`
   (`DblqhMain.cpp:6329`, `ZCOMMIT`/`ZCOMPLETE` at `6362-6375`), which
   holds up to 8 COMPLETEs. Plan §3.3 mentions this.

**Saves.** From two barriers per operation to about one per dirty part per
round. With 50 operations per round that is 100 → 1-2 barriers, and the
filler waste drops by the same factor.

**Costs.**
- Each COMMITTED, COMPLETED and forwarded COMMIT/COMPLETE waits for the end
  of the round. Under load a round is about 10-100 µs [I]; at low load
  rounds are short and the delay is small.
- Lock hold on every replica grows by that delay (K comes before
  visibility), which lowers hot-row throughput (plan §3.2).
- New states must be handled by takeover (`abortStateHandlerLab`), node
  failure and ndbinfo.
- Adaptive rule: persist at once when the round has only one parked
  operation, defer otherwise.

---

## 9. Cost per operation on the commit path

Per write operation per replica, durable mode, W = 64, option 2. Figures are
published or estimated, not measured here; all [I], except the checksums.

| Step | Today (file REDO) | PMEM, durable |
|---|---|---|
| Append PREPARE + COMMIT in DRAM | ~50-100 ns | same, plus COMPLETE ~10 ns |
| Checksums (XXH3, E4; measured, `step1_phases.md` Timings) | none (constant 37) | ~37 ns for PREPARE (124 B) + COMMIT + COMPLETE on x86-64 with AVX2; ~53 ns with a 1000-byte PREPARE |
| Fillers | – | ~5 ns |
| ntstore copy of ~320 B | – (pwrite in an NDBFS thread) | ~20-40 ns |
| `sfence` after ntstores, ×2 (C and K) | – | Optane ~100-200 ns each, 200-400 ns total. DRAM-backed persistent memory (NVDIMM-N, CXL with backup) ~50-100 ns each |
| FSWRITEREQ share (1 per 256 KB) | small | – |
| **LDM time added** | | **~0.3-0.5 µs** |

Context:
- Optane DC PMM (gen 1): ntstore + `sfence` ~90-100 ns per line, random
  read ~300 ns, write bandwidth ~2 GB/s per DIMM and ~12 GB/s for six
  interleaved DIMMs (Izraelevitz et al., 2019; Yang et al., FAST 2020) [I].
- An LDM spends roughly 1-5 µs of CPU on a key write [I], so the persists
  add about 10-30%.
- Latency to the application is dominated by the extra message round of
  plan §3.2 (tens of µs), not by the persists.
- Bandwidth: ~320 B per operation per replica. At 1 M write operations per
  second per node that is ~320 MB/s, far below PMEM bandwidth [I]. Near
  saturation the `sfence` waits grow to µs.
- For comparison, today's file sync costs 20 µs-5 ms (`research_redo_log.md`
  §4.1).

---

## 10. Configuration and start-up checks

### 10.1 Variables

| Purpose | Suggested names | Type, default | Where |
|---|---|---|---|
| REDO on PMEM (conclusion 2) | **`RedoLogMode`** = `file` \| `pmem`; or `MemoryMappedRedoLog` (bool); or `RedoLogOnPersistentMemory` | string, `file`; `CI_RESTART_INITIAL` (switching needs an initial node restart, plan §2.1) | `ConfigInfo.cpp` beside `NoOfFragmentLogParts`…`InitFragmentLogFiles` (`1134-1152`); a new `CFG_DB_*` id in `include/mgmapi/mgmapi_config_parameters.h` (near `CFG_DB_INIT_REDO`, line 161); read in `Dblqh::execREAD_CONFIG` beside `2766-2801` |
| Directory on the DAX file system | **`FileSystemPathRedoLog`** (default: `FileSystemPath`) | string | `ConfigInfo.cpp` beside `FileSystemPathDD` (`1484-1490`); a new `BP_REDO` in `FsOpenReq::BasePathSpec` (`include/kernel/signaldata/FsOpenReq.hpp:161-167`) and in the parameter table of `Ndbfs.cpp:268-300`. The node-failure file (plan §5.4) uses the same directory |
| Write unit | `PmemWriteUnit` (64/128/256) | first a compile-time constant; a hidden config later | – |
| Durable commits | owned by P5 | | |

A string enum leaves room for a non-DAX `mmap` mode later (Q7).

REDO files today live under `FileSystemPath` with no separate REDO
directory: the base paths are `BP_FS`, `BP_BACKUP`, `BP_DD_DF` and `BP_DD_UF`
only (`FsOpenReq.hpp:161-167`) [V]. Putting all of `FileSystemPath` on PMEM
would waste PMEM on LCP files, hence the new path.

### 10.2 Checks

Configuration time (`checkDbConstraints`, `ConfigInfo.cpp:4112..`):
- durable commits on ⇒ `RedoLogMode=pmem` (D8);
- `pmem` ⇒ `EncryptedFileSystem=0` (XTS encrypts whole 32 KB pages in
  NDBFS, which a mapping bypasses), `Diskless=0`;
- `pmem` ⇒ `InitFragmentLogFiles=full`, or force it with a warning. Sparse
  files on DAX allocate blocks on the first write fault, and with
  `MAP_SYNC` that fault commits file-system metadata synchronously, a
  stall of tens of µs or more in the LDM [I].

Data-node start:
- `MAP_SYNC` refused (`EOPNOTSUPP`) ⇒ a new FSOPENREF error ⇒ DBLQH calls
  `progError(NDBD_EXIT_INVALID_CONFIG)` with "REDO log file … is not on a
  DAX file system". In the first iteration this applies with durable
  commits on or off (Q7).
- Platform: Linux x86-64 only in the first iteration; ntstores (SSE2) are
  always there; `clwb`/`clflushopt` (CPUID) are used only for in-place
  metadata if not done with ntstores.
- Persistence domain (`persistence_domain` of the region in sysfs:
  `memory_controller` = ADR, `cpu_cache` = eADR) is logged. With ntstores
  the barrier is `sfence` in both, so the domain changes no code in this
  design; a region that reports neither is refused when durable commits are
  on, unless an override is set (hardware subtask).
- The files must carry the PMEM format version (mbyte header / page 0);
  otherwise refuse and ask for an initial node restart (plan §2.1).
- `ODirect`, `ODirectSyncFlag` and `RedoBuffer` are ignored for REDO
  writes (info message). `Configuration::get_and_set_redo_buffer`
  (`src/kernel/vm/Configuration.cpp:1005-1024`) sets the staging size plus
  what SR needs (R-6).
- `MaxNoOfOpenFiles` (`ConfigInfo.cpp:1158-1162`) must allow parts × files
  open REDO files, since all stay open.
- Initial start writes the whole REDO through NDBFS (`OM_INIT` path, §1.10):
  for example 64 GB at 2-10 GB/s takes about 6-30 s [I].

---

## 11. Assumptions and requirements on the other subtasks

| Id | To | Statement |
|---|---|---|
| A-1 | format | The PMEM format keeps files of 1 MB mbytes; if it keeps 32 KB pages, a page header starts each page |
| A-2 | format | A FILLER record can fill any gap of ≥ 2 words; the write path extends a 1-word gap by one unit |
| H1 | hardware | §4.2. Not required with W padding; required for option B |
| R-1 | format | Every record's checksum covers its own position and lap (E4: bound to lap and position through S). Stale PMEM from an earlier lap can hold a record with a valid plain checksum at exactly the offset where the log now ends |
| R-2 | recovery | The log of a part ends at the first record that fails validation. Never skip a bad record: the barrier is contiguous, so nothing after the first bad record was acknowledged |
| R-3 | format | The checksum may sit in the header or in a trailer; the writer finishes it before any byte of the record is copied (§2.4) |
| R-4 | format | A page header (and mbyte header) is final when the page starts: no fill index, no write-time fields, checksum computed at page start |
| R-5 | format, recovery | Every in-place update of persisted data is failure-atomic: one aligned 8-byte store, or two alternating slots with sequence numbers. This covers `ZPOS_FILE_NO` in page 0 of file 0 (§6.2) and the rewrite of COMMIT records as `ZINVALID_COMMIT_TYPE` in SR phase 2 step C (plan §5.2): if the type word and the checksum are separate words, a torn rewrite makes the record invalid and, by R-2, truncates the log |
| R-6 | recovery | Say whether SR reads through the mapping or keeps FSREADREQ into DRAM pages, and how many RedoBuffer pages SR needs per part |
| R-7 | recovery | Writing resumes after an SR at a W boundary (or a new mbyte), so that the first barrier never rewrites a persisted unit |
| R-8 | recovery | Beyond the persisted end, at most the range of one copy (a few pages) can hold new data, possibly torn; nothing else differs from the previous lap. This bounds the invalidation in SR phase 4 (`research_system_restart.md` §5.4), which today searches up to 1 MB further |

---

## 12. Open questions

1. **H1** (§4.2): if confirmed, is option B (no filler) worth the extra
   risk for about W bytes per operation?
2. **W on real hardware:** 64 against 256 on Optane, and on CXL persistent
   memory. Measure bandwidth, `sfence` latency and log volume (P6).
3. **Pre-faulting:** does `MAP_POPULATE` on a `MAP_SYNC` DAX mapping fault
   pages for write, so that no fault happens at run time? Are 2 MB (PMD)
   mappings used with fully allocated files? Verify with the page-fault
   counter.
4. **NUMA:** a part's files should sit on the PMEM of the socket that runs
   its LDM. Remote PMEM writes are much slower [I]. Per-part paths?
5. **Writers per DIMM:** Optane bandwidth falls with many concurrent
   writers per DIMM [I]. Does interleaving across DIMMs hide this with
   8-32 LDMs?
6. **Hardware availability:** Optane is discontinued [I]. Which persistent
   memory does production use? The design needs only ntstore + `sfence` to
   be a persist.
7. **Non-DAX memory mapping** for durable commits off (page cache plus
   `msync` off the LDM thread): needed, or is `memmap=` emulation enough
   for everyone without PMEM?
8. **Shared parts:** measure the mutex hold during `redoPersist`; decide
   whether the fence-outside-the-mutex variant (§5) is needed.
9. **Torn copy emulation:** an ERROR_INSERT that copies a random subset of
   lines of the last `redoCopyOut` and then crashes. Together with
   `kill -9` on emulated PMEM this covers power loss for option 2.
10. **AC_NR_COPY / AC_IGNORED** operations at COMPLETE: is a COMPLETE
    record needed (P3)?
11. **ndbinfo:** add barriers, bytes copied, filler bytes and a persist
    latency histogram per part, next to the `logspaces` and `logbuffers`
    tables that DBLQH serves today (`DblqhMain.cpp:45639`, `45679`).

---

## 13. Recommendations

1. Build records in DRAM pages as today and copy to the DAX mapping with
   ntstores at persist points; end every copy with `sfence` by the copying
   thread, under the part mutex (§2.3, §2.4).
2. One primitive `redoPersist(part)`; per-operation `m_redo_end_lsn` and
   per-part `m_pmem_persisted` (§2.2).
3. Place barriers as in the table of §3 and add the debug assertion at every
   dependent send and at `localCommitLab`.
4. Pad, then persist, with a FILLER record and W = 64; make W a
   compile-time constant to test 128 and 256 (§4.4).
5. Let NDBFS open and map files with a new `OM_MAP_SYNC` flag and return
   the address in FSOPENCONF; map every file of a part once at start; add
   `ndb_pmem` to portlib (§2.1).
6. Make the file switch synchronous: old file, new page 0, file 0 page 0
   word, each with a barrier (§6.2).
7. Reduce GCP_SAVEREQ to COMPLETED_GCI + `redoPersist` per part and an
   immediate GCP_SAVECONF (§6.3).
8. Without durable commits, persist at GCP save, mbyte switch, file switch
   and page full (§7).
9. In PMEM mode bypass LFOs, FSWRITEREQ, `timeSup`, FSSYNCREQ, the
   file-change state machine and the IO-problem states; shrink the
   RedoBuffer (§2.6).
10. Grow the commit reservation to COMMIT + max(COMPLETE, ABORT) + two
    fillers (§6.4).
11. Add `RedoLogMode` and `FileSystemPathRedoLog`, with the checks of §10.
12. After the first iteration works, try one barrier per `execPACKED_SIGNAL`,
    then one per round in `execSEND_PACKED` (§8).
13. Hand R-1 to R-8 to the format and recovery subtasks; R-1, R-2 and R-5
    are needed for correctness, not only for speed.
