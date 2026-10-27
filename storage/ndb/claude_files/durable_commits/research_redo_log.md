# RONDB-1150 durable commits: REDO log write path, record formats, flush/sync

Scope: the DBLQH REDO log write path, on-disk record formats, and NDBFS
flush/sync mechanics, as input to planning "durable commits" (for READ_BACKUP=1
tables the commit is durable on disk before the API is told it committed).
Commit-protocol/locks, the restart/REDO-replay path and micro-GCP are covered
by other research notes.

Unless prefixed otherwise, paths are relative to
`storage/ndb/src/kernel/blocks/`. `DblqhMain.cpp` = `dblqh/DblqhMain.cpp`,
`Dblqh.hpp` = `dblqh/Dblqh.hpp`.

Tags: **[V]** = verified by reading the code at the cited lines.
**[I]** = inferred (from comments, naming or reasoning). Not verified by running anything.

---

## 0. Summary

* **Layout.** Each data node has `NoOfFragmentLogParts` log parts (4, 6, 8, 10, 12,
  16, 20, 24 or 32; the default is 4). Log part `p` is owned by LDM worker
  `p % numLDM`. A fragment maps to log part `(lqhInstanceKey-1) % ndbLogParts`.
  A log part is a ring of `NoOfFragmentLogFiles` files (default 16). Each file is
  `FragmentLogFileSize` (the ConfigInfo default is 1G in this tree). A file is
  divided into 1 MB "mbytes", each of 32 pages, and each page is 32 KB (8192
  words) with a 32-word header. A position is `(lap, fileNo, pageNo, wordIdx)`.
  No linear LSN exists today.
* **Formats.** PREPARE (8-word header + key + attrinfo) has **no transid, no
  table/frag, no GCI and no TC node**. COMMIT (9 words) has table, schemaVersion,
  frag, a pointer to the prepare, and **`gci_hi` only**. It has **no transid
  and no `gci_lo`**. ABORT (3 words) is the only record with a transid. COMPLETED_GCI
  is 2 words. **No record identifies a transaction across fragments, log parts
  or nodes.** Restart consistency is all-or-nothing per GCP (`gci_hi`).
* **When records are written.** PREPARE is written at LQHKEYREQ, after
  ACC/TUP, on every replica. COMMIT is written at the **COMMIT** phase
  (`commitReqLab` → `TUP_WRITELOG_REQ` → `LQH_WRITELOG_REQ`) on **every replica**,
  primary and backups alike. Nothing is written at COMPLETE.
* **Write path.** Records are copied into the in-memory page of the current
  file. When a page fills, it is linked onto the file's "filled" list. When 8
  pages (256 KB) are pending, one FSWRITEREQ is sent. Partially filled pages are
  written only at (a) a GCP_SAVEREQ (`timeSup` writes a *copy* of the current page
  and keeps filling the original), (b) an mbyte switch, or (c) a file switch.
  **There is no per-operation or per-transaction force path today.**
* **Sync.** A sync happens: on every mbyte switch (sync flag on the write); on
  the last write in a file and the file-change metadata writes; implicitly in
  NDBFS every >1 MB written (`OM_AUTOSYNC`); and per GCP through an explicit
  FSSYNCREQ for each log part. NDBFS uses `fsync()`, not `fdatasync()`. Each open
  REDO file is bound to one dedicated NDBFS IO thread with a FIFO queue, so
  writes and syncs on one file are strictly ordered.
* **GCP flush.** On GCP_SAVEREQ(g), LQH writes COMPLETED_GCI(g) in each of its
  log parts. It records the in-memory position per part, forces the partial page
  to disk, and waits until FSWRITECONF covers that position in *all* of its parts.
  It then sends FSSYNCREQ for each part. When all FSSYNCCONFs have arrived it
  replies GCP_SAVECONF.
* **Hook.** The GCP machinery is already a "wait until position P is written,
  then sync" mechanism, but it is single-shot and per LQH instance. A durable
  commit needs:
  1. a per-log-part monotonic LSN;
  2. `durable_lsn`, advanced only by *synced* write completions, with the same
     file-change gating as `checkGcpCompleted`;
  3. a waiter queue ordered by LSN;
  4. a "force current page with sync" primitive (refactored from `timeSup`);
  5. a leader/follower group commit: at most one outstanding forced sync per
     log part, and when it completes, wake all covered waiters and immediately
     re-force if more waiters exist.

  The force should be requested when the COMMIT record is written. The wait
  should be at COMPLETE (or before COMPLETED is sent), so the sync overlaps the
  COMMIT→COMMITTED→COMPLETE round trip.
* **Format and restart implications (inputs for other agents).** Making
  commits beyond the last GCP survive requires either epoch granularity
  (`gci_lo` in commit records plus an "epoch complete" marker per log part) or
  transaction granularity (transid plus participant information). The current
  COMMIT record supports neither. Release builds have **no page checksum**
  (constant 37) and **do not zero recycled log pages**. Reading past the last
  COMPLETED_GCI record therefore needs a reliable end-of-valid-data rule.

---

## 1. REDO layout in RonDB

### 1.1 Log parts and the LDM mapping

| Item | Value / rule | Where |
|---|---|---|
| Number of log parts | `globalData.ndbLogParts` = `NoOfFragmentLogParts`. The default `NDB_DEFAULT_LOG_PARTS`=4. The max is 32. Allowed values are 4, 6, 8, 10, 12, 16, 20, 24 and 32 **[V]** | `ndbd.cpp:285-291`, `include/kernel/ndb_limits.h:387,391`, `DblqhMain.cpp:2684-2697` |
| Owner of log part `lpno` | LDM worker `lpno % lqhWorkers` (instance = worker+1). An LDM can own 0..n parts **[V]** | `dblqh/DblqhCommon.cpp` (`NdbLogPartInfo` ctor), `DblqhInit.cpp:154-155` |
| Fragment → log part | `fragptr.p->lqhInstanceKey = getInstanceKey(tab,frag)` (== `logPartId+1`). `get_log_part_record(instanceKey)`: part = `(instanceKey-1) % ndbLogParts`, owning LDM = `part % numLDM`, local index = `part / numLDM` **[V]** | `DblqhMain.cpp:3674-3678`, `2964-2977` |
| Operation → log part | `regTcPtr->m_log_part_ptr_p = logPart` (the fragment's part) **[V]** | `DblqhMain.cpp:10672`, `39498` |
| Cross-LDM access | If `ndbLogParts` is not a multiple of `numLDM` (and numLDM > 2), several LDMs write the same part under `m_log_part_mutex` (`lock_log_part`). Otherwise there is no mutex **[V]** | `DblqhMain.cpp:13305-13368`, `Dblqh.hpp:6636-6648` |
| Query threads (Dbqlqh) | Own no log parts (`clogPartFileSize=0`, no LFO/log pages) **[V]** | `DblqhInit.cpp:142-148`, `DblqhMain.cpp:2749-2753` |
| GCP record | **One** `GcpRecord` per LQH instance (`ZGCPREC_FILE_SIZE 1`). It holds per-part arrays indexed by the *local* part index **[V]** | `Dblqh.hpp:4695`, `1508-1550` |

FSWRITEREQ can be issued by any LDM that holds the log-part lock. The
`userReference` is always `logPartPtrP->myRef`, so FSWRITECONF/FSOPENCONF
always return to the **owning** LDM **[V]** (`DblqhMain.cpp:41105`,
`36232`, comment at `34868-34876`).

### 1.2 Files, mbytes, pages

| Item | Value | Where |
|---|---|---|
| Files per part | `cnoLogFiles` = `NoOfFragmentLogFiles` (ConfigInfo default 16, min 3) **[V]** | `DblqhMain.cpp:2699-2702`, `common/mgmcommon/ConfigInfo.cpp:1140-1144` |
| File size | `clogFileSize` MB = `FragmentLogFileSize` (ConfigInfo default "1G", min 4M, max 1G; the code default before config is 16) **[V]** | `ConfigInfo.cpp:1146-1148`, `DblqhMain.cpp:2817-2821`, `DblqhInit.cpp:186` |
| Mbyte | 1 MB = `ZPAGES_IN_MBYTE`=32 pages. **No record spans an mbyte boundary** (`checkNewMbyte` and the `ZNEXT_LOG_SIZE` reserve) **[V]** | `Dblqh.hpp:179`, `DblqhMain.cpp:14172-14214` |
| Page | `ZPAGE_SIZE` = 8192 words = **32 KB** (`logPageWord[8192]`). `ZPAGE_HEADER_SIZE` = 32 words. Old comments saying "8 kbyte" or a "12-word header" are stale **[V]** | `Dblqh.hpp:177-180`, `2780` |
| Usable words per mbyte | `(8192-32)*32`; the last mbyte of a file has one page less **[V]** | `DblqhMain.cpp:43815-43834` |
| Page 0 of each file | File descriptor (FD) page. In file 0, page 0 also records "last file in use" (`ZPOS_FILE_NO`) and is rewritten at every file change **[V]** | `DblqhMain.cpp:36073-36170`, `35130-35204` |
| Per-mbyte metadata (in memory, also written into FD pages) | `logMaxGciCompleted[mb]`, `logMaxGciStarted[mb]`, `logLastPrepRef[mb]` (oldest live prepare as `fileNo<<16 | mbyte`), set in `writeFileDescriptor` at each mbyte start **[V]** | `Dblqh.hpp:2371-2388`, `DblqhMain.cpp:36019-36066` |

### 1.3 In-memory log buffer ("RedoBuffer")

* Each log part has its own array of 32 KB `LogPageRecord`s, allocated from
  `RG_FILE_BUFFERS`. Its size is `globalData.theRedoBuffer` **per log part**,
  rounded to half-MB multiples. **[V]** (`DblqhMain.cpp:2717-2733`,
  `DblqhInit.cpp:321-360`)
* With `RedoBuffer=0` (automatic), the size per part is
  `numLDM*32MB/numLogParts`, capped at 64 MB per part (the comment says "min",
  but the code uses `MIN`, so it is a cap) **[V]**
  (`vm/Configuration.cpp:1006-1023`). The other automatic-memory path defaults
  to 16 MB (`vm/Configuration.cpp:1320-1327`) **[V]**.
* There is a free list and `noOfFreeLogPages` per part. `count_free_log_pages()`
  subtracts space "booked" by queued cross-LDM writes. When fewer than
  `ZMIN_LOG_PAGES_OPERATION`(10) pages are free, the operation is queued, or
  aborted with error 1221 (`ZTEMPORARY_REDO_LOG_FAILURE`) when
  QueueOnRedoProblem is off **[V]** (`DblqhMain.cpp:947-1008`, `13376-13457`).
* Released pages are **not** zeroed in release builds. Only VM_TRACE builds
  `memset` them **[V]** (`DblqhMain.cpp:35983-36011`).

### 1.4 What a position ("LSN") looks like today

* Positions are `(fileNo, pageNo-in-file, wordIndex)` plus the part's `logLap`,
  which is incremented when the head wraps to file 0 (`DblqhMain.cpp:43846-43854`) **[V]**.
* An operation remembers where its prepare record is:
  `logStartFileNo / logStartPageNo / logStartPageIndex / logStopPageNo`.
  All four are **Uint16** (`Dblqh.hpp:3259-3262`) **[V]**. The GCP record
  stores `gcpFilePtr` (LogFileRecord i-value), `gcpPageNo` and `gcpWordNo`, also
  Uint16 (`Dblqh.hpp:1517-1526`).
* `m_total_written_words` (Uint64 per part) counts logical record words
  (prepare, commit, abort, completed GCI). It does **not** count headers or
  skipped space, so it is *not* a positional LSN **[V]**
  (`DblqhMain.cpp:14232`, `43552`, `43592`, `43660`).
* Positions are compared only within one file (`checkGcpCompleted` requires
  `gcpFilePtr == logFilePtr.i`) **[V]** (`DblqhMain.cpp:34163-34190`).
* Proposed linear LSN **[I]**:
  `lsn = fileBaseLsn + pageNo*8192 + wordIdx`, where `fileBaseLsn` increases by
  `clogFileSize*32*8192` each time the head enters a new file. This is
  monotonic across laps. A 1 GB file is 32768 pages, which still fits the
  Uint16 page fields.

### 1.5 Page header (32 words)

| Word | Name | Content |
|---|---|---|
| 0 | `ZPOS_CHECKSUM` | **Constant 37 in release builds**. It is computed only under `VM_TRACE` (`DblqhMain.cpp:46632-46639`), and the check at read time is commented out (`40838-40839`) **[V]** |
| 1 | `ZPOS_LOG_LAP` | lap of the part when the page was initialised. Used to find the log end at restart |
| 2 | `ZPOS_MAX_GCI_COMPLETED` | `logPartNewestCompletedGCI` at page init |
| 3 | `ZPOS_MAX_GCI_STARTED` | `cnewestGci` at page init |
| 4 / 5 | `ZNEXT_PAGE` / `ZPREV_PAGE` | in-memory link only |
| 6 | `ZPOS_VERSION` | NDB_VERSION |
| 7 | `ZPOS_NO_LOG_FILES` | |
| 8 | `ZCURR_PAGE_INDEX` | fill index. On disk it is the end of valid data for partial writes and 8192 for full pages |
| 10 | `ZLAST_LOG_PREP_REF` | oldest live prepare `fileNo<<16 | mbyte` |
| 11 | `ZPOS_DIRTY` | used when invalidating commits during SR |
| 12-20 | debug, but always written at write time | log timer, page i, `__LINE__` of writer, page no, file no, word written, in-writing flag, prev page no, in-free-list (`writeDbgInfoPageHeader`, `DblqhMain.cpp:46750-46760`) |
| 21 | `ZPOS_NO_LOG_PARTS` | |
| 22-31 | zero | (`initLogpage` memsets the header, `35577-35604`) |

Sources: `Dblqh.hpp:181-212`, `DblqhMain.cpp:35577-35604` **[V]**.

---

## 2. Record formats (exact, from the writer code)

The type codes are in `Dblqh.hpp:253-262`. **All `ZPOS_*` position defines for
prepare/commit/abort in `Dblqh.hpp:265-307` are dead code.** None is
referenced in `DblqhMain.cpp`. The `LogPageRecord` comment block
(`Dblqh.hpp:2640-2775`) is partly stale: for example, it lists a transid in
COMMIT and a schema version in PREPARE, but neither is written **[V]**.

### 2.1 PREPARE (`ZPREP_OP_TYPE` = 1), written by `writeLogHeader` + `writeKey` + `writeAttrinfoLab`

`DblqhMain.cpp:14221-14304` **[V]**

| Word | Field |
|---|---|
| 0 | type = 1 |
| 1 | total length = 8 + aiLen + keyLen |
| 2 | hashValue |
| 3 | operation (ZUPDATE/ZINSERT/ZDELETE/ZWRITE..., incl. RonDB `ZINSERT_TTL`, replayed as ZINSERT, `43029-43046`) |
| 4 | aiLen (`currTupAiLen` = TUP's logged attrinfo length, `13191-13192`) |
| 5 | keyLen |
| 6 | rowid.m_page_no |
| 7 | rowid.m_page_idx |
| 8.. | key words, then attrinfo words |

* There is **no transid, table id, fragment id, schema version, GCI or TC node**.
  Table, fragment and schema come from the COMMIT record that points back at the
  prepare.
* The record can span pages (at most 3) but never an mbyte boundary.
* Written in `rwConcludedLab` → `writePrepareLog` (`13232-13293`, `13376-13457`),
  i.e. during LQHKEYREQ execution after ACC/TUP. This happens on each replica
  (each LQH in the chain runs its own LQHKEYREQ) **[V]**. Reads are not logged.
  A fragment with `logFlag==FALSE` (during NR copy) does not log.
* The operation is linked into the part's `firstLogTcrec/lastLogTcrec` list of
  "prepared but not committed/aborted" operations (`13509-13524`). This list
  drives the `ZLAST_LOG_PREP_REF` / tail calculation.
* Commit-space reservation: `increment_committed_mbytes` adds
  `ZCOMMIT_LOG_SIZE+1` words per logged prepare, so a COMMIT/ABORT can always be
  written later (`13477`, `47881-47909`) **[V]**.

### 2.2 COMMIT (`ZCOMMIT_TYPE` = 2, `ZCOMMIT_LOG_SIZE` = 9), written by `writeCommitLog`

`DblqhMain.cpp:43566-43621` **[V]**

| Word | Field |
|---|---|
| 0 | type = 2 |
| 1 | tableId |
| 2 | schemaVersion |
| 3 | fragId |
| 4 | prepare fileNo |
| 5 | prepare startPageNo |
| 6 | prepare startPageIndex |
| 7 | prepare stopPageNo |
| 8 | **gci_hi only** |

* `gci_lo` is **not** stored. On replay, `readCommitLog` sets `gci_lo=0` and
  *synthesises* a fake transid (`42763-42810`) **[V]**.
* Written at the **COMMIT phase on every replica**. `execCOMMIT` →
  `commitReqLab` (`15196-15274`) → `Dbtup::execTUP_WRITELOG_REQ`
  (`dbtup/DbtupCommit.cpp:247-276`, which loops all ops on the same row) →
  `Dblqh::execLQH_WRITELOG_REQ` (`DblqhMain.cpp:15276-15360`). Only after
  that does the primary (`seqNoReplica==0`) commit locally, or a backup forward
  COMMIT down the chain (`commitReplyLab`, `15617-15645`) **[V]**.
* If the log part has queued complete-records, or no free pages, the commit is
  queued (`LOG_COMMIT_QUEUED[_WAIT_SIGNAL]`) and later written by
  `handle_queued_log_write` (`856-944`) **[V]**.
* Dirty (simple) writes on logged fragments write PREPARE and COMMIT
  back-to-back in `doWritePrepareLog` (`13569-13584`) **[V]**.
* **Nothing is written to the REDO at COMPLETE** (`execCOMPLETE`, `14934-15030`) **[V]**.

### 2.3 ABORT (`ZABORT_TYPE` = 3, 3 words), written by `writeAbortLog`

`DblqhMain.cpp:43542-43559` **[V]**: `[3, transid1, transid2]`.

* Written in the abort path when the operation's prepare was written
  (`17095-17125`).
* This is the only record carrying a transid. It is skipped on replay
  (`39200-39206`).

### 2.4 COMPLETED_GCI (`ZCOMPLETED_GCI_TYPE` = 8, 2 words), written by `writeCompletedGciLog`

`DblqhMain.cpp:43631-43662` **[V]**: `[8, cnewestCompletedGci]`.

* `cnewestCompletedGci` is the gci of the GCP_SAVEREQ being processed.
* It also sets `logPartNewestCompletedGCI` (which then goes into later page
  headers and FD info).
* Written once per GCP per log part (`start_synch_gcp` `33957-34000`, or
  deferred through `logNextStart` `42576-42665`).

### 2.5 Structural records

| Type | Size | Content / when | Where |
|---|---|---|---|
| FD (4) | 3 + nFD*3*clogFileSize | At page 0 word 32: `[4, nFD, fileNo]`, then for this file and previous files the per-mbyte `maxGciCompleted[]`, `maxGciStarted[]`, `lastPrepRef[]`, then a NEXT_LOG record | `36073-36130` **[V]** |
| NEXT_LOG_RECORD (6) | 1 (2 reserved) | "skip to next page" | `36128` **[V]** |
| NEXT_MBYTE (7) | 1 | end of mbyte; written by `writeNextLog` | `43825-43826` **[V]** |
| INVALID_COMMIT (9) | 9 | a COMMIT overwritten during SR because gci > restart gci | `39114-39133` **[V]** |
| NEW_PREP (0), FRAG_SPLIT (5) | | **Never written** (legacy). Note that type 0 equals zeroed memory | grep: no writers **[V]** |

### 2.6 Cross-transaction identity

**None.** No record links the operations of one transaction across fragments,
log parts or nodes. COMMIT records carry no transid. The restart decision is
purely `gci_hi <= crestartNewestGci` per commit record (`39113-39133`), and
replay of each part stops at the COMPLETED_GCI record of `logLastGci`
(`39304-39350`) **[V]**.

---

## 3. Write path (in memory → NDBFS)

1. **Append.**
   * `writeLogWord`/`writeLogWords` copy into `logFile.currentLogpage`
     (`43721-43800`).
   * When a page becomes full, `completedLogPage(ZNORMAL, sync=false)` is
     called. A fresh page is seized and initialised, and `currentFilepage++`.
   * The prepare header and commit records have fast paths that write directly
     into the page (`14234-14244`, `43607-43619`) **[V]**.
2. **Batching.**
   * `completedLogPage` (`41035-41160`) links the full page onto
     `firstFilledPage..lastFilledPage` and increments `noLogpagesInBuffer`.
   * It returns without I/O unless `noLogpagesInBuffer == ZMAX_PAGES_WRITTEN`
     (8 pages = 256 KB), or the type is `ZENFORCE_WRITE` or
     `ZLAST_WRITE_IN_FILE` **[V]**.
   * When it writes, it seizes an LFO (log file operation record). It stamps
     the debug header and checksum on each page, and sends one FSWRITEREQ
     (`fsFormatListOfMemPages`, up to 15 page i-values, JBA).
   * The sync flag is set iff `ZLAST_WRITE_IN_FILE || sync_flag`. The LFO
     records `lfoPageNo`, `noPagesRw` and `lfoWordWritten=ZPAGE_SIZE-1`.
     `filePosition` is advanced.
3. **Mbyte switch.**
   * `checkNewMbyte` / `writeCommitLog` / `writeAbortLog` /
     `writeCompletedGciLog` call `changeMbyte` when the record would not fit
     (`40863-40868`).
   * `changeMbyte` = `writeNextLog` + `writeFileDescriptor`.
   * `writeNextLog` writes NEXT_MBYTE. It then calls
     `completedLogPage(ZENFORCE_WRITE, sync=true)`, or
     `(ZLAST_WRITE_IN_FILE, sync=true)` at the end of a file. In other words,
     **every mbyte switch issues a synced write** (comment `43788-43794`, code
     `43843-43869`) **[V]**.
   * It also checks free log space: it calls `force_lcp` if
     `free_mb <= c_free_mb_force_lcp_limit`, and sets `P_TAIL_PROBLEM` if
     `free_mb <= 4 + committed_mb` (`43955-43970`).
4. **File switch.**
   * The new file's page 0 (FD) is written with sync
     (`writeFileHeaderOpen`, `36150-36156`), and the *next* file is opened
     ahead of time (`openNextLogfile`).
   * When both the last write of the old file and the first write of the new
     file are done, page 0 of **file 0** is rewritten with sync to record the
     new last file (`firstPageWriteLab`/`lastWriteInFileLab`, `35130-35311`).
   * `fileChangeState` tracks this. If the next file is not open in time,
     `P_FILE_CHANGE_PROBLEM` is set (`43901-43915`) **[V]**.
5. **Partial page write** (`timeSup`, `34944-35067`).
   * The current page is copied into a seized page. The copy is written either
     with the pending full pages (`completedLogPage(ZENFORCE_WRITE, sync=false)`,
     after which `lfoWordWritten` is the real last word and `filePosition--`),
     or alone (`writeSinglePage(..., sync=true)`).
   * The original page continues to be filled and is later rewritten at the same
     file offset. No log space is wasted.
   * If the current page is the last page of an mbyte, it calls `changeMbyte`
     instead, which wastes at most one page **[V]**.
   * **`timeSup` is only triggered from `initGcpRecLab` via
     `startTimeSupervision`, once per GCP_SAVEREQ, with no delay** (`34055-34067`,
     `34121`). The "1 second" comment is legacy **[V]**. Between GCPs, a partially
     filled page stays in memory until it fills.
6. **Write order guarantee.**
   * Each REDO file is opened "bound" (`m_do_bind`). One NDBFS IO thread is
     attached to it and dequeues from that file's private channel
     (`ndbfs/Ndbfs.cpp:88-99`, `562-576`, `ndbfs/AsyncIoThread.cpp:110-116`,
     `175-179`, `287-293`) **[V]**.
   * So all writes and syncs to one file execute **in FIFO order**, and
     FSWRITECONFs for one file arrive in order **[I]**, based on single-thread
     dequeue plus a FIFO reply channel.
   * Two files are open at the same time during a file change. Those are
     ordered by the `fileChangeState` protocol, not by NDBFS.
7. **Completion.**
   * Flow: `execFSWRITECONF` → `initFsrwconf` (takes the log-part lock and
     clears in-writing flags) → state switch → `writeLogfileLab` /
     `lastWriteInFileLab` / `writePageZeroLab` → `checkGcpCompleted` and page
     release. The log-part lock is released at the end of `execFSWRITECONF`
     (`34686-34767`, `34859-34935`, `35069-35100`) **[V]**.
   * Note: the log-part mutex is held during the switch and is not recursive.
     Any new wake-up logic must not re-enter code that takes the lock **[V/I]**.

---

## 4. Flush / sync mechanics (NDBFS and portlib)

| Mechanism | What happens | Where |
|---|---|---|
| FSWRITEREQ with sync flag | `Request::writeSync` → `writeReq` then `syncReq` in the bound IO thread | `ndbfs/Ndbfs.cpp:1021-1032`, `ndbfs/AsyncIoThread.cpp:194-200` **[V]** |
| FSSYNCREQ | `Request::sync` → `syncReq` | `ndbfs/Ndbfs.cpp:1068-1091`, `AsyncIoThread.cpp:201-202` **[V]** |
| `syncReq` | `m_file.sync()`: a no-op if no bytes were written since the last sync, else `do_sync()` = **`::fsync()`** with an EINTR loop | `ndbfs/AsyncFile.cpp:1043-1049`, `common/portlib/ndb_file_common.cpp:98-109`, `ndb_file_posix.cpp:278-284` **[V]** |
| `OM_AUTOSYNC` | REDO files are opened with `auto_sync_size = MAX_REDO_PAGES_WITHOUT_SYNCH(32) * 32KB = 1 MB`. After each `pwrite`, if more than 1 MB is unsynced, fsync runs inline | `DblqhMain.cpp:35639`, `35710`, `35853`, `vm/pc.hpp:325`, `ndb_file_common.cpp:78-96`, `ndb_file_posix.cpp:104`, `132` **[V]** |
| `ODirect` (`c_o_direct`, ConfigInfo default false) | `OM_DIRECT` → O_DIRECT after the size check. If O_DIRECT fails, NDBFS reopens with `O_SYNC` | `DblqhMain.cpp:2755-2758`, `35620-35628`, `ndbfs/AsyncFile.cpp:330-358`, `ndb_file_posix.cpp:~420-458`, `ConfigInfo.cpp:1397-1399` **[V]** |
| `ODirectSyncFlag` | `OM_DIRECT_SYNC` → `m_os_syncs_each_write=true`, so **all fsyncs are skipped**. It is ignored unless `InitFragmentLogFiles=full` (and on Windows) | `DblqhMain.cpp:2780-2801`, `ndb_file_posix.cpp:~430-458`, `ndb_file_common.cpp:79-81`, `99-101` **[V]** |
| `InitFragmentLogFiles` | default `sparse`. With sparse files, the first write into a hole allocates blocks, so fsync must also commit file-system metadata **[I]** | `ConfigInfo.cpp:1150-1152`, `DblqhMain.cpp:2766-2778` |
| `DiskSyncSize` | used only by BACKUP/LCP files, **not** REDO | `backup/BackupInit.cpp:291` **[V]** |
| Write coalescing | Normal REDO files have `OM_WRITE_BUFFER`, so a multi-page FSWRITEREQ is copied into a contiguous buffer and written with fewer syscalls | `DblqhMain.cpp:35838-35840`, `ndbfs/AsyncFile.cpp:883-940` **[V]** |
| Encryption | `OM_ENCRYPT_XTS`. The XTS data unit equals the 32 KB page (`page_size=File_formats::NDB_PAGE_SIZE`) | `DblqhMain.cpp:35633-35636`, `ndbfs/AsyncFile.cpp:235-253`, `diskpage.hpp:36` **[V]** |

### 4.1 Signal and thread round trip for one synced write

The path is:

1. LDM sends FSWRITEREQ (JBA) to NDBFS.
2. NDBFS runs in thread 0, `thr_GLOBAL` (`vm/mt.cpp:7259`), and does
   `forward()` into the file's IO-thread channel.
3. The IO thread does pwrite and fsync. It writes the reply into
   `theFromThreads` and calls `m_fs.wakeup()` (`ndbfs/AsyncIoThread.cpp:245-246`).
4. Thread 0 picks the reply up via `SEND_PACKED`/`CONTINUEB` `scanIPC`
   (`ndbfs/Ndbfs.cpp:1585-1595`, `1726-1781`, `vm/mt.cpp:1766-1777`).
5. NDBFS sends FSWRITECONF (JBA) to the owning LDM (`ndbfs/Ndbfs.cpp:1517`).

**[V]** for the path. Expected latency **[I]**: about 2 thread hops plus
pwrite plus fsync.

* With enterprise NVMe that has power-loss protection, an fsync of an O_DIRECT
  32-256 KB write is about 20-100 µs.
* With consumer SSDs, or devices with a volatile cache that need a FLUSH, it is
  about 0.5-5 ms.
* With cloud block storage (EBS gp3/io2), it is about 0.5-2 ms.
* Main-thread load adds tens of µs per hop.

### 4.2 Syncs per log part today

1. Every mbyte switch (one synced write per MB).
2. Implicit NDBFS auto-sync for every >1 MB of writes (largely the same event).
3. Every file switch: the last write in the old file, page 0 of the new file,
   and page 0 of file 0, all synced.
4. Per GCP (default every 2 s): the `timeSup` partial write (synced when it is a
   single page) plus one FSSYNCREQ.

Syncs on one log part are serialised by its single bound IO thread. The sync
rate per part is therefore bounded by `1 / (write+fsync latency)`. The parts
sync in parallel on separate IO threads **[I]**.

---

## 5. GCP_SAVEREQ flush, end to end

DblqhProxy fans GCP_SAVEREQ out to each LDM worker (`dblqh/DblqhProxy.cpp:1108-1135`).
Each worker handles **its own** log parts and replies separately.

1. `execGCP_SAVEREQ` (`33749-33955`) sets `cnewestCompletedGci = gci`. It
   handles restart and stop cases, calls `sendRESTORABLE_GCI_REP(gci)` (which
   reports gci-1 to NDBCNTR/BACKUP), and allocates the single GcpRecord
   (`ccurrentGcprec=0`).
2. `start_synch_gcp` (`33957-34000`) loops over the instance's log parts under
   the lock.
   * If the part is IDLE, it writes COMPLETED_GCI(gci) immediately.
   * If the part is ACTIVE (writes are queued), it sets `waitWriteGciLog=WWGL_TRUE`
     and kicks `ZLOG_LQHKEYREQ`. The queue runner writes the GCI record before
     anything else (`queued_log_write` `1010-1040`, `logNextStart`
     `42628-42664`). When no part is still waiting, it sends `ZINIT_GCP_REC`.
3. `initGcpRecLab` (`34074-34133`) records, per part, the current
   `(file, currentFilepage, ZCURR_PAGE_INDEX-1)` as the target. It sets the
   state to ZWAIT_DISK and `logPart.gcprec=0`, then calls
   `startTimeSupervision`, which runs `timeSup` immediately to force the
   partial page.
4. On each FSWRITECONF, `checkGcpCompleted` (`34141-34258`) runs from
   `writeLogfileLab` (only when `fileChangeState==NOT_ONGOING`), from
   `lastWriteInFileLab` and from `writePageZeroLab`.
   * It compares the written `(page, word)` with the target, in the same file
     only.
   * When **all** of the instance's parts are ZON_DISK, it sends **FSSYNCREQ**
     for the target file of each part. A non-open file is treated as already
     synced.
5. `execFSSYNCCONF` (`34260-34308`) marks the part synced. When all parts are
   synced, it sends GCP_SAVECONF and sets `ccurrentGcprec=RNIL`.

**Why "all records ≤ gci are already in the buffers"** **[I]**: DIH sends
GCP_SAVEREQ(g) only after the GCP_COMMIT round for g. Every TC has then finished
the commit phase of all transactions in g. Because COMMIT passes through every
replica's `commitReqLab` before COMMITTED reaches TC, every COMMIT record with
`gci_hi<=g` has already been appended in memory. This belongs to the
DIH/TC agents to confirm.

**Properties relevant to durable commits:**

* There is one outstanding GCP per LQH instance.
* The sync waits for the *slowest* part's write before *any* part is synced
  (latency = max(write) + max(sync)).
* `FSSYNCCONF` is decoded as a GCP-only event (userPointer = LogFileRecord i).
  New sync users must be distinguishable.

---

## 6. Tail management and REDO-full handling

* **Tail position.** `logTailFileNo/logTailMbyte` per part (`Dblqh.hpp:2083`, `2205`).
* **Tail cut.** NDBCNTR sends `CUT_REDO_LOG_TAIL_REQ(keepGci = m_max_keep_gci)`
  to all LQHs after an LCP completes and the restorable GCI ≥ max GCI in the LCP
  (`ndbcntr/NdbcntrMain.cpp:7883-7907`). `execCUT_REDO_LOG_TAIL_REQ` →
  `setLogTail(keepGci)` (`31467-31471`, `33467-33730`) **[V]**.
  * `setLogTail` walks the per-mbyte `logMaxGciStarted[mb]` from the old tail
    until an mbyte with `maxGciStarted >= keepGci` is found.
  * It steps back one mbyte, then moves the tail to that mbyte's
    `logLastPrepRef`, so the oldest live prepare is kept.
  * The granularity is 1 MB.
* **Limits.**
  * `c_free_mb_force_lcp_limit`: max(total − LCP-trigger MB, total/3)
    (`2869-2891`).
  * `c_free_mb_tail_problem_limit` = 4 MB.
  * Free space is `free_log(head, tail)` (`740-748`).
  * `P_TAIL_PROBLEM` is set when `free_mb <= 4 + committed_mb` (the reserved
    commit/abort space). It is cleared when the tail moves
    (`33646-33660`, `43962-43967`).
  * Prepares then abort with 410 (`ZTAIL_PROBLEM_IN_LOG_ERROR`). Queueing is
    disabled for this problem (`13396-13414`).
  * Head meeting tail is a crash: "Head/Tail met in REDO log"
    (`43917-43940`) **[V]**.
* **Other problems.** `P_REDO_IO_PROBLEM` (1234) and `P_FILE_CHANGE_PROBLEM`
  (1220) cause queueing or abort (`13587-13622`).
* **Implications for durable commits [I]:**
  * Records written after the last completed GCP lie *ahead* of the head of the
    restorable region. They do not hold the tail back, because the tail is
    driven by LCP keepGci and old prepares.
  * New per-commit records (for example an extended COMMIT carrying
    `gci_lo`/transid) increase per-op REDO volume. The commit reservation
    `ZCOMMIT_LOG_SIZE+1` (`47888-47909`) must grow with them.
  * The repeated partial-page copies need extra buffer pages and LFOs while
    in flight. `count_free_log_pages` and `clfoFileSize` (`2735-2740`) must
    budget for them. With "one outstanding force per part" the extra need is
    bounded (about 1 page and 1 LFO per part).
  * If restart keeps commits with `gci_hi > last GCP`, the next GCI numbers must
    not be reused. That is DIH/restart scope.

---

## 7. Proposed hook: "wait until REDO is durable past position P, then continue"

### 7.1 State per LogPartRecord [I]

```
Uint64 m_head_lsn;          // LSN of next word to be appended (derived)
Uint64 m_durable_lsn;       // highest LSN known written AND synced (file-change gated)
Uint64 m_force_issued_lsn;  // end LSN of the outstanding forced+synced write, 0 if none
Uint32 m_force_outstanding; // 0/1 (or small N for pipelining)
OperationQueue m_durable_wait_queue;   // FIFO == LSN order (appends are under the log-part lock)
Bitmask m_remote_waiters;   // LDM instances with waiters on this part (mutex configs)
```

* Per `LogFileRecord`: `Uint64 m_lsn_base`, set when the file becomes the head
  file in `writeNextLog`.
* Per `LogFileOperationRecord`: `Uint64 lfoEndLsn` and `bool lfoSync`, set in
  `completedLogPage` and `writeSinglePage`.

### 7.2 Assign the waiter LSN

* In `writeCommitLog` (`43566`), after the record is appended, set
  `regTcPtr->m_commit_end_lsn = lsn(currentFile, currentFilepage,
  ZCURR_PAGE_INDEX) - 1`. Do this only when the operation is flagged
  "durable" (READ_BACKUP or a per-transaction flag).
* **LQH has no READ_BACKUP knowledge today.** Only TC has `TR_READ_BACKUP`
  (`dbtc/Dbtc.hpp:1745`, `dbtc/DbtcMain.cpp:1130-1138`). The flag must come in
  LQHKEYREQ or COMMIT; that is protocol-agent scope.
* The prepare record needs no separate wait. It precedes the commit record in
  the same part. Per-file FIFO plus fsync-of-file covers it. If the prepare is in
  a previous file, that file's last write was synced (`ZLAST_WRITE_IN_FILE`).

### 7.3 Request the force eagerly, at commit-record time

* After writeCommitLog: if `m_commit_end_lsn > m_durable_lsn` and
  `!m_force_outstanding`, call `forceCurrentPage(logPart, sync=true)`.
* `forceCurrentPage` is a refactor of the body of `timeSup`
  (`34961-35062`) with `sync=true` on the `completedLogPage(ZENFORCE_WRITE,...)`
  path as well. It sets `m_force_outstanding` and `lfoSync=true`.
* Callable from any LDM holding the lock, as `completedLogPage` is today.
* It reuses the existing P_FILE_CHANGE_PROBLEM deferral: CONTINUEB with a
  50 ms retry, which is a latency risk only at file switches.

### 7.4 Wait at the protocol point

* Where the protocol needs durability (proposal: in `execCOMPLETE` before
  `localCommitLab`/`sendCompleteLqh`/`sendCompletedTc`), check
  `m_commit_end_lsn <= logPart->m_durable_lsn`. If not, link the op into
  `m_durable_wait_queue` with a new transaction state (for example
  `WAIT_REDO_DURABLE`) and return.
* Because the force was issued at COMMIT time, the sync overlaps the
  COMMITTED→TC→COMPLETE round trip. In the common case the wait is already
  satisfied.

### 7.5 Advance `m_durable_lsn`

Update it next to every `checkGcpCompleted` call:

| Call site | Rule |
|---|---|
| `writeLogfileLab` (`35069-35100`) | if `lfoSync` and `fileChangeState==NOT_ONGOING`, advance to `lfoEndLsn`. Otherwise stash it as "synced-but-gated" |
| `lastWriteInFileLab` (`35206-35220`) | always synced, so advance |
| `writePageZeroLab` (`35313-35345`) | release the gated value |
| `execFSSYNCCONF` (`34260`) | advance to the last LSN dispatched before the FSSYNCREQ was sent. FIFO means the sync covers it |

Mbyte-switch writes (sync=true) also advance the LSN for free. NDBFS auto-sync
is invisible to LQH and is ignored.

### 7.6 Group commit (leader/follower)

On completion of the forced write, clear `m_force_outstanding`, wake every
waiter with LSN ≤ `m_durable_lsn`, and **if waiters remain, immediately issue
the next force**. That force covers everything appended in the meantime. The
batch size then adapts to device latency.

Optional:

* allow 2 outstanding forces (pipelining), since the IO thread serialises them
  anyway;
* add a µs-scale "commit delay" knob.

### 7.7 Where the queue is serviced

* FSWRITECONF/FSSYNCCONF arrive at the **owning LDM**.
* **Non-mutex configs** (`ndbLogParts` is a multiple of numLDM, the normal
  case): all waiters are local. Wake them after the log-part lock is released
  (the lock is held in `execFSWRITECONF` until `34767`). Wake in bounded
  batches via CONTINUEB to respect real-time breaks.
* **Mutex configs**: keep a waiter list per (part, LDM instance). Send one
  signal to each instance in `m_remote_waiters` carrying `(part, durable_lsn)`,
  following the pattern of `send_handle_queued_log_write` (`770-835`).

### 7.8 How many log parts one transaction touches

* Per node, the parts touched = the distinct log parts of the fragments it
  writes, at most `min(#fragments, ndbLogParts)`.
* With READ_BACKUP and 2 replicas, every written fragment has a COMMIT record
  on 2 nodes. A single-row write therefore needs **2 part-syncs (one per
  replica node)**, and a transaction over F fragments needs up to 2F,
  deduplicated per (node, part).
* Fully replicated tables need one per node.
* Each operation waits individually. LQH has no per-transaction record in the
  log module, and waking in LSN order makes per-op waiting cheap.

### 7.9 Cost model [I]

* Each force writes at least one full 32 KB page, the partial-page copy. At
  1000 forces/s per part that is about 32 MB/s of extra write bandwidth per part.
  It is mitigable by writing only the dirty 4 KB tail, which needs a new NDBFS
  format or size path and O_DIRECT alignment of 512/4096
  (`include/ndb_global.h:179-180`).
* Sync throughput per part is about `1/(write+fsync)`. Transactions per sync are
  unbounded because of group commit.
* Recommended for durable mode: `InitFragmentLogFiles=full` (no metadata
  journal in fsync). O_DIRECT is optional. `fdatasync` instead of `fsync` is a
  small win. Do not rely on `ODirectSyncFlag`, which skips all flushes and is
  unsafe on volatile-cache devices.

---

## 8. RonDB-specific vs upstream

* **Decoupled log parts and LDMs, the log-part mutex, and the booked REDO space
  for queued cross-LDM writes** (`m_booked_redo_log_space`, `ZCONTINUE_WRITE_LOG`).
  These were introduced in commit d680256ca2b / e182c5868f6 (2020-08-08,
  Mikael Ronström, "WL#13219, WL#13980, WL#13930") **[V]** (git log `-S`).
  Whether this is identical in upstream 8.0.23+ is **[I]**.
* **Query threads (Dbqlqh)** have no REDO (`DblqhInit.cpp:142-148`) **[V]**.
* **Defaults** (ConfigInfo): `FragmentLogFileSize` "1G" (`ConfigInfo.cpp:1146-1148`)
  and `NoOfFragmentLogFiles` 16 (`1140-1144`). The automatic RedoBuffer is
  `numLDM*32MB/parts`, capped at 64 MB per part (`vm/Configuration.cpp:1006-1023`).
  The upstream defaults are 16M per file and RedoBuffer 32M **[I]**.
* **`ZINSERT_TTL`** may appear in PREPARE records and is replayed as ZINSERT
  (`43029-43046`) **[V]**.
* **Prepare records carry the rowid** (words 6-7), as in upstream 7.x+ **[I]**.
* **NDBFS calls `Dblqh::execFSWRITEREQ` directly**, cross-thread, during REDO
  file init to format mbyte headers (`35733-35790`) **[V]**.
* The GCP_SAVEREQ path writes the local sysfile during restarts
  (`write_local_sysfile_gcp_complete[_late]`) **[V]**. This is RonDB partial-LCP
  and local-sysfile machinery.

---

## 9. Open questions and risks

1. **Restart granularity.** COMMIT records lack `gci_lo` and transid.
   * Epoch-granular durability needs `gci_lo` in commit records (a new record
     type, for example `ZCOMMIT_EXT_TYPE`; do not reuse type 0) plus a per-part
     "epoch completed" marker. `execSUB_GCP_COMPLETE_REP` already passes through
     LQH (`34045-34050`) and is a natural trigger.
   * Transaction-granular durability needs transid plus participant info.
   * Which one is chosen determines the new record formats. Restart/micro-GCP
     agents to decide.
2. **End-of-valid-data after a crash.**
   * Release builds have no page checksum (37) and do not zero recycled pages.
   * Partial pages on disk contain stale bytes after `ZCURR_PAGE_INDEX`, which
     may look like valid old records.
   * Today's replay never reads past COMPLETED_GCI(last GCI), so this is
     harmless today. Durable replay needs a real per-page checksum plus
     lap/file/page identity, and a rule based on `ZCURR_PAGE_INDEX`, or
     per-record checksums.
   * Old versions crash on unknown record types ("Invalid logword",
     `39352-39364`), so upgrade/downgrade gating is needed. `redoLogReader`
     (`dblqh/redoLogReader/records.hpp`, `reader.cpp`) must learn any new types.
3. **Torn rewrites of the current page.** A forced partial page is rewritten
   many times at the same offset.
   * Plain files: the already-durable prefix bytes are identical, so only the
     header sector is exposed **[I]**.
   * **With XTS encryption the data unit is the whole 32 KB page**, so a torn
     rewrite can destroy already-acknowledged records **[I]**.
   * This also affects today's COMPLETED_GCI page, but rarely. Consider
     ping-pong slots, or "close the page on force" in encrypted mode.
4. **File-change gating.** Records in a new file are not recoverable until page
   0 of file 0 is rewritten. Durable acks issued during a file switch wait for
   2-3 extra synced writes, and possibly 50 ms retries under
   P_FILE_CHANGE_PROBLEM. How large is the tail latency?
5. **Where to wait.** Waiting at COMPLETE on backups delays backup lock release
   (backups commit in TUP at COMPLETE, `15003-15008`), and a wait at each chain
   hop is serial. Is a separate parallel "durable" ack to TC preferable?
   Protocol agent to decide.
6. **Main-thread NDBFS hop.** Every forced write goes through thread 0 twice.
   Under load, should REDO FSWRITEREQ/CONF bypass the NDBFS block (WL#8890-style
   direct replies, `vm/mt.cpp:1766-1777`)?
7. **`fsync` vs `fdatasync`**, and the behaviour of `ODirectSyncFlag` (skips all
   flushes) when durable mode is on. Should durable mode reject or warn about
   `ODirectSyncFlag`?
8. **GCP path reuse.** Should GCP_SAVEREQ itself become a client of the new
   durable-LSN machinery (target = COMPLETED_GCI LSN per part), which would
   remove the "all parts written before any sync" serialisation in
   `checkGcpCompleted`?
9. **Minor.** In `logNextStart` the "still waiting" loop locks
   `regLogPartPtr` instead of `lnsLogPartPtr.p` (`42654-42661`) **[V]**. This is
   harmless in non-mutex configs and worth fixing if the code is touched.
