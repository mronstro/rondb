/*
   Copyright (c) 2026, Hopsworks and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is designed to work with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have either included with
   the program or referenced in the documentation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

/*
 * RONDB-1150: the REDO log of DBLQH with RedoLogMode=pmem. The records
 * in the PMEM format (PmemRedoFormat.hpp), the copy to the mappings and
 * the persist, the restart from the mappings, the crash error inserts,
 * and the REDO log files that NDBFS keeps open and mapped.
 *
 * File mode, the normal mode, is in DblqhMain.cpp. Its functions call
 * the ones here only when c_redo_pmem_format or c_redo_pmem is set, so
 * that the code of PMEM mode stays out of the way of file mode.
 */

#define DBLQH_C
#include <ndb_limits.h>
#include <algorithm>
#include <cstring>
#include "Dblqh.hpp"
#include "PmemRedoScan.hpp"
#include "portlib/ndb_pmem.h"

#include <signaldata/FsConf.hpp>
#include <EventLogger.hpp>

#define JAM_FILE_ID 574

#ifdef NDB_DEBUG_REDO_EXEC
static int DEBUG_REDO_EXEC = 1;
#else
#define DEBUG_REDO_EXEC 0
#endif

/* ==========================================================================
 * RONDB-1150: the REDO records in the PMEM format (PmemRedoFormat.hpp,
 * impl_step1_lqh_write.md S4, S5.1)
 *
 * Entered from today's writers when c_redo_pmem_format is set. The
 * records go into the log pages as today: writeLogWords() completes a
 * page and goes on in the next one inside a record. A record's checksum
 * is taken for the place of its w0, one piece per page. Phase 8 copies
 * the pages to the mapping and persists them (S5.2, S5.3).
 * ========================================================================== */

static_assert(PmemRedo::PAGE_WORDS == ZPAGE_SIZE &&
                  PmemRedo::HEADER_WORDS == ZPAGE_HEADER_SIZE &&
                  PmemRedo::PAGES_IN_MBYTE == ZPAGES_IN_MBYTE,
              "the PMEM format has the geometry of the log pages");
static_assert(PmemRedo::TYPE_PREPARE == ZPREP_OP_TYPE &&
                  PmemRedo::TYPE_COMMIT == ZCOMMIT_TYPE &&
                  PmemRedo::TYPE_ABORT == ZABORT_TYPE &&
                  PmemRedo::TYPE_FD == ZFD_TYPE &&
                  PmemRedo::TYPE_NEXT_MBYTE == ZNEXT_MBYTE_TYPE &&
                  PmemRedo::TYPE_COMPLETED_GCI == ZCOMPLETED_GCI_TYPE,
              "the PMEM record types keep today's numbers");
static_assert(PmemRedo::NEXT_MBYTE_LEN == ZNEXT_LOG_SIZE,
              "every record leaves room for a NEXT_MBYTE");
static_assert(PmemRedo::HDR_LAP == ZPOS_LOG_LAP &&
                  PmemRedo::HDR_MAX_GCI_COMPLETED == ZPOS_MAX_GCI_COMPLETED &&
                  PmemRedo::HDR_MAX_GCI_STARTED == ZPOS_MAX_GCI_STARTED &&
                  PmemRedo::HDR_VERSION == ZPOS_VERSION &&
                  PmemRedo::HDR_NO_LOG_FILES == ZPOS_NO_LOG_FILES &&
                  PmemRedo::HDR_LAST_PREP_REF == ZLAST_LOG_PREP_REF &&
                  PmemRedo::HDR_PAGE_NO == ZPOS_PAGE_NO &&
                  PmemRedo::HDR_FILE_NO == ZPOS_PAGE_FILE_NO &&
                  PmemRedo::HDR_NO_LOG_PARTS == ZPOS_NO_LOG_PARTS,
              "the PMEM page header words keep the ZPOS_* numbers");

/* S of a record whose w0 goes at the current position (F10: the lap of
   the page header) */
PmemRedo::Suffix Dblqh::redoSuffix(const LogPartRecord *logPartPtrP,
                                   const LogFileRecord *logFilePtrP,
                                   const LogPageRecord *logPagePtrP) const {
  return PmemRedo::suffix(logPagePtrP->logPageWord[ZPOS_LOG_LAP],
                          logPartPtrP->logPartNo, logFilePtrP->fileNo,
                          logFilePtrP->currentFilepage,
                          logPagePtrP->logPageWord[ZCURR_PAGE_INDEX]);
}

/**
 * S4.2: a record of at most 12 words built in rec, w1 left 0. A new
 * mbyte first if the record would not leave room for a NEXT_MBYTE, as
 * today; then the checksum for its place, split where the page ends, and
 * the words into the log pages.
 */
void Dblqh::redoAppendFixed(Signal *signal, LogPartRecord *logPartPtrP,
                            LogPageRecordPtr &logPagePtr,
                            LogFileRecordPtr &logFilePtr, Uint32 *rec,
                            Uint32 len) {
  ndbassert(len == PmemRedo::w0Len(rec[0]) && len <= PmemRedo::COMMIT_LEN);
  if (len + ZNEXT_LOG_SIZE > logFilePtr.p->remainingWordsInMbyte) {
    jam();
    changeMbyte(signal, logPagePtr, logFilePtr, logPartPtrP);
  }
  const Uint32 index = logPagePtr.p->logPageWord[ZCURR_PAGE_INDEX];
  ndbassert((index & 1) == 0);
  rec[1] = PmemRedo::splitChecksum(
      rec, ZPAGE_SIZE - index,
      redoSuffix(logPartPtrP, logFilePtr.p, logPagePtr.p));
  logFilePtr.p->remainingWordsInMbyte -= len;
  logPartPtrP->m_total_written_words += len;
  writeLogWords(signal, rec, len, logPagePtr, logFilePtr, logPartPtrP);
  redoEndOfRecord(logPartPtrP, logFilePtr.p);
}

/**
 * S4.3: a PREPARE (format §5.1). The header goes in from the stack, the
 * key and the attrinfo from their sections as today, then a pad word if
 * needed; checkNewMbyte() made room for all of it in the mbyte. The
 * checksum is taken where the record lies, one piece per page (E4), over
 * the start page, the pages after it on the file's filled list
 * (completedLogPage() links them in order) and the current page; w1 is
 * stored last. The walk needs the filled pages linked until the record
 * ends: in the PMEM format completedLogPage() only links them, and the
 * copy-out after the record releases them (phase 8, S5.2).
 */
void Dblqh::writePrepareLogPmem(Signal *signal,
                                const TcConnectionrec *regTcPtr,
                                LogPageRecordPtr &logPagePtr,
                                LogFileRecordPtr &logFilePtr,
                                LogPartRecord *logPartPtrP) {
  const Uint32 keyLen = regTcPtr->primKeyLen;
  const Uint32 aiLen = regTcPtr->currTupAiLen;
  const Uint32 len = PmemRedo::prepareLen(keyLen, aiLen, false);
  const LogPageRecordPtr startPagePtr = logPagePtr;
  const Uint32 startIndex = logPagePtr.p->logPageWord[ZCURR_PAGE_INDEX];
  ndbassert((startIndex & 1) == 0);
  const PmemRedo::Suffix s =
      redoSuffix(logPartPtrP, logFilePtr.p, logPagePtr.p);

  Uint32 hdr[PmemRedo::PREPARE_HEAD];
  PmemRedo::prepareHead(hdr, 0, len, regTcPtr->hashValue,
                        regTcPtr->operation, aiLen, keyLen,
                        regTcPtr->m_row_id.m_page_no,
                        regTcPtr->m_row_id.m_page_idx);
  writeLogWords(signal, hdr, PmemRedo::PREPARE_HEAD, logPagePtr, logFilePtr,
                logPartPtrP);
  writeKey(signal, regTcPtr, logPagePtr, logFilePtr, logPartPtrP);
  writeAttrinfoLab(signal, regTcPtr, logPagePtr, logFilePtr, logPartPtrP);
  if ((keyLen + aiLen) & 1) {
    const Uint32 pad = 0;
    writeLogWords(signal, &pad, 1, logPagePtr, logFilePtr, logPartPtrP);
  }
  logPartPtrP->m_total_written_words += len;

  const Uint32 noPages = PmemRedo::pagesSpanned(startIndex, len);
  ndbrequire(noPages <= PmemRedo::PREPARE_MAX_PAGES);
  const Uint32 *pages[PmemRedo::PREPARE_MAX_PAGES];
  LogPageRecordPtr pagePtr = startPagePtr;
  pages[0] = pagePtr.p->logPageWord;
  for (Uint32 i = 1; i < noPages; i++) {
    pagePtr.i = pagePtr.p->logPageWord[ZNEXT_PAGE];
    if (pagePtr.i == RNIL) pagePtr.i = logFilePtr.p->currentLogpage;
    ptrCheckGuard(pagePtr, logPartPtrP->logPageFileSize,
                  logPartPtrP->logPageRecord);
    pages[i] = pagePtr.p->logPageWord;
  }
  startPagePtr.p->logPageWord[startIndex + 1] =
      PmemRedo::pagedChecksum(pages, startIndex, s);
  redoEndOfRecord(logPartPtrP, logFilePtr.p);
}

/**
 * S4.4: a COMMIT (format §5.2): where its PREPARE is, the GCI and the
 * transid. A durable one (X4, OP_DURABLE) has CF_DURABLE and the opCount
 * of its transaction, and keeps the COMPLETE's part of the operation's
 * reservation, which its COMPLETE gives back (redoCompleteDurable());
 * any other gives back all of it. Its end goes to m_redo_end_lsn when a
 * dependent signal waits for it (S5.7, S5.8): a durable COMMIT, or any
 * with the benchmark switch on; else 0, so that a switch turned on later
 * is not waited for by an older COMMIT.
 */
void Dblqh::writeCommitLogPmem(Signal *signal, TcConnectionrec *regTcPtr,
                               LogPartRecord *logPartPtrP, bool durable) {
  LogPageRecordPtr logPagePtr;
  LogFileRecordPtr logFilePtr;
  logFilePtr.i = logPartPtrP->currentLogfile;
  ptrCheckGuard(logFilePtr, logPartPtrP->my_block->clogFileFileSize,
                logPartPtrP->my_block->logFileRecord);
  logPagePtr.i = logFilePtr.p->currentLogpage;
  ptrCheckGuard(logPagePtr, logPartPtrP->logPageFileSize,
                logPartPtrP->logPageRecord);
  ndbassert(!m_is_in_query_thread);
  Uint32 rec[PmemRedo::COMMIT_LEN];
  PmemRedo::commitRecord(
      rec, durable ? PmemRedo::CF_DURABLE : 0, regTcPtr->tableref,
      regTcPtr->schemaVersion, regTcPtr->fragmentid, regTcPtr->logStartFileNo,
      regTcPtr->logStartPageNo, regTcPtr->logStartPageIndex,
      regTcPtr->logStopPageNo, regTcPtr->gci_hi, regTcPtr->gci_lo,
      regTcPtr->transid[0], regTcPtr->transid[1],
      durable ? regTcPtr->m_op_count : 0);
  redoAppendFixed(signal, logPartPtrP, logPagePtr, logFilePtr, rec,
                  PmemRedo::COMMIT_LEN);
  regTcPtr->m_redo_end_lsn =
      (durable || c_redo_pmem_persist_commit != 0)
          ? redoPosLsn(logPartPtrP, logFilePtr.p, logPagePtr.p)
          : 0;
  release_committed_words(logPartPtrP, regTcPtr, PmemRedo::AT_COMMIT,
                          durable);
}

/**
 * S4.4: an ABORT (format §5.3). flags is 0 from today's callers; with
 * AF_AFTER_COMMIT (rule F, X4) a dependent signal waits for it.
 */
void Dblqh::writeAbortLogPmem(Signal *signal, TcConnectionrec *regTcPtr,
                              LogPageRecordPtr &logPagePtr,
                              LogFileRecordPtr &logFilePtr,
                              LogPartRecord *logPartPtrP, Uint32 flags) {
  Uint32 rec[PmemRedo::ABORT_LEN];
  PmemRedo::abortRecord(rec, flags, regTcPtr->transid[0],
                        regTcPtr->transid[1]);
  redoAppendFixed(signal, logPartPtrP, logPagePtr, logFilePtr, rec,
                  PmemRedo::ABORT_LEN);
  if (flags & PmemRedo::AF_AFTER_COMMIT) {
    regTcPtr->m_redo_end_lsn =
        redoPosLsn(logPartPtrP, logFilePtr.p, logPagePtr.p);
  }
  release_committed_words(logPartPtrP, regTcPtr, PmemRedo::AT_ABORT, false);
}

/* S4.4: a COMPLETED_GCI (format §5.4), with today's error insert 5051 */
void Dblqh::writeCompletedGciLogPmem(Signal *signal,
                                     LogPageRecordPtr &logPagePtr,
                                     LogFileRecordPtr &logFilePtr,
                                     LogPartRecord *logPartPtrP) {
  if ((PmemRedo::COMPLETED_GCI_LEN + ZNEXT_LOG_SIZE) >
      logFilePtr.p->remainingWordsInMbyte) {
    jam();
    changeMbyte(signal, logPagePtr, logFilePtr, logPartPtrP);
  }

  if (ERROR_INSERTED(5051) && (logFilePtr.p->currentFilepage > 0) &&
      (logFilePtr.p->currentFilepage % 32) == 0) {
    SET_ERROR_INSERT_VALUE(5000);
  }

  if (DEBUG_REDO_EXEC) {
    g_eventLogger->info(
        "(%u)writeCompletedGciLogPmem gci: %u part: %u"
        " file: %u page: %u (mb: %u)",
        instance(), cnewestCompletedGci, logPartPtrP->logPartNo,
        logFilePtr.p->fileNo, logFilePtr.p->currentFilepage,
        logFilePtr.p->currentFilepage >> ZTWOLOG_NO_PAGES_IN_MBYTE);
  }

  Uint32 rec[PmemRedo::COMPLETED_GCI_LEN];
  PmemRedo::completedGciRecord(rec, cnewestCompletedGci);
  redoAppendFixed(signal, logPartPtrP, logPagePtr, logFilePtr, rec,
                  PmemRedo::COMPLETED_GCI_LEN);
  logPartPtrP->logPartNewestCompletedGCI = cnewestCompletedGci;
  logPartPtrP->m_pmem_gci_end_lsn =
      redoPosLsn(logPartPtrP, logFilePtr.p, logPagePtr.p);
}

/**
 * S4.4: a COMPLETE (format §5.5), after a durable COMMIT; a dependent
 * signal waits for it, and it gives back the rest of the reservation.
 * With the log part locked, from redoCompleteDurable().
 */
void Dblqh::writeCompleteLog(Signal *signal, TcConnectionrec *regTcPtr,
                             LogPartRecord *logPartPtrP) {
  ndbrequire(c_redo_pmem_format);
  LogPageRecordPtr logPagePtr;
  LogFileRecordPtr logFilePtr;
  logFilePtr.i = logPartPtrP->currentLogfile;
  ptrCheckGuard(logFilePtr, logPartPtrP->my_block->clogFileFileSize,
                logPartPtrP->my_block->logFileRecord);
  logPagePtr.i = logFilePtr.p->currentLogpage;
  ptrCheckGuard(logPagePtr, logPartPtrP->logPageFileSize,
                logPartPtrP->logPageRecord);
  Uint32 rec[PmemRedo::COMPLETE_LEN];
  PmemRedo::completeRecord(rec, regTcPtr->transid[0], regTcPtr->transid[1]);
  redoAppendFixed(signal, logPartPtrP, logPagePtr, logFilePtr, rec,
                  PmemRedo::COMPLETE_LEN);
  regTcPtr->m_redo_end_lsn =
      redoPosLsn(logPartPtrP, logFilePtr.p, logPagePtr.p);
  release_committed_words(logPartPtrP, regTcPtr, PmemRedo::AT_COMPLETE, true);
}

/**
 * X4.5 and the barrier K of X4.4, at COMPLETE and COMPLETEREQ of an
 * operation whose durable COMMIT kept the COMPLETE's part of its
 * reservation (RESERVED_TAIL): its COMPLETE record, persistent before
 * the operation becomes visible on a backup, before COMPLETE is passed on
 * and before COMPLETED or COMPLETECONF (invariant K). Once only, as the
 * record gives the reservation back. An operation of a node restart's
 * copy (AC_NR_COPY) or ignored by it (AC_IGNORED) writes none (DI-10) and
 * only gives the reservation back.
 */
void Dblqh::redoCompleteDurable(Signal *signal, TcConnectionrec *regTcPtr) {
  ndbassert(regTcPtr->m_committed_log_space == PmemRedo::RESERVED_TAIL);
  LogPartRecord *const logPartPtrP = regTcPtr->m_log_part_ptr_p;
  lock_log_part(logPartPtrP);
  if (regTcPtr->activeCreat != Fragrecord::AC_NORMAL) {
    jam();
    release_committed_words(logPartPtrP, regTcPtr, PmemRedo::AT_COMPLETE,
                            true);
    unlock_log_part(logPartPtrP);
    return;
  }
  jam();
  writeCompleteLog(signal, regTcPtr, logPartPtrP);
  redoPersistCommit(signal, logPartPtrP, regTcPtr);
  unlock_log_part(logPartPtrP);
}

/**
 * S4.5: a FILLER of len words that closes a write unit (format §5.6). Its
 * body is zeroed, so that the copied unit is the same every time, and is
 * not in the checksum. It never crosses a page end, and is not counted as
 * written log.
 */
void Dblqh::writeFillerPmem(Signal *signal, LogPartRecord *logPartPtrP,
                            LogPageRecordPtr &logPagePtr,
                            LogFileRecordPtr &logFilePtr, Uint32 len) {
  const Uint32 index = logPagePtr.p->logPageWord[ZCURR_PAGE_INDEX];
  ndbrequire(len >= PmemRedo::FILLER_MIN && len <= PmemRedo::FILLER_MAX &&
             (len & 1) == 0 && index + len <= ZPAGE_SIZE);
  ndbrequire(logFilePtr.p->remainingWordsInMbyte >= len);
  Uint32 rec[PmemRedo::FILLER_MAX] = {0};
  rec[0] = PmemRedo::makeW0(PmemRedo::TYPE_FILLER, 0, len);
  rec[1] = PmemRedo::recordChecksum(
      rec, redoSuffix(logPartPtrP, logFilePtr.p, logPagePtr.p));
  logFilePtr.p->remainingWordsInMbyte -= len;
  logPartPtrP->m_pmem_stats.filler_bytes += 4 * len;
  writeLogWords(signal, rec, len, logPagePtr, logFilePtr, logPartPtrP);
}

/**
 * S4.5: the NEXT_MBYTE at the current position (format §5.7), and the
 * rest of its write unit zeroed. The page index moves to the end of the
 * unit, so that the copy of the page (F6) takes the whole unit. Every
 * record left room for it (ZNEXT_LOG_SIZE). redoPmemEndMbyte() calls it
 * and fences it before the next mbyte is touched (W2).
 */
void Dblqh::writeNextMbytePmem(LogPartRecord *logPartPtrP,
                               LogFileRecord *logFilePtrP,
                               LogPageRecord *logPagePtrP) {
  Uint32 *const page = logPagePtrP->logPageWord;
  const Uint32 index = page[ZCURR_PAGE_INDEX];
  ndbrequire((index & 1) == 0 &&
             index + PmemRedo::NEXT_MBYTE_LEN <= ZPAGE_SIZE);
  page[index] = PmemRedo::makeW0(PmemRedo::TYPE_NEXT_MBYTE, 0,
                                 PmemRedo::NEXT_MBYTE_LEN);
  page[index + 1] = PmemRedo::recordChecksum(
      &page[index], redoSuffix(logPartPtrP, logFilePtrP, logPagePtrP));
  const Uint32 end = index + PmemRedo::NEXT_MBYTE_LEN;
  const Uint32 unitEnd = end + PmemRedo::padWords(end);
  std::memset(&page[end], 0, sizeof(Uint32) * (unitEnd - end));
  page[ZCURR_PAGE_INDEX] = unitEnd;
}

/**
 * S5.3, W2, from writeNextLog() at the end of an mbyte: the NEXT_MBYTE,
 * and all of the mbyte before it, persistent before any byte of the next
 * mbyte is written. The copy goes before the lap and the file change in
 * writeNextLog(), which the LSN of the old mbyte depends on. The page is
 * then done.
 */
void Dblqh::redoPmemEndMbyte(LogPageRecordPtr &logPagePtr,
                             LogFileRecordPtr &logFilePtr,
                             LogPartRecord *logPartPtrP) {
  writeNextMbytePmem(logPartPtrP, logFilePtr.p, logPagePtr.p);
  redoCopyOut(logPartPtrP, false);
  const bool lastMbyte = logFilePtr.p->currentMbyte ==
                         logPartPtrP->my_block->clogFileSize - 1;
  if (ERROR_INSERTED(5156) && !lastMbyte) {
    redoPmemCrashPoint(5156, logPartPtrP,
                       "the NEXT_MBYTE persistent, before the next mbyte");
  }
  if (ERROR_INSERTED(5158) && lastMbyte) {
    redoPmemCrashPoint(5158, logPartPtrP,
                       "the end of a file persistent, before page 0 of "
                       "the next file");
  }
  releaseLogpage(logPagePtr, logPartPtrP);
}

/**
 * From writeNextLog() at the start of the next mbyte, its first page set
 * up. W3: a new file, mapped since the start, gets its FD, then the
 * last-file slot, each persistent before the first record of the file
 * (writeFileHeaderOpenPmem()); no open of the next file. In the same
 * file, the dead space after the NEXT_MBYTE is never stored.
 */
void Dblqh::redoPmemStartMbyte(LogPageRecordPtr &logPagePtr,
                               LogFileRecordPtr &logFilePtr,
                               LogPartRecord *logPartPtrP) {
  if (logFilePtr.p->currentMbyte == 0) {
    jam();
    writeFileHeaderOpenPmem(logPagePtr, logFilePtr, logPartPtrP);
    logFilePtr.p->fileChangeState = LogFileRecord::NOT_ONGOING;
  } else {
    jam();
    logPartPtrP->m_pmem_persisted_lsn =
        redoLsn(logPartPtrP, logFilePtr.p->fileNo,
                logFilePtr.p->currentFilepage, 0);
  }
}

/**
 * S4.6: page 0 of a file in its log page, after initLogpage(): the FD at
 * word 32 (format §5.8) with the descriptors of writeFileHeaderOpen(), and
 * a FILLER to the page end of which only w0 and w1 are set. The FILLER's
 * body, where file 0 keeps the control area (E10), is never copied (D4).
 * Phase 8 copies the page (S5.3, S4.8).
 */
void Dblqh::redoBuildPageZero(LogPageRecordPtr logPagePtr,
                              LogFileRecordPtr logFilePtr,
                              LogPartRecord *logPartPtrP) {
  Uint32 *const page = logPagePtr.p->logPageWord;
  Dblqh *const owner = logPartPtrP->my_block;
  const Uint32 noFd =
      std::min(Uint32(logPartPtrP->noLogFiles), owner->cmaxLogFilesInPageZero);
  const Uint32 len = PmemRedo::fdLen(noFd, clogFileSize);
  const Uint32 fillerIndex = ZPAGE_HEADER_SIZE + len;
  ndbrequire(fillerIndex + 2 <= PmemRedo::CONTROL_AREA_WORD);

  Uint32 *const fd = &page[ZPAGE_HEADER_SIZE];
  fd[0] = PmemRedo::makeW0(PmemRedo::TYPE_FD, 0, len);
  fd[1] = 0;
  fd[PmemRedo::FD_NO_FD] = noFd;
  fd[PmemRedo::FD_FILE_NO] = logFilePtr.p->fileNo;
  LogFileRecordPtr filePtr = logFilePtr;
  for (Uint32 f = 0; f < noFd; f++) {
    jam();
    ptrCheckGuard(filePtr, owner->clogFileFileSize, owner->logFileRecord);
    Uint32 *const arrays =
        &fd[PmemRedo::FD_ARRAYS + f * ZFD_MBYTE_SIZE * clogFileSize];
    for (Uint32 mb = 0; mb < clogFileSize; mb++) {
      arrays[mb] = filePtr.p->logMaxGciCompleted[mb];
      arrays[clogFileSize + mb] = filePtr.p->logMaxGciStarted[mb];
      arrays[2 * clogFileSize + mb] = filePtr.p->logLastPrepRef[mb];
    }
    filePtr.i = filePtr.p->prevLogFile;
  }
  const Uint32 used =
      PmemRedo::FD_ARRAYS + noFd * ZFD_MBYTE_SIZE * clogFileSize;
  if (used < len) fd[used] = 0;  // the pad word

  const Uint32 lap = page[ZPOS_LOG_LAP];
  const Uint32 fileNo = logFilePtr.p->fileNo;
  fd[1] = PmemRedo::recordChecksum(
      fd, PmemRedo::suffix(lap, logPartPtrP->logPartNo, fileNo, 0,
                           ZPAGE_HEADER_SIZE));
  page[fillerIndex] = PmemRedo::makeW0(PmemRedo::TYPE_FILLER, 0,
                                       ZPAGE_SIZE - fillerIndex);
  page[fillerIndex + 1] = PmemRedo::recordChecksum(
      &page[fillerIndex],
      PmemRedo::suffix(lap, logPartPtrP->logPartNo, fileNo, 0, fillerIndex));
  page[ZCURR_PAGE_INDEX] = ZPAGE_SIZE;
}

/* The page header as stored on PMEM, from the page's DRAM header */
void Dblqh::redoPmemHeaderImage(Uint32 *img, const LogPageRecord *logPagePtrP,
                                Uint32 fileNo, Uint32 pageNo,
                                const LogPartRecord *logPartPtrP) const {
  PmemRedo::buildPageHeader(img, logPagePtrP->logPageWord, fileNo, pageNo,
                            logPartPtrP->logPartNo, getOwnNodeId());
}

/* S5.1: the byte position of a word in the log of the part, its lap's */
Uint64 Dblqh::redoLsn(const LogPartRecord *logPartPtrP, Uint32 fileNo,
                      Uint32 pageNo, Uint32 word) const {
  return PmemRedo::lsn(logPartPtrP->logLap, logPartPtrP->noLogFiles,
                       logPartPtrP->my_block->clogFileSize, fileNo, pageNo,
                       word);
}

/**
 * The end of what the writers have put in the log pages: the current
 * position, or the start of the current page while it holds only its
 * header. So a record that ends at a page end ends at the next page's
 * start, and nothing of a page is counted before its first record.
 */
Uint64 Dblqh::redoPosLsn(const LogPartRecord *logPartPtrP,
                         const LogFileRecord *logFilePtrP,
                         const LogPageRecord *logPagePtrP) const {
  const Uint32 index = logPagePtrP->logPageWord[ZCURR_PAGE_INDEX];
  return redoLsn(logPartPtrP, logFilePtrP->fileNo,
                 logFilePtrP->currentFilepage,
                 index == ZPAGE_HEADER_SIZE ? 0 : index);
}

Uint64 Dblqh::redoAppendLsn(LogPartRecord *logPartPtrP) {
  LogFileRecordPtr logFilePtr;
  logFilePtr.i = logPartPtrP->currentLogfile;
  ptrCheckGuard(logFilePtr, logPartPtrP->my_block->clogFileFileSize,
                logPartPtrP->my_block->logFileRecord);
  LogPageRecordPtr logPagePtr;
  logPagePtr.i = logFilePtr.p->currentLogpage;
  ptrCheckGuard(logPagePtr, logPartPtrP->logPageFileSize,
                logPartPtrP->logPageRecord);
  return redoPosLsn(logPartPtrP, logFilePtr.p, logPagePtr.p);
}

Uint8 *Dblqh::redoPmemAddr(const LogFileRecord *logFilePtrP, Uint32 pageNo,
                           Uint32 word) const {
  return logFilePtrP->m_pmem_base + Uint64(pageNo) * PmemRedo::PAGE_BYTES +
         4 * word;
}

bool Dblqh::redoHasUnpersisted(LogPartRecord *logPartPtrP) {
  return redoAppendLsn(logPartPtrP) > logPartPtrP->m_pmem_persisted_lsn;
}

/**
 * The write position after a restart (impl_step1_lqh_write.md §7.2):
 * recovery has set the head and closed its write unit, so the log is
 * persistent up to it and no page waits for a copy.
 */
void Dblqh::redoInitWritePosition(LogPartRecord *logPartPtrP) {
  LogFileRecordPtr logFilePtr;
  logFilePtr.i = logPartPtrP->currentLogfile;
  ptrCheckGuard(logFilePtr, logPartPtrP->my_block->clogFileFileSize,
                logPartPtrP->my_block->logFileRecord);
  ndbrequire(logFilePtr.p->firstFilledPage == RNIL);
  const Uint64 lsn = redoAppendLsn(logPartPtrP);
  ndbrequire(lsn % PmemRedo::W_BYTES == 0);
  logPartPtrP->m_pmem_persisted_lsn = lsn;
}

/* ==========================================================================
 * RONDB-1150: the write path of the PMEM format (impl_step1_lqh_write.md
 * S4.8, S5.2-S5.4)
 *
 * The records are built in the log pages; redoCopyOut() moves them to the
 * mapping with non-temporal stores and one fence. The full pages go at
 * the end of each record, the rest of the current page at a persist: the
 * GCP save, the mbyte switch and the file switch. Every store to the
 * mapping is fenced by the thread that made it before the log part is
 * unlocked (S5.6).
 * ========================================================================== */

/**
 * Words from up to to of a log page to the mapping, page pageNo of the
 * file. From word 0 the page's header goes first, built from its DRAM
 * header (R3); it is stored once in the lap (E5), as nothing is copied
 * from word 0 of a page again. A page with nothing after its header is
 * not stored yet. Returns the bytes copied, which the caller fences.
 */
Uint32 Dblqh::redoCopyPage(LogPartRecord *logPartPtrP,
                           const LogFileRecord *logFilePtrP,
                           const LogPageRecord *logPagePtrP, Uint32 pageNo,
                           Uint32 from, Uint32 to) {
  ndbrequire(from % PmemRedo::W_WORDS == 0 && to % PmemRedo::W_WORDS == 0 &&
             from <= to && to <= ZPAGE_SIZE);
  Uint32 bytes = 0;
  if (from == 0) {
    if (to <= ZPAGE_HEADER_SIZE) return 0;
    alignas(PmemRedo::W_BYTES) Uint32 img[ZPAGE_HEADER_SIZE];
    redoPmemHeaderImage(img, logPagePtrP, logFilePtrP->fileNo, pageNo,
                        logPartPtrP);
    redoPmemCopy(redoPmemAddr(logFilePtrP, pageNo, 0), img, sizeof(img));
    bytes += sizeof(img);
    from = ZPAGE_HEADER_SIZE;
  }
  if (to > from) {
    redoPmemCopy(redoPmemAddr(logFilePtrP, pageNo, from),
                 &logPagePtrP->logPageWord[from], 4 * (to - from));
    bytes += 4 * (to - from);
  }
  logPartPtrP->m_pmem_unfenced += bytes;
  return bytes;
}

/**
 * The drain of this thread's stores to the mappings. With the power-loss
 * emulation nothing of this thread is pending after it (recovery plan
 * S7.3): a store left pending was not flushed. Error insert 5171 stops
 * the node before the K-th drain, K its extra value or random up to 1000.
 */
void Dblqh::redoPmemDrain() {
  if (ERROR_INSERTED(5171) && redoPmemCountTo(5171)) {
    redoPmemCrashPoint(5171, nullptr, "before a drain");
  }
  ndb_pmem_drain();
  ndbassert(ndb_pmem_emul_pending() == 0);
}

/**
 * S7.3, with the power-loss emulation in debug builds, before
 * GCP_SAVECONF: no thread has a line pending in the log that this part
 * made persistent since the last check, [checked, persisted). A drain
 * missing in another thread, as in a log part shared by LDMs, shows
 * here, before a power loss could lose a GCP that was saved.
 */
void Dblqh::redoPmemCheckGcpPersisted(LogPartRecord *logPartPtrP) {
  Dblqh *const owner = logPartPtrP->my_block;
  const Uint32 noFiles = logPartPtrP->noLogFiles;
  const Uint64 fileBytes = Uint64(clogFileSize) << 20;
  lock_log_part(logPartPtrP);
  const Uint64 to = logPartPtrP->m_pmem_persisted_lsn;
  Uint64 at = logPartPtrP->m_pmem_gcp_checked_lsn;
  if (to > at + noFiles * fileBytes) at = to - noFiles * fileBytes;
  Uint64 pendingAt = 0;
  bool pending = false;
  while (at < to && !pending) {
    const Uint32 fileNo = Uint32((at / fileBytes) % noFiles);
    const Uint64 off = at % fileBytes;
    const Uint64 n = std::min(to - at, fileBytes - off);
    LogFileRecordPtr filePtr;
    filePtr.i = logPartPtrP->firstLogfile;
    for (Uint32 f = 0; f <= fileNo; f++) {
      ptrCheckGuard(filePtr, owner->clogFileFileSize, owner->logFileRecord);
      if (f < fileNo) filePtr.i = filePtr.p->nextLogFile;
    }
    ndbrequire(filePtr.p->fileNo == fileNo &&
               filePtr.p->m_pmem_base != nullptr);
    pending = ndb_pmem_emul_range_pending(filePtr.p->m_pmem_base + off, n);
    pendingAt = at;
    at += n;
  }
  logPartPtrP->m_pmem_gcp_checked_lsn = to;
  unlock_log_part(logPartPtrP);
  if (pending) {
    char buf[200];
    BaseString::snprintf(buf, sizeof(buf),
                         "PMEM REDO log part %u: a line persisted for "
                         "GCP_SAVECONF is not persistent, in file %u from "
                         "LSN %llu",
                         logPartPtrP->logPartNo,
                         Uint32((pendingAt / fileBytes) % noFiles),
                         (unsigned long long)pendingAt);
    progError(__LINE__, NDBD_EXIT_SR_REDOLOG, buf);
  }
}

/**
 * S5.2, S5.6: the fence after the write path's stores to the mapping, by
 * the thread that made them and before the log part is unlocked. Then
 * __RedoLogPmemPersistDelayNs (Q-A11): the persist takes as long as it
 * would on slower persistent memory, 200-2000 ns on CXL, so that commit
 * latency and throughput can be measured for it on DRAM.
 */
void Dblqh::redoPmemFence(LogPartRecord *logPartPtrP) {
#if defined(VM_TRACE) || defined(ERROR_INSERT)
  if (unlikely(c_redo_pmem_tear != 0)) {
    /* S7.1: the persist of a crash error insert ends torn, unfenced */
    redoPmemCrashPoint(c_redo_pmem_tear, logPartPtrP,
                       "a copy to the mapping torn before its fence");
  }
#endif
  redoPmemDrain();
  logPartPtrP->m_pmem_unfenced = 0;
  const Uint32 delayNs = c_redo_pmem_persist_delay_ns;
  if (delayNs != 0) {
    const NDB_TICKS start = NdbTick_getCurrentTicks();
    while (NdbTick_Elapsed(start, NdbTick_getCurrentTicks()).nanoSec() <
           delayNs) {
    }
  }
}

/**
 * The counters of ndbinfo redo_log_pmem for one fence, and its time when
 * start is set (one persist in 16): at most 250 ns, 500 ns, 1, 2, 4, 8,
 * 16 us, more.
 */
void Dblqh::redoCountPersist(LogPartRecord *logPartPtrP, Uint64 bytes,
                             const NDB_TICKS *start) {
  LogPartRecord::RedoPmemStats &stats = logPartPtrP->m_pmem_stats;
  stats.barriers++;
  stats.bytes_copied += bytes;
  if (start != nullptr) {
    const Uint64 ns =
        NdbTick_Elapsed(*start, NdbTick_getCurrentTicks()).nanoSec();
    Uint32 bucket = 0;
    for (Uint64 limit = 250; bucket < 7 && ns > limit; limit *= 2) bucket++;
    stats.lat_samples++;
    stats.lat_hist[bucket]++;
  }
}

/**
 * S5.2: the log of the current file from the persisted LSN to the
 * mapping: the filled pages, and unless filledOnly the current page up to
 * its index, then the fence. The filled pages go back to the free list,
 * and the persisted LSN moves to the end of the copy. With filledOnly it
 * may stop inside a record; a crash then leaves the record without its
 * next page's header, which the restart rejects. Called with the log part
 * locked; the only store of records to the mapping.
 */
void Dblqh::redoCopyOut(LogPartRecord *logPartPtrP, bool filledOnly) {
  Dblqh *const owner = logPartPtrP->my_block;
  LogFileRecordPtr logFilePtr;
  logFilePtr.i = logPartPtrP->currentLogfile;
  ptrCheckGuard(logFilePtr, owner->clogFileFileSize, owner->logFileRecord);
  LogFileRecord *const filePtrP = logFilePtr.p;
  if (filledOnly && filePtrP->firstFilledPage == RNIL) return;
  ndbrequire(filePtrP->m_pmem_base != nullptr);

  /* The persisted LSN and the filled pages are in the current file (S5.3) */
  const Uint64 fileStart = redoLsn(logPartPtrP, filePtrP->fileNo, 0, 0);
  const Uint64 persisted = logPartPtrP->m_pmem_persisted_lsn;
  ndbrequire(persisted >= fileStart && persisted % PmemRedo::W_BYTES == 0);
  Uint32 pageNo = Uint32((persisted - fileStart) / PmemRedo::PAGE_BYTES);
  Uint32 word = Uint32((persisted - fileStart) % PmemRedo::PAGE_BYTES) / 4;
  ndbrequire(pageNo + filePtrP->noLogpagesInBuffer ==
             filePtrP->currentFilepage);
  LogPageRecordPtr curPagePtr;
  curPagePtr.i = filePtrP->currentLogpage;
  ptrCheckGuard(curPagePtr, logPartPtrP->logPageFileSize,
                logPartPtrP->logPageRecord);

  /**
   * S7.1: error insert 5155 tears this persist, 5157 the first one into
   * an mbyte after the first, which stores the mbyte's header. Each
   * stops the node at the fence.
   */
  if (ERROR_INSERTED(5155)) redoPmemArmTear(5155);
  if (ERROR_INSERTED(5157) && word == 0 && pageNo != 0 &&
      pageNo % ZPAGES_IN_MBYTE == 0 &&
      (filePtrP->firstFilledPage != RNIL ||
       (!filledOnly &&
        curPagePtr.p->logPageWord[ZCURR_PAGE_INDEX] > ZPAGE_HEADER_SIZE))) {
    redoPmemArmTear(5157);
  }

  const bool timed = (logPartPtrP->m_pmem_stats.barriers % 16) == 0;
  NDB_TICKS start;
  NdbTick_Invalidate(&start);
  if (timed) start = NdbTick_getCurrentTicks();
  Uint64 bytes = 0;
  LogPageRecordPtr pagePtr;
  for (pagePtr.i = filePtrP->firstFilledPage; pagePtr.i != RNIL;
       pagePtr.i = pagePtr.p->logPageWord[ZNEXT_PAGE]) {
    ptrCheckGuard(pagePtr, logPartPtrP->logPageFileSize,
                  logPartPtrP->logPageRecord);
    ndbrequire(pagePtr.p->logPageWord[ZCURR_PAGE_INDEX] == ZPAGE_SIZE);
    bytes += redoCopyPage(logPartPtrP, filePtrP, pagePtr.p, pageNo, word,
                          ZPAGE_SIZE);
    pageNo++;
    word = 0;
  }
  if (!filledOnly) {
    bytes += redoCopyPage(logPartPtrP, filePtrP, curPagePtr.p, pageNo, word,
                          curPagePtr.p->logPageWord[ZCURR_PAGE_INDEX]);
  }
  redoPmemFence(logPartPtrP);
  redoCountPersist(logPartPtrP, bytes, timed ? &start : nullptr);
  const Uint64 to =
      filledOnly
          ? redoLsn(logPartPtrP, filePtrP->fileNo, filePtrP->currentFilepage, 0)
          : redoPosLsn(logPartPtrP, filePtrP, curPagePtr.p);
#if defined(VM_TRACE) || defined(ERROR_INSERT)
  redoPmemVerifyCopy(logPartPtrP, filePtrP, persisted, to);
#endif

  pagePtr.i = filePtrP->firstFilledPage;
  while (pagePtr.i != RNIL) {
    ptrCheckGuard(pagePtr, logPartPtrP->logPageFileSize,
                  logPartPtrP->logPageRecord);
    const Uint32 nextI = pagePtr.p->logPageWord[ZNEXT_PAGE];
    releaseLogpage(pagePtr, logPartPtrP);
    pagePtr.i = nextI;
  }
  filePtrP->firstFilledPage = RNIL;
  filePtrP->lastFilledPage = RNIL;
  filePtrP->noLogpagesInBuffer = 0;
  logPartPtrP->m_pmem_persisted_lsn = to;
}

/**
 * The end of every record but a FILLER or a NEXT_MBYTE: the pages it
 * filled go to the mapping, so that at most the pages of one record wait
 * in DRAM.
 */
void Dblqh::redoEndOfRecord(LogPartRecord *logPartPtrP,
                            const LogFileRecord *logFilePtrP) {
  if (logFilePtrP->firstFilledPage != RNIL) {
    jam();
    redoCopyOut(logPartPtrP, true);
  }
}

/**
 * The write unit at the current position closed (W7): by a FILLER, or by
 * the NEXT_MBYTE when the unit is the last of the mbyte, which persists
 * the mbyte itself. remainingWordsInMbyte is the words to the end of the
 * mbyte, so it equals the pad only in the mbyte's last unit.
 */
void Dblqh::redoPadToUnit(Signal *signal, LogPartRecord *logPartPtrP) {
  LogFileRecordPtr logFilePtr;
  logFilePtr.i = logPartPtrP->currentLogfile;
  ptrCheckGuard(logFilePtr, logPartPtrP->my_block->clogFileFileSize,
                logPartPtrP->my_block->logFileRecord);
  LogPageRecordPtr logPagePtr;
  logPagePtr.i = logFilePtr.p->currentLogpage;
  ptrCheckGuard(logPagePtr, logPartPtrP->logPageFileSize,
                logPartPtrP->logPageRecord);
  const Uint32 pad =
      PmemRedo::padWords(logPagePtr.p->logPageWord[ZCURR_PAGE_INDEX]);
  if (pad == 0) return;
  if (logFilePtr.p->remainingWordsInMbyte == pad) {
    jam();
    changeMbyte(signal, logPagePtr, logFilePtr, logPartPtrP);
    return;
  }
  jam();
  writeFillerPmem(signal, logPartPtrP, logPagePtr, logFilePtr, pad);
}

/**
 * S5.2: everything written to the log part persistent, with its last
 * unit closed. With the log part locked.
 */
void Dblqh::redoPersist(Signal *signal, LogPartRecord *logPartPtrP) {
  if (!redoHasUnpersisted(logPartPtrP)) return;
  redoPadToUnit(signal, logPartPtrP);
  if (redoHasUnpersisted(logPartPtrP)) {
    jam();
    redoCopyOut(logPartPtrP, false);
  }
}

/**
 * S5.8: the barrier at a C place of E8 (impl_step1_lqh_write.md), where
 * X4 keeps it for durable operations: the COMMIT that a dependent signal
 * waits for is persistent before the signal, and the COMPLETE of a
 * durable operation (K, redoCompleteDurable()). One barrier persists the
 * whole log part, so the other records written since are persistent too.
 * With the log part locked. In a debug build DUMP 2368 4 skips the next
 * one, and the check before the dependent signal stops the node.
 */
void Dblqh::redoPersistCommit(Signal *signal, LogPartRecord *logPartPtrP,
                              const TcConnectionrec *regTcPtr) {
  if (regTcPtr->m_redo_end_lsn <= logPartPtrP->m_pmem_persisted_lsn) return;
#if defined(VM_TRACE) || defined(ERROR_INSERT)
  if (unlikely(c_redo_pmem_skip_barrier)) {
    jam();
    c_redo_pmem_skip_barrier = false;
    g_eventLogger->info(
        "LDM(%u): PMEM REDO: DUMP 2368 4 skips the barrier of a COMMIT or "
        "COMPLETE in log part %u",
        instance(), logPartPtrP->logPartNo);
    return;
  }
#endif
  redoPersist(signal, logPartPtrP);
}

/* S5.8: redoPersistCommit() at commitReqLab, which takes the lock */
void Dblqh::redoPersistOp(Signal *signal, const TcConnectionrec *regTcPtr) {
  LogPartRecord *const logPartPtrP = regTcPtr->m_log_part_ptr_p;
  lock_log_part(logPartPtrP);
  redoPersistCommit(signal, logPartPtrP, regTcPtr);
  unlock_log_part(logPartPtrP);
}

/* S5.7: a dependent signal would go before its REDO record is persistent */
void Dblqh::redoCheckPersistedFailed(const TcConnectionrec *regTcPtr,
                                     Uint64 persisted, Uint32 line) {
  const LogPartRecord *const logPartPtrP = regTcPtr->m_log_part_ptr_p;
  char buf[200];
  BaseString::snprintf(
      buf, sizeof(buf),
      "PMEM REDO: the signal at line %u waits for a REDO record that is "
      "not persistent: log part %u, record end LSN %llu, persisted LSN %llu",
      line, logPartPtrP->logPartNo,
      (unsigned long long)regTcPtr->m_redo_end_lsn,
      (unsigned long long)persisted);
  g_eventLogger->error("LDM(%u): %s", instance(), buf);
  progError(__LINE__, NDBD_EXIT_PRGERR, buf);
}

/**
 * DUMP 2368 2 (S5.8): the counters of ndbinfo redo_log_pmem of a log
 * part, to the cluster log: the persists, the bytes stored, the FILLER
 * bytes, and the persist time of one persist in 16.
 */
void Dblqh::redoPmemPrintCounters(const LogPartRecord *logPartPtrP) {
  const LogPartRecord::RedoPmemStats &s = logPartPtrP->m_pmem_stats;
  char buf[400];
  BaseString::snprintf(
      buf, sizeof(buf),
      "PMEM REDO log part %u: %llu persists, %llu bytes stored, %llu filler "
      "bytes; persist time of %llu: <=250ns %llu, <=500ns %llu, <=1us %llu, "
      "<=2us %llu, <=4us %llu, <=8us %llu, <=16us %llu, >16us %llu; persist "
      "at commit %s",
      logPartPtrP->logPartNo, (unsigned long long)s.barriers,
      (unsigned long long)s.bytes_copied, (unsigned long long)s.filler_bytes,
      (unsigned long long)s.lat_samples, (unsigned long long)s.lat_hist[0],
      (unsigned long long)s.lat_hist[1], (unsigned long long)s.lat_hist[2],
      (unsigned long long)s.lat_hist[3], (unsigned long long)s.lat_hist[4],
      (unsigned long long)s.lat_hist[5], (unsigned long long)s.lat_hist[6],
      (unsigned long long)s.lat_hist[7],
      c_redo_pmem_persist_commit != 0 ? "on" : "off");
  g_eventLogger->info("LDM(%u): %s", instance(), buf);
  infoEvent("%s", buf);
}

/**
 * S5.3: page 0 of a new file at a file switch, in its log page after
 * initLogpage(): the FD and its FILLER (S4.6), persistent; then the
 * last-file slot, persistent before the first record of the file (W3).
 * Writing goes on in page 1, as after writeFileHeaderOpen().
 */
void Dblqh::writeFileHeaderOpenPmem(LogPageRecordPtr &logPagePtr,
                                    LogFileRecordPtr logFilePtr,
                                    LogPartRecord *logPartPtrP) {
  ndbrequire(logFilePtr.p->m_pmem_base != nullptr &&
             logFilePtr.p->currentFilepage == 0 &&
             logFilePtr.p->firstFilledPage == RNIL);
  redoBuildPageZero(logPagePtr, logFilePtr, logPartPtrP);
  /* S7.1: error inserts 5159, 5161-5163 at the file switch */
  if (ERROR_INSERTED(5159)) redoPmemArmTear(5159);
  redoCopyPageZero(logPagePtr, logFilePtr, logPartPtrP);
  if (ERROR_INSERTED(5161)) {
    redoPmemCrashPoint(5161, logPartPtrP,
                       "page 0 of a new file persistent, before the slot");
  }
  if (ERROR_INSERTED(5162)) redoPmemArmTear(5162);
  redoWriteLastFileSlot(logPartPtrP, logFilePtr.p->fileNo,
                        logPartPtrP->logLap);
  if (ERROR_INSERTED(5163)) {
    redoPmemCrashPoint(5163, logPartPtrP,
                       "the slot of a new file persistent, before its first "
                       "record");
  }
  if (logPagePtr.i != logFilePtr.p->logPageZero) {
    jam();
    releaseLogpage(logPagePtr, logPartPtrP);
  }
  logFilePtr.p->filePosition = 1;
  seizeLogpage(logPagePtr, logPartPtrP);
  initLogpage(logPagePtr, logFilePtr.p, logPartPtrP);
  logFilePtr.p->currentLogpage = logPagePtr.i;
  logFilePtr.p->currentFilepage = 1;
  logPartPtrP->m_pmem_persisted_lsn =
      redoLsn(logPartPtrP, logFilePtr.p->fileNo, 1, 0);
}

/**
 * Page 0 of a file, as redoBuildPageZero() built it, to the mapping: the
 * header and the words up to the end of the unit that holds the header of
 * the FD's FILLER, the rest of that unit zero. The FILLER's body after it
 * is never stored: in file 0 it holds the control area (D4, R4).
 */
void Dblqh::redoCopyPageZero(LogPageRecordPtr logPagePtr,
                             LogFileRecordPtr logFilePtr,
                             LogPartRecord *logPartPtrP) {
  Uint32 *const page = logPagePtr.p->logPageWord;
  const Uint32 fillerIndex =
      ZPAGE_HEADER_SIZE + PmemRedo::w0Len(page[ZPAGE_HEADER_SIZE]);
  const Uint32 end = fillerIndex + PmemRedo::FILLER_MIN;
  const Uint32 unitEnd = end + PmemRedo::padWords(end);
  ndbrequire(PmemRedo::w0Type(page[ZPAGE_HEADER_SIZE]) == ZFD_TYPE &&
             unitEnd <= PmemRedo::CONTROL_AREA_WORD);
  std::memset(&page[end], 0, sizeof(Uint32) * (unitEnd - end));
  const Uint32 bytes =
      redoCopyPage(logPartPtrP, logFilePtr.p, logPagePtr.p, 0, 0, unitEnd);
  redoPmemFence(logPartPtrP);
  redoCountPersist(logPartPtrP, bytes, nullptr);
}

/**
 * S4.8, R2: the first pages of a file at an initial start, through the
 * mapping; NDBFS wrote the file as zeros (OM_INIT). Page 0 holds the FD,
 * with lap 1 in file 0 and lap 0 (never written) in the others. File 0
 * also gets page 1, COMPLETED_GCI(1) and the FILLER of its unit, where the
 * head starts (initFourth(), R6), and the control area: the config line
 * and slot 1 naming file 0 in lap 1.
 */
void Dblqh::redoPmemInitFile(LogPageRecordPtr logPagePtr,
                             LogFileRecordPtr logFilePtr,
                             LogPartRecord *logPartPtrP) {
  ndbrequire(logFilePtr.p->m_pmem_base != nullptr);
  redoBuildPageZero(logPagePtr, logFilePtr, logPartPtrP);
  redoCopyPageZero(logPagePtr, logFilePtr, logPartPtrP);
  if (logFilePtr.p->fileNo != 0) return;

  const Uint32 partNo = logPartPtrP->logPartNo;
  initLogpage(logPagePtr, logFilePtr.p, logPartPtrP);
  Uint32 *const page = logPagePtr.p->logPageWord;
  page[ZPOS_LOG_LAP] = 1;
  Uint32 *const gciRec = &page[ZPAGE_HEADER_SIZE];
  PmemRedo::completedGciRecord(gciRec, 1);
  gciRec[1] = PmemRedo::recordChecksum(
      gciRec, PmemRedo::suffix(1, partNo, 0, 1, ZPAGE_HEADER_SIZE));
  const Uint32 fillerIndex = ZPAGE_HEADER_SIZE + PmemRedo::COMPLETED_GCI_LEN;
  const Uint32 fillerLen = PmemRedo::padWords(fillerIndex);
  Uint32 *const filler = &page[fillerIndex];
  std::memset(filler, 0, sizeof(Uint32) * fillerLen);
  filler[0] = PmemRedo::makeW0(PmemRedo::TYPE_FILLER, 0, fillerLen);
  filler[1] = PmemRedo::recordChecksum(
      filler, PmemRedo::suffix(1, partNo, 0, 1, fillerIndex));
  Uint64 bytes = redoCopyPage(logPartPtrP, logFilePtr.p, logPagePtr.p, 1, 0,
                              fillerIndex + fillerLen);

  alignas(PmemRedo::W_BYTES) Uint32 line[PmemRedo::W_WORDS];
  PmemRedo::buildCtrlConfig(line, globalData.ndbLogParts, partNo,
                            logPartPtrP->noLogFiles, clogFileSize,
                            getOwnNodeId());
  ndb_pmem_copy_nt(redoPmemAddr(logFilePtr.p, 0, PmemRedo::CTRL_CONFIG_WORD),
                   line, sizeof(line));
  bytes += sizeof(line);
  logPartPtrP->m_pmem_unfenced += sizeof(line);
  redoPmemFence(logPartPtrP);
  redoCountPersist(logPartPtrP, bytes, nullptr);

  /* The dirty-shutdown count of the REDO path, which the slots record */
  const Uint32 pathNo = logPartPtrP->m_redo_path_no;
  ndbrequire(pathNo < NDB_ARRAY_SIZE(globalData.theRedoPmemPath));
  const Uint64 dsc = globalData.theRedoPmemPath[pathNo].dirty_shutdown;
  logPartPtrP->m_pmem_slot_seq = 0;
  logPartPtrP->m_pmem_dsc_recorded = dsc != ~Uint64(0) ? dsc : 0;
  logPartPtrP->m_pmem_dsc_flags =
      dsc != ~Uint64(0) ? PmemRedo::SLOT_F_DSC_VALID : 0;
  redoWriteLastFileSlot(logPartPtrP, 0, 1);
}

/**
 * E10, recovery plan S6.3: the last file of the log and its lap in the
 * next slot of the control area, one line with one copy and a fence. The
 * caller has made page 0 of the file persistent. With the log part
 * locked at a file switch, or by the LDM thread during a start.
 */
void Dblqh::redoWriteLastFileSlot(LogPartRecord *logPartPtrP, Uint32 fileNo,
                                  Uint32 lap) {
  Dblqh *const owner = logPartPtrP->my_block;
  LogFileRecordPtr file0Ptr;
  file0Ptr.i = logPartPtrP->firstLogfile;
  ptrCheckGuard(file0Ptr, owner->clogFileFileSize, owner->logFileRecord);
  ndbrequire(file0Ptr.p->fileNo == 0 && file0Ptr.p->m_pmem_base != nullptr);
  const Uint64 seq = logPartPtrP->m_pmem_slot_seq + 1;
  alignas(PmemRedo::W_BYTES) Uint32 line[PmemRedo::W_WORDS];
  PmemRedo::buildSlot(line, seq, fileNo, lap, logPartPtrP->logPartNo,
                      logPartPtrP->m_pmem_dsc_recorded,
                      logPartPtrP->m_pmem_dsc_flags);
  redoPmemCopy(redoPmemAddr(file0Ptr.p, 0, PmemRedo::slotWord(seq)), line,
               sizeof(line));
  logPartPtrP->m_pmem_unfenced += sizeof(line);
  redoPmemFence(logPartPtrP);
  redoCountPersist(logPartPtrP, sizeof(line), nullptr);
  logPartPtrP->m_pmem_slot_seq = seq;
}

/**
 * DUMP 2368 3 (S5.2): the log part persisted, then read back through the
 * mappings with the restart's scan from the start of the current mbyte.
 * The end of the valid log it finds must be the persisted position (the
 * start of a page whose header is not yet stored counts as that page's
 * first record position).
 */
void Dblqh::redoPmemVerify(Signal *signal, LogPartRecord *logPartPtrP) {
  Dblqh *const owner = logPartPtrP->my_block;
  lock_log_part(logPartPtrP);
  redoPersist(signal, logPartPtrP);
  const Uint32 noFiles = logPartPtrP->noLogFiles;
  const Uint8 **bases = new const Uint8 *[noFiles];
  LogFileRecordPtr filePtr;
  filePtr.i = logPartPtrP->firstLogfile;
  for (Uint32 f = 0; f < noFiles; f++) {
    ptrCheckGuard(filePtr, owner->clogFileFileSize, owner->logFileRecord);
    ndbrequire(filePtr.p->fileNo == f && filePtr.p->m_pmem_base != nullptr);
    bases[f] = filePtr.p->m_pmem_base;
    filePtr.i = filePtr.p->nextLogFile;
  }
  filePtr.i = logPartPtrP->currentLogfile;
  ptrCheckGuard(filePtr, owner->clogFileFileSize, owner->logFileRecord);
  const PmemRedo::Geom g = {noFiles, clogFileSize, logPartPtrP->logPartNo};
  const PmemRedo::PartView v = {g, bases};
  const Uint32 fileNo = filePtr.p->fileNo;
  const Uint32 mbyte = filePtr.p->currentMbyte;
  const PmemRedo::ScanResult r =
      PmemRedo::findEnd(v, fileNo, mbyte, logPartPtrP->logLap);
  const Uint64 persisted = logPartPtrP->m_pmem_persisted_lsn;
  unlock_log_part(logPartPtrP);
  delete[] bases;

  Uint64 end = PmemRedo::posLsn(g, r.end);
  if (r.end.pageIndex == ZPAGE_HEADER_SIZE) end -= 4 * ZPAGE_HEADER_SIZE;
  const bool ok = end == persisted;
  char buf[256];
  BaseString::snprintf(
      buf, sizeof(buf),
      "PMEM REDO verify%s: log part %u, %u records from file %u mbyte %u, "
      "end at file %u page %u word %u (%s), persisted LSN %llu",
      ok ? " ok" : " failed", logPartPtrP->logPartNo, r.records, fileNo,
      mbyte, r.end.fileNo, r.end.pageNo, r.end.pageIndex,
      PmemRedo::reasonName(r.reason), (unsigned long long)persisted);
  if (ok) {
    g_eventLogger->info("LDM(%u): %s", instance(), buf);
  } else {
    g_eventLogger->error("LDM(%u): %s", instance(), buf);
  }
  infoEvent("%s", buf);
}

/* ==========================================================================
 * RONDB-1150: a system or node restart from the PMEM format (recovery
 * plan S6.1, S6.3-S6.6)
 *
 * Phase 1 reads the mappings directly: the control area, the headers of
 * the mbytes of the last file, page 0 of the files before it, and the
 * records up to the end of the log E. Phases 3 and 4 run as in file mode
 * on copies of the pages, read from the mappings at once
 * (redoPmemReadPages()). Phase 3 checks every record it reads and
 * invalidates a COMMIT after the restart's GCI in place; phase 4 zeroes
 * the log after the head and writes the last-file slot.
 * ========================================================================== */

PmemRedo::PartView Dblqh::redoPmemView(
    const LogPartRecord *logPartPtrP) const {
  ndbrequire(logPartPtrP->m_pmem_file_base != nullptr);
  const PmemRedo::Geom g = {logPartPtrP->noLogFiles, clogFileSize,
                            logPartPtrP->logPartNo};
  return PmemRedo::PartView{g, logPartPtrP->m_pmem_file_base};
}

/**
 * S6.1, E14: the pages of a read copied from the mapping into its log
 * pages, then FSREADCONF to this block as NDBFS sends it, so that the
 * restart goes on as after a read of the file.
 */
void Dblqh::redoPmemReadPages(Signal *signal, LogFileOperationRecordPtr lfoPtr,
                              const LogFileRecord *logFilePtrP,
                              LogPartRecord *logPartPtrP) {
  LogFileOperationRecord *const lfoP = lfoPtr.p;
  ndbrequire(logFilePtrP->m_pmem_base != nullptr &&
             lfoP->lfoPageNo + lfoP->noPagesRw <=
                 clogFileSize * ZPAGES_IN_MBYTE);
  for (Uint32 i = 0; i < lfoP->noPagesRw; i++) {
    LogPageRecordPtr pagePtr;
    pagePtr.i = i == 0 ? lfoP->firstLfoPage : lfoP->logPageArray[i];
    ptrCheckGuard(pagePtr, logPartPtrP->logPageFileSize,
                  logPartPtrP->logPageRecord);
    std::memcpy(pagePtr.p->logPageWord,
                redoPmemAddr(logFilePtrP, lfoP->lfoPageNo + i, 0),
                PmemRedo::PAGE_BYTES);
  }
  signal->theData[0] = lfoPtr.i;
  sendSignal(cownref, GSN_FSREADCONF, signal, 1, JBB);
}

/**
 * S6.3, S6.4: phase 1 of a system or node restart, on the mappings of the
 * log part, all open since OPENING_PMEM_MAP_ALL and closed for DBLQH. In
 * place of the reads of the file-mode phase 1:
 *   A  the control area of file 0: the configuration that the files were
 *      made for, and from the slot with the higher seq the last file f
 *      and its lap L;
 *   B  page 0 of f and the headers of its mbytes: the last mbyte written
 *      in L, and the GCIs of f's mbytes;
 *   C  the FDs in page 0 of the files before f, stepping back as
 *      readSrLastMbyteLab() does: the GCIs of their mbytes;
 *   D  the records from the last mbyte to E, the end of the valid log,
 *      also into the next file when its slot was not written (W3);
 *   E  the rest of E's mbyte zeroed: copies that persisted out of order
 *      leave no valid record after E for a later restart to find.
 * Then the part has completed phase 1, as when its last file closes.
 */
void Dblqh::redoPmemSrPhase1(Signal *signal, LogPartRecordPtr logPartPtr) {
  LogPartRecord *const partP = logPartPtr.p;
  const Uint32 noFiles = partP->noLogFiles;
  const Uint32 partNo = partP->logPartNo;
  ndbrequire(partP->m_pmem_file_base == nullptr);
  partP->m_pmem_file_base = new Uint8 *[noFiles];
  LogFileRecordPtr filePtr;
  filePtr.i = partP->firstLogfile;
  for (Uint32 f = 0; f < noFiles; f++) {
    ptrCheckGuard(filePtr, clogFileFileSize, logFileRecord);
    ndbrequire(filePtr.p->fileNo == f && filePtr.p->m_pmem_base != nullptr &&
               filePtr.p->logFileStatus == LogFileRecord::CLOSED);
    partP->m_pmem_file_base[f] = filePtr.p->m_pmem_base;
    filePtr.i = filePtr.p->nextLogFile;
  }
  const PmemRedo::PartView v = redoPmemView(partP);
  char msg[160];
  char buf[400];

  /* A */
  const Uint32 *const page00 = v.page(0, 0);
  const Uint32 ctrl = PmemRedo::checkCtrlConfig(
      page00 + PmemRedo::CTRL_CONFIG_WORD, v.g, globalData.ndbLogParts,
      getOwnNodeId(), msg, sizeof(msg));
  if (ctrl == PmemRedo::CTRL_NOT_PMEM) {
    BaseString::snprintf(buf, sizeof(buf),
                         "RedoLogMode=pmem: REDO log part %u was not written "
                         "in PMEM mode; changing RedoLogMode needs an "
                         "initial node restart",
                         partNo);
    progError(__LINE__, NDBD_EXIT_INVALID_CONFIG, buf);
  }
  if (ctrl == PmemRedo::CTRL_MISMATCH) {
    BaseString::snprintf(buf, sizeof(buf),
                         "RedoLogMode=pmem: REDO log part %u was written for "
                         "another configuration, %s; changing it needs an "
                         "initial node restart",
                         partNo, msg);
    progError(__LINE__, NDBD_EXIT_INVALID_CONFIG, buf);
  }
  if (ctrl != PmemRedo::CTRL_VALID) {
    BaseString::snprintf(buf, sizeof(buf),
                         "RedoLogMode=pmem: the control area of REDO log "
                         "part %u is not valid: %s",
                         partNo, msg);
    progError(__LINE__, NDBD_EXIT_SR_REDOLOG, buf);
  }
  PmemRedo::Slot slot;
  if (PmemRedo::pickSlot(page00 + PmemRedo::SLOT0_WORD,
                         page00 + PmemRedo::SLOT1_WORD, v.g, &slot) < 0) {
    BaseString::snprintf(buf, sizeof(buf),
                         "RedoLogMode=pmem: both last-file slots of REDO log "
                         "part %u are invalid",
                         partNo);
    progError(__LINE__, NDBD_EXIT_SR_REDOLOG, buf);
  }
  partP->m_pmem_slot_seq = slot.seq;
  redoPmemCheckDirtyShutdown(partP, slot);
  const Uint32 lastFileNo = slot.fileNo;
  const Uint32 lap = slot.lap;

  /* B */
  const PmemRedo::LastMbyte last =
      PmemRedo::findLastMbyte(v, lastFileNo, lap);
  PmemRedo::RecInfo info;
  Uint32 reason = last.reason;
  if (reason == PmemRedo::R_VALID) {
    reason = PmemRedo::checkRecord(
        v, PmemRedo::Pos{lastFileNo, 0, ZPAGE_HEADER_SIZE, lap}, &info);
  }
  if (reason != PmemRedo::R_VALID) {
    BaseString::snprintf(buf, sizeof(buf),
                         "RedoLogMode=pmem: page 0 of file %u, the last file "
                         "of REDO log part %u in lap %u, is not valid: %s",
                         lastFileNo, partNo, lap,
                         PmemRedo::reasonName(reason));
    progError(__LINE__, NDBD_EXIT_SR_REDOLOG, buf);
  }
  if (last.validAfterDrop) {
    BaseString::snprintf(buf, sizeof(buf),
                         "RedoLogMode=pmem: file %u of REDO log part %u has "
                         "an mbyte of lap %u after mbyte %u, the last one "
                         "written in it; the log is corrupt",
                         lastFileNo, partNo, lap, last.mbyte);
    progError(__LINE__, NDBD_EXIT_SR_REDOLOG, buf);
  }
  LogFileRecordPtr lastFilePtr;
  findLogfile(signal, lastFileNo, partP, &lastFilePtr);
  for (Uint32 mb = 0; mb < clogFileSize; mb++) {
    /* As readSrLastMbyteLab(), 0 where no header was stored */
    const Uint32 pageNo = mb * ZPAGES_IN_MBYTE;
    const Uint32 *const hdr = v.page(lastFileNo, pageNo);
    const bool valid = PmemRedo::checkPageHeader(hdr, lastFileNo, pageNo,
                                                 partNo) == PmemRedo::R_VALID;
    lastFilePtr.p->logMaxGciCompleted[mb] =
        valid ? hdr[PmemRedo::HDR_MAX_GCI_COMPLETED] : 0;
    lastFilePtr.p->logMaxGciStarted[mb] =
        valid ? hdr[PmemRedo::HDR_MAX_GCI_STARTED] : 0;
    lastFilePtr.p->logLastPrepRef[mb] =
        valid ? hdr[PmemRedo::HDR_LAST_PREP_REF] : 0;
  }

  /**
   * C. A page 0 is persistent before its file holds a record (W3), so it
   * is valid. Its lap may be L for a file after f: a restart zeroed that
   * file after the head, which it moved back to f; the GCIs read from it
   * are then of files after the head, which phase 3 does not read.
   */
  LogFileRecordPtr fdFilePtr = lastFilePtr;
  Uint32 fileNo = lastFileNo;
  for (Uint32 covered = 0; covered + 1 < noFiles;) {
    const Uint32 *const page0 = v.page(fileNo, 0);
    const Uint32 fdLap = page0[PmemRedo::HDR_LAP];
    reason = PmemRedo::checkPageHeader(page0, fileNo, 0, partNo);
    if (reason == PmemRedo::R_VALID && fdLap > lap) {
      reason = PmemRedo::R_HDR_LAP;
    }
    if (reason == PmemRedo::R_VALID) {
      reason = PmemRedo::checkRecord(
          v, PmemRedo::Pos{fileNo, 0, ZPAGE_HEADER_SIZE, fdLap}, &info);
    }
    if (reason != PmemRedo::R_VALID) {
      BaseString::snprintf(buf, sizeof(buf),
                           "RedoLogMode=pmem: page 0 of file %u of REDO log "
                           "part %u is not valid: %s",
                           fileNo, partNo, PmemRedo::reasonName(reason));
      progError(__LINE__, NDBD_EXIT_SR_REDOLOG, buf);
    }
    const Uint32 noFd = page0[ZPAGE_HEADER_SIZE + PmemRedo::FD_NO_FD];
    const Uint32 n = std::min(noFd - 1, noFiles - 1 - covered);
    ndbrequire(n > 0);
    redoPmemGciFromFd(page0, n, fdFilePtr);
    covered += n;
    fileNo = (fileNo + noFiles - n) % noFiles;
    findLogfile(signal, fileNo, partP, &fdFilePtr);
  }

  /* D */
  const PmemRedo::ScanResult scan =
      PmemRedo::findEnd(v, lastFileNo, last.mbyte, lap);
  partP->m_pmem_end = scan.end;
  partP->m_pmem_end_reason = scan.reason;
  /* ndb_redo_log_reader --find-end prints the same line */
  PmemRedo::formatEnd(buf, sizeof(buf), partNo, lastFileNo, lap, slot.seq,
                      last.mbyte, scan);
  g_eventLogger->info("LDM(%u): %s", instance(), buf);

  /* E. From the page start when no record of E's page is valid */
  Uint64 from = PmemRedo::posLsn(v.g, scan.end);
  if (scan.end.pageIndex == ZPAGE_HEADER_SIZE) {
    from -= 4 * ZPAGE_HEADER_SIZE;
  }
  const Uint64 mbyteBytes = Uint64(1) << 20;
  const Uint64 to = (from / mbyteBytes + 1) * mbyteBytes;
  /**
   * S7.1: error insert 5172 stops the node before the zeroing, so that
   * the next start must find the same E; 5167 after a random prefix of
   * it, not drained.
   */
  if (ERROR_INSERTED(5172)) {
    redoPmemCrashPoint(5172, partP,
                       "phase 1 found the end of the log, before its zeroing");
  }
  if (ERROR_INSERTED(5167)) {
    redoPmemSeed(5167);
    const Uint64 prefix = 8 * (redoPmemRand() % ((to - from) / 8 + 1));
    if (prefix > 0) redoPmemZero(partP, from, from + prefix);
    redoPmemCrashPoint(5167, partP,
                       "phase 1 zeroed a prefix of the log after its end");
  }
  redoPmemZero(partP, from, to);
  redoPmemDrain();

  partP->logLap = lap;
  partP->lastLogfile = lastFilePtr.i;
  partP->lastMbyte = last.mbyte;
  filePtr.i = partP->firstLogfile;
  ptrCheckGuard(filePtr, clogFileFileSize, logFileRecord);
  closingSrLab(signal, filePtr);
}

/**
 * E17, Q4: the dirty-shutdown count of the REDO path against the count
 * the slot recorded. A higher count means that the device lost writes it
 * had acknowledged as persistent. Step 1 reports it and records it in the
 * slots that this start writes; X6 makes the node stale. A device that
 * reports no count (nodax, memmap=) records none.
 */
void Dblqh::redoPmemCheckDirtyShutdown(LogPartRecord *logPartPtrP,
                                       const PmemRedo::Slot &slot) {
  const Uint32 pathNo = logPartPtrP->m_redo_path_no;
  ndbrequire(pathNo < NDB_ARRAY_SIZE(globalData.theRedoPmemPath));
  const Uint64 dsc = globalData.theRedoPmemPath[pathNo].dirty_shutdown;
  logPartPtrP->m_pmem_unsafe_shutdown = false;
  logPartPtrP->m_pmem_dsc_recorded = 0;
  logPartPtrP->m_pmem_dsc_flags = 0;
  if (dsc == ~Uint64(0)) return;
  if ((slot.flags & PmemRedo::SLOT_F_DSC_VALID) &&
      dsc > slot.dirtyShutdownCount) {
    jam();
    logPartPtrP->m_pmem_unsafe_shutdown = true;
    char buf[256];
    BaseString::snprintf(
        buf, sizeof(buf),
        "REDO log part %u: the persistent memory of REDO path %u reported "
        "an unsafe shutdown (dirty-shutdown count %llu, %llu when the "
        "last-file slot was written); REDO writes it acknowledged may be "
        "lost",
        logPartPtrP->logPartNo, pathNo, (unsigned long long)dsc,
        (unsigned long long)slot.dirtyShutdownCount);
    g_eventLogger->warning("LDM(%u): %s", instance(), buf);
    warningEvent("%s", buf);
  }
  logPartPtrP->m_pmem_dsc_recorded = dsc;
  logPartPtrP->m_pmem_dsc_flags =
      PmemRedo::SLOT_F_DSC_VALID |
      (logPartPtrP->m_pmem_unsafe_shutdown ? PmemRedo::SLOT_F_UNSAFE_SHUTDOWN
                                           : 0);
}

/**
 * As initGciInLogFileRec(), from an FD of the PMEM format in page 0 of
 * the file logFilePtr: the GCIs of the mbytes of the noFd files before it.
 * Descriptor 0, the file itself, was written before its mbytes.
 */
void Dblqh::redoPmemGciFromFd(const Uint32 *page0, Uint32 noFd,
                              LogFileRecordPtr logFilePtr) {
  const Uint32 *const arrays =
      page0 + ZPAGE_HEADER_SIZE + PmemRedo::FD_ARRAYS;
  LogFileRecordPtr filePtr = logFilePtr;
  for (Uint32 fd = 1; fd <= noFd; fd++) {
    filePtr.i = filePtr.p->prevLogFile;
    ptrCheckGuard(filePtr, clogFileFileSize, logFileRecord);
    const Uint32 *const a = arrays + fd * ZFD_MBYTE_SIZE * clogFileSize;
    for (Uint32 mb = 0; mb < clogFileSize; mb++) {
      filePtr.p->logMaxGciCompleted[mb] = a[mb];
      filePtr.p->logMaxGciStarted[mb] = a[clogFileSize + mb];
      filePtr.p->logLastPrepRef[mb] = a[2 * clogFileSize + mb];
    }
  }
}

/**
 * [from, to) of the log of a part zeroed, LSNs in one file. Page 0 of the
 * file is kept: it holds the FD, and in file 0 the control area. The
 * caller fences.
 */
void Dblqh::redoPmemZero(LogPartRecord *logPartPtrP, Uint64 from, Uint64 to) {
  const Uint64 fileBytes = Uint64(clogFileSize) << 20;
  ndbrequire(logPartPtrP->m_pmem_file_base != nullptr && from < to &&
             from / fileBytes == (to - 1) / fileBytes);
  const Uint32 fileNo = Uint32((from / fileBytes) % logPartPtrP->noLogFiles);
  Uint64 begin = from % fileBytes;
  const Uint64 end = begin + (to - from);
  if (begin < PmemRedo::PAGE_BYTES) begin = PmemRedo::PAGE_BYTES;
  if (begin < end) {
    Uint8 *const at = logPartPtrP->m_pmem_file_base[fileNo] + begin;
    ndb_pmem_zero(at, end - begin);
#if defined(VM_TRACE) || defined(ERROR_INSERT)
    /* S7.2, M3: the range reads as zero */
    Uint8 bits = 0;
    for (Uint64 i = 0; i < end - begin; i++) bits |= at[i];
    ndbrequire(bits == 0);
#endif
  }
}

/* S6.5: the log of a part cannot be read; the restart stops */
void Dblqh::redoPmemSrError(const LogPartRecord *logPartPtrP,
                            const PmemRedo::Pos &pos, Uint32 reason,
                            const char *what) {
  const PmemRedo::Pos &end = logPartPtrP->m_pmem_end;
  char buf[512];
  BaseString::snprintf(
      buf, sizeof(buf),
      "Error while reading REDO log: %s; log part %u, record at file %u "
      "page %u word %u in lap %u: %s; end of the log at file %u page %u "
      "word %u in lap %u (%s); last GCI %u%s",
      what, logPartPtrP->logPartNo, pos.fileNo, pos.pageNo, pos.pageIndex,
      pos.lap, PmemRedo::reasonName(reason), end.fileNo, end.pageNo,
      end.pageIndex, end.lap,
      PmemRedo::reasonName(logPartPtrP->m_pmem_end_reason),
      logPartPtrP->logLastGci,
      logPartPtrP->m_pmem_unsafe_shutdown
          ? "; the persistent memory reported an unsafe shutdown, restart "
            "this node with --initial"
          : "");
  g_eventLogger->info("LDM(%u): %s", instance(), buf);
  progError(__LINE__, NDBD_EXIT_SR_REDOLOG, buf);
}

/**
 * S6.5: a COMMIT of the PMEM format (format §5.2) after its w0: where its
 * PREPARE is, and its GCI. The replay uses neither gci_lo nor the
 * transid, as with readCommitLog().
 */
void Dblqh::readCommitLogPmem(CommitLogRecord *commitLogRecord,
                              const TcConnectionrecPtr tcConnectptr,
                              LogPageRecordPtr &logPagePtr,
                              LogFileRecord *logFilePtrP,
                              LogPartRecord *logPartPtrP) {
  ndbassert(!m_is_in_query_thread);
  Uint32 rec[PmemRedo::COMMIT_LEN];
  rec[0] = 0;
  for (Uint32 i = 1; i < PmemRedo::COMMIT_LEN; i++) {
    rec[i] = readLogword(logPagePtr, logFilePtrP, logPartPtrP);
  }
  tcConnectptr.p->tableref = rec[PmemRedo::COMMIT_TABLE_ID];
  tcConnectptr.p->schemaVersion = rec[PmemRedo::COMMIT_SCHEMA_VERSION];
  tcConnectptr.p->fragmentid = rec[PmemRedo::COMMIT_FRAG_ID];
  commitLogRecord->fileNo = rec[PmemRedo::COMMIT_PREP_FILE_INDEX] >> 16;
  commitLogRecord->startPageIndex =
      rec[PmemRedo::COMMIT_PREP_FILE_INDEX] & 0xFFFF;
  commitLogRecord->startPageNo = rec[PmemRedo::COMMIT_PREP_PAGES] >> 16;
  commitLogRecord->stopPageNo = rec[PmemRedo::COMMIT_PREP_PAGES] & 0xFFFF;
  tcConnectptr.p->gci_hi = rec[PmemRedo::COMMIT_GCI_HI];
  tcConnectptr.p->gci_lo = 0;
  tcConnectptr.p->transid[0] = logPartPtrP->ptrI + 65536;
  tcConnectptr.p->transid[1] = (DBLQH << 20) + (cownNodeid << 8);
}

/**
 * R6: the COMMIT at commitPos refers to a PREPARE that is valid where it
 * says, less than a lap before the COMMIT, and that ends in the page the
 * COMMIT names, so that readExecLog() reads all of it.
 */
void Dblqh::redoPmemCheckPrepare(const LogPartRecord *logPartPtrP,
                                 const PmemRedo::Pos &commitPos,
                                 const CommitLogRecord &commitLogRecord) {
  PmemRedo::Pos pos = {commitLogRecord.fileNo, commitLogRecord.startPageNo,
                       commitLogRecord.startPageIndex, 0};
  pos.lap = PmemRedo::lapAt(commitPos, pos.fileNo, pos.pageNo, pos.pageIndex);
  PmemRedo::RecInfo info;
  Uint32 reason =
      PmemRedo::checkRecord(redoPmemView(logPartPtrP), pos, &info);
  if (reason == PmemRedo::R_VALID) {
    const Uint32 lastPage = info.next.pageIndex == ZPAGE_HEADER_SIZE
                                ? info.next.pageNo - 1
                                : info.next.pageNo;
    if (PmemRedo::w0Type(info.w0) != PmemRedo::TYPE_PREPARE) {
      reason = PmemRedo::R_TYPE_UNKNOWN;
    } else if (info.next.fileNo != pos.fileNo ||
               lastPage != commitLogRecord.stopPageNo) {
      reason = PmemRedo::R_LEN;
    }
  }
  if (reason != PmemRedo::R_VALID) {
    redoPmemSrError(logPartPtrP, pos, reason,
                    "a COMMIT does not refer to a valid PREPARE");
  }
}

/**
 * E9, S6.5: a COMMIT of a GCI after the restart's cancelled in place, as
 * ZINVALID_COMMIT_TYPE cancels it in file mode: one aligned 4-byte store
 * of its w0 with RF_INVALIDATED, which the checksum does not cover, and
 * the write-back of its line. The fence is at the end of the round and
 * before phase 4 moves the head. A restart before it finds the same
 * COMMITs again and stores the same flag.
 */
void Dblqh::redoPmemInvalidateCommit(LogPartRecord *logPartPtrP,
                                     Uint32 fileNo, Uint32 pageNo,
                                     Uint32 pageIndex, Uint32 w0) {
  ndbrequire(PmemRedo::w0Type(w0) == PmemRedo::TYPE_COMMIT &&
             fileNo < logPartPtrP->noLogFiles &&
             logPartPtrP->m_pmem_file_base != nullptr);
  Uint32 *const addr = reinterpret_cast<Uint32 *>(
      logPartPtrP->m_pmem_file_base[fileNo] +
      Uint64(pageNo) * PmemRedo::PAGE_BYTES + 4 * pageIndex);
  ndbassert((*addr | PmemRedo::RF_INVALIDATED) ==
            (w0 | PmemRedo::RF_INVALIDATED));
  ndb_pmem_store32(addr, w0 | PmemRedo::RF_INVALIDATED);
  ndb_pmem_flush(addr, sizeof(Uint32));
  logPartPtrP->m_pmem_inval_pending++;
  /* S7.1: error insert 5169 after the N-th store, N its extra value or 1 */
  if (ERROR_INSERTED(5169) && redoPmemCountTo(5169)) {
    redoPmemCrashPoint(5169, logPartPtrP,
                       "a COMMIT invalidated, before the drain of its flag");
  }
}

/**
 * S6.6: phase 4 once the head H, the end of the COMPLETED_GCI of the
 * restart's GCI, is the write position (readSrFourthPhaseLab()). The
 * COMMITs that phase 3 invalidated are fenced, as the head moves back
 * over the GCIs they name. Then [ceilW(H), E) is zeroed, from the start
 * of H's page when no record of the page is before H, so that a later
 * restart finds no record after the head. At an initial start E is H.
 */
void Dblqh::redoPmemSrFourth(Signal *signal, LogPartRecord *logPartPtrP) {
  redoPmemDrain();
  logPartPtrP->m_pmem_inval_pending = 0;
  const PmemRedo::Geom g = {logPartPtrP->noLogFiles, clogFileSize,
                            logPartPtrP->logPartNo};
  const PmemRedo::Pos head = {logPartPtrP->headFileNo,
                              logPartPtrP->headPageNo,
                              logPartPtrP->headPageIndex, logPartPtrP->logLap};
  const PmemRedo::Pos &end = logPartPtrP->m_pmem_end;
  ndbrequire(PmemRedo::posLsn(g, head) <= PmemRedo::posLsn(g, end));
  Uint64 from = PmemRedo::posLsn(g, head);
  if (head.pageIndex == ZPAGE_HEADER_SIZE) {
    from -= 4 * ZPAGE_HEADER_SIZE;
  } else {
    from += 4 * PmemRedo::padWords(head.pageIndex);
  }
  Uint64 to = PmemRedo::posLsn(g, end);
  if (end.pageIndex == ZPAGE_HEADER_SIZE) to -= 4 * ZPAGE_HEADER_SIZE;
  logPartPtrP->m_pmem_zero_from = from;
  logPartPtrP->m_pmem_zero_to = std::max(from, to);
  logPartPtrP->m_pmem_zero_crash = 0;
  if (ERROR_INSERTED(5168)) {
    /* S7.1: stop the node after a random number of pages, from the end */
    redoPmemSeed(5168);
    const Uint64 bytes = logPartPtrP->m_pmem_zero_to - from;
    const Uint64 pages =
        (bytes + PmemRedo::PAGE_BYTES - 1) / PmemRedo::PAGE_BYTES;
    const Uint64 zeroed = PmemRedo::PAGE_BYTES * (redoPmemRand() % (pages + 1));
    logPartPtrP->m_pmem_zero_crash =
        std::max(from, logPartPtrP->m_pmem_zero_to - std::min(bytes, zeroed));
  }
  g_eventLogger->info(
      "LDM(%u): PMEM REDO log part %u: head at file %u page %u word %u in "
      "lap %u, %llu bytes to zero after it",
      instance(), logPartPtrP->logPartNo, head.fileNo, head.pageNo,
      head.pageIndex, head.lap,
      (unsigned long long)(logPartPtrP->m_pmem_zero_to - from));
  redoPmemSrZero(signal, logPartPtrP->ptrI);
}

/**
 * S6.6: one mbyte of the zeroing per signal, from the end backwards, each
 * fenced; page 0 of every file kept. A crash in between leaves the zeroed
 * bytes after the rest, so the next restart finds its end before them and
 * zeroes again. Then the write unit at H is closed as the GCP save closed
 * it, with the same FILLER or NEXT_MBYTE (W7), from the words before H in
 * the head page, which are the stored ones. Last the slot names the
 * head's file, where a later restart starts.
 */
void Dblqh::redoPmemSrZero(Signal *signal, Uint32 logPartPtrI) {
  LogPartRecordPtr logPartPtr;
  logPartPtr.i = logPartPtrI;
  ptrCheckGuard(logPartPtr, clogPartFileSize, logPartRecord);
  LogPartRecord *const partP = logPartPtr.p;
  const Uint64 from = partP->m_pmem_zero_from;
  if (partP->m_pmem_zero_to > from) {
    jam();
    const Uint64 mbyteBytes = Uint64(1) << 20;
    const Uint64 to = partP->m_pmem_zero_to;
    const Uint64 lo = std::max(from, ((to - 1) / mbyteBytes) * mbyteBytes);
    if (unlikely(partP->m_pmem_zero_crash >= lo)) {
      /* Error insert 5168: the batch zeroed down to the crash, no drain */
      const Uint64 crash = partP->m_pmem_zero_crash;
      if (crash < to) redoPmemZero(partP, crash, to);
      redoPmemCrashPoint(5168, partP,
                         "phase 4 zeroed a part of the log after the head");
    }
    redoPmemZero(partP, lo, to);
    redoPmemDrain();
    partP->m_pmem_zero_to = lo;
    if (lo > from) {
      jam();
      signal->theData[0] = ZPMEM_SR_ZERO;
      signal->theData[1] = logPartPtrI;
      sendSignal(cownref, GSN_CONTINUEB, signal, 2, JBB);
      return;
    }
  }
  /* S7.1: error inserts 5168 (nothing to zero), 5170, 5162 and 5163 */
  if (unlikely(partP->m_pmem_zero_crash != 0)) {
    redoPmemCrashPoint(5168, partP, "phase 4 had nothing to zero");
  }
  if (ERROR_INSERTED(5170)) {
    redoPmemCrashPoint(5170, partP,
                       "phase 4 zeroed the log after the head, before the "
                       "close of its write unit");
  }

  lock_log_part(partP);
  const Uint32 index = partP->headPageIndex;
  partP->m_pmem_persisted_lsn =
      redoLsn(partP, partP->headFileNo, partP->headPageNo,
              index == ZPAGE_HEADER_SIZE ? 0
                                         : index - index % PmemRedo::W_WORDS);
  redoPersist(signal, partP);
  redoInitWritePosition(partP);
  unlock_log_part(partP);

  LogFileRecordPtr logFilePtr;
  logFilePtr.i = partP->currentLogfile;
  ptrCheckGuard(logFilePtr, clogFileFileSize, logFileRecord);
  if (ERROR_INSERTED(5162)) redoPmemArmTear(5162);
  redoWriteLastFileSlot(partP, logFilePtr.p->fileNo, partP->logLap);
  if (ERROR_INSERTED(5163)) {
    redoPmemCrashPoint(5163, partP,
                       "the slot of phase 4 persistent, before the end of "
                       "phase 4");
  }
#if defined(VM_TRACE) || defined(ERROR_INSERT)
  /* S7.2, M3: a later restart finds the end of the log at the head */
  redoPmemAssertEnd(partP, "the end of phase 4");
#endif
  delete[] partP->m_pmem_file_base;
  partP->m_pmem_file_base = nullptr;
  signal->theData[0] = ZSR_FOURTH_COMP;
  signal->theData[1] = logPartPtrI;
  sendSignal(cownref, GSN_CONTINUEB, signal, 2, JBB);
}

/* ==========================================================================
 * RONDB-1150: the crash error inserts of the PMEM format and their torn
 * copy (recovery plan S7.1, S7.2 M1), the debug checks of what is claimed
 * persistent (S7.2 M3), and DUMP 2369
 *
 * A crash point stops the node with NDBD_EXIT_ERROR_INSERT, so that it
 * restarts as RestartOnErrorInsert says. A torn persist is armed before
 * its copies (redoPmemArmTear()) and stops the node at its fence, with
 * the copies torn by redoPmemCopyTorn(), or, with the power-loss
 * emulation (S7.3), copied and torn by the power loss of the crash.
 * ========================================================================== */

/**
 * A copy of the write path to the mapping. Torn while a crash error
 * insert has armed it and the power-loss emulation is off, which then
 * tears it at the crash.
 */
void Dblqh::redoPmemCopy(void *dst, const void *src, size_t len) {
#if defined(VM_TRACE) || defined(ERROR_INSERT)
  if (unlikely(c_redo_pmem_tear != 0) && !ndb_pmem_emul_active()) {
    redoPmemCopyTorn(static_cast<Uint8 *>(dst),
                     static_cast<const Uint8 *>(src), len);
    return;
  }
#endif
  ndb_pmem_copy_nt(dst, src, len);
}

/**
 * M1: a copy as a crash in the middle of it may leave it. Each 64-byte
 * line is copied with probability 500 per mille, torn (each 8-byte word
 * old or new) with 100, else left as it was, the values of DUMP 2370.
 * No flush and no fence: the crash follows at the fence. The stores stay
 * in the mapping after the crash on every host (memmap=, nodax), so the
 * restart finds what persistent memory may keep of a persist: holes
 * before valid data, orphans, torn records and torn page headers.
 */
void Dblqh::redoPmemCopyTorn(Uint8 *dst, const Uint8 *src, size_t len) {
  size_t done = 0;
  while (done < len) {
    const UintPtr at = reinterpret_cast<UintPtr>(dst + done);
    const size_t n =
        std::min<size_t>(len - done, NDB_PMEM_LINE - at % NDB_PMEM_LINE);
    const Uint64 r = redoPmemRand();
    const Uint32 p = Uint32(r % 1000);
    if (p < 500) {
      std::memcpy(dst + done, src + done, n);
    } else if (p < 600) {
      for (size_t w = 0; w < n; w += 8) {
        if ((r >> (32 + w / 8)) & 1) {
          std::memcpy(dst + done + w, src + done + w,
                      std::min<size_t>(8, n - w));
        }
      }
    }
    done += n;
  }
}

/**
 * The PRNG of a crash error insert: its seed is the insert's extra value
 * (a count for 5169 and 5171), else from the time. The crash writes it to
 * the node log, so that a run can be repeated.
 */
void Dblqh::redoPmemSeed(Uint32 code) {
  Uint32 seed = (code == 5169 || code == 5171) ? 0 : ERROR_INSERT_EXTRA;
  if (seed == 0) seed = Uint32(NdbTick_CurrentMillisecond()) | 1;
  c_redo_pmem_seed = seed;
  c_redo_pmem_rand = seed;
}

/* SplitMix64, as the power-loss emulation */
Uint64 Dblqh::redoPmemRand() {
  Uint64 z = (c_redo_pmem_rand += 0x9E3779B97F4A7C15ULL);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

/* The copies of this thread torn and its next fence a crash */
void Dblqh::redoPmemArmTear(Uint32 code) {
  if (c_redo_pmem_tear != 0) return;
  redoPmemSeed(code);
  c_redo_pmem_tear = code;
}

/**
 * 5169 and 5171: true at the K-th event since the insert was set, K its
 * extra value, else 1 for 5169 and random up to 1000 for 5171.
 */
bool Dblqh::redoPmemCountTo(Uint32 code) {
  if (c_redo_pmem_count_code != code) {
    redoPmemSeed(code);
    Uint32 count = ERROR_INSERT_EXTRA;
    if (count == 0) {
      count = code == 5169 ? 1 : 1 + Uint32(redoPmemRand() % 1000);
    }
    c_redo_pmem_count_code = code;
    c_redo_pmem_count = 0;
    c_redo_pmem_count_to = count;
  }
  return ++c_redo_pmem_count >= c_redo_pmem_count_to;
}

/**
 * The crash of an error insert. With the power-loss emulation the lines
 * not yet persistent are kept with probability 500 per mille, torn with
 * 100 and restored otherwise, from the insert's seed, the values of the
 * torn copy.
 */
void Dblqh::redoPmemCrashPoint(Uint32 code, const LogPartRecord *logPartPtrP,
                               const char *what) {
  if (c_redo_pmem_seed == 0) redoPmemSeed(code);
  const bool emul = ndb_pmem_emul_active();
  if (emul) ndb_pmem_emul_set_crash(c_redo_pmem_seed, 500, 100);
  char part[32] = "";
  if (logPartPtrP != nullptr) {
    BaseString::snprintf(part, sizeof(part), " in REDO log part %u",
                         logPartPtrP->logPartNo);
  }
  char buf[256];
  BaseString::snprintf(buf, sizeof(buf),
                       "PMEM REDO error insert %u: %s%s, seed %u%s", code,
                       what, part, c_redo_pmem_seed,
                       emul ? ", power loss keep 500 tear 100"
                       : c_redo_pmem_tear == code ? ", copy torn"
                                                  : "");
  g_eventLogger->info("LDM(%u): %s", instance(), buf);
  progError(__LINE__, NDBD_EXIT_ERROR_INSERT, buf);
}

/**
 * M3: the log of the part persistent up to lsn and nothing stored without
 * its fence, where it is claimed: GCP_SAVECONF.
 */
void Dblqh::redoPmemAssertPersisted(const LogPartRecord *logPartPtrP,
                                    Uint64 lsn, const char *what) {
  if (logPartPtrP->m_pmem_persisted_lsn >= lsn &&
      logPartPtrP->m_pmem_unfenced == 0) {
    return;
  }
  char buf[256];
  BaseString::snprintf(
      buf, sizeof(buf),
      "PMEM REDO log part %u: %s claims the log persistent up to LSN %llu; "
      "persisted LSN %llu, %u bytes not fenced",
      logPartPtrP->logPartNo, what, (unsigned long long)lsn,
      (unsigned long long)logPartPtrP->m_pmem_persisted_lsn,
      logPartPtrP->m_pmem_unfenced);
  progError(__LINE__, NDBD_EXIT_PRGERR, buf);
}

/**
 * M3 at the end of phase 4: the restart's scan from the start of the
 * head's mbyte ends at the persisted position, the head with its unit
 * closed, as in redoPmemVerify(). A later restart then finds E there.
 * An initial start runs phase 4 without phase 1, so the view is built
 * from the mappings of the files, which every file has from its first
 * open.
 */
void Dblqh::redoPmemAssertEnd(LogPartRecord *logPartPtrP, const char *what) {
  const Uint32 noFiles = logPartPtrP->noLogFiles;
  const Uint8 **bases = new const Uint8 *[noFiles];
  LogFileRecordPtr filePtr;
  filePtr.i = logPartPtrP->firstLogfile;
  for (Uint32 f = 0; f < noFiles; f++) {
    ptrCheckGuard(filePtr, clogFileFileSize, logFileRecord);
    ndbrequire(filePtr.p->fileNo == f && filePtr.p->m_pmem_base != nullptr);
    bases[f] = filePtr.p->m_pmem_base;
    filePtr.i = filePtr.p->nextLogFile;
  }
  filePtr.i = logPartPtrP->currentLogfile;
  ptrCheckGuard(filePtr, clogFileFileSize, logFileRecord);
  const PmemRedo::Geom g = {noFiles, clogFileSize, logPartPtrP->logPartNo};
  const PmemRedo::PartView v = {g, bases};
  const PmemRedo::ScanResult r = PmemRedo::findEnd(
      v, filePtr.p->fileNo, filePtr.p->currentMbyte, logPartPtrP->logLap);
  delete[] bases;
  Uint64 end = PmemRedo::posLsn(g, r.end);
  if (r.end.pageIndex == ZPAGE_HEADER_SIZE) end -= 4 * ZPAGE_HEADER_SIZE;
  const Uint64 persisted = logPartPtrP->m_pmem_persisted_lsn;
  if (end == persisted && logPartPtrP->m_pmem_unfenced == 0) return;
  char buf[256];
  BaseString::snprintf(
      buf, sizeof(buf),
      "PMEM REDO log part %u: at %s the log ends at file %u page %u word %u "
      "(%s), LSN %llu, not at the persisted LSN %llu",
      logPartPtrP->logPartNo, what, r.end.fileNo, r.end.pageNo,
      r.end.pageIndex, PmemRedo::reasonName(r.reason),
      (unsigned long long)end, (unsigned long long)persisted);
  progError(__LINE__, NDBD_EXIT_PRGERR, buf);
}

/**
 * M3 after the fence of redoCopyOut(): the log of the current file in
 * [from, to) reads in the mapping as in the log pages that hold it, the
 * filled pages and then the current page up to its index, a page header
 * as its image. It finds a persisted LSN moved over bytes that were never
 * copied, which the power-loss emulation cannot see.
 */
void Dblqh::redoPmemVerifyCopy(LogPartRecord *logPartPtrP,
                               const LogFileRecord *logFilePtrP, Uint64 from,
                               Uint64 to) {
  const Uint64 fileStart = redoLsn(logPartPtrP, logFilePtrP->fileNo, 0, 0);
  ndbrequire(from >= fileStart && from <= to);
  const Uint32 toPage = Uint32((to - fileStart) / PmemRedo::PAGE_BYTES);
  const Uint32 toWord = Uint32((to - fileStart) % PmemRedo::PAGE_BYTES) / 4;
  Uint32 pageNo = Uint32((from - fileStart) / PmemRedo::PAGE_BYTES);
  Uint32 word = Uint32((from - fileStart) % PmemRedo::PAGE_BYTES) / 4;
  LogPageRecordPtr pagePtr;
  pagePtr.i = logFilePtrP->firstFilledPage != RNIL
                  ? logFilePtrP->firstFilledPage
                  : logFilePtrP->currentLogpage;
  bool ok = true;
  while (ok && (pageNo < toPage || (pageNo == toPage && word < toWord))) {
    ptrCheckGuard(pagePtr, logPartPtrP->logPageFileSize,
                  logPartPtrP->logPageRecord);
    const Uint32 *const page = pagePtr.p->logPageWord;
    const Uint32 end = pageNo < toPage ? ZPAGE_SIZE : toWord;
    ok = end <= page[ZCURR_PAGE_INDEX];
    if (ok && word == 0) {
      alignas(PmemRedo::W_BYTES) Uint32 img[ZPAGE_HEADER_SIZE];
      redoPmemHeaderImage(img, pagePtr.p, logFilePtrP->fileNo, pageNo,
                          logPartPtrP);
      ok = std::memcmp(redoPmemAddr(logFilePtrP, pageNo, 0), img,
                       sizeof(img)) == 0;
      word = ZPAGE_HEADER_SIZE;
    }
    if (ok && end > word) {
      ok = std::memcmp(redoPmemAddr(logFilePtrP, pageNo, word), &page[word],
                       4 * (end - word)) == 0;
    }
    if (!ok) break;
    pageNo++;
    word = 0;
    pagePtr.i = pagePtr.i == logFilePtrP->lastFilledPage
                    ? logFilePtrP->currentLogpage
                    : page[ZNEXT_PAGE];
  }
  if (ok) return;
  char buf[256];
  BaseString::snprintf(
      buf, sizeof(buf),
      "PMEM REDO log part %u: file %u page %u in the mapping is not the log "
      "page copied to it, persist from LSN %llu to %llu",
      logPartPtrP->logPartNo, logFilePtrP->fileNo, pageNo,
      (unsigned long long)from, (unsigned long long)to);
  progError(__LINE__, NDBD_EXIT_PRGERR, buf);
}

/**
 * DUMP 2369 (S7.1): the state of a log part to the node and cluster logs:
 * the config line and the last-file slot of the control area, the end E
 * that the last restart found, the head, the persisted LSN, the last
 * COMPLETED_GCI and whether it is persistent, and the COMMIT flag stores
 * of a restart not yet fenced.
 */
void Dblqh::redoPmemPrintInfo(LogPartRecord *logPartPtrP) {
  const Uint32 partNo = logPartPtrP->logPartNo;
  const PmemRedo::Geom g = {logPartPtrP->noLogFiles, clogFileSize, partNo};
  LogFileRecordPtr file0Ptr;
  file0Ptr.i = logPartPtrP->firstLogfile;
  ptrCheckGuard(file0Ptr, clogFileFileSize, logFileRecord);
  char ctrl[160] = "not mapped";
  char slot[96] = "";
  lock_log_part(logPartPtrP);
  if (file0Ptr.p->m_pmem_base != nullptr) {
    const Uint32 *const page00 =
        reinterpret_cast<const Uint32 *>(file0Ptr.p->m_pmem_base);
    char msg[128];
    if (PmemRedo::checkCtrlConfig(page00 + PmemRedo::CTRL_CONFIG_WORD, g,
                                  globalData.ndbLogParts, getOwnNodeId(), msg,
                                  sizeof(msg)) == PmemRedo::CTRL_VALID) {
      BaseString::snprintf(ctrl, sizeof(ctrl), "valid");
    } else {
      BaseString::snprintf(ctrl, sizeof(ctrl), "not valid: %s", msg);
    }
    PmemRedo::Slot s;
    const int index = PmemRedo::pickSlot(page00 + PmemRedo::SLOT0_WORD,
                                         page00 + PmemRedo::SLOT1_WORD, g, &s);
    if (index < 0) {
      BaseString::snprintf(slot, sizeof(slot), ", no valid last-file slot");
    } else {
      BaseString::snprintf(slot, sizeof(slot),
                           ", slot %d seq %llu names file %u in lap %u",
                           index, (unsigned long long)s.seq, s.fileNo, s.lap);
    }
  }
  LogFileRecordPtr filePtr;
  filePtr.i = logPartPtrP->currentLogfile;
  ptrCheckGuard(filePtr, clogFileFileSize, logFileRecord);
  LogPageRecordPtr pagePtr;
  pagePtr.i = filePtr.p->currentLogpage;
  ptrCheckGuard(pagePtr, logPartPtrP->logPageFileSize,
                logPartPtrP->logPageRecord);
  const Uint32 headFileNo = filePtr.p->fileNo;
  const Uint32 headPageNo = filePtr.p->currentFilepage;
  const Uint32 headIndex = pagePtr.p->logPageWord[ZCURR_PAGE_INDEX];
  const Uint32 lap = logPartPtrP->logLap;
  const Uint64 persisted = logPartPtrP->m_pmem_persisted_lsn;
  const Uint32 gci = logPartPtrP->logPartNewestCompletedGCI;
  const Uint64 gciEnd = logPartPtrP->m_pmem_gci_end_lsn;
  unlock_log_part(logPartPtrP);

  char buf[400];
  const PmemRedo::Pos &e = logPartPtrP->m_pmem_end;
  char end[160] = "none since an initial start";
  if (e.lap != 0) {
    BaseString::snprintf(
        end, sizeof(end), "file %u page %u word %u lap %u (%s)", e.fileNo,
        e.pageNo, e.pageIndex, e.lap,
        PmemRedo::reasonName(logPartPtrP->m_pmem_end_reason));
  }
  BaseString::snprintf(buf, sizeof(buf),
                       "PMEM REDO log part %u: control area %s%s; end of the "
                       "log at the last restart %s",
                       partNo, ctrl, slot, end);
  g_eventLogger->info("LDM(%u): %s", instance(), buf);
  infoEvent("%s", buf);
  char gciText[64] = "none since the start";
  if (gciEnd != 0) {
    BaseString::snprintf(gciText, sizeof(gciText), "%u, %s", gci,
                         persisted >= gciEnd ? "persistent" : "not persistent");
  }
  BaseString::snprintf(
      buf, sizeof(buf),
      "PMEM REDO log part %u: head at file %u page %u word %u lap %u, "
      "persisted LSN %llu; last COMPLETED_GCI %s; %u COMMIT flag stores not "
      "fenced",
      partNo, headFileNo, headPageNo, headIndex, lap,
      (unsigned long long)persisted, gciText,
      logPartPtrP->m_pmem_inval_pending);
  g_eventLogger->info("LDM(%u): %s", instance(), buf);
  infoEvent("%s", buf);
}

/**
 * RONDB-1150, PMEM format: the words that a COMMIT, COMPLETE or ABORT
 * record of the operation gives back (PmemRedo::releasedWords()). A
 * durable COMMIT (X4) keeps the COMPLETE's part, any other gives back
 * all of them.
 */
void Dblqh::release_committed_words(LogPartRecord *logPartPtrP,
                                    TcConnectionrec *regTcPtr,
                                    PmemRedo::RedoRelease what, bool durable) {
  Uint32 after;
  const Uint32 words = PmemRedo::releasedWords(
      regTcPtr->m_committed_log_space, what, durable, &after);
  ndbrequire(words != 0);
  ndbassert(logPartPtrP->m_committed_words >= words);
  logPartPtrP->m_committed_words -= words;
  regTcPtr->m_committed_log_space = Uint8(after);
}

/* ==========================================================================
 * RONDB-1150, PMEM mode: the REDO log files, which NDBFS maps and keeps
 * open from their first open until the node stops
 * ========================================================================== */

/**
 * RONDB-1150, PMEM mode: SR and NR open and map every file of the log
 * part before reading file 0, so that the whole REDO log is mapped from
 * the start and every later open is openKeptRedoFile(). The opens run in
 * parallel, one IO thread each. When the last is open, file 0 is opened
 * as without PMEM, through openKeptRedoFile().
 */
void Dblqh::openAllRedoFilesPmem(Signal *signal, LogPartRecord *logPartPtrP) {
  ndbrequire(logPartPtrP->m_pmem_files_to_map == 0);
  logPartPtrP->m_pmem_files_to_map = logPartPtrP->noLogFiles;
  LogFileRecordPtr filePtr;
  filePtr.i = logPartPtrP->firstLogfile;
  for (Uint32 f = 0; f < logPartPtrP->noLogFiles; f++) {
    jam();
    ptrCheckGuard(filePtr, clogFileFileSize, logFileRecord);
    ndbrequire(filePtr.p->logFileStatus == LogFileRecord::CLOSED &&
               filePtr.p->m_pmem_fileRef == RNIL);
    filePtr.p->logFileStatus = LogFileRecord::OPENING_PMEM_MAP_ALL;
    openFileRw(signal, filePtr, false); /* No write buffering */
    filePtr.i = filePtr.p->nextLogFile;
  }
  ndbrequire(filePtr.i == logPartPtrP->firstLogfile);
}

/**
 * RONDB-1150, PMEM mode: a REDO log file found under another REDO path
 * than asked for (a changed CPU binding, NUMA layout or path list) is
 * used there; the part's next files are asked for there too. Memory on
 * another NUMA node than the LDM thread works, more slowly. One warning
 * each per log part.
 */
void Dblqh::checkRedoPmemPlacement(LogPartRecord *logPartPtrP,
                                   Uint32 fileInfo) {
  const Uint32 path_no =
      (fileInfo >> FsConf::REDO_PATH_SHIFT) & FsConf::REDO_PATH_MASK;
  if (path_no != logPartPtrP->m_redo_path_no) {
    jam();
    if (!logPartPtrP->m_redo_path_warned) {
      logPartPtrP->m_redo_path_warned = true;
      char asked[32];
      char found[32];
      BaseString::snprintf(asked, sizeof(asked), "REDO path %u",
                           logPartPtrP->m_redo_path_no);
      BaseString::snprintf(found, sizeof(found), "REDO path %u", path_no);
      g_eventLogger->warning(
          "LDM(%u): the REDO log files of log part %u were found under %s, "
          "not under %s; they stay there until an initial start",
          instance(), logPartPtrP->logPartNo,
          path_no == FsOpenReq::REDO_PATH_FS ? "FileSystemPath" : found,
          logPartPtrP->m_redo_path_no == FsOpenReq::REDO_PATH_FS
              ? "FileSystemPath"
              : asked);
    }
    logPartPtrP->m_redo_path_no = Uint8(path_no);
  }
  const Uint32 numa = fileInfo >> FsConf::PMEM_NUMA_SHIFT;
  if (numa != 0 && logPartPtrP->m_pmem_mem_numa_node < 0) {
    jam();
    const Int32 mem_node = Int32(numa) - 1;
    logPartPtrP->m_pmem_mem_numa_node = mem_node;
    if (c_ldm_numa_node >= 0 && mem_node != c_ldm_numa_node) {
      g_eventLogger->warning(
          "LDM(%u): runs on NUMA node %d, but the REDO log of log part %u is "
          "in memory of NUMA node %d; every REDO write crosses NUMA nodes",
          instance(), c_ldm_numa_node, logPartPtrP->logPartNo, mem_node);
    }
  }
}

/**
 * RONDB-1150, PMEM mode: NDBFS maps the REDO log file, under the REDO
 * path of its log part. The caller may be an LDM that shares the part,
 * so only the part is read. No write buffer, which only joins the pages
 * of a write: NDBFS keeps every file open (closeFile()), and
 * RG_FILE_BUFFERS has room for 4 of them per log part (ndbd.cpp).
 */
void Dblqh::setRedoPmemOpenFlags(FsOpenReq *req,
                                 const LogPartRecord *logPartPtrP) const {
  req->fileFlags &= ~FsOpenReq::OM_WRITE_BUFFER;
  req->fileFlags |= FsOpenReq::OM_MAP_SYNC | FsOpenReq::OM_REDO_PATH;
  FsOpenReq::setRedoPathNo(req->secondFileFlags, logPartPtrP->m_redo_path_no);
}

/**
 * RONDB-1150, PMEM mode: open a REDO log file that NDBFS keeps open
 * since its first open (closeFile()). The owner of the log part gets an
 * FSOPENCONF without the mapping words, as from openFileRw_cache(), and
 * execFSOPENCONF() continues as after an open by NDBFS. The caller may
 * be an LDM that shares the part; the file's fields it reads are set
 * under the part's lock.
 */
void Dblqh::openKeptRedoFile(Signal *signal, LogFileRecordPtr filePtr,
                             BlockReference ownerRef) {
  ndbrequire(filePtr.p->fileRef == RNIL &&
             filePtr.p->m_pmem_fileRef != RNIL);
  signal->theData[0] = filePtr.i;
  signal->theData[1] = filePtr.p->m_pmem_fileRef;
  sendSignal(ownerRef, GSN_FSOPENCONF, signal, 2, JBB);
}
