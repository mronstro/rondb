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

/**
 * RONDB-1150, step 1 plan S4.2-S4.7: the records as the DBLQH writers
 * build them (PmemRedoFormat.hpp). The record builders; the checksum of
 * a record that a page end splits, from a buffer as redoAppendFixed()
 * takes it and where the record lies in the log pages as
 * writePrepareLogPmem() takes it; the FILLER that closes a unit; and the
 * reservation. Every record is put in log pages as writeLogWords() puts
 * it, and checked by the restart scan's own reader (PmemRedoScan.cpp).
 */

#include <ndb_global.h>
#include <util/NdbTap.hpp>

#include <algorithm>
#include <cstring>
#include <vector>

#include "PmemRedoScan.hpp"

using namespace PmemRedo;

namespace {

constexpr Uint32 LAP = 3;
constexpr Uint32 PART = 5;
constexpr Uint32 FILE_NO = 1;
constexpr Uint32 NODE_ID = 7;

bool samePos(const Pos &a, const Pos &b) {
  return a.fileNo == b.fileNo && a.pageNo == b.pageNo &&
         a.pageIndex == b.pageIndex && a.lap == b.lap;
}

Pos at(Uint32 pageNo, Uint32 pageIndex) {
  return Pos{FILE_NO, pageNo, pageIndex, LAP};
}

Suffix suffixAt(const Pos &p) {
  return suffix(p.lap, PART, p.fileNo, p.pageNo, p.pageIndex);
}

/**
 * A log part of 2 files of 1 MB. The records go in mbyte 0 of file 1,
 * pages 1-31, whose headers are those of LAP, as the copy-out stores them.
 */
class Log {
 public:
  Log() : m_g{2, 1, PART}, m_files(2), m_bases(2) {
    for (Uint32 f = 0; f < 2; f++) {
      m_files[f].assign(size_t(m_g.pagesInFile()) * PAGE_WORDS, 0);
      m_bases[f] = reinterpret_cast<const Uint8 *>(m_files[f].data());
    }
  }

  PartView view() const { return PartView{m_g, m_bases.data()}; }

  Uint32 *page(Uint32 pageNo) {
    return m_files[FILE_NO].data() + size_t(pageNo) * PAGE_WORDS;
  }

  /* Pages first to last zeroed, each with its header */
  void clear(Uint32 first, Uint32 last) {
    for (Uint32 p = first; p <= last; p++) {
      Uint32 *const words = page(p);
      memset(words, 0, PAGE_BYTES);
      Uint32 dram[HEADER_WORDS] = {0};
      dram[HDR_LAP] = LAP;
      dram[HDR_NO_LOG_FILES] = m_g.noFiles;
      buildPageHeader(words, dram, FILE_NO, p, PART, NODE_ID);
    }
  }

  /**
   * n words from p on, as writeLogWords(): at a page end they go on at
   * word 32 of the next page. Returns where the next record goes.
   */
  Pos put(Pos p, const Uint32 *words, Uint32 n) {
    while (n > 0) {
      if (p.pageIndex == PAGE_WORDS) p = at(p.pageNo + 1, HEADER_WORDS);
      const Uint32 k = std::min(n, PAGE_WORDS - p.pageIndex);
      memcpy(page(p.pageNo) + p.pageIndex, words, 4 * k);
      p.pageIndex += k;
      words += k;
      n -= k;
    }
    if (p.pageIndex == PAGE_WORDS) p = at(p.pageNo + 1, HEADER_WORDS);
    return p;
  }

 private:
  const Geom m_g;
  std::vector<std::vector<Uint32>> m_files;
  std::vector<const Uint8 *> m_bases;
};

/* The words of each builder, and the record accepted in one page */
void builders() {
  const Pos p = at(4, 100);
  const Suffix s = suffixAt(p);

  Uint32 rec[COMMIT_LEN];
  commitRecord(rec, CF_DURABLE, 11, 12, 13, 2, 300, 4000, 301, 14, 15, 16,
               17, 18);
  OK(rec[0] == makeW0(TYPE_COMMIT, CF_DURABLE, COMMIT_LEN) && rec[1] == 0);
  OK(rec[COMMIT_TABLE_ID] == 11 && rec[COMMIT_SCHEMA_VERSION] == 12 &&
     rec[COMMIT_FRAG_ID] == 13);
  OK(rec[COMMIT_PREP_FILE_INDEX] == ((2u << 16) | 4000));
  OK(rec[COMMIT_PREP_PAGES] == ((300u << 16) | 301));
  OK(rec[COMMIT_GCI_HI] == 14 && rec[COMMIT_GCI_LO] == 15);
  OK(rec[COMMIT_TRANSID1] == 16 && rec[COMMIT_TRANSID2] == 17 &&
     rec[COMMIT_OP_COUNT] == 18);
  rec[1] = recordChecksum(rec, s);
  OK(checkRecordWords(rec, COMMIT_LEN, s) == R_VALID);

  abortRecord(rec, AF_AFTER_COMMIT, 21, 22);
  OK(rec[0] == makeW0(TYPE_ABORT, AF_AFTER_COMMIT, ABORT_LEN) &&
     rec[1] == 0 && rec[ABORT_TRANSID1] == 21 && rec[ABORT_TRANSID2] == 22);
  rec[1] = recordChecksum(rec, s);
  OK(checkRecordWords(rec, ABORT_LEN, s) == R_VALID);

  completeRecord(rec, 31, 32);
  OK(rec[0] == makeW0(TYPE_COMPLETE, 0, COMPLETE_LEN) && rec[1] == 0 &&
     rec[ABORT_TRANSID1] == 31 && rec[ABORT_TRANSID2] == 32);
  rec[1] = recordChecksum(rec, s);
  OK(checkRecordWords(rec, COMPLETE_LEN, s) == R_VALID);

  completedGciRecord(rec, 41);
  OK(rec[0] == makeW0(TYPE_COMPLETED_GCI, 0, COMPLETED_GCI_LEN) &&
     rec[1] == 0 && rec[COMPLETED_GCI_GCI] == 41 && rec[3] == 0);
  rec[1] = recordChecksum(rec, s);
  OK(checkRecordWords(rec, COMPLETED_GCI_LEN, s) == R_VALID);

  /* A PREPARE: the header, key, attrinfo and the pad word */
  const Uint32 keyLen = 3;
  const Uint32 aiLen = 6;
  const Uint32 len = prepareLen(keyLen, aiLen, false);
  OK(len == PREPARE_HEAD + keyLen + aiLen + 1);
  std::vector<Uint32> prep(len, 0);
  prepareHead(prep.data(), 0, len, 51, 52, aiLen, keyLen, 53, 54);
  OK(prep[0] == makeW0(TYPE_PREPARE, 0, len) && prep[1] == 0);
  OK(prep[PREP_HASH_VALUE] == 51 && prep[PREP_OPERATION] == 52 &&
     prep[PREP_AI_LEN] == aiLen && prep[PREP_KEY_LEN] == keyLen &&
     prep[PREP_ROWID_PAGE] == 53 && prep[PREP_ROWID_IDX] == 54);
  for (Uint32 i = PREPARE_HEAD; i < len - 1; i++) prep[i] = 0x1000 + i;
  prep[1] = recordChecksum(prep.data(), s);
  OK(checkRecordWords(prep.data(), len, s) == R_VALID);
}

/**
 * The records of fixed length, at every place from inside a page to the
 * last word pair, their checksum split where the page ends, as
 * redoAppendFixed() takes it. Where both pieces hold words, the checksum of
 * the whole body in one piece is rejected.
 */
void fixedRecords(Log &log) {
  Uint32 recs[5][COMMIT_LEN];
  commitRecord(recs[0], 0, 11, 12, 13, 0, 300, 4000, 301, 14, 15, 16, 17, 0);
  abortRecord(recs[1], 0, 21, 22);
  completeRecord(recs[2], 31, 32);
  completedGciRecord(recs[3], 41);
  recs[4][0] = makeW0(TYPE_SR_HEAD, 0, SR_HEAD_LEN);
  for (Uint32 i = 2; i < SR_HEAD_LEN; i++) recs[4][i] = 60 + i;

  const Uint32 pageNo = 4;
  for (const Uint32 *r : recs) {
    const Uint32 len = w0Len(r[0]);
    for (Uint32 index = PAGE_WORDS - len - 4; index <= PAGE_WORDS - 2;
         index += 2) {
      log.clear(pageNo, pageNo + 1);
      const Pos p = at(pageNo, index);
      const Uint32 inFirst = PAGE_WORDS - index;
      Uint32 rec[COMMIT_LEN];
      memcpy(rec, r, 4 * len);
      rec[1] = splitChecksum(rec, inFirst, suffixAt(p));
      const Pos end = log.put(p, rec, len);
      RecInfo info;
      OK(checkRecord(log.view(), p, &info) == R_VALID);
      OK(info.w0 == rec[0] && samePos(info.next, end));
      OK(pagesSpanned(index, len) == (len > inFirst ? 2u : 1u));

      if (inFirst > 2 && inFirst < len) {
        rec[1] = recordChecksum(rec, suffixAt(p));
        log.put(p, rec, 2);
        OK(checkRecord(log.view(), p, &info) == R_CHECKSUM);
      }
    }
  }
}

/**
 * PREPAREs of 1 to 4 pages from places in their first page, put in the
 * log pages and their checksum taken there, page by page, as
 * writePrepareLogPmem() takes it. The checksum of the body in one piece,
 * as the source sections hold it, is rejected once two pages hold body
 * words: the pieces are the page segments (F4).
 */
void prepares(Log &log) {
  const Uint32 sizes[][2] = {{1, 0},
                             {3, 200},
                             {5, 9000},
                             {2, 17000},
                             {MAX_KEY_SIZE_IN_WORDS, 0},
                             {MAX_KEY_SIZE_IN_WORDS,
                              MAX_LOG_RECORD_SIZE_WORDS}};
  const Uint32 indexes[] = {HEADER_WORDS, 4000, PAGE_WORDS - 100,
                            PAGE_WORDS - 4, PAGE_WORDS - 2};
  const Uint32 firstPage = 2;
  for (const auto &size : sizes) {
    const Uint32 keyLen = size[0];
    const Uint32 aiLen = size[1];
    const Uint32 len = prepareLen(keyLen, aiLen, false);
    OK(len <= PREPARE_MAX);
    std::vector<Uint32> rec(len, 0);
    prepareHead(rec.data(), 0, len, 51, 52, aiLen, keyLen, 53, 54);
    for (Uint32 i = PREPARE_HEAD; i < PREPARE_HEAD + keyLen + aiLen; i++)
      rec[i] = 0x9E3779B1u * i;

    for (Uint32 index : indexes) {
      const Uint32 noPages = pagesSpanned(index, len);
      OK(noPages <= PREPARE_MAX_PAGES);
      log.clear(firstPage, firstPage + PREPARE_MAX_PAGES);
      const Pos p = at(firstPage, index);
      const Pos end = log.put(p, rec.data(), len);
      OK(end.pageNo - firstPage + (end.pageIndex == HEADER_WORDS ? 0 : 1) ==
         noPages);

      const Uint32 *pages[PREPARE_MAX_PAGES];
      for (Uint32 i = 0; i < noPages; i++) pages[i] = log.page(firstPage + i);
      log.page(firstPage)[index + 1] = pagedChecksum(pages, index, suffixAt(p));
      RecInfo info;
      OK(checkRecord(log.view(), p, &info) == R_VALID);
      OK(info.w0 == rec[0] && samePos(info.next, end));

      const Uint32 pieces = (PAGE_WORDS - index > 2 ? 1 : 0) + noPages - 1;
      if (pieces > 1) {
        log.page(firstPage)[index + 1] = recordChecksum(rec.data(),
                                                        suffixAt(p));
        OK(checkRecord(log.view(), p, &info) == R_CHECKSUM);
      }
    }
  }
  OK(pagesSpanned(PAGE_WORDS - 2, PREPARE_MAX) == PREPARE_MAX_PAGES);
  OK(pagesSpanned(HEADER_WORDS, PAGE_DATA_WORDS) == 1);
  OK(pagesSpanned(HEADER_WORDS, PAGE_DATA_WORDS + 2) == 2);
}

/**
 * The FILLER of writeFillerPmem() that closes a unit, at every even word
 * not on a W boundary: accepted, and the next record on the boundary.
 */
void fillers(Log &log) {
  const Uint32 pageNo = 6;
  log.clear(pageNo, pageNo + 1);
  for (Uint32 index = HEADER_WORDS; index < PAGE_WORDS; index += 2) {
    const Uint32 len = padWords(index);
    if (len == 0) continue;
    OK(len >= FILLER_MIN && len <= FILLER_MAX);
    const Pos p = at(pageNo, index);
    Uint32 rec[FILLER_MAX] = {0};
    rec[0] = makeW0(TYPE_FILLER, 0, len);
    rec[1] = recordChecksum(rec, suffixAt(p));
    const Pos end = log.put(p, rec, len);
    RecInfo info;
    OK(checkRecord(log.view(), p, &info) == R_VALID);
    OK(samePos(info.next, end));
    OK(end.pageIndex % W_WORDS == 0);
  }
}

/* The reservation of S4.7, and what it covers */
void reservation() {
  Uint32 after;
  OK(releasedWords(RESERVED_FULL, AT_COMMIT, false, &after) == RESERVE &&
     after == RESERVED_NONE);
  OK(releasedWords(RESERVED_FULL, AT_ABORT, false, &after) == RESERVE &&
     after == RESERVED_NONE);
  OK(releasedWords(RESERVED_FULL, AT_COMMIT, true, &after) ==
         RESERVE_AT_COMMIT &&
     after == RESERVED_TAIL);
  OK(releasedWords(RESERVED_TAIL, AT_COMPLETE, true, &after) == 20 &&
     after == RESERVED_NONE);
  OK(releasedWords(RESERVED_TAIL, AT_ABORT, false, &after) == 20 &&
     after == RESERVED_NONE);

  /* Records that cannot come in the state */
  OK(releasedWords(RESERVED_NONE, AT_COMMIT, false, &after) == 0);
  OK(releasedWords(RESERVED_NONE, AT_COMPLETE, true, &after) == 0);
  OK(releasedWords(RESERVED_NONE, AT_ABORT, false, &after) == 0);
  OK(releasedWords(RESERVED_TAIL, AT_COMMIT, true, &after) == 0);
  OK(releasedWords(RESERVED_FULL, AT_COMPLETE, true, &after) == 0);

  /* The COMMIT, then the COMPLETE or rule-F ABORT, each closing its unit */
  OK(RESERVE_AT_COMMIT >= COMMIT_LEN + FILLER_MAX);
  OK(RESERVE - RESERVE_AT_COMMIT >=
     std::max(COMPLETE_LEN, ABORT_LEN) + FILLER_MAX + NEXT_MBYTE_LEN);
}

}  // namespace

TAPTEST(pmem_redo_writer) {
  Log log;
  builders();
  fixedRecords(log);
  prepares(log);
  fillers(log);
  reservation();
  return 1;
}
