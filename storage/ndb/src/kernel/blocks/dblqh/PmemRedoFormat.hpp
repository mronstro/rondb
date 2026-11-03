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
#ifndef PMEM_REDO_FORMAT_HPP
#define PMEM_REDO_FORMAT_HPP

#include <ndb_limits.h>
#include <ndb_types.h>
#include <util/ndb_xxh3.h>

/**
 * RONDB-1150: the REDO log format with RedoLogMode=pmem
 * (pmem_redo_design.md E2-E5, E9, E13; pmem_redo_format.md). The DBLQH
 * writers, the restart scan (PmemRedoScan.hpp), ndb_redo_log_reader and
 * the unit tests share it, so it holds no block types. File mode does not
 * use it.
 *
 * The geometry is today's: a log part has noFiles files of fileSizeMb
 * mbytes, an mbyte has 32 pages of 8192 words, and every page starts with
 * a 32-word header. A record is 8-byte aligned, has an even length in
 * words, and starts with two words:
 *   w0  type (bits 0-7), flags (8-15), length in words (16-31)
 *   w1  checksum
 * The length counts w0, w1 and the pad word, not the page headers inside a
 * record that spans pages. Type 0 is unwritten memory: no record.
 *
 * The checksum, over the words in little-endian memory order (E4):
 *   H  = XXH3_64(w2 .. w(n-1)), one piece per page: H = XXH3_64(p1), then
 *        H = XXH3_64_seed(pi, H). With no body, H = EMPTY_HASH.
 *   w1 = low 32 bits of XXH3_64_seed((w0 & ~RF_INVALIDATED) || S, 20, H)
 *   S  = [lap, 0, (logPartNo << 16) | fileNo, pageNo * 8192 + pageIndex]
 * n is the length, except for a FILLER, whose body is not covered (n = 2).
 * S is not stored: the lap comes from the header of the page that holds
 * w0, the rest from the position. A record of an older lap, or one in the
 * wrong place, fails its checksum.
 */
namespace PmemRedo {

/* Geometry, as ZPAGE_SIZE, ZPAGE_HEADER_SIZE and ZPAGES_IN_MBYTE */
constexpr Uint32 PAGE_WORDS = 8192;
constexpr Uint32 PAGE_BYTES = 4 * PAGE_WORDS;
constexpr Uint32 HEADER_WORDS = 32;
constexpr Uint32 PAGE_DATA_WORDS = PAGE_WORDS - HEADER_WORDS;
constexpr Uint32 PAGES_IN_MBYTE = 32;

/* The write unit W (E2): every persist ends on a W boundary */
constexpr Uint32 W_BYTES = 64;
constexpr Uint32 W_WORDS = W_BYTES / 4;

/**
 * The last 64 words of page 0 of file 0 are the control area of the
 * restart (E10, R4). They lie in the body of the FILLER that follows the
 * FD, which is never stored.
 */
constexpr Uint32 CONTROL_AREA_WORD = PAGE_WORDS - 64;

/**
 * Record types. 5 is reserved; 6 (NEXT_LOG_RECORD) and 9 (INVALID_COMMIT)
 * are retired.
 */
constexpr Uint32 TYPE_PREPARE = 1;
constexpr Uint32 TYPE_COMMIT = 2;
constexpr Uint32 TYPE_ABORT = 3;
constexpr Uint32 TYPE_FD = 4;
constexpr Uint32 TYPE_NEXT_MBYTE = 7;
constexpr Uint32 TYPE_COMPLETED_GCI = 8;
constexpr Uint32 TYPE_FILLER = 10;
constexpr Uint32 TYPE_COMPLETE = 11;
constexpr Uint32 TYPE_SR_HEAD = 12;

/* Flags in w0 */
/* COMMIT: cancelled by a restart, not in the checksum (E9) */
constexpr Uint32 RF_INVALIDATED = 1u << 8;
/* COMMIT: written under durable commits */
constexpr Uint32 CF_DURABLE = 1u << 9;
/* ABORT: after the operation's COMMIT (rule F) */
constexpr Uint32 AF_AFTER_COMMIT = 1u << 9;
/* PREPARE: the transid in words 8 and 9 */
constexpr Uint32 PF_TRANSID = 1u << 9;

inline Uint32 makeW0(Uint32 type, Uint32 flags, Uint32 len) {
  return type | flags | (len << 16);
}
inline Uint32 w0Type(Uint32 w0) { return w0 & 0xFF; }
inline Uint32 w0Flags(Uint32 w0) { return w0 & 0xFF00; }
inline Uint32 w0Len(Uint32 w0) { return w0 >> 16; }

/* Lengths in words, w0 and w1 included (E13) */
constexpr Uint32 PREPARE_HEAD = 8;
constexpr Uint32 COMMIT_LEN = 12;
constexpr Uint32 ABORT_LEN = 4;
constexpr Uint32 COMPLETE_LEN = 4;
constexpr Uint32 COMPLETED_GCI_LEN = 4;
constexpr Uint32 NEXT_MBYTE_LEN = 2;
constexpr Uint32 SR_HEAD_LEN = 6;
constexpr Uint32 FILLER_MIN = 2;
constexpr Uint32 FILLER_MAX = W_WORDS - 2;  // all but the FILLER after the FD
constexpr Uint32 FD_HEADER = 4;
constexpr Uint32 FD_MAX_FILES = 40;  // as cmaxLogFilesInPageZero
/* The header, the transid, the largest key and log record of TUP, a pad */
constexpr Uint32 PREPARE_MAX =
    (PREPARE_HEAD + 2 + MAX_KEY_SIZE_IN_WORDS + MAX_LOG_RECORD_SIZE_WORDS + 1) &
    ~1u;
/* The pages a PREPARE can span: w0 and w1 in the last 2 words of one */
constexpr Uint32 PREPARE_MAX_PAGES = 4;
static_assert(1 + (PREPARE_MAX - 2 + PAGE_DATA_WORDS - 1) / PAGE_DATA_WORDS <=
                  PREPARE_MAX_PAGES,
              "a PREPARE spans at most PREPARE_MAX_PAGES pages");

/**
 * Words an operation reserves in its log part: the COMMIT and the
 * COMPLETE or rule-F ABORT, each with the largest FILLER that closes its
 * unit, and the NEXT_MBYTE slack (format §7.3). Step 1 releases them all at
 * COMMIT (R5).
 */
constexpr Uint32 RESERVE =
    (COMMIT_LEN + FILLER_MAX) + (COMPLETE_LEN + FILLER_MAX) + NEXT_MBYTE_LEN;
constexpr Uint32 RESERVE_AT_COMMIT = COMMIT_LEN + FILLER_MAX;

/* Record words (format §5); words 0 and 1 are w0 and w1 */
constexpr Uint32 PREP_HASH_VALUE = 2;
constexpr Uint32 PREP_OPERATION = 3;
constexpr Uint32 PREP_AI_LEN = 4;
constexpr Uint32 PREP_KEY_LEN = 5;
constexpr Uint32 PREP_ROWID_PAGE = 6;
constexpr Uint32 PREP_ROWID_IDX = 7;
constexpr Uint32 PREP_TRANSID = 8;  // with PF_TRANSID, else the key starts here

constexpr Uint32 COMMIT_TABLE_ID = 2;
constexpr Uint32 COMMIT_SCHEMA_VERSION = 3;
constexpr Uint32 COMMIT_FRAG_ID = 4;
constexpr Uint32 COMMIT_PREP_FILE_INDEX = 5;  // fileNo << 16 | startPageIndex
constexpr Uint32 COMMIT_PREP_PAGES = 6;       // startPageNo << 16 | stopPageNo
constexpr Uint32 COMMIT_GCI_HI = 7;
constexpr Uint32 COMMIT_GCI_LO = 8;
constexpr Uint32 COMMIT_TRANSID1 = 9;
constexpr Uint32 COMMIT_TRANSID2 = 10;
constexpr Uint32 COMMIT_OP_COUNT = 11;

constexpr Uint32 ABORT_TRANSID1 = 2;  // also COMPLETE
constexpr Uint32 ABORT_TRANSID2 = 3;

constexpr Uint32 COMPLETED_GCI_GCI = 2;  // word 3 is a pad

constexpr Uint32 FD_NO_FD = 2;
constexpr Uint32 FD_FILE_NO = 3;
/* Per FD and mbyte: max GCI completed, max GCI started, last prepare ref */
constexpr Uint32 FD_ARRAYS = 4;

/* Page header words (format §4.1), the DBLQH ZPOS_* numbers */
constexpr Uint32 HDR_CHECKSUM = 0;
constexpr Uint32 HDR_LAP = 1;
constexpr Uint32 HDR_MAX_GCI_COMPLETED = 2;
constexpr Uint32 HDR_MAX_GCI_STARTED = 3;
constexpr Uint32 HDR_VERSION = 6;
constexpr Uint32 HDR_NO_LOG_FILES = 7;
constexpr Uint32 HDR_LAST_PREP_REF = 10;
constexpr Uint32 HDR_PAGE_NO = 15;
constexpr Uint32 HDR_FILE_NO = 16;
constexpr Uint32 HDR_NO_LOG_PARTS = 21;
constexpr Uint32 HDR_FORMAT_MAGIC = 22;
constexpr Uint32 HDR_RESTART_GEN = 23;  // reserved, 0 (E12)
constexpr Uint32 HDR_LOG_PART_NO = 24;
constexpr Uint32 HDR_WRITE_UNIT = 25;
constexpr Uint32 HDR_NODE_ID = 26;

constexpr Uint32 FORMAT_MAGIC = 0x504D5231;  // "PMR1", version 1

/* XXH3_64 of no bytes */
constexpr Uint64 EMPTY_HASH = 0x2D06800538D394C2ULL;

/* Words to the next W boundary, from an even word index */
inline Uint32 padWords(Uint32 pageIndex) {
  return (W_WORDS - (pageIndex % W_WORDS)) % W_WORDS;
}

inline Uint32 prepareLen(Uint32 keyLen, Uint32 aiLen, bool transid) {
  const Uint32 n = PREPARE_HEAD + (transid ? 2 : 0) + keyLen + aiLen;
  return n + (n & 1);
}

/* FDs that fit in page 0, as cmaxLogFilesInPageZero before DUMP 2396 */
inline Uint32 maxFdFiles(Uint32 fileSizeMb) {
  const Uint32 n = (PAGE_WORDS - HEADER_WORDS - 128) / (3 * fileSizeMb);
  return n < FD_MAX_FILES ? n : FD_MAX_FILES;
}

inline Uint32 fdLen(Uint32 noFd, Uint32 fileSizeMb) {
  const Uint32 n = FD_HEADER + 3 * noFd * fileSizeMb;
  return n + (n & 1);
}

/**
 * Byte position in the log of a part (impl_step1_lqh_write.md §3.3). It
 * grows along the log: the lap is the one the log has at that place.
 */
inline Uint64 lsn(Uint32 lap, Uint32 noFiles, Uint32 fileSizeMb,
                  Uint32 fileNo, Uint32 pageNo, Uint32 pageIndex) {
  const Uint64 fileBytes = Uint64(fileSizeMb) << 20;
  return (Uint64(lap) * noFiles + fileNo) * fileBytes +
         Uint64(pageNo) * PAGE_BYTES + 4 * pageIndex;
}

/* The suffix S of the checksum, never stored */
struct Suffix {
  Uint32 lap;
  Uint32 gen;  // reserved, 0
  Uint32 partFile;
  Uint32 pos;
};

inline Suffix suffix(Uint32 lap, Uint32 logPartNo, Uint32 fileNo,
                     Uint32 pageNo, Uint32 pageIndex) {
  return Suffix{lap, 0, (logPartNo << 16) | fileNo,
                pageNo * PAGE_WORDS + pageIndex};
}

/* Number of words the checksum covers, w0 and w1 included */
inline Uint32 hashedLen(Uint32 w0) {
  return w0Type(w0) == TYPE_FILLER ? 2 : w0Len(w0);
}

/**
 * The checksum of one record. Give the body words w2 .. w(n-1) in order,
 * one piece per page, then finish with w0 and S. The pieces are fixed by
 * the page ends: hashing the body in other pieces gives another checksum.
 */
class RecChecksum {
 public:
  void piece(const Uint32 *words, Uint32 n) {
    if (n == 0) return;
    m_hash = m_first ? ndb_xxh3_64(words, 4 * n)
                     : ndb_xxh3_64_seed(words, 4 * n, m_hash);
    m_first = false;
  }
  Uint32 finish(Uint32 w0, const Suffix &s) const {
    const Uint32 mix[5] = {w0 & ~RF_INVALIDATED, s.lap, s.gen, s.partFile,
                           s.pos};
    return Uint32(ndb_xxh3_64_seed(mix, sizeof(mix), m_hash));
  }

 private:
  Uint64 m_hash = EMPTY_HASH;
  bool m_first = true;
};

/* The checksum of a record that lies whole in one page */
inline Uint32 recordChecksum(const Uint32 *rec, const Suffix &s) {
  RecChecksum c;
  c.piece(rec + 2, hashedLen(rec[0]) - 2);
  return c.finish(rec[0], s);
}

/**
 * The checksum of a record built in one buffer, of which the first inFirst
 * words (at least w0 and w1) fit in the page and the rest goes on at word
 * 32 of the next page; the rest fits in that page.
 */
inline Uint32 splitChecksum(const Uint32 *rec, Uint32 inFirst,
                            const Suffix &s) {
  const Uint32 len = hashedLen(rec[0]);
  const Uint32 k = len < inFirst ? len : inFirst;
  RecChecksum c;
  c.piece(rec + 2, k - 2);
  c.piece(rec + k, len - k);
  return c.finish(rec[0], s);
}

/* The pages that a record of len words at word pageIndex lies in */
inline Uint32 pagesSpanned(Uint32 pageIndex, Uint32 len) {
  const Uint32 inFirst = PAGE_WORDS - pageIndex;
  if (len <= inFirst) return 1;
  return 1 + (len - inFirst + PAGE_DATA_WORDS - 1) / PAGE_DATA_WORDS;
}

/**
 * The checksum of a record as it lies in the log pages: w0 at word
 * pageIndex of pages[0], the rest going on at word 32 of pages[1],
 * pages[2], ..., one piece per page. pages holds pagesSpanned() pages.
 */
inline Uint32 pagedChecksum(const Uint32 *const *pages, Uint32 pageIndex,
                            const Suffix &s) {
  const Uint32 w0 = pages[0][pageIndex];
  const Uint32 len = hashedLen(w0);
  const Uint32 inFirst = PAGE_WORDS - pageIndex;
  const Uint32 n1 = len < inFirst ? len : inFirst;
  RecChecksum c;
  c.piece(pages[0] + pageIndex + 2, n1 - 2);
  Uint32 left = len - n1;
  for (Uint32 i = 1; left > 0; i++) {
    const Uint32 n = left < PAGE_DATA_WORDS ? left : PAGE_DATA_WORDS;
    c.piece(pages[i] + HEADER_WORDS, n);
    left -= n;
  }
  return c.finish(w0, s);
}

/**
 * The records as the DBLQH writers build them (format §5), w1 left 0 for
 * the checksum at the place the record is written.
 */
inline void prepareHead(Uint32 *hdr, Uint32 flags, Uint32 len,
                        Uint32 hashValue, Uint32 operation, Uint32 aiLen,
                        Uint32 keyLen, Uint32 rowidPage, Uint32 rowidIdx) {
  hdr[0] = makeW0(TYPE_PREPARE, flags, len);
  hdr[1] = 0;
  hdr[PREP_HASH_VALUE] = hashValue;
  hdr[PREP_OPERATION] = operation;
  hdr[PREP_AI_LEN] = aiLen;
  hdr[PREP_KEY_LEN] = keyLen;
  hdr[PREP_ROWID_PAGE] = rowidPage;
  hdr[PREP_ROWID_IDX] = rowidIdx;
}

/* The PREPARE is at (prepFileNo, prepStartPageNo, prepStartPageIndex) */
inline void commitRecord(Uint32 *rec, Uint32 flags, Uint32 tableId,
                         Uint32 schemaVersion, Uint32 fragId,
                         Uint32 prepFileNo, Uint32 prepStartPageNo,
                         Uint32 prepStartPageIndex, Uint32 prepStopPageNo,
                         Uint32 gciHi, Uint32 gciLo, Uint32 transid1,
                         Uint32 transid2, Uint32 opCount) {
  rec[0] = makeW0(TYPE_COMMIT, flags, COMMIT_LEN);
  rec[1] = 0;
  rec[COMMIT_TABLE_ID] = tableId;
  rec[COMMIT_SCHEMA_VERSION] = schemaVersion;
  rec[COMMIT_FRAG_ID] = fragId;
  rec[COMMIT_PREP_FILE_INDEX] = (prepFileNo << 16) | prepStartPageIndex;
  rec[COMMIT_PREP_PAGES] = (prepStartPageNo << 16) | prepStopPageNo;
  rec[COMMIT_GCI_HI] = gciHi;
  rec[COMMIT_GCI_LO] = gciLo;
  rec[COMMIT_TRANSID1] = transid1;
  rec[COMMIT_TRANSID2] = transid2;
  rec[COMMIT_OP_COUNT] = opCount;
}

inline void abortRecord(Uint32 *rec, Uint32 flags, Uint32 transid1,
                        Uint32 transid2) {
  rec[0] = makeW0(TYPE_ABORT, flags, ABORT_LEN);
  rec[1] = 0;
  rec[ABORT_TRANSID1] = transid1;
  rec[ABORT_TRANSID2] = transid2;
}

inline void completeRecord(Uint32 *rec, Uint32 transid1, Uint32 transid2) {
  rec[0] = makeW0(TYPE_COMPLETE, 0, COMPLETE_LEN);
  rec[1] = 0;
  rec[ABORT_TRANSID1] = transid1;
  rec[ABORT_TRANSID2] = transid2;
}

inline void completedGciRecord(Uint32 *rec, Uint32 gci) {
  rec[0] = makeW0(TYPE_COMPLETED_GCI, 0, COMPLETED_GCI_LEN);
  rec[1] = 0;
  rec[COMPLETED_GCI_GCI] = gci;
  rec[3] = 0;
}

/**
 * The words an operation keeps reserved in its log part
 * (TcConnectionrec::m_committed_log_space), and the records that release
 * them (S4.7, E13): RESERVE at the PREPARE; all of it at a COMMIT outside
 * durable commits (all of step 1) or at a normal ABORT; at a durable
 * COMMIT all but the COMPLETE's part, which its COMPLETE or rule-F ABORT
 * releases.
 */
enum Reservation : Uint32 {
  RESERVED_NONE = 0,
  RESERVED_FULL = 1,
  RESERVED_TAIL = 2
};
enum RedoRelease : Uint32 { AT_COMMIT, AT_COMPLETE, AT_ABORT };

/* The words released and the state after; 0 if the record cannot come */
inline Uint32 releasedWords(Uint32 state, RedoRelease what, bool durable,
                            Uint32 *after) {
  constexpr Uint32 tail = RESERVE - RESERVE_AT_COMMIT;
  *after = RESERVED_NONE;
  switch (what) {
    case AT_COMMIT:
      if (state != RESERVED_FULL) return 0;
      if (!durable) return RESERVE;
      *after = RESERVED_TAIL;
      return RESERVE_AT_COMMIT;
    case AT_COMPLETE:
      return state == RESERVED_TAIL ? tail : 0;
    case AT_ABORT:
      if (state == RESERVED_FULL) return RESERVE;
      return state == RESERVED_TAIL ? tail : 0;
  }
  return 0;
}

/* Low 32 bits of XXH3_64 of header words 1-31 (E5) */
inline Uint32 headerChecksum(const Uint32 *hdr) {
  return Uint32(ndb_xxh3_64(hdr + 1, 4 * (HEADER_WORDS - 1)));
}

/**
 * The header of a page as stored on PMEM (E5, R2): the words recovery
 * reads, taken from the DRAM header of the page, the page's identity and
 * the format words. Every other word is 0 and word 0 is the checksum of
 * words 1-31. It is stored by the first copy of the page and never
 * rewritten in that lap. img may be dramHdr.
 */
inline void buildPageHeader(Uint32 *img, const Uint32 *dramHdr, Uint32 fileNo,
                            Uint32 pageNo, Uint32 logPartNo, Uint32 nodeId) {
  const Uint32 lap = dramHdr[HDR_LAP];
  const Uint32 gciCompleted = dramHdr[HDR_MAX_GCI_COMPLETED];
  const Uint32 gciStarted = dramHdr[HDR_MAX_GCI_STARTED];
  const Uint32 version = dramHdr[HDR_VERSION];
  const Uint32 noFiles = dramHdr[HDR_NO_LOG_FILES];
  const Uint32 lastPrepRef = dramHdr[HDR_LAST_PREP_REF];
  const Uint32 noParts = dramHdr[HDR_NO_LOG_PARTS];
  for (Uint32 i = 0; i < HEADER_WORDS; i++) img[i] = 0;
  img[HDR_LAP] = lap;
  img[HDR_MAX_GCI_COMPLETED] = gciCompleted;
  img[HDR_MAX_GCI_STARTED] = gciStarted;
  img[HDR_VERSION] = version;
  img[HDR_NO_LOG_FILES] = noFiles;
  img[HDR_LAST_PREP_REF] = lastPrepRef;
  img[HDR_PAGE_NO] = pageNo;
  img[HDR_FILE_NO] = fileNo;
  img[HDR_NO_LOG_PARTS] = noParts;
  img[HDR_FORMAT_MAGIC] = FORMAT_MAGIC;
  img[HDR_LOG_PART_NO] = logPartNo;
  img[HDR_WRITE_UNIT] = W_BYTES;
  img[HDR_NODE_ID] = nodeId;
  img[HDR_CHECKSUM] = headerChecksum(img);
}

/**
 * The control area of a log part (E10, recovery plan S6.3): four lines of
 * W at CONTROL_AREA_WORD of page 0 of file 0.
 *   config          written once at the initial start: the configuration
 *                   the files were made for
 *   reserved        0 (X5, X6)
 *   slot 0, slot 1  the last file of the log and its lap. A file switch
 *                   writes slot seq & 1 with seq + 1 once the new file's
 *                   FD is persistent, so a torn slot leaves the other.
 * Each line is stored with one copy and a fence. Its last word is the low
 * 32 bits of XXH3_64 of the 15 words before it.
 */
constexpr Uint32 CTRL_CONFIG_WORD = CONTROL_AREA_WORD;
constexpr Uint32 SLOT0_WORD = CONTROL_AREA_WORD + 2 * W_WORDS;
constexpr Uint32 SLOT1_WORD = SLOT0_WORD + W_WORDS;
constexpr Uint32 LINE_CHECKSUM = W_WORDS - 1;

constexpr Uint32 CTRL_MAGIC = 0x5243544C;  // "RCTL"
constexpr Uint32 CTRL_VERSION = 1;
constexpr Uint32 CTRL_W_MAGIC = 0;
constexpr Uint32 CTRL_W_VERSION = 1;
constexpr Uint32 CTRL_W_NO_PARTS = 2;
constexpr Uint32 CTRL_W_PART_NO = 3;
constexpr Uint32 CTRL_W_NO_FILES = 4;
constexpr Uint32 CTRL_W_FILE_SIZE_MB = 5;
constexpr Uint32 CTRL_W_WRITE_UNIT = 6;
constexpr Uint32 CTRL_W_NODE_ID = 7;

/* Slot words; a 64-bit value low word first */
constexpr Uint32 SLOT_MAGIC = 0x52534C54;  // "RSLT"
constexpr Uint32 SLOT_W_MAGIC = 0;
constexpr Uint32 SLOT_W_SEQ = 1;
constexpr Uint32 SLOT_W_FILE_NO = 3;
constexpr Uint32 SLOT_W_LAP = 4;
constexpr Uint32 SLOT_W_PART_NO = 5;
constexpr Uint32 SLOT_W_DSC = 6;  // the dirty-shutdown count recorded
constexpr Uint32 SLOT_W_FLAGS = 8;
/* Slot flags (bits 0-7); bits 8-15 hold the index of the slot */
constexpr Uint32 SLOT_F_DSC_VALID = 1;        // the device reports the count
constexpr Uint32 SLOT_F_UNSAFE_SHUTDOWN = 2;  // seen by the start that wrote it

/* The largest FD ends early enough that the FILLER after it stays clear */
static_assert((HEADER_WORDS + FD_HEADER + (PAGE_WORDS - HEADER_WORDS - 128) +
               1 + FILLER_MIN + W_WORDS - 1) /
                      W_WORDS * W_WORDS <=
                  CONTROL_AREA_WORD,
              "page 0 is stored up to the unit of the FD's FILLER header");

inline Uint32 lineChecksum(const Uint32 *line) {
  return Uint32(ndb_xxh3_64(line, 4 * LINE_CHECKSUM));
}

inline void buildCtrlConfig(Uint32 *line, Uint32 noParts, Uint32 logPartNo,
                            Uint32 noFiles, Uint32 fileSizeMb, Uint32 nodeId) {
  for (Uint32 i = 0; i < W_WORDS; i++) line[i] = 0;
  line[CTRL_W_MAGIC] = CTRL_MAGIC;
  line[CTRL_W_VERSION] = CTRL_VERSION;
  line[CTRL_W_NO_PARTS] = noParts;
  line[CTRL_W_PART_NO] = logPartNo;
  line[CTRL_W_NO_FILES] = noFiles;
  line[CTRL_W_FILE_SIZE_MB] = fileSizeMb;
  line[CTRL_W_WRITE_UNIT] = W_BYTES;
  line[CTRL_W_NODE_ID] = nodeId;
  line[LINE_CHECKSUM] = lineChecksum(line);
}

/* The slot that sequence number seq goes in */
inline Uint32 slotIndex(Uint64 seq) { return Uint32(seq & 1); }
inline Uint32 slotWord(Uint64 seq) {
  return slotIndex(seq) == 0 ? SLOT0_WORD : SLOT1_WORD;
}

inline void buildSlot(Uint32 *line, Uint64 seq, Uint32 fileNo, Uint32 lap,
                      Uint32 logPartNo, Uint64 dirtyShutdownCount,
                      Uint32 flags) {
  for (Uint32 i = 0; i < W_WORDS; i++) line[i] = 0;
  line[SLOT_W_MAGIC] = SLOT_MAGIC;
  line[SLOT_W_SEQ] = Uint32(seq);
  line[SLOT_W_SEQ + 1] = Uint32(seq >> 32);
  line[SLOT_W_FILE_NO] = fileNo;
  line[SLOT_W_LAP] = lap;
  line[SLOT_W_PART_NO] = logPartNo;
  line[SLOT_W_DSC] = Uint32(dirtyShutdownCount);
  line[SLOT_W_DSC + 1] = Uint32(dirtyShutdownCount >> 32);
  line[SLOT_W_FLAGS] = (flags & 0xFF) | (slotIndex(seq) << 8);
  line[LINE_CHECKSUM] = lineChecksum(line);
}

/* Why a page or a record is not valid (recovery §3.2, V1-V5) */
enum Reason : Uint32 {
  R_VALID = 0,
  R_HDR_FORMAT,     // V1: not the format magic, write unit, restart gen
  R_HDR_CHECKSUM,   // V1: the header is torn or corrupt
  R_HDR_IDENTITY,   // V1: page, file or log part number of another place
  R_HDR_LAP,        // V1: the header of another lap
  R_POS,            // not a record position: odd, in a header, outside
  R_TYPE_ZERO,      // V2: type 0, unwritten memory
  R_TYPE_UNKNOWN,   // V2
  R_FLAGS,          // V2: a flag the type does not have
  R_LEN,            // V2: odd, out of bounds, or not that of the content
  R_CROSSES_MBYTE,  // V2: does not end before the end of the mbyte
  R_SPAN_HDR,       // V3: a further page of the record fails V1
  R_CHECKSUM,       // V4
  R_FD_POS,         // V5: FD not at word 32 of page 0, or other record there
  R_FILLER_ALIGN,   // V5: FILLER not ending on a W boundary or page 0's end
  R_REASONS
};

inline const char *reasonName(Uint32 reason) {
  static const char *const names[R_REASONS] = {
      "valid",
      "page header not in this format",
      "page header checksum",
      "page header of another place",
      "page header of another lap",
      "not a record position",
      "unwritten (type 0)",
      "unknown record type",
      "flags",
      "record length",
      "record crosses the end of the mbyte",
      "spanned page header",
      "record checksum",
      "FD position",
      "FILLER alignment"};
  return reason < R_REASONS ? names[reason] : "unknown reason";
}

/* V1 without the lap: format, checksum and identity of a page header */
inline Uint32 checkPageHeader(const Uint32 *hdr, Uint32 fileNo, Uint32 pageNo,
                              Uint32 logPartNo) {
  if (hdr[HDR_FORMAT_MAGIC] != FORMAT_MAGIC ||
      hdr[HDR_WRITE_UNIT] != W_BYTES || hdr[HDR_RESTART_GEN] != 0)
    return R_HDR_FORMAT;
  if (hdr[HDR_CHECKSUM] != headerChecksum(hdr)) return R_HDR_CHECKSUM;
  if (hdr[HDR_PAGE_NO] != pageNo || hdr[HDR_FILE_NO] != fileNo ||
      hdr[HDR_LOG_PART_NO] != logPartNo)
    return R_HDR_IDENTITY;
  return R_VALID;
}

inline bool pageHeaderOk(const Uint32 *hdr, Uint32 fileNo, Uint32 pageNo,
                         Uint32 logPartNo) {
  return checkPageHeader(hdr, fileNo, pageNo, logPartNo) == R_VALID;
}

/**
 * V2 on w0 alone: a known type, its flags, and a length that is even and
 * within the type's bounds. The exact length of a PREPARE and an FD, and
 * the end inside the mbyte, need more than w0.
 */
inline Uint32 checkFraming(Uint32 w0) {
  const Uint32 type = w0Type(w0);
  const Uint32 flags = w0Flags(w0);
  const Uint32 len = w0Len(w0);
  Uint32 allowed = 0;
  Uint32 minLen = 0;
  Uint32 maxLen = 0;
  switch (type) {
    case 0:
      return R_TYPE_ZERO;
    case TYPE_PREPARE:
      allowed = PF_TRANSID;
      minLen = PREPARE_HEAD;
      maxLen = PREPARE_MAX;
      break;
    case TYPE_COMMIT:
      allowed = RF_INVALIDATED | CF_DURABLE;
      minLen = maxLen = COMMIT_LEN;
      break;
    case TYPE_ABORT:
      allowed = AF_AFTER_COMMIT;
      minLen = maxLen = ABORT_LEN;
      break;
    case TYPE_FD:
      minLen = FD_HEADER;
      maxLen = PAGE_DATA_WORDS;
      break;
    case TYPE_NEXT_MBYTE:
      minLen = maxLen = NEXT_MBYTE_LEN;
      break;
    case TYPE_COMPLETED_GCI:
      minLen = maxLen = COMPLETED_GCI_LEN;
      break;
    case TYPE_FILLER:
      minLen = FILLER_MIN;
      maxLen = PAGE_DATA_WORDS;
      break;
    case TYPE_COMPLETE:
      minLen = maxLen = COMPLETE_LEN;
      break;
    case TYPE_SR_HEAD:
      minLen = maxLen = SR_HEAD_LEN;
      break;
    default:
      return R_TYPE_UNKNOWN;
  }
  if (flags & ~allowed) return R_FLAGS;
  if ((len & 1) || len < minLen || len > maxLen) return R_LEN;
  return R_VALID;
}

/* The length of a PREPARE is that of its key and attrinfo */
inline bool prepareLenOk(Uint32 w0, Uint32 aiLen, Uint32 keyLen) {
  if (aiLen > PREPARE_MAX || keyLen > PREPARE_MAX) return false;
  return w0Len(w0) ==
         prepareLen(keyLen, aiLen, (w0Flags(w0) & PF_TRANSID) != 0);
}

/* The length of an FD is that of its descriptors, at most the ones that fit */
inline bool fdLenOk(Uint32 w0, Uint32 noFd, Uint32 noFiles,
                    Uint32 fileSizeMb) {
  if (noFd == 0 || noFd > noFiles || noFd > maxFdFiles(fileSizeMb))
    return false;
  return w0Len(w0) == fdLen(noFd, fileSizeMb);
}

/**
 * A record that lies whole in one page, in at most maxWords words: its
 * framing, the length of a PREPARE and the checksum for suffix s. The
 * restart scan (PmemRedoScan.hpp) adds the page headers, the records that
 * span pages, the exact length of an FD and the rules of position.
 */
inline Uint32 checkRecordWords(const Uint32 *rec, Uint32 maxWords,
                               const Suffix &s) {
  const Uint32 w0 = rec[0];
  const Uint32 r = checkFraming(w0);
  if (r != R_VALID) return r;
  if (w0Len(w0) > maxWords) return R_LEN;
  if (w0Type(w0) == TYPE_PREPARE &&
      !prepareLenOk(w0, rec[PREP_AI_LEN], rec[PREP_KEY_LEN]))
    return R_LEN;
  if (rec[1] != recordChecksum(rec, s)) return R_CHECKSUM;
  return R_VALID;
}

inline bool recordOk(const Uint32 *rec, Uint32 maxWords, const Suffix &s) {
  return checkRecordWords(rec, maxWords, s) == R_VALID;
}

}  // namespace PmemRedo

#endif
