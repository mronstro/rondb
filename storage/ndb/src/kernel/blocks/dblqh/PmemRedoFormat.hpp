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
