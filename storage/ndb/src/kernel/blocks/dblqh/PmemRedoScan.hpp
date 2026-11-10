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
#ifndef PMEM_REDO_SCAN_HPP
#define PMEM_REDO_SCAN_HPP

#include <cstddef>

#include "PmemRedoFormat.hpp"

/**
 * RONDB-1150: reading the REDO log of a part with RedoLogMode=pmem
 * (pmem_redo_design.md E11, pmem_redo_recovery.md §3, step 1 plan S6.2):
 * the validity of a record (V1-V5), the end of the log E, and the last
 * mbyte found from the mbyte headers. Plain functions over the mapped
 * files, for DBLQH, ndb_redo_log_reader and the unit tests.
 *
 * A record at p is valid if:
 *   V1  the header of its page has the format, its checksum, the identity
 *       of the page and the expected lap;
 *   V2  its type is known, its flags are those of the type, and its length
 *       is even, within the type's bounds and, for a PREPARE or an FD,
 *       that of its content; it ends before the end of the mbyte, so that
 *       a NEXT_MBYTE still fits (a NEXT_MBYTE may end at the end);
 *   V3  every further page it spans passes V1 with the same lap;
 *   V4  its checksum matches;
 *   V5  an FD is at word 32 of page 0 and nowhere else; page 0 holds the
 *       FD and the FILLER to the page end that follows it, and nothing
 *       else; every other FILLER is shorter than W and ends on a W
 *       boundary.
 * After a NEXT_MBYTE the next record is the first of the next mbyte, so
 * nothing after a NEXT_MBYTE in its mbyte is read.
 *
 * Bounds come before the checksum, so a garbage length never makes a
 * check read outside the mbyte.
 */
namespace PmemRedo {

/* Where a record starts, or where a range ends, in a log part */
struct Pos {
  Uint32 fileNo;
  Uint32 pageNo;     // page in the file
  Uint32 pageIndex;  // word in the page
  Uint32 lap;        // the lap of the log at this place
};

/* The files of a log part, as in Dblqh's LogPartRecord */
struct Geom {
  Uint32 noFiles;
  Uint32 fileSizeMb;
  Uint32 logPartNo;

  Uint32 pagesInFile() const { return fileSizeMb * PAGES_IN_MBYTE; }
};

/* The mapped files of a log part, DBLQH's LogFileRecord::m_pmem_base */
struct PartView {
  Geom g;
  const Uint8 *const *fileBase;  // fileBase[fileNo], fileSizeMb MB each

  const Uint32 *page(Uint32 fileNo, Uint32 pageNo) const {
    return reinterpret_cast<const Uint32 *>(fileBase[fileNo] +
                                            Uint64(pageNo) * PAGE_BYTES);
  }
};

struct RecInfo {
  Uint32 w0;
  /**
   * Where the next record starts: after this one, skipping page headers;
   * after a NEXT_MBYTE, the first record position of the next mbyte.
   */
  Pos next;
};

/* The result of a scan for the end of the log */
struct ScanResult {
  Pos end;          // E, the first position that holds no valid record
  Uint32 reason;    // why the record at E is not valid
  Uint32 records;   // valid records from the start to E
  Uint32 mbytes;    // NEXT_MBYTE records followed
  bool nextFile;    // E lies in a later file than the start
};

/* The result of the walk over the mbyte headers of the last file */
struct LastMbyte {
  Uint32 reason;  // R_VALID, else why page 0 of the file fails V1
  Uint32 mbyte;   // the last mbyte whose header passes V1 with the lap
  /**
   * A later mbyte passes V1 with the lap too. The log never leaves such a
   * gap (W2), so the caller reports corruption.
   */
  bool validAfterDrop;
};

inline Uint64 posLsn(const Geom &g, const Pos &p) {
  return lsn(p.lap, g.noFiles, g.fileSizeMb, p.fileNo, p.pageNo, p.pageIndex);
}

/* The first record position of an mbyte: the FD in mbyte 0 */
inline Pos mbyteStart(Uint32 fileNo, Uint32 mbyte, Uint32 lap) {
  return Pos{fileNo, mbyte * PAGES_IN_MBYTE, HEADER_WORDS, lap};
}

/**
 * The lap of fileNo when the log ends at end: the files up to end's have
 * its lap, the later ones the lap before (0: never written).
 */
inline Uint32 expectedLap(const Pos &end, Uint32 fileNo) {
  return fileNo <= end.fileNo ? end.lap : end.lap - 1;
}

/**
 * The lap of a position less than one lap before end in the log: end's
 * lap up to end, the lap before after it in end's file and in the files
 * after end's. The restart reads its start (recovery plan S6.5) and the
 * PREPARE of a COMMIT this way.
 */
inline Uint32 lapAt(const Pos &end, Uint32 fileNo, Uint32 pageNo,
                    Uint32 pageIndex) {
  if (fileNo != end.fileNo) return expectedLap(end, fileNo);
  const bool after = pageNo > end.pageNo ||
                     (pageNo == end.pageNo && pageIndex > end.pageIndex);
  return after ? end.lap - 1 : end.lap;
}

/* The first record position of the mbyte after the one holding p */
Pos nextMbyteStart(const Geom &g, const Pos &p);

/**
 * The W boundary at or after p. A page end gives word 0 of the next page,
 * in the next mbyte or file if the page is the last, with the lap + 1 in
 * file 0.
 */
Pos ceilUnit(const Geom &g, const Pos &p);

/* V1 for the page at (fileNo, pageNo) with the lap */
Uint32 checkPage(const PartView &v, Uint32 fileNo, Uint32 pageNo, Uint32 lap);

/* V1-V5 for the record at p, p.lap the expected lap; R_VALID fills *out */
Uint32 checkRecord(const PartView &v, const Pos &p, RecInfo *out);

/**
 * E: follows the records from the first record position of (fileNo,
 * mbyte), with the lap, to the first position that is not valid. After a
 * NEXT_MBYTE it goes on in the next mbyte, also in the next file (with the
 * lap + 1 in file 0), which covers a file switch whose last-file slot was
 * not yet written.
 */
ScanResult findEnd(const PartView &v, Uint32 fileNo, Uint32 mbyte,
                   Uint32 lap);

/**
 * The last mbyte of fileNo written in the lap: the mbyte before the first
 * one whose first page fails V1 with the lap, an invalid header counting
 * as an older lap (recovery §3.4 step 3).
 */
LastMbyte findLastMbyte(const PartView &v, Uint32 fileNo, Uint32 lap);

/**
 * The line that phase 1 of a restart logs for a log part, and that
 * ndb_redo_log_reader --find-end prints from the files of the part: the
 * same text, so that a test can compare them.
 */
void formatEnd(char *buf, size_t size, Uint32 logPartNo, Uint32 lastFileNo,
               Uint32 lap, Uint64 slotSeq, Uint32 lastMbyte,
               const ScanResult &scan);

/* The config line of the control area against the node's configuration */
enum CtrlCheck : Uint32 {
  CTRL_VALID = 0,
  CTRL_NOT_PMEM,       // no magic: the files were not written in PMEM mode
  CTRL_CORRUPT,        // the checksum fails
  CTRL_OTHER_VERSION,  // another version of the control area
  CTRL_MISMATCH        // made for another configuration or node
};

/**
 * CTRL_VALID, or why not, with a message in msg; for CTRL_MISMATCH it
 * names the first field that differs.
 */
Uint32 checkCtrlConfig(const Uint32 *line, const Geom &g, Uint32 noParts,
                       Uint32 nodeId, char *msg, size_t size);

/* A valid last-file slot */
struct Slot {
  Uint64 seq;
  Uint32 fileNo;
  Uint32 lap;
  Uint64 dirtyShutdownCount;
  Uint32 flags;  // SLOT_F_*
};

/**
 * The slot line at index (0 or 1) is valid for the part: its magic, its
 * checksum, its own index and seq, the log part, a file of the part, and
 * a lap of at least 1.
 */
bool slotValid(const Uint32 *line, Uint32 index, const Geom &g, Slot *out);

/* The index of the valid slot with the higher seq, -1 if neither is valid */
int pickSlot(const Uint32 *slot0, const Uint32 *slot1, const Geom &g,
             Slot *out);

}  // namespace PmemRedo

#endif
