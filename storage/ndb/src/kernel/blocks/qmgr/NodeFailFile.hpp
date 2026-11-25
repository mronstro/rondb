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
#ifndef NODE_FAIL_FILE_HPP
#define NODE_FAIL_FILE_HPP

#include <ndb_global.h>
#include <ndb_limits.h>
#include <util/ndb_xxh3.h>
#include <fcntl.h>
#include <unistd.h>
#include <memory>

/**
 * RONDB-1150, X6.1: the node-failure file (plan §5.4, impl_next_steps.md
 * X6.1). Each data node keeps a small file beside REDO path 0, mapped as
 * the REDO log is. Before QMGR confirms the failure of node X
 * (PREP_FAILCONF), it stores "X failed while GCI g was current" here, so
 * that every survivor has the record before any transaction commits
 * without X. At a system restart a record with g after the restart's GCI
 * R makes X stale: it takes no part in the restart and joins by a node
 * restart afterwards (X6.3).
 *
 * Layout, 64-byte lines: line 0 the header; then two slots per node id,
 * written alternately, as the last-file slots of the REDO log (E10). Each
 * line ends with the low 32 bits of XXH3 over its other words, so that a
 * slot torn by a crash during its store is not valid and the other slot
 * holds the record before it. Only the latest failure of a node matters
 * (DI-12).
 */
namespace NodeFailFile {

constexpr Uint32 LINE_WORDS = 16;
constexpr Uint32 LINE_BYTES = 4 * LINE_WORDS;
constexpr Uint32 HEADER_MAGIC = 0x4e464631;  // "NFF1"
constexpr Uint32 SLOT_MAGIC = 0x4e46534c;    // "NFSL"
constexpr Uint32 FORMAT_VERSION = 1;
constexpr Uint32 FILE_BYTES =
    ((LINE_BYTES * (1 + 2 * ABS_MAX_NDB_NODES) + 4095) / 4096) * 4096;
constexpr const char *FILE_NAME = "nodefail.dat";

/* Header words */
constexpr Uint32 H_MAGIC = 0;
constexpr Uint32 H_VERSION = 1;
constexpr Uint32 H_NODE_ID = 2;
/* Slot words */
constexpr Uint32 S_MAGIC = 0;
constexpr Uint32 S_SEQ = 1;  // 64 bits, words 1 and 2
constexpr Uint32 S_NODE_ID = 3;
constexpr Uint32 S_GCI_HI = 4;
constexpr Uint32 S_FAIL_NO = 5;
constexpr Uint32 S_INDEX = 6;  // the slot's own place, 0 or 1
constexpr Uint32 CHECKSUM = LINE_WORDS - 1;

/* A failure of a node as the file records it */
struct Record {
  Uint32 nodeId;
  Uint32 gciHi;
  Uint32 failNo;
  Uint64 seq;
};

inline Uint32 checksum(const Uint32 *line) {
  return Uint32(ndb_xxh3_64(line, 4 * CHECKSUM));
}

inline Uint32 slotOffset(Uint32 nodeId, Uint32 index) {
  return LINE_BYTES * (1 + 2 * nodeId + index);
}

inline void buildHeader(Uint32 *line, Uint32 ownNodeId) {
  for (Uint32 i = 0; i < LINE_WORDS; i++) line[i] = 0;
  line[H_MAGIC] = HEADER_MAGIC;
  line[H_VERSION] = FORMAT_VERSION;
  line[H_NODE_ID] = ownNodeId;
  line[CHECKSUM] = checksum(line);
}

inline bool headerValid(const Uint32 *line, Uint32 ownNodeId) {
  return line[H_MAGIC] == HEADER_MAGIC &&
         line[H_VERSION] == FORMAT_VERSION && line[H_NODE_ID] == ownNodeId &&
         line[CHECKSUM] == checksum(line);
}

inline void buildSlot(Uint32 *line, Uint32 index, const Record &r) {
  for (Uint32 i = 0; i < LINE_WORDS; i++) line[i] = 0;
  line[S_MAGIC] = SLOT_MAGIC;
  line[S_SEQ] = Uint32(r.seq);
  line[S_SEQ + 1] = Uint32(r.seq >> 32);
  line[S_NODE_ID] = r.nodeId;
  line[S_GCI_HI] = r.gciHi;
  line[S_FAIL_NO] = r.failNo;
  line[S_INDEX] = index;
  line[CHECKSUM] = checksum(line);
}

inline bool slotValid(const Uint32 *line, Uint32 nodeId, Uint32 index,
                      Record *out) {
  if (line[S_MAGIC] != SLOT_MAGIC || line[S_NODE_ID] != nodeId ||
      line[S_INDEX] != index || line[CHECKSUM] != checksum(line)) {
    return false;
  }
  out->nodeId = nodeId;
  out->gciHi = line[S_GCI_HI];
  out->failNo = line[S_FAIL_NO];
  out->seq = Uint64(line[S_SEQ]) | (Uint64(line[S_SEQ + 1]) << 32);
  return out->seq != 0;
}

/**
 * The latest record of nodeId in the file at base, FILE_BYTES long: the
 * valid slot with the higher seq. *slot is the index of the slot that the
 * next record of the node goes to, the other one or 0.
 */
inline bool latest(const Uint8 *base, Uint32 nodeId, Record *out,
                   Uint32 *slot) {
  Record r[2];
  bool valid[2];
  for (Uint32 i = 0; i < 2; i++) {
    valid[i] = slotValid(
        reinterpret_cast<const Uint32 *>(base + slotOffset(nodeId, i)), nodeId,
        i, &r[i]);
  }
  if (!valid[0] && !valid[1]) {
    *slot = 0;
    return false;
  }
  const Uint32 best = (!valid[1] || (valid[0] && r[0].seq > r[1].seq)) ? 0 : 1;
  *out = r[best];
  *slot = 1 - best;
  return true;
}

/**
 * The GCI of the latest recorded failure of each node id into
 * gci[ABS_MAX_NDB_NODES], 0 where there is none, read from the file in
 * dir before QMGR maps it; false without a valid file of this node.
 */
inline bool readFailGcis(const char *dir, Uint32 ownNodeId, Uint32 *gci) {
  for (Uint32 i = 0; i < ABS_MAX_NDB_NODES; i++) gci[i] = 0;
  if (dir == nullptr) return false;
  char path[1024];
  snprintf(path, sizeof(path), "%s%s", dir, FILE_NAME);
  const int fd = ::open(path, O_RDONLY);
  if (fd < 0) return false;
  std::unique_ptr<Uint8[]> file(new Uint8[FILE_BYTES]);
  const ssize_t n = ::pread(fd, file.get(), FILE_BYTES, 0);
  ::close(fd);
  if (n != ssize_t(FILE_BYTES) ||
      !headerValid(reinterpret_cast<const Uint32 *>(file.get()), ownNodeId)) {
    return false;
  }
  for (Uint32 nodeId = 1; nodeId < ABS_MAX_NDB_NODES; nodeId++) {
    Record r;
    Uint32 slot;
    if (latest(file.get(), nodeId, &r, &slot)) gci[nodeId] = r.gciHi;
  }
  return true;
}

}  // namespace NodeFailFile

#endif
