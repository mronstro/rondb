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
 * R makes X stale, if a node of its node group outlived the failure
 * (outlived()): X takes no part in the restart and joins by a node
 * restart afterwards (X6.3).
 *
 * Layout, 64-byte lines: line 0 the header; then two slots per node id,
 * written alternately, as the last-file slots of the REDO log (E10). Each
 * line ends with the low 32 bits of XXH3 over its other words, so that a
 * slot torn by a crash during its store is not valid and the other slot
 * holds the record before it. Only the latest failure of a node matters
 * (DI-12). Node id 0 is no node: its slots hold the start state of this
 * node (X6.7), so that the header is written only when the file is made.
 */
namespace NodeFailFile {

constexpr Uint32 LINE_WORDS = 16;
constexpr Uint32 LINE_BYTES = 4 * LINE_WORDS;
constexpr Uint32 HEADER_MAGIC = 0x4e464631;  // "NFF1"
constexpr Uint32 SLOT_MAGIC = 0x4e46534c;    // "NFSL"
constexpr Uint32 STATE_MAGIC = 0x4e465354;   // "NFST"
constexpr Uint32 FORMAT_VERSION = 1;
constexpr Uint32 FILE_BYTES =
    ((LINE_BYTES * (1 + 2 * ABS_MAX_NDB_NODES) + 4095) / 4096) * 4096;
constexpr const char *FILE_NAME = "nodefail.dat";
constexpr Uint32 STATE_NODE_ID = 0;
constexpr Uint32 NO_GROUP = ~Uint32(0);

/* Header words */
constexpr Uint32 H_MAGIC = 0;
constexpr Uint32 H_VERSION = 1;
constexpr Uint32 H_NODE_ID = 2;
/* Slot words, of a node's failure and of the start state */
constexpr Uint32 S_MAGIC = 0;
constexpr Uint32 S_SEQ = 1;  // 64 bits, words 1 and 2
constexpr Uint32 S_NODE_ID = 3;
constexpr Uint32 S_GCI_HI = 4;
constexpr Uint32 S_FAIL_NO = 5;
constexpr Uint32 S_INDEX = 6;  // the slot's own place, 0 or 1
constexpr Uint32 T_DSC = 7;    // start state: 64 bits, words 7 and 8
constexpr Uint32 T_FLAGS = 9;  // start state: TF_*
constexpr Uint32 CHECKSUM = LINE_WORDS - 1;
/* The dirty-shutdown count in T_DSC is that of the REDO paths */
constexpr Uint32 TF_DSC_VALID = 1;
/* An unsafe shutdown of the REDO paths, and no start completed since */
constexpr Uint32 TF_UNSAFE = 2;

/* A failure of a node as the file records it */
struct Record {
  Uint32 nodeId;
  Uint32 gciHi;
  Uint32 failNo;
  Uint64 seq;
};

/* X6.7: the start state, in the slots of node id 0 */
struct StartState {
  Uint64 dsc;
  Uint32 flags;
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

inline void buildState(Uint32 *line, Uint32 index, const StartState &s) {
  for (Uint32 i = 0; i < LINE_WORDS; i++) line[i] = 0;
  line[S_MAGIC] = STATE_MAGIC;
  line[S_SEQ] = Uint32(s.seq);
  line[S_SEQ + 1] = Uint32(s.seq >> 32);
  line[S_NODE_ID] = STATE_NODE_ID;
  line[S_INDEX] = index;
  line[T_DSC] = Uint32(s.dsc);
  line[T_DSC + 1] = Uint32(s.dsc >> 32);
  line[T_FLAGS] = s.flags;
  line[CHECKSUM] = checksum(line);
}

inline bool stateValid(const Uint32 *line, Uint32 index, StartState *out) {
  if (line[S_MAGIC] != STATE_MAGIC || line[S_NODE_ID] != STATE_NODE_ID ||
      line[S_INDEX] != index || line[CHECKSUM] != checksum(line)) {
    return false;
  }
  out->dsc = Uint64(line[T_DSC]) | (Uint64(line[T_DSC + 1]) << 32);
  out->flags = line[T_FLAGS];
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

/* As latest(), the start state */
inline bool latestState(const Uint8 *base, StartState *out, Uint32 *slot) {
  StartState s[2];
  bool valid[2];
  for (Uint32 i = 0; i < 2; i++) {
    valid[i] = stateValid(
        reinterpret_cast<const Uint32 *>(base + slotOffset(STATE_NODE_ID, i)),
        i, &s[i]);
  }
  if (!valid[0] && !valid[1]) {
    *slot = 0;
    return false;
  }
  const Uint32 best = (!valid[1] || (valid[0] && s[0].seq > s[1].seq)) ? 0 : 1;
  *out = s[best];
  *slot = 1 - best;
  return true;
}

/**
 * X6.7 (plan §5.4, E17): does this start follow an unsafe shutdown of the
 * persistent memory of the REDO log? Yes if the start state says so, as
 * no start completed after one (TF_UNSAFE), or if the devices now count
 * more dirty shutdowns (dsc, when dscKnown) than the state recorded. The
 * REDO log is then read to its valid end, but writes acknowledged as
 * persistent may be missing, and the node is stale for the durable tail.
 */
inline bool unsafeShutdown(const Uint8 *base, bool dscKnown, Uint64 dsc) {
  StartState s;
  Uint32 slot;
  if (!latestState(base, &s, &slot)) return false;
  if (s.flags & TF_UNSAFE) return true;
  return (s.flags & TF_DSC_VALID) != 0 && dscKnown && dsc > s.dsc;
}

/**
 * The file of this node in dir into file, FILE_BYTES, with pread(),
 * before QMGR maps it; false without a valid file of this node.
 */
inline bool readFile(const char *dir, Uint32 ownNodeId,
                     std::unique_ptr<Uint8[]> *file) {
  if (dir == nullptr) return false;
  char path[1024];
  snprintf(path, sizeof(path), "%s%s", dir, FILE_NAME);
  const int fd = ::open(path, O_RDONLY);
  if (fd < 0) return false;
  file->reset(new Uint8[FILE_BYTES]);
  const ssize_t n = ::pread(fd, file->get(), FILE_BYTES, 0);
  ::close(fd);
  return n == ssize_t(FILE_BYTES) &&
         headerValid(reinterpret_cast<const Uint32 *>(file->get()), ownNodeId);
}

/**
 * The file in dir removed, as an initial start does with the rest of the
 * file system. NDBCNTR clears directories below FileSystemPath, and the
 * whole of a FileSystemPathRedoLog directory; without one, REDO path 0
 * is FileSystemPath itself, where the file is not in any of the cleared
 * directories. Left behind, its records carry GCIs of the cluster before
 * the initial start, far above those of the new one, and the first
 * system restart finds every node stale.
 */
inline void removeFile(const char *dir) {
  if (dir == nullptr) return;
  char path[1024];
  snprintf(path, sizeof(path), "%s%s", dir, FILE_NAME);
  (void)::unlink(path);
}

/**
 * The sysfile as this node read it: the restart's GCI R, and the node
 * group (NO_GROUP for none) and the last completed GCI of each node id
 */
struct SysView {
  Uint32 restorableGci;
  Uint32 nodeGroup[ABS_MAX_NDB_NODES];
  Uint32 lastCompletedGci[ABS_MAX_NDB_NODES];
};

/* From DBDIH, which runs in the same thread as QMGR and NDBCNTR */
template <class Dih>
void fillView(const Dih *dih, SysView *v) {
  v->restorableGci = dih->sysfileRestorableGci();
  for (Uint32 nodeId = 0; nodeId < ABS_MAX_NDB_NODES; nodeId++) {
    v->nodeGroup[nodeId] = dih->sysfileNodeGroup(nodeId);
    v->lastCompletedGci[nodeId] = dih->sysfileLastCompletedGci(nodeId);
  }
}

/**
 * X6.3 (plan §5.4): may the cluster have committed on the fragments of
 * the failed node of r without it after the restart's GCI R, as the file
 * at base and the sysfile of this node show? Then its failure makes it
 * stale. That takes another node of its node group that took part in the
 * GCP save of R and outlived the failure: this node, which recorded it;
 * one with no failure recorded after R; or one whose latest failure came
 * later, with a higher seq (recordNodeFailures() gives the nodes of one
 * failure one seq). The last nodes of a node group to fail are not
 * stale: nothing ran on its fragments without them, and a cluster that
 * lost a node group can restart from them.
 */
inline bool outlived(const Uint8 *base, const Record &r, Uint32 ownNodeId,
                     const SysView &v) {
  const Uint32 ng = v.nodeGroup[r.nodeId];
  if (ng == NO_GROUP) return false;
  for (Uint32 peer = 1; peer < ABS_MAX_NDB_NODES; peer++) {
    if (peer == r.nodeId || v.nodeGroup[peer] != ng ||
        v.lastCompletedGci[peer] < v.restorableGci) {
      continue;
    }
    if (peer == ownNodeId) return true;
    Record p;
    Uint32 slot;
    if (!latest(base, peer, &p, &slot) || p.gciHi <= v.restorableGci ||
        p.seq > r.seq) {
      return true;
    }
  }
  return false;
}

/**
 * For the election (X6.3): into gci[ABS_MAX_NDB_NODES] the GCI of the
 * latest recorded failure of each node id that a peer outlived, 0 where
 * there is none, read from the file in dir before QMGR maps it; false
 * without a valid file of this node.
 */
inline bool readStaleGcis(const char *dir, Uint32 ownNodeId,
                          const SysView &v, Uint32 *gci) {
  for (Uint32 i = 0; i < ABS_MAX_NDB_NODES; i++) gci[i] = 0;
  std::unique_ptr<Uint8[]> file;
  if (!readFile(dir, ownNodeId, &file)) return false;
  for (Uint32 nodeId = 1; nodeId < ABS_MAX_NDB_NODES; nodeId++) {
    Record r;
    Uint32 slot;
    if (latest(file.get(), nodeId, &r, &slot) &&
        outlived(file.get(), r, ownNodeId, v)) {
      gci[nodeId] = r.gciHi;
    }
  }
  return true;
}

}  // namespace NodeFailFile

#endif
