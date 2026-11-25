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

#include "PmemRedoTail.hpp"

#include <cstring>
#include <new>

namespace PmemRedo {

namespace {

Uint32 hashTransid(Uint32 transid1, Uint32 transid2) {
  Uint64 h = (Uint64(transid1) << 32) | transid2;
  h ^= h >> 33;
  h *= 0xff51afd7ed558ccdULL;
  h ^= h >> 33;
  h *= 0xc4ceb9fe1a85ec53ULL;
  h ^= h >> 33;
  return Uint32(h);
}

/* Doubles arr, keeping its first cap elements; false when out of memory */
template <class T>
bool growArray(T *&arr, Uint32 &cap, Uint32 firstCap) {
  const Uint32 newCap = cap == 0 ? firstCap : 2 * cap;
  if (newCap <= cap) return false;
  T *const grown = new (std::nothrow) T[newCap];
  if (grown == nullptr) return false;
  if (cap > 0) std::memcpy(grown, arr, sizeof(T) * cap);
  delete[] arr;
  arr = grown;
  cap = newCap;
  return true;
}

/* A bucket array of n heads, all TAIL_NIL; nullptr when out of memory */
Uint32 *newBuckets(Uint32 n) {
  Uint32 *const buckets = new (std::nothrow) Uint32[n];
  if (buckets != nullptr) {
    for (Uint32 i = 0; i < n; i++) buckets[i] = TAIL_NIL;
  }
  return buckets;
}

constexpr Uint32 FIRST_CAP = 1024;  // a power of two, as the buckets

}  // namespace

/* TailTable */

TailTable::~TailTable() {
  delete[] m_entries;
  delete[] m_buckets;
  delete[] m_commits;
}

Uint32 TailTable::bucket(Uint32 transid1, Uint32 transid2) const {
  return hashTransid(transid1, transid2) & m_bucketMask;
}

/* One bucket per entry; the new entries go to the free list */
bool TailTable::growEntries() {
  const Uint32 oldCap = m_entryCap;
  Uint32 *const buckets = newBuckets(oldCap == 0 ? FIRST_CAP : 2 * oldCap);
  if (buckets == nullptr) return false;
  if (!growArray(m_entries, m_entryCap, FIRST_CAP)) {
    delete[] buckets;
    return false;
  }
  delete[] m_buckets;
  m_buckets = buckets;
  m_bucketMask = m_entryCap - 1;
  for (Uint32 e = 0; e < oldCap; e++) {
    Entry &n = m_entries[e];
    if (n.first == TAIL_NIL) continue;
    const Uint32 b = bucket(n.transid1, n.transid2);
    n.nextHash = m_buckets[b];
    m_buckets[b] = e;
  }
  for (Uint32 e = m_entryCap; e-- > oldCap;) {
    m_entries[e].first = TAIL_NIL;
    m_entries[e].nextHash = m_freeEntry;
    m_freeEntry = e;
  }
  return true;
}

bool TailTable::growCommits() {
  const Uint32 oldCap = m_commitCap;
  if (!growArray(m_commits, m_commitCap, FIRST_CAP)) return false;
  for (Uint32 c = m_commitCap; c-- > oldCap;) {
    m_commits[c].next = m_freeCommit;
    m_freeCommit = c;
  }
  return true;
}

const TailTable::Entry *TailTable::find(Uint32 transid1,
                                        Uint32 transid2) const {
  if (m_used == 0) return nullptr;
  for (Uint32 e = m_buckets[bucket(transid1, transid2)]; e != TAIL_NIL;
       e = m_entries[e].nextHash) {
    const Entry &n = m_entries[e];
    if (n.transid1 == transid1 && n.transid2 == transid2) return &n;
  }
  return nullptr;
}

TailResult TailTable::addCommit(const Pos &pos, const Uint32 *rec) {
  const Uint32 transid1 = rec[COMMIT_TRANSID1];
  const Uint32 transid2 = rec[COMMIT_TRANSID2];
  const Entry *found = find(transid1, transid2);
  if (found != nullptr && (found->gciHi != rec[COMMIT_GCI_HI] ||
                           found->opCount != rec[COMMIT_OP_COUNT])) {
    return TAIL_MISMATCH;
  }
  if (m_freeCommit == TAIL_NIL && !growCommits()) return TAIL_NO_MEMORY;
  Uint32 e;
  if (found != nullptr) {
    e = Uint32(found - m_entries);
  } else {
    if (m_freeEntry == TAIL_NIL && !growEntries()) return TAIL_NO_MEMORY;
    e = m_freeEntry;
    Entry &n = m_entries[e];
    m_freeEntry = n.nextHash;
    n.transid1 = transid1;
    n.transid2 = transid2;
    n.last = TAIL_NIL;
    n.count = 0;
    n.gciHi = rec[COMMIT_GCI_HI];
    n.opCount = rec[COMMIT_OP_COUNT];
    const Uint32 b = bucket(transid1, transid2);
    n.nextHash = m_buckets[b];
    m_buckets[b] = e;
    m_used++;
  }
  const Uint32 c = m_freeCommit;
  Node &node = m_commits[c];
  m_freeCommit = node.next;
  node.c.pos = pos;
  std::memcpy(node.c.rec, rec, sizeof(node.c.rec));
  node.next = TAIL_NIL;
  Entry &n = m_entries[e];
  if (n.last == TAIL_NIL) {
    n.first = c;
  } else {
    m_commits[n.last].next = c;
  }
  n.last = c;
  n.count++;
  m_commitsUsed++;
  return TAIL_OK;
}

void TailTable::unlink(Uint32 e) {
  Entry &n = m_entries[e];
  Uint32 *link = &m_buckets[bucket(n.transid1, n.transid2)];
  while (*link != e) link = &m_entries[*link].nextHash;
  *link = n.nextHash;
  n.first = TAIL_NIL;
  n.nextHash = m_freeEntry;
  m_freeEntry = e;
  m_used--;
}

Uint32 TailTable::take(Uint32 e) {
  const Uint32 first = m_entries[e].first;
  if (first != TAIL_NIL) unlink(e);
  return first;
}

Uint32 TailTable::takeComplete(Uint32 transid1, Uint32 transid2) {
  const Entry *n = find(transid1, transid2);
  return n == nullptr ? TAIL_NIL : take(Uint32(n - m_entries));
}

void TailTable::releaseCommits(Uint32 first) {
  while (first != TAIL_NIL) {
    const Uint32 next = m_commits[first].next;
    m_commits[first].next = m_freeCommit;
    m_freeCommit = first;
    m_commitsUsed--;
    first = next;
  }
}

/* TailUnion */

TailUnion::~TailUnion() {
  delete[] m_entries;
  delete[] m_buckets;
  delete[] m_counts;
}

Uint32 TailUnion::bucket(Uint32 transid1, Uint32 transid2) const {
  return hashTransid(transid1, transid2) & m_bucketMask;
}

bool TailUnion::grow() {
  const Uint32 oldCap = m_entryCap;
  Uint32 *const buckets = newBuckets(oldCap == 0 ? FIRST_CAP : 2 * oldCap);
  if (buckets == nullptr) return false;
  if (!growArray(m_entries, m_entryCap, FIRST_CAP)) {
    delete[] buckets;
    return false;
  }
  delete[] m_buckets;
  m_buckets = buckets;
  m_bucketMask = m_entryCap - 1;
  for (Uint32 e = 0; e < m_used; e++) {
    Entry &n = m_entries[e];
    const Uint32 b = bucket(n.transid1, n.transid2);
    n.nextHash = m_buckets[b];
    m_buckets[b] = e;
  }
  return true;
}

bool TailUnion::growCounts() {
  return growArray(m_counts, m_countCap, FIRST_CAP);
}

TailUnion::Entry *TailUnion::find(Uint32 transid1, Uint32 transid2) {
  if (m_used == 0) return nullptr;
  for (Uint32 e = m_buckets[bucket(transid1, transid2)]; e != TAIL_NIL;
       e = m_entries[e].nextHash) {
    Entry &n = m_entries[e];
    if (n.transid1 == transid1 && n.transid2 == transid2) return &n;
  }
  return nullptr;
}

const TailUnion::Entry *TailUnion::find(Uint32 transid1,
                                        Uint32 transid2) const {
  return const_cast<TailUnion *>(this)->find(transid1, transid2);
}

TailResult TailUnion::add(Uint32 nodeId, Uint32 transid1, Uint32 transid2,
                          Uint32 count, Uint32 gciHi, Uint32 opCount) {
  Entry *n = find(transid1, transid2);
  if (n != nullptr) {
    if (n->gciHi != gciHi || n->opCount != opCount) return TAIL_MISMATCH;
    for (Uint32 c = n->counts; c != TAIL_NIL; c = m_counts[c].next) {
      if (m_counts[c].nodeId == nodeId) return TAIL_DUPLICATE;
    }
  }
  if (m_countUsed == m_countCap && !growCounts()) return TAIL_NO_MEMORY;
  if (n == nullptr) {
    if (m_used == m_entryCap && !grow()) return TAIL_NO_MEMORY;
    const Uint32 e = m_used++;
    n = &m_entries[e];
    n->transid1 = transid1;
    n->transid2 = transid2;
    n->gciHi = gciHi;
    n->opCount = opCount;
    n->counts = TAIL_NIL;
    n->seenGen = 0;
    n->hit = false;
    const Uint32 b = bucket(transid1, transid2);
    n->nextHash = m_buckets[b];
    m_buckets[b] = e;
  }
  const Uint32 c = m_countUsed++;
  m_counts[c].nodeId = nodeId;
  m_counts[c].count = count;
  m_counts[c].next = n->counts;
  n->counts = c;
  return TAIL_OK;
}

void TailUnion::sawCommit(Uint32 transid1, Uint32 transid2) {
  Entry *n = find(transid1, transid2);
  if (n != nullptr) n->seenGen = m_gen;
}

TailUnion::Entry *TailUnion::sawComplete(Uint32 transid1, Uint32 transid2) {
  Entry *n = find(transid1, transid2);
  return n != nullptr && n->seenGen == m_gen ? n : nullptr;
}

Uint32 TailUnion::count(const Entry &e, Uint32 nodeId) const {
  for (Uint32 c = e.counts; c != TAIL_NIL; c = m_counts[c].next) {
    if (m_counts[c].nodeId == nodeId) return m_counts[c].count;
  }
  return 0;
}

bool TailUnion::fallbackCommits(const Entry &e, const Uint32 *srNodes,
                                Uint32 noSrNodes,
                                const Uint16 *nodeGroup) const {
  Uint64 sum = 0;
  for (Uint32 c = e.counts; c != TAIL_NIL; c = m_counts[c].next) {
    const Uint32 nodeId = m_counts[c].nodeId;
    const Uint32 ng = nodeGroup[nodeId];
    bool inSr = false;
    bool lowest = true;
    for (Uint32 i = 0; i < noSrNodes; i++) {
      if (nodeGroup[srNodes[i]] != ng) continue;
      if (count(e, srNodes[i]) != m_counts[c].count) return false;
      if (srNodes[i] == nodeId) inSr = true;
      if (srNodes[i] < nodeId) lowest = false;
    }
    if (!inSr) return false;
    /* The node group counts once, at its lowest SR node */
    if (lowest) sum += m_counts[c].count;
  }
  return sum == e.opCount;
}

bool TailUnion::commits(const Entry &e, const Uint32 *srNodes,
                        Uint32 noSrNodes, const Uint16 *nodeGroup) const {
  return e.hit || fallbackCommits(e, srNodes, noSrNodes, nodeGroup);
}

Uint32 TailUnion::gciPrime(Uint32 gciMax, const Uint32 *srNodes,
                           Uint32 noSrNodes, const Uint16 *nodeGroup) const {
  for (Uint32 e = 0; e < m_used; e++) {
    const Entry &n = m_entries[e];
    if (n.gciHi > gciMax && commits(n, srNodes, noSrNodes, nodeGroup)) {
      gciMax = n.gciHi;
    }
  }
  return gciMax;
}

}  // namespace PmemRedo
