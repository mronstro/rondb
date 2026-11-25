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
#ifndef PMEM_REDO_TAIL_HPP
#define PMEM_REDO_TAIL_HPP

#include "PmemRedoScan.hpp"

/**
 * RONDB-1150: phase 2 of a system restart on the durable tail, the
 * records after the restart's GCI R (plan §5.2, impl_next_steps.md
 * X5.3-X5.5). Plain data structures, for DBLQH and the unit test:
 *
 *   TailTable  step A in one log part: each transaction from its first
 *              durable COMMIT of the tail to its first COMPLETE, with its
 *              COMMITs in log order. What is left after the scan is the
 *              part's in-doubt set.
 *   TailUnion  steps B and C in one DBLQH worker: U, the in-doubt sets of
 *              every SR node with the count each node reported, the
 *              COMPLETEs found for them by the rescan (DI-2), and the
 *              verdicts, the same in every worker.
 *
 * Memory grows as needed; an add that finds none fails, and the restart
 * stops (Q-B11).
 */
namespace PmemRedo {

constexpr Uint32 TAIL_NIL = 0xFFFFFFFF;

enum TailResult {
  TAIL_OK = 0,
  TAIL_NO_MEMORY = 1,
  /* Two records of one transaction disagree on its GCI or opCount */
  TAIL_MISMATCH = 2,
  /* A node reported a transaction twice */
  TAIL_DUPLICATE = 3
};

/* A COMMIT of the tail as step A keeps it: where its w0 is, and its words */
struct TailCommit {
  Pos pos;
  Uint32 rec[COMMIT_LEN];
};

class TailTable {
 public:
  struct Entry {
    Uint32 transid1;
    Uint32 transid2;
    Uint32 first;  // the COMMITs in log order, TAIL_NIL when free
    Uint32 last;
    Uint32 count;
    Uint32 gciHi;
    Uint32 opCount;
    Uint32 nextHash;
  };

  TailTable() = default;
  ~TailTable();
  TailTable(const TailTable &) = delete;
  TailTable &operator=(const TailTable &) = delete;

  /* A durable COMMIT of the tail; rec holds its COMMIT_LEN words */
  TailResult addCommit(const Pos &pos, const Uint32 *rec);
  /**
   * A COMPLETE: the COMMITs of its transaction in log order, its entry
   * removed, or TAIL_NIL when the transaction has none queued. The
   * caller executes them and then releases them.
   */
  Uint32 takeComplete(Uint32 transid1, Uint32 transid2);
  const TailCommit &commit(Uint32 c) const { return m_commits[c].c; }
  Uint32 nextCommit(Uint32 c) const { return m_commits[c].next; }
  void releaseCommits(Uint32 first);

  /* The in-doubt set: the entries left, over e = 0 .. capacity() - 1 */
  Uint32 size() const { return m_used; }
  Uint32 capacity() const { return m_entryCap; }
  const Entry *entry(Uint32 e) const {
    return m_entries[e].first == TAIL_NIL ? nullptr : &m_entries[e];
  }
  const Entry *find(Uint32 transid1, Uint32 transid2) const;
  /* Step C: the COMMITs of entry e, the entry removed */
  Uint32 take(Uint32 e);
  /* COMMITs queued, over all entries */
  Uint32 commits() const { return m_commitsUsed; }

 private:
  struct Node {
    TailCommit c;
    Uint32 next;
  };
  Uint32 bucket(Uint32 transid1, Uint32 transid2) const;
  bool growEntries();
  bool growCommits();
  void unlink(Uint32 e);

  Entry *m_entries = nullptr;
  Uint32 m_entryCap = 0;
  Uint32 m_freeEntry = TAIL_NIL;  // through nextHash
  Uint32 m_used = 0;
  Uint32 *m_buckets = nullptr;
  Uint32 m_bucketMask = 0;
  Node *m_commits = nullptr;
  Uint32 m_commitCap = 0;
  Uint32 m_freeCommit = TAIL_NIL;
  Uint32 m_commitsUsed = 0;
};

class TailUnion {
 public:
  /* A transaction of U */
  struct Entry {
    Uint32 transid1;
    Uint32 transid2;
    Uint32 gciHi;
    Uint32 opCount;
    Uint32 counts;  // the counts of the nodes that reported it
    Uint32 seenGen;
    bool hit;       // a COMPLETE found in some part (step B)
    Uint32 nextHash;
  };

  TailUnion() = default;
  ~TailUnion();
  TailUnion(const TailUnion &) = delete;
  TailUnion &operator=(const TailUnion &) = delete;

  /* Step B: node reported count COMMITs of the transaction, in doubt */
  TailResult add(Uint32 nodeId, Uint32 transid1, Uint32 transid2,
                 Uint32 count, Uint32 gciHi, Uint32 opCount);
  /**
   * As add(), but a second report of the node adds to its count: the
   * DBLQH proxy merges the parts of its workers into the node's set.
   */
  TailResult merge(Uint32 nodeId, Uint32 transid1, Uint32 transid2,
                   Uint32 count, Uint32 gciHi, Uint32 opCount);
  Entry *find(Uint32 transid1, Uint32 transid2);
  const Entry *find(Uint32 transid1, Uint32 transid2) const;
  Uint32 size() const { return m_used; }
  Uint32 capacity() const { return m_entryCap; }
  const Entry *entry(Uint32 e) const {
    return e < m_used ? &m_entries[e] : nullptr;
  }

  /**
   * The rescan of a part (DI-2), one part at a time: a COMPLETE of T
   * counts only after a durable COMMIT of the tail of T in the same part,
   * as a COMPLETE from before the tail may carry a reused transid.
   */
  void startPart() { m_gen++; }
  void sawCommit(Uint32 transid1, Uint32 transid2);
  /* The transaction of a COMPLETE that counts, else nullptr */
  Entry *sawComplete(Uint32 transid1, Uint32 transid2);

  /* The count node reported for e, 0 when it did not report it */
  Uint32 count(const Entry &e, Uint32 nodeId) const;
  /**
   * Step C: commit e? Yes with a COMPLETE found, else by the fallback
   * (plan §5.5): in each node group the SR nodes report the same count,
   * and the counts of the node groups add up to opCount. srNodes holds
   * noSrNodes node ids, nodeGroup the node group of each node id.
   */
  bool commits(const Entry &e, const Uint32 *srNodes, Uint32 noSrNodes,
               const Uint16 *nodeGroup) const;
  bool fallbackCommits(const Entry &e, const Uint32 *srNodes,
                       Uint32 noSrNodes, const Uint16 *nodeGroup) const;
  /* G': gciMax, or above it the GCI of a transaction of U that commits */
  Uint32 gciPrime(Uint32 gciMax, const Uint32 *srNodes, Uint32 noSrNodes,
                  const Uint16 *nodeGroup) const;

 private:
  struct Count {
    Uint32 nodeId;
    Uint32 count;
    Uint32 next;
  };
  Uint32 bucket(Uint32 transid1, Uint32 transid2) const;
  bool grow();
  bool growCounts();
  TailResult add(Uint32 nodeId, Uint32 transid1, Uint32 transid2,
                 Uint32 count, Uint32 gciHi, Uint32 opCount, bool sum);

  Entry *m_entries = nullptr;  // dense, never removed
  Uint32 m_entryCap = 0;
  Uint32 m_used = 0;
  Uint32 *m_buckets = nullptr;
  Uint32 m_bucketMask = 0;
  Count *m_counts = nullptr;
  Uint32 m_countCap = 0;
  Uint32 m_countUsed = 0;
  Uint32 m_gen = 1;  // an entry starts with seenGen 0, seen in no part
};

}  // namespace PmemRedo

#endif
