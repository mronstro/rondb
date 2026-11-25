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
 * RONDB-1150, X5.3-X5.5: the tables of phase 2 (PmemRedoTail.cpp). Step A
 * queues the COMMITs of a transaction in log order and hands them over at
 * its first COMPLETE; what is left is the in-doubt set. Steps B and C
 * merge the in-doubt sets of the nodes, count a COMPLETE only after a
 * COMMIT of the tail in the same part (DI-2), and decide by a COMPLETE or
 * by the node-group counts against opCount (plan §5.5).
 */

#include <ndb_global.h>
#include <util/NdbTap.hpp>

#include <cstring>

#include "PmemRedoTail.hpp"

using namespace PmemRedo;

namespace {

void commitRec(Uint32 *rec, Uint32 transid1, Uint32 transid2, Uint32 gciHi,
               Uint32 opCount, Uint32 tag) {
  commitRecord(rec, CF_DURABLE, /*tableId*/ tag, 1, 0, 0, 0, 16, 0, gciHi, 0,
               transid1, transid2, opCount);
}

Pos posOf(Uint32 n) { return Pos{n / 1000, n % 1000, 16, 1}; }

/* Step A in one part: hand-over at COMPLETE, log order, the in-doubt set */
void stepA() {
  TailTable t;
  Uint32 rec[COMMIT_LEN];
  commitRec(rec, 1, 10, 7, 3, 100);
  OK(t.addCommit(posOf(1), rec) == TAIL_OK);
  commitRec(rec, 2, 20, 7, 1, 200);
  OK(t.addCommit(posOf(2), rec) == TAIL_OK);
  commitRec(rec, 1, 10, 7, 3, 101);
  OK(t.addCommit(posOf(3), rec) == TAIL_OK);
  OK(t.size() == 2 && t.commits() == 3);

  /* The same transaction with another GCI or opCount */
  commitRec(rec, 1, 10, 8, 3, 102);
  OK(t.addCommit(posOf(4), rec) == TAIL_MISMATCH);
  commitRec(rec, 1, 10, 7, 4, 102);
  OK(t.addCommit(posOf(4), rec) == TAIL_MISMATCH);
  OK(t.commits() == 3);

  /* A COMPLETE of a transaction with none queued */
  OK(t.takeComplete(3, 30) == TAIL_NIL);
  OK(t.takeComplete(1, 11) == TAIL_NIL);

  Uint32 c = t.takeComplete(1, 10);
  OK(c != TAIL_NIL);
  OK(t.commit(c).rec[COMMIT_TABLE_ID] == 100);
  OK(t.commit(c).pos.pageNo == 1);
  const Uint32 c2 = t.nextCommit(c);
  OK(c2 != TAIL_NIL && t.commit(c2).rec[COMMIT_TABLE_ID] == 101);
  OK(t.nextCommit(c2) == TAIL_NIL);
  OK(t.size() == 1 && t.find(1, 10) == nullptr);
  /* A later COMPLETE of the same transaction: already executed */
  OK(t.takeComplete(1, 10) == TAIL_NIL);
  t.releaseCommits(c);
  OK(t.commits() == 1);

  /* The in-doubt set */
  Uint32 seen = 0;
  for (Uint32 e = 0; e < t.capacity(); e++) {
    const TailTable::Entry *n = t.entry(e);
    if (n == nullptr) continue;
    seen++;
    OK(n->transid1 == 2 && n->transid2 == 20 && n->count == 1 &&
       n->gciHi == 7 && n->opCount == 1);
    const Uint32 f = t.take(e);
    OK(f != TAIL_NIL && t.commit(f).rec[COMMIT_TABLE_ID] == 200);
    t.releaseCommits(f);
  }
  OK(seen == 1 && t.size() == 0 && t.commits() == 0);
}

/* Many transactions: growth, rehash, reuse of free entries */
void manyTransactions() {
  TailTable t;
  Uint32 rec[COMMIT_LEN];
  const Uint32 N = 5000;
  for (Uint32 round = 0; round < 3; round++) {
    for (Uint32 i = 0; i < N; i++) {
      for (Uint32 k = 0; k < 3; k++) {
        commitRec(rec, i, round, 9, 3, i);
        OK(t.addCommit(posOf(i), rec) == TAIL_OK);
      }
    }
  }
  OK(t.size() == 3 * N && t.commits() == 9 * N);
  /* Complete the even transactions of round 1 */
  for (Uint32 i = 0; i < N; i += 2) {
    const Uint32 c = t.takeComplete(i, 1);
    OK(c != TAIL_NIL);
    Uint32 k = 0;
    for (Uint32 x = c; x != TAIL_NIL; x = t.nextCommit(x)) k++;
    OK(k == 3);
    t.releaseCommits(c);
  }
  OK(t.size() == 3 * N - N / 2 && t.commits() == 9 * N - 3 * (N / 2));
  OK(t.find(2, 1) == nullptr && t.find(3, 1) != nullptr);
  /* Freed entries are reused */
  for (Uint32 i = 0; i < N; i += 2) {
    commitRec(rec, i, 7, 9, 1, i);
    OK(t.addCommit(posOf(i), rec) == TAIL_OK);
  }
  Uint32 left = 0;
  for (Uint32 e = 0; e < t.capacity(); e++) {
    if (t.entry(e) == nullptr) continue;
    left++;
    t.releaseCommits(t.take(e));
  }
  OK(left == 3 * N && t.size() == 0 && t.commits() == 0);
}

/* Steps B and C: U, the rescan rule, the verdicts and G' */
void stepsBC() {
  /* Node groups: 1, 2 in 0; 3, 4 in 1 */
  Uint16 ng[8];
  for (Uint32 i = 0; i < 8; i++) ng[i] = 0xFFFF;
  ng[1] = ng[2] = 0;
  ng[3] = ng[4] = 1;
  const Uint32 sr[] = {1, 2, 3, 4};

  TailUnion u;
  /* T1: 2 ops in node group 0, 1 in node group 1, all COMMITs there */
  OK(u.add(1, 1, 1, 2, 10, 3) == TAIL_OK);
  OK(u.add(2, 1, 1, 2, 10, 3) == TAIL_OK);
  OK(u.add(3, 1, 1, 1, 10, 3) == TAIL_OK);
  OK(u.add(4, 1, 1, 1, 10, 3) == TAIL_OK);
  /* T2: as T1 but node 4 lacks its COMMIT */
  OK(u.add(1, 2, 2, 2, 11, 3) == TAIL_OK);
  OK(u.add(2, 2, 2, 2, 11, 3) == TAIL_OK);
  OK(u.add(3, 2, 2, 1, 11, 3) == TAIL_OK);
  /* T3: node group 0 only, every COMMIT there */
  OK(u.add(1, 3, 3, 2, 12, 2) == TAIL_OK);
  OK(u.add(2, 3, 3, 2, 12, 2) == TAIL_OK);
  /* T4: a COMMIT of an op that no node has: opCount 3, counts add to 2 */
  OK(u.add(1, 4, 4, 2, 13, 3) == TAIL_OK);
  OK(u.add(2, 4, 4, 2, 13, 3) == TAIL_OK);
  /* T5: node 2 has one COMMIT less than node 1 */
  OK(u.add(1, 5, 5, 2, 14, 2) == TAIL_OK);
  OK(u.add(2, 5, 5, 1, 14, 2) == TAIL_OK);
  OK(u.size() == 5);

  OK(u.add(1, 1, 1, 2, 10, 3) == TAIL_DUPLICATE);
  OK(u.add(3, 3, 3, 2, 99, 2) == TAIL_MISMATCH);
  OK(u.add(3, 3, 3, 2, 12, 5) == TAIL_MISMATCH);

  const TailUnion::Entry *t1 = u.find(1, 1);
  const TailUnion::Entry *t2 = u.find(2, 2);
  const TailUnion::Entry *t3 = u.find(3, 3);
  const TailUnion::Entry *t4 = u.find(4, 4);
  const TailUnion::Entry *t5 = u.find(5, 5);
  OK(t1 && t2 && t3 && t4 && t5 && u.find(6, 6) == nullptr);
  OK(u.count(*t2, 4) == 0 && u.count(*t2, 3) == 1);

  OK(u.fallbackCommits(*t1, sr, 4, ng));
  OK(!u.fallbackCommits(*t2, sr, 4, ng));
  OK(u.fallbackCommits(*t3, sr, 4, ng));
  OK(!u.fallbackCommits(*t4, sr, 4, ng));
  OK(!u.fallbackCommits(*t5, sr, 4, ng));
  /* G' with the fallback alone: T1 and T3 */
  OK(u.gciPrime(5, sr, 4, ng) == 12);
  OK(u.gciPrime(20, sr, 4, ng) == 20);

  /* The rescan of a part: a COMPLETE counts after a tail COMMIT there */
  u.startPart();
  OK(u.sawComplete(2, 2) == nullptr);
  u.sawCommit(2, 2);
  u.sawCommit(9, 9);  // not in U
  TailUnion::Entry *hit = u.sawComplete(2, 2);
  OK(hit != nullptr && hit->transid1 == 2);
  hit->hit = true;
  OK(u.sawComplete(9, 9) == nullptr);
  /* The next part: the COMMIT seen in the last one does not count */
  u.startPart();
  OK(u.sawComplete(5, 5) == nullptr);
  OK(u.sawComplete(2, 2) == nullptr);
  u.sawCommit(5, 5);
  OK(u.sawComplete(5, 5) != nullptr);

  /* T2 now commits by its COMPLETE */
  OK(u.commits(*t2, sr, 4, ng) && !u.fallbackCommits(*t2, sr, 4, ng));
  OK(!u.commits(*t5, sr, 4, ng));
  OK(u.gciPrime(5, sr, 4, ng) == 12);
  u.find(5, 5)->hit = true;
  OK(u.gciPrime(5, sr, 4, ng) == 14);

  /* Only nodes 1 and 3 in the SR, one per node group */
  TailUnion u2;
  const Uint32 sr2[] = {1, 3};
  OK(u2.add(1, 1, 1, 2, 10, 3) == TAIL_OK);
  OK(u2.add(3, 1, 1, 1, 10, 3) == TAIL_OK);
  OK(u2.add(1, 4, 4, 2, 13, 3) == TAIL_OK);
  OK(u2.fallbackCommits(*u2.find(1, 1), sr2, 2, ng));
  OK(!u2.fallbackCommits(*u2.find(4, 4), sr2, 2, ng));
  /* A node outside the SR never reports; if one did, no fallback */
  OK(!u.fallbackCommits(*t1, sr2, 2, ng));
}

/* U grows past its first capacity */
void manyInDoubt() {
  Uint16 ng[4] = {0xFFFF, 0, 0, 0xFFFF};
  const Uint32 sr[] = {1, 2};
  TailUnion u;
  const Uint32 N = 5000;
  for (Uint32 i = 0; i < N; i++) {
    OK(u.add(1, i, 0, 1, 100 + i, 1) == TAIL_OK);
    if (i % 2 == 0) OK(u.add(2, i, 0, 1, 100 + i, 1) == TAIL_OK);
  }
  OK(u.size() == N);
  Uint32 commit = 0;
  for (Uint32 e = 0; e < u.size(); e++) {
    if (u.commits(*u.entry(e), sr, 2, ng)) commit++;
  }
  OK(commit == N / 2);
  OK(u.gciPrime(0, sr, 2, ng) == 100 + N - 2);
}

}  // namespace

TAPTEST(pmem_redo_tail) {
  stepA();
  manyTransactions();
  stepsBC();
  manyInDoubt();
  return 1;
}
