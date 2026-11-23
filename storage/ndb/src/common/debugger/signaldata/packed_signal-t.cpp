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
 * RONDB-1150 (X4.3, X4.14): the packed COMMIT of a durable transaction,
 * ZCOMMIT_DURABLE (8): the words of ZCOMMIT and the opCount. The packed
 * signals as Dbtc::sendCommitLqh and Dblqh::sendCommitLqh put them in a
 * container of at most 25 words, checked by PackedSignal::verify() as
 * the senders and the receivers check them, and printed by the printers
 * of PACKED_SIGNAL and COMMIT.
 */

#include <ndb_global.h>
#include <ndb_init.h>
#include <util/NdbTap.hpp>

#include <BlockNumbers.h>
#include <GlobalSignalNumbers.h>
#include <debugger/DebuggerNames.hpp>
#include <signaldata/CommitReq.hpp>
#include <signaldata/PackedSignal.hpp>

#include <cstring>
#include <string>

namespace {

/* The words of a container, with room for a signal read past its end */
constexpr Uint32 CONTAINER_WORDS = 25;

struct Container {
  Uint32 words[CONTAINER_WORDS + ZCOMMIT_DURABLE_LEN] = {};
  Uint32 len = 0;
};

/* As Dbtc::sendCommitLqh: [ptr, gci_hi, transid1, transid2, gci_lo] and,
   with the code of a durable transaction, its opCount */
void packCommit(Container &c, Uint32 ptr, Uint64 gci, Uint32 transid1,
                Uint32 transid2, bool durable, Uint32 opCount) {
  const Uint32 len =
      durable ? Uint32(Commit::SignalLengthDurable) : Commit::SignalLength;
  const Uint32 code = durable ? ZCOMMIT_DURABLE : ZCOMMIT;
  Uint32 w[ZCOMMIT_DURABLE_LEN] = {ptr,      Uint32(gci >> 32), transid1,
                                   transid2, Uint32(gci),       opCount};
  w[0] |= code << 28;
  OK(c.len + len <= CONTAINER_WORDS);
  memcpy(&c.words[c.len], w, len * sizeof(Uint32));
  c.len += len;
}

/* [ptr, transid1, transid2], as COMPLETE, COMMITTED and COMPLETED */
void packThree(Container &c, Uint32 code, Uint32 ptr, Uint32 transid1,
               Uint32 transid2) {
  OK(c.len + 3 <= CONTAINER_WORDS);
  c.words[c.len++] = ptr | (code << 28);
  c.words[c.len++] = transid1;
  c.words[c.len++] = transid2;
}

/* As the senders check a container for DBLQH, and DBLQH on receipt */
bool verifyForLqh(const Container &c) {
  return PackedSignal::verify(c.words, c.len, DBLQH, LQH_RECEIVE_TYPES,
                              Commit::SignalLength);
}

bool verifyForTc(const Container &c) {
  return PackedSignal::verify(c.words, c.len, DBTC, TC_RECEIVE_TYPES, 0);
}

std::string printed(GlobalSignalNumber gsn, const Uint32 *data, Uint32 len) {
  SignalDataPrintFunction print = findPrintFunction(gsn);
  OK(print != nullptr);
  FILE *f = tmpfile();
  OK(f != nullptr);
  OK(print(f, data, len, DBLQH));
  std::string out;
  rewind(f);
  char buf[512];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
  fclose(f);
  return out;
}

int count(const std::string &s, const char *what) {
  int n = 0;
  for (size_t at = s.find(what); at != std::string::npos;
       at = s.find(what, at + 1)) {
    n++;
  }
  return n;
}

void codes() {
  /* The code fits the 4 bits of word 0, DBLQH takes it and DBTC not */
  OK(ZCOMMIT_DURABLE < 16);
  OK((LQH_RECEIVE_TYPES & (1 << ZCOMMIT_DURABLE)) != 0);
  OK((TC_RECEIVE_TYPES & (1 << ZCOMMIT_DURABLE)) == 0);
  /* DBLQH unpacks it into an unpacked durable COMMIT */
  OK(ZCOMMIT_DURABLE_LEN == Commit::SignalLengthDurable);
  OK(Commit::SignalLengthDurable == Commit::SignalLength + 1);
}

void containers() {
  const Uint64 gci = (Uint64(77) << 32) | 5;

  /* Durable and plain COMMITs with COMPLETEs, as one container */
  {
    Container c;
    packCommit(c, 1, gci, 0x10, 0x20, true, 3);
    packCommit(c, 2, gci, 0x11, 0x21, false, 0);
    packThree(c, ZCOMPLETE, 3, 0x12, 0x22);
    packCommit(c, 4, gci, 0x13, 0x23, true, 0x0fffffff);
    OK(c.len == 6 + 5 + 3 + 6);
    OK(verifyForLqh(c));
  }

  /* The fullest container: a COMMIT of 6 words is added up to 25 words
     (the senders send the container first when it has more than 25 - 6) */
  {
    Container c;
    packCommit(c, 1, gci, 1, 2, true, 1);
    packCommit(c, 2, gci, 1, 2, false, 0);
    packCommit(c, 3, gci, 1, 2, false, 0);
    packThree(c, ZCOMPLETE, 4, 1, 2);
    OK(c.len == CONTAINER_WORDS - ZCOMMIT_DURABLE_LEN);
    packCommit(c, 5, gci, 1, 2, true, 2);
    OK(c.len == CONTAINER_WORDS);
    OK(verifyForLqh(c));
  }

  /* An opCount with all bits set is data, not a code */
  {
    Container c;
    packCommit(c, 1, gci, 1, 2, true, 0xffffffff);
    packThree(c, ZCOMPLETE, 2, 1, 2);
    OK(verifyForLqh(c));
  }

  /* The replies to DBTC are as before */
  {
    Container c;
    packThree(c, ZCOMMITTED, 1, 1, 2);
    packThree(c, ZCOMPLETED, 2, 1, 2);
    OK(verifyForTc(c));
  }
}

void refused() {
  const Uint64 gci = (Uint64(9) << 32) | 1;

  /* A durable COMMIT to DBTC */
  {
    Container c;
    packCommit(c, 1, gci, 1, 2, true, 1);
    OK(!verifyForTc(c));
  }

  /* A durable COMMIT cut to the length of a plain one */
  {
    Container c;
    packThree(c, ZCOMPLETE, 1, 1, 2);
    packCommit(c, 2, gci, 1, 2, true, 1);
    c.len--;
    OK(!verifyForLqh(c));
  }

  /* A plain COMMIT with the durable code: the next signal is misread */
  {
    Container c;
    packCommit(c, 1, gci, 1, 2, false, 0);
    c.words[0] = (c.words[0] & 0x0fffffff) | (Uint32(ZCOMMIT_DURABLE) << 28);
    packThree(c, ZCOMPLETE, 2, 1, 2);
    OK(!verifyForLqh(c));
  }
}

void printers() {
  const Uint64 gci = (Uint64(12) << 32) | 34;
  Container c;
  packCommit(c, 1, gci, 0x10, 0x20, true, 7);
  packThree(c, ZCOMPLETE, 2, 0x10, 0x20);
  packCommit(c, 3, gci, 0x10, 0x20, false, 0);
  packCommit(c, 4, gci, 0x10, 0x20, true, 8);

  const std::string packed = printed(GSN_PACKED_SIGNAL, c.words, c.len);
  OK(count(packed, "r.sn: \"COMMIT_DURABLE\"") == 2);
  OK(count(packed, "r.sn: \"COMMIT\"") == 1);
  OK(count(packed, "r.sn: \"COMPLETE\"") == 1);
  OK(count(packed, "length: 6,") == 2);
  OK(count(packed, "Packed signal 3 ") == 1);
  OK(count(packed, "Packed signal 4 ") == 0);

  /* The unpacked COMMIT that DBLQH makes of it, and a plain one */
  Uint32 commit[ZCOMMIT_DURABLE_LEN] = {1, 12, 0x10, 0x20, 34, 7};
  const std::string durable =
      printed(GSN_COMMIT, commit, Commit::SignalLengthDurable);
  OK(count(durable, "durable, opCount = 7") == 1);
  const std::string plain = printed(GSN_COMMIT, commit, Commit::SignalLength);
  OK(count(plain, "durable") == 0);
  OK(count(plain, "gci_lo = H'00000022 gci_hi = H'0000000c") == 1);
}

}  // namespace

TAPTEST(packed_signal) {
  ndb_init();
  codes();
  containers();
  refused();
  printers();
  ndb_end(0);
  return 1;
}
