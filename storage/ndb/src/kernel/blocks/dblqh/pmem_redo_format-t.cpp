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
 * RONDB-1150, step 1 plan S4.1: the bytes of the REDO log format with
 * RedoLogMode=pmem (PmemRedoFormat.hpp). The checksum against xxhash's
 * own XXH3, every record type through recordOk, the page header image,
 * and the size arithmetic. The scan over whole logs is pmem_redo_scan-t.
 */

#include <ndb_global.h>
#include <util/NdbTap.hpp>

#include <cstdio>
#include <cstring>

#include "PmemRedoFormat.hpp"

#define XXH_INLINE_ALL
#include <util/ndb_xxhash.h>

using namespace PmemRedo;

namespace {

/* The checksum as E4 defines it, from xxhash itself */
Uint32 referenceChecksum(Uint32 w0, Uint64 bodyHash, const Suffix &s) {
  const Uint32 mix[5] = {w0 & ~RF_INVALIDATED, s.lap, s.gen, s.partFile,
                         s.pos};
  return Uint32(XXH3_64bits_withSeed(mix, sizeof(mix), bodyHash));
}

void fillBody(Uint32 *body, Uint32 n, Uint32 seed) {
  for (Uint32 i = 0; i < n; i++) body[i] = seed * 0x9E3779B1u + i * 0x85EBCA77u;
}

/* A record of len words at rec, its checksum for s in w1 */
void build(Uint32 *rec, Uint32 type, Uint32 flags, Uint32 len,
           const Suffix &s) {
  rec[0] = makeW0(type, flags, len);
  fillBody(rec + 2, len - 2, len + type);
  if (type == TYPE_PREPARE) {
    const Uint32 head = (flags & PF_TRANSID) ? PREPARE_HEAD + 2 : PREPARE_HEAD;
    const Uint32 keyLen = 3;
    rec[PREP_KEY_LEN] = keyLen;
    rec[PREP_AI_LEN] = len - head - keyLen - ((len - head - keyLen) & 1);
  }
  rec[1] = recordChecksum(rec, s);
}

void checksumVectors() {
  /* XXH3_64 of no bytes */
  OK(EMPTY_HASH == XXH3_64bits(nullptr, 0));

  /* A COMMIT: its body in one piece */
  Uint32 rec[COMMIT_LEN];
  rec[0] = makeW0(TYPE_COMMIT, CF_DURABLE, COMMIT_LEN);
  for (Uint32 i = 2; i < COMMIT_LEN; i++) rec[i] = 1000 + i;
  const Suffix s = suffix(7, 3, 2, 100, 40);
  OK(s.lap == 7 && s.gen == 0 && s.partFile == ((3u << 16) | 2) &&
     s.pos == 100 * 8192 + 40);
  const Uint32 expected = referenceChecksum(
      rec[0], XXH3_64bits(rec + 2, 4 * (COMMIT_LEN - 2)), s);
  OK(recordChecksum(rec, s) == expected);

  /* RF_INVALIDATED is not in the checksum */
  rec[0] |= RF_INVALIDATED;
  OK(recordChecksum(rec, s) == expected);

  /* No body: the hash of no bytes, which the writer need not compute */
  const Uint32 nextMbyte = makeW0(TYPE_NEXT_MBYTE, 0, NEXT_MBYTE_LEN);
  RecChecksum none;
  OK(none.finish(nextMbyte, s) == referenceChecksum(nextMbyte, EMPTY_HASH, s));

  /* A FILLER: only w0 and S, whatever its length */
  Uint32 filler[FILLER_MAX];
  filler[0] = makeW0(TYPE_FILLER, 0, FILLER_MAX);
  fillBody(filler + 2, FILLER_MAX - 2, 5);
  OK(recordChecksum(filler, s) == referenceChecksum(filler[0], EMPTY_HASH, s));

  /* A body in two pieces: the hash of the first seeds the second */
  Uint32 body[100];
  fillBody(body, 100, 9);
  const Uint32 w0 = makeW0(TYPE_PREPARE, 0, 102);
  RecChecksum two;
  two.piece(body, 0);  // an empty piece changes nothing
  two.piece(body, 30);
  two.piece(body + 30, 70);
  const Uint64 chained =
      XXH3_64bits_withSeed(body + 30, 4 * 70, XXH3_64bits(body, 4 * 30));
  OK(two.finish(w0, s) == referenceChecksum(w0, chained, s));
  RecChecksum one;
  one.piece(body, 100);
  OK(one.finish(w0, s) == referenceChecksum(w0, XXH3_64bits(body, 400), s));
  OK(one.finish(w0, s) != two.finish(w0, s));
  RecChecksum swapped;
  swapped.piece(body + 30, 70);
  swapped.piece(body, 30);
  OK(swapped.finish(w0, s) != two.finish(w0, s));

  /* A long body, beyond XXH3's 240-byte inline path */
  Uint32 big[2000];
  fillBody(big, 2000, 13);
  RecChecksum c;
  c.piece(big, 2000);
  OK(c.finish(w0, s) == referenceChecksum(w0, XXH3_64bits(big, 8000), s));
}

struct TypeCase {
  Uint32 type;
  Uint32 flags;
  Uint32 len;
};

void recordTypes() {
  const TypeCase cases[] = {
      {TYPE_PREPARE, 0, prepareLen(3, 10, false)},
      {TYPE_PREPARE, 0, prepareLen(3, 11, false)},  // with the pad word
      {TYPE_PREPARE, PF_TRANSID, prepareLen(3, 10, true)},
      {TYPE_PREPARE, 0, prepareLen(3, 4000, false)},
      {TYPE_COMMIT, 0, COMMIT_LEN},
      {TYPE_COMMIT, CF_DURABLE, COMMIT_LEN},
      {TYPE_ABORT, 0, ABORT_LEN},
      {TYPE_ABORT, AF_AFTER_COMMIT, ABORT_LEN},
      {TYPE_COMPLETE, 0, COMPLETE_LEN},
      {TYPE_COMPLETED_GCI, 0, COMPLETED_GCI_LEN},
      {TYPE_NEXT_MBYTE, 0, NEXT_MBYTE_LEN},
      {TYPE_FILLER, 0, FILLER_MIN},
      {TYPE_FILLER, 0, FILLER_MAX},
      {TYPE_FD, 0, fdLen(3, 4)},
      {TYPE_SR_HEAD, 0, SR_HEAD_LEN},
  };
  static Uint32 rec[PAGE_DATA_WORDS];
  for (const TypeCase &tc : cases) {
    const Suffix s = suffix(3, 1, 2, 77, 1000);
    build(rec, tc.type, tc.flags, tc.len, s);
    OK(checkRecordWords(rec, tc.len, s) == R_VALID);
    OK(!recordOk(rec, tc.len - 2, s));  // longer than the room

    /* A changed body word: a FILLER's body is dead */
    for (Uint32 i = 2; i < tc.len; i++) {
      rec[i] ^= 0x100;
      const Uint32 r = checkRecordWords(rec, tc.len, s);
      if (tc.type == TYPE_FILLER)
        OK(r == R_VALID);
      else if (tc.type == TYPE_PREPARE &&
               (i == PREP_AI_LEN || i == PREP_KEY_LEN))
        OK(r == R_LEN);
      else
        OK(r == R_CHECKSUM);
      rec[i] ^= 0x100;
    }

    /* The same bytes in another lap, log part, file or place */
    const Suffix other[] = {
        suffix(4, 1, 2, 77, 1000), suffix(2, 1, 2, 77, 1000),
        suffix(3, 0, 2, 77, 1000), suffix(3, 1, 3, 77, 1000),
        suffix(3, 1, 2, 78, 1000), suffix(3, 1, 2, 77, 1002),
        Suffix{3, 1, s.partFile, s.pos}};
    for (const Suffix &o : other)
      OK(checkRecordWords(rec, tc.len, o) == R_CHECKSUM);

    /* RF_INVALIDATED: kept by a COMMIT, a flag no other type has */
    rec[0] |= RF_INVALIDATED;
    OK(checkRecordWords(rec, tc.len, s) ==
       (tc.type == TYPE_COMMIT ? R_VALID : R_FLAGS));
    rec[0] &= ~RF_INVALIDATED;

    /* Another length in w0 */
    rec[0] = makeW0(tc.type, tc.flags, tc.len + 2);
    OK(!recordOk(rec, tc.len + 2, s));
    rec[0] = makeW0(tc.type, tc.flags, tc.len);
    OK(recordOk(rec, tc.len, s));
  }
}

void framing() {
  OK(checkFraming(makeW0(0, 0, 0)) == R_TYPE_ZERO);
  OK(checkFraming(0) == R_TYPE_ZERO);
  const Uint32 unknown[] = {5, 6, 9, 13, 100, 255};
  for (Uint32 t : unknown) OK(checkFraming(makeW0(t, 0, 4)) == R_TYPE_UNKNOWN);

  OK(checkFraming(makeW0(TYPE_COMMIT, 0, 11)) == R_LEN);
  OK(checkFraming(makeW0(TYPE_COMMIT, 0, 10)) == R_LEN);
  OK(checkFraming(makeW0(TYPE_COMMIT, 0, 14)) == R_LEN);
  OK(checkFraming(makeW0(TYPE_ABORT, 0, 2)) == R_LEN);
  OK(checkFraming(makeW0(TYPE_COMPLETE, 0, 6)) == R_LEN);
  OK(checkFraming(makeW0(TYPE_COMPLETED_GCI, 0, 2)) == R_LEN);
  OK(checkFraming(makeW0(TYPE_NEXT_MBYTE, 0, 4)) == R_LEN);
  OK(checkFraming(makeW0(TYPE_SR_HEAD, 0, 4)) == R_LEN);
  OK(checkFraming(makeW0(TYPE_FILLER, 0, 0)) == R_LEN);
  OK(checkFraming(makeW0(TYPE_FILLER, 0, PAGE_DATA_WORDS + 2)) == R_LEN);
  OK(checkFraming(makeW0(TYPE_FD, 0, PAGE_DATA_WORDS + 2)) == R_LEN);
  OK(checkFraming(makeW0(TYPE_PREPARE, 0, 6)) == R_LEN);
  OK(checkFraming(makeW0(TYPE_PREPARE, 0, PREPARE_MAX)) == R_VALID);
  OK(checkFraming(makeW0(TYPE_PREPARE, 0, PREPARE_MAX + 2)) == R_LEN);

  /* Flags of other types, and the reserved ones */
  OK(checkFraming(makeW0(TYPE_COMPLETE, 1u << 9, 4)) == R_FLAGS);
  OK(checkFraming(makeW0(TYPE_COMMIT, 1u << 10, 12)) == R_FLAGS);
  OK(checkFraming(makeW0(TYPE_FILLER, 1u << 15, 4)) == R_FLAGS);
  OK(checkFraming(makeW0(TYPE_COMMIT, RF_INVALIDATED | CF_DURABLE, 12)) ==
     R_VALID);

  /* The length of a PREPARE is that of its content */
  OK(prepareLenOk(makeW0(TYPE_PREPARE, 0, 22), 10, 3));
  OK(!prepareLenOk(makeW0(TYPE_PREPARE, 0, 24), 10, 3));
  OK(!prepareLenOk(makeW0(TYPE_PREPARE, PF_TRANSID, 22), 10, 3));
  OK(prepareLenOk(makeW0(TYPE_PREPARE, PF_TRANSID, 24), 10, 3));
  OK(!prepareLenOk(makeW0(TYPE_PREPARE, 0, 22), 0xFFFFFFF0, 26));

  /* The length of an FD is that of its descriptors */
  OK(fdLenOk(makeW0(TYPE_FD, 0, fdLen(3, 4)), 3, 3, 4));
  OK(!fdLenOk(makeW0(TYPE_FD, 0, fdLen(3, 4)), 2, 3, 4));
  OK(!fdLenOk(makeW0(TYPE_FD, 0, fdLen(0, 4)), 0, 3, 4));
  OK(!fdLenOk(makeW0(TYPE_FD, 0, fdLen(4, 4)), 4, 3, 4));
  OK(!fdLenOk(makeW0(TYPE_FD, 0, fdLen(3, 1024)), 3, 3, 1024));
}

void pageHeader() {
  Uint32 dram[HEADER_WORDS];
  for (Uint32 i = 0; i < HEADER_WORDS; i++) dram[i] = 0xD0000000 + i;
  Uint32 img[HEADER_WORDS];
  buildPageHeader(img, dram, 5, 1234, 3, 7);

  /* The words recovery reads, the identity and the format; 0 elsewhere */
  const Uint32 kept[] = {HDR_LAP,      HDR_MAX_GCI_COMPLETED,
                         HDR_MAX_GCI_STARTED, HDR_VERSION,
                         HDR_NO_LOG_FILES,    HDR_LAST_PREP_REF,
                         HDR_NO_LOG_PARTS};
  for (Uint32 w : kept) OK(img[w] == dram[w]);
  OK(img[HDR_PAGE_NO] == 1234 && img[HDR_FILE_NO] == 5 &&
     img[HDR_LOG_PART_NO] == 3 && img[HDR_NODE_ID] == 7);
  OK(img[HDR_FORMAT_MAGIC] == FORMAT_MAGIC && img[HDR_WRITE_UNIT] == 64 &&
     img[HDR_RESTART_GEN] == 0);
  const Uint32 zero[] = {4, 5, 8, 9, 11, 12, 13, 14, 17, 18, 19, 20,
                         27, 28, 29, 30, 31};
  for (Uint32 w : zero) OK(img[w] == 0);
  OK(img[HDR_CHECKSUM] == Uint32(XXH3_64bits(img + 1, 124)));
  OK(checkPageHeader(img, 5, 1234, 3) == R_VALID);
  OK(pageHeaderOk(img, 5, 1234, 3));

  /* Built in place, from the DRAM header itself */
  Uint32 inPlace[HEADER_WORDS];
  memcpy(inPlace, dram, sizeof(dram));
  buildPageHeader(inPlace, inPlace, 5, 1234, 3, 7);
  OK(memcmp(inPlace, img, sizeof(img)) == 0);

  /* No word of 1-31 can change: no mask (R2) */
  for (Uint32 w = 0; w < HEADER_WORDS; w++) {
    img[w] ^= 0x10;
    const Uint32 r = checkPageHeader(img, 5, 1234, 3);
    if (w == HDR_FORMAT_MAGIC || w == HDR_WRITE_UNIT || w == HDR_RESTART_GEN)
      OK(r == R_HDR_FORMAT);
    else
      OK(r == R_HDR_CHECKSUM);
    img[w] ^= 0x10;
  }

  /* Another place */
  OK(checkPageHeader(img, 4, 1234, 3) == R_HDR_IDENTITY);
  OK(checkPageHeader(img, 5, 1235, 3) == R_HDR_IDENTITY);
  OK(checkPageHeader(img, 5, 1234, 2) == R_HDR_IDENTITY);

  /* A zeroed page */
  Uint32 none[HEADER_WORDS] = {0};
  OK(checkPageHeader(none, 0, 0, 0) == R_HDR_FORMAT);
}

void sizes() {
  for (Uint32 idx = HEADER_WORDS; idx < PAGE_WORDS; idx += 2) {
    const Uint32 pad = padWords(idx);
    OK(pad % 2 == 0 && pad < W_WORDS && (idx + pad) % W_WORDS == 0);
  }
  OK(padWords(HEADER_WORDS) == 0);
  OK(padWords(PAGE_WORDS - 2) == 2);

  OK(PREPARE_MAX == 23130);
  OK(prepareLen(MAX_KEY_SIZE_IN_WORDS, MAX_LOG_RECORD_SIZE_WORDS, true) ==
     PREPARE_MAX);
  for (Uint32 key = 1; key <= MAX_KEY_SIZE_IN_WORDS; key += 61) {
    for (Uint32 ai = 0; ai <= MAX_LOG_RECORD_SIZE_WORDS; ai += 97) {
      for (int transid = 0; transid < 2; transid++) {
        const Uint32 len = prepareLen(key, ai, transid != 0);
        OK(len % 2 == 0 && len <= PREPARE_MAX);
        OK(len >= PREPARE_HEAD + key + ai);
      }
    }
  }

  OK(fdLen(2, 1024) == 6148);
  OK(maxFdFiles(1024) == 2 && maxFdFiles(16) == 40 && maxFdFiles(4) == 40);
  for (Uint32 size = 4; size <= 1024; size++) {
    const Uint32 n = maxFdFiles(size);
    const Uint32 cmax = (PAGE_WORDS - HEADER_WORDS - 128) / (3 * size);
    OK(n >= 1 && n == (cmax < 40 ? cmax : 40));
    const Uint32 len = fdLen(n, size);
    OK(len % 2 == 0 && len <= 8036);
    /* The unit of the FILLER header after the FD ends below the control area */
    OK(HEADER_WORDS + len + W_WORDS <= CONTROL_AREA_WORD);
  }

  OK(RESERVE == 46 && RESERVE_AT_COMMIT == 26);
  OK(CONTROL_AREA_WORD == 8128 && W_WORDS == 16 && PAGE_DATA_WORDS == 8160);

  /* The LSN grows along the log, across files and laps */
  OK(lsn(1, 3, 4, 0, 0, 32) < lsn(1, 3, 4, 0, 0, 34));
  OK(lsn(1, 3, 4, 0, 0, 8190) < lsn(1, 3, 4, 0, 1, 32));
  OK(lsn(1, 3, 4, 0, 127, 8190) < lsn(1, 3, 4, 1, 0, 32));
  OK(lsn(1, 3, 4, 2, 127, 8190) < lsn(2, 3, 4, 0, 0, 32));
  OK(lsn(2, 3, 4, 0, 0, 0) == 3 * (Uint64(4) << 20) * 2);
}

}  // namespace

TAPTEST(pmem_redo_format) {
  checksumVectors();
  recordTypes();
  framing();
  pageHeader();
  sizes();
  printf("pmem_redo_format: XXH3 %s\n", ndb_xxh3_implementation());
  return 1;
}
