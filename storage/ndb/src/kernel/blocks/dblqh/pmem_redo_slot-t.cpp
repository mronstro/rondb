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
 * RONDB-1150, step 1 plan S6.3, test U5: the control area of a log part
 * (PmemRedoFormat.hpp, PmemRedoScan.cpp). The config line against the
 * configuration, with a message that names what differs; the two
 * last-file slots, the higher seq winning; and a slot torn at 8 bytes,
 * every one of the 256 mixes of its old and new chunks, which must leave
 * either the new slot or the other one, never a mix.
 */

#include <ndb_global.h>
#include <util/NdbTap.hpp>

#include <cstring>

#include "PmemRedoScan.hpp"

using namespace PmemRedo;

namespace {

constexpr Uint32 NO_PARTS = 4;
constexpr Uint32 PART = 3;
constexpr Uint32 NO_FILES = 16;
constexpr Uint32 FILE_SIZE_MB = 64;
constexpr Uint32 NODE_ID = 2;

const Geom g = {NO_FILES, FILE_SIZE_MB, PART};

bool sameSlot(const Slot &s, Uint64 seq, Uint32 fileNo, Uint32 lap,
              Uint64 dsc, Uint32 flags) {
  return s.seq == seq && s.fileNo == fileNo && s.lap == lap &&
         s.dirtyShutdownCount == dsc && s.flags == flags;
}

/* The layout of the control area in page 0 of file 0 */
void layout() {
  OK(CTRL_CONFIG_WORD == 8128);
  OK(SLOT0_WORD == 8160);
  OK(SLOT1_WORD == 8176);
  OK(SLOT1_WORD + W_WORDS == PAGE_WORDS);
  OK(slotWord(1) == SLOT1_WORD && slotWord(2) == SLOT0_WORD);

  /* The largest FD of every file size, its FILLER's header unit before it */
  for (Uint32 mb = 1; mb <= 1024; mb++) {
    const Uint32 fdEnd = HEADER_WORDS + fdLen(maxFdFiles(mb), mb);
    const Uint32 unitEnd = fdEnd + FILLER_MIN + padWords(fdEnd + FILLER_MIN);
    if (unitEnd > CONTROL_AREA_WORD) {
      fprintf(stderr, "FragmentLogFileSize %uM: the FILLER's unit ends at %u\n",
              mb, unitEnd);
      OK(false);
    }
  }
}

/* The config line, and every way it can fail */
void config() {
  char msg[200];
  Uint32 line[W_WORDS];
  buildCtrlConfig(line, NO_PARTS, PART, NO_FILES, FILE_SIZE_MB, NODE_ID);
  OK(checkCtrlConfig(line, g, NO_PARTS, NODE_ID, msg, sizeof(msg)) ==
     CTRL_VALID);

  /* Never written: zeros, or a file-mode page */
  Uint32 zero[W_WORDS] = {0};
  OK(checkCtrlConfig(zero, g, NO_PARTS, NODE_ID, msg, sizeof(msg)) ==
     CTRL_NOT_PMEM);

  /* Any word changed, the checksum included, after the magic */
  for (Uint32 w = 1; w < W_WORDS; w++) {
    Uint32 bad[W_WORDS];
    memcpy(bad, line, sizeof(bad));
    bad[w] ^= 0x100;
    OK(checkCtrlConfig(bad, g, NO_PARTS, NODE_ID, msg, sizeof(msg)) ==
       CTRL_CORRUPT);
  }

  /* Another version, with its checksum */
  {
    Uint32 other[W_WORDS];
    memcpy(other, line, sizeof(other));
    other[CTRL_W_VERSION] = CTRL_VERSION + 1;
    other[LINE_CHECKSUM] = lineChecksum(other);
    OK(checkCtrlConfig(other, g, NO_PARTS, NODE_ID, msg, sizeof(msg)) ==
       CTRL_OTHER_VERSION);
  }

  /* Made for another configuration: the message names the field */
  const struct {
    Uint32 noParts, part, noFiles, sizeMb, nodeId;
    const char *name;
  } cases[] = {
      {2, PART, NO_FILES, FILE_SIZE_MB, NODE_ID, "NoOfFragmentLogParts"},
      {NO_PARTS, 1, NO_FILES, FILE_SIZE_MB, NODE_ID, "log part"},
      {NO_PARTS, PART, 4, FILE_SIZE_MB, NODE_ID, "NoOfFragmentLogFiles"},
      {NO_PARTS, PART, NO_FILES, 16, NODE_ID, "FragmentLogFileSize"},
      {NO_PARTS, PART, NO_FILES, FILE_SIZE_MB, 1, "node id"}};
  for (const auto &c : cases) {
    Uint32 other[W_WORDS];
    buildCtrlConfig(other, c.noParts, c.part, c.noFiles, c.sizeMb, c.nodeId);
    OK(checkCtrlConfig(other, g, NO_PARTS, NODE_ID, msg, sizeof(msg)) ==
       CTRL_MISMATCH);
    OK(strstr(msg, c.name) != nullptr);
    printf("%s\n", msg);
  }

  /* Another write unit */
  {
    Uint32 other[W_WORDS];
    memcpy(other, line, sizeof(other));
    other[CTRL_W_WRITE_UNIT] = 2 * W_BYTES;
    other[LINE_CHECKSUM] = lineChecksum(other);
    OK(checkCtrlConfig(other, g, NO_PARTS, NODE_ID, msg, sizeof(msg)) ==
       CTRL_MISMATCH);
    OK(strstr(msg, "write unit") != nullptr);
  }
}

/* Each slot alone, the pair, and the slots that are not valid */
void slots() {
  Uint32 s0[W_WORDS] = {0};
  Uint32 s1[W_WORDS] = {0};
  Slot s;
  OK(pickSlot(s0, s1, g, &s) == -1);

  /* The initial start writes seq 1, in slot 1 */
  buildSlot(s1, 1, 0, 1, PART, 0, 0);
  OK(pickSlot(s0, s1, g, &s) == 1);
  OK(sameSlot(s, 1, 0, 1, 0, 0));

  /* The flags and the 64-bit values come back */
  const Uint64 bigSeq = (Uint64(5) << 32) | 6;
  const Uint64 dsc = (Uint64(7) << 32) | 9;
  buildSlot(s0, bigSeq, 15, 0x10000, PART, dsc,
            SLOT_F_DSC_VALID | SLOT_F_UNSAFE_SHUTDOWN);
  OK(pickSlot(s0, s1, g, &s) == 0);
  OK(sameSlot(s, bigSeq, 15, 0x10000, dsc,
              SLOT_F_DSC_VALID | SLOT_F_UNSAFE_SHUTDOWN));

  /* The higher seq wins, in either slot */
  buildSlot(s0, 4, 2, 1, PART, 0, 0);
  buildSlot(s1, 5, 3, 1, PART, 0, 0);
  OK(pickSlot(s0, s1, g, &s) == 1 && s.seq == 5 && s.fileNo == 3);
  buildSlot(s0, 6, 4, 1, PART, 0, 0);
  OK(pickSlot(s0, s1, g, &s) == 0 && s.seq == 6 && s.fileNo == 4);

  /* Not valid: the line of the other slot, another part, no such file, lap 0 */
  Uint32 line[W_WORDS];
  buildSlot(line, 6, 4, 1, PART, 0, 0);
  OK(slotValid(line, 0, g, &s));
  OK(!slotValid(line, 1, g, &s));
  buildSlot(line, 6, 4, 1, PART + 1, 0, 0);
  OK(!slotValid(line, 0, g, &s));
  buildSlot(line, 6, NO_FILES, 1, PART, 0, 0);
  OK(!slotValid(line, 0, g, &s));
  buildSlot(line, 6, 4, 0, PART, 0, 0);
  OK(!slotValid(line, 0, g, &s));
  buildSlot(line, 0, 4, 1, PART, 0, 0);
  OK(!slotValid(line, 0, g, &s));

  /* Any word changed */
  buildSlot(line, 6, 4, 1, PART, 0, 0);
  for (Uint32 w = 0; w < W_WORDS; w++) {
    Uint32 bad[W_WORDS];
    memcpy(bad, line, sizeof(bad));
    bad[w] ^= 1;
    OK(!slotValid(bad, 0, g, &s));
  }
}

/**
 * File switches that write seq 1, 2, 3, ...: each write is torn at 8
 * bytes in all 256 ways. The pick is then the new slot, with exactly its
 * values, or the other slot, which holds the previous switch; never a
 * mix. Before seq 2 the other slot is empty, and a torn first slot leaves
 * none.
 */
void tornSlots() {
  Uint32 area[2][W_WORDS];
  memset(area, 0, sizeof(area));
  Uint32 mixes = 0;
  for (Uint64 seq = 1; seq <= 40; seq++) {
    const Uint32 fileNo = Uint32((seq - 1) % NO_FILES);
    const Uint32 lap = Uint32(1 + (seq - 1) / NO_FILES);
    const Uint32 index = slotIndex(seq);
    Uint32 newLine[W_WORDS];
    buildSlot(newLine, seq, fileNo, lap, PART, seq / 3, SLOT_F_DSC_VALID);
    const Uint32 *oldLine = area[index];

    for (Uint32 mask = 0; mask < 256; mask++) {
      Uint32 torn[2][W_WORDS];
      memcpy(torn, area, sizeof(torn));
      for (Uint32 chunk = 0; chunk < 8; chunk++) {
        const Uint32 *from = (mask & (1u << chunk)) ? newLine : oldLine;
        torn[index][2 * chunk] = from[2 * chunk];
        torn[index][2 * chunk + 1] = from[2 * chunk + 1];
      }
      const bool isNew = memcmp(torn[index], newLine, sizeof(newLine)) == 0;
      const bool isOld = memcmp(torn[index], oldLine, sizeof(newLine)) == 0;
      if (!isNew && !isOld) mixes++;

      Slot s;
      const int pick = pickSlot(torn[0], torn[1], g, &s);
      if (isNew) {
        OK(pick == int(index));
        OK(sameSlot(s, seq, fileNo, lap, seq / 3, SLOT_F_DSC_VALID));
      } else if (seq == 1) {
        OK(pick == -1);
      } else {
        /* The previous switch, from the other slot */
        OK(pick == int(1 - index));
        OK(s.seq == seq - 1);
      }
    }
    memcpy(area[index], newLine, sizeof(newLine));
  }
  OK(mixes > 0);
}

}  // namespace

TAPTEST(pmem_redo_slot) {
  layout();
  config();
  slots();
  tornSlots();
  return 1;
}
