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
 * RONDB-1150, step 1 plan S6.2: the restart scan of the REDO log with
 * RedoLogMode=pmem (PmemRedoScan.hpp) on synthetic logs, tests U2-U4 of
 * impl_step1_recovery_test.md §4.1.
 *
 * TestLog writes a log part as the PMEM writer will (format §7): records
 * built with PmemRedoFormat.hpp, a page header stored when the writer
 * moves onto the page, a FILLER or a NEXT_MBYTE closing the write unit at
 * every barrier, the NEXT_MBYTE fenced before the next mbyte is touched
 * (W2), and a file switch that fences page 0 of the next file before the
 * last-file slot names it. It keeps the old content of every 64-byte line
 * stored since the last fence, so that a crash can leave each line old,
 * new, or torn at 8 bytes (crash model A2). Its restart over the format
 * (recovery §3.4, §4.2) zeroes what lies after the end, resumes at E or
 * at an earlier record end H, closes the unit and writes the slot.
 *
 * Without arguments, as ctest runs it: the position arithmetic, crafted
 * records, the cases of recovery §3.3, 300 random logs, and a check that
 * the random logs fail when the restart does not zero. With --random:
 * random logs only, --loops=N (10000) from --seed=S (the time); a failure
 * prints the seed that replays it with --loops=1.
 */

#include <ndb_global.h>
#include <util/NdbTap.hpp>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <vector>

#include "PmemRedoScan.hpp"

using namespace PmemRedo;

namespace {

bool g_verbose = true;
Uint64 g_seed = 0;  // the random log being run, for the failure message

#define CHECK(cond)                                                       \
  do {                                                                    \
    if (!(cond)) {                                                        \
      if (g_verbose)                                                      \
        fprintf(stderr, "%s:%d: CHECK(%s) failed, seed %llu\n", __FILE__, \
                __LINE__, #cond, (unsigned long long)g_seed);             \
      return false;                                                       \
    }                                                                     \
  } while (0)

struct Rng {
  Uint64 s;
  explicit Rng(Uint64 seed) : s(seed) {}
  Uint64 next() {  // splitmix64
    Uint64 z = (s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
  Uint32 below(Uint32 n) { return Uint32(next() % n); }
  bool chance(Uint32 percent) { return below(100) < percent; }
};

bool samePos(const Pos &a, const Pos &b) {
  return a.fileNo == b.fileNo && a.pageNo == b.pageNo &&
         a.pageIndex == b.pageIndex && a.lap == b.lap;
}

/* A record as the writer stored it */
struct LogRec {
  Pos pos;
  Uint32 w0;
  Uint32 w1;
  Pos next;
};

enum CrashMode {
  CRASH_CLEAN,  // no line stored since the last fence persists
  CRASH_FULL,   // every line persists
  CRASH_RANDOM  // each line old, new or torn at 8 bytes
};

class TestLog {
 public:
  static constexpr Uint32 NODE_ID = 7;

  TestLog(Uint32 noFiles, Uint32 fileSizeMb, Uint32 logPartNo)
      : m_g{noFiles, fileSizeMb, logPartNo},
        m_files(noFiles),
        m_bases(noFiles),
        m_touched(noFiles),
        m_buf(PREPARE_MAX),
        m_rng(0) {
    for (Uint32 f = 0; f < noFiles; f++) {
      m_files[f].assign(size_t(m_g.pagesInFile()) * PAGE_WORDS, 0);
      m_bases[f] = reinterpret_cast<const Uint8 *>(m_files[f].data());
      m_touched[f].assign(m_g.pagesInFile(), false);
    }
    reset();
  }

  const Geom &geom() const { return m_g; }
  PartView view() const { return PartView{m_g, m_bases.data()}; }
  const std::vector<LogRec> &history() const { return m_history; }
  Uint32 slotFile() const { return m_slotFile; }
  Uint32 slotLap() const { return m_slotLap; }
  const Pos &persisted() const { return m_persisted; }
  const Pos &cur() const { return m_cur; }
  bool dead() const { return m_dead; }

  /* Raw access, as a crash or a bug would leave the memory */
  Uint32 *rawPage(Uint32 fileNo, Uint32 pageNo) {
    m_touched[fileNo][pageNo] = true;
    return m_files[fileNo].data() + size_t(pageNo) * PAGE_WORDS;
  }
  Uint32 *at(const Pos &p) { return rawPage(p.fileNo, p.pageNo) + p.pageIndex; }

  /* Zeroed files, a new writer */
  void reset() {
    for (Uint32 f = 0; f < m_g.noFiles; f++) {
      for (Uint32 p = 0; p < m_g.pagesInFile(); p++) {
        if (!m_touched[f][p]) continue;
        memset(m_files[f].data() + size_t(p) * PAGE_WORDS, 0, PAGE_BYTES);
        m_touched[f][p] = false;
      }
    }
    m_journal.clear();
    m_history.clear();
    m_dead = false;
    m_eventsLeft = 0;
    m_slotFile = 0;
    m_slotLap = 0;
    m_cur = Pos{0, 0, HEADER_WORDS, 0};
    m_hdrStored = false;
    m_persisted = m_cur;
    m_zeroing = true;
    setStream(0);
  }

  /* The content of the records that follow, so that two laps can be alike */
  void setStream(Uint64 seed) {
    m_rng = Rng(seed);
    m_gci = 1;
    m_lastPrepRef = 0;
  }
  void forgetHistory() { m_history.clear(); }
  void setZeroing(bool on) { m_zeroing = on; }

  /* The process stops after n more events: a record, a fence, a slot write */
  void stopAfter(Uint32 n) { m_eventsLeft = n; }

  /* ------------------------------------------------------------------ */
  /* The writer                                                          */
  /* ------------------------------------------------------------------ */

  /* Words from the current position to the end of its mbyte */
  Uint32 room() const {
    const Uint32 lastPage =
        (m_cur.pageNo / PAGES_IN_MBYTE + 1) * PAGES_IN_MBYTE - 1;
    return (PAGE_WORDS - m_cur.pageIndex) +
           (lastPage - m_cur.pageNo) * PAGE_DATA_WORDS;
  }

  /* A record at the current position, after a NEXT_MBYTE if it does not fit */
  Pos append(Uint32 type, Uint32 flags, const Uint32 *body, Uint32 len) {
    if (m_dead) return m_cur;
    if (len + NEXT_MBYTE_LEN > room()) nextMbyte();
    if (m_dead) return m_cur;
    return put(makeW0(type, flags, len), body);
  }

  /* The NEXT_MBYTE, fenced (W2), then the next mbyte or file */
  void nextMbyte() {
    put(makeW0(TYPE_NEXT_MBYTE, 0, NEXT_MBYTE_LEN), nullptr);
    persist();
    if (!m_dead && m_cur.pageNo == 0) startFile(m_cur.fileNo, m_cur.lap);
  }

  /**
   * Page 0 of a file, the FD and a FILLER to the page end, fenced; then
   * the last-file slot names the file. The writer goes on in page 1. The
   * FD has its own buffer: a file switch comes inside append(), while
   * m_buf holds the body of the record that did not fit.
   */
  void startFile(Uint32 fileNo, Uint32 lap) {
    if (m_dead) return;
    m_cur = Pos{fileNo, 0, HEADER_WORDS, lap};
    m_hdrStored = false;
    const Uint32 noFd = std::min(m_g.noFiles, maxFdFiles(m_g.fileSizeMb));
    const Uint32 len = fdLen(noFd, m_g.fileSizeMb);
    std::vector<Uint32> fd(len - 2);
    fd[FD_NO_FD - 2] = noFd;
    fd[FD_FILE_NO - 2] = fileNo;
    for (Uint32 i = FD_ARRAYS - 2; i < len - 2; i++)
      fd[i] = Uint32(m_rng.next());
    put(makeW0(TYPE_FD, 0, len), fd.data());
    put(makeW0(TYPE_FILLER, 0, PAGE_WORDS - m_cur.pageIndex), nullptr);
    persist();
    writeSlot(fileNo, lap);
  }

  /* The writer at the first record position of (fileNo, mbyte) */
  void beginAt(Uint32 fileNo, Uint32 mbyte, Uint32 lap) {
    startFile(fileNo, lap);
    while (!m_dead && m_cur.fileNo == fileNo &&
           m_cur.pageNo / PAGES_IN_MBYTE < mbyte)
      nextMbyte();
  }

  /* Close the write unit (format §7.1) and fence */
  void barrier() {
    closeUnit();
    persist();
  }

  void closeUnit() {
    if (m_dead) return;
    const Uint32 gap = padWords(m_cur.pageIndex);
    if (gap == 0) return;
    if (m_cur.pageIndex + gap == PAGE_WORDS &&
        m_cur.pageNo % PAGES_IN_MBYTE == PAGES_IN_MBYTE - 1) {
      nextMbyte();
      return;
    }
    put(makeW0(TYPE_FILLER, 0, gap), nullptr);
  }

  /* A fence: what was stored is persistent */
  void persist() {
    if (m_dead) return;
    m_journal.clear();
    m_persisted = m_cur;
    event();
  }

  void writeSlot(Uint32 fileNo, Uint32 lap) {
    if (m_dead) return;
    m_slotFile = fileNo;
    m_slotLap = lap;
    event();
  }

  /* A PREPARE of len words, len even and at least 10 */
  Pos prepareOfLen(Uint32 len) {
    const Uint32 keyLen = 2;
    const Uint32 aiLen = len - PREPARE_HEAD - keyLen;
    const Uint32 seed = Uint32(m_rng.next());
    for (Uint32 i = 0; i < len - 2; i++) m_buf[i] = seed + i * 0x9E3779B1u;
    m_buf[PREP_AI_LEN - 2] = aiLen;
    m_buf[PREP_KEY_LEN - 2] = keyLen;
    m_lastPrepRef++;
    return append(TYPE_PREPARE, 0, m_buf.data(), len);
  }

  /* A PREPARE that ends at word index of the current page, or at its end */
  Pos fillPageTo(Uint32 index) { return prepareOfLen(index - m_cur.pageIndex); }

  /* Big PREPAREs until about roomLeft words are left in the mbyte */
  void fillTo(Uint32 roomLeft) {
    const Pos start = m_cur;
    const Uint32 mbyte = start.pageNo / PAGES_IN_MBYTE;
    while (!m_dead && m_cur.fileNo == start.fileNo &&
           m_cur.pageNo / PAGES_IN_MBYTE == mbyte) {
      const Uint32 left = room();
      if (left < roomLeft + 64) return;
      const Uint32 len = std::min(PREPARE_MAX, left - roomLeft) & ~1u;
      if (len < 16) return;
      prepareOfLen(len);
    }
  }

  /* A record of a random run-time type, then sometimes a barrier */
  Uint32 randomRecord(Uint32 bigPercent) {
    const Uint32 pick = m_rng.below(100);
    Uint32 type;
    Uint32 flags = 0;
    Uint32 len;
    if (pick < 40) {
      type = TYPE_PREPARE;
      const bool transid = m_rng.chance(20);
      const Uint32 keyLen =
          1 + (m_rng.chance(5) ? m_rng.below(MAX_KEY_SIZE_IN_WORDS)
                               : m_rng.below(16));
      const Uint32 aiLen = m_rng.chance(bigPercent)
                               ? m_rng.below(MAX_LOG_RECORD_SIZE_WORDS + 1)
                               : m_rng.below(200);
      len = prepareLen(keyLen, aiLen, transid);
      if (transid) flags = PF_TRANSID;
      for (Uint32 i = 0; i < len - 2; i++) m_buf[i] = Uint32(m_rng.next());
      m_buf[PREP_AI_LEN - 2] = aiLen;
      m_buf[PREP_KEY_LEN - 2] = keyLen;
      m_lastPrepRef++;
    } else {
      if (pick < 65) {
        type = TYPE_COMMIT;
        len = COMMIT_LEN;
        if (m_rng.chance(50)) flags = CF_DURABLE;
      } else if (pick < 75) {
        type = TYPE_ABORT;
        len = ABORT_LEN;
        if (m_rng.chance(30)) flags = AF_AFTER_COMMIT;
      } else if (pick < 85) {
        type = TYPE_COMPLETE;
        len = COMPLETE_LEN;
      } else if (pick < 95) {
        type = TYPE_COMPLETED_GCI;
        len = COMPLETED_GCI_LEN;
      } else {
        type = TYPE_SR_HEAD;
        len = SR_HEAD_LEN;
      }
      for (Uint32 i = 0; i < len - 2; i++) m_buf[i] = Uint32(m_rng.next());
      if (type == TYPE_COMPLETED_GCI) {
        m_buf[COMPLETED_GCI_GCI - 2] = m_gci++;
        m_buf[1] = 0;
      }
    }
    append(type, flags, m_buf.data(), len);
    if (m_rng.chance(15)) barrier();
    return len;
  }

  /* Random records for about words words, or until the process stops */
  void randomWindow(Uint32 words, Uint32 bigPercent) {
    Uint32 done = 0;
    while (!m_dead && done < words) done += randomRecord(bigPercent);
  }

  /* ------------------------------------------------------------------ */
  /* Crash and restart                                                   */
  /* ------------------------------------------------------------------ */

  /* The node stops: every line stored since the last fence persists or not */
  void crash(CrashMode mode, Rng &rng) {
    for (auto &e : m_journal) {
      const Uint32 fileNo = Uint32(e.first >> 40);
      Uint32 *line = m_files[fileNo].data() +
                     size_t(e.first & ((Uint64(1) << 40) - 1)) * W_WORDS;
      const Uint32 fate = mode == CRASH_CLEAN  ? 0
                          : mode == CRASH_FULL ? 1
                                               : rng.below(3);
      if (fate == 0) {
        memcpy(line, e.second.w, W_BYTES);
      } else if (fate == 2) {
        for (Uint32 c = 0; c < W_WORDS; c += 2) {
          if (rng.chance(50)) {
            line[c] = e.second.w[c];
            line[c + 1] = e.second.w[c + 1];
          }
        }
      }
    }
    m_journal.clear();
    m_dead = true;
  }

  /**
   * The restart of step 1 over the format, the log ending at e, writing
   * resuming at head:
   *   1. zero [e, end of mbyte(e)) (phase 1) and, with the head moved
   *      back, [ceilW(head), e) (phase 4); page 0 of every file kept;
   *   2. the slot names the head's file, after the file switch is redone
   *      if the head is in page 0;
   *   3. zero page 0 of the later files that the log no longer reaches,
   *      so that no scan takes their FD for one of this log;
   *   4. close the unit at the head.
   * Each step is fenced, so a crash between two steps leaves a log that
   * the next restart reads the same way.
   */
  bool restart(const Pos &e, Pos head) {
    m_dead = false;
    m_eventsLeft = 0;
    m_journal.clear();
    if (m_zeroing) {
      zeroRange(e, mbyteEnd(e));
      if (!samePos(head, e)) zeroRange(ceilUnit(m_g, head), e);
    }
    if (head.pageNo == 0) head.pageIndex = HEADER_WORDS;
    m_cur = head;
    persist();

    const Uint64 headLsn = posLsn(m_g, head);
    while (!m_history.empty() && posLsn(m_g, m_history.back().pos) >= headLsn)
      m_history.pop_back();

    if (head.pageNo == 0)
      startFile(head.fileNo, head.lap);
    else if (m_slotFile != head.fileNo || m_slotLap != head.lap)
      writeSlot(head.fileNo, head.lap);

    if (m_zeroing) {
      Uint32 fileNo = head.fileNo;
      Uint32 lap = head.lap;
      for (Uint32 n = 0; fileNo != e.fileNo || lap != e.lap; n++) {
        CHECK(n < m_g.noFiles);
        fileNo++;
        if (fileNo == m_g.noFiles) {
          fileNo = 0;
          lap++;
        }
        zeroWords(fileNo, 0, 0, PAGE_WORDS);
      }
      persist();
    }

    if (head.pageNo != 0) {
      m_cur = head;
      m_hdrStored =
          checkPage(view(), head.fileNo, head.pageNo, head.lap) == R_VALID;
      CHECK(m_hdrStored || head.pageIndex == HEADER_WORDS);
      closeUnit();
      persist();
    }
    return true;
  }

 private:
  struct Line {
    Uint32 w[W_WORDS];
  };

  void event() {
    if (m_eventsLeft > 0 && --m_eventsLeft == 0) m_dead = true;
  }

  /* A store into the mapping; the old content of a line is kept to the fence */
  void store(Uint32 fileNo, Uint32 pageNo, Uint32 index, const Uint32 *src,
             Uint32 n) {
    if (m_dead || n == 0) return;
    m_touched[fileNo][pageNo] = true;
    const Uint64 first = (Uint64(pageNo) * PAGE_WORDS + index) / W_WORDS;
    const Uint64 last = (Uint64(pageNo) * PAGE_WORDS + index + n - 1) / W_WORDS;
    for (Uint64 line = first; line <= last; line++) {
      const Uint64 key = (Uint64(fileNo) << 40) | line;
      if (m_journal.count(key) != 0) continue;
      Line old;
      memcpy(old.w, m_files[fileNo].data() + line * W_WORDS, W_BYTES);
      m_journal.emplace(key, old);
    }
    memcpy(m_files[fileNo].data() + size_t(pageNo) * PAGE_WORDS + index, src,
           4 * n);
  }

  void zeroWords(Uint32 fileNo, Uint32 pageNo, Uint32 index, Uint32 n) {
    static const Uint32 zero[PAGE_WORDS] = {0};
    store(fileNo, pageNo, index, zero, n);
  }

  /* The first page of the mbyte after the one holding p, word 0 */
  Pos mbyteEnd(const Pos &p) const {
    const Pos n = nextMbyteStart(m_g, p);
    return Pos{n.fileNo, n.pageNo, 0, n.lap};
  }

  /* Zero [from, to) along the log, page 0 of every file kept */
  void zeroRange(const Pos &from, const Pos &to) {
    const Uint64 end = posLsn(m_g, to);
    Pos p = from;
    while (posLsn(m_g, p) < end) {
      const bool last = p.fileNo == to.fileNo && p.pageNo == to.pageNo &&
                        p.lap == to.lap;
      const Uint32 stop = last ? to.pageIndex : PAGE_WORDS;
      if (p.pageNo != 0)
        zeroWords(p.fileNo, p.pageNo, p.pageIndex, stop - p.pageIndex);
      if (last) return;
      if (p.pageNo + 1 < m_g.pagesInFile()) {
        p = Pos{p.fileNo, p.pageNo + 1, 0, p.lap};
      } else {
        const Uint32 fileNo = p.fileNo + 1 < m_g.noFiles ? p.fileNo + 1 : 0;
        p = Pos{fileNo, 0, 0, fileNo == 0 ? p.lap + 1 : p.lap};
      }
    }
  }

  /* The header of the current page, stored before its first record word */
  void ensureHeader() {
    if (m_hdrStored) return;
    Uint32 dram[HEADER_WORDS];
    for (Uint32 i = 0; i < HEADER_WORDS; i++) dram[i] = 0xDEAD0000 + i;
    dram[HDR_LAP] = m_cur.lap;
    dram[HDR_MAX_GCI_COMPLETED] = m_gci - 1;
    dram[HDR_MAX_GCI_STARTED] = m_gci;
    dram[HDR_VERSION] = 0x00090A00;
    dram[HDR_NO_LOG_FILES] = m_g.noFiles;
    dram[HDR_LAST_PREP_REF] = m_lastPrepRef;
    dram[HDR_NO_LOG_PARTS] = 4;
    Uint32 img[HEADER_WORDS];
    buildPageHeader(img, dram, m_cur.fileNo, m_cur.pageNo, m_g.logPartNo,
                    NODE_ID);
    store(m_cur.fileNo, m_cur.pageNo, 0, img, HEADER_WORDS);
    m_hdrStored = true;
  }

  /* A record at the current position; the caller checked the room */
  Pos put(Uint32 w0, const Uint32 *body) {
    if (m_dead) return m_cur;
    ensureHeader();
    const Pos start = m_cur;
    const Uint32 type = w0Type(w0);
    const Uint32 len = w0Len(w0);
    store(start.fileNo, start.pageNo, start.pageIndex, &w0, 1);
    RecChecksum c;
    Pos p = start;
    if (type == TYPE_FILLER) {
      p.pageIndex += len;  // the body is dead, never stored
    } else {
      p.pageIndex += 2;
      for (Uint32 done = 2; done < len;) {
        if (p.pageIndex == PAGE_WORDS) {
          p.pageNo++;
          p.pageIndex = HEADER_WORDS;
          m_cur = p;
          m_hdrStored = false;
          ensureHeader();
        }
        const Uint32 n = std::min(len - done, PAGE_WORDS - p.pageIndex);
        store(p.fileNo, p.pageNo, p.pageIndex, body + done - 2, n);
        c.piece(body + done - 2, n);
        p.pageIndex += n;
        done += n;
      }
    }
    const Uint32 w1 = c.finish(w0, suffix(start.lap, m_g.logPartNo,
                                          start.fileNo, start.pageNo,
                                          start.pageIndex));
    store(start.fileNo, start.pageNo, start.pageIndex + 1, &w1, 1);

    Pos next;
    if (type == TYPE_NEXT_MBYTE)
      next = nextMbyteStart(m_g, start);
    else if (p.pageIndex == PAGE_WORDS)
      next = Pos{p.fileNo, p.pageNo + 1, HEADER_WORDS, p.lap};
    else
      next = p;
    m_hdrStored = next.fileNo == p.fileNo && next.pageNo == p.pageNo;
    m_cur = next;
    if (!m_dead) m_history.push_back(LogRec{start, w0, w1, next});
    event();
    return start;
  }

  const Geom m_g;
  std::vector<std::vector<Uint32>> m_files;
  std::vector<const Uint8 *> m_bases;
  std::vector<std::vector<bool>> m_touched;
  std::vector<Uint32> m_buf;
  std::map<Uint64, Line> m_journal;  // (fileNo << 40 | line) -> old content
  std::vector<LogRec> m_history;
  Rng m_rng;
  Pos m_cur;
  bool m_hdrStored;
  Pos m_persisted;
  Uint32 m_slotFile;
  Uint32 m_slotLap;
  Uint32 m_gci;
  Uint32 m_lastPrepRef;
  Uint32 m_eventsLeft;
  bool m_dead;
  bool m_zeroing;
};

/* ------------------------------------------------------------------ */
/* Checks of a scan against what the writer stored                    */
/* ------------------------------------------------------------------ */

/**
 * Record by record from start: every valid record is the one the writer
 * stored there, and the walk ends where scan ended, for the same reason.
 */
bool walkMatches(TestLog &log, const Pos &start, const ScanResult &scan) {
  const PartView v = log.view();
  const Geom &g = log.geom();
  const std::vector<LogRec> &hist = log.history();
  const Uint64 startLsn = posLsn(g, start);
  size_t i = 0;
  while (i < hist.size() && posLsn(g, hist[i].pos) < startLsn) i++;

  Pos p = start;
  Uint32 records = 0;
  for (;;) {
    RecInfo info;
    const Uint32 r = checkRecord(v, p, &info);
    if (r != R_VALID) {
      CHECK(r == scan.reason);
      break;
    }
    CHECK(i < hist.size());
    const LogRec &w = hist[i];
    CHECK(samePos(w.pos, p));
    CHECK(w.w0 == info.w0);
    CHECK(w.w1 == log.at(p)[1]);
    CHECK(samePos(w.next, info.next));
    i++;
    records++;
    p = info.next;
  }
  CHECK(samePos(p, scan.end));
  CHECK(records == scan.records);
  return true;
}

/**
 * Phase 1 (recovery §3.4): the slot names the last file, its mbyte
 * headers give the last mbyte, the scan from there gives E. What it finds
 * is what the writer stored, and E is at or after the last fence.
 */
bool findLogEnd(TestLog &log, ScanResult *scan) {
  const PartView v = log.view();
  const Geom &g = log.geom();
  const LastMbyte last = findLastMbyte(v, log.slotFile(), log.slotLap());
  CHECK(last.reason == R_VALID);
  CHECK(!last.validAfterDrop);
  *scan = findEnd(v, log.slotFile(), last.mbyte, log.slotLap());
  CHECK(walkMatches(log, mbyteStart(log.slotFile(), last.mbyte, log.slotLap()),
                    *scan));
  const Pos &e = scan->end;
  const Pos &f = log.persisted();
  if (g_verbose && posLsn(g, e) < posLsn(g, f))
    fprintf(stderr,
            "E (file %u page %u word %u lap %u, %s) is before the last fence "
            "(file %u page %u word %u lap %u)\n",
            e.fileNo, e.pageNo, e.pageIndex, e.lap, reasonName(scan->reason),
            f.fileNo, f.pageNo, f.pageIndex, f.lap);
  CHECK(posLsn(g, e) >= posLsn(g, f));
  return true;
}

/* The scan from an earlier mbyte reaches the same E through the same records */
bool walkFrom(TestLog &log, const Pos &start, const ScanResult &scan) {
  const ScanResult from = findEnd(log.view(), start.fileNo,
                                  start.pageNo / PAGES_IN_MBYTE, start.lap);
  CHECK(samePos(from.end, scan.end));
  CHECK(from.reason == scan.reason);
  CHECK(walkMatches(log, start, from));
  return true;
}

/* ------------------------------------------------------------------ */
/* Positions                                                           */
/* ------------------------------------------------------------------ */

bool arithmetic(TestLog &log) {
  const Geom &g = log.geom();  // 3 files of 4 mbytes
  CHECK(g.pagesInFile() == 128);

  CHECK(samePos(mbyteStart(1, 0, 2), Pos{1, 0, 32, 2}));
  CHECK(samePos(mbyteStart(1, 3, 2), Pos{1, 96, 32, 2}));
  CHECK(samePos(nextMbyteStart(g, Pos{0, 5, 100, 1}), Pos{0, 32, 32, 1}));
  CHECK(samePos(nextMbyteStart(g, Pos{0, 100, 8190, 1}), Pos{1, 0, 32, 1}));
  CHECK(samePos(nextMbyteStart(g, Pos{2, 127, 40, 1}), Pos{0, 0, 32, 2}));

  CHECK(samePos(ceilUnit(g, Pos{0, 5, 40, 1}), Pos{0, 5, 48, 1}));
  CHECK(samePos(ceilUnit(g, Pos{0, 5, 48, 1}), Pos{0, 5, 48, 1}));
  CHECK(samePos(ceilUnit(g, Pos{0, 5, 8178, 1}), Pos{0, 6, 0, 1}));
  CHECK(samePos(ceilUnit(g, Pos{1, 127, 8190, 1}), Pos{2, 0, 0, 1}));
  CHECK(samePos(ceilUnit(g, Pos{2, 127, 8180, 1}), Pos{0, 0, 0, 2}));

  const Pos end = {1, 50, 100, 3};
  CHECK(expectedLap(end, 0) == 3 && expectedLap(end, 1) == 3 &&
        expectedLap(end, 2) == 2);
  CHECK(lapAt(end, 0, 120, 32) == 3 && lapAt(end, 2, 0, 32) == 2);
  CHECK(lapAt(end, 1, 49, 8000) == 3 && lapAt(end, 1, 50, 100) == 3);
  CHECK(lapAt(end, 1, 50, 102) == 2 && lapAt(end, 1, 51, 32) == 2);

  CHECK(posLsn(g, Pos{2, 127, 8190, 1}) < posLsn(g, Pos{0, 0, 0, 2}));
  CHECK(posLsn(g, Pos{0, 0, 32, 1}) < posLsn(g, Pos{0, 1, 32, 1}));
  return true;
}

/* ------------------------------------------------------------------ */
/* V1-V5 on crafted records                                            */
/* ------------------------------------------------------------------ */

/* A record whose checksum is made for s, stored raw, inside one page */
void craft(TestLog &log, const Pos &p, Uint32 w0, const Uint32 *body,
           const Suffix &s) {
  Uint32 *rec = log.at(p);
  rec[0] = w0;
  const Uint32 hashed = std::min(hashedLen(w0), PAGE_WORDS - p.pageIndex);
  for (Uint32 i = 2; i < hashed; i++) rec[i] = body[i - 2];
  RecChecksum c;
  c.piece(rec + 2, hashed - 2);
  rec[1] = c.finish(w0, s);
}

void rawHeader(TestLog &log, Uint32 fileNo, Uint32 pageNo, Uint32 claimedPageNo,
               Uint32 lap) {
  Uint32 dram[HEADER_WORDS] = {0};
  dram[HDR_LAP] = lap;
  dram[HDR_NO_LOG_FILES] = log.geom().noFiles;
  buildPageHeader(log.rawPage(fileNo, pageNo), dram, fileNo, claimedPageNo,
                  log.geom().logPartNo, TestLog::NODE_ID);
}

bool framing(TestLog &log) {
  log.reset();
  log.setStream(11);
  log.beginAt(0, 1, 1);
  std::vector<Uint32> body(PREPARE_MAX);
  for (Uint32 i = 0; i < PREPARE_MAX; i++) body[i] = 0x51000000 + i;
  const Pos first = log.append(TYPE_COMMIT, 0, body.data(), COMMIT_LEN);
  CHECK(samePos(first, Pos{0, 32, 32, 1}));

  const PartView v = log.view();
  const Geom &g = log.geom();
  RecInfo info;
  const auto at = [](Uint32 index) { return Pos{0, 32, index, 1}; };
  const auto sfx = [&g](const Pos &p) {
    return suffix(p.lap, g.logPartNo, p.fileNo, p.pageNo, p.pageIndex);
  };

  CHECK(checkRecord(v, first, &info) == R_VALID);
  CHECK(info.w0 == makeW0(TYPE_COMMIT, 0, COMMIT_LEN));
  CHECK(samePos(info.next, at(44)));

  /* V2: type, flags, length */
  const Pos p = at(1000);
  CHECK(checkRecord(v, p, &info) == R_TYPE_ZERO);
  const Uint32 unknown[] = {5, 6, 9, 13, 255};
  for (Uint32 t : unknown) {
    craft(log, p, makeW0(t, 0, 4), body.data(), sfx(p));
    CHECK(checkRecord(v, p, &info) == R_TYPE_UNKNOWN);
  }
  craft(log, p, makeW0(TYPE_COMMIT, 0, 11), body.data(), sfx(p));
  CHECK(checkRecord(v, p, &info) == R_LEN);
  craft(log, p, makeW0(TYPE_COMMIT, 0, 14), body.data(), sfx(p));
  CHECK(checkRecord(v, p, &info) == R_LEN);
  craft(log, p, makeW0(TYPE_FILLER, 0, 0), body.data(), sfx(p));
  CHECK(checkRecord(v, p, &info) == R_LEN);
  craft(log, p, makeW0(TYPE_COMPLETE, CF_DURABLE, 4), body.data(), sfx(p));
  CHECK(checkRecord(v, p, &info) == R_FLAGS);
  craft(log, p, makeW0(TYPE_COMMIT, 1u << 10, 12), body.data(), sfx(p));
  CHECK(checkRecord(v, p, &info) == R_FLAGS);
  craft(log, p, makeW0(TYPE_COMPLETE, 0, 4), body.data(), sfx(p));
  CHECK(checkRecord(v, p, &info) == R_VALID);

  /* V2: the length of a PREPARE is that of its key and attrinfo */
  std::vector<Uint32> prep(body);
  prep[PREP_AI_LEN - 2] = 10;
  prep[PREP_KEY_LEN - 2] = 3;
  craft(log, p, makeW0(TYPE_PREPARE, 0, 22), prep.data(), sfx(p));
  CHECK(checkRecord(v, p, &info) == R_VALID);
  craft(log, p, makeW0(TYPE_PREPARE, 0, 24), prep.data(), sfx(p));
  CHECK(checkRecord(v, p, &info) == R_LEN);
  craft(log, p, makeW0(TYPE_PREPARE, PF_TRANSID, 22), prep.data(), sfx(p));
  CHECK(checkRecord(v, p, &info) == R_LEN);
  craft(log, p, makeW0(TYPE_PREPARE, PF_TRANSID, 24), prep.data(), sfx(p));
  CHECK(checkRecord(v, p, &info) == R_VALID);

  /* V5: an FD only at word 32 of page 0 */
  std::vector<Uint32> fd(body);
  fd[FD_NO_FD - 2] = 3;
  fd[FD_FILE_NO - 2] = 0;
  craft(log, p, makeW0(TYPE_FD, 0, fdLen(3, 4)), fd.data(), sfx(p));
  CHECK(checkRecord(v, p, &info) == R_FD_POS);

  /* V5: a FILLER ends on a W boundary and is shorter than W */
  craft(log, at(1002), makeW0(TYPE_FILLER, 0, 4), body.data(), sfx(at(1002)));
  CHECK(checkRecord(v, at(1002), &info) == R_FILLER_ALIGN);
  craft(log, at(1004), makeW0(TYPE_FILLER, 0, 4), body.data(), sfx(at(1004)));
  CHECK(checkRecord(v, at(1004), &info) == R_VALID);
  CHECK(samePos(info.next, at(1008)));
  craft(log, at(1024), makeW0(TYPE_FILLER, 0, 16), body.data(), sfx(at(1024)));
  CHECK(checkRecord(v, at(1024), &info) == R_FILLER_ALIGN);

  /* V4: the same bytes elsewhere, or a checksum made for another place */
  memcpy(log.at(at(2000)), log.at(first), 4 * COMMIT_LEN);
  CHECK(checkRecord(v, at(2000), &info) == R_CHECKSUM);
  const Pos q = at(3000);
  const Suffix wrong[] = {
      suffix(2, g.logPartNo, 0, 32, 3000), suffix(0, g.logPartNo, 0, 32, 3000),
      suffix(1, g.logPartNo + 1, 0, 32, 3000),
      suffix(1, g.logPartNo, 1, 32, 3000), suffix(1, g.logPartNo, 0, 33, 3000),
      suffix(1, g.logPartNo, 0, 32, 3002)};
  for (const Suffix &s : wrong) {
    craft(log, q, makeW0(TYPE_COMMIT, 0, COMMIT_LEN), body.data(), s);
    CHECK(checkRecord(v, q, &info) == R_CHECKSUM);
  }
  craft(log, q, makeW0(TYPE_COMMIT, 0, COMMIT_LEN), body.data(), sfx(q));
  CHECK(checkRecord(v, q, &info) == R_VALID);

  /* E9: a COMMIT invalidated in place by one store stays valid */
  log.at(first)[0] |= RF_INVALIDATED;
  CHECK(checkRecord(v, first, &info) == R_VALID);
  CHECK(info.w0 & RF_INVALIDATED);
  log.at(first)[0] &= ~RF_INVALIDATED;

  /* Not a record position */
  CHECK(checkRecord(v, at(30), &info) == R_POS);
  CHECK(checkRecord(v, at(33), &info) == R_POS);
  CHECK(checkRecord(v, at(PAGE_WORDS), &info) == R_POS);
  CHECK(checkRecord(v, Pos{3, 32, 32, 1}, &info) == R_POS);
  CHECK(checkRecord(v, Pos{0, 128, 32, 1}, &info) == R_POS);

  /* V1: another lap, a header of another page */
  CHECK(checkRecord(v, Pos{0, 32, 32, 2}, &info) == R_HDR_LAP);
  rawHeader(log, 0, 40, 41, 1);
  CHECK(checkRecord(v, Pos{0, 40, 32, 1}, &info) == R_HDR_IDENTITY);
  CHECK(checkRecord(v, Pos{0, 41, 32, 1}, &info) == R_HDR_FORMAT);

  /* V2: the end of the mbyte; page 63 is the last of mbyte 1 */
  rawHeader(log, 0, 63, 63, 1);
  const Pos tooLate = {0, 63, 8182, 1};
  craft(log, tooLate, makeW0(TYPE_COMMIT, 0, COMMIT_LEN), body.data(),
        sfx(tooLate));
  CHECK(checkRecord(v, tooLate, &info) == R_CROSSES_MBYTE);
  const Pos lastFit = {0, 63, 8178, 1};
  craft(log, lastFit, makeW0(TYPE_COMMIT, 0, COMMIT_LEN), body.data(),
        sfx(lastFit));
  CHECK(checkRecord(v, lastFit, &info) == R_VALID);
  CHECK(samePos(info.next, Pos{0, 63, 8190, 1}));
  const Pos nextMbyte = {0, 63, 8190, 1};
  craft(log, nextMbyte, makeW0(TYPE_NEXT_MBYTE, 0, NEXT_MBYTE_LEN), body.data(),
        sfx(nextMbyte));
  CHECK(checkRecord(v, nextMbyte, &info) == R_VALID);
  CHECK(samePos(info.next, mbyteStart(0, 2, 1)));

  /* V3: a record into a page whose header fails */
  rawHeader(log, 0, 61, 61, 1);
  rawHeader(log, 0, 62, 62, 2);
  const Pos spans = {0, 61, 8100, 1};
  prep[PREP_KEY_LEN - 2] = 2;
  prep[PREP_AI_LEN - 2] = 190;
  craft(log, spans, makeW0(TYPE_PREPARE, 0, 200), prep.data(), sfx(spans));
  CHECK(checkRecord(v, spans, &info) == R_SPAN_HDR);

  /* V5: page 0 holds the FD at word 32 and the FILLER to the page end */
  RecInfo fdInfo;
  CHECK(checkRecord(v, Pos{0, 0, 32, 1}, &fdInfo) == R_VALID);
  CHECK(w0Type(fdInfo.w0) == TYPE_FD);
  CHECK(checkRecord(v, fdInfo.next, &info) == R_VALID);
  CHECK(w0Type(info.w0) == TYPE_FILLER);
  CHECK(samePos(info.next, Pos{0, 1, 32, 1}));

  rawHeader(log, 2, 0, 0, 1);
  const Pos fdPos = {2, 0, 32, 1};
  fd[FD_FILE_NO - 2] = 2;
  craft(log, fdPos, makeW0(TYPE_COMMIT, 0, COMMIT_LEN), body.data(),
        sfx(fdPos));
  CHECK(checkRecord(v, fdPos, &info) == R_FD_POS);
  craft(log, fdPos, makeW0(TYPE_FD, 0, fdLen(3, 4) + 2), fd.data(), sfx(fdPos));
  CHECK(checkRecord(v, fdPos, &info) == R_LEN);
  fd[FD_NO_FD - 2] = 0;
  craft(log, fdPos, makeW0(TYPE_FD, 0, fdLen(0, 4)), fd.data(), sfx(fdPos));
  CHECK(checkRecord(v, fdPos, &info) == R_LEN);
  fd[FD_NO_FD - 2] = 3;
  craft(log, fdPos, makeW0(TYPE_FD, 0, fdLen(3, 4)), fd.data(), sfx(fdPos));
  CHECK(checkRecord(v, fdPos, &info) == R_VALID);
  const Pos after = info.next;
  CHECK(samePos(after, Pos{2, 0, 32 + fdLen(3, 4), 1}));
  craft(log, after, makeW0(TYPE_COMMIT, 0, COMMIT_LEN), body.data(),
        sfx(after));
  CHECK(checkRecord(v, after, &info) == R_FD_POS);
  craft(log, after, makeW0(TYPE_FILLER, 0, PAGE_WORDS - after.pageIndex - 16),
        body.data(), sfx(after));
  CHECK(checkRecord(v, after, &info) == R_FILLER_ALIGN);
  craft(log, after, makeW0(TYPE_FILLER, 0, PAGE_WORDS - after.pageIndex),
        body.data(), sfx(after));
  CHECK(checkRecord(v, after, &info) == R_VALID);
  CHECK(samePos(info.next, Pos{2, 1, 32, 1}));
  const Pos midPage0 = {2, 0, 2000, 1};
  craft(log, midPage0, makeW0(TYPE_FILLER, 0, 16), body.data(), sfx(midPage0));
  CHECK(checkRecord(v, midPage0, &info) == R_FD_POS);

  /* V5: nothing after a NEXT_MBYTE in its mbyte is read */
  const Pos early = at(44);
  craft(log, early, makeW0(TYPE_NEXT_MBYTE, 0, NEXT_MBYTE_LEN), body.data(),
        sfx(early));
  const ScanResult scan = findEnd(v, 0, 0, 1);
  CHECK(samePos(scan.end, mbyteStart(0, 2, 1)));
  CHECK(scan.reason == R_HDR_FORMAT);
  CHECK(scan.records == 5);  // FD, FILLER, NEXT_MBYTE, COMMIT, NEXT_MBYTE
  CHECK(scan.mbytes == 2);
  CHECK(!scan.nextFile);
  return true;
}

/* ------------------------------------------------------------------ */
/* The cases of recovery §3.3                                          */
/* ------------------------------------------------------------------ */

/**
 * The writer in mbyte 1 of file 1, lap 2. With previousLap, lap 1 was
 * written there first from the same stream, so the two laps hold the
 * same records at the same places up to where lap 2 stops.
 */
void setUp(TestLog &log, Uint64 stream, bool previousLap) {
  log.reset();
  if (previousLap) {
    log.setStream(stream);
    log.beginAt(1, 1, 1);
    log.randomWindow(3000, 0);
    log.barrier();
    log.fillPageTo(PAGE_WORDS);
    log.barrier();
    log.randomWindow(3000, 0);
    log.barrier();
    log.forgetHistory();
  }
  log.setStream(stream);
  log.beginAt(1, 1, 2);
  log.randomWindow(3000, 0);
  log.barrier();
}

bool cleanEnd(TestLog &log, bool previousLap) {
  Rng rng(1);
  setUp(log, 101, previousLap);
  log.crash(CRASH_CLEAN, rng);
  ScanResult scan;
  CHECK(findLogEnd(log, &scan));
  CHECK(samePos(scan.end, log.persisted()));
  CHECK(scan.end.pageIndex % W_WORDS == 0);  // a FILLER closed the unit
  if (!previousLap) {
    CHECK(scan.reason == R_TYPE_ZERO);
  } else {
    /**
     * Lap 1 wrote a PREPARE there to the page end, with its checksum
     * bound to lap 1. Lap 2 rewrote the page header, unless E starts the
     * page.
     */
    const Pos &e = scan.end;
    const Suffix lap1 = suffix(1, log.geom().logPartNo, e.fileNo, e.pageNo,
                               e.pageIndex);
    CHECK(checkRecordWords(log.at(e), PAGE_WORDS - e.pageIndex, lap1) ==
          R_VALID);
    CHECK(scan.reason ==
          (e.pageIndex == HEADER_WORDS ? R_HDR_LAP : R_CHECKSUM));
  }
  CHECK(walkFrom(log, mbyteStart(1, 0, 2), scan));
  return true;
}

bool previousLapAtPageStart(TestLog &log, bool previousLap) {
  Rng rng(2);
  setUp(log, 102, previousLap);
  log.fillPageTo(PAGE_WORDS);
  log.barrier();  // the next page is not started: its header is old
  log.crash(CRASH_CLEAN, rng);
  ScanResult scan;
  CHECK(findLogEnd(log, &scan));
  CHECK(samePos(scan.end, log.persisted()));
  CHECK(scan.end.pageIndex == HEADER_WORDS);
  CHECK(scan.reason == (previousLap ? R_HDR_LAP : R_HDR_FORMAT));
  return true;
}

bool tornLastRecord(TestLog &log) {
  Rng rng(3);
  setUp(log, 103, false);
  const Pos commit = log.append(TYPE_COMMIT, CF_DURABLE,
                                std::vector<Uint32>(10, 77).data(), COMMIT_LEN);
  log.crash(CRASH_FULL, rng);
  ScanResult scan;
  CHECK(findLogEnd(log, &scan));
  CHECK(posLsn(log.geom(), scan.end) > posLsn(log.geom(), commit));

  /* One 8-byte chunk of the COMMIT kept its old content */
  log.at(commit)[6] = 0;
  log.at(commit)[7] = 0;
  CHECK(findLogEnd(log, &scan));
  CHECK(samePos(scan.end, commit));
  CHECK(scan.reason == R_CHECKSUM);
  return true;
}

bool tornPageHeader(TestLog &log) {
  Rng rng(4);
  setUp(log, 104, false);
  log.fillPageTo(PAGE_WORDS);
  log.barrier();
  const Pos first = log.append(TYPE_COMPLETE, 0,
                               std::vector<Uint32>(2, 5).data(), COMPLETE_LEN);
  CHECK(first.pageIndex == HEADER_WORDS);
  log.crash(CRASH_FULL, rng);
  log.rawPage(first.fileNo, first.pageNo)[HDR_VERSION] = 0;
  ScanResult scan;
  CHECK(findLogEnd(log, &scan));
  CHECK(samePos(scan.end, first));
  CHECK(scan.reason == R_HDR_CHECKSUM);
  return true;
}

bool spannedRecords(TestLog &log) {
  Rng rng(5);
  setUp(log, 105, false);

  /* A PREPARE of the largest size over 4 pages */
  log.fillPageTo(PAGE_WORDS - 6);
  const size_t index = log.history().size();
  const Pos big = log.prepareOfLen(PREPARE_MAX);
  CHECK(big.pageIndex == PAGE_WORDS - 6);
  CHECK(log.history()[index].next.pageNo == big.pageNo + 3);

  /* A PREPARE over 2 pages whose second page header is torn */
  log.barrier();
  log.fillPageTo(PAGE_WORDS - 100);
  log.barrier();
  const Pos two = log.prepareOfLen(400);
  log.crash(CRASH_FULL, rng);
  ScanResult scan;
  CHECK(findLogEnd(log, &scan));
  CHECK(posLsn(log.geom(), scan.end) > posLsn(log.geom(), two));
  log.rawPage(two.fileNo, two.pageNo + 1)[HDR_MAX_GCI_STARTED] ^= 1;
  CHECK(findLogEnd(log, &scan));
  CHECK(samePos(scan.end, two));
  CHECK(scan.reason == R_SPAN_HDR);
  return true;
}

bool mbyteHeader(TestLog &log, bool previousLap) {
  Rng rng(6);
  setUp(log, 106, previousLap);
  log.nextMbyte();
  const Pos second = log.cur();
  CHECK(samePos(second, mbyteStart(1, 2, 2)));
  if (previousLap) {
    /* Nothing stored in mbyte 2 in lap 2: its header is one of lap 1 */
    rawHeader(log, 1, second.pageNo, second.pageNo, 1);
    log.crash(CRASH_CLEAN, rng);
  } else {
    log.append(TYPE_COMPLETE, 0, std::vector<Uint32>(2, 6).data(),
               COMPLETE_LEN);
    log.crash(CRASH_FULL, rng);
    log.rawPage(1, second.pageNo)[HDR_LAP + 1] ^= 1;  // a torn header
  }
  CHECK(findLastMbyte(log.view(), 1, 2).mbyte == 1);
  ScanResult scan;
  CHECK(findLogEnd(log, &scan));
  CHECK(samePos(scan.end, second));
  CHECK(scan.reason == (previousLap ? R_HDR_LAP : R_HDR_CHECKSUM));
  CHECK(scan.mbytes == 1);
  return true;
}

bool zeroedRegion(TestLog &log) {
  Rng rng(7);
  setUp(log, 107, false);
  const std::vector<LogRec> &hist = log.history();
  const LogRec victim = hist[hist.size() / 2];
  Uint32 *w = log.at(victim.pos);
  memset(w, 0, 4 * std::min<Uint32>(100, PAGE_WORDS - victim.pos.pageIndex));
  log.crash(CRASH_CLEAN, rng);
  const LastMbyte last = findLastMbyte(log.view(), 1, 2);
  CHECK(last.reason == R_VALID);
  const ScanResult scan = findEnd(log.view(), 1, last.mbyte, 2);
  CHECK(samePos(scan.end, victim.pos));
  CHECK(scan.reason == R_TYPE_ZERO);
  return true;
}

/**
 * The file switch: the NEXT_MBYTE of the last mbyte is fenced, page 0 of
 * the next file is stored, and the process stops before it is fenced
 * (fdTorn) or before the slot names the new file.
 */
bool fileSwitch(TestLog &log, bool fdTorn) {
  Rng rng(8);
  log.reset();
  log.setStream(108);
  log.beginAt(1, 3, 2);
  log.randomWindow(2000, 0);
  log.barrier();
  log.stopAfter(fdTorn ? 3 : 5);  // NEXT_MBYTE, fence, FD (, FILLER, fence)
  log.nextMbyte();
  CHECK(log.dead());
  CHECK(log.slotFile() == 1);
  log.crash(CRASH_FULL, rng);
  const Pos fdPos = {2, 0, HEADER_WORDS, 2};
  if (fdTorn) log.at(fdPos)[10] ^= 0xFF;
  ScanResult scan;
  CHECK(findLogEnd(log, &scan));
  CHECK(scan.nextFile);
  CHECK(scan.mbytes == 1);
  if (fdTorn) {
    CHECK(samePos(scan.end, fdPos));
    CHECK(scan.reason == R_CHECKSUM);
  } else {
    CHECK(samePos(scan.end, Pos{2, 1, HEADER_WORDS, 2}));
    CHECK(scan.reason == R_HDR_FORMAT);
  }

  /* The restart redoes the file switch, or names the file in the slot */
  CHECK(log.restart(scan.end, scan.end));
  CHECK(log.slotFile() == 2 && log.slotLap() == 2);
  log.randomWindow(500, 0);
  log.barrier();
  log.crash(CRASH_CLEAN, rng);
  CHECK(findLogEnd(log, &scan));
  CHECK(!scan.nextFile);
  CHECK(walkFrom(log, mbyteStart(1, 3, 2), scan));
  return true;
}

/**
 * Orphans after a hole: records after the last fence persist while one
 * before them does not. V1-V5 accept the orphans. The restart zeroes
 * them; a new record ending where an orphan started then ends the log
 * there. Without the zeroing the scan runs on into the orphans.
 */
bool orphans(TestLog &log, bool zeroing) {
  Rng rng(9);
  setUp(log, 109, false);
  log.setZeroing(zeroing);
  std::vector<Uint32> body(PREPARE_HEAD + 40, 9);
  body[PREP_AI_LEN - 2] = 30;
  body[PREP_KEY_LEN - 2] = 2;
  const Pos hole = log.append(TYPE_COMMIT, 0, body.data(), COMMIT_LEN);
  const Pos orphan = log.cur();
  /* No barrier: none of them is fenced */
  log.append(TYPE_COMPLETE, 0, body.data(), COMPLETE_LEN);
  log.append(TYPE_PREPARE, 0, body.data(), prepareLen(2, 30, false));
  log.append(TYPE_COMMIT, CF_DURABLE, body.data(), COMMIT_LEN);
  log.append(TYPE_ABORT, AF_AFTER_COMMIT, body.data(), ABORT_LEN);
  log.append(TYPE_COMPLETED_GCI, 0, body.data(), COMPLETED_GCI_LEN);
  log.crash(CRASH_FULL, rng);
  memset(log.at(hole), 0, 4 * COMMIT_LEN);

  RecInfo info;
  CHECK(checkRecord(log.view(), orphan, &info) == R_VALID);
  ScanResult scan;
  CHECK(findLogEnd(log, &scan));
  CHECK(samePos(scan.end, hole));
  CHECK(scan.reason == R_TYPE_ZERO);

  CHECK(log.restart(scan.end, scan.end));
  const Pos again = log.append(TYPE_COMMIT, 0, body.data(), COMMIT_LEN);
  CHECK(samePos(again, hole));
  CHECK(samePos(log.cur(), orphan));
  log.crash(CRASH_FULL, rng);

  const ScanResult rescan = findEnd(log.view(), 1, 1, 2);
  if (zeroing) {
    CHECK(samePos(rescan.end, orphan));
    CHECK(rescan.reason == R_TYPE_ZERO);
    CHECK(findLogEnd(log, &scan));
  } else {
    CHECK(posLsn(log.geom(), rescan.end) > posLsn(log.geom(), orphan));
  }
  return true;
}

bool cases(TestLog &log) {
  CHECK(cleanEnd(log, false));
  CHECK(cleanEnd(log, true));
  CHECK(previousLapAtPageStart(log, false));
  CHECK(previousLapAtPageStart(log, true));
  CHECK(tornLastRecord(log));
  CHECK(tornPageHeader(log));
  CHECK(spannedRecords(log));
  CHECK(mbyteHeader(log, false));
  CHECK(mbyteHeader(log, true));
  CHECK(zeroedRegion(log));
  CHECK(fileSwitch(log, true));
  CHECK(fileSwitch(log, false));
  CHECK(orphans(log, true));
  CHECK(orphans(log, false));
  return true;
}

/* ------------------------------------------------------------------ */
/* Random logs (U4)                                                    */
/* ------------------------------------------------------------------ */

CrashMode pickMode(Rng &rng) {
  const Uint32 r = rng.below(100);
  return r < 25 ? CRASH_CLEAN : r < 40 ? CRASH_FULL : CRASH_RANDOM;
}

/**
 * One random log: a part of a file written in lap 1-3 over the previous
 * lap (often the same records), random records and barriers, a crash
 * after a random event, E checked; a restart at E or at an earlier
 * record end, more records, a second crash, often soon after the
 * restart, and E checked again: no record from before the restart
 * beyond the head is accepted.
 */
bool randomLog(TestLog &log, Uint64 seed, bool zeroing) {
  g_seed = seed;
  Rng rng(seed);
  log.reset();
  log.setZeroing(zeroing);
  const Geom &g = log.geom();
  const Uint32 fileNo = rng.below(g.noFiles);
  const Uint32 mbyte = rng.below(g.fileSizeMb);
  const Uint32 lap = 1 + rng.below(3);
  const Uint32 roomLeft =
      64 + (rng.chance(50) ? rng.below(4000)
                           : rng.below(PAGES_IN_MBYTE * PAGE_DATA_WORDS));
  const Uint32 window =
      64 + (rng.chance(20) ? rng.below(300000) : rng.below(20000));
  const Uint32 bigPercent = rng.chance(30) ? 5 : 0;
  const Uint64 stream = rng.next();

  if (lap > 1) {
    log.setStream(rng.chance(50) ? stream : rng.next());
    log.beginAt(fileNo, mbyte, lap - 1);
    log.fillTo(roomLeft);
    log.barrier();
    log.randomWindow(window + 4000, bigPercent);
    log.barrier();
    log.forgetHistory();
  }
  log.setStream(stream);
  log.beginAt(fileNo, mbyte, lap);
  log.fillTo(roomLeft);
  log.barrier();
  const Pos start = mbyteStart(fileNo, 0, lap);

  log.stopAfter(1 + rng.below(window / 16 + 20));
  log.randomWindow(window, bigPercent);
  log.crash(pickMode(rng), rng);
  ScanResult scan;
  CHECK(findLogEnd(log, &scan));
  CHECK(walkFrom(log, start, scan));

  /* The head: E, or the end of an earlier record */
  Pos head = scan.end;
  if (rng.chance(50)) {
    const std::vector<LogRec> &hist = log.history();
    const Uint64 endLsn = posLsn(g, scan.end);
    size_t n = 0;
    while (n < hist.size() && posLsn(g, hist[n].next) <= endLsn) n++;
    if (n > 0) head = hist[rng.below(Uint32(n))].next;
  }
  CHECK(log.restart(scan.end, head));

  log.setStream(rng.next());
  log.stopAfter(rng.chance(30) ? 1 + rng.below(3)
                               : 1 + rng.below(window / 16 + 20));
  log.randomWindow(rng.chance(30) ? 64 : window, bigPercent);
  log.crash(pickMode(rng), rng);
  CHECK(findLogEnd(log, &scan));
  CHECK(walkFrom(log, start, scan));
  return true;
}

bool randomLogs(TestLog &log, Uint64 seed, Uint32 loops) {
  for (Uint32 i = 0; i < loops; i++) {
    if (!randomLog(log, seed + i, true)) {
      fprintf(stderr,
              "random log %u failed; replay it with --random --seed=%llu "
              "--loops=1\n",
              i, (unsigned long long)(seed + i));
      return false;
    }
  }
  return true;
}

/**
 * The random logs are a test: without the zeroing of the restart they
 * fail. A log counts only if it passes with the zeroing; the two runs are
 * the same up to the restart, so the failure is after it.
 */
bool zeroingNeeded(TestLog &log, Uint64 seed) {
  for (Uint32 i = 0; i < 2000; i++) {
    if (!randomLog(log, seed + i, true)) return false;
    g_verbose = false;
    const bool passed = randomLog(log, seed + i, false);
    g_verbose = true;
    if (!passed) {
      printf("without zeroing, random log %u accepts a stale record\n", i);
      return true;
    }
  }
  fprintf(stderr, "2000 random logs passed without zeroing\n");
  return false;
}

}  // namespace

int main(int argc, char **argv) {
  bool randomOnly = false;
  Uint32 loops = 0;
  Uint64 seed = 1;
  bool seedGiven = false;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--random") == 0) {
      randomOnly = true;
    } else if (strncmp(argv[i], "--loops=", 8) == 0) {
      loops = Uint32(strtoul(argv[i] + 8, nullptr, 10));
    } else if (strncmp(argv[i], "--seed=", 7) == 0) {
      seed = strtoull(argv[i] + 7, nullptr, 10);
      seedGiven = true;
    } else {
      fprintf(stderr, "usage: %s [--random] [--loops=N] [--seed=S]\n",
              argv[0]);
      return 2;
    }
  }
  if (randomOnly && !seedGiven) seed = Uint64(time(nullptr));
  if (loops == 0) loops = randomOnly ? 10000 : 300;

  TestLog log(3, 4, 5);  // 3 files of 4 MB, log part 5
  if (randomOnly) {
    plan(1);
    ok(randomLogs(log, seed, loops), "%u random logs from seed %llu", loops,
       (unsigned long long)seed);
    return exit_status();
  }
  plan(5);
  ok(arithmetic(log), "positions");
  ok(framing(log), "V1-V5 on crafted records");
  ok(cases(log), "the end-of-log cases of recovery 3.3");
  ok(randomLogs(log, seed, loops), "%u random logs from seed %llu", loops,
     (unsigned long long)seed);
  ok(zeroingNeeded(log, seed), "random logs fail without the zeroing");
  return exit_status();
}
