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

#include <ndb_global.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/mman.h>
#endif

#include <NdbOut.hpp>
#include "../PmemRedoScan.hpp"
#include "kernel/signaldata/FsOpenReq.hpp"
#include "pmem_reader.hpp"
#include "portlib/ndb_file.h"

/**
 * RONDB-1150 (recovery plan S6.8): the REDO log format of
 * RedoLogMode=pmem, read with the checks of the restart (V1-V5,
 * PmemRedoScan.hpp). A file is read one mbyte at a time from the first
 * record position of the mbyte, with the lap of its first page header, up
 * to its NEXT_MBYTE or to the first position that holds no valid record,
 * the end of the valid log in that lap. Positions are printed as
 * mbyte:page:word, the page counted in the mbyte; a COMMIT names the page
 * of its PREPARE in the file, as it is stored.
 */
using namespace PmemRedo;

namespace {

constexpr Uint64 MBYTE_BYTES = Uint64(1) << 20;

/* A REDO log file, mapped read-only where the platform allows */
class PmemFile {
 public:
  PmemFile() = default;
  PmemFile(const PmemFile &) = delete;
  PmemFile &operator=(const PmemFile &) = delete;
  ~PmemFile() {
    release();
    if (m_file.is_open()) m_file.close();
  }

  /* 0, or -1 after a message on stderr */
  int load(const char *name) {
    if (m_file.open(name, FsOpenReq::OM_READONLY) != 0) {
      fprintf(stderr, "Error: cannot open %s: %s\n", name, strerror(errno));
      return -1;
    }
    const ndb_off_t size = m_file.get_size();
    if (size <= 0 || Uint64(size) % MBYTE_BYTES != 0) {
      fprintf(stderr, "Error: %s is %lld bytes, not a whole number of MB\n",
              name, (long long)size);
      return -1;
    }
    m_size = Uint64(size);
#ifndef _WIN32
    void *p = mmap(nullptr, size_t(m_size), PROT_READ, MAP_PRIVATE,
                   m_file.get_os_handle(), 0);
    if (p == MAP_FAILED) {
      fprintf(stderr, "Error: cannot map %s: %s\n", name, strerror(errno));
      return -1;
    }
    m_base = static_cast<const Uint8 *>(p);
#else
    Uint8 *buf = new Uint8[size_t(m_size)];
    for (Uint64 off = 0; off < m_size; off += MBYTE_BYTES) {
      if (m_file.read_pos(buf + off, size_t(MBYTE_BYTES), ndb_off_t(off)) !=
          int(MBYTE_BYTES)) {
        delete[] buf;
        fprintf(stderr, "Error: cannot read %s\n", name);
        return -1;
      }
    }
    m_base = buf;
#endif
    return 0;
  }

  const Uint8 *base() const { return m_base; }
  Uint64 size() const { return m_size; }

 private:
  void release() {
    if (m_base == nullptr) return;
#ifndef _WIN32
    munmap(const_cast<Uint8 *>(m_base), size_t(m_size));
#else
    delete[] m_base;
#endif
    m_base = nullptr;
  }

  ndb_file m_file;
  const Uint8 *m_base = nullptr;
  Uint64 m_size = 0;
};

bool zeroWords(const Uint32 *w, Uint32 n) {
  for (Uint32 i = 0; i < n; i++) {
    if (w[i] != 0) return false;
  }
  return true;
}

/* Word k of the record at p, the page headers it spans skipped */
Uint32 recWord(const PartView &v, const Pos &p, Uint32 k) {
  const Uint32 inFirst = PAGE_WORDS - p.pageIndex;
  if (k < inFirst) return v.page(p.fileNo, p.pageNo)[p.pageIndex + k];
  k -= inFirst;
  return v.page(p.fileNo, p.pageNo + 1 + k / PAGE_DATA_WORDS)
      [HEADER_WORDS + k % PAGE_DATA_WORDS];
}

void formatPos(char *buf, size_t size, Uint32 pageNo, Uint32 pageIndex) {
  snprintf(buf, size, "%u:%u:%u", pageNo / PAGES_IN_MBYTE,
           pageNo % PAGES_IN_MBYTE, pageIndex);
}

/* A line of values, of any length */
void printArray(const char *what, const Uint32 *a, Uint32 n) {
  std::string s(what);
  char num[16];
  for (Uint32 i = 0; i < n; i++) {
    snprintf(num, sizeof(num), " %u", a[i]);
    s += num;
  }
  ndbout << s.c_str() << endl;
}

/**
 * The FD in page 0 of fileNo: for each file before it, its own first,
 * the max GCI completed, the max GCI started and the last prepare
 * reference of each mbyte.
 */
void printFd(const char *at, const Uint32 *rec, const Geom &g,
             Uint32 fileNo) {
  const Uint32 noFd = rec[FD_NO_FD];
  ndbout_c("%s FD files %u, file %u", at, noFd, rec[FD_FILE_NO]);
  for (Uint32 d = 0; d < noFd; d++) {
    const Uint32 *const a = rec + FD_ARRAYS + d * 3 * g.fileSizeMb;
    ndbout_c("  file %u", (fileNo + g.noFiles - d) % g.noFiles);
    printArray("    max gci completed:", a, g.fileSizeMb);
    printArray("    max gci started:  ", a + g.fileSizeMb, g.fileSizeMb);
    printArray("    last prepare ref: ", a + 2 * g.fileSizeMb, g.fileSizeMb);
  }
}

/* A valid record, unless the options leave it out */
void printRecord(const PartView &v, const Pos &p, const RecInfo &info,
                 const PmemReaderOptions &o) {
  const Uint32 type = w0Type(info.w0);
  const Uint32 flags = w0Flags(info.w0);
  const Uint32 len = w0Len(info.w0);
  bool hasTransid = false;
  Uint32 t1 = 0;
  Uint32 t2 = 0;
  switch (type) {
    case TYPE_PREPARE:
      if (flags & PF_TRANSID) {
        hasTransid = true;
        t1 = recWord(v, p, PREP_TRANSID);
        t2 = recWord(v, p, PREP_TRANSID + 1);
      }
      break;
    case TYPE_COMMIT:
      hasTransid = true;
      t1 = recWord(v, p, COMMIT_TRANSID1);
      t2 = recWord(v, p, COMMIT_TRANSID2);
      break;
    case TYPE_ABORT:
    case TYPE_COMPLETE:
      hasTransid = true;
      t1 = recWord(v, p, ABORT_TRANSID1);
      t2 = recWord(v, p, ABORT_TRANSID2);
      break;
    default:
      break;
  }
  if (o.transidFilter &&
      !(hasTransid && t1 == o.transid[0] && t2 == o.transid[1]))
    return;
  if (!o.print || (type == TYPE_FILLER && !o.dump)) return;

  char at[32];
  formatPos(at, sizeof(at), p.pageNo, p.pageIndex);
  switch (type) {
    case TYPE_PREPARE: {
      char tid[48] = "";
      if (hasTransid) {
        snprintf(tid, sizeof(tid), " transid 0x%08x 0x%08x", t1, t2);
      }
      ndbout_c(
          "%s PREPARE len %u hash 0x%08x op %u key %u ai %u rowid %u.%u%s "
          "pages %u",
          at, len, recWord(v, p, PREP_HASH_VALUE),
          recWord(v, p, PREP_OPERATION), recWord(v, p, PREP_KEY_LEN),
          recWord(v, p, PREP_AI_LEN), recWord(v, p, PREP_ROWID_PAGE),
          recWord(v, p, PREP_ROWID_IDX), tid,
          pagesSpanned(p.pageIndex, len));
      break;
    }
    case TYPE_COMMIT: {
      const Uint32 fileIndex = recWord(v, p, COMMIT_PREP_FILE_INDEX);
      const Uint32 pages = recWord(v, p, COMMIT_PREP_PAGES);
      ndbout_c(
          "%s COMMIT table %u version %u frag %u prepare at file %u page %u "
          "word %u to page %u gci %u/%u transid 0x%08x 0x%08x ops %u%s%s",
          at, recWord(v, p, COMMIT_TABLE_ID),
          recWord(v, p, COMMIT_SCHEMA_VERSION), recWord(v, p, COMMIT_FRAG_ID),
          fileIndex >> 16, pages >> 16, fileIndex & 0xFFFF, pages & 0xFFFF,
          recWord(v, p, COMMIT_GCI_HI), recWord(v, p, COMMIT_GCI_LO), t1, t2,
          recWord(v, p, COMMIT_OP_COUNT),
          (flags & CF_DURABLE) ? " durable" : "",
          (flags & RF_INVALIDATED) ? " invalidated" : "");
      break;
    }
    case TYPE_ABORT:
      ndbout_c("%s ABORT transid 0x%08x 0x%08x%s", at, t1, t2,
               (flags & AF_AFTER_COMMIT) ? " after commit" : "");
      break;
    case TYPE_COMPLETE:
      ndbout_c("%s COMPLETE transid 0x%08x 0x%08x", at, t1, t2);
      break;
    case TYPE_COMPLETED_GCI:
      ndbout_c("%s COMPLETED_GCI gci %u", at, recWord(v, p, COMPLETED_GCI_GCI));
      break;
    case TYPE_NEXT_MBYTE:
      ndbout_c("%s NEXT_MBYTE", at);
      break;
    case TYPE_FD:
      printFd(at, v.page(p.fileNo, 0) + p.pageIndex, v.g, p.fileNo);
      break;
    case TYPE_FILLER:
      ndbout_c("%s FILLER len %u", at, len);
      break;
    case TYPE_SR_HEAD:
      ndbout_c("%s SR_HEAD 0x%08x 0x%08x 0x%08x 0x%08x", at, recWord(v, p, 2),
               recWord(v, p, 3), recWord(v, p, 4), recWord(v, p, 5));
      break;
    default:
      break;
  }
}

/* One page header: its checks and the words that recovery reads */
void printPageHeader(const PartView &v, Uint32 fileNo, Uint32 pageNo) {
  const Uint32 *const hdr = v.page(fileNo, pageNo);
  char at[32];
  formatPos(at, sizeof(at), pageNo, 0);
  if (zeroWords(hdr, HEADER_WORDS)) {
    ndbout_c("%s page header: unwritten", at);
    return;
  }
  const Uint32 r = checkPageHeader(hdr, fileNo, pageNo, v.g.logPartNo);
  ndbout_c(
      "%s page header: %s; lap %u, max gci completed %u, max gci started "
      "%u, last prepare ref %u, version %u, %u files, %u log parts; log "
      "part %u, file %u, page %u, write unit %u, node %u",
      at, r == R_VALID ? "ok" : reasonName(r), hdr[HDR_LAP],
      hdr[HDR_MAX_GCI_COMPLETED], hdr[HDR_MAX_GCI_STARTED],
      hdr[HDR_LAST_PREP_REF], hdr[HDR_VERSION], hdr[HDR_NO_LOG_FILES],
      hdr[HDR_NO_LOG_PARTS], hdr[HDR_LOG_PART_NO], hdr[HDR_FILE_NO],
      hdr[HDR_PAGE_NO], hdr[HDR_WRITE_UNIT], hdr[HDR_NODE_ID]);
}

/* --lap: the lap and GCIs of a page header, as for the file mode */
void printLap(const PartView &v, Uint32 fileNo, Uint32 pageNo) {
  const Uint32 *const hdr = v.page(fileNo, pageNo);
  char at[32];
  formatPos(at, sizeof(at), pageNo, 0);
  const Uint32 r = checkPageHeader(hdr, fileNo, pageNo, v.g.logPartNo);
  if (r != R_VALID) {
    ndbout_c("%s (no lap information: %s)", at,
             zeroWords(hdr, HEADER_WORDS) ? "unwritten" : reasonName(r));
    return;
  }
  ndbout_c("%s lap: %u maxgcicompleted: %u maxgcistarted: %u restartgen: %u",
           at, hdr[HDR_LAP], hdr[HDR_MAX_GCI_COMPLETED],
           hdr[HDR_MAX_GCI_STARTED], hdr[HDR_RESTART_GEN]);
}

/**
 * Page 0 of file 0: the config line and the two last-file slots, and the
 * slot that a restart takes. False if a restart could not use them.
 */
bool printControlArea(const PartView &v, const Uint32 *page0) {
  bool ok = true;
  const Uint32 *const line = page0 + CTRL_CONFIG_WORD;
  char msg[160];
  if (checkCtrlConfig(line, v.g, page0[HDR_NO_LOG_PARTS], page0[HDR_NODE_ID],
                      msg, sizeof(msg)) == CTRL_VALID) {
    ndbout_c(
        "control area: %u log parts, log part %u, %u files of %u MB, write "
        "unit %u bytes, node %u",
        line[CTRL_W_NO_PARTS], line[CTRL_W_PART_NO], line[CTRL_W_NO_FILES],
        line[CTRL_W_FILE_SIZE_MB], line[CTRL_W_WRITE_UNIT],
        line[CTRL_W_NODE_ID]);
  } else {
    ndbout_c("control area: %s", msg);
    ok = false;
  }
  const Uint32 *const slots[2] = {page0 + SLOT0_WORD, page0 + SLOT1_WORD};
  for (Uint32 i = 0; i < 2; i++) {
    Slot s;
    if (slotValid(slots[i], i, v.g, &s)) {
      ndbout_c(
          "slot %u: seq %llu, file %u, lap %u, dirty-shutdown count %llu%s%s",
          i, (unsigned long long)s.seq, s.fileNo, s.lap,
          (unsigned long long)s.dirtyShutdownCount,
          (s.flags & SLOT_F_DSC_VALID) ? "" : " (not reported)",
          (s.flags & SLOT_F_UNSAFE_SHUTDOWN) ? ", unsafe shutdown seen" : "");
    } else {
      ndbout_c("slot %u: %s", i,
               zeroWords(slots[i], W_WORDS) ? "never written" : "not valid");
    }
  }
  Slot last;
  const int index = pickSlot(slots[0], slots[1], v.g, &last);
  if (index < 0) {
    ndbout_c("last file: none, neither slot is valid");
    ok = false;
  } else {
    ndbout_c("last file: %u in lap %u (slot %d, seq %llu)", last.fileNo,
             last.lap, index, (unsigned long long)last.seq);
  }
  return ok;
}

}  // namespace

bool pmem_redo_file(const char *fileName) {
  ndb_file file;
  if (file.open(fileName, FsOpenReq::OM_READONLY) != 0) return false;
  Uint32 hdr[HEADER_WORDS];
  const bool pmem = file.read_pos(hdr, sizeof(hdr), 0) == int(sizeof(hdr)) &&
                    hdr[HDR_FORMAT_MAGIC] == FORMAT_MAGIC;
  file.close();
  return pmem;
}

int pmem_reader_main(const char *fileName, const PmemReaderOptions &o) {
  PmemFile file;
  if (file.load(fileName) != 0) return 1;
  const Uint32 *const page0 = reinterpret_cast<const Uint32 *>(file.base());
  const Uint32 fileNo = page0[HDR_FILE_NO];
  const Uint32 partNo = page0[HDR_LOG_PART_NO];
  const Uint32 noFiles = page0[HDR_NO_LOG_FILES];
  const Uint32 mbytes = Uint32(file.size() / MBYTE_BYTES);
  const Uint32 r = checkPageHeader(page0, fileNo, 0, partNo);
  if (r != R_VALID || fileNo >= noFiles) {
    ndbout_c("Error: page 0 of %s: %s", fileName,
             r != R_VALID ? reasonName(r) : "file number out of range");
    return 1;
  }
  /* The other files of the part are not read */
  std::vector<const Uint8 *> bases(noFiles, nullptr);
  bases[fileNo] = file.base();
  const PartView v = {Geom{noFiles, mbytes, partNo}, bases.data()};
  ndbout_c("PMEM REDO log file %s: log part %u, file %u of %u, %u MB, node %u",
           fileName, partNo, fileNo, noFiles, mbytes, page0[HDR_NODE_ID]);

  Uint32 errors = 0;
  if (fileNo == 0 && !printControlArea(v, page0)) errors++;

  if (o.onlyFileDesc) {
    const Pos p = {fileNo, 0, HEADER_WORDS, page0[HDR_LAP]};
    RecInfo info;
    const Uint32 fr = checkRecord(v, p, &info);
    if (fr != R_VALID) {
      ndbout_c("Error: the FD in page 0: %s", reasonName(fr));
      return 1;
    }
    char at[32];
    formatPos(at, sizeof(at), p.pageNo, p.pageIndex);
    printFd(at, page0 + HEADER_WORDS, v.g, fileNo);
    return errors > 0 && o.check ? 1 : 0;
  }

  Uint32 first = 0;
  Uint32 last = mbytes - 1;
  if (o.startAtMbyte != 0) {
    if (o.startAtMbyte >= mbytes) {
      ndbout_c("Error: mbyte %u is not in the file of %u MB", o.startAtMbyte,
               mbytes);
      return 1;
    }
    first = last = o.startAtMbyte;
  }

  /**
   * The mbyte where the log of a lap ended without a NEXT_MBYTE. The log
   * of that lap goes on in no later mbyte of the file: a restart zeroes
   * the log after its end, and a writer leaves no gap. The file cannot
   * tell whether that mbyte is the last of the log, which may end in a
   * torn record.
   */
  std::map<Uint32, Uint32> endOfLap;
  for (Uint32 mb = first; mb <= last; mb++) {
    const Uint32 pageNo = mb * PAGES_IN_MBYTE;
    if (o.onlyLap || o.onlyPageHeaders || o.onlyMbyteHeaders) {
      const Uint32 n = o.onlyMbyteHeaders ? 1 : PAGES_IN_MBYTE;
      for (Uint32 i = 0; i < n; i++) {
        if (o.onlyLap) {
          printLap(v, fileNo, pageNo + i);
        } else {
          printPageHeader(v, fileNo, pageNo + i);
        }
      }
      continue;
    }
    const Uint32 *const hdr = v.page(fileNo, pageNo);
    const Uint32 hr = checkPageHeader(hdr, fileNo, pageNo, partNo);
    if (hr != R_VALID) {
      ndbout_c("mb: %u %s", mb,
               zeroWords(hdr, HEADER_WORDS) ? "unwritten" : reasonName(hr));
      continue;
    }
    const Uint32 lap = hdr[HDR_LAP];
    ndbout_c("mb: %u lap %u", mb, lap);
    const auto ended = endOfLap.find(lap);
    if (ended != endOfLap.end()) {
      ndbout_c("Error: mbyte %u holds the log of lap %u, which ended in "
               "mbyte %u",
               mb, lap, ended->second);
      errors++;
    }
    Pos p = mbyteStart(fileNo, mb, lap);
    Uint32 records = 0;
    for (;;) {
      RecInfo info;
      const Uint32 rr = checkRecord(v, p, &info);
      if (rr != R_VALID) {
        char at[32];
        formatPos(at, sizeof(at), p.pageNo, p.pageIndex);
        ndbout_c("END OF VALID LOG at %s reason=%s after %u records", at,
                 reasonName(rr), records);
        Uint32 later = 0;
        for (Uint32 q = p.pageNo + 1; q < pageNo + PAGES_IN_MBYTE; q++) {
          if (checkPage(v, fileNo, q, lap) == R_VALID) later++;
        }
        if (later > 0) {
          ndbout_c("  %u later pages of the mbyte have a header of lap %u",
                   later, lap);
        }
        endOfLap.emplace(lap, mb);
        break;
      }
      records++;
      printRecord(v, p, info, o);
      if (w0Type(info.w0) == TYPE_NEXT_MBYTE) {
        if (!o.print) ndbout_c("  %u records to the NEXT_MBYTE", records);
        break;
      }
      p = info.next;
    }
  }
  if (errors > 0) {
    ndbout_c("%u error%s in %s", errors, errors == 1 ? "" : "s", fileName);
    if (o.check) return 1;
  }
  return 0;
}

int pmem_find_end_main(const char *dir) {
  const size_t len = strlen(dir);
  const char *const sep = (len > 0 && dir[len - 1] == '/') ? "" : "/";
  char name[1024];
  snprintf(name, sizeof(name), "%s%sS0.FragLog", dir, sep);
  std::vector<std::unique_ptr<PmemFile>> files;
  files.emplace_back(new PmemFile());
  if (files[0]->load(name) != 0) return 1;

  /* A: the control area of file 0 gives the files and the last file */
  const Uint32 *const page00 =
      reinterpret_cast<const Uint32 *>(files[0]->base());
  const Uint32 *const line = page00 + CTRL_CONFIG_WORD;
  if (line[CTRL_W_MAGIC] != CTRL_MAGIC) {
    fprintf(stderr,
            "Error: %s has no control area, it was not written in PMEM "
            "mode\n",
            name);
    return 1;
  }
  const Geom g = {line[CTRL_W_NO_FILES], line[CTRL_W_FILE_SIZE_MB],
                  line[CTRL_W_PART_NO]};
  char msg[160];
  if (checkCtrlConfig(line, g, line[CTRL_W_NO_PARTS], line[CTRL_W_NODE_ID],
                      msg, sizeof(msg)) != CTRL_VALID ||
      g.noFiles == 0 || g.fileSizeMb == 0) {
    fprintf(stderr, "Error: the control area of %s is not valid: %s\n", name,
            msg);
    return 1;
  }
  std::vector<const Uint8 *> bases;
  for (Uint32 f = 0; f < g.noFiles; f++) {
    snprintf(name, sizeof(name), "%s%sS%u.FragLog", dir, sep, f);
    if (f > 0) {
      files.emplace_back(new PmemFile());
      if (files[f]->load(name) != 0) return 1;
    }
    if (files[f]->size() != Uint64(g.fileSizeMb) * MBYTE_BYTES) {
      fprintf(stderr,
              "Error: %s is %llu bytes, the control area gives files of %u "
              "MB\n",
              name, (unsigned long long)files[f]->size(), g.fileSizeMb);
      return 1;
    }
    bases.push_back(files[f]->base());
  }
  const PartView v = {g, bases.data()};
  Slot slot;
  if (pickSlot(page00 + SLOT0_WORD, page00 + SLOT1_WORD, g, &slot) < 0) {
    fprintf(stderr,
            "Error: both last-file slots of REDO log part %u are invalid\n",
            g.logPartNo);
    return 1;
  }

  /**
   * B: page 0 and the mbyte headers of the last file give its last mbyte.
   * The GCIs that the restart reads from the FDs (C) do not move the end.
   */
  const LastMbyte last = findLastMbyte(v, slot.fileNo, slot.lap);
  Uint32 reason = last.reason;
  if (reason == R_VALID) {
    RecInfo info;
    reason = checkRecord(v, Pos{slot.fileNo, 0, HEADER_WORDS, slot.lap}, &info);
  }
  if (reason != R_VALID) {
    fprintf(stderr,
            "Error: page 0 of file %u, the last file of REDO log part %u in "
            "lap %u, is not valid: %s\n",
            slot.fileNo, g.logPartNo, slot.lap, reasonName(reason));
    return 1;
  }
  if (last.validAfterDrop) {
    fprintf(stderr,
            "Error: file %u of REDO log part %u has an mbyte of lap %u after "
            "mbyte %u, the last one written in it; the log is corrupt\n",
            slot.fileNo, g.logPartNo, slot.lap, last.mbyte);
    return 1;
  }

  /* D: the records from the last mbyte to E */
  const ScanResult scan = findEnd(v, slot.fileNo, last.mbyte, slot.lap);
  char buf[400];
  formatEnd(buf, sizeof(buf), g.logPartNo, slot.fileNo, slot.lap, slot.seq,
            last.mbyte, scan);
  ndbout_c("%s", buf);
  return 0;
}
