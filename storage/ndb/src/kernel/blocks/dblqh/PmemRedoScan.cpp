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

#include "PmemRedoScan.hpp"

namespace PmemRedo {

namespace {

Uint32 nextFileNo(const Geom &g, Uint32 fileNo) {
  return fileNo + 1 < g.noFiles ? fileNo + 1 : 0;
}

/* Word k of the record at p, page headers skipped; its pages are checked */
Uint32 recordWord(const PartView &v, const Pos &p, Uint32 k) {
  const Uint32 inFirst = PAGE_WORDS - p.pageIndex;
  if (k < inFirst) return v.page(p.fileNo, p.pageNo)[p.pageIndex + k];
  k -= inFirst;
  return v.page(p.fileNo, p.pageNo + 1 + k / PAGE_DATA_WORDS)
      [HEADER_WORDS + k % PAGE_DATA_WORDS];
}

}  // namespace

Pos nextMbyteStart(const Geom &g, const Pos &p) {
  const Uint32 mbyte = p.pageNo / PAGES_IN_MBYTE + 1;
  if (mbyte < g.fileSizeMb) return mbyteStart(p.fileNo, mbyte, p.lap);
  const Uint32 fileNo = nextFileNo(g, p.fileNo);
  return mbyteStart(fileNo, 0, fileNo == 0 ? p.lap + 1 : p.lap);
}

Pos ceilUnit(const Geom &g, const Pos &p) {
  const Uint32 index = p.pageIndex + padWords(p.pageIndex);
  if (index < PAGE_WORDS) return Pos{p.fileNo, p.pageNo, index, p.lap};
  if (p.pageNo + 1 < g.pagesInFile())
    return Pos{p.fileNo, p.pageNo + 1, 0, p.lap};
  const Uint32 fileNo = nextFileNo(g, p.fileNo);
  return Pos{fileNo, 0, 0, fileNo == 0 ? p.lap + 1 : p.lap};
}

Uint32 checkPage(const PartView &v, Uint32 fileNo, Uint32 pageNo,
                 Uint32 lap) {
  const Uint32 *hdr = v.page(fileNo, pageNo);
  const Uint32 r = checkPageHeader(hdr, fileNo, pageNo, v.g.logPartNo);
  if (r != R_VALID) return r;
  if (hdr[HDR_LAP] != lap) return R_HDR_LAP;
  return R_VALID;
}

Uint32 checkRecord(const PartView &v, const Pos &p, RecInfo *out) {
  const Geom &g = v.g;
  if (p.fileNo >= g.noFiles || p.pageNo >= g.pagesInFile() ||
      p.pageIndex < HEADER_WORDS || p.pageIndex >= PAGE_WORDS ||
      (p.pageIndex & 1))
    return R_POS;

  /* V1, and V2 on w0 */
  Uint32 r = checkPage(v, p.fileNo, p.pageNo, p.lap);
  if (r != R_VALID) return r;
  const Uint32 *page = v.page(p.fileNo, p.pageNo);
  const Uint32 w0 = page[p.pageIndex];
  r = checkFraming(w0);
  if (r != R_VALID) return r;
  const Uint32 type = w0Type(w0);
  const Uint32 len = w0Len(w0);

  /* V5: page 0 holds the FD at word 32 and the FILLER after it */
  if (p.pageNo == 0) {
    if (p.pageIndex == HEADER_WORDS) {
      if (type != TYPE_FD) return R_FD_POS;
    } else if (type != TYPE_FILLER ||
               p.pageIndex != HEADER_WORDS + w0Len(page[HEADER_WORDS])) {
      return R_FD_POS;
    }
  } else if (type == TYPE_FD) {
    return R_FD_POS;
  }

  /* V2: the record ends before the end of the mbyte, a NEXT_MBYTE at it */
  const Uint32 inFirst = PAGE_WORDS - p.pageIndex;
  const Uint32 lastPage =
      (p.pageNo / PAGES_IN_MBYTE + 1) * PAGES_IN_MBYTE - 1;
  const Uint32 room = inFirst + (lastPage - p.pageNo) * PAGE_DATA_WORDS;
  if (len > (type == TYPE_NEXT_MBYTE ? room : room - NEXT_MBYTE_LEN))
    return R_CROSSES_MBYTE;

  /* V3: every further page the record spans */
  const Uint32 spanned =
      len > inFirst ? (len - inFirst + PAGE_DATA_WORDS - 1) / PAGE_DATA_WORDS
                    : 0;
  for (Uint32 i = 1; i <= spanned; i++) {
    if (checkPage(v, p.fileNo, p.pageNo + i, p.lap) != R_VALID)
      return R_SPAN_HDR;
  }

  /* V2 on the content, V5 for a FILLER */
  switch (type) {
    case TYPE_PREPARE:
      if (!prepareLenOk(w0, recordWord(v, p, PREP_AI_LEN),
                        recordWord(v, p, PREP_KEY_LEN)))
        return R_LEN;
      break;
    case TYPE_FD:
      if (!fdLenOk(w0, recordWord(v, p, FD_NO_FD), g.noFiles, g.fileSizeMb))
        return R_LEN;
      break;
    case TYPE_FILLER:
      if (p.pageNo == 0) {
        if (p.pageIndex + len != PAGE_WORDS) return R_FILLER_ALIGN;
      } else if (len > FILLER_MAX || (p.pageIndex + len) % W_WORDS != 0) {
        return R_FILLER_ALIGN;
      }
      break;
    default:
      break;
  }

  /* V4: the body one piece per page, then w0 and S */
  RecChecksum c;
  const Uint32 hashed = hashedLen(w0);
  if (hashed > 2) {
    const Uint32 n1 = (hashed < inFirst ? hashed : inFirst) - 2;
    c.piece(page + p.pageIndex + 2, n1);
    Uint32 left = hashed - 2 - n1;
    for (Uint32 pageNo = p.pageNo + 1; left > 0; pageNo++) {
      const Uint32 n = left < PAGE_DATA_WORDS ? left : PAGE_DATA_WORDS;
      c.piece(v.page(p.fileNo, pageNo) + HEADER_WORDS, n);
      left -= n;
    }
  }
  const Suffix s =
      suffix(p.lap, g.logPartNo, p.fileNo, p.pageNo, p.pageIndex);
  if (page[p.pageIndex + 1] != c.finish(w0, s)) return R_CHECKSUM;

  out->w0 = w0;
  if (type == TYPE_NEXT_MBYTE) {
    out->next = nextMbyteStart(g, p);
  } else if (len < inFirst) {
    out->next = Pos{p.fileNo, p.pageNo, p.pageIndex + len, p.lap};
  } else {
    const Uint32 k = len - inFirst;
    out->next = Pos{p.fileNo, p.pageNo + 1 + k / PAGE_DATA_WORDS,
                    HEADER_WORDS + k % PAGE_DATA_WORDS, p.lap};
  }
  return R_VALID;
}

ScanResult findEnd(const PartView &v, Uint32 fileNo, Uint32 mbyte,
                   Uint32 lap) {
  ScanResult res = {mbyteStart(fileNo, mbyte, lap), R_VALID, 0, 0, false};
  /**
   * The loop ends: a lap more in file 0 at every wrap, and a page header
   * holds one lap.
   */
  for (;;) {
    RecInfo info;
    const Uint32 r = checkRecord(v, res.end, &info);
    if (r != R_VALID) {
      res.reason = r;
      res.nextFile = res.end.fileNo != fileNo;
      return res;
    }
    res.records++;
    if (w0Type(info.w0) == TYPE_NEXT_MBYTE) res.mbytes++;
    res.end = info.next;
  }
}

LastMbyte findLastMbyte(const PartView &v, Uint32 fileNo, Uint32 lap) {
  LastMbyte res = {checkPage(v, fileNo, 0, lap), 0, false};
  if (res.reason != R_VALID) return res;
  Uint32 mbyte = 1;
  while (mbyte < v.g.fileSizeMb &&
         checkPage(v, fileNo, mbyte * PAGES_IN_MBYTE, lap) == R_VALID)
    mbyte++;
  res.mbyte = mbyte - 1;
  for (mbyte++; mbyte < v.g.fileSizeMb; mbyte++) {
    if (checkPage(v, fileNo, mbyte * PAGES_IN_MBYTE, lap) == R_VALID) {
      res.validAfterDrop = true;
      break;
    }
  }
  return res;
}

}  // namespace PmemRedo
