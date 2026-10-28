# RONDB-1150: REDO record format on persistent memory

Status: design draft, subtask of plan revision 6 (`durable_commits_plan.md`
§2.1, §7). No code has been changed. Companion documents written in parallel:
`research_pmem_hardware.md` (hardware), `pmem_redo_write_path.md` (write
path), `pmem_redo_recovery.md` (recovery). Where this format depends on them,
§11 states the assumption or requirement.

Paths are relative to `storage/ndb/`. Short names:
`DblqhMain.cpp` = `src/kernel/blocks/dblqh/DblqhMain.cpp`,
`Dblqh.hpp` = `src/kernel/blocks/dblqh/Dblqh.hpp`,
`reader.cpp` / `records.cpp` / `records.hpp` = files in
`src/kernel/blocks/dblqh/redoLogReader/`.

Tags: **[V]** verified by reading the code at the cited lines. **[I]**
inferred. Nothing was built or run.

---

## 0. Summary

| Topic | Decision |
|---|---|
| Geometry | Unchanged: files, 1 MB mbytes, 32 KB pages, a 32-word header on every page, positions `(fileNo, pageNo, pageIndex)`. No record spans an mbyte |
| Record header | Two words on every record. `w0` = type (8 bits), flags (8 bits), length in words (16 bits). `w1` = CRC32C |
| What the CRC covers | `w0` (without the mutable INVALIDATED bit), then `w2 … w(len-1)` in logical order (interleaved page headers skipped), then a 16-byte suffix `(lap, restartGen, logPart/fileNo, word position)` that is not stored |
| Stale records | Rejected by the suffix. A record from an older lap, from before a restart, or from another position gives a different CRC. No lap word per record |
| Alignment | Every record starts on 8 bytes and has an even length. So every gap is ≥ 2 words and every FILLER carries a CRC. Every word the reader interprets is CRC-checked |
| Page header | Written once, complete with its own CRC, when the page is started. Never updated. Fill index, links, dirty flag and debug words move to DRAM |
| Spanning records | One CRC per record over its logical words (option A, §6). A record is valid only if every page header it crosses is valid |
| FILLER | Type 10, 2 + n words, CRC over its header. Written at every persist barrier to close the current write unit W. In the last unit of an mbyte, NEXT_MBYTE closes it instead |
| COMMIT | 12 words (48 B): adds transid, gci_lo, opCount; the 4 prepare-reference fields packed into 2 |
| COMPLETE | 4 words (16 B): header + transid |
| ABORT | 4 words; flag `AF_AFTER_COMMIT` marks a rule-F abort |
| INVALID_COMMIT | A flag bit in the COMMIT header, set by one 4-byte store. Type 9 is retired |
| Overhead | Small update: 116 B today → 192 / 256 / 512 B at W = 64 / 128 / 256. Large update: 476 B → 576 / 640 / 768 B (§8) |
| Checksum code | NDB has no CRC32C helper. Add one, ported from InnoDB's `ut_crc32` (§9) |

---

## 1. What the code needs from the format

| Need | Where | Consequence for the PMEM format |
|---|---|---|
| A COMMIT finds its PREPARE by `(fileNo, startPageNo, startPageIndex, stopPageNo)`, all `Uint16` | `Dblqh.hpp:3259-3262`, `DblqhMain.cpp:42763-42810` [V] | Keep the page addressing. The four fields fit in two words |
| Readers skip the 32-word header at each page change | `readLogword` `DblqhMain.cpp:43054-43074`, `readLogwordExec` `43082-43103`, `stepAhead` `43514-43535` [V] | Keep a header on every page, or rewrite every reader |
| No record spans an mbyte. Each writer checks `size + ZNEXT_LOG_SIZE ≤ remainingWordsInMbyte` | `checkNewMbyte` `14172-14214`, `43546-43550`, `43578-43582`, `43634-43638` [V] | Keep. NEXT_MBYTE becomes exactly 2 words, the size already reserved (`Dblqh.hpp:245`) |
| SR phase 1 reads the header of the first page of each mbyte: lap, max GCI completed, max GCI started, last prepare reference | `readSrLastMbyteLab` `36367-36461` [V] | Keep these header fields with today's meaning |
| The FD record sits at word 32 of page 0 | `writeFileHeaderOpen` `36073-36161`; position check `39221-39229`; arrays read by `initGciInLogFileRec` `42279-42320` [V] | Keep the place; offsets inside it shift by one word |
| PREPARE header has fixed offsets 2–7 | `writeLogHeader` `14221-14255`, `readLogHeader` `43000-43047` [V] | Keep offsets 2–7 |
| SR rewrites a COMMIT in place as `ZINVALID_COMMIT_TYPE` | `DblqhMain.cpp:39113-39133` [V]; plan §5.2 step C | The rewrite must be one atomic store and must not break the CRC |
| Page 0 of file 0 is rewritten at each file change to record the last file | `firstPageWriteLab` `35190-35199`, `lastWriteInFileLab` `35297-35307` [V] | An in-place update of a persisted page. Drop it (§4.3) |
| The reader uses `ZCURR_PAGE_INDEX` of the page as its cursor and writes it | `43057-43061`, `42777-42778` [V] | On PMEM the reader must not store into the mapping (§11) |
| Max PREPARE size | `MAX_LOG_RECORD_SIZE_WORDS` = 18000 + 4096 (`include/kernel/ndb_limits.h:142,175-176`), enforced in `DbtupExecQuery.cpp:6670` [V]; key ≤ 1023 words (`ndb_limits.h:154`) [V] | Max PREPARE = 8 + 2 + 1023 + 22096 + 1 pad = 23130 words. Fits a 16-bit length. It can span **4 pages**, not 3 (§6.3) |

What PMEM changes [I, to be confirmed by `research_pmem_hardware.md`]:
- There is no page write. Persistence is per cache line (clwb + sfence on ADR,
  sfence on eADR). Power-fail atomicity is 8 aligned bytes.
- Within one barrier, ADR may persist lines in any order. A crash can leave a
  hole: a later line persisted, an earlier one lost.
- Each persist point writes only the lines it dirtied. Writing 32 KB pages and
  checksumming whole pages makes no sense.

---

## 2. Principles

| # | Principle |
|---|---|
| P1 | **Write once per (lap, restartGen).** Every word of a page is stored once in a lap. The only in-place change is the INVALIDATED bit, set by SR |
| P2 | **Every interpreted word is CRC-checked.** The bodies of FILLERs and the area after NEXT_MBYTE are dead space and are never read |
| P3 | **The CRC is bound to where and when the record was written** (§3.3). A checksum alone does not stop a stale, intact record |
| P4 | **8-byte alignment and even lengths.** Gaps are even, so a FILLER always has room for its CRC. `w0` and `w1` share one 8-byte unit |
| P5 | **The log is the longest valid prefix.** Recovery stops at the first invalid record and never skips one |
| P6 | **W is a performance parameter only.** No correctness argument relies on a W unit being written atomically. Torn units are possible at any W |

---

## 3. Common record header and checksum

### 3.1 Word 0

| Bits | Field | Meaning |
|---|---|---|
| 0–7 | type | §3.2. Type 0 is unwritten (zeroed) memory and means "no record here" |
| 8–15 | flags | §3.2 |
| 16–31 | len | Record length in words: includes `w0`, `w1` and any pad word; excludes interleaved page headers. Even, ≥ 2, ≤ 65534 |

An old-format reader sees for example `0x000C0002` for a COMMIT and stops
with "Invalid logword" (`DblqhMain.cpp:39350-39363`) [V]. The two formats
cannot be mixed by accident.

### 3.2 Type codes and flags

| Code | Today (`Dblqh.hpp:253-262`) [V] | PMEM format |
|---|---|---|
| 0 | NEW_PREP, never written | Unwritten. A clean end of log |
| 1 | PREPARE | PREPARE (§5.1) |
| 2 | COMMIT | COMMIT, 12 words (§5.2) |
| 3 | ABORT | ABORT, 4 words (§5.4) |
| 4 | FD | FD (§5.8) |
| 5 | FRAG_SPLIT, never written | Reserved |
| 6 | NEXT_LOG_RECORD | Retired; FILLER to the page end replaces it |
| 7 | NEXT_MBYTE | NEXT_MBYTE, 2 words (§5.6) |
| 8 | COMPLETED_GCI | COMPLETED_GCI, 4 words (§5.5) |
| 9 | INVALID_COMMIT | Retired; replaced by the flag `RF_INVALIDATED` |
| 10 | — | FILLER (§5.7) |
| 11 | — | COMPLETE, 4 words (§5.3) |
| 12 | — | SR_HEAD (§5.9, content owned by recovery) |

| Flag bit | Name | Types | Meaning | In CRC |
|---|---|---|---|---|
| 0 (`w0` bit 8) | `RF_INVALIDATED` | COMMIT | Cancelled by SR; replaces type 9 | **No** (mutable) |
| 1 | `CF_DURABLE` | COMMIT | Written under the durable protocol (GCI ≥ g). A COMPLETE or a rule-F ABORT is expected | Yes |
| 1 | `AF_AFTER_COMMIT` | ABORT | Rule F: this operation's COMMIT record was written before | Yes |
| 1 | `PF_TRANSID` | PREPARE | Words 8–9 hold the transid | Yes |
| 2–7 | — | — | Reserved, 0 | Yes |

### 3.3 What the CRC covers

`w1` = CRC32C (Castagnoli, as in iSCSI: initial value `0xFFFFFFFF`, final
XOR `0xFFFFFFFF`) over this byte string, words in little-endian memory order:

```
(w0 & ~0x00000100)  ||  w2 || w3 || ... || w(n-1)  ||  S
S = [ lap, restartGen, (logPartNo << 16) | fileNo, pageNo * 8192 + pageIndex ]
```

- `n = len` for every type except FILLER, where `n = 2` (the body is dead).
- `w1` itself is not part of the input.
- `w2 … w(n-1)` are the record's logical words. Page headers that sit inside
  the record are skipped; they have their own CRC (§4.2).
- `S` is 16 bytes and is **not stored**. The reader knows it: `(pageNo,
  pageIndex)` is where `w0` lies; `lap`, `restartGen` and `logPartNo` come
  from the header of the page that holds `w0`; `fileNo` from the file.
- `S` comes last so that the writer can compute the CRC of the record body
  before it takes the log-part lock, and add only `S` under the lock (§11, W8).

**Why the suffix, and why no lap word per record.** CRC alone fails in three
cases. Each is common, not theoretical:

| Stale record | Why it passes a plain CRC | What rejects it |
|---|---|---|
| From an older lap, at the same offset | Fillers make records start on W boundaries in every lap, so old and new record starts coincide often [I] | `lap` in `S` |
| From before a restart, same lap | An SR or node restart moves the head back to `COMPLETED_GCI(R)` and the same positions are written again (`invalidateLogAfterLastGCI` exists for this, `DblqhMain.cpp:39534-39858`) [V]. Records beyond the new end keep their old valid CRC | `restartGen` in `S` (§4.4) |
| Misplaced data (another part, file or offset) | A file restored to the wrong directory, a bug in the position arithmetic | `logPartNo`, `fileNo`, position in `S` |

An explicit lap word in each record would cost 4 bytes per record and still
miss the restart case. The suffix costs no space.

### 3.4 When is a record valid

A record at position p is valid iff all of these hold:

1. p is 8-byte aligned and lies after the page header, inside the usable part
   of the current mbyte.
2. `type` is one of 1, 2, 3, 4, 7, 8, 10, 11, 12.
3. `len` is even and inside the type's bounds: fixed for COMMIT (12),
   COMPLETE (4), ABORT (4), COMPLETED_GCI (4), NEXT_MBYTE (2), SR_HEAD (6);
   PREPARE exactly `roundup2(8 + 2·PF_TRANSID + keyLen + aiLen)` ≤ 23130;
   FD ≤ 8160; FILLER ≤ 8160 and ending on a W boundary.
4. The record ends before the end of the mbyte.
5. Every page header that the record crosses is valid (§4.2) and carries the
   same `lap` and `restartGen` as the page where it starts.
6. The CRC matches `w1`.

Bounds are checked before the CRC, so a garbage `len` never makes the reader
run off the mbyte.

---

## 4. The page header on PMEM

### 4.1 Word by word

Today the header is cleared and filled in `initLogpage` (`DblqhMain.cpp:
35577-35605`), and words 0 and 12–20 are rewritten at every write by
`writeDbgInfoPageHeader` (`46750-46762`) and `calcPageCheckSum`
(`46632-46639`, constant 37 in release builds) [V].

| Word | Name (`Dblqh.hpp:188-211`) | Today | PMEM: written once at page init |
|---|---|---|---|
| 0 | `ZPOS_CHECKSUM` | 37, set at every write | CRC32C over words 1–31 |
| 1 | `ZPOS_LOG_LAP` | at init | same |
| 2 | `ZPOS_MAX_GCI_COMPLETED` | at init | same |
| 3 | `ZPOS_MAX_GCI_STARTED` | at init | same |
| 4, 5 | `ZNEXT_PAGE`, `ZPREV_PAGE` | in-memory list links, changed at write (`41044-41056`) | 0. Links live in DRAM |
| 6 | `ZPOS_VERSION` | at init | same |
| 7 | `ZPOS_NO_LOG_FILES` | at init | same |
| 8 | `ZCURR_PAGE_INDEX` | fill index, changed at every append; on disk it is the end of data of a partial page | 0. The fill index lives in DRAM; the end of data comes from the record chain |
| 9 | — | 0 | 0 |
| 10 | `ZLAST_LOG_PREP_REF` | at init | same |
| 11 | `ZPOS_DIRTY` | set by SR (`39132`), cleared at write (`43672`) | 0. SR keeps dirty state in DRAM |
| 12–14 | timer, page i, `__LINE__` | every write | 0 |
| 15 | `ZPOS_PAGE_NO` | every write | page number in file (identity) |
| 16 | `ZPOS_PAGE_FILE_NO` | every write | file number (identity) |
| 17–20 | word written, in writing, prev page, in free list | every write or seize | 0 |
| 21 | `ZPOS_NO_LOG_PARTS` | at init | same |
| 22 | new `ZPOS_FORMAT_MAGIC` | 0 | constant with format version 1 |
| 23 | new `ZPOS_RESTART_GEN` | 0 | restart generation (§4.4) |
| 24 | new `ZPOS_LOG_PART_NO` | 0 | log part number |
| 25 | new `ZPOS_WRITE_UNIT` | 0 | W in bytes (64, 128 or 256) |
| 26 | new `ZPOS_NODE_ID` | 0 | own node id |
| 27–31 | — | 0 | 0, reserved |

### 4.2 Header validity

A header is valid iff the magic matches, the CRC matches, and words 15, 16 and
24 equal the page's real position and log part. A zeroed page has no magic and
is invalid. Recovery treats an invalid header as "not written in this lap"
(§11, R1). The header is 128 bytes, two cache lines at W = 64, so a torn header
is possible; its CRC catches that.

### 4.3 Which fields are final at page init, and what replaces the others

**Final at init, never updated (no change of meaning):** lap, max GCI
completed, max GCI started, version, number of files, last prepare reference,
number of log parts, plus the new identity fields. [V] for "set at init":
`initLogpage` `35583-35604`; nothing else stores them except
`initWriteEndLab` and `execFSWRITEREQ` during initial formatting
(`35371-35395`, `35763-35779`).

**Updated after init today, and the PMEM replacement:**

| Field | Replacement |
|---|---|
| `ZCURR_PAGE_INDEX` | DRAM cursor in the writer. Recovery finds the end of data by walking valid records (P5) |
| `ZPOS_CHECKSUM` (whole page) | Header-only CRC at init plus one CRC per record |
| Debug words 12–20 | Dropped on PMEM. They described each 32 KB write, which no longer exists. Words 15–16 keep the page identity |
| `ZNEXT_PAGE`, `ZPREV_PAGE`, `ZPOS_DIRTY`, in-free-list, in-writing | DRAM only |
| Word 34 of page 0 in file 0 (last file in use) | **Dropped.** Recovery finds the last file by reading the page-0 header of every file (lap, then restartGen). On PMEM that is a few memory reads per file. This also removes the file-change page-0 write from the write path. Fallback if recovery wants to keep it: declare that word mutable (excluded from the FD CRC, like `RF_INVALIDATED`) and update it with one 4-byte store |

**The "page GCI" fields.** Words 2 and 3 are snapshots of
`logPartNewestCompletedGCI` and `cnewestGci` when the page was started. They
are lower bounds valid at the page start. That is exactly what `srLogLimits`
uses: it walks mbyte headers and relies on `MAX_GCI_STARTED ≥
MAX_GCI_COMPLETED ≥ LAST_GCI` (`DblqhMain.cpp:38720-38727`) [V]. So they can
stay write-once. Two remarks for recovery [I]:
- The durable tail starts before `COMPLETED_GCI(R_gcp)` in the log.
  COMPLETED_GCI(g) is written at GCP_SAVEREQ(g), after GCI g+1 has started,
  so COMMITs of g+1 come earlier in the log. Phase 2 should use the
  `srLogLimits` start rule with `logStartGci = R_gcp + 1`. The existing fields
  are enough.
- A per-page upper bound ("max GCI written in this page") would have to be
  updated as the page fills, which is an in-place update. It is not proposed.

### 4.4 Restart generation

- `restartGen` is a 32-bit counter per log part. It is 1 at initial start. It
  is incremented every time a node start (SR or node restart) resumes writing
  to an existing REDO.
- After an increment, writing starts at a fresh mbyte, so all pages of an
  mbyte share one `(lap, restartGen)`.
- Recovery reads the largest value in the head mbyte's header and uses that
  plus one.
- Effect: records left after the old head, or after a hole, never validate
  once writing resumes. This holds even if recovery does not zero them.
  Phase-4 zeroing (`DblqhMain.cpp:39853`) [V] becomes optional on PMEM
  (recovery decides, §11 R2).

---

## 5. Record layouts

All records: `w0` = header (§3.1), `w1` = CRC (§3.3). Sizes in 32-bit words.

### 5.1 PREPARE (type 1), `8 + key + attrinfo`, rounded up to even

| Word | Field | Today (`writeLogHeader`, `DblqhMain.cpp:14221-14255`) [V] |
|---|---|---|
| 0 | `w0`: type 1, flags, len | type 1 |
| 1 | CRC | total length |
| 2 | hashValue | same |
| 3 | operation (incl. `ZINSERT_TTL`, replayed as ZINSERT, `43042-43044`) | same |
| 4 | aiLen | same |
| 5 | keyLen | same |
| 6 | rowid.m_page_no | same |
| 7 | rowid.m_page_idx | same |
| 8–9 | transid1, transid2, only with `PF_TRANSID` | — |
| next keyLen | key words (`writeKey`, `14262-14279`) | same |
| next aiLen | attrinfo words (`writeAttrinfoLab`, `14286-14308`) | same |
| last | 0, pad word if `keyLen + aiLen` is odd | — |

- The header stays 8 words: the length moves into `w0`, and `w1`, which held
  the length, now holds the CRC.
- Writer: compute the CRC while `writeKey` and `writeAttrinfoLab` copy the
  sections, then store `w1` last. Both copy through `writeLogWords`
  (`43746-43787`), which already handles page changes.
- `checkNewMbyte` (`14188-14190`) must add the pad word and, with
  `PF_TRANSID`, 2 words.
- `PF_TRANSID` is off in iteration 1 (plan §7: optional). The flag lets it be
  added later without a format change.

### 5.2 COMMIT (type 2), 12 words

| Word | Field | Today (`writeCommitLog`, `43566-43621`) [V] |
|---|---|---|
| 0 | `w0`: type 2, flags (`CF_DURABLE`, `RF_INVALIDATED`), len 12 | type 2 |
| 1 | CRC | tableId |
| 2 | tableId | schemaVersion |
| 3 | schemaVersion | fragId |
| 4 | fragId | prepare fileNo |
| 5 | prepare `fileNo << 16` \| `startPageIndex` | startPageNo |
| 6 | prepare `startPageNo << 16` \| `stopPageNo` | startPageIndex |
| 7 | gci_hi | stopPageNo |
| 8 | gci_lo (new) | gci_hi |
| 9 | transid1 (new) | — |
| 10 | transid2 (new) | — |
| 11 | opCount (new, plan §5.5) | — |

- Plan §7 counts 13 content words: today's 9 plus 4. The new header adds the
  CRC (14). Packing saves 2 (12). Packing is safe: all four prepare fields are
  `Uint16` in `TcConnectionrec` (`Dblqh.hpp:3259-3262`) [V]; page index <
  8192, page number < 32768 for a 1 GB file.
- Durable and non-durable COMMITs use the same 12 words. A log can hold both
  (online activation at GCI g, plan §2.2). `CF_DURABLE` lets phase 2 check
  `CF_DURABLE == (gci_hi ≥ g)`.
- `readCommitLog` (`42763-42810`) must read the real transid and gci_lo for
  phase 2. Replay through `execLogRecord` should keep the synthetic transid
  (`42804-42805`) [V], because many replayed operations share one
  TcConnectionrec in a part [I].
- Invalidation (today `39113-39133`: type word → 9, page marked dirty, page
  rewritten by `writeDirty` `43669ff`) [V] becomes: one 4-byte store of
  `w0 | 0x100`, then flush and fence. The CRC excludes that bit, so the record
  stays valid and is read as INVALID_COMMIT. Readers skip `len` words, as
  `39099-39103` does today with `ZCOMMIT_LOG_SIZE`.

### 5.3 COMPLETE (type 11), 4 words, new

| Word | Field |
|---|---|
| 0 | `w0`: type 11, flags 0, len 4 |
| 1 | CRC |
| 2 | transid1 |
| 3 | transid2 |

Plan §7 says "3 words, same shape as ABORT". It is 4 here because of the CRC.
One per operation (D7). Written by the new `writeCompleteLog`, then persisted
(invariant K).

### 5.4 ABORT (type 3), 4 words

| Word | Field | Today (`writeAbortLog`, `43542-43559`) [V] |
|---|---|---|
| 0 | `w0`: type 3, flag `AF_AFTER_COMMIT`, len 4 | type 3 |
| 1 | CRC | transid1 |
| 2 | transid1 | transid2 |
| 3 | transid2 | — |

- Today ABORT is written when a prepared operation aborts
  (`17095-17125`, queued variant `896-904`) [V]. That ABORT needs no
  persistence: no COMMIT exists for the operation.
- Rule F writes an ABORT after the operation's COMMIT, sets
  `AF_AFTER_COMMIT`, and persists it before the lock is released.
- Why the flag: with `IgnoreError`, one operation of T can abort in the
  prepare phase (normal ABORT carrying T's transid) while other operations of
  T commit. Without the flag, phase 2 step B would send "T aborted" for that
  record and veto the fallback (plan §5.2, §5.5). The flag makes steps A and B
  act only on rule-F aborts [I].
- The plan's "operation identity" is not included. Phase 2 needs only the
  transid. Open question 3 discusses adding the COMMIT record's position.

### 5.5 COMPLETED_GCI (type 8), 4 words

`[w0: type 8, len 4 | CRC | gci | 0]`. Today `[8, gci]`
(`writeCompletedGciLog`, `43631-43662`; initial `COMPLETED_GCI(1)` in file 0
page 1, `35408-35413`) [V]. Word 3 is a pad for 8-byte alignment.

### 5.6 NEXT_MBYTE (type 7), 2 words

`[w0: type 7, len 2 | CRC]`. The rest of the mbyte after it is dead space.
Today it is 1 word stored at the fill index without advancing it
(`43824-43826`), with 2 words reserved by `ZNEXT_LOG_SIZE` (`Dblqh.hpp:245`,
comment at `233-240`) [V]. The new record uses exactly that reserve.

### 5.7 FILLER (type 10), 2 + n words, new

| Word | Field |
|---|---|
| 0 | `w0`: type 10, flags 0, len = distance to the next W boundary (or to the page end on the FD page) |
| 1 | CRC over `w0 ‖ S` only |
| 2 … len-1 | dead, not stored by the writer, never read |

- Gaps are even (P4), so a 1-word gap cannot occur and no 1-word form is
  needed.
- A FILLER never crosses a page: page ends are W boundaries (W divides 32768).
- Placement rules are in §7.

### 5.8 FD (type 4), at word 32 of page 0

| Word | Field | Today (`writeFileHeaderOpen`, `36082-36129`) [V] |
|---|---|---|
| 0 | `w0`: type 4, len = 4 + 3·nFD·clogFileSize (+1 pad if odd) | type 4 |
| 1 | CRC | nFD |
| 2 | nFD | fileNo (in file 0, rewritten as "last file", §4.3) |
| 3 | own fileNo, never rewritten | first array word |
| 4 … | nFD × (`maxGciCompleted[mb]`, `maxGciStarted[mb]`, `lastPrepRef[mb]`) for mb = 0 … clogFileSize-1 | same arrays, from word 3 |
| then | FILLER to the end of page 0 | NEXT_LOG_RECORD (type 6), 1 word, at `36128` |

- With 1 GB files, `cmaxLogFilesInPageZero = (8192-32-128)/(3·1024) = 2`
  (`DblqhMain.cpp:2833-2848`) [V], so len = 6148 words: fits 16 bits.
- PMEM constants: `ZPOS_NO_FD = 2`, `ZPOS_FILE_NO = 3`, `ZFD_HEADER_SIZE = 4`.
  The position check (`39221-39229`) and `initGciInLogFileRec` (`42290`) must
  use them.
- As today, the entries for the file itself are stale when the FD is written;
  recovery reads them from the mbyte headers (`42283-42287`) [V].

### 5.9 SR_HEAD (type 12), 6 words, placeholder

`[w0: type 12, len 6 | CRC | R_gcp | G' | restartGen | 0]`. Plan §5.3. The
recovery subtask owns its content; the format reserves the type and the
framing.

### 5.10 Writers and readers to change

| Function | `DblqhMain.cpp` | Change |
|---|---|---|
| `writeLogHeader` fast path | `14234-14244` | Store `w0`; leave `w1` for the end |
| `writeKey`, `writeAttrinfoLab` | `14262-14308` | CRC update per copied chunk; pad; finalize with `S`; store `w1` |
| `checkNewMbyte` | `14188-14214` | Pad and optional transid in the size |
| `writeCommitLog` | `43566-43621` | 12 words; then (durable) close the unit and persist; two-step reservation (§7.3) |
| `writeAbortLog` | `43542-43559` | 4 words; with rule F, flag, close and persist |
| `writeCompletedGciLog` | `43631-43662` | 4 words |
| `writeNextLog` | `43801-44003` | 2-word NEXT_MBYTE with CRC; barrier before the next mbyte's header |
| `writeFileHeaderOpen` | `36073-36161` | FD with CRC; FILLER to page end |
| `initLogpage` | `35577-35605` | New fields; header CRC; complete at once |
| `writeDbgInfoPageHeader`, `calcPageCheckSum` | `46632-46639`, `46750-46762` | Not used on PMEM |
| `firstPageWriteLab`, `lastWriteInFileLab` | `35190-35199`, `35297-35307` | No page-0 rewrite on PMEM |
| `initWriteEndLab`, `initFirstPageLab`, `execFSWRITEREQ` | `35371-35418`, `35763-35779` | Initial format in the new framing |
| `execSr` switch | `39086-39363` | Dispatch on `w0 & 0xFF`; PREPARE length from `w0` (today `w1`, `39089-39094`); INVALIDATED flag instead of type 9; ABORT 4; COMPLETED_GCI 4; FD offsets; new COMPLETE, FILLER, SR_HEAD; default case = end-of-log check, not always a crash |
| `readCommitLog` | `42763-42810` | 12-word layout; unpack; real transid, gci_lo, opCount |
| `readLogHeader` | `43000-43047` | Offsets 2–7 unchanged; `PF_TRANSID` moves the key start |
| `readSrFrontpageLab`, `readSrLastMbyteLab` | `36289-36322`, `36367-36461` | Header validity; last file from page-0 headers |

---

## 6. Records that span pages

### 6.1 Options

| Option | CRC | For | Against |
|---|---|---|---|
| **A. Logical CRC, keep every page header** | One CRC per record over its logical words; interleaved headers skipped and checked on their own | Addressing, readers' header skipping (`43054-43103`, `43514-43535`), mbyte headers and COMMIT back-references all stay. CRC32C is streaming, so pieces cost nothing extra | A reader must check every header the record crosses |
| B. Fragments, one CRC each | Each piece in a page gets its own header and CRC | Pages are self-contained | Changes the meaning of `len` and of the back-reference; 8 B per piece; reassembly in SR; more types |
| C. No page headers inside an mbyte | Contiguous CRC | Simplest record CRC; saves 0.4 % | Writer (`writeLogWord(s)`, `43721-43787`) and SR reader (`readLogword`, `stepAhead`, `readExecLog`, the page cache) assume a header on every page. The old format stays in use on non-PMEM nodes, so there would be two reader paths |

### 6.2 Recommendation: option A

- `len` and the CRC input are logical, as today's PREPARE length
  (`stepAhead(logWord - 2)` at `39091-39092` skips headers) [V].
- **A record is valid only if every page header it crosses is valid and has
  the same `(lap, restartGen)`** (§3.4 rule 5). The record CRC does not cover
  those headers. Without this rule a valid record could hide a torn header.
- The header of a new page is stored when the writer moves onto the page
  (`writeLogWords` calls `initLogpage`, `43765-43770`) [V], before the rest of
  the record. Both are persisted by the same barrier.
- Recovery keeps the mbyte headers for head and tail finding, as the
  architect asked.

### 6.3 How many pages a PREPARE spans

Max PREPARE = 23130 words (§1). A page holds 8160 record words. A PREPARE that
starts in the last words of a page can touch 4 pages [V for the limits]. The
comment at `DblqhMain.cpp:39059-39066` and `ZMIN_READ_BUFFER_SIZE = 3`
(`Dblqh.hpp:185`) assume 3, based on an older 30000-byte row limit. Whether
TUP ever logs such a record is [I]. This matters today for SR reading from
disk; it stops mattering if SR reads straight from the mapping. Noted for
`pmem_redo_recovery.md`.

---

## 7. FILLER, write units and space reservation

### 7.1 Closing a unit

At every persist barrier the writer closes the current write unit:

1. Let `g` = words from the current position to the next W boundary.
2. If `g = 0`: nothing to write.
3. Else, if that boundary is the end of the mbyte: write NEXT_MBYTE and switch
   mbyte (`changeMbyte`, `40863-40868`). NEXT_MBYTE fills the last unit.
4. Else: write FILLER with `len = g`.

Then the barrier. The next record starts on a fresh unit, so no persisted unit
is written twice (P1).

- Step 3 always fits. A record is placed only if `size + 2 ≤ remaining`
  (today's check with `ZNEXT_LOG_SIZE = 2`). The mbyte end is a W boundary, so
  after any record the space left in the mbyte is either inside the last unit
  (then ≥ 2 words remain) or at least a full unit.
- The effect is an mbyte switch slightly early, wasting less than W per mbyte.
- `remainingWordsInMbyte` is decremented by the filler length.
  `m_total_written_words` (`14232`, `43552`, `43592`, `43660`) [V] stays
  logical. A new counter should count filler words, for ndbinfo.

### 7.2 Which records persist

| Record | Persisted | Closes a unit |
|---|---|---|
| PREPARE | With the next barrier in its part | No |
| COMMIT, durable | Immediately (C) | Yes |
| COMMIT, non-durable | At GCP save | Only at GCP save |
| COMPLETE | Immediately (K) | Yes |
| ABORT, rule F | Immediately | Yes |
| ABORT, normal | No | No |
| COMPLETED_GCI | At GCP save | Yes |
| NEXT_MBYTE | At the mbyte switch | It is the closer |

### 7.3 Space reservation per operation

Today `increment_committed_mbytes` adds `ZCOMMIT_LOG_SIZE + 1 = 10` words per
logged prepare and `writeCommitLog` or `writeAbortLog` subtracts them
(`47888-47909`, `13477`, `43558`, `43620`) [V]. The reservation feeds the
tail-problem limit `free_mb ≤ 4 + committed_mb` (`43975-43979`) [V].

New reservation, with `F = W/4 - 2` (largest filler in words):

```
R = (12 + F) + (4 + F) + 2      COMMIT + filler, COMPLETE or rule-F ABORT + filler, NEXT_MBYTE slack
```

| W | F | R (words) | Today |
|---|---|---|---|
| 64 B | 14 | 46 | 10 |
| 128 B | 30 | 78 | 10 |
| 256 B | 62 | 142 | 10 |
| non-durable (no filler at COMMIT) | 0 | 14 | 10 |

Release in two steps: `12 + F` at `writeCommitLog`, the rest at
`writeCompleteLog` or the rule-F `writeAbortLog`. A normal ABORT releases
all of R. COMPLETE and rule-F ABORT are never both written for one operation
(plan §3.1, F) [I].

Example: 1 million operations in flight at W = 256 reserve about 540 MB per
part. With the default 16 GB per part this only moves the tail-problem limit.

---

## 8. Space overhead

### 8.1 Record sizes

| Record | Today | PMEM |
|---|---|---|
| PREPARE header | 32 B | 32 B (+8 with `PF_TRANSID`) |
| PREPARE, 2 key + 10 AI words | 80 B | 80 B |
| PREPARE, 2 key + 100 AI words | 440 B | 440 B |
| COMMIT | 36 B | 48 B |
| COMPLETE | — | 16 B |
| ABORT | 12 B | 16 B |
| COMPLETED_GCI | 8 B | 16 B |
| Page header | 128 B per 32 KB (0.39 %) | same |

### 8.2 Bytes per write operation, per replica

Model: durable mode, iteration 1. The COMMIT barrier closes the unit holding
PREPARE + COMMIT; the COMPLETE barrier closes a unit holding the COMPLETE.
Formula: `⌈(P + C)/W⌉·W + ⌈K/W⌉·W`, with P, C, K the PREPARE, COMMIT and
COMPLETE bytes. Page headers add 0.4 % everywhere and are left out.

| Operation | Today | PMEM, no close | W = 64 | W = 128 | W = 256 |
|---|---|---|---|---|---|
| Small update (2 key, 10 AI) | 116 B | 144 B (1.24×) | 192 B (1.66×) | 256 B (2.21×) | 512 B (4.41×) |
| Large update (2 key, 100 AI) | 476 B | 504 B (1.06×) | 576 B (1.21×) | 640 B (1.34×) | 768 B (1.61×) |
| Small dirty write (PREPARE + COMMIT + COMPLETE, one barrier) | 116 B | 144 B | 192 B | 256 B | 256 B |

- "No close" means appending without fillers and flushing a partly written
  line again. It is shown as the lower bound; whether it is acceptable is a
  hardware question (§11, H2).
- Barriers per operation: 0 today (only per GCP), 2 in durable mode.
- **Concurrency changes little [I].** Records of many operations interleave,
  but every COMMIT and COMPLETE still closes a unit. A segment between two
  barriers averages about 72 B for the small update. At W ≥ 128 almost every
  segment takes one unit, so about 2W per operation, as in the table. At
  W = 64 it averages about 3 units (≈ 200 B).
- Batching helps a lot: COMPLETEs of a packed COMPLETE signal, or the several
  COMMITs TUP writes for one row (`DbtupCommit.cpp:247-276`), could share one
  barrier (§12, point 5).
- With W > 64, filler bodies are space, not necessarily media writes: the
  writer flushes only lines it stored into. Whether it should store whole
  units (to avoid read-modify-write in the device) is a write-path question.
- Non-durable memory-mapped mode: only the larger COMMIT (+12 B) and rare
  fillers at GCP saves and mbyte switches.

### 8.3 Does the REDO size need a new default?

The default is `NoOfFragmentLogFiles` = 16 × `FragmentLogFileSize` = 1G per
log part (`ConfigInfo.cpp:1140-1148`) [V], with 4 parts by default, so 64 GB
per node.

- The REDO must hold all writes between LCP-driven tail cuts. At the same
  write rate, the new format fills it 1.2–1.7× faster at W = 64 and up to
  4.4× faster at W = 256 for small writes.
- **Recommendation: no new default.** 64 GB of PMEM per node is already large.
  Instead:
  - document the multiplier and the sizing rule (write rate × bytes per
    operation × time for two LCPs);
  - default W to 64 unless the hardware study shows a large penalty;
  - report filler bytes in ndbinfo, so users see the real factor;
  - MTR and autotest on `memmap=` emulated PMEM must set small explicit sizes,
    since that memory is RAM.

---

## 9. Checksum implementation

`grep -rn -i crc32c` over `include/`, `mysys/`, `storage/ndb/` and the rest of
the tree [V]:

| Found | Usable in ndbd? |
|---|---|
| `storage/innobase/ut/crc32.cc`: CRC-32C with SSE4.2 `_mm_crc32_u64` (`:440`) and ARMv8 `__crc32cd` (`:467`), runtime selection (`ut0crc32.h:149-165`) | Not linked into NDB; portable code in the same tree and licence |
| `extra/abseil/.../absl/crc/crc32c.h` | Built only with bundled protobuf (`CMakeLists.txt:2154-2161`) |
| `storage/ndb/src/common/util/ndbxfrm_file.cpp:1339`: `crc32()` | zlib CRC-32, a different polynomial |
| `storage/ndb/include/util/Checksum.hpp` | XOR checksums only |
| `storage/ndb/include/util/ndb_xxhash.h` (lists CRC32C only in a benchmark table, `:76`) | xxHash, not CRC |

NDB has no CRC32C helper. Proposal:
- Add `include/util/ndb_crc32c.h` and `src/common/util/ndb_crc32c.cpp`:
  `Uint32 ndb_crc32c_update(Uint32 crc, const void *buf, size_t len)` plus
  init and finalize helpers. Use SSE4.2 on x86-64 and the ARMv8 CRC extension
  on aarch64 (this includes the macOS development machines), with a
  slice-by-8 table fallback. Port it from InnoDB's `crc32.cc`. Select the
  implementation at run time, in the way `rondb_hash.cpp:41` does for AVX2
  [V].
- Unit test against the standard vector: CRC-32C("123456789") = `0xE3069283`.
- Cost [I]: one 8-byte instruction per 8 bytes, about 3 cycles latency each.
  A COMMIT plus suffix (64 B) is about 10 ns; a 440 B PREPARE about 50 ns on
  one stream, less if interleaved. A fused copy-and-CRC loop hides most of it.

---

## 10. redoLogReader

Today the reader walks 1 MB at a time, ends each page at `m_current_page_index`
(`records.cpp:255`), detects unused pages by version 0 and index 0
(`reader.cpp:262`), and checks the XOR page checksum unless it is 37
(`reader.cpp:313-330`) [V]. It handles a record crossing one page by moving
the tail before the next page's data (`reader.cpp:345-350`), which is not
enough for a 4-page PREPARE [V/I].

Changes:
1. **Detect the format** from the magic in the page-0 header. Keep the old
   path unchanged.
2. **Headers:** check the CRC, magic and identity; print lap, restartGen, W,
   log part and node id; `--lap` also prints restartGen. Ignore words 4, 5, 8
   and 11.
3. **Records:** parse `w0`. Gather the record's logical words into a scratch
   buffer, skipping page headers (any span). Check the bounds and the CRC with
   `S` taken from the header of the start page. Stop the page walk at the
   first invalid record and print it as "end of valid log", with the reason.
4. **Types:** 12-word COMMIT with unpacked prepare reference, transid, gci_lo,
   opCount and the INVALIDATED flag; COMPLETE; ABORT with
   `AF_AFTER_COMMIT`; COMPLETED_GCI; NEXT_MBYTE; FILLER (print only with
   `--dump`); FD with the new offsets; SR_HEAD.
5. **New options:** `--transid=T1,T2` to print only one transaction's records;
   `--in-doubt` to list transids with a COMMIT and no COMPLETE or rule-F ABORT
   after a given position. This helps debug SR phase 2.
6. **I/O:** a DAX file is an ordinary file, so `pread` works. The PMEM format
   is not encrypted (§12, point 6), so the reader skips `ndbxfrm`
   (`reader.cpp:209-223`) for it.

---

## 11. Assumptions and requirements for the other subtasks

### 11.1 Hardware (`research_pmem_hardware.md`)

| # | Assumption | Used by |
|---|---|---|
| H1 | Aligned 4- and 8-byte stores are power-fail atomic | `RF_INVALIDATED` store |
| H2 | Writing back a cache line never changes bytes that were not stored to; flushing a line again leaves its persisted bytes intact | SR invalidation; the "no close" policy |
| H3 | Within one barrier, ADR may persist lines in any order; eADR persists in program order | Valid-prefix rule (P5) |
| H4 | W only affects speed; no W unit is written atomically | P6 |

If H2 does not hold, in-place invalidation needs another design, for example
an INVALIDATE record appended at the head that names the COMMIT's position.

### 11.2 Write path (`pmem_redo_write_path.md`)

| # | Requirement |
|---|---|
| W1 | Store all 32 header words, CRC included, once at page init; never again. Fill index, links, dirty and debug state live in DRAM |
| W2 | Every word of a record, `w1` included, is stored before the barrier that persists it; `w1` may be stored last |
| W3 | Close the unit before every barrier (§7.1) |
| W4 | At an mbyte switch: store NEXT_MBYTE, barrier, then store the next mbyte's first header. Then a valid current-lap mbyte header means the mbyte before it is complete, and holes stay in the last mbyte |
| W5 | Count fillers in free space; reserve R per operation (§7.3) |
| W6 | After a restart that resumes writing: increment restartGen and start at a fresh mbyte (§4.4) |
| W7 | No rewrite of page 0 of file 0 |
| W8 | The CRC of a record body may be computed before taking the log-part lock; only `S` is added under the lock |
| W9 | Files fully allocated and formatted at initial start (mbyte headers with valid CRC), no sparse holes |
| W10 | Invalidation: one 4-byte store of `w0 \| 0x100`, then flush and fence |

### 11.3 Recovery (`pmem_redo_recovery.md`)

| # | Requirement |
|---|---|
| R1 | Check headers (§4.2). Treat an invalid header as "not written in this lap" |
| R2 | Find the last file from the page-0 headers. Find the last mbyte by the lap drop if phase-4 zeroing is kept, or by the `(lap, restartGen)` drop if it is not |
| R3 | Validate records by §3.4. The log ends at the first invalid record of the last mbyte. Never skip an invalid record. An invalid record before the last mbyte is corruption |
| R4 | A record that crosses a page is valid only if every crossed header is valid with the same `(lap, restartGen)` |
| R5 | Do not store into the mapping except for the INVALIDATED flag and SR's own new records. Today's readers store their cursor into the page (`43057-43061`) [V], so they must work on DRAM copies or keep cursors in DRAM |
| R6 | When following a COMMIT's back-reference, validate the PREPARE there, with `S` from the PREPARE's own page (it may be in an earlier lap or file) |
| R7 | Keep the synthetic transid for replay; use the real transid for phase 2 |
| R8 | New restartGen = largest found + 1 |
| R9 | A PREPARE can span 4 pages (§6.3) |

### 11.4 Differences with the parallel drafts

Read after this document was written. To settle when the drafts are merged.

| Topic | This format | Other draft | Proposed resolution |
|---|---|---|---|
| Atomicity, W | H1–H4; W = 64 suggested | `research_pmem_hardware.md`: only aligned 8-byte stores are failure-atomic; W = 64, fixed, recorded in the file | Agree. An aligned 4-byte store lies inside one 8-byte chunk, so H1 holds. Keep W in the page header so the reader validates FILLERs |
| Last-file word in page 0 of file 0 | Dropped; recovery scans page-0 headers | Recovery: two checksummed slots with sequence numbers in a control area. Write path: one aligned store of word 34 | Three answers; pick one. Any of them is torn-safe. Dropping it is the smallest change to the write path |
| INVALID_COMMIT | Flag bit, excluded from the CRC | Recovery: store type 9 in the type byte, CRC computed as if the type were COMMIT | Equivalent. The flag needs no special case in the CRC routine |
| Orphans after a restart | `restartGen` in the CRC suffix (no space cost), with a fresh mbyte after each restart | Recovery: zero `[H, end of last mbyte)` and keep writing in the head page; a generation is rejected as "a word per record" | Zeroing alone is sound. `restartGen` costs no word here, since it comes from the page header. It only helps if writing restarts at a fresh mbyte; otherwise keep it constant |
| Header image | Words 4, 5, 8, 11, 12–14, 17–20 are 0 on PMEM; CRC over the final words | Write path: records built in DRAM pages, new bytes copied to PMEM | The copy of a page's first 128 bytes must be the PMEM header image (§4.1), not the DRAM header with its fill index and links |
| Filler worst case | `W/4 − 2` words (gaps are even) | Write path: `W − 4` bytes; 14-word COMMIT | Use 12 words and `W/4 − 2`: R = 46 words at W = 64 (write path: 48) |

---

## 12. Review of the architect's guidance

1. **"No checksums on whole pages."** Agreed. The design keeps the page
   geometry but checksums only the header.
2. **"A checksum on each record, including page headers."** Agreed, but a
   checksum alone is not enough. With W-aligned fillers, record starts recur
   at the same offsets in every lap, so a stale record with a valid CRC is
   likely to sit right after the end of the log. Restarts that move the head
   back create the same risk within one lap. The CRC must be bound to lap,
   restart generation and position (§3.3). FILLERs must be checked too,
   otherwise a stale filler can carry the reader over a hole.
3. **"Keep the MByte headers; consider the page GCI."** Agreed. The page GCI
   fields are lower-bound snapshots and can stay write-once (§4.3). The real
   in-place updates are the fill index and the last-file word in page 0 of
   file 0, and both can go.
4. **"Minimum write size W, filler records."** Risky in two ways.
   - W gives no atomicity. A torn unit is possible at any W; only the CRCs
     protect. Nothing should be built on "a unit is all or nothing".
   - A filler at every barrier is expensive for small writes: 4.4× the REDO
     volume and 2 × 256 B of PMEM writes per small update at W = 256. W = 64
     costs 1.66×. Choose W from measurements, start with 64, and keep the
     "no close" policy open if H2 holds and flushing a line again is cheap.
5. **"Persist COMMIT and COMPLETE immediately in iteration 1."** Agreed. But
   invariants C and K only need persistence before the reply signal leaves.
   One barrier at the end of the signal that wrote several COMMIT or COMPLETE
   records (TUP's loop over the operations on one row, a packed COMPLETE)
   gives the same guarantees with fewer fillers, and is still synchronous.
   This is a safe refinement for iteration 1.
6. **Not in the guidance: encryption.** REDO encryption uses XTS with a 32 KB
   data unit (`DblqhMain.cpp:35634-35637`, `research_redo_log.md` §4) [V]. It
   cannot work with in-place, line-granular persistence. Iteration 1 should
   refuse memory-mapped REDO with `EncryptedFileSystem=1`. Encryption per
   closed W unit is possible later, but open units would have to be staged in
   DRAM so that no plaintext reaches the media.

---

## Open questions

1. **W and the close policy.** Is flushing a partly written line again costly
   on the target hardware, and does a 256 B unit avoid device read-modify-
   write? This decides between W = 64, W = 256 and "no close"
   (`research_pmem_hardware.md`).
2. **Phase-4 zeroing on PMEM.** Keep it (lap-only ordering), or rely on
   restartGen and the `(lap, restartGen)` drop (§4.4)? Recovery decides.
3. **Rule-F ABORT content.** Add the COMMIT record's position (+2 words) so
   that step C can invalidate it without keeping the queue, and so that
   `redoLogReader` can pair them?
4. **GCI in COMPLETE.** Adding gci_hi (4 → 6 words with pad) would let phase 2
   check that a COMPLETE in the tail has a GCI ≥ g. Free at W ≥ 64 when
   persisted alone, a cost when batched. Not proposed for now.
5. **Transid in PREPARE** (`PF_TRANSID`). It would let recovery check that a
   back-reference points to the right transaction. Off in iteration 1; turn
   on in debug builds?
6. **A COMMIT after a rule-F ABORT of the same T in one part.** The format
   treats it as a protocol violation. P3 must confirm that takeover can never
   produce it.
7. **16-bit length.** Enough for 23130-word PREPAREs and 8160-word FDs. A
   future row-size increase beyond about 65000 words would need a wider field.
8. **The last-file word.** Drop it (recommended) or keep it as a mutable word
   (§4.3)?

## Recommendations

1. Keep today's geometry and page headers. Make the header write-once with its
   own CRC, identity fields, a format magic, W and restartGen (§4).
2. Frame every record with `w0` = type/flags/len and `w1` = CRC32C over the
   logical words plus the unstored suffix `(lap, restartGen, part/file,
   position)` (§3).
3. Align records to 8 bytes with even lengths, so every FILLER has a CRC and
   every interpreted word is checked.
4. Use option A for spanning records, with the rule that every crossed page
   header must be valid (§6).
5. Close the current unit at every barrier with a FILLER, or with NEXT_MBYTE
   in the last unit of an mbyte; reserve `R = 18 + 2F` words per operation and
   release it in two steps (§7).
6. COMMIT = 12 words, COMPLETE = 4, ABORT = 4 with `AF_AFTER_COMMIT`,
   COMPLETED_GCI = 4, NEXT_MBYTE = 2; INVALID_COMMIT becomes a flag set by one
   4-byte store (§5).
7. Drop the rewrite of page 0 of file 0 on PMEM.
8. Start with W = 64; allow one barrier per signal rather than per record;
   keep the REDO default size and document the multiplier (§8).
9. Add an `ndb_crc32c` helper ported from InnoDB, with a hardware path on
   x86-64 and aarch64 (§9).
10. Teach `redoLogReader` the new format, with CRC checks, gathering of
    spanning records and transaction filters (§10).
11. Refuse memory-mapped REDO together with REDO encryption in iteration 1.
