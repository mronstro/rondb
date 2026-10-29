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
#ifndef NDB_PMEM_H
#define NDB_PMEM_H

#include <stddef.h>
#include <ndb_types.h>

/**
 * Persistent memory for the REDO log (pmem_redo_design.md E7, E18).
 *
 * Every write to persistent memory goes through these calls, so that the
 * power-loss emulation of the tests sees all of them:
 *   - records: ndb_pmem_copy_nt(), then ndb_pmem_drain();
 *   - in-place stores: ndb_pmem_store32/64(), ndb_pmem_flush(), then
 *     ndb_pmem_drain();
 *   - zeroing: ndb_pmem_zero(), then ndb_pmem_drain().
 * A write is persistent when the drain of the thread that made it returns.
 *
 * x86-64 copies with non-temporal stores or MOVDIR64B, or with stores and
 * a write-back per line (CLWB, else CLFLUSHOPT, else CLFLUSH); the drain
 * is SFENCE. aarch64 copies with stores and DC CVAP per line (DC CVAC
 * without FEAT_DPB); the drain is DSB SY. Other platforms use memcpy and a
 * fence, and only need to build.
 */

static constexpr size_t NDB_PMEM_LINE = 64;

enum ndb_pmem_copy_method {
  NDB_PMEM_COPY_AUTO = 0,      // MOVDIR64B if present, else NT stores
  NDB_PMEM_COPY_NTSTORE = 1,   // x86-64 non-temporal stores
  NDB_PMEM_COPY_MOVDIR64B = 2, // x86-64 MOVDIR64B
  NDB_PMEM_COPY_CLWB = 3       // stores and a write-back per line
};

enum : unsigned {
  NDB_PMEM_MAP_SYNC_REQUIRED = 0, // fail with EOPNOTSUPP without MAP_SYNC
  NDB_PMEM_MAP_SYNC_OPTIONAL = 1  // else map with MAP_SHARED
};

struct ndb_pmem_mapping {
  void *addr;
  size_t len;
  bool map_sync;
};

/**
 * Choose the copy method. 0, or ENOTSUP if this CPU lacks it, and the
 * method stays as it was. Call it before any copy; the first copy
 * chooses NDB_PMEM_COPY_AUTO otherwise. Calling it again with the same
 * method does nothing.
 */
int ndb_pmem_init(ndb_pmem_copy_method method);

/**
 * The copy method in use, for logs and tests: "movdir64b",
 * "ntstore-avx", "ntstore-sse2", "store+clwb", "store+clflushopt",
 * "store+clflush", "store+dc-cvap", "store+dc-cvac" or "memcpy".
 */
const char *ndb_pmem_method_name();

/**
 * Map len bytes of fd from offset 0, read and write, at an address
 * aligned to 2 MB so that large pages can be used. 0 or an errno:
 * EOPNOTSUPP means MAP_SYNC is not possible (no DAX, old kernel, not
 * Linux); with NDB_PMEM_MAP_SYNC_OPTIONAL the file is then mapped with
 * MAP_SHARED and out->map_sync is false.
 */
int ndb_pmem_map(int fd, size_t len, unsigned flags, ndb_pmem_mapping *out);
int ndb_pmem_unmap(ndb_pmem_mapping *m);

/**
 * Fault every page of a mapping in, writable, without changing it, so
 * that the first write of a record does not take a page fault. Call it
 * before any other thread writes the mapping. 0 or an errno.
 */
int ndb_pmem_prefault(void *addr, size_t len);

/**
 * Lock the pages of a mapping in memory, so that the kernel cannot evict
 * them. It matters on a page-cache file, as in the DRAM test modes; Linux
 * ignores it on DAX, which has no page cache. Locking faults pages in for
 * reading only, so prefault first. 0 or an errno, e.g. ENOMEM or EPERM
 * when RLIMIT_MEMLOCK is too low.
 */
int ndb_pmem_lock(void *addr, size_t len);

/**
 * Copy whole lines: dst is aligned to NDB_PMEM_LINE and len is a
 * multiple of it. The copy includes the write-back of the lines.
 */
void ndb_pmem_copy_nt(void *dst, const void *src, size_t len);

/* Aligned single stores in place (E9, E10); then ndb_pmem_flush() */
void ndb_pmem_store32(Uint32 *dst, Uint32 v);
void ndb_pmem_store64(Uint64 *dst, Uint64 v);

/* Zero any range (E12); the write-back is included */
void ndb_pmem_zero(void *dst, size_t len);

/* Write back every line that holds a byte of [addr, addr + len) */
void ndb_pmem_flush(const void *addr, size_t len);

/* Wait until the copies, zeroing and flushes of this thread are done */
void ndb_pmem_drain();

#endif
