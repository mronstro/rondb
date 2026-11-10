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
 * Whether this CPU can write a cache line back to persistent memory:
 * x86-64 always, aarch64 with DC CVAP (FEAT_DPB) but not with DC CVAC
 * alone, other platforms never. Copies still work without it, but they
 * do not persist.
 */
bool ndb_pmem_cpu_persists();

/**
 * Map len bytes of fd from offset 0, read and write, at an address
 * aligned to 2 MB so that large pages can be used. 0 or an errno:
 * EOPNOTSUPP means MAP_SYNC is not possible (no DAX, old kernel, not
 * Linux); with NDB_PMEM_MAP_SYNC_OPTIONAL the file is then mapped with
 * MAP_SHARED and out->map_sync is false. Threads may map at the same
 * time.
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

/**
 * Power-loss emulation for tests (platform plan S1.5, recovery plan S7.3).
 * Every write above keeps the 64-byte pre-image of each line it touches,
 * once until the line is persistent, in a list of the writing thread, and
 * then writes the mapping, so that every thread sees the new bytes. Lines
 * of a copy or a zeroing are written back; a store's line is written back
 * by ndb_pmem_flush(). ndb_pmem_drain() makes this thread's written-back
 * lines persistent; a line stored but not flushed stays pending, as on
 * the hardware. A power loss then keeps, restores or tears each pending
 * line. A full list makes its oldest line persistent early, which the
 * hardware also may do. Any file works, DAX or not.
 */
struct ndb_pmem_emul_stats {
  Uint64 written;        // lines that became pending
  Uint64 persisted;      // pending lines that a drain made persistent
  Uint64 evicted_early;  // made persistent early: the list was full
  Uint64 kept;           // a power loss kept the new line
  Uint64 reverted;       // a power loss restored the old line
  Uint64 torn;           // a power loss restored some of its 8-byte words
  Uint64 shared;         // became pending while pending in another thread
  Uint32 threads;        // threads that wrote with the emulation on
  Uint32 not_parked;     // threads that the last freeze could not stop
};

/**
 * Turn the emulation on, before the first write to a mapping, with at
 * most max_pending pending lines per thread. 0, EINVAL for 0, or EBUSY if
 * it is on with another limit.
 */
int ndb_pmem_emul_enable(Uint32 max_pending);
bool ndb_pmem_emul_active();

/* The pending lines of this thread */
Uint32 ndb_pmem_emul_pending();

/* Whether any thread has a pending line in [addr, addr + len) */
bool ndb_pmem_emul_range_pending(const void *addr, size_t len);

/**
 * Stop every write: a write that starts later waits forever, and the call
 * returns when no thread is inside one, or after 1 s. A thread that
 * crashed inside a write is not waited for. The threads that did not stop.
 */
Uint32 ndb_pmem_emul_freeze();

/**
 * The power loss: freeze, then keep each pending line of every stopped
 * thread with probability keep_permille / 1000, tear it (restore a random
 * subset of its 8-byte words) with probability tear_permille / 1000, else
 * restore it. The caller then exits. seed 0 takes the time.
 */
void ndb_pmem_emul_power_fail(Uint64 seed, Uint32 keep_permille,
                              Uint32 tear_permille);

/**
 * The power loss of a crash, once per process: the values of
 * ndb_pmem_emul_set_crash(), by default the time as seed and every
 * pending line restored. Another thread that crashes meanwhile waits
 * until it is done.
 */
void ndb_pmem_emul_on_crash();
void ndb_pmem_emul_set_crash(Uint64 seed, Uint32 keep_permille,
                             Uint32 tear_permille);

void ndb_pmem_emul_get_stats(ndb_pmem_emul_stats *out);

/* Tests: no line pending, no thread stopped, counts at 0; still on */
void ndb_pmem_emul_reset();

/**
 * Platform queries for the start-up checks (E17, E20), from sysfs on
 * Linux (ndb_pmem_region.cpp). Elsewhere every answer is "unknown".
 */
enum ndb_pmem_domain {
  NDB_PMEM_DOMAIN_UNKNOWN = 0,   // no persistent memory region found
  NDB_PMEM_DOMAIN_NONE = 1,      // a region without a domain, e.g. memmap=
  NDB_PMEM_DOMAIN_MEMCTRL = 2,   // ADR: persistent at the memory controller
  NDB_PMEM_DOMAIN_CPU_CACHE = 3  // eADR: the CPU caches are persistent too
};

struct ndb_pmem_region_info {
  ndb_pmem_domain domain; // the weakest of all regions behind the file
  int numa_node;          // closest CPU node of the regions; -1: not one
  int target_node;        // memory node of the regions; -1: not one
  Uint64 dirty_shutdown;  // summed over DIMMs or memory devices; ~0: none
  Uint32 badblock_ranges; // bad-block ranges on the devices
  bool stacked;           // device mapper or md: several devices below
  bool dax_inode;         // the file is DAX (statx STATX_ATTR_DAX)
  char device[32];        // block device of the file system, e.g. "pmem0"
  char region[256];       // sysfs path of the first region, for messages
};

/**
 * What lies behind the file system of fd. 0, or the errno of fstat. A
 * file that is not on a persistent memory region gives 0 and
 * NDB_PMEM_DOMAIN_UNKNOWN.
 */
int ndb_pmem_get_region_info(int fd, ndb_pmem_region_info *info);
int ndb_pmem_persistence_domain(int fd, ndb_pmem_domain *domain);

/**
 * The NUMA node of the region; else of the page at addr, a mapped
 * address or nullptr; -1 if not known.
 */
int ndb_pmem_numa_node(int fd, const void *addr);

/* The summed dirty-shutdown count; ENOTSUP if the devices have none */
int ndb_pmem_dirty_shutdown(int fd, Uint64 *count);

/**
 * The number of bad-block ranges under bytes [off, off + len) of the
 * file. *exact is false when the file's extents cannot be known (no
 * FIEMAP, several devices below, no device found); every range on the
 * devices then counts.
 */
int ndb_pmem_badblocks_overlap(int fd, Uint64 off, Uint64 len, Uint32 *n,
                               bool *exact);

/* Tests: read sysfs below root; nullptr or "" for the real one */
void ndb_pmem_set_sysfs_root(const char *root);

#endif
