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

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <atomic>
#include <chrono>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <portlib/NdbHW.hpp>
#include <portlib/ndb_pmem.h>
#include "my_compiler.h"

#if defined(__x86_64__) && defined(__GNUC__) && !defined(_WIN32)
#define NDB_PMEM_X86_64
#include <immintrin.h>
#elif defined(__aarch64__) && defined(__GNUC__)
#define NDB_PMEM_ARM64
#endif

#ifdef __linux__
/* Values from the kernel's uapi headers, for older C libraries */
#ifndef MAP_SHARED_VALIDATE
#define MAP_SHARED_VALIDATE 0x03
#endif
#ifndef MAP_SYNC
#define MAP_SYNC 0x80000
#endif
#ifndef MADV_POPULATE_WRITE
#define MADV_POPULATE_WRITE 23
#endif
#endif

namespace {

typedef void (*copy_func)(void *dst, const void *src, size_t len);
typedef void (*zero_func)(void *dst, size_t len);
typedef void (*flush_func)(const void *addr, size_t len);

/**
 * A copy method. copy and zero_lines take whole lines, dst aligned to
 * NDB_PMEM_LINE, and include the write-back of the lines.
 */
struct Method {
  copy_func copy;
  zero_func zero_lines;
  const char *name;
};

inline uintptr_t line_down(uintptr_t a) {
  return a & ~(uintptr_t)(NDB_PMEM_LINE - 1);
}

inline uintptr_t line_up(uintptr_t a) {
  return line_down(a + NDB_PMEM_LINE - 1);
}

flush_func choose_flush();
const Method *choose_method(ndb_pmem_copy_method method);

/**
 * Chosen at the first use or by ndb_pmem_init(). Relaxed loads are
 * enough: the values are functions and constant tables, and any of them
 * is correct.
 */
std::atomic<flush_func> g_flush{nullptr};
std::atomic<const Method *> g_method{nullptr};

inline void flush(const void *addr, size_t len) {
  flush_func f = g_flush.load(std::memory_order_relaxed);
  if (unlikely(f == nullptr)) {
    f = choose_flush();
    g_flush.store(f, std::memory_order_relaxed);
  }
  f(addr, len);
}

inline const Method *method() {
  const Method *m = g_method.load(std::memory_order_relaxed);
  if (unlikely(m == nullptr)) {
    ndb_pmem_init(NDB_PMEM_COPY_AUTO);
    m = g_method.load(std::memory_order_relaxed);
  }
  return m;
}

/* Stores, then a write-back of every line */
void copy_store_flush(void *dst, const void *src, size_t len) {
  memcpy(dst, src, len);
  flush(dst, len);
}

void zero_store_flush(void *dst, size_t len) {
  memset(dst, 0, len);
  flush(dst, len);
}

#if defined(NDB_PMEM_X86_64)

struct Line64 {
  char b[NDB_PMEM_LINE];
};

void flush_clflush(const void *addr, size_t len) {
  if (len == 0) return;
  const uintptr_t end = (uintptr_t)addr + len;
  for (uintptr_t a = line_down((uintptr_t)addr); a < end; a += NDB_PMEM_LINE) {
    _mm_clflush((const void *)a);
  }
}

__attribute__((target("clflushopt"))) void flush_clflushopt(const void *addr,
                                                            size_t len) {
  if (len == 0) return;
  const uintptr_t end = (uintptr_t)addr + len;
  for (uintptr_t a = line_down((uintptr_t)addr); a < end; a += NDB_PMEM_LINE) {
    _mm_clflushopt((void *)a);
  }
}

__attribute__((target("clwb"))) void flush_clwb(const void *addr, size_t len) {
  if (len == 0) return;
  const uintptr_t end = (uintptr_t)addr + len;
  for (uintptr_t a = line_down((uintptr_t)addr); a < end; a += NDB_PMEM_LINE) {
    _mm_clwb((void *)a);
  }
}

void copy_nt_sse2(void *dst, const void *src, size_t len) {
  char *d = static_cast<char *>(dst);
  const char *s = static_cast<const char *>(src);
  for (size_t i = 0; i < len; i += NDB_PMEM_LINE) {
    const __m128i x0 = _mm_loadu_si128((const __m128i *)(s + i));
    const __m128i x1 = _mm_loadu_si128((const __m128i *)(s + i + 16));
    const __m128i x2 = _mm_loadu_si128((const __m128i *)(s + i + 32));
    const __m128i x3 = _mm_loadu_si128((const __m128i *)(s + i + 48));
    _mm_stream_si128((__m128i *)(d + i), x0);
    _mm_stream_si128((__m128i *)(d + i + 16), x1);
    _mm_stream_si128((__m128i *)(d + i + 32), x2);
    _mm_stream_si128((__m128i *)(d + i + 48), x3);
  }
}

void zero_nt_sse2(void *dst, size_t len) {
  char *d = static_cast<char *>(dst);
  const __m128i z = _mm_setzero_si128();
  for (size_t i = 0; i < len; i += NDB_PMEM_LINE) {
    _mm_stream_si128((__m128i *)(d + i), z);
    _mm_stream_si128((__m128i *)(d + i + 16), z);
    _mm_stream_si128((__m128i *)(d + i + 32), z);
    _mm_stream_si128((__m128i *)(d + i + 48), z);
  }
}

__attribute__((target("avx"))) void copy_nt_avx(void *dst, const void *src,
                                                size_t len) {
  char *d = static_cast<char *>(dst);
  const char *s = static_cast<const char *>(src);
  for (size_t i = 0; i < len; i += NDB_PMEM_LINE) {
    const __m256i x0 = _mm256_loadu_si256((const __m256i *)(s + i));
    const __m256i x1 = _mm256_loadu_si256((const __m256i *)(s + i + 32));
    _mm256_stream_si256((__m256i *)(d + i), x0);
    _mm256_stream_si256((__m256i *)(d + i + 32), x1);
  }
}

__attribute__((target("avx"))) void zero_nt_avx(void *dst, size_t len) {
  char *d = static_cast<char *>(dst);
  const __m256i z = _mm256_setzero_si256();
  for (size_t i = 0; i < len; i += NDB_PMEM_LINE) {
    _mm256_stream_si256((__m256i *)(d + i), z);
    _mm256_stream_si256((__m256i *)(d + i + 32), z);
  }
}

/**
 * MOVDIR64B (%rdx), %rax: one 64-byte direct store, written as bytes as
 * the Linux kernel does, so that no compiler support is needed.
 */
inline void movdir64b(void *dst, const void *src) {
  asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02"
               : "+m"(*static_cast<Line64 *>(dst))
               : "m"(*static_cast<const Line64 *>(src)), "a"(dst), "d"(src));
}

void copy_movdir64b(void *dst, const void *src, size_t len) {
  char *d = static_cast<char *>(dst);
  const char *s = static_cast<const char *>(src);
  for (size_t i = 0; i < len; i += NDB_PMEM_LINE) {
    movdir64b(d + i, s + i);
  }
}

alignas(NDB_PMEM_LINE) const Line64 zero_line{};

void zero_movdir64b(void *dst, size_t len) {
  char *d = static_cast<char *>(dst);
  for (size_t i = 0; i < len; i += NDB_PMEM_LINE) {
    movdir64b(d + i, &zero_line);
  }
}

const Method method_movdir64b = {copy_movdir64b, zero_movdir64b, "movdir64b"};
const Method method_nt_avx = {copy_nt_avx, zero_nt_avx, "ntstore-avx"};
const Method method_nt_sse2 = {copy_nt_sse2, zero_nt_sse2, "ntstore-sse2"};
const Method method_store_clwb = {copy_store_flush, zero_store_flush,
                                  "store+clwb"};
const Method method_store_clflushopt = {copy_store_flush, zero_store_flush,
                                        "store+clflushopt"};
const Method method_store_clflush = {copy_store_flush, zero_store_flush,
                                     "store+clflush"};

flush_func choose_flush() {
  const ndb_cpu_features *f = Ndb_GetCpuFeatures();
  if (f->clwb) return flush_clwb;
  if (f->clflushopt) return flush_clflushopt;
  return flush_clflush;
}

/* AVX-512 is left out: it can lower the clock of the core (S1.3) */
const Method *choose_method(ndb_pmem_copy_method m) {
  const ndb_cpu_features *f = Ndb_GetCpuFeatures();
  switch (m) {
    case NDB_PMEM_COPY_AUTO:
      if (f->movdir64b) return &method_movdir64b;
      return f->avx ? &method_nt_avx : &method_nt_sse2;
    case NDB_PMEM_COPY_NTSTORE:
      return f->avx ? &method_nt_avx : &method_nt_sse2;
    case NDB_PMEM_COPY_MOVDIR64B:
      return f->movdir64b ? &method_movdir64b : nullptr;
    case NDB_PMEM_COPY_CLWB:
      if (f->clwb) return &method_store_clwb;
      if (f->clflushopt) return &method_store_clflushopt;
      return &method_store_clflush;
  }
  return nullptr;
}

inline void drain_cpu() { _mm_sfence(); }

#elif defined(NDB_PMEM_ARM64)

/* DC CVAP, written as SYS for assemblers that do not know it */
inline void dc_cvap(uintptr_t a) {
  asm volatile("sys #3, c7, c12, #1, %0" : : "r"(a) : "memory");
}

inline void dc_cvac(uintptr_t a) {
  asm volatile("dc cvac, %0" : : "r"(a) : "memory");
}

void flush_cvap(const void *addr, size_t len) {
  if (len == 0) return;
  const uintptr_t end = (uintptr_t)addr + len;
  for (uintptr_t a = line_down((uintptr_t)addr); a < end; a += NDB_PMEM_LINE) {
    dc_cvap(a);
  }
}

void flush_cvac(const void *addr, size_t len) {
  if (len == 0) return;
  const uintptr_t end = (uintptr_t)addr + len;
  for (uintptr_t a = line_down((uintptr_t)addr); a < end; a += NDB_PMEM_LINE) {
    dc_cvac(a);
  }
}

const Method method_store_cvap = {copy_store_flush, zero_store_flush,
                                  "store+dc-cvap"};
const Method method_store_cvac = {copy_store_flush, zero_store_flush,
                                  "store+dc-cvac"};

/* Without FEAT_DPB there is no point of persistence; clean to coherence */
flush_func choose_flush() {
  return Ndb_GetCpuFeatures()->arm_dcpop ? flush_cvap : flush_cvac;
}

const Method *choose_method(ndb_pmem_copy_method m) {
  switch (m) {
    case NDB_PMEM_COPY_AUTO:
    case NDB_PMEM_COPY_CLWB:
      return Ndb_GetCpuFeatures()->arm_dcpop ? &method_store_cvap
                                             : &method_store_cvac;
    case NDB_PMEM_COPY_NTSTORE:
    case NDB_PMEM_COPY_MOVDIR64B:
      return nullptr;
  }
  return nullptr;
}

inline void drain_cpu() { asm volatile("dsb sy" : : : "memory"); }

#else

/* Other platforms only need to build */
void flush_none(const void *, size_t) {}

const Method method_memcpy = {copy_store_flush, zero_store_flush, "memcpy"};

flush_func choose_flush() { return flush_none; }

const Method *choose_method(ndb_pmem_copy_method m) {
  switch (m) {
    case NDB_PMEM_COPY_AUTO:
    case NDB_PMEM_COPY_CLWB:
      return &method_memcpy;
    case NDB_PMEM_COPY_NTSTORE:
    case NDB_PMEM_COPY_MOVDIR64B:
      return nullptr;
  }
  return nullptr;
}

inline void drain_cpu() { std::atomic_thread_fence(std::memory_order_seq_cst); }

#endif

/*
 * Power-loss emulation (platform plan S1.5). Each thread that writes has a
 * list of its pending lines, oldest first, with the pre-image of each and
 * an index by address. The thread locks its own list during a write, so
 * that a freeze, which takes every list's lock, waits for the writes under
 * way and stops all later ones. The locks are spin locks that a signal
 * handler can try. The lists are never freed; the registry only grows.
 */

struct EmulLine {
  uintptr_t addr;
  bool flushed;  // written back: persistent at this thread's next drain
  Uint8 pre[NDB_PMEM_LINE];
};

class EmulLock {
 public:
  bool try_lock() { return !m_held.exchange(true, std::memory_order_acquire); }
  void lock() {
    while (!try_lock()) std::this_thread::yield();
  }
  /* At least one try, then until the deadline */
  bool lock_until(std::chrono::steady_clock::time_point deadline) {
    while (!try_lock()) {
      if (std::chrono::steady_clock::now() >= deadline) return false;
      std::this_thread::yield();
    }
    return true;
  }
  void unlock() { m_held.store(false, std::memory_order_release); }

 private:
  std::atomic<bool> m_held{false};
};

struct EmulList {
  EmulLock lock;
  bool frozen = false;  // its lock is held by the freeze
  std::vector<EmulLine> lines;
  size_t first = 0;  // lines before it are no longer pending
  std::unordered_map<uintptr_t, size_t> index;
  ndb_pmem_emul_stats stats{};

  size_t pending() const { return lines.size() - first; }
};

constexpr Uint32 EMUL_MAX_THREADS = 1024;
std::atomic<bool> g_emul_active{false};
std::atomic<bool> g_emul_frozen{false};
Uint32 g_emul_max_pending = 0;
EmulList *g_emul_lists[EMUL_MAX_THREADS];
std::atomic<Uint32> g_emul_list_count{0};
EmulLock g_emul_register_lock;
std::atomic<Uint32> g_emul_not_parked{0};
std::atomic<Uint64> g_emul_crash_seed{0};
std::atomic<Uint32> g_emul_crash_keep{0};
std::atomic<Uint32> g_emul_crash_tear{0};
std::atomic<int> g_emul_crash_state{0};  // 1: under way, 2: done

/* Small, as libndbclient has static TLS */
thread_local EmulList *t_emul_list = nullptr;
thread_local bool t_emul_in_write = false;

inline bool emul_on() {
  return unlikely(g_emul_active.load(std::memory_order_relaxed));
}

Uint64 emul_rand(Uint64 *state) {
  Uint64 z = (*state += 0x9E3779B97F4A7C15ULL);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

Uint32 emul_list_count() {
  return g_emul_list_count.load(std::memory_order_acquire);
}

/* This thread's list, registered at its first write */
EmulList *emul_list() {
  EmulList *l = t_emul_list;
  if (likely(l != nullptr)) return l;
  l = new EmulList();
  l->lines.reserve(g_emul_max_pending + 1);
  l->index.reserve(2 * size_t(g_emul_max_pending));
  g_emul_register_lock.lock();
  const Uint32 n = g_emul_list_count.load(std::memory_order_relaxed);
  if (n < EMUL_MAX_THREADS) {
    g_emul_lists[n] = l;
    g_emul_list_count.store(n + 1, std::memory_order_release);
  } else {
    fprintf(stderr,
            "ndb_pmem: power-loss emulation: more than %u threads write, "
            "the writes of this one are not emulated\n",
            EMUL_MAX_THREADS);
  }
  g_emul_register_lock.unlock();
  t_emul_list = l;
  return l;
}

/* This thread's list, locked for a write; waits forever once frozen */
EmulList *emul_begin() {
  EmulList *l = emul_list();
  l->lock.lock();
  while (g_emul_frozen.load(std::memory_order_acquire) && !l->frozen) {
    /* A list that the freeze did not take: registered after it */
    l->lock.unlock();
    std::this_thread::yield();
    l->lock.lock();
  }
  t_emul_in_write = true;
  return l;
}

void emul_end(EmulList *l) {
  t_emul_in_write = false;
  l->lock.unlock();
}

/* Debug aid: a line pending in two threads, two writers between fences */
void emul_check_shared(EmulList *l, uintptr_t addr) {
  const Uint32 n = emul_list_count();
  for (Uint32 i = 0; i < n; i++) {
    EmulList *o = g_emul_lists[i];
    if (o == l || !o->lock.try_lock()) continue;
    const bool found = o->index.find(addr) != o->index.end();
    o->lock.unlock();
    if (found) {
      static std::atomic<bool> reported{false};
      if (!reported.exchange(true)) {
        fprintf(stderr,
                "ndb_pmem: power-loss emulation: line %p is pending in two "
                "threads\n",
                (void *)addr);
      }
      l->stats.shared++;
      return;
    }
  }
}

/* The lines of [start, end) are written; flushed: they are written back */
void emul_record(EmulList *l, uintptr_t start, uintptr_t end, bool flushed) {
  for (uintptr_t a = line_down(start); a < end; a += NDB_PMEM_LINE) {
    const auto it = l->index.find(a);
    if (it != l->index.end()) {
      l->lines[it->second].flushed = flushed;
      continue;
    }
    if (l->pending() >= g_emul_max_pending) {
      l->index.erase(l->lines[l->first].addr);
      l->first++;
      l->stats.evicted_early++;
    }
    emul_check_shared(l, a);
    EmulLine e;
    e.addr = a;
    e.flushed = flushed;
    memcpy(e.pre, (const void *)a, NDB_PMEM_LINE);
    l->index.emplace(a, l->lines.size());
    l->lines.push_back(e);
    l->stats.written++;
  }
}

/* The pending lines that drop() selects are no longer pending */
template <class Drop>
Uint64 emul_compact(EmulList *l, Drop drop) {
  Uint64 dropped = 0;
  size_t out = 0;
  for (size_t i = l->first; i < l->lines.size(); i++) {
    if (drop(l->lines[i])) {
      dropped++;
      continue;
    }
    if (out != i) l->lines[out] = l->lines[i];
    out++;
  }
  l->lines.resize(out);
  l->first = 0;
  l->index.clear();
  for (size_t i = 0; i < out; i++) l->index.emplace(l->lines[i].addr, i);
  return dropped;
}

}  // namespace

int ndb_pmem_init(ndb_pmem_copy_method m) {
  const Method *chosen = choose_method(m);
  if (chosen == nullptr) return ENOTSUP;
  g_flush.store(choose_flush(), std::memory_order_relaxed);
  g_method.store(chosen, std::memory_order_relaxed);
  return 0;
}

const char *ndb_pmem_method_name() { return method()->name; }

bool ndb_pmem_cpu_persists() {
#if defined(NDB_PMEM_X86_64)
  return true;
#elif defined(NDB_PMEM_ARM64)
  return Ndb_GetCpuFeatures()->arm_dcpop;
#else
  return false;
#endif
}

int ndb_pmem_map(int fd, size_t len, unsigned flags, ndb_pmem_mapping *out) {
  out->addr = nullptr;
  out->len = 0;
  out->map_sync = false;
#ifdef _WIN32
  (void)fd;
  (void)len;
  (void)flags;
  return EOPNOTSUPP;
#else
  if (len == 0) return EINVAL;
  const size_t page = (size_t)sysconf(_SC_PAGESIZE);
  /**
   * Whether MAP_SYNC works is found on one page mapped where the kernel
   * chooses, before the file is mapped over the reserved range. A
   * MAP_FIXED mmap that the file system refuses, as it refuses MAP_SYNC
   * without DAX, can have unmapped the range already (Linux 6.11), and
   * another thread may map into it before this one maps it again.
   */
  int map_flags = MAP_SHARED;
  bool map_sync = false;
  int err = EOPNOTSUPP;
#ifdef __linux__
  void *probe = mmap(nullptr, page, PROT_READ | PROT_WRITE,
                     MAP_SHARED_VALIDATE | MAP_SYNC, fd, 0);
  if (probe != MAP_FAILED) {
    munmap(probe, page);
    map_flags = MAP_SHARED_VALIDATE | MAP_SYNC;
    map_sync = true;
  } else {
    err = errno;
    /* Kernels before 4.15 do not know MAP_SHARED_VALIDATE */
    if (err == EINVAL) err = EOPNOTSUPP;
  }
#endif
  if (!map_sync &&
      (err != EOPNOTSUPP || !(flags & NDB_PMEM_MAP_SYNC_OPTIONAL))) {
    return err;
  }

  /**
   * Reserve 2 MB more than needed, map the file at the first 2 MB
   * boundary inside, and release the rest.
   */
  const size_t align = size_t(2) << 20;
  const size_t reserve_len = len + align;
  int reserve_flags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef MAP_NORESERVE
  reserve_flags |= MAP_NORESERVE;
#endif
  void *reserve = mmap(nullptr, reserve_len, PROT_NONE, reserve_flags, -1, 0);
  if (reserve == MAP_FAILED) return errno;
  const uintptr_t reserve_start = (uintptr_t)reserve;
  const uintptr_t reserve_end = reserve_start + reserve_len;
  const uintptr_t base = (reserve_start + align - 1) & ~(uintptr_t)(align - 1);
  const uintptr_t end = base + ((len + page - 1) / page) * page;

  void *addr = mmap((void *)base, len, PROT_READ | PROT_WRITE,
                    map_flags | MAP_FIXED, fd, 0);
  if (addr == MAP_FAILED) err = errno;
  /**
   * After a failure [base, end) may be unmapped and another thread's
   * now: it is left alone, at worst a reserved range is lost.
   */
  if (base > reserve_start) munmap(reserve, base - reserve_start);
  if (end < reserve_end) munmap((void *)end, reserve_end - end);
  if (addr == MAP_FAILED) return err;
  out->addr = addr;
  out->len = len;
  out->map_sync = map_sync;
  return 0;
#endif
}

int ndb_pmem_unmap(ndb_pmem_mapping *m) {
  int res = 0;
  if (emul_on() && m->addr != nullptr) {
    /* The pending lines of the mapping stay as they are: persistent */
    const uintptr_t start = (uintptr_t)m->addr;
    const uintptr_t end = start + m->len;
    const Uint32 n = emul_list_count();
    for (Uint32 i = 0; i < n; i++) {
      EmulList *l = g_emul_lists[i];
      if (l->frozen) continue;
      l->lock.lock();
      l->stats.persisted += emul_compact(l, [&](const EmulLine &e) {
        return e.addr >= start && e.addr < end;
      });
      l->lock.unlock();
    }
  }
#ifndef _WIN32
  if (m->addr != nullptr && munmap(m->addr, m->len) != 0) res = errno;
#endif
  m->addr = nullptr;
  m->len = 0;
  m->map_sync = false;
  return res;
}

int ndb_pmem_prefault(void *addr, size_t len) {
#ifdef _WIN32
  (void)addr;
  (void)len;
  return EOPNOTSUPP;
#else
#ifdef __linux__
  /* Linux 5.14 and later: fault in writable, nothing written */
  if (madvise(addr, len, MADV_POPULATE_WRITE) == 0) return 0;
  if (errno != EINVAL) return errno;
#endif
  /**
   * Write back the value read from one byte of every 4 KB page, then
   * write the lines back, so that no dirty line stays in the cache.
   */
  volatile char *p = static_cast<volatile char *>(addr);
  for (size_t off = 0; off < len; off += 4096) {
    const char c = p[off];
    p[off] = c;
    flush(static_cast<char *>(addr) + off, 1);
  }
  ndb_pmem_drain();
  return 0;
#endif
}

int ndb_pmem_lock(void *addr, size_t len) {
#ifdef _WIN32
  (void)addr;
  (void)len;
  return EOPNOTSUPP;
#else
  return mlock(addr, len) == 0 ? 0 : errno;
#endif
}

void ndb_pmem_copy_nt(void *dst, const void *src, size_t len) {
  assert(((uintptr_t)dst % NDB_PMEM_LINE) == 0);
  assert((len % NDB_PMEM_LINE) == 0);
  if (emul_on()) {
    EmulList *l = emul_begin();
    emul_record(l, (uintptr_t)dst, (uintptr_t)dst + len, true);
    method()->copy(dst, src, len);
    emul_end(l);
    return;
  }
  method()->copy(dst, src, len);
}

namespace {

inline void store32(Uint32 *dst, Uint32 v) {
#ifdef __GNUC__
  __atomic_store_n(dst, v, __ATOMIC_RELAXED);
#else
  *(volatile Uint32 *)dst = v;
#endif
}

inline void store64(Uint64 *dst, Uint64 v) {
#ifdef __GNUC__
  __atomic_store_n(dst, v, __ATOMIC_RELAXED);
#else
  *(volatile Uint64 *)dst = v;
#endif
}

void zero(void *dst, size_t len) {
  const uintptr_t start = (uintptr_t)dst;
  const uintptr_t end = start + len;
  const uintptr_t first = line_up(start);
  const uintptr_t last = line_down(end);
  if (first >= last) {
    /* No whole line */
    memset(dst, 0, len);
    flush(dst, len);
    return;
  }
  if (start < first) {
    memset(dst, 0, first - start);
    flush(dst, first - start);
  }
  method()->zero_lines((void *)first, last - first);
  if (last < end) {
    memset((void *)last, 0, end - last);
    flush((void *)last, end - last);
  }
}

}  // namespace

void ndb_pmem_store32(Uint32 *dst, Uint32 v) {
  assert(((uintptr_t)dst % sizeof(Uint32)) == 0);
  if (emul_on()) {
    EmulList *l = emul_begin();
    emul_record(l, (uintptr_t)dst, (uintptr_t)dst + sizeof(v), false);
    store32(dst, v);
    emul_end(l);
    return;
  }
  store32(dst, v);
}

void ndb_pmem_store64(Uint64 *dst, Uint64 v) {
  assert(((uintptr_t)dst % sizeof(Uint64)) == 0);
  if (emul_on()) {
    EmulList *l = emul_begin();
    emul_record(l, (uintptr_t)dst, (uintptr_t)dst + sizeof(v), false);
    store64(dst, v);
    emul_end(l);
    return;
  }
  store64(dst, v);
}

void ndb_pmem_zero(void *dst, size_t len) {
  if (len == 0) return;
  if (emul_on()) {
    EmulList *l = emul_begin();
    emul_record(l, (uintptr_t)dst, (uintptr_t)dst + len, true);
    zero(dst, len);
    emul_end(l);
    return;
  }
  zero(dst, len);
}

void ndb_pmem_flush(const void *addr, size_t len) {
  if (emul_on() && len > 0) {
    /* This thread's lines; a flush of another thread's line is not seen */
    EmulList *l = emul_begin();
    const uintptr_t end = (uintptr_t)addr + len;
    for (uintptr_t a = line_down((uintptr_t)addr); a < end;
         a += NDB_PMEM_LINE) {
      const auto it = l->index.find(a);
      if (it != l->index.end()) l->lines[it->second].flushed = true;
    }
    flush(addr, len);
    emul_end(l);
    return;
  }
  flush(addr, len);
}

void ndb_pmem_drain() {
  drain_cpu();
  if (emul_on()) {
    EmulList *l = emul_begin();
    if (l->pending() > 0) {
      l->stats.persisted +=
          emul_compact(l, [](const EmulLine &e) { return e.flushed; });
    }
    emul_end(l);
  }
}

int ndb_pmem_emul_enable(Uint32 max_pending) {
  if (max_pending == 0) return EINVAL;
  if (g_emul_active.load()) {
    return max_pending == g_emul_max_pending ? 0 : EBUSY;
  }
  g_emul_max_pending = max_pending;
  g_emul_active.store(true);
  return 0;
}

bool ndb_pmem_emul_active() { return emul_on(); }

Uint32 ndb_pmem_emul_pending() {
  if (!emul_on() || t_emul_list == nullptr) return 0;
  EmulList *l = emul_begin();
  const Uint32 n = Uint32(l->pending());
  emul_end(l);
  return n;
}

bool ndb_pmem_emul_range_pending(const void *addr, size_t len) {
  if (!emul_on() || len == 0) return false;
  const uintptr_t start = line_down((uintptr_t)addr);
  const uintptr_t end = (uintptr_t)addr + len;
  const size_t range_lines = (line_up(end) - start) / NDB_PMEM_LINE;
  bool found = false;
  const Uint32 n = emul_list_count();
  for (Uint32 i = 0; i < n && !found; i++) {
    EmulList *l = g_emul_lists[i];
    if (l->frozen) continue;
    l->lock.lock();
    if (range_lines <= l->pending()) {
      for (uintptr_t a = start; a < end && !found; a += NDB_PMEM_LINE) {
        found = l->index.find(a) != l->index.end();
      }
    } else {
      for (size_t k = l->first; k < l->lines.size() && !found; k++) {
        found = l->lines[k].addr >= start && l->lines[k].addr < end;
      }
    }
    l->lock.unlock();
  }
  return found;
}

Uint32 ndb_pmem_emul_freeze() {
  if (!emul_on()) return 0;
  g_emul_frozen.store(true, std::memory_order_release);
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(1);
  Uint32 not_parked = 0;
  const Uint32 n = emul_list_count();
  for (Uint32 i = 0; i < n; i++) {
    EmulList *l = g_emul_lists[i];
    if (l->frozen) continue;
    if (l == t_emul_list && t_emul_in_write) {
      /* This thread crashed inside a write: its list may be half updated */
      not_parked++;
      continue;
    }
    if (l->lock.lock_until(deadline)) {
      l->frozen = true;
    } else {
      not_parked++;
    }
  }
  g_emul_not_parked.store(not_parked);
  return not_parked;
}

void ndb_pmem_emul_power_fail(Uint64 seed, Uint32 keep_permille,
                              Uint32 tear_permille) {
  if (!emul_on()) return;
  ndb_pmem_emul_freeze();
  Uint64 state = seed != 0 ? seed
                           : Uint64(std::chrono::steady_clock::now()
                                        .time_since_epoch()
                                        .count());
  const Uint32 n = emul_list_count();
  for (Uint32 i = 0; i < n; i++) {
    EmulList *l = g_emul_lists[i];
    if (!l->frozen) continue;
    for (size_t k = l->first; k < l->lines.size(); k++) {
      const EmulLine &e = l->lines[k];
      const Uint64 r = emul_rand(&state);
      const Uint32 p = Uint32(r % 1000);
      if (p < keep_permille) {
        l->stats.kept++;
      } else if (p < keep_permille + tear_permille) {
        const Uint32 words = Uint32(r >> 32) & 0xFF;
        for (Uint32 w = 0; w < NDB_PMEM_LINE / 8; w++) {
          if (words & (1u << w)) {
            memcpy((void *)(e.addr + 8 * w), e.pre + 8 * w, 8);
          }
        }
        l->stats.torn++;
      } else {
        memcpy((void *)e.addr, e.pre, NDB_PMEM_LINE);
        l->stats.reverted++;
      }
    }
    /* Nothing is pending; the index is stale until a reset */
    l->first = l->lines.size();
  }
}

void ndb_pmem_emul_set_crash(Uint64 seed, Uint32 keep_permille,
                             Uint32 tear_permille) {
  g_emul_crash_seed.store(seed);
  g_emul_crash_keep.store(keep_permille);
  g_emul_crash_tear.store(tear_permille);
}

void ndb_pmem_emul_on_crash() {
  if (!emul_on()) return;
  int expected = 0;
  if (g_emul_crash_state.compare_exchange_strong(expected, 1)) {
    ndb_pmem_emul_power_fail(g_emul_crash_seed.load(),
                             g_emul_crash_keep.load(),
                             g_emul_crash_tear.load());
    g_emul_crash_state.store(2, std::memory_order_release);
    return;
  }
  /* Another thread loses the power: exit only once it is done */
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (g_emul_crash_state.load(std::memory_order_acquire) != 2 &&
         std::chrono::steady_clock::now() < deadline) {
    std::this_thread::yield();
  }
}

void ndb_pmem_emul_get_stats(ndb_pmem_emul_stats *out) {
  *out = ndb_pmem_emul_stats{};
  const Uint32 n = emul_list_count();
  for (Uint32 i = 0; i < n; i++) {
    EmulList *l = g_emul_lists[i];
    /* A frozen list is held by the freeze, which has stopped its writer */
    const bool lock = !l->frozen;
    if (lock) l->lock.lock();
    const ndb_pmem_emul_stats &s = l->stats;
    out->written += s.written;
    out->persisted += s.persisted;
    out->evicted_early += s.evicted_early;
    out->kept += s.kept;
    out->reverted += s.reverted;
    out->torn += s.torn;
    out->shared += s.shared;
    if (lock) l->lock.unlock();
  }
  out->threads = n;
  out->not_parked = g_emul_not_parked.load();
}

void ndb_pmem_emul_reset() {
  const Uint32 n = emul_list_count();
  for (Uint32 i = 0; i < n; i++) {
    EmulList *l = g_emul_lists[i];
    if (l->frozen) {
      l->frozen = false;
    } else {
      l->lock.lock();
    }
    l->lines.clear();
    l->first = 0;
    l->index.clear();
    l->stats = ndb_pmem_emul_stats{};
    l->lock.unlock();
  }
  g_emul_not_parked.store(0);
  g_emul_crash_state.store(0);
  g_emul_frozen.store(false, std::memory_order_release);
}

#ifdef TEST_NDB_PMEM

#include <util/NdbTap.hpp>
#include <algorithm>
#include <chrono>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#endif

namespace {

#ifndef _WIN32

constexpr size_t TEST_FILE_SIZE = size_t(4) << 20;

Uint64 test_rand() {
  static Uint64 state = 0x9E3779B97F4A7C15ULL;
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return state;
}

struct TestFile {
  int fd;
  char path[1024];
};

bool create_file(const char *dir, TestFile *f) {
  snprintf(f->path, sizeof(f->path), "%s/ndb_pmem-t.XXXXXX", dir);
  f->fd = mkstemp(f->path);
  if (f->fd < 0) {
    perror(f->path);
    return false;
  }
  if (ftruncate(f->fd, TEST_FILE_SIZE) != 0) {
    perror("ftruncate");
    close(f->fd);
    unlink(f->path);
    return false;
  }
  return true;
}

void remove_file(TestFile *f) {
  close(f->fd);
  unlink(f->path);
}

/* A copy method with the write-back it is used with */
struct TestVariant {
  const Method *method;
  flush_func flush;
};

std::vector<TestVariant> test_variants() {
  std::vector<TestVariant> variants;
#if defined(NDB_PMEM_X86_64)
  const ndb_cpu_features *f = Ndb_GetCpuFeatures();
  variants.push_back({&method_nt_sse2, choose_flush()});
  if (f->avx) variants.push_back({&method_nt_avx, choose_flush()});
  if (f->movdir64b) variants.push_back({&method_movdir64b, choose_flush()});
  if (f->clwb) variants.push_back({&method_store_clwb, flush_clwb});
  if (f->clflushopt) {
    variants.push_back({&method_store_clflushopt, flush_clflushopt});
  }
  variants.push_back({&method_store_clflush, flush_clflush});
#elif defined(NDB_PMEM_ARM64)
  if (Ndb_GetCpuFeatures()->arm_dcpop) {
    variants.push_back({&method_store_cvap, flush_cvap});
  }
  variants.push_back({&method_store_cvac, flush_cvac});
#else
  variants.push_back({&method_memcpy, flush_none});
#endif
  return variants;
}

void use_variant(const TestVariant &v) {
  g_flush.store(v.flush, std::memory_order_relaxed);
  g_method.store(v.method, std::memory_order_relaxed);
}

/* The public methods give what this CPU has */
void test_init() {
  OK(ndb_pmem_init(NDB_PMEM_COPY_AUTO) == 0);
  printf("ndb_pmem: auto chooses %s\n", ndb_pmem_method_name());
  printf("ndb_pmem: this CPU %s write lines back to persistent memory\n",
         ndb_pmem_cpu_persists() ? "can" : "cannot");
#if defined(NDB_PMEM_X86_64)
  OK(ndb_pmem_cpu_persists());
#elif defined(NDB_PMEM_ARM64)
  OK(ndb_pmem_cpu_persists() == Ndb_GetCpuFeatures()->arm_dcpop);
#endif
  const ndb_pmem_copy_method methods[] = {NDB_PMEM_COPY_NTSTORE,
                                          NDB_PMEM_COPY_MOVDIR64B,
                                          NDB_PMEM_COPY_CLWB};
  for (ndb_pmem_copy_method m : methods) {
    const int r = ndb_pmem_init(m);
    OK(r == 0 || r == ENOTSUP);
    printf("ndb_pmem: method %d: %s\n", (int)m,
           r == 0 ? ndb_pmem_method_name() : "not supported");
    OK(ndb_pmem_init(m) == r);
  }
#if defined(NDB_PMEM_X86_64)
  OK(ndb_pmem_init(NDB_PMEM_COPY_NTSTORE) == 0);
  OK(ndb_pmem_init(NDB_PMEM_COPY_MOVDIR64B) ==
     (Ndb_GetCpuFeatures()->movdir64b ? 0 : ENOTSUP));
#else
  OK(ndb_pmem_init(NDB_PMEM_COPY_NTSTORE) == ENOTSUP);
  OK(ndb_pmem_init(NDB_PMEM_COPY_MOVDIR64B) == ENOTSUP);
#endif
  OK(ndb_pmem_init(NDB_PMEM_COPY_AUTO) == 0);
}

#ifdef __linux__
long minor_faults() {
  struct rusage ru;
  getrusage(RUSAGE_THREAD, &ru);
  return ru.ru_minflt;
}
#endif

/**
 * Write the offset into the first word of every 4 KB page; the minor
 * faults that takes on Linux, else -1.
 */
long write_every_page(char *base) {
#ifdef __linux__
  const long before = minor_faults();
#endif
  for (size_t off = 0; off < TEST_FILE_SIZE; off += 4096) {
    ndb_pmem_store64(reinterpret_cast<Uint64 *>(base + off), off);
    ndb_pmem_flush(base + off, sizeof(Uint64));
  }
  ndb_pmem_drain();
#ifdef __linux__
  return minor_faults() - before;
#else
  return -1;
#endif
}

/**
 * The minor faults of writing every page of a new file in dir, mapped
 * with flags, after a prefault if asked and a lock if asked. -1 if not
 * Linux, -2 if the lock was refused.
 */
long faults_on_new_file(const char *dir, unsigned flags, bool prefault,
                        bool lock) {
  TestFile f;
  OK(create_file(dir, &f));
  ndb_pmem_mapping m;
  OK(ndb_pmem_map(f.fd, TEST_FILE_SIZE, flags, &m) == 0);
  long faults = -2;
  if (prefault) {
    OK(ndb_pmem_prefault(m.addr, TEST_FILE_SIZE) == 0);
  }
  const int r = lock ? ndb_pmem_lock(m.addr, TEST_FILE_SIZE) : 0;
  if (r == 0) {
    faults = write_every_page(static_cast<char *>(m.addr));
  } else {
    printf("ndb_pmem: lock refused: %s\n", strerror(r));
  }
  OK(ndb_pmem_unmap(&m) == 0);
  remove_file(&f);
  return faults;
}

/**
 * After a prefault, writing every page of the mapping takes no page
 * fault. That is required on DAX (map_sync) only: on a page-cache file
 * the count depends on how the kernel maps the cache. New files without
 * prefault, and with prefault and lock, show the difference. Only a
 * mapping is written while the faults are counted.
 */
void test_prefault(char *base, std::vector<Uint8> &expected, bool map_sync,
                   const char *dir) {
  OK(ndb_pmem_prefault(base, TEST_FILE_SIZE) == 0);
#ifdef __linux__
  const bool populate = madvise(base, 4096, MADV_POPULATE_WRITE) == 0;
  printf("ndb_pmem: MADV_POPULATE_WRITE %s\n",
         populate ? "used" : "not supported, pages written instead");
#endif
  const long faults = write_every_page(base);
  for (size_t off = 0; off < TEST_FILE_SIZE; off += 4096) {
    const Uint64 v = off;
    memcpy(expected.data() + off, &v, sizeof(v));
  }
  if (faults < 0) return;

  const unsigned flags =
      map_sync ? NDB_PMEM_MAP_SYNC_REQUIRED : NDB_PMEM_MAP_SYNC_OPTIONAL;
  const long faults_without = faults_on_new_file(dir, flags, false, false);
  const long faults_locked = faults_on_new_file(dir, flags, true, true);
  printf("ndb_pmem: minor faults writing %zu pages: %ld after prefault, "
         "%ld without prefault, %ld after prefault and lock%s\n",
         TEST_FILE_SIZE / 4096, faults, faults_without, faults_locked,
         map_sync ? "" : " (page cache, not checked)");
  if (map_sync) {
    OK(faults <= (long)(TEST_FILE_SIZE / 4096 / 64));
  }
}

/**
 * Copies of 1 to 8 lines over 64 KB, in-place stores and zeroing of
 * random ranges, with the current method; the mapping must then hold
 * what was written.
 */
void test_writes(char *base, std::vector<Uint8> &expected, size_t at) {
  alignas(NDB_PMEM_LINE) Uint8 src[8 * NDB_PMEM_LINE];
  const size_t area = 64 * 1024;
  size_t off = at;
  while (off < at + area) {
    size_t lines = 1 + test_rand() % 8;
    lines = std::min(lines, (at + area - off) / NDB_PMEM_LINE);
    const size_t n = lines * NDB_PMEM_LINE;
    for (size_t i = 0; i < n; i++) {
      src[i] = (Uint8)test_rand();
    }
    ndb_pmem_copy_nt(base + off, src, n);
    memcpy(expected.data() + off, src, n);
    off += n;
  }
  ndb_pmem_drain();

  for (int i = 0; i < 100; i++) {
    const size_t o32 = at + 4 * (test_rand() % (area / 4));
    const Uint32 v32 = (Uint32)test_rand();
    ndb_pmem_store32(reinterpret_cast<Uint32 *>(base + o32), v32);
    ndb_pmem_flush(base + o32, sizeof(v32));
    memcpy(expected.data() + o32, &v32, sizeof(v32));
    const size_t o64 = at + 8 * (test_rand() % (area / 8));
    const Uint64 v64 = test_rand();
    ndb_pmem_store64(reinterpret_cast<Uint64 *>(base + o64), v64);
    ndb_pmem_flush(base + o64, sizeof(v64));
    memcpy(expected.data() + o64, &v64, sizeof(v64));
  }
  ndb_pmem_drain();

  for (int i = 0; i < 100; i++) {
    const size_t len = 1 + test_rand() % 300;
    const size_t o = at + test_rand() % (area - len);
    ndb_pmem_zero(base + o, len);
    memset(expected.data() + o, 0, len);
  }
  /* Whole lines, and a range that starts and ends inside lines */
  ndb_pmem_zero(base + at + 4096, 8 * NDB_PMEM_LINE);
  memset(expected.data() + at + 4096, 0, 8 * NDB_PMEM_LINE);
  ndb_pmem_zero(base + at + 8192 + 24, 5 * NDB_PMEM_LINE);
  memset(expected.data() + at + 8192 + 24, 0, 5 * NDB_PMEM_LINE);
  ndb_pmem_drain();

  OK(memcmp(base, expected.data(), TEST_FILE_SIZE) == 0);
}

/* Informational: ns per copy and drain of 1, 2 and 8 lines */
void test_timing(char *base, const std::vector<TestVariant> &variants) {
  alignas(NDB_PMEM_LINE) Uint8 src[8 * NDB_PMEM_LINE];
  for (Uint8 &b : src) {
    b = (Uint8)test_rand();
  }
  printf("ndb_pmem: ns per copy + drain, on this file (not persistent memory)\n");
  printf("%18s %8s %8s %8s\n", "method", "1 line", "2 lines", "8 lines");
  typedef std::chrono::steady_clock clock;
  const size_t area = size_t(1) << 20;
  for (const TestVariant &v : variants) {
    use_variant(v);
    printf("%18s", v.method->name);
    const size_t line_counts[] = {1, 2, 8};
    for (size_t lines : line_counts) {
      const size_t n = lines * NDB_PMEM_LINE;
      const size_t iterations = 100000;
      size_t off = 0;
      const auto start = clock::now();
      for (size_t i = 0; i < iterations; i++) {
        ndb_pmem_copy_nt(base + off, src, n);
        ndb_pmem_drain();
        off += n;
        if (off + n > area) off = 0;
      }
      const auto stop = clock::now();
      printf(" %8.1f",
             std::chrono::duration<double, std::nano>(stop - start).count() /
                 (double)iterations);
    }
    printf("\n");
  }
}

/**
 * Everything on a file in dir. If dax, the directory is on a DAX file
 * system and MAP_SYNC must work.
 */
void test_dir(const char *dir, bool dax) {
  TestFile f;
  OK(create_file(dir, &f));
  ndb_pmem_mapping m;
  const int r = ndb_pmem_map(f.fd, TEST_FILE_SIZE, NDB_PMEM_MAP_SYNC_REQUIRED, &m);
  printf("ndb_pmem: map with MAP_SYNC required in %s: %s\n", dir,
         r == 0 ? "mapped" : strerror(r));
  if (dax) {
    OK(r == 0);
  }
  if (r == 0) {
    OK(m.map_sync);
  } else {
    OK(r == EOPNOTSUPP);
    OK(m.addr == nullptr);
    OK(ndb_pmem_map(f.fd, TEST_FILE_SIZE, NDB_PMEM_MAP_SYNC_OPTIONAL, &m) == 0);
    OK(!m.map_sync);
  }
  OK(m.addr != nullptr);
  OK(m.len == TEST_FILE_SIZE);
  OK(((uintptr_t)m.addr & ((size_t(2) << 20) - 1)) == 0);
  char *base = static_cast<char *>(m.addr);

  std::vector<Uint8> expected(TEST_FILE_SIZE, 0);
  OK(memcmp(base, expected.data(), TEST_FILE_SIZE) == 0);
  test_prefault(base, expected, m.map_sync, dir);

  const std::vector<TestVariant> variants = test_variants();
  size_t at = 0;
  for (const TestVariant &v : variants) {
    use_variant(v);
    printf("ndb_pmem: method %s tested\n", ndb_pmem_method_name());
    test_writes(base, expected, at);
    at = (at + 128 * 1024) % TEST_FILE_SIZE;
  }
  test_timing(base, variants);
  /* The timing wrote the first MB */
  ndb_pmem_drain();
  memcpy(expected.data(), base, size_t(1) << 20);
  OK(ndb_pmem_init(NDB_PMEM_COPY_AUTO) == 0);

  /* What the mapping holds is in the file */
  OK(ndb_pmem_unmap(&m) == 0);
  OK(m.addr == nullptr);
  std::vector<Uint8> file(TEST_FILE_SIZE);
  OK(pread(f.fd, file.data(), TEST_FILE_SIZE, 0) == (ssize_t)TEST_FILE_SIZE);
  OK(memcmp(file.data(), expected.data(), TEST_FILE_SIZE) == 0);
  remove_file(&f);
}

/**
 * Threads that map, fault in, write and read back their own files at the
 * same time, as the NDBFS IO threads do. Without DAX the MAP_SYNC attempt
 * fails; that must not leave a gap that another thread maps into, which
 * Linux 6.11 does for a refused MAP_FIXED mmap. Before the fix the fault
 * in failed with ENOMEM, or a page held another thread's tag.
 */
void test_concurrent_maps(const char *dir) {
  constexpr Uint32 THREADS = 8;
  constexpr Uint32 PASSES = 30;
  std::atomic<Uint32> failures{0};
  auto run = [&](Uint32 thread_no) {
    for (Uint32 pass = 0; pass < PASSES; pass++) {
      TestFile f;
      if (!create_file(dir, &f)) {
        failures++;
        return;
      }
      ndb_pmem_mapping m;
      int r =
          ndb_pmem_map(f.fd, TEST_FILE_SIZE, NDB_PMEM_MAP_SYNC_OPTIONAL, &m);
      const char *step = "map";
      if (r == 0) {
        step = "prefault";
        r = ndb_pmem_prefault(m.addr, TEST_FILE_SIZE);
      }
      if (r == 0) {
        step = "read back";
        volatile Uint64 *base = static_cast<volatile Uint64 *>(m.addr);
        const Uint64 tag = (Uint64(thread_no) << 48) | (Uint64(pass) << 32);
        for (size_t off = 0; off < TEST_FILE_SIZE; off += 4096) {
          base[off / sizeof(Uint64)] = tag | off;
        }
        for (size_t off = 0; off < TEST_FILE_SIZE; off += 4096) {
          if (base[off / sizeof(Uint64)] != (tag | off)) r = -1;
        }
      }
      if (r != 0 && failures++ == 0) {
        printf("ndb_pmem: thread %u pass %u: %s failed: %s\n", thread_no, pass,
               step, r > 0 ? strerror(r) : "a page holds another tag");
      }
      ndb_pmem_unmap(&m);
      remove_file(&f);
      if (r != 0) return;
    }
  };
  std::vector<std::thread> threads;
  for (Uint32 t = 0; t < THREADS; t++) threads.emplace_back(run, t);
  for (std::thread &t : threads) t.join();
  printf("ndb_pmem: %u threads mapped %u files each at the same time in %s: "
         "%u failed\n",
         THREADS, PASSES, dir, failures.load());
  OK(failures.load() == 0);
}

constexpr size_t LINE_BYTES = NDB_PMEM_LINE;

/* The lines [line, line + n) of base hold the byte v */
bool lines_hold(const Uint8 *base, size_t line, size_t n, Uint8 v) {
  for (size_t i = line * LINE_BYTES; i < (line + n) * LINE_BYTES; i++) {
    if (base[i] != v) return false;
  }
  return true;
}

/* n lines at line, of the byte v, each copied and drained: persistent */
void persist_lines(Uint8 *base, size_t line, size_t n, Uint8 v) {
  alignas(NDB_PMEM_LINE) Uint8 src[LINE_BYTES];
  memset(src, v, LINE_BYTES);
  for (size_t i = 0; i < n; i++) {
    ndb_pmem_copy_nt(base + (line + i) * LINE_BYTES, src, LINE_BYTES);
    ndb_pmem_drain();
  }
}

/* n lines at line, of the byte v, copied and not drained */
void write_lines(Uint8 *base, size_t line, size_t n, Uint8 v) {
  alignas(NDB_PMEM_LINE) Uint8 src[LINE_BYTES];
  memset(src, v, LINE_BYTES);
  for (size_t i = 0; i < n; i++) {
    ndb_pmem_copy_nt(base + (line + i) * LINE_BYTES, src, LINE_BYTES);
  }
}

/**
 * The power-loss emulation (S1.5) on a file in dir: what a drain made
 * persistent stays and the rest is restored, kept or torn; a store needs
 * its flush; a full list makes its oldest line persistent early; a line
 * pending in two threads is seen; a write waits while frozen. Runs last,
 * as the emulation stays on.
 */
void test_emulation(const char *dir) {
  constexpr Uint32 MAX_PENDING = 64;
  OK(ndb_pmem_emul_enable(0) == EINVAL);
  OK(ndb_pmem_emul_enable(MAX_PENDING) == 0);
  OK(ndb_pmem_emul_enable(MAX_PENDING) == 0);
  OK(ndb_pmem_emul_enable(MAX_PENDING + 1) == EBUSY);
  OK(ndb_pmem_emul_active());
  TestFile f;
  OK(create_file(dir, &f));
  ndb_pmem_mapping m;
  OK(ndb_pmem_map(f.fd, TEST_FILE_SIZE, NDB_PMEM_MAP_SYNC_OPTIONAL, &m) == 0);
  Uint8 *const base = static_cast<Uint8 *>(m.addr);
  ndb_pmem_emul_stats st;

  /* 3 lines drained, 2 not: the power loss restores the 2 */
  persist_lines(base, 0, 5, 0x11);
  OK(ndb_pmem_emul_pending() == 0);
  persist_lines(base, 0, 3, 0x22);
  write_lines(base, 3, 2, 0x22);
  OK(ndb_pmem_emul_pending() == 2);
  OK(lines_hold(base, 3, 2, 0x22));
  OK(ndb_pmem_emul_range_pending(base + 3 * LINE_BYTES + 8, 8));
  OK(!ndb_pmem_emul_range_pending(base, 3 * LINE_BYTES));
  ndb_pmem_emul_power_fail(1, 0, 0);
  OK(lines_hold(base, 0, 3, 0x22));
  OK(lines_hold(base, 3, 2, 0x11));
  ndb_pmem_emul_get_stats(&st);
  OK(st.reverted == 2 && st.persisted == 8 && st.written == 10);
  ndb_pmem_emul_reset();

  /* A store with no flush stays pending after the drain */
  Uint32 *const w32 = reinterpret_cast<Uint32 *>(base + 8 * LINE_BYTES);
  ndb_pmem_store32(w32, 7);
  ndb_pmem_flush(w32, sizeof(Uint32));
  ndb_pmem_drain();
  OK(ndb_pmem_emul_pending() == 0);
  ndb_pmem_store32(w32, 8);
  ndb_pmem_drain();
  OK(ndb_pmem_emul_pending() == 1);
  ndb_pmem_emul_power_fail(2, 0, 0);
  OK(*w32 == 7);
  ndb_pmem_emul_reset();
  Uint64 *const w64 = reinterpret_cast<Uint64 *>(base + 9 * LINE_BYTES);
  ndb_pmem_store64(w64, 9);
  ndb_pmem_flush(w64, sizeof(Uint64));
  ndb_pmem_drain();
  OK(ndb_pmem_emul_pending() == 0);

  /* keep 1000: every pending line stays new */
  persist_lines(base, 16, 8, 0x11);
  write_lines(base, 16, 8, 0x22);
  ndb_pmem_emul_power_fail(3, 1000, 0);
  OK(lines_hold(base, 16, 8, 0x22));
  ndb_pmem_emul_get_stats(&st);
  OK(st.kept == 8 && st.reverted == 0);
  ndb_pmem_emul_reset();

  /* tear 1000: each 8-byte word whole, old or new */
  persist_lines(base, 24, 8, 0x11);
  write_lines(base, 24, 8, 0x22);
  ndb_pmem_emul_power_fail(4, 0, 1000);
  Uint32 old_words = 0;
  bool whole = true;
  for (size_t i = 24 * LINE_BYTES; i < 32 * LINE_BYTES; i += 8) {
    const bool is_old =
        memcmp(base + i, "\x11\x11\x11\x11\x11\x11\x11\x11", 8) == 0;
    const bool is_new =
        memcmp(base + i, "\x22\x22\x22\x22\x22\x22\x22\x22", 8) == 0;
    whole = whole && (is_old || is_new);
    old_words += is_old;
  }
  OK(whole);
  ndb_pmem_emul_get_stats(&st);
  OK(st.torn == 8);
  printf("ndb_pmem: emulation: 8 torn lines kept %u of 64 words old\n",
         old_words);
  ndb_pmem_emul_reset();

  /* A zeroing that starts and ends inside lines restores both lines */
  persist_lines(base, 32, 2, 0x22);
  ndb_pmem_zero(base + 32 * LINE_BYTES + 24, 80);
  OK(ndb_pmem_emul_pending() == 2);
  ndb_pmem_emul_power_fail(5, 0, 0);
  OK(lines_hold(base, 32, 2, 0x22));
  ndb_pmem_emul_reset();

  /* A full list makes its oldest line persistent early */
  persist_lines(base, 64, MAX_PENDING + 16, 0x11);
  write_lines(base, 64, MAX_PENDING + 16, 0x22);
  OK(ndb_pmem_emul_pending() == MAX_PENDING);
  ndb_pmem_emul_power_fail(6, 0, 0);
  OK(lines_hold(base, 64, 16, 0x22));
  OK(lines_hold(base, 80, MAX_PENDING, 0x11));
  ndb_pmem_emul_get_stats(&st);
  OK(st.evicted_early == 16 && st.reverted == MAX_PENDING);
  ndb_pmem_emul_reset();

  /* A line pending in two threads is seen */
  std::thread other([&] { write_lines(base, 200, 1, 0x33); });
  other.join();
  write_lines(base, 200, 1, 0x44);
  ndb_pmem_emul_get_stats(&st);
  OK(st.shared == 1);
  ndb_pmem_emul_reset();

  /* Frozen, a write waits; nothing under way, the freeze stops all */
  OK(ndb_pmem_emul_freeze() == 0);
  std::atomic<bool> done{false};
  std::thread writer([&] {
    write_lines(base, 210, 1, 0x55);
    done = true;
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  OK(!done.load());
  ndb_pmem_emul_reset();
  writer.join();
  OK(done.load());
  OK(lines_hold(base, 210, 1, 0x55));
  ndb_pmem_emul_reset();

  /* An unmap leaves nothing pending */
  write_lines(base, 220, 1, 0x66);
  OK(ndb_pmem_emul_pending() == 1);
  OK(ndb_pmem_unmap(&m) == 0);
  OK(ndb_pmem_emul_pending() == 0);
  remove_file(&f);
  printf("ndb_pmem: power-loss emulation tested\n");
}

#endif

}  // namespace

TAPTEST(ndb_pmem) {
#ifdef _WIN32
  printf("ndb_pmem: not tested on Windows\n");
#else
  test_init();
  const char *tmp = getenv("TMPDIR");
  const char *tmp_dir = (tmp != nullptr && *tmp != 0) ? tmp : "/tmp";
  test_dir(tmp_dir, false);
  test_concurrent_maps(tmp_dir);
  /* A directory on a DAX file system, e.g. ext4 with -o dax on memmap= */
  const char *dax_dir = getenv("NDB_PMEM_DIR");
  if (dax_dir != nullptr && *dax_dir != 0) {
    test_dir(dax_dir, true);
  } else {
    printf("ndb_pmem: set NDB_PMEM_DIR to a DAX directory to test MAP_SYNC\n");
  }
  /* Last: the emulation stays on */
  test_emulation(tmp_dir);
#endif
  return 1;
}

#endif
