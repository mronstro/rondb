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

#include <string.h>
#include <atomic>

#include <portlib/NdbHW.hpp>
#include <util/ndb_xxh3.h>
#include <util/rondb_hash.hpp>
#include "my_compiler.h"

/**
 * On x86-64 the AVX2 code of XXH3 is compiled with a target attribute
 * and chosen at run time, as xxhash's own xxh_x86dispatch.c does, so
 * the build needs no -mavx2. XXH_X86DISPATCH aligns the accumulator
 * for AVX2 and keeps the SSE2 code. Other platforms, and builds with
 * -mavx512f, use the code the build chose, NEON on aarch64.
 */
#if defined(__x86_64__) && defined(__GNUC__) && !defined(_WIN32) && \
    !defined(__AVX512F__)
#define NDB_XXH3_X86_DISPATCH
#define XXH_DISPATCH_AVX2 1
#define XXH_TARGET_AVX2 __attribute__((target("avx2")))
#define XXH_X86DISPATCH
#include <immintrin.h>
#endif

#define XXH_INLINE_ALL
#include <util/ndb_xxhash.h>

namespace {

/**
 * Hash an input of more than XXH3_MIDSIZE_MAX bytes, with the default
 * secret when seed is 0 and with a secret made from the seed otherwise,
 * as XXH3_64bits_withSeed() does. The signature is XXH3_hashLong64_f;
 * the secret arguments are not used.
 */
#ifdef NDB_XXH3_X86_DISPATCH
XXH_NO_INLINE XXH_TARGET_AVX2 XXH64_hash_t
hash_long_avx2(const void *XXH_RESTRICT input, size_t len, XXH64_hash_t seed,
               const xxh_u8 *XXH_RESTRICT, size_t) {
  return XXH3_hashLong_64b_withSeed_internal(
      input, len, seed, XXH3_accumulate_avx2, XXH3_scrambleAcc_avx2,
      XXH3_initCustomSecret_avx2);
}

XXH_NO_INLINE XXH64_hash_t hash_long_sse2(const void *XXH_RESTRICT input,
                                          size_t len, XXH64_hash_t seed,
                                          const xxh_u8 *XXH_RESTRICT,
                                          size_t) {
  return XXH3_hashLong_64b_withSeed_internal(
      input, len, seed, XXH3_accumulate_sse2, XXH3_scrambleAcc_sse2,
      XXH3_initCustomSecret_sse2);
}
#else
XXH_NO_INLINE XXH64_hash_t hash_long_build(const void *XXH_RESTRICT input,
                                           size_t len, XXH64_hash_t seed,
                                           const xxh_u8 *XXH_RESTRICT,
                                           size_t) {
  return XXH3_hashLong_64b_withSeed_internal(input, len, seed,
                                             XXH3_accumulate, XXH3_scrambleAcc,
                                             XXH3_initCustomSecret);
}

/* The name of the code the build chose */
const char *build_name() {
#if XXH_VECTOR == XXH_AVX512
  return "avx512";
#elif XXH_VECTOR == XXH_AVX2
  return "avx2";
#elif XXH_VECTOR == XXH_SSE2
  return "sse2";
#elif XXH_VECTOR == XXH_NEON
  return "neon";
#elif XXH_VECTOR == XXH_SVE
  return "sve";
#elif XXH_VECTOR == XXH_VSX
  return "vsx";
#else
  return "scalar";
#endif
}
#endif

struct Choice {
  XXH3_hashLong64_f hash_long;
  const char *name;
};

Choice choose() {
#ifdef NDB_XXH3_X86_DISPATCH
  if (Ndb_GetCpuFeatures()->avx2) {
    return {hash_long_avx2, "avx2"};
  }
  return {hash_long_sse2, "sse2"};
#else
  return {hash_long_build, build_name()};
#endif
}

const Choice &choice() {
  static const Choice the_choice = choose();
  return the_choice;
}

XXH64_hash_t hash_long_first_call(const void *XXH_RESTRICT input, size_t len,
                                  XXH64_hash_t seed,
                                  const xxh_u8 *XXH_RESTRICT secret,
                                  size_t secret_len);

/**
 * Relaxed loads are enough: both values are correct functions, the
 * first call only makes the choice.
 */
std::atomic<XXH3_hashLong64_f> g_hash_long{hash_long_first_call};

XXH64_hash_t hash_long_first_call(const void *XXH_RESTRICT input, size_t len,
                                  XXH64_hash_t seed,
                                  const xxh_u8 *XXH_RESTRICT secret,
                                  size_t secret_len) {
  ndb_xxh3_init();
  return g_hash_long.load(std::memory_order_relaxed)(input, len, seed, secret,
                                                     secret_len);
}

inline Uint64 xxh3_64(const void *buf, size_t len, Uint64 seed) {
  if (likely(len <= XXH3_MIDSIZE_MAX)) {
    return XXH3_64bits_internal(buf, len, seed, XXH3_kSecret,
                                sizeof(XXH3_kSecret), nullptr);
  }
  return g_hash_long.load(std::memory_order_relaxed)(
      buf, len, seed, XXH3_kSecret, sizeof(XXH3_kSecret));
}

}  // namespace

Uint64 ndb_xxh3_64(const void *buf, size_t len) {
  return xxh3_64(buf, len, 0);
}

Uint64 ndb_xxh3_64_seed(const void *buf, size_t len, Uint64 seed) {
  return xxh3_64(buf, len, seed);
}

void ndb_xxh3_init() {
  g_hash_long.store(choice().hash_long, std::memory_order_relaxed);
}

const char *ndb_xxh3_implementation() { return choice().name; }

Uint64 rondb_xxhash_std(const char *keybuf, Uint32 keylen_bytes) {
  return xxh3_64(keybuf, keylen_bytes, 0);
}

#ifdef TEST_NDB_XXH3

#include <util/NdbTap.hpp>
#include <algorithm>
#include <chrono>
#include <vector>

namespace {

XXH_NO_INLINE XXH64_hash_t hash_long_scalar(const void *XXH_RESTRICT input,
                                            size_t len, XXH64_hash_t seed,
                                            const xxh_u8 *XXH_RESTRICT,
                                            size_t) {
  return XXH3_hashLong_64b_withSeed_internal(
      input, len, seed, XXH3_accumulate_scalar, XXH3_scrambleAcc_scalar,
      XXH3_initCustomSecret_scalar);
}

struct TestVariant {
  const char *name;
  XXH3_hashLong64_f hash_long;
  bool available;
};

/* Every implementation this platform has, scalar first */
std::vector<TestVariant> test_variants() {
  std::vector<TestVariant> variants;
  variants.push_back({"scalar", hash_long_scalar, true});
#ifdef NDB_XXH3_X86_DISPATCH
  variants.push_back({"sse2", hash_long_sse2, true});
  variants.push_back({"avx2", hash_long_avx2, Ndb_GetCpuFeatures()->avx2});
#else
  if (strcmp(build_name(), "scalar") != 0) {
    variants.push_back({build_name(), hash_long_build, true});
  }
#endif
  return variants;
}

Uint64 variant_hash(const TestVariant &v, const void *buf, size_t len,
                    Uint64 seed) {
  if (len <= XXH3_MIDSIZE_MAX) {
    return XXH3_64bits_internal(buf, len, seed, XXH3_kSecret,
                                sizeof(XXH3_kSecret), nullptr);
  }
  return v.hash_long(buf, len, seed, XXH3_kSecret, sizeof(XXH3_kSecret));
}

Uint64 test_rand() {
  static Uint64 state = 0x9E3779B97F4A7C15ULL;
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return state;
}

void check(bool cond, const char *what, const char *variant, size_t len,
           size_t offset, Uint64 seed) {
  if (!cond) {
    printf("FAILED: %s, %s, length %zu, offset %zu, seed 0x%llx\n", what,
           variant, len, offset, (unsigned long long)seed);
  }
  OK(cond);
}

void test_known_values() {
  /* The hash of no bytes, from xxhash's own test vectors */
  const Uint64 empty = 0x2D06800538D394C2ULL;
  OK(XXH3_64bits("", 0) == empty);
  OK(ndb_xxh3_64("", 0) == empty);
  OK(ndb_xxh3_64_seed("", 0, 0) == empty);
}

/**
 * Every implementation against the header's XXH3, which is what the
 * hash of keys was before: all lengths up to two 1024-byte blocks,
 * some long ones, every alignment, with and without a seed.
 */
void test_against_header(const std::vector<TestVariant> &variants) {
  std::vector<size_t> lengths;
  for (size_t len = 0; len <= 2100; len++) {
    lengths.push_back(len);
  }
  const size_t long_lengths[] = {4095, 4096, 4097, 16384, 32768, 92520, 100003};
  for (size_t len : long_lengths) {
    lengths.push_back(len);
  }
  std::vector<Uint8> data(100003 + 8);
  for (Uint8 &b : data) {
    b = (Uint8)test_rand();
  }
  for (size_t len : lengths) {
    for (size_t offset = 0; offset < 8; offset++) {
      const Uint8 *p = data.data() + offset;
      const Uint64 seed = (offset & 1) ? test_rand() : 0;
      const Uint64 expected = XXH3_64bits_withSeed(p, len, seed);
      if (seed == 0) {
        check(XXH3_64bits(p, len) == expected, "XXH3_64bits", "header", len,
              offset, seed);
        check(ndb_xxh3_64(p, len) == expected, "ndb_xxh3_64",
              ndb_xxh3_implementation(), len, offset, seed);
      }
      check(ndb_xxh3_64_seed(p, len, seed) == expected, "ndb_xxh3_64_seed",
            ndb_xxh3_implementation(), len, offset, seed);
      for (const TestVariant &v : variants) {
        if (v.available) {
          check(variant_hash(v, p, len, seed) == expected, "variant", v.name,
                len, offset, seed);
        }
      }
    }
  }
}

/* The hash of keys and the distribution hash are the header's XXH3 */
void test_rondb_hash() {
  std::vector<Uint32> key(2048);
  for (Uint32 &w : key) {
    w = (Uint32)test_rand();
  }
  const char *p = reinterpret_cast<const char *>(key.data());
  const Uint32 words[] = {0, 1, 4, 60, 61, 255, 256, 2048};
  for (Uint32 n : words) {
    const Uint64 expected = XXH3_64bits(p, 4 * n);
    OK(rondb_xxhash_std(p, 4 * n) == expected);
    Uint32 hash_val[4];
    rondb_calc_hash(hash_val, p, n, true);
    OK(hash_val[0] == (Uint32)expected);
    OK(hash_val[1] == (Uint32)(expected >> 32));
  }
}

/**
 * Informational: nanoseconds per hash for the sizes of the REDO records
 * (bytes checksummed: 4 + 4 * (words - 2) + 16), for every
 * implementation, and for the checksum of a record: the body in one
 * call, then a seeded hash of the 20 bytes of type word and position
 * suffix, seeded with the body's hash. Nothing is checked here. Each
 * result changes the input of the next call, so the calls form a chain,
 * as when records are written one after the other.
 */
void test_timing(const std::vector<TestVariant> &variants) {
  const size_t sizes[] = {20, 28, 60, 124, 300, 1000, 32768, 92520};
  std::vector<Uint64> storage(92520 / 8 + 1);
  Uint8 *buf = reinterpret_cast<Uint8 *>(storage.data());
  for (size_t i = 0; i < 92520; i++) {
    buf[i] = (Uint8)test_rand();
  }
  printf("ndb_xxh3: %s, ns per hash; record = checksum of a REDO record\n",
         ndb_xxh3_implementation());
  printf("%8s", "bytes");
  for (const TestVariant &v : variants) {
    printf(" %10s", v.name);
  }
  printf(" %10s\n", "record");
  typedef std::chrono::steady_clock clock;
  Uint64 sink = 0;
  for (size_t len : sizes) {
    const size_t iterations = std::max<size_t>(2000, (64 << 20) / len);
    const size_t body = len - 20;
    printf("%8zu", len);
    for (size_t m = 0; m <= variants.size(); m++) {
      const bool record = (m == variants.size());
      if (!record && !variants[m].available) {
        printf(" %10s", "-");
        continue;
      }
      Uint64 h = 0;
      const auto start = clock::now();
      for (size_t i = 0; i < iterations; i++) {
        buf[0] ^= (Uint8)h;
        if (!record) {
          h = variant_hash(variants[m], buf, len, 0);
        } else {
          /* The body takes part in the chain too, or the compiler
             could hash it once, outside the loop */
          buf[4] ^= (Uint8)h;
          Uint8 tail[20];
          memcpy(tail, buf, 4);
          memcpy(tail + 4, buf + 4 + body, 16);
          h = (Uint32)ndb_xxh3_64_seed(tail, sizeof(tail),
                                       ndb_xxh3_64(buf + 4, body));
        }
      }
      const auto stop = clock::now();
      sink += h;
      printf(" %10.1f",
             std::chrono::duration<double, std::nano>(stop - start).count() /
                 (double)iterations);
    }
    printf("\n");
  }
  printf("(sink %llu)\n", (unsigned long long)sink);
}

}  // namespace

TAPTEST(ndb_xxh3) {
  /* Inputs up to 240 bytes do not need the choice */
  OK(ndb_xxh3_64("", 0) == 0x2D06800538D394C2ULL);
  ndb_xxh3_init();
  ndb_xxh3_init();
  printf("ndb_xxh3 implementation: %s\n", ndb_xxh3_implementation());
#ifdef NDB_XXH3_X86_DISPATCH
  OK(strcmp(ndb_xxh3_implementation(),
            Ndb_GetCpuFeatures()->avx2 ? "avx2" : "sse2") == 0);
#endif

  const std::vector<TestVariant> variants = test_variants();
  for (const TestVariant &v : variants) {
    printf("variant %-8s %s\n", v.name,
           v.available ? "tested" : "not supported by this CPU");
  }

  test_known_values();
  test_against_header(variants);
  test_rondb_hash();
  test_timing(variants);
  return 1;
}

#endif
