/*****************************************************************************

Copyright (c) 2009, 2010 Facebook, Inc.
Copyright (c) 2011, 2026, Oracle and/or its affiliates.
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

*****************************************************************************/

/* Copyright (C) 2009-2010 Facebook, Inc.  All Rights Reserved.

   Dual licensed under BSD license and GPLv2.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY FACEBOOK, INC. ``AS IS'' AND ANY EXPRESS OR
   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
   EVENT SHALL FACEBOOK, INC. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
   OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
   OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
   more details.

   You should have received a copy of the GNU General Public License along with
   this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA */

/* The below CRC32 implementation is based on the implementation included with
zlib with modifications to process 8 bytes at a time and using SSE 4.2
extensions when available.  The polynomial constant has been changed to
match the one used by SSE 4.2 and does not return the same value as the
version used by zlib.  The original zlib copyright notice follows. */

/* crc32.c -- compute the CRC-32 of a buf stream
Copyright (C) 1995-2005 Mark Adler
For conditions of distribution and use, see copyright notice in zlib.h

Thanks to Rodney Brown <rbrown64@csc.com.au> for his contribution of faster
CRC methods: exclusive-oring 32 bits of buf at a time, and pre-computing
tables for updating the shift register in one step with three exclusive-ors
instead of four steps with four exclusive-ors.  This results in about a
factor of two increase in speed on a Power PC G4 (PPC7455) using gcc -O3.
 */

/**
 * CRC-32C for NDB, ported from InnoDB's storage/innobase/ut/crc32.cc.
 *
 * Changes from the InnoDB code:
 * - Every variant takes the CRC so far and returns the new one, so a
 *   checksum can be computed over several pieces (zlib convention).
 * - The choice of variant uses Ndb_GetCpuFeatures() and is made at the
 *   first call, or by ndb_crc32c_init().
 * - Words are read with memcpy instead of pointer casts.
 * - Only the CRC-32C variants are kept: no legacy big-endian variant, no
 *   Windows hardware path. Big-endian and Windows use the software code.
 */

#include <ndb_global.h>

#include <string.h>
#include <atomic>
#include <utility>

#include <portlib/NdbHW.hpp>
#include <util/ndb_crc32c.h>
#include "my_compiler.h"
#include "my_config.h"

#if defined(WORDS_BIGENDIAN)
#define NDB_CRC32C_SOFTWARE_ONLY
#elif defined(__GNUC__) && defined(__x86_64__) && !defined(_WIN32)
#define NDB_CRC32C_X86_64
#elif defined(__GNUC__) && defined(__aarch64__)
#define NDB_CRC32C_ARM64
#if defined(__APPLE__)
/* Apple ARM: CRC32 and PMULL are always there, no target attributes */
#define NDB_CRC32C_ARM64_APPLE
#else
#define NDB_CRC32C_ARM64_DEFAULT
#endif
#else
#define NDB_CRC32C_SOFTWARE_ONLY
#endif

#ifdef NDB_CRC32C_X86_64
#include <nmmintrin.h>
#include <wmmintrin.h>
#endif

#ifdef NDB_CRC32C_ARM64
#include <arm_acle.h>
#include <arm_neon.h>
#endif

typedef Uint32 (*ndb_crc32c_func_t)(Uint32 crc, const Uint8 *buf, size_t len);

namespace {

/** Reads a T from a possibly unaligned address. */
template <typename T>
inline T load(const Uint8 *p) {
  T v;
  memcpy(&v, p, sizeof(v));
  return v;
}

/* CRC32 software implementation. */
namespace software {

#ifdef WORDS_BIGENDIAN
/** Swap the byte order of an 8 byte integer.
@param[in]      i       8-byte integer
@return 8-byte integer */
inline uint64_t swap_byteorder(uint64_t i) {
  return (i << 56 | (i & 0x000000000000FF00ULL) << 40 |
          (i & 0x0000000000FF0000ULL) << 24 | (i & 0x00000000FF000000ULL) << 8 |
          (i & 0x000000FF00000000ULL) >> 8 | (i & 0x0000FF0000000000ULL) >> 24 |
          (i & 0x00FF000000000000ULL) >> 40 | i >> 56);
}
#endif

/* Precalculated table used to generate the CRC32 if the CPU does not
have support for it */
uint32_t crc32_slice8_table[8][256];

/** Initializes the table that is used to generate the CRC32 if the CPU does
 not have support for it. */
void crc32_slice8_table_init() {
  /* bit-reversed poly 0x1EDC6F41 (from SSE42 crc32 instruction) */
  static const uint32_t poly = 0x82f63b78;
  uint32_t n;
  uint32_t k;
  uint32_t c;

  for (n = 0; n < 256; n++) {
    c = n;
    for (k = 0; k < 8; k++) {
      c = (c & 1) ? (poly ^ (c >> 1)) : (c >> 1);
    }
    crc32_slice8_table[0][n] = c;
  }

  for (n = 0; n < 256; n++) {
    c = crc32_slice8_table[0][n];
    for (k = 1; k < 8; k++) {
      c = crc32_slice8_table[0][c & 0xFF] ^ (c >> 8);
      crc32_slice8_table[k][n] = c;
    }
  }
}

/** Calculate CRC32 over 8-bit data using a software implementation.
@param[in,out]  crc     crc32 checksum so far when this function is called,
when the function ends it will contain the new checksum
@param[in,out]  data    data to be checksummed, the pointer will be advanced
with 1 byte
@param[in,out]  len     remaining bytes, it will be decremented with 1 */
inline void crc32_8(uint32_t *crc, const Uint8 **data, size_t *len) {
  const uint8_t i = (*crc ^ (*data)[0]) & 0xFF;

  *crc = (*crc >> 8) ^ crc32_slice8_table[0][i];

  (*data)++;
  (*len)--;
}

/** Calculate CRC32 over a 64-bit integer using a software implementation.
@param[in]      crc     crc32 checksum so far
@param[in]      data    data to be checksummed
@return resulting checksum of crc + crc(data) */
inline uint32_t crc32_64_low(uint32_t crc, uint64_t data) {
  const uint64_t i = crc ^ data;

  return (crc32_slice8_table[7][(i)&0xFF] ^
          crc32_slice8_table[6][(i >> 8) & 0xFF] ^
          crc32_slice8_table[5][(i >> 16) & 0xFF] ^
          crc32_slice8_table[4][(i >> 24) & 0xFF] ^
          crc32_slice8_table[3][(i >> 32) & 0xFF] ^
          crc32_slice8_table[2][(i >> 40) & 0xFF] ^
          crc32_slice8_table[1][(i >> 48) & 0xFF] ^
          crc32_slice8_table[0][(i >> 56)]);
}

/** Calculate CRC32 over 64-bit byte string using a software implementation.
@param[in,out]  crc     crc32 checksum so far when this function is called,
when the function ends it will contain the new checksum
@param[in,out]  data    data to be checksummed, the pointer will be advanced
with 8 bytes
@param[in,out]  len     remaining bytes, it will be decremented with 8 */
inline void crc32_64(uint32_t *crc, const Uint8 **data, size_t *len) {
  uint64_t data_int = load<uint64_t>(*data);

#ifdef WORDS_BIGENDIAN
  data_int = swap_byteorder(data_int);
#endif /* WORDS_BIGENDIAN */

  *crc = crc32_64_low(*crc, data_int);

  *data += 8;
  *len -= 8;
}

/** Calculates CRC32 in software, without using CPU instructions.
@param[in]     crc_in  CRC so far, 0 for the first piece
@param[in]     buf     data over which to calculate CRC32
@param[in]     len     data length
@return CRC-32C (polynomial 0x11EDC6F41) */
Uint32 crc32c(Uint32 crc_in, const Uint8 *buf, size_t len) {
  uint32_t crc = ~crc_in;

  /* Calculate byte-by-byte up to an 8-byte aligned address. After
  this consume the input 8-bytes at a time. */
  while (len > 0 && (reinterpret_cast<uintptr_t>(buf) & 7) != 0) {
    crc32_8(&crc, &buf, &len);
  }

  while (len >= 128) {
    /* This call is repeated 16 times. 16 * 8 = 128. */
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
    crc32_64(&crc, &buf, &len);
  }

  while (len >= 8) {
    crc32_64(&crc, &buf, &len);
  }

  while (len > 0) {
    crc32_8(&crc, &buf, &len);
  }

  return ~crc;
}
} /* namespace software */

#ifndef NDB_CRC32C_SOFTWARE_ONLY

namespace hardware {

/** The CRC-32C polynomial without the implicit highest 1 at x^32 */
constexpr uint32_t CRC32C_POLYNOMIAL{0x1EDC6F41};

/** A helper template to statically unroll a loop with a fixed number of
iterations, where the iteration number itself is constexpr. So, instead of:

   Something::template run<0>(a,b);
   Something::template run<1>(a,b);
   Something::template run<2>(a,b);

you can write:

    Loop<3>::template run<Something>(a, b);
*/
template <size_t iterations>
struct Loop {
  template <typename Step_executor, typename... Args>
  static void run(Args &&...args) {
    Loop<iterations - 1>::template run<Step_executor, Args...>(
        std::forward<Args>(args)...);
    Step_executor::template run<iterations - 1>(std::forward<Args>(args)...);
  }
};
template <>
struct Loop<0> {
  template <typename Step_executor, typename... Args>
  static void run(Args &&...) {}
};

/** Computes x^(len*8) modulo CRC32-C polynomial, which is useful, when you need
to conceptually append len bytes of zeros to already computed hash.
@param[in]  len   The value of len in the x^(len*8) mod CRC32-C
@return the rest of x^(len*8) mod CRC32-C, with the most significant coefficient
of the resulting rest - the one which is for x^31 - stored as the most
significant bit of the uint32_t (the one at 1U<<31) */
constexpr uint32_t compute_x_to_8len(size_t len) {
  // The x^(len*8) mod CRC32 polynomial depends on len only.
  uint32_t x_to_8len = 1;
  // push len bytes worth of zeros
  for (size_t i = 0; i < len * 8; ++i) {
    const bool will_wrap = x_to_8len >> 31 & 1;
    x_to_8len <<= 1;
    if (will_wrap) x_to_8len ^= CRC32C_POLYNOMIAL;
  }
  return x_to_8len;
}

/** Produces a 64-bit result by moving i-th bit of 32-bit input to the
32-i-th position (zeroing the other bits). Please note that in particular this
moves 0-th bit to 32-nd, and 31-st bit to 1-st, so the range in which data
resides is not only mirrored, but also shifted one bit. Such operation is useful
for implementing polynomial multiplication when one of the operands is given in
reverse and we need the result reversed, too (as is the case in CRC32-C):
    rev(w * v) =   rev(w)*flip_at_32(v)
proof:
    rev(w * v)[i] = (w * v)[63-i] = sum(0<=j<=31){w[j]*v[63-i-j]} =
    sum(0<=j<=31){rev(w)[31-j]*v[63-i-j]} =
    sum(0<=j<=31){rev(w)[31-j]*flip_at_32(v)[32-63+i+j]} =
    sum(0<=j<=31){rev(w)[31-j]*flip_at_32(v)[i-(j-31)]} =
    sum(0<=j<=31){rev(w)[j]*flip_at_32(v)[i-j]} =
    rev(w)*flip_at_32(v)[i]
So, for example, if crc32=rev(w) is the variable storing the CRC32-C hash of a
buffer, and you want to conceptually append len bytes of zeros to it, then you
can precompute v = compute_x_to_8len(len), and are interested in rev(w*v), which
you can achieve by crc32 * flip_at_32(compute_x_to_8len(len)).
@param[in]  w   The input 32-bit polynomial
@return The polynomial flipped and shifted, so that i-th bit becomes 32-i-th. */
constexpr uint64_t flip_at_32(uint32_t w) {
  uint64_t f{0};
  for (int i = 0; i < 32; ++i) {
    if (((w >> i) & 1)) {
      f ^= uint64_t{1} << (32 - i);
    }
  }
  return f;
}

/** The collection of functions implementing hardware accelerated updating of
CRC32-C hash by processing a few (1,2,4 or 8) bytes of input. They are grouped
together in a type, so it's easier to swap their implementation by providing
algo_to_use template argument to higher level functions. */
struct crc32_impl {
  static inline uint32_t update(uint32_t crc, unsigned char data);
  static inline uint32_t update(uint32_t crc, uint16_t data);
  static inline uint32_t update(uint32_t crc, uint32_t data);
  static inline uint64_t update(uint64_t crc, uint64_t data);
};

#ifdef NDB_CRC32C_X86_64
MY_ATTRIBUTE((target("sse4.2")))
uint32_t crc32_impl::update(uint32_t crc, unsigned char data) {
  return _mm_crc32_u8(crc, data);
}
MY_ATTRIBUTE((target("sse4.2")))
uint32_t crc32_impl::update(uint32_t crc, uint16_t data) {
  return _mm_crc32_u16(crc, data);
}
MY_ATTRIBUTE((target("sse4.2")))
uint32_t crc32_impl::update(uint32_t crc, uint32_t data) {
  return _mm_crc32_u32(crc, data);
}
MY_ATTRIBUTE((target("sse4.2")))
uint64_t crc32_impl::update(uint64_t crc, uint64_t data) {
  return _mm_crc32_u64(crc, data);
}
#endif /* NDB_CRC32C_X86_64 */

#ifdef NDB_CRC32C_ARM64
#ifdef NDB_CRC32C_ARM64_DEFAULT
MY_ATTRIBUTE((target("+crc")))
#endif /* NDB_CRC32C_ARM64_DEFAULT */
uint32_t crc32_impl::update(uint32_t crc, unsigned char data) {
  return __crc32cb(crc, data);
}
#ifdef NDB_CRC32C_ARM64_DEFAULT
MY_ATTRIBUTE((target("+crc")))
#endif /* NDB_CRC32C_ARM64_DEFAULT */
uint32_t crc32_impl::update(uint32_t crc, uint16_t data) {
  return __crc32ch(crc, data);
}
#ifdef NDB_CRC32C_ARM64_DEFAULT
MY_ATTRIBUTE((target("+crc")))
#endif /* NDB_CRC32C_ARM64_DEFAULT */
uint32_t crc32_impl::update(uint32_t crc, uint32_t data) {
  return __crc32cw(crc, data);
}
#ifdef NDB_CRC32C_ARM64_DEFAULT
MY_ATTRIBUTE((target("+crc")))
#endif /* NDB_CRC32C_ARM64_DEFAULT */
uint64_t crc32_impl::update(uint64_t crc, uint64_t data) {
  return (uint64_t)__crc32cd((uint32_t)crc, data);
}
#endif /* NDB_CRC32C_ARM64 */

/** Implementation of polynomial_mul_rev<w>(rev_u) function which uses hardware
accelerated polynomial multiplication to compute rev(w*u), where rev_u=rev(u).
This is accomplished by using rev_u * flip_at_32(w), @see flip_at_32 for
explanation why it works and why this is useful. */
struct use_pclmul : crc32_impl {
  template <uint32_t w>
  inline static uint64_t polynomial_mul_rev(uint32_t rev_u);
};
#ifdef NDB_CRC32C_X86_64
template <uint32_t w>
MY_ATTRIBUTE((target("sse4.2,pclmul")))
uint64_t use_pclmul::polynomial_mul_rev(uint32_t rev_u) {
  constexpr uint64_t flipped_w = flip_at_32(w);
  return _mm_cvtsi128_si64(_mm_clmulepi64_si128(
      _mm_set_epi64x(0, rev_u), _mm_set_epi64x(0, flipped_w), 0x00));
}
#endif /* NDB_CRC32C_X86_64 */

#ifdef NDB_CRC32C_ARM64
/** This function performs just a "type casts" from uint64_t to poly64_t.
@param[in]  w   The 64 coefficients of the polynomial
@return the polynomial w(x) = sum_{i=0}^{63} { (w&(1ULL << i)) * x^{i} }
*/
static inline poly64_t uint64_t_to_poly_64_t(uint64_t w) {
  /* This should compile down to nothing */
  return vget_lane_p64(vcreate_p64(w), 0);
}
/** This function takes a polynomial and extracts the 64 least significant
coefficients.
@param[in]  w   The polynomial w(x) = sum_{i=0}^{127} { a_i * x^{i} }
@return
   The lowest 64 coefficients, i.e. (result & (1ULL << i)) == a_i for 0<=i<64
*/
static inline uint64_t less_significant_half_of_poly128_t_to_uint64_t(
    poly128_t w) {
  /* This should compile down to just a single mov */
  return vgetq_lane_u64(vreinterpretq_u64_p128(w), 0);
}
template <uint32_t w>
#ifdef NDB_CRC32C_ARM64_DEFAULT
MY_ATTRIBUTE((target("+crypto")))
#endif /* NDB_CRC32C_ARM64_DEFAULT */
uint64_t use_pclmul::polynomial_mul_rev(uint32_t rev_u) {
  constexpr uint64_t flipped_w = flip_at_32(w);
  return less_significant_half_of_poly128_t_to_uint64_t(vmull_p64(
      uint64_t_to_poly_64_t(flipped_w), uint64_t_to_poly_64_t(rev_u)));
}
#endif /* NDB_CRC32C_ARM64 */

/** Implementation of polynomial_mul_rev<w>(rev_u) function which uses a simple
loop over i: if(w>>i&1)result^=rev_u<<(32-i), which is equivalent to
w * flip_at_32(rev_u), which in turn is equivalent to rev(rev(w) * rev_u),
@see flip_at_32 for explanation why this holds,
@see use_pclmul for explanation of what polynomial_mul_rev is computing.
This implementation is to be used when hardware accelerated polynomial
multiplication is not available. It tries to unroll the simple loop, so just
the few xors and shifts for non-zero bits of w are emitted. */
struct use_unrolled_loop_poly_mul : crc32_impl {
  template <uint32_t x_to_len_8>
  struct Polynomial_mul_rev_step_executor {
    template <size_t i>
    static void run(uint64_t &acc, const uint32_t hash_1 [[maybe_unused]]) {
      if constexpr (x_to_len_8 >> ((uint32_t)i) & 1) {
        acc ^= uint64_t{hash_1} << (32 - i);
      }
    }
  };
  template <uint32_t w>
  inline static uint64_t polynomial_mul_rev(uint32_t rev_u) {
    uint64_t rev_w_times_u{0};
    Loop<32>::run<Polynomial_mul_rev_step_executor<w>>(rev_w_times_u, rev_u);
    return rev_w_times_u;
  }
};

/** Rolls the crc forward by len bytes, that is updates it as if 8*len zero bits
were processed.
@param[in]      crc     initial value of the hash
@return Updated value of the hash: rev(rev(crc)*(x^{8*len} mod CRC32-C)) */
template <size_t len, typename algo_to_use>
inline static uint64_t roll(uint32_t crc) {
  return algo_to_use::template polynomial_mul_rev<compute_x_to_8len(len)>(crc);
}

/** Takes a 64-bit reversed representation of a polynomial, and computes the
32-bit reversed representation of it modulo CRC32-C.
@param[in]  big   The 64-bit representation of polynomial w, with the most
                  significant coefficient (the one for x^63) stored at least
                  significant bit (the one at 1<<0).
@return The 32-bit representation of w mod CRC-32, in which the most significant
        coefficient (the one for x^31) stored at least significant bit
        (the one at 1<<0). */
template <typename algo_to_use>
static inline uint32_t fold_64_to_32(uint64_t big) {
  /* crc is stored in bit-reversed format, so "significant part of uint64_t" is
  actually the least significant part of the polynomial, and the "insignificant
  part of uint64_t" are the coefficients of highest degrees for which we need to
  compute the rest mod crc32-c polynomial. */
  return algo_to_use::update((uint32_t)big, uint32_t{0}) ^ (big >> 32);
}

/** The body of unrolled loop used to process slices in parallel, which in i-th
iteration processes 8 bytes from the i-th slice of data, where each slice has
slice_len bytes. */
template <typename algo_to_use, size_t slice_len>
struct Update_step_executor {
  template <size_t i>
  static void run(uint64_t *crc, const Uint8 *data) {
    crc[i] = algo_to_use::update(crc[i], load<uint64_t>(data + i * slice_len));
  }
};

/** The body of unrolled loop used to combine partial results from each slice
into the final hash of whole chunk, which in i-th iteration takes the crc of
i-th slice and "rolls it forward" by virtually processing as many zeros as there
are from the end of the i-th slice to the end of the chunk. */
template <typename algo_to_use, size_t slice_len, size_t slices_count>
struct Combination_step_executor {
  template <size_t i>
  static void run(uint64_t &combined, const uint64_t *crc) {
    combined ^= roll<slice_len *(slices_count - 1 - i), algo_to_use>(crc[i]);
  }
};

/** Updates the crc checksum by processing slices_count*slice_len bytes of data.
The chunk is processed as slice_count independent slices of length slice_len,
and the results are combined together at the end to compute correct result.
@param[in]      crc0    initial value of the hash
@param[in]      data    data over which to calculate CRC32-C
@return The value of _crc updated by processing the range
        data[0]...data[slices_count*slice_len-1]. */
template <size_t slice_len, size_t slices_count, typename algo_to_use>
static inline uint32_t consume_chunk(uint32_t crc0, const Uint8 *data) {
  static_assert(slices_count > 0, "there must be at least one slice");
  /* crc[i] is the hash for i-th slice, data[i*slice_len...(i+1)*slice_len)
  where the initial value for each crc[i] is zero, except crc[0] for which we
  use the initial value crc0 passed in by the caller. */
  uint64_t crc[slices_count]{crc0};
  /* Each iteration of the for() loop will eat 8 bytes (single uint64_t) from
  each slice. */
  static_assert(
      slice_len % sizeof(uint64_t) == 0,
      "we must be able to process a slice efficiently using 8-byte updates");
  constexpr auto iters = slice_len / sizeof(uint64_t);
  for (size_t i = 0; i < iters; ++i) {
    Loop<slices_count>::template run<
        Update_step_executor<algo_to_use, slice_len>>(crc, data);
    data += sizeof(uint64_t);
  }
  /* combined_crc = sum crc[i]*x^{slices_count-i-1} mod CRC32-C */
  uint64_t combined_crc{0};
  /* This ugly if is here to ensure that fold_64_to_32 is called just once, as
  opposed to being done as part of combining each individual slice, which would
  also be correct, but would mean that CPU can't process roll()s in parallel.
  That is:
    combined ^= roll<"n-1 slices">(crc[0])
    combined ^= roll<"n-2 slices">(crc[1])
    ...
    combined ^= roll<1>(crc[n-2])
    return fold_64_to_32(combined) ^ crc[n-1]
  is faster than:
    crc[1] ^= fold_64_to_32(roll<"n-1 slices">(crc[0]))
    crc[2] ^= fold_64_to_32(roll<"n-1 slices">(crc[1]))
    ...
    crc[n-1] ^= fold_64_to_32(roll<1>(crc[n-2]))
    return crc[n-1]
  as the inputs to roll()s are independent, but now fold_64_to_32 is only needed
  conditionally, when slices_count > 1. */
  if constexpr (1 < slices_count) {
    Loop<slices_count - 1>::template run<
        Combination_step_executor<algo_to_use, slice_len, slices_count>>(
        combined_crc, crc);
    combined_crc = fold_64_to_32<algo_to_use>(combined_crc);
  }
  return combined_crc ^ crc[slices_count - 1];
}

/** Updates the crc checksum by processing at most len bytes of data.
The data is consumed in chunks of size slice_len*slices_count, and stops when
no more full chunks can be fit into len bytes.
Each chunk is processed as slice_count independent slices of length slice_len,
and the results are combined together at the end to compute correct result.
@param[in,out]  crc     initial value of the hash. Updated by this function by
                        processing data[0]...data[B*(slice_len * slices_count)],
                        where B = floor(len / (slice_len * slices_count)).
@param[in,out]  data    data over which to calculate CRC32-C. Advanced by this
                        function to point to unprocessed part of the buffer.
@param[in,out]  len     data length to be processed. Updated by this function
                        to be len % (slice_len * slices_count). */
template <size_t slice_len, size_t slices_count, typename algo_to_use>
static inline void consume_chunks(uint32_t &crc, const Uint8 *&data,
                                  size_t &len) {
  while (len >= slice_len * slices_count) {
    crc = consume_chunk<slice_len, slices_count, algo_to_use>(crc, data);
    len -= slice_len * slices_count;
    data += slice_len * slices_count;
  }
}
/** Updates the crc checksum by processing Chunk (1,2 or 4 bytes) of data,
but only when the len of the data provided, when decomposed into powers of two,
has a Chunk of this length. This is used to process the prefix of the buffer to
get to the position which is aligned mod 8, and to process the remaining suffix
which starts at position aligned  mod 8, but has less than 8 bytes.
@param[in,out]  crc     initial value of the hash. Updated by this function by
                        processing Chunk pointed by data.
@param[in,out]  data    data over which to calculate CRC32-C. Advanced by this
                        function to point to unprocessed part of the buffer.
@param[in,out]  len     data length, allowed to be processed. */
template <typename Chunk, typename algo_to_use>
static inline void consume_pow2(uint32_t &crc, const Uint8 *&data, size_t len) {
  if (len & sizeof(Chunk)) {
    crc = algo_to_use::update(crc, load<Chunk>(data));
    data += sizeof(Chunk);
  }
}
/** The hardware accelerated implementation of CRC32-C exploiting within-core
parallelism on reordering processors, by consuming the data in large chunks
split into 3 independent slices each. It's optimized for handling buffers of
length typical for 16kb pages and redo log blocks, but it works correctly for
any len and alignment.
@param[in]      crc     initial value of the hash (0 for first block, or the
                        result of CRC32-C for the data processed so far)
@param[in]      data    data over which to calculate CRC32-C
@param[in]      len     data length
@return CRC-32C (polynomial 0x11EDC6F41) */
template <typename algo_to_use>
static uint32_t crc32(uint32_t crc, const Uint8 *data, size_t len) {
  crc = ~crc;
  if (8 <= len) {
    /* For performance, the main loop will operate on uint64_t[].
    On some  platforms unaligned reads are not allowed, on others they are
    slower, so we start by consuming the unaligned prefix of the data. */
    const size_t prefix_len = (8 - reinterpret_cast<uintptr_t>(data)) & 7;
    /* data address may be unaligned, so we read just one byte if it's odd */
    consume_pow2<Uint8, algo_to_use>(crc, data, prefix_len);
    /* data address is now aligned mod 2, but may be unaligned mod 4*/
    consume_pow2<uint16_t, algo_to_use>(crc, data, prefix_len);
    /* data address is now aligned mod 4, but may be unaligned mod 8 */
    consume_pow2<uint32_t, algo_to_use>(crc, data, prefix_len);
    /* data is now aligned mod 8 */
    len -= prefix_len;
    /* The suffix_len will be needed later, but we can compute it here already,
    as len will only be modified by subtracting multiples of 8, and hopefully,
    learning suffix_len sooner will make it easier for branch predictor later.*/
    const size_t suffix_len = len & 7;
    /* A typical page is 16kb, but the part for which we compute crc32 is a bit
    shorter, thus 5440*3 is the largest multiple of 8*3 that fits. For pages
    larger than 16kb, there's not much gain from handling them specially. */
    consume_chunks<5440, 3, algo_to_use>(crc, data, len);
    /* A typical redo log block is 0.5kb, but 168*3 is the largest multiple of
    8*3 which fits in the part for which we compute crc32. */
    consume_chunks<168, 3, algo_to_use>(crc, data, len);
    /* In general there can be some left-over (smaller than 168*3) which we
    consume 8*1 bytes at a time. */
    consume_chunks<8, 1, algo_to_use>(crc, data, len);
    /* Finally, there might be unprocessed suffix_len < 8, which we deal with
    minimal number of computations caring about proper alignment. */
    consume_pow2<uint32_t, algo_to_use>(crc, data, suffix_len);
    consume_pow2<uint16_t, algo_to_use>(crc, data, suffix_len);
    consume_pow2<Uint8, algo_to_use>(crc, data, suffix_len);
  } else {
    while (len--) {
      crc = algo_to_use::update(crc, *data++);
    }
  }
  return ~crc;
}

/** The specialization of crc32<> template for use_pclmul. Used on platforms
which support hardware accelerated polynomial multiplication.
@param[in]      crc     CRC so far, 0 for the first piece
@param[in]      data    data over which to calculate CRC32-C
@param[in]      len     data length
@return CRC-32C (polynomial 0x11EDC6F41) */
#ifdef NDB_CRC32C_X86_64
MY_ATTRIBUTE((target("sse4.2,pclmul"), flatten))
#endif /* NDB_CRC32C_X86_64 */
#ifdef NDB_CRC32C_ARM64_APPLE
MY_ATTRIBUTE((flatten))
#endif /* NDB_CRC32C_ARM64_APPLE */
#ifdef NDB_CRC32C_ARM64_DEFAULT
MY_ATTRIBUTE((target("+crc+crypto"), flatten))
#endif /* NDB_CRC32C_ARM64_DEFAULT */
Uint32 crc32c_using_pclmul(Uint32 crc, const Uint8 *data, size_t len) {
  return crc32<use_pclmul>(crc, data, len);
}

/** The specialization of crc32<> template for use_unrolled_loop_poly_mul. Used
on platforms which do not support hardware accelerated polynomial
multiplication.
@param[in]      crc     CRC so far, 0 for the first piece
@param[in]      data    data over which to calculate CRC32-C
@param[in]      len     data length
@return CRC-32C (polynomial 0x11EDC6F41) */
#ifdef NDB_CRC32C_X86_64
MY_ATTRIBUTE((target("sse4.2"), flatten))
#endif /* NDB_CRC32C_X86_64 */
#ifdef NDB_CRC32C_ARM64_APPLE
MY_ATTRIBUTE((flatten))
#endif /* NDB_CRC32C_ARM64_APPLE */
#ifdef NDB_CRC32C_ARM64_DEFAULT
MY_ATTRIBUTE((target("+crc"), flatten))
#endif /* NDB_CRC32C_ARM64_DEFAULT */
Uint32 crc32c_using_unrolled_loop_poly_mul(Uint32 crc, const Uint8 *data,
                                           size_t len) {
  return crc32<use_unrolled_loop_poly_mul>(crc, data, len);
}

} /* namespace hardware */

#endif /* !NDB_CRC32C_SOFTWARE_ONLY */

struct Crc32cChoice {
  ndb_crc32c_func_t func;
  const char *name;
};

Crc32cChoice choose_crc32c() {
  software::crc32_slice8_table_init();
#if defined(NDB_CRC32C_X86_64)
  const struct ndb_cpu_features *features = Ndb_GetCpuFeatures();
  if (features->sse42) {
    if (features->pclmul) {
      return {hardware::crc32c_using_pclmul, "sse4.2+pclmul"};
    }
    return {hardware::crc32c_using_unrolled_loop_poly_mul, "sse4.2"};
  }
#elif defined(NDB_CRC32C_ARM64)
  const struct ndb_cpu_features *features = Ndb_GetCpuFeatures();
  if (features->arm_crc32) {
    if (features->arm_pmull) {
      return {hardware::crc32c_using_pclmul, "armv8-crc+pmull"};
    }
    return {hardware::crc32c_using_unrolled_loop_poly_mul, "armv8-crc"};
  }
#endif
  return {software::crc32c, "software"};
}

/* Made once, thread safe, the first time it is needed */
const Crc32cChoice &crc32c_choice() {
  static const Crc32cChoice choice = choose_crc32c();
  return choice;
}

Uint32 crc32c_first_call(Uint32 crc, const Uint8 *buf, size_t len);

/**
 * The variant in use. It starts at crc32c_first_call, which makes the
 * choice. The acquire load pairs with the release store of
 * ndb_crc32c_init(), so the software tables are seen initialised.
 */
std::atomic<ndb_crc32c_func_t> g_crc32c_func{crc32c_first_call};

Uint32 crc32c_first_call(Uint32 crc, const Uint8 *buf, size_t len) {
  ndb_crc32c_init();
  return crc32c_choice().func(crc, buf, len);
}

}  // namespace

void ndb_crc32c_init() {
  g_crc32c_func.store(crc32c_choice().func, std::memory_order_release);
}

Uint32 ndb_crc32c(Uint32 crc, const void *buf, size_t len) {
  return g_crc32c_func.load(std::memory_order_acquire)(
      crc, static_cast<const Uint8 *>(buf), len);
}

const char *ndb_crc32c_implementation() { return crc32c_choice().name; }

#ifdef TEST_NDB_CRC32C

#include <util/NdbTap.hpp>
#include <algorithm>
#include <chrono>
#include <vector>

#define XXH_INLINE_ALL
#include <util/ndb_xxhash.h>

/* A bit-at-a-time CRC-32C, independent of the tables and instructions */
static Uint32 crc32c_bitwise(Uint32 crc, const Uint8 *buf, size_t len) {
  crc = ~crc;
  while (len--) {
    crc ^= *buf++;
    for (int k = 0; k < 8; k++) {
      crc = (crc >> 1) ^ (0x82F63B78U & (0U - (crc & 1)));
    }
  }
  return ~crc;
}

static Uint32 test_rand_state = 0x9E3779B9;
static Uint32 test_rand() {
  /* xorshift32 */
  Uint32 x = test_rand_state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  test_rand_state = x;
  return x;
}

struct TestVariant {
  const char *name;
  ndb_crc32c_func_t func;
  bool available;
};

static std::vector<TestVariant> test_variants() {
  std::vector<TestVariant> variants;
  variants.push_back({"software", software::crc32c, true});
#if defined(NDB_CRC32C_X86_64)
  const struct ndb_cpu_features *f = Ndb_GetCpuFeatures();
  variants.push_back({"sse4.2", hardware::crc32c_using_unrolled_loop_poly_mul,
                      f->sse42});
  variants.push_back(
      {"sse4.2+pclmul", hardware::crc32c_using_pclmul, f->sse42 && f->pclmul});
#elif defined(NDB_CRC32C_ARM64)
  const struct ndb_cpu_features *f = Ndb_GetCpuFeatures();
  variants.push_back({"armv8-crc",
                      hardware::crc32c_using_unrolled_loop_poly_mul,
                      f->arm_crc32});
  variants.push_back({"armv8-crc+pmull", hardware::crc32c_using_pclmul,
                      f->arm_crc32 && f->arm_pmull});
#endif
  return variants;
}

static void test_known_values(const std::vector<TestVariant> &variants) {
  /* The check value of CRC-32C, and the vectors of RFC 3720, B.4 */
  Uint8 zeros[32], ones[32], incr[32], decr[32];
  for (int i = 0; i < 32; i++) {
    zeros[i] = 0x00;
    ones[i] = 0xFF;
    incr[i] = (Uint8)i;
    decr[i] = (Uint8)(31 - i);
  }
  const struct {
    const Uint8 *buf;
    size_t len;
    Uint32 crc;
  } cases[] = {{(const Uint8 *)"123456789", 9, 0xE3069283},
               {zeros, 32, 0x8A9136AA},
               {ones, 32, 0x62A8AB43},
               {incr, 32, 0x46DD794E},
               {decr, 32, 0x113FDB5C}};
  for (const auto &c : cases) {
    OK(crc32c_bitwise(0, c.buf, c.len) == c.crc);
    OK(ndb_crc32c(0, c.buf, c.len) == c.crc);
    for (const TestVariant &v : variants) {
      if (v.available) {
        OK(v.func(0, c.buf, c.len) == c.crc);
      }
    }
  }
  /* An empty piece leaves the CRC unchanged */
  const Uint32 seeds[] = {0, 0xFFFFFFFF, 0x12345678};
  for (Uint32 seed : seeds) {
    OK(ndb_crc32c(seed, zeros, 0) == seed);
    for (const TestVariant &v : variants) {
      if (v.available) {
        OK(v.func(seed, zeros, 0) == seed);
      }
    }
  }
}

static void test_against_bitwise(const std::vector<TestVariant> &variants) {
  /* Every length up to 4200 and the lengths around the chunk sizes of the
     hardware code (3 x 168 and 3 x 5440 bytes), at every alignment, with a
     random starting CRC. 92520 bytes is the largest REDO PREPARE record. */
  std::vector<size_t> lengths;
  for (size_t len = 0; len <= 4200; len++) {
    lengths.push_back(len);
  }
  const size_t big[] = {16319, 16320, 16321, 16327, 16328, 16824,
                        32640, 33144, 49000, 92520};
  for (size_t len : big) {
    lengths.push_back(len);
  }
  std::vector<Uint8> buf(92520 + 8);
  for (Uint8 &b : buf) {
    b = (Uint8)test_rand();
  }
  for (size_t len : lengths) {
    for (size_t offset = 0; offset < 8; offset++) {
      const Uint8 *p = buf.data() + offset;
      const Uint32 seed = (len % 3 == 0) ? 0 : test_rand();
      const Uint32 expected = crc32c_bitwise(seed, p, len);
      OK(ndb_crc32c(seed, p, len) == expected);
      for (const TestVariant &v : variants) {
        if (v.available) {
          OK(v.func(seed, p, len) == expected);
        }
      }
    }
  }
}

static void test_chaining(const std::vector<TestVariant> &variants) {
  std::vector<Uint8> buf(20000);
  for (Uint8 &b : buf) {
    b = (Uint8)test_rand();
  }
  /* Every split of 200 bytes */
  const Uint32 whole200 = ndb_crc32c(0, buf.data(), 200);
  for (size_t split = 0; split <= 200; split++) {
    const Uint32 first = ndb_crc32c(0, buf.data(), split);
    OK(ndb_crc32c(first, buf.data() + split, 200 - split) == whole200);
    for (const TestVariant &v : variants) {
      if (v.available) {
        const Uint32 vfirst = v.func(0, buf.data(), split);
        OK(v.func(vfirst, buf.data() + split, 200 - split) == whole200);
      }
    }
  }
  /* Splits of 20000 bytes around the chunk boundaries */
  const Uint32 whole = ndb_crc32c(0, buf.data(), buf.size());
  const size_t splits[] = {0,     1,     7,     8,     503,   504,  505,
                           16319, 16320, 16321, 19992, 19999, 20000};
  for (size_t split : splits) {
    const Uint32 first = ndb_crc32c(0, buf.data(), split);
    OK(ndb_crc32c(first, buf.data() + split, buf.size() - split) == whole);
  }
  /* Three pieces, as for a REDO record: type word, body, position suffix */
  const Uint32 three = ndb_crc32c(
      ndb_crc32c(ndb_crc32c(0, buf.data(), 4), buf.data() + 4, 40),
      buf.data() + 44, 16);
  OK(three == ndb_crc32c(0, buf.data(), 60));
}

/**
 * Informational: nanoseconds per checksum, for the sizes the REDO log
 * uses, CRC-32C against XXH3. Nothing is checked here.
 *   crc32c    ndb_crc32c over the whole buffer in one call
 *   crc32c/3  ndb_crc32c in three pieces, as for a REDO record:
 *             4 bytes type word, the body, 16 bytes position suffix
 *   xxh3      XXH3_64bits over the whole buffer in one call
 *   xxh3/3    XXH3 streaming in the same three pieces
 *   xxh3+mix  A record format built for XXH3: XXH3_64bits over the body
 *             with the default secret, then a seeded XXH3 over the
 *             20 bytes of type word and position suffix, seeded with
 *             the body's hash; the low 32 bits are the checksum
 * Each result changes the first byte of the next input, so the calls
 * form a chain, as when records are written one after the other.
 */
static void test_timing() {
  const size_t sizes[] = {20, 28, 60, 124, 300, 1000, 32768, 92520};
  std::vector<Uint64> storage(92520 / 8 + 1);
  Uint8 *buf = reinterpret_cast<Uint8 *>(storage.data());
  for (size_t i = 0; i < 92520; i++) {
    buf[i] = (Uint8)test_rand();
  }
  printf("ndb_crc32c: %s, XXH_VECTOR %d (0 scalar, 1 SSE2, 2 AVX2, "
         "3 AVX512, 4 NEON)\n",
         ndb_crc32c_implementation(), (int)XXH_VECTOR);
  printf("%8s %10s %10s %10s %10s %10s   (ns per checksum)\n", "bytes",
         "crc32c", "crc32c/3", "xxh3", "xxh3/3", "xxh3+mix");
  typedef std::chrono::steady_clock clock;
  Uint64 sink = 0;
  for (size_t len : sizes) {
    const size_t iterations = std::max<size_t>(2000, (64 << 20) / len);
    const size_t body = len - 20;
    double ns[5];
    for (int method = 0; method < 5; method++) {
      Uint64 h = 0;
      const auto start = clock::now();
      for (size_t i = 0; i < iterations; i++) {
        buf[0] ^= (Uint8)h;
        switch (method) {
          case 0:
            h = ndb_crc32c(0, buf, len);
            break;
          case 1:
            h = ndb_crc32c(
                ndb_crc32c(ndb_crc32c(0, buf, 4), buf + 4, body),
                buf + 4 + body, 16);
            break;
          case 2:
            h = XXH3_64bits(buf, len);
            break;
          case 4: {
            /* The body takes part in the chain too, or the compiler
               could hash it once, outside the loop */
            buf[4] ^= (Uint8)h;
            Uint8 tail[20];
            memcpy(tail, buf, 4);
            memcpy(tail + 4, buf + 4 + body, 16);
            h = (Uint32)XXH3_64bits_withSeed(tail, sizeof(tail),
                                             XXH3_64bits(buf + 4, body));
            break;
          }
          default: {
            XXH3_state_t state;
            XXH3_64bits_reset(&state);
            XXH3_64bits_update(&state, buf, 4);
            XXH3_64bits_update(&state, buf + 4, body);
            XXH3_64bits_update(&state, buf + 4 + body, 16);
            h = XXH3_64bits_digest(&state);
            break;
          }
        }
      }
      const auto stop = clock::now();
      sink += h;
      ns[method] =
          std::chrono::duration<double, std::nano>(stop - start).count() /
          (double)iterations;
    }
    printf("%8zu %10.1f %10.1f %10.1f %10.1f %10.1f\n", len, ns[0], ns[1],
           ns[2], ns[3], ns[4]);
  }
  printf("(sink %llu)\n", (unsigned long long)sink);
}

TAPTEST(ndb_crc32c) {
  /* The first call chooses the implementation */
  OK(ndb_crc32c(0, "123456789", 9) == 0xE3069283);
  ndb_crc32c_init();
  ndb_crc32c_init();
  OK(ndb_crc32c(0, "123456789", 9) == 0xE3069283);
  printf("ndb_crc32c implementation: %s\n", ndb_crc32c_implementation());

  const std::vector<TestVariant> variants = test_variants();
  for (const TestVariant &v : variants) {
    printf("variant %-16s %s\n", v.name,
           v.available ? "tested" : "not supported by this CPU");
  }
#if defined(NDB_CRC32C_X86_64) || defined(NDB_CRC32C_ARM64)
  /* Correct, but slow: a CPU, or a VM CPU model, without CRC32 */
  if (strcmp(ndb_crc32c_implementation(), "software") == 0) {
    printf("WARNING: this CPU has no CRC32 instructions, software is used\n");
  }
#endif

  test_known_values(variants);
  test_against_bitwise(variants);
  test_chaining(variants);
  test_timing();
  return 1;
}

#endif
