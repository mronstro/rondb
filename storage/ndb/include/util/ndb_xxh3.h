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
#ifndef NDB_XXH3_H
#define NDB_XXH3_H

#include <stddef.h>
#include <ndb_types.h>

/**
 * XXH3 with 64-bit result: the hash of keys (rondb_xxhash_std) and the
 * checksum of the REDO log records on persistent memory.
 *
 * Inputs over 240 bytes use vector code, chosen at run time: AVX2 on
 * x86-64 when the CPU and the OS support it, otherwise SSE2; NEON on
 * aarch64. Shorter inputs use the same scalar code everywhere. The
 * build needs no -mavx2 and runs on CPUs without AVX2.
 *
 * Every implementation gives the same hash as XXH3_64bits() and
 * XXH3_64bits_withSeed() of ndb_xxhash.h, on every platform. The hash
 * of a key decides where its row is stored, so this must never change.
 *
 * ndb_xxh3_64(buf, 0) == 0x2D06800538D394C2.
 */
Uint64 ndb_xxh3_64(const void *buf, size_t len);
Uint64 ndb_xxh3_64_seed(const void *buf, size_t len, Uint64 seed);

/**
 * Choose the implementation. Called by ndb_init(); it is also done at
 * the first input over 240 bytes. Calling it again does nothing.
 */
void ndb_xxh3_init();

/**
 * The implementation used for inputs over 240 bytes, for logs and
 * tests: "avx2" or "sse2" on x86-64, "neon" on aarch64; "scalar" or
 * another name on other platforms and with special build flags.
 */
const char *ndb_xxh3_implementation();

#endif
