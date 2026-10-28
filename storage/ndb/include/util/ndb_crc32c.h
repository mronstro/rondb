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
#ifndef NDB_CRC32C_H
#define NDB_CRC32C_H

#include <stddef.h>
#include <ndb_types.h>

/**
 * CRC-32C (Castagnoli, polynomial 0x1EDC6F41), the checksum of the
 * REDO log records on persistent memory.
 *
 * It uses the CRC32 instructions of SSE 4.2 on x86-64 and of ARMv8 on
 * aarch64 when the CPU has them, and a table-driven software version
 * otherwise. The choice is made at run time.
 *
 * Start with crc = 0 and pass the previous result to continue, as
 * with zlib's crc32():
 *   ndb_crc32c(ndb_crc32c(0, a, n), b, m) == ndb_crc32c(0, a||b, n+m)
 * ndb_crc32c(0, "123456789", 9) == 0xE3069283.
 */
Uint32 ndb_crc32c(Uint32 crc, const void *buf, size_t len);

/**
 * Choose the implementation. Called by ndb_init(); it is also done at
 * the first call of ndb_crc32c(). Calling it again does nothing.
 */
void ndb_crc32c_init();

/**
 * The name of the implementation in use, for logs and tests:
 * "sse4.2+pclmul", "sse4.2", "armv8-crc+pmull", "armv8-crc" or "software".
 */
const char *ndb_crc32c_implementation();

#endif
