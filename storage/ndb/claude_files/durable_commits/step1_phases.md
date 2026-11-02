# RONDB-1150 step 1: implementation phases and progress

Step 1 puts the REDO log on persistent memory at today's durability
(`pmem_redo_design.md`). It is implemented in the phases below, one pull
request each, in the order of `implementation_plan.md` §2.2. This file
records the phases and their state; the plans hold the detail.

There is no CI: whoever pushes runs the tests of the phase's gate, on the
platforms that apply (`implementation_plan.md` §2.4), and lists the
commands and results in the pull request. Every phase leaves file mode
unchanged.

| Phase | Pull request | Content | Packages | Gate (what the pusher runs) | Needs | State |
|---|---|---|---|---|---|---|
| 1 | 2 | CPU feature detection and XXH3, with AVX2 chosen at run time | S1.1, S1.2 | `NdbHW-t`, `ndb_xxh3-t`, `rondb_hash-t` on Linux x86_64, Linux ARM64 and macOS ARM64; file-mode regression | — | **Done**: the XXH3 version passed all tests (reported 2026-10-29); the first, CRC32C version had passed on 2026-10-28 |
| 2 | 3 | PMEM helper and platform queries | S1.3, S1.4 | `ndb_pmem-t` on a plain file on the three platforms and on `memmap=` | 1 | **In progress**: S1.3 passed `ndb_pmem-t` on macOS ARM64 and Linux x86_64 (2026-10-29); Linux ARM64 to be tested. S1.4 passed `ndb_pmem_region-t` and `NdbHW-t` on macOS ARM64 and Linux x86_64 (2026-10-29); Linux ARM64 to be tested |
| 3 | 4 | Configuration: parameters, path parser, checks, test settings | S2.1–S2.3, S2.7 | Config unit tests, management-server refusals | — | **In progress**: `RedoLogPaths-t`, `MgmConfig-t`, `ndb.ndb_redo_pmem_config`, `ndb.ndb_config` and `ndb.ndb_basic` in PMEM mode passed on macOS ARM64 (2026-10-29); `ndb.ndb_redo_pmem_config`, `RedoLogPaths-t` and `MgmConfig-t` passed on Linux x86_64 (2026-10-30); Linux ARM64 postponed |
| 4 | 5 | NDBFS mapping and placement; PMEM mode with today's format (**M0.2**) | S3.1–S3.4, S2.4, S2.5 | MTR ndb suite and a testSystemRestart subset in `nodax` and on `memmap=` | 2, 3 | **In progress**: 4a (NDBFS maps the REDO files), 4b (REDO paths, NUMA placement) and 4c (start-time platform checks) passed on macOS ARM64 and Linux x86_64 (2026-10-30), after the fix of a race in `ndb_pmem_map` that 4a found on Linux. Still to run for the gate: Linux ARM64 (postponed), the testSystemRestart subset, and `memmap=` |
| 5 | 6 | Initial start and restarts with every file mapped; ndbinfo `redo_log_pmem` | S3.5, S3.6, S2.6 | Initial start, SR and NR in PMEM mode; ndbinfo rows | 4 | **In progress**: 5a (every REDO file kept open and mapped, by a close that keeps the file in NDBFS) passed on macOS ARM64 (2026-10-31), Linux x86_64 to be tested; 5b (ndbinfo `redo_log_pmem`) passed on macOS ARM64 (2026-11-02), Linux x86_64 to be tested |
| 6 | 7 | Record format and reader module | S4.1, S6.2 | Unit tests over synthetic logs on the three platforms | 1 | **In progress**: `pmem_redo_format-t` and `pmem_redo_scan-t` (300 random logs from seed 1, then 10000 from a time-based seed) passed on macOS ARM64 (2026-11-02); Linux x86_64 and Linux ARM64 to be tested |
| 7 | 8 | Record writers | S4.2–S4.7, S5.1 | Unit tests; file-mode regression | 6 | **Written** (2026-11-02), to be tested: the PMEM record writers behind `c_redo_pmem_format` (false until phase 8), the reservation, the LSN helpers, `pmem_redo_writer-t` |
| 8 | 9 | PMEM REDO end to end: write path and recovery together (**M0.3**) | S4.8, S5.2–S5.5, S6.1, S6.3–S6.6 | Initial start, traffic, SR and NR in PMEM mode; the ledger in PMEM mode | 5, 7, ledger | Not started |
| 9 | 10 | Checks, benchmark switch, persist delay | S5.6–S5.9, Q-A11 | Shared log parts; debug send checks; `DUMP 2368` latency numbers | 8 | Not started |
| 10 | 11 | Node restart and `redoLogReader` | S6.7, S6.8 | testNodeRestart subset; reader on files from crash tests | 8 | Not started |
| 11 | 12 | Power-loss emulation and crash inserts (**M0.4**) | S1.5, S7.1–S7.3, S7.5 | `pmem-redo-tests.txt` with power-loss emulation | 8, 10 | Not started |

**Side tracks**, independent of the phases above:

| Track | Pull request | Content | Needed by | State |
|---|---|---|---|---|
| Ledger | 1 | GCP-saved ledger checker (S7.4), validated in file mode on today's code | Phase 8 | Not started |
| Bug fix | 0 | `ZMIN_READ_BUFFER_SIZE` 3 → 4 in both modes, own ticket (R13, Q-A6) | — | Not started |

---

## Phase 1: CPU feature detection and XXH3

**Scope.** `implementation_plan.md` pull request 2; platform plan S1.1 and
S1.2. The hash of keys now chooses AVX2 at run time and gives the same
hashes as before. Nothing else calls the new code yet, so file mode is
otherwise unchanged.

**Changes.**

| File | Change |
|---|---|
| `include/portlib/NdbHW.hpp` | `struct ndb_cpu_features` and `Ndb_GetCpuFeatures()` |
| `src/common/portlib/NdbHW.cpp` | Detection, once, on first call, independent of `NdbHW_Init()`: CPUID and XGETBV on x86-64, `getauxval` on Linux ARM64, `sysctlbyname` on macOS ARM64. `TAPTEST(NdbCPU)` prints and checks the features. `is_avx2_supported()` reports the detected AVX2, read once at start; it always returned 0 before |
| `include/util/ndb_xxh3.h` | `ndb_xxh3_64(buf, len)`, `ndb_xxh3_64_seed(buf, len, seed)`, `ndb_xxh3_init()`, `ndb_xxh3_implementation()` |
| `src/common/util/ndb_xxh3.cpp` | XXH3 from `ndb_xxhash.h`, and `rondb_xxhash_std()`. Inputs up to 240 bytes take the inline scalar code. Longer ones go through a function pointer chosen once: on x86-64 the AVX2 code, compiled with `target("avx2")` as xxhash's own `xxh_x86dispatch.c` does, when `Ndb_GetCpuFeatures()` reports AVX2, otherwise SSE2; elsewhere the code the build chose, NEON on aarch64. The unit test is in the same file |
| `include/util/rondb_hash.hpp`, `src/common/util/rondb_hash.cpp` | `rondb_calc_hash` calls `rondb_xxhash_std`; its AVX2 branch, which never ran, and `rondb_xxhash_avx2` are gone |
| `src/common/util/xxhash_avx2.cpp`, `xxhash_std.cpp` | Removed, replaced by `ndb_xxh3.cpp` |
| `src/common/util/CMakeLists.txt` | `ndb_xxh3.cpp` in `ndbgeneral`; `ndb_xxh3-t` |
| `src/common/util/ndb_init.cpp` | `ndb_xxh3_init()` in `ndb_init_internal()` |

The first version of this phase had a CRC32C instead, a port of InnoDB's
(`ndb_crc32c`, commit 77a146884ec). It was removed after decision 5; commit
4102f7f1c7a has it with its timing test.

**Decisions taken while implementing.**

1. **CRC32C first, then XXH3.** The first version ported InnoDB's CRC32C,
   because nothing better was in the tree:
   - simdjson has no CRC32C.
   - The bundled Abseil has one, but chooses its hardware path at compile
     time, from flags RonDB's build does not set.
   - Abseil is also built only with bundled protobuf, and it is Apache-2.0
     code, which cannot be copied into GPLv2 files.

   Timing it against XXH3, which the tree already has, decided for XXH3
   (decision 5).
2. **AVX2 is chosen at run time, not by `-mavx2`.**
   - `-mavx2` for the whole build would make every program require AVX2.
     Such a program dies with SIGILL on a CPU or VM CPU model without it.
   - Before, AVX2 was never chosen at run time, in any build.
     `rondb_calc_hash` took `rondb_xxhash_avx2` only under
     `#if defined(__AVX2__)` and only if `is_avx2_supported()`, which
     always returned 0.
   - With `-mavx2`, `xxhash_std.cpp` was compiled with AVX2 too, because
     `ndb_xxhash.h` chooses the vector code from `__AVX2__`. The
     `XXH_VECTOR_TYPE` define in `xxhash_avx2.cpp` was not read.
   - Every XXH3 implementation (scalar, SSE2, AVX2, NEON) gives the same
     hash, so the distribution of rows does not change; `ndb_xxh3-t`
     checks it.
   - AVX2 makes inputs over 240 bytes about twice as fast. Shorter ones
     run the same scalar code in every implementation.
   - AVX-512 is left out for now; it could be added the same way.
3. **Windows** uses the code the build chose, because the run-time choice
   needs GCC or Clang. Neither Windows nor big-endian is a supported
   platform (Q-A5).
4. **The hash of keys keeps its entry point.** Callers still use
   `rondb_xxhash_std()`, which moved from `xxhash_std.cpp` into
   `ndb_xxh3.cpp` and gains the run-time choice.
5. **XXH3 rather than CRC32C** (settled 2026-10-28). The definition is in
   `pmem_redo_design.md` E4.
   - In the CRC32C format a record is checksummed in three pieces: `w0`
     without the invalidation bit, the body, and the 16 bytes of `S`,
     which are never stored. CRC32C chains them at about 2 ns per piece.
   - The XXH3 format hashes the body in one call. It then mixes in `w0`
     and `S` with a seeded hash of 20 bytes. Both formats bind the checksum
     to lap and position.
   - Per operation (PREPARE + COMMIT + COMPLETE) on x86-64 with AVX2, XXH3
     against CRC32C (Timings):
     - with a PREPARE of 124 bytes: 37 ns against 41 ns;
     - with a PREPARE of 1000 bytes: 53 ns against 98 ns. The PREPARE
       alone is 28 ns against 75 ns.
   - Without AVX2 those are 37 against 38 ns and 80 against 95 ns. On macOS
     ARM64 they are 27 against 37 ns and 39 against 85 ns.
   - CRC32C stays faster for the shortest records (FILLER, COMPLETE, ABORT)
     by a few nanoseconds. Without AVX2 it is also faster from 32 KB.
     PREPAREs are seldom tiny, so XXH3 wins where the bytes are.

**Commands for the pusher** (from the build directory, configured with
`-DWITH_UNIT_TESTS=1`), on Linux x86_64, Linux ARM64 and macOS ARM64:

```
cmake --build . --target NdbHW-t ndb_xxh3-t rondb_hash-t
ctest -R 'NdbHW-t|ndb_xxh3-t|rondb_hash-t' --output-on-failure
./runtime_output_directory/ndb_xxh3-t      # prints the implementation and timings
```

`ndb_xxh3-t` should report `avx2` on an x86_64 CPU with AVX2 (`sse2`
without it) and `neon` on ARM64. It checks that every implementation the
CPU has gives the header's XXH3 for every length up to 2100 bytes and some
long ones, at every alignment, with and without a seed. It also checks the
hash of keys and the distribution hash. It prints ns per hash for each
implementation and for the checksum of a REDO record (`record`). The
timings mean something only from an optimised build (`-DWITH_DEBUG=0`).

**Timings.** These come from `ndb_crc32c-t`, the timing test of the CRC32C
version (commit 4102f7f1c7a), in an optimised build, in ns per checksum. `crc32c/3` and `xxh3/3` checksum the same bytes in three
pieces, 4 + body + 16, as a record is checksummed. `xxh3+mix` is a format
built for XXH3: the body in one call,
then a seeded XXH3 over the 20 bytes of `w0` and `S` with the body's hash
as seed. Each result feeds the next input, so the loop measures latency
with the data in cache.

macOS ARM64, Apple M5 Pro, `armv8-crc+pmull`, XXH3 with NEON
(2026-10-28):

| bytes | record (E13) | crc32c | crc32c/3 | xxh3 | xxh3/3 | xxh3+mix |
|---|---|---|---|---|---|---|
| 20 | FILLER header, NEXT_MBYTE | 4.0 | 7.5 | 4.7 | 8.5 | 7.3 |
| 28 | COMPLETE, ABORT, COMPLETED_GCI | 4.6 | 8.8 | 4.7 | 8.7 | 9.0 |
| 60 | COMMIT | 7.2 | 11.4 | 4.9 | 10.1 | 8.8 |
| 124 | PREPARE, 20 words of key and attrinfo | 12.4 | 16.8 | 5.4 | 10.7 | 9.2 |
| 300 | PREPARE, 64 words | 27.2 | 31.0 | 10.8 | 25.4 | 14.4 |
| 1000 | PREPARE, 239 words | 60.7 | 65.0 | 19.2 | 55.6 | 21.5 |
| 32768 | PREPARE, 8181 words | 919.6 | 914.8 | 619.3 | 1577.4 | 633.2 |
| 92520 | largest PREPARE, 4 pages | 2663.4 | 2699.2 | 1795.4 | 4524.0 | 1827.9 |

The bytes checksummed are 4 + 4·(words − 2) + 16. At 92 KB this is
35 GB/s for CRC-32C, 51 GB/s for XXH3 one-shot and with the mix, and
20 GB/s for streaming XXH3. Each extra CRC call costs about 2 ns, and the
mix about 3 ns. Comparing today's format (`crc32c/3`) with a format
built for XXH3 (`xxh3+mix`):
- up to 28 bytes they are equal;
- for a COMMIT, XXH3 is 1.3 times faster;
- for a PREPARE of 124 to 1000 bytes, it is 1.8 to 3 times faster;
- for the largest records, it is 1.45 times faster.

For one operation, a PREPARE of 124 bytes plus a COMMIT and a COMPLETE,
that is 37 ns against 27 ns. With a PREPARE of 1000 bytes it is 85 ns
against 39 ns. A real spanning PREPARE has one more piece per page header
it crosses, in both formats.

Linux x86_64, Intel Core i9-13900K, `sse4.2+pclmul`, XXH3 with SSE2, the
normal build (2026-10-28):

| bytes | record (E13) | crc32c | crc32c/3 | xxh3 | xxh3/3 | xxh3+mix |
|---|---|---|---|---|---|---|
| 20 | FILLER header, NEXT_MBYTE | 6.9 | 5.7 | 7.9 | 16.6 | 12.3 |
| 28 | COMPLETE, ABORT, COMPLETED_GCI | 7.8 | 7.4 | 7.9 | 16.8 | 12.5 |
| 60 | COMMIT | 11.2 | 12.0 | 8.1 | 14.9 | 12.2 |
| 124 | PREPARE, 20 words of key and attrinfo | 18.2 | 18.8 | 9.0 | 16.6 | 12.5 |
| 300 | PREPARE, 64 words | 37.2 | 37.8 | 17.1 | 46.3 | 24.0 |
| 1000 | PREPARE, 239 words | 74.9 | 75.1 | 46.1 | 73.5 | 55.2 |
| 32768 | PREPARE, 8181 words | 919.4 | 906.9 | 1512.0 | 1475.6 | 1514.2 |
| 92520 | largest PREPARE, 4 pages | 2615.2 | 2614.7 | 4272.3 | 4150.2 | 4255.2 |

- At 92 KB CRC-32C runs at 35 GB/s and XXH3 with SSE2 at 22 GB/s.
- Unlike on the M5, CRC-32C is the faster from 32 KB, by 1.6 times.
- The short records are 1.7 to 2.2 times faster with CRC-32C, because the
  mix costs about 4 ns here.
- XXH3 wins only the PREPAREs of 124 to 1000 bytes, by 1.4 to 1.6 times.
- `crc32c/3` is below `crc32c` at 20 and 28 bytes in this run and in an
  earlier one, so that is not noise. The cause was not investigated.
- The earlier run, from a build without `xxh3+mix`, was 13 to 21 % slower
  for both checksums, which points to a different clock. The i9-13900K
  has performance and efficiency cores, and a run can land on either.
  Pinning the run to a performance core with `taskset` makes runs
  comparable.
- A desktop part at up to 5.8 GHz gives low absolute times. Server parts
  at 2 to 4 GHz will be slower, but the ratios should hold, because both
  checksums scale with the clock. Unlike this part, Xeons have AVX-512,
  which XXH3 could use above 240 bytes behind the same kind of run-time
  choice.

The same machine, built with `-mavx2` (XXH3 with AVX2, 2026-10-28):

| bytes | record (E13) | crc32c | crc32c/3 | xxh3 | xxh3/3 | xxh3+mix |
|---|---|---|---|---|---|---|
| 20 | FILLER header, NEXT_MBYTE | 6.9 | 7.6 | 7.8 | 15.2 | 11.9 |
| 28 | COMPLETE, ABORT, COMPLETED_GCI | 7.8 | 10.6 | 7.8 | 15.2 | 12.3 |
| 60 | COMMIT | 11.2 | 11.9 | 8.3 | 13.8 | 11.9 |
| 124 | PREPARE, 20 words of key and attrinfo | 18.2 | 18.9 | 9.0 | 15.3 | 12.4 |
| 300 | PREPARE, 64 words | 37.2 | 37.9 | 14.8 | 39.8 | 20.9 |
| 1000 | PREPARE, 239 words | 74.9 | 75.1 | 26.9 | 53.0 | 28.4 |
| 32768 | PREPARE, 8181 words | 904.8 | 905.5 | 784.1 | 772.0 | 766.8 |
| 92520 | largest PREPARE, 4 pages | 2611.6 | 2611.5 | 2155.6 | 2165.4 | 2168.2 |

- **Up to 240 bytes nothing changes.** XXH3 runs the same scalar code as
  in the normal build: the `xxh3` and `xxh3+mix` columns agree with it
  within 0.4 ns.
- **The mix costs 3.5 to 4.5 ns here.**
- **AVX2 makes XXH3 more than twice as fast above 240 bytes**: 43 GB/s at
  92 KB, against 22 GB/s with SSE2.
- **CRC-32C runs at the same speed in both builds** (2612 and 2615 ns at
  92 KB), as it should, since it uses no AVX2.

The CRC32C timing test was removed with decision 5, so Linux ARM64 is
timed with `ndb_xxh3-t` only.

**`ndb_xxh3-t`**, the XXH3 version, prints ns per hash for each
implementation and for the checksum of a REDO record (`record`). macOS
ARM64, Apple M5 Pro, optimised build (2026-10-29):

| bytes | scalar | neon | record |
|---|---|---|---|
| 20 | 7.8 | 6.2 | 7.7 |
| 28 | 5.0 | 4.9 | 9.1 |
| 60 | 5.1 | 5.1 | 8.7 |
| 124 | 5.5 | 5.7 | 9.4 |
| 300 | 20.2 | 11.0 | 14.8 |
| 1000 | 57.8 | 20.1 | 22.8 |
| 32768 | 1807.0 | 640.5 | 672.0 |
| 92520 | 5342.9 | 1836.0 | 1817.9 |

- `record` matches `xxh3+mix` of the comparison within about 1 ns, and
  within 6 % at 32 KB, so going through the chosen function costs nothing
  measurable.
- Above 240 bytes NEON is 2.9 times faster than scalar. Up to 240 bytes
  both run the same scalar code; the 20-byte row is the first timed loop.

Linux x86_64, Intel Core i9-13900K, normal build without `-mavx2`,
`avx2` chosen at run time (2026-10-29):

| bytes | scalar | sse2 | avx2 | record |
|---|---|---|---|---|
| 20 | 8.1 | 7.8 | 7.8 | 12.5 |
| 28 | 7.8 | 7.8 | 7.8 | 12.4 |
| 60 | 8.1 | 8.1 | 8.1 | 12.4 |
| 124 | 8.7 | 8.7 | 8.7 | 12.4 |
| 300 | 30.9 | 18.0 | 14.7 | 19.0 |
| 1000 | 100.6 | 49.4 | 27.6 | 28.9 |
| 32768 | 3208.6 | 1542.8 | 769.9 | 761.0 |
| 92520 | 9057.3 | 4286.3 | 2175.6 | 2160.6 |

- `record` matches `xxh3+mix` of the `-mavx2` build. The run-time choice
  gives full AVX2 speed in a build that does not require AVX2.
- Per operation (PREPARE, COMMIT, COMPLETE) that is 37 ns with a 124-byte
  PREPARE and 54 ns with a 1000-byte one.
- Above 240 bytes AVX2 is 1.8 to 2 times faster than SSE2, and about
  4 times faster than scalar.

Linux ARM64: to come.

---

## Phase 2: PMEM helper and platform queries

**Scope.** `implementation_plan.md` pull request 3; platform plan S1.3 and
S1.4. It is written in two parts, tested one at a time:

| Part | Package | Content | State |
|---|---|---|---|
| 2a | S1.3 | `ndb_pmem` core: map, prefault, copy, in-place stores, zero, flush, drain | Passed on macOS ARM64 and Linux x86_64 (2026-10-29); Linux ARM64 to be tested |
| 2b | S1.4 | Platform queries: persistence domain, region, NUMA node, bad blocks, dirty shutdown; `Ndb_GetThreadNumaNode()` | `ndb_pmem_region-t` passed on macOS ARM64 (2026-10-29), fixture trees included; `NdbHW-t` gives thread node -1 on macOS, as it should. Passed on Linux x86_64 (2026-10-29): `/tmp` on xfs over `dm-0` gives device `dm-0`, stacked, domain unknown, no bad ranges (exact), no DAX; thread node 0 on the one-socket i9-13900K. Linux ARM64 to be tested |

Nothing calls the helper before S3.2, so file mode is unchanged.

**Changes in 2a.**

| File | Change |
|---|---|
| `include/portlib/ndb_pmem.h` | The API of S1.3 |
| `src/common/portlib/ndb_pmem.cpp` | The copy methods, chosen once and used through a function pointer, and the write-back chosen by CPU. On x86-64: MOVDIR64B, NT stores (AVX, else SSE2), or stores with CLWB, else CLFLUSHOPT, else CLFLUSH; the drain is SFENCE. On aarch64: stores with DC CVAP, or DC CVAC without FEAT_DPB; the drain is DSB SY. Elsewhere `memcpy` and a fence. The map reserves 2 MB more, maps at a 2 MB boundary and releases the rest. The prefault uses `MADV_POPULATE_WRITE`, else writes back one byte per 4 KB. The unit test is in the same file |
| `src/common/portlib/CMakeLists.txt` | `ndb_pmem.cpp` in `ndbportlib`; `ndb_pmem-t` |

**Decisions taken while implementing.**

1. **No new build checks.** `MAP_SHARED_VALIDATE`, `MAP_SYNC` and
   `MADV_POPULATE_WRITE` take the kernel's values when the C library lacks
   them. The platform plan had CMake checks and `ndb_config.h` defines.
2. **MOVDIR64B is written as bytes**, as the Linux kernel does, so no
   compiler support is needed.
3. **`ndb_pmem_init()` can change the method.** It returns `ENOTSUP` for a
   method the CPU lacks and keeps the current one. Calling it again with
   the same method does nothing.
4. **The drain is a function in `ndb_pmem.cpp`, not inline.** The call costs
   about 1 ns against a persist of 200 to 2000 ns, and the power-loss
   emulation of S1.5 hooks in there.
5. **`ndb_pmem_zero()` takes any range.** The end of log E of E12 is not on
   a line boundary. The whole lines in the range use the method; the partial
   lines at either end use stores and a write-back.
6. **On aarch64, `CLWB` means the same as `AUTO`**: stores and DC CVAP.
   `NTSTORE` and `MOVDIR64B` return `ENOTSUP` there.
7. **`ndb_pmem_lock()` (`mlock`) for the DRAM test modes.**
   - On a page-cache file it keeps the REDO pages from being evicted; an
     evicted page would turn a write into a read from disk.
   - It faults shared pages in for reading only, so the prefault comes
     first.
   - Linux skips DAX mappings in `mlock`, so on DAX it does nothing.
   - With `LockPagesInMainMemory` the data node's `mlockall(MCL_CURRENT |
     MCL_FUTURE)` (`src/kernel/vm/ndbd_malloc_impl.cpp:1348`) locks the
     mappings anyway.
   - Locked page cache counts against `RLIMIT_MEMLOCK`, so S3.2 should
     warn and go on if the lock is refused.

**Changes in 2b.**

| File | Change |
|---|---|
| `include/portlib/ndb_pmem.h` | `ndb_pmem_domain`, `ndb_pmem_region_info` and the queries of S1.4 |
| `src/common/portlib/ndb_pmem_region.cpp` | The queries, from sysfs: `fstat` gives the device number; `/sys/dev/block/M:m` gives the block device. Device mapper and md are followed through `slaves/`. The region is the closest directory above with `persistence_domain`, and has `numa_node`, `target_node` and `mapping<k>` naming the DIMMs or memory devices with their dirty-shutdown counts. Bad blocks come from the disk's `badblocks` and the file's `FS_IOC_FIEMAP` extents. DAX comes from `statx`. The NUMA node falls back to `get_mempolicy` on a mapped address. The unit test is in the same file |
| `include/portlib/NdbHW.hpp`, `src/common/portlib/NdbHW.cpp` | `Ndb_GetThreadNumaNode()`: the node whose `cpulist` holds every CPU of the thread's affinity mask, else -1. `NdbHW-t` prints it |
| `src/common/portlib/CMakeLists.txt` | `ndb_pmem_region.cpp` in `ndbportlib`; `ndb_pmem_region-t` |

**Decisions taken in 2b.**

8. **The queries have their own file and test**, `ndb_pmem_region.cpp`
   and `ndb_pmem_region-t`, not `ndb_pmem-t` as the plan had it. They are
   plain sysfs reading, tested on fixture trees, and share nothing with the
   copy code.
9. **`ndb_pmem_get_region_info()`, not `ndb_pmem_region_info()`.** A
   function with the name of the struct would hide the struct in C++, as
   `stat()` hides `struct stat`.
10. **`ndb_pmem_badblocks_overlap()` returns whether the count is exact.**
    It is not when FIEMAP fails, when several devices lie below (device
    mapper), or when no device is found; every range then counts.
11. **An unknown `persistence_domain` string gives `UNKNOWN`**, the
    weakest answer, so a new kernel value never passes as persistent.
12. **`Ndb_GetThreadNumaNode()` reads the node CPU lists itself.** The plan
    had it go through `ndb_cpuinfo_data`, but `NdbHW_Init()` is not called
    in every program, and the start check needs the answer once.

**Commands for the pusher.** `cmake .` first, because there are new source
files. Then, on Linux x86_64, Linux ARM64 and macOS ARM64:

```
cmake --build . --target NdbHW-t ndb_pmem-t ndb_pmem_region-t
ctest -R 'NdbHW-t|ndb_pmem-t|ndb_pmem_region-t' --output-on-failure
./runtime_output_directory/ndb_pmem-t            # methods, faults, timings
./runtime_output_directory/ndb_pmem_region-t     # prints what lies behind $TMPDIR
NDB_PMEM_DIR=/mnt/pmem ./runtime_output_directory/ndb_pmem-t   # Linux, a DAX mount on memmap=
NDB_PMEM_DIR=/mnt/pmem ./runtime_output_directory/ndb_pmem_region-t
```

`ndb_pmem_region-t` checks the parsing on fixture trees: `memmap=`, NFIT
with two DIMMs, CXL-like, eADR, no block device, NVMe, a partition, and
device mapper over two regions. It then prints what lies behind a file in
`$TMPDIR`; with `NDB_PMEM_DIR` it requires a region and a DAX inode.

`ndb_pmem-t` maps a 4 MB file in `$TMPDIR`. There `MAP_SYNC` must fail with
`EOPNOTSUPP` and the optional mapping must work. It tests every copy method
the CPU has with copies, in-place stores and zeroing, and reads the file
back. On Linux it counts the page faults of writing every page in three
cases: after the prefault, on a new file without it, and on a new file
after prefault and lock. It requires none after the prefault only on DAX. On a page-cache file the count depends on how the
kernel maps the cache: Linux x86_64 took 64 faults for 1024 pages, one per
64 KB, on xfs with kernel 6.11; most likely one per large folio (not
verified). A run with `TMPDIR=/dev/shm` (tmpfs, no write tracking) tells
the two apart. It prints ns per copy and drain for each method; on a plain
file these are not the costs on persistent memory. With `NDB_PMEM_DIR`, it
also requires `MAP_SYNC` to work there. On macOS it is the first run of DC
CVAP from user space: a `SIGILL` would mean macOS forbids it (S1.3).

On macOS ARM64 (Apple M5 Pro) `ndb_pmem-t` passed, with DC CVAP and DC
CVAC both running from user space; `auto` chooses `store+dc-cvap`. macOS
reports `EOPNOTSUPP` as "Operation not supported on socket".

ns per copy and drain on a plain file, optimised build, macOS ARM64 (Apple
M5 Pro). These are cache and DRAM costs, not those of persistent memory:

| method | 1 line | 2 lines | 8 lines |
|---|---|---|---|
| store+dc-cvap | 6.0 | 23.0 | 35.9 |
| store+dc-cvac | 6.1 | 21.1 | 33.6 |

On Linux x86_64 (i9-13900K, kernel 6.11) `ndb_pmem-t` passed on tmpfs
(`TMPDIR=/dev/shm`), with all six methods: `auto` chooses `movdir64b`.

- **The prefault works.** Writing the 1024 pages took 0 faults after the
  prefault, 1024 on a new file without it, and 0 after prefault and lock.
- **On xfs it took 64 faults all the same.** That comes from xfs tracking
  writes to its page cache, most likely one fault per 64 KB folio. DAX has
  no page cache.

ns per copy and drain on tmpfs, optimised build:

| method | 1 line | 2 lines | 8 lines |
|---|---|---|---|
| ntstore-sse2 | 55.9 | 57.2 | 63.3 |
| ntstore-avx | 51.9 | 55.9 | 60.4 |
| movdir64b | 51.5 | 53.9 | 60.8 |
| store+clwb | 64.8 | 69.0 | 106.8 |
| store+clflushopt | 65.8 | 73.8 | 118.5 |
| store+clflush | 72.2 | 139.0 | 535.8 |

The SFENCE after NT stores and MOVDIR64B waits for the writes to reach
memory, about 50 ns here, and grows little up to 8 lines. Stores plus a
write-back grow faster, and CLFLUSH orders every line. So `auto` is right
to prefer MOVDIR64B, then NT stores.

---

## Phase 3: Configuration

**Scope.** `implementation_plan.md` pull request 4; platform plan S2.1,
S2.2, S2.3 and S2.7. The parameters exist, the management server checks
them, and the data node reads them. PMEM mode is accepted but nothing
maps a file before phase 4: the REDO log is written as in file mode,
with full initialisation and without ODirect, and the node says so at
every start. File mode is unchanged.

**Changes.**

| File | Change |
|---|---|
| `include/mgmapi/mgmapi_config_parameters.h` | Ids 711–715 (`CFG_DB_REDO_LOG_MODE`, `_REDO_LOG_PATH`, `_REDO_PMEM_TEST_MODE`, `_REDO_PMEM_POWER_LOSS_EMUL`, `_REDO_PMEM_COPY_METHOD`) and their values; 716 is kept for `DurableCommits` |
| `src/common/mgmcommon/ConfigInfo.cpp` | `RedoLogMode` (`file`, `pmem`), `FileSystemPathRedoLog`, `__RedoLogPmemTestMode` (`off`, `emulated`, `nodax`), `__RedoLogPmemPowerLossEmulation`, `__RedoLogPmemCopyMethod` (`auto`, `ntstore`, `movdir64b`, `clwb`). The checks are `checkRedoLogPmem()`, called from `checkDbConstraints` |
| `include/util/RedoLogPaths.hpp`, `src/common/util/RedoLogPaths.cpp` | The parser of `FileSystemPathRedoLog`, in `ndbgeneral`; the unit test is in the same file |
| `src/common/util/CMakeLists.txt` | `RedoLogPaths.cpp`; `RedoLogPaths-t` |
| `src/mgmsrv/testConfig.cpp` | `MgmConfig-t`: the new values in `test_param_values`; `test_redo_log_pmem()` for the checks and what reaches the data node; `test_unique_param_ids()`, no two parameters of one section with the same id |
| `src/kernel/blocks/dblqh/Dblqh.hpp`, `DblqhMain.cpp` | `c_redo_pmem`, `c_redo_pmem_test_mode`. In PMEM mode: refuses `EncryptedFileSystem` and `Diskless`, writes the files in full at an initial start, and opens them without ODirect |
| `src/kernel/blocks/ndbfs/Ndbfs.hpp`, `Ndbfs.cpp` | `read_redo_pmem_config()`, before any file is opened. In PMEM mode: checks the path, refuses `__RedoLogPmemPowerLossEmulation`, chooses the copy method with `ndb_pmem_init()` and refuses one the CPU lacks, and logs the method, the test mode and that the files are not mapped yet |
| `mysql-test/suite/ndb/t/ndb_redo_pmem_config.test`, `r/…result`, `ndb_redo_pmem_*.ini` | `ndb_config` on four config files: warnings, values, three refusals |
| `mysql-test/suite/ndb/pmem_redo.cnf` | Puts a test run in PMEM mode with `nodax` (`--defaults-extra-file`) |

**What the management server checks** (platform plan S2.2):

| Setting | Result |
|---|---|
| `pmem` with `EncryptedFileSystem=1` or `Diskless=1` | Error |
| `pmem`, `FileSystemPathRedoLog` does not parse | Error with the parser's reason |
| `pmem`, `InitFragmentLogFiles` other than `full` | Replaced by `full`, no warning |
| `pmem`, test mode `off`, no `FileSystemPathRedoLog` | Warning: the REDO log goes under `FileSystemPath`, which must be DAX |
| `pmem`, each test setting set | Warning: test setting |
| `file` with `FileSystemPathRedoLog` | Warning: no effect |
| `file` with a test setting | Warning: no effect |

**Decisions taken while implementing.**

1. **PMEM mode starts before phase 4**, written as in file mode, with a
   warning at every start. Refusing it would leave the data-node checks
   of this phase untestable until phase 4.
2. **`__RedoLogPmemPowerLossEmulation` is refused by the data node until
   S1.5 (phase 11).** A test that believes it emulates a power loss but
   does not would pass for the wrong reason. The management server
   accepts it with a warning, so configurations need no change later.
3. **Every test setting gets a warning**, not only the test mode, and
   each one says "no effect" in file mode.
4. **`index_for_node()` reports whether the node had its own entry**
   (`bool *found`). S2.4 warns when a part's node has none.
5. **NUMA node ids go up to 1023**, the largest Linux allows, and blanks
   around an entry and around its `:` are ignored. A path may contain
   `:`; only digits and `:` at the start of an entry name a node.
6. **No allowlist in `test_unique_param_ids()`.** A scan of the 374
   entries in `ConfigInfo.cpp` found no two names with one id in a
   section.
7. **NDBFS parses the path again but does not keep it yet.** The REDO
   base paths come with S3.3 in phase 4.
8. **DBLQH turns ODirect off for the REDO log in PMEM mode.** DBLQH's
   `c_o_direct` is used only by the three REDO open functions.

**Commands for the pusher.** `cmake .` first, because there are new source
files. Then, on Linux x86_64, Linux ARM64 and macOS ARM64:

```
cmake --build .
ctest -R 'RedoLogPaths-t|MgmConfig-t' --output-on-failure
cd mysql-test
./mtr ndb.ndb_redo_pmem_config ndb.ndb_config
./mtr --defaults-extra-file=suite/ndb/pmem_redo.cnf ndb.ndb_basic
```

The whole build is needed: MTR runs `ndb_config`, `ndb_mgmd`, `ndbmtd`
and `mysqld`, which all hold the new parameters.

`ndb_redo_pmem_config.result` was written by hand. The first run showed
that a refused section also got the warning about a missing
`FileSystemPathRedoLog`; `checkRedoLogPmem()` now stops at the first
error, and the result was kept as written. The last run starts the cluster in PMEM mode with
`nodax`; the data node logs show the copy method, the test-mode warning
and that the files are not mapped yet. The initial start writes every
REDO log file in full (4 files of 64 MB per log part in the MTR
configuration), so it takes longer than in file mode.

---

## Phase 4: NDBFS mapping, placement and start checks

**Scope.** `implementation_plan.md` pull request 5; platform plan S3.1–S3.4,
S2.4 and S2.5. In PMEM mode NDBFS maps every REDO log file it opens,
places it on the NUMA node of its log part and checks the platform at
start. The REDO is still written through FSWRITEREQ in today's format, and
files are opened and closed as today (milestone M0.2). Written in three
parts, tested one at a time:

| Part | Packages | Content | State |
|---|---|---|---|
| 4a | S3.1, S3.2, S3.4 | `OM_MAP_SYNC`; NDBFS maps, prefaults and locks a REDO file at open and unmaps it at close; FSOPENCONF carries the address; DBLQH asks for the mapping and keeps the address | Passed on macOS ARM64 and Linux x86_64 (2026-10-30); Linux ARM64 postponed |
| 4b | S3.3, S2.4 | REDO paths under `FileSystemPathRedoLog`, cleanup at initial start, lookup across paths; each log part on the path of its LDM thread's NUMA node | Passed on macOS ARM64 and Linux x86_64 (2026-10-30); Linux ARM64 postponed; the placement on two NUMA nodes needs a two-socket Linux machine |
| 4c | S2.5 | Probe of each REDO path at start, verdict per test mode, bad blocks inside a file, dirty-shutdown count | Passed on macOS ARM64 and Linux x86_64 (2026-10-30), with the refusal of PMEM mode without DAX at the probe; Linux ARM64 postponed; `memmap=` to be run |

**Changes in 4a.**

| File | Change |
|---|---|
| `include/kernel/signaldata/FsOpenReq.hpp`, printer | `OM_MAP_SYNC = 0x20000000` |
| `include/kernel/signaldata/FsConf.hpp`, printer | FSOPENCONF of a mapped file: `PMEM_MAPPED`, `PMEM_MAP_SYNC` in `fileInfo`, 7 words with the address in words 5 and 6 |
| `include/kernel/signaldata/FsRef.hpp` | `fsErrNotDax`, `fsErrPmemMapFailed` |
| `src/kernel/blocks/ndbfs/AsyncFile.hpp`, `AsyncFile.cpp` | `m_pmem`; `openReq` checks the flags, and after the initialisation maps the file (`map_pmem()`): `ndb_pmem_map` with MAP_SYNC required or optional, `ndb_pmem_prefault`, and without MAP_SYNC `ndb_pmem_lock`, with one warning if refused. Every failure path and `closeReq` unmap |
| `src/kernel/blocks/ndbfs/AsyncIoThread.hpp` | `par.open.pmem_addr`, `pmem_map_sync` |
| `src/kernel/blocks/ndbfs/Ndbfs.hpp`, `Ndbfs.cpp` | `m_pmem_map_flags`, optional with `nodax`, read by the IO threads; the 7-word FSOPENCONF; one info line for the first mapped file |
| `src/kernel/blocks/ndbfs/VoidFs.cpp` | `ndbrequire` that no open asks for a mapping |
| `src/kernel/blocks/dblqh/Dblqh.hpp`, `DblqhMain.cpp` | `LogFileRecord::m_pmem_base`. The three REDO open functions zero `secondFileFlags` and add `OM_MAP_SYNC` in PMEM mode; `initFsopenconf` requires the mapping and keeps its address; FSCLOSECONF clears it; FSOPENREF messages for the two new codes; the delayed FSOPENCONF of `ERROR_INSERT 5090` keeps all its words |

**Decisions taken in 4a.**

1. **Phase 4 in three parts**, as phase 2 was: mapping first, then
   placement, then the checks, each testable alone.
2. **Today's open flags plus `OM_MAP_SYNC`.** The plan drops
   `OM_AUTOSYNC`, `OM_WRITE_BUFFER` and `OM_ZEROS_ARE_SPARSE` in PMEM mode,
   but until phase 8 the REDO is written through FSWRITEREQ, which uses
   them. They go with the PMEM write path. `OM_DIRECT` is already off in
   PMEM mode (phase 3).
3. **No `OM_THREAD_POOL` yet.** Files are opened and closed as today, so a
   bound IO thread per open file is as today. Phase 5 keeps every file
   open and needs the pool; FSWRITEREQ on unbound threads may then be
   reordered, which phase 5 must check before it sets the flag.
4. **Only what 4a fills is defined.** `fsErrPmemBadBlocks` and the domain,
   REDO path and NUMA bits of `fileInfo` come with 4b and 4c.
5. **A failed map other than "no MAP_SYNC" is `fsErrPmemMapFailed`**, and
   NDBFS logs the file name and `errno`, since FsRef has room for one code.
6. **DBLQH requires the mapping in PMEM mode** (`ndbrequire` in
   `initFsopenconf`): an unmapped REDO file in PMEM mode is a bug.

**Commands for the pusher.** On Linux x86_64, Linux ARM64 and macOS ARM64:

```
cmake --build .
cd mysql-test
./mtr --defaults-extra-file=suite/ndb/pmem_redo.cnf ndb.ndb_basic
grep -h "REDO log file .* mapped\|cannot be locked" var/mysql_cluster.1/ndbd.*/ndbd.log
./mtr --defaults-extra-file=suite/ndb/pmem_redo.cnf ndb.ndb_restart ndb.ndb_restart2 ndb.testNodeRestartGcpSaveAndFileChange
./mtr ndb.ndb_basic ndb.ndb_restart ndb.ndb_redo_log_reader
```

The first three runs are PMEM mode with `nodax`: every REDO file is
mapped, prefaulted and locked if the memory limit allows; the data node
logs say "mapped without MAP_SYNC", and "cannot be locked" once if the
limit is too low. The grep follows a run of one test, since MTR clears
`var/mysql_cluster.1` when a later test restarts the cluster with another
configuration. The last run is file mode, which must be unchanged.

`ndb.ndb_redo_log_reader` runs in file mode only: its nodes 3 and 4 have
`EncryptedFileSystem=1`, which the management server refuses with
`RedoLogMode=pmem` (phase 3), so the cluster does not start. The same
holds for the tests using `encrypted_filesystem.cnf` and the
`ndb_secretsfile*` tests.

PMEM mode without a test mode must refuse a file system without DAX: a
cnf file with only `[cluster_config]` and `RedoLogMode=pmem`, given to
`--defaults-extra-file`, makes the cluster start fail with exit code 2350
and "cannot be mapped with MAP_SYNC" in the node log.

**4a on Linux x86_64 (2026-10-30): a race in `ndb_pmem_map` (phase 2a
code), fixed.** `ndb.ndb_restart` in `nodax` stopped node 2 with 2350,
"mapping .../D8/DBLQH/S0.FragLog failed: Cannot allocate memory", on XFS
without DAX, kernel 6.11, with 11 GB free. `ndb_pmem_map` reserved a
range, then mapped the file over it with `MAP_FIXED | MAP_SYNC`. XFS
refuses MAP_SYNC without DAX in its mmap handler, after the kernel has
unmapped the reserved range, so another IO thread could place its
reservation in the gap; the fallback `MAP_SHARED | MAP_FIXED`, and the
`munmap` of the whole reservation on error, then hit that thread's
range, whose prefault failed with ENOMEM. A stand-alone program with 8
threads failed 5 to 12 times in 240 maps, never with 1 thread or
without the reservation. The fix: MAP_SYNC is tried on one page mapped
where the kernel chooses, the file is mapped over the reservation once
with flags that work, and after a failure only the head and tail of the
reservation are released. `ndb_pmem-t` gets `test_concurrent_maps` (8
threads, 30 files each, every page tagged and read back), and
`AsyncFile::map_pmem` logs a failed map and a failed prefault apart.
macOS never tries MAP_SYNC, so it did not show. With the fix (commit
8e1334e8060) `ndb_pmem-t` and ten repeats of `ndb.ndb_restart`,
`ndb.ndb_restart2` and `ndb.ndb_basic` in `nodax` passed on Linux x86_64.

Two failures seen while testing phase 4 were not in the REDO code and
are fixed in their own commits: `ndb.ndb_restart2` dropped its table
before the second mysqld had reconnected after the system restart
(edaae483475), and on macOS (`lower_case_table_names=2`) the mysqld
metadata change monitor failed an MDL assertion for `TEST_DB`, a
database the NDBT tests create through the NDB API (544bdc0e830).

**Changes in 4b.** File mode is unchanged: no REDO path slot is filled,
no new flag is sent, and the REDO log stays under `FileSystemPath` with
today's names, cleanup and probes, whether `FileSystemPathRedoLog` is set
or not (`ndb.ndb_redo_paths_file_mode`).

| File | Change |
|---|---|
| `include/kernel/signaldata/FsOpenReq.hpp`, printer | `OM_REDO_PATH = 0x40000000`; the REDO path number in `secondFileFlags` bits 8-11 (`getRedoPathNo`, `setRedoPathNo`), `REDO_PATH_FS = 15` for `FileSystemPath`; `BP_REDO_FIRST = 4` to `BP_REDO_LAST = 11`, `BP_MAX = 12` |
| `include/kernel/signaldata/FsConf.hpp`, printer | `fileInfo` bits 8-11: the REDO path the file was opened under; bits 16-31: NUMA node of the memory + 1, with MAP_SYNC only |
| `src/kernel/blocks/ndbfs/Filename.hpp`, `Filename.cpp` | `set_base_path()`: the same name under another base path |
| `src/kernel/blocks/ndbfs/Ndbfs.hpp`, `Ndbfs.cpp` | PMEM mode: one slot per `FileSystemPathRedoLog` entry, `<path>/ndb_<id>_fs/`, created and checked at READ_CONFIG and logged; an entry that is `FileSystemPath` leaves its slot empty. `get_redo_base_path()`; `OM_REDO_PATH` opens go under the slot; FSOPENCONF carries the path used and the memory's node; parameter names for the slots; the ODirect probe stops before the REDO slots; `ERROR_INSERT 2000/2001` also save and restore the REDO paths |
| `src/kernel/blocks/ndbfs/AsyncFile.hpp`, `AsyncFile.cpp` | `open_redo_elsewhere()`: an `OM_REDO_PATH` open that finds no file looks under the other REDO paths, then `FileSystemPath`; `map_pmem()` fills the request and, with MAP_SYNC, the NUMA node of the memory (`ndb_pmem_numa_node`) |
| `src/kernel/blocks/ndbfs/AsyncIoThread.hpp` | `par.open.pmem_numa_node`, `redo_path_no` |
| `src/kernel/blocks/ndbfs/VoidFs.cpp` | `ndbrequire` that no open asks for a REDO path |
| `src/kernel/blocks/ndbcntr/NdbcntrMain.cpp` | `clearFilesystem`: 8 more steps, `V_BASEPATH` `BP_REDO_FIRST + i` with `ownDirectory = 0`; NDBFS answers at once for an empty slot, without touching the disk, as for unset Disk Data paths |
| `src/kernel/blocks/dblqh/Dblqh.hpp`, `DblqhMain.cpp` | `c_ldm_numa_node`, `c_redo_path_no`; `LogPartRecord::m_redo_path_no`, `m_redo_path_warned`, `m_redo_numa_checked`. `initRedoPathConfig()` in READ_CONFIG: the LDM's NUMA node (`Ndb_GetThreadNumaNode`), its path (`RedoLogPaths::index_for_node`), one info line, or a warning if unbound or not listed. `setRedoPmemOpenFlags()` in the three open functions. `checkRedoPmemPlacement()` in `initFsopenconf`: adopts the path a file was found under, one warning per part, and one warning if the memory is on another NUMA node. FSOPENREF "not under FileSystemPathRedoLog or FileSystemPath; was FileSystemPathRedoLog changed without --initial?" |
| `mysql-test/suite/ndb/t/ndb_redo_pmem_paths.{test,cnf}`, `r/` | PMEM mode with `nodax`, `FileSystemPathRedoLog` = the cluster's BackupDataDir: files there and not under `FileSystemPath`; system restart, node restart, a log part moved to `FileSystemPath` found there with one warning, initial node restart puts it back |
| `mysql-test/suite/ndb/t/ndb_redo_paths_file_mode.{test,cnf}`, `r/` | File mode with `FileSystemPathRedoLog` set: files under `FileSystemPath`, nothing created under the REDO path, and an initial node restart leaves a file there alone |

**Decisions taken in 4b.**

1. **File mode is unchanged.** NDBFS returns from
   `read_redo_pmem_config` before it fills a REDO slot, DBLQH sets
   `OM_REDO_PATH` only under `c_redo_pmem`, and the ODirect probe covers
   the same four base paths as before. The one difference is the 8 more
   FSREMOVEREQ steps of an initial start, answered by NDBFS for an empty
   slot without touching the disk.
2. **PMEM mode always sends `OM_REDO_PATH`.** Without
   `FileSystemPathRedoLog` the path is `REDO_PATH_FS`, so there is one
   code path; NDBFS then finds no other place to look.
3. **The path number is 4 bits** in both `secondFileFlags` and
   `fileInfo` (bits 8-11), so both carry `REDO_PATH_FS = 15`; the plan had
   8 bits in `secondFileFlags`.
4. **`Filename::set_base_path()` instead of a new argument to
   `Filename::set`**: the lookup in the IO thread rebuilds the name too.
5. **Lookup order**: the other REDO paths by number, then
   `FileSystemPath`. NDBFS reports the path it opened under; DBLQH adopts
   it for the part, so its next files are asked for there, and warns once
   per part. NDBFS does not log each file.
6. **The memory's NUMA node is reported with MAP_SYNC only.** With
   `nodax` the memory is the page cache, placed by the IO thread that
   faulted it in, so a comparison would say nothing about the hardware.
7. **`ERROR_INSERT 2000/2001` save and restore the REDO paths too**, so
   the testSystemRestart case that uses them works in PMEM mode.
8. **The ODirect probe stops at `BP_REDO_FIRST`** instead of skipping
   empty REDO slots: PMEM mode never opens a REDO file with ODirect.
9. **Fix of 4a found while reading**: `openFileRw_cache` sends itself a
   2-word FSOPENCONF for a REDO file it keeps open during REDO execution.
   4a's `ndbrequire` of 7 words would have stopped the node at the first
   cache hit. `initFsopenconf` now requires the mapping only in an
   FSOPENCONF from NDBFS, and otherwise that the file is still mapped.

**Commands for the pusher (4b).** On Linux x86_64, Linux ARM64 and macOS
ARM64:

```
cmake --build .
cd mysql-test
./mtr ndb.ndb_redo_paths_file_mode
./mtr ndb.ndb_redo_pmem_paths
grep -h "RedoLogMode=pmem: REDO path\|REDO log parts go on\|were found under" var/mysql_cluster.1/ndbd.*/ndbd.log
./mtr --defaults-extra-file=suite/ndb/pmem_redo.cnf ndb.ndb_basic ndb.ndb_restart ndb.ndb_restart2 ndb.testNodeRestartGcpSaveAndFileChange
./mtr ndb.ndb_basic ndb.ndb_restart ndb.ndb_redo_log_reader ndb.ndb_redo_pmem_config
```

The grep shows, for each data node, "REDO path 0 (every NUMA node):
.../mysql_cluster.1/ndb_<id>_fs/" at each start, one "REDO log parts go
on REDO path 0" line per LDM (NUMA node "not known" on macOS, 0 on a
one-socket Linux machine), and on node 2 one "log part 1 were found under
FileSystemPath" line. The `pmem_redo.cnf` runs are PMEM mode without
`FileSystemPathRedoLog`, the last run file mode.

On a two-socket Linux machine, PMEM mode with
`ThreadConfig=ldm={count=2,cpubind=<a CPU of node 0>,<a CPU of node 1>}`
and `FileSystemPathRedoLog=0:/path/a,1:/path/b` puts log parts 0 and 2
under `/path/a/ndb_<id>_fs/` and 1 and 3 under `/path/b/ndb_<id>_fs/`.

**Changes in 4c.** File mode and `nodax` are unchanged: neither probes
anything.

| File | Change |
|---|---|
| `include/util/RedoLogPaths.hpp`, `src/common/util/RedoLogPaths.cpp` | `RedoPmemProbe`, `RedoPmemVerdict` and the pure function `redo_pmem_path_verdict()`; `RedoLogPaths-t` tests it on probe fixtures in all three test modes |
| `include/portlib/ndb_pmem.h`, `src/common/portlib/ndb_pmem.cpp` | `ndb_pmem_cpu_persists()`: x86-64 always, aarch64 with DC CVAP; `ndb_pmem-t` prints and checks it |
| `src/kernel/blocks/ndbfs/Ndbfs.hpp`, `Ndbfs.cpp` | `probe_redo_path_pmem()`, from `read_redo_pmem_config` in production and `emulated` mode: `ndb_<id>_pmem_probe.tmp` of 2 MB under each REDO path in use, mapped with MAP_SYNC required, `ndb_pmem_get_region_info()`, removed; the verdict refuses the start (2350) or logs warnings and one info line. Production mode refuses a CPU that cannot persist, `emulated` warns |
| `include/kernel/signaldata/FsRef.hpp` | `fsErrPmemBadBlocks = FS_ERR_BIT \| 18` |
| `src/kernel/blocks/ndbfs/AsyncFile.cpp` | `map_pmem()` with MAP_SYNC: a file on bad blocks (`ndb_pmem_badblocks_overlap`) is unmapped and refused before the prefault |
| `src/kernel/blocks/dblqh/DblqhMain.cpp` | FSOPENREF message for `fsErrPmemBadBlocks`; the `fsErrNotDax` message no longer names `FileSystemPath` |

What the verdict does (E17, platform plan S2.5):

| Probe | `off` (production) | `emulated` | `nodax` |
|---|---|---|---|
| MAP_SYNC refused | refuse: "... is not on a DAX file system (mmap MAP_SYNC: ...)" | refuse | not probed |
| No region found, or not read | refuse: "... its persistence domain is not known" | refuse | not probed |
| Region without a persistence domain (`memmap=`) | refuse: "... reports no persistence domain (memmap= emulation?)" | warning | not probed |
| `memory_controller`, `cpu_cache` | info line | info line | not probed |
| Bad-block ranges on the device | warning with the count | warning | not probed |
| Dirty-shutdown count | in the info line, or "not exposed" | same | not probed |

**Decisions taken in 4c.**

1. **`nodax` probes nothing**, as the plan's table skips every check
   there, so macOS and Linux without DAX start as in 4b.
2. **The paths probed** are each REDO path in use and `FileSystemPath`
   when some REDO log goes there (no `FileSystemPathRedoLog`, or an entry
   that is `FileSystemPath`). A file found elsewhere by the 4b lookup is
   still checked at its open, for MAP_SYNC and bad blocks.
3. **The verdict lives in `util/RedoLogPaths`**, not in NDBFS, so that
   `RedoLogPaths-t` tests it without a data node.
4. **A DAX file system without a region found is refused** in production
   and `emulated` mode, as in the plan: MAP_SYNC works but nothing says
   whether the memory persists.
5. **Bad blocks inside a file are refused, outside a warning.** When the
   extents of the file cannot be known (no FIEMAP, a stacked device),
   every range of the device counts, as `ndb_pmem_badblocks_overlap`
   says; refusing such a node is better than a SIGBUS.
6. **The dirty-shutdown count is only logged.** "Not exposed" means
   unknown, not clean (design issue 9). Recording it in the control area
   and warning when it grew is S6 (R10).
7. **No `get_redo_path_info()` table and no domain bits in `fileInfo`
   yet.** Their readers are ndbinfo (S2.6) and S6, so they come with them.
8. **ARM without DC CVAP** is refused in production mode, a warning with
   `emulated`, nothing with `nodax`.

**Commands for the pusher (4c).** On Linux x86_64, Linux ARM64 and macOS
ARM64:

```
cmake --build .
ctest -R "RedoLogPaths-t|ndb_pmem-t" --output-on-failure
cd mysql-test
./mtr --defaults-extra-file=suite/ndb/pmem_redo.cnf ndb.ndb_basic ndb.ndb_restart ndb.ndb_restart2 ndb.testNodeRestartGcpSaveAndFileChange
./mtr ndb.ndb_redo_pmem_paths ndb.ndb_redo_paths_file_mode ndb.ndb_basic ndb.ndb_redo_pmem_config
```

`RedoLogPaths-t` prints a "verdict" line per case. The refusal now comes
from the probe, before the initial start writes the REDO log: a cnf file
with only `[cluster_config]` and `RedoLogMode=pmem`, given to
`--defaults-extra-file`, makes the start fail with exit code 2350 and
"RedoLogMode=pmem: FileSystemPath ... is not on a DAX file system (mmap
MAP_SYNC: Operation not supported)" in the node log. The same with
`__RedoLogPmemTestMode=emulated` added.

On Linux with `memmap=` (optional): production mode refuses with
"reports no persistence domain", and `emulated` starts with a warning and
an info line naming the region.

---

## Phase 5: every REDO log file kept open and mapped; ndbinfo

**Scope.** `implementation_plan.md` pull request 6; platform plan S3.5,
S3.6 and S2.6. In PMEM mode every REDO log file is mapped from its first
open until the node stops, so that phase 8 can write and read the whole
log through the mappings. The REDO is still written through FSWRITEREQ
in today's format. Written in two parts:

| Part | Packages | Content | State |
|---|---|---|---|
| 5a | S3.5, S3.6 | NDBFS keeps a REDO log file open and mapped when DBLQH closes it; DBLQH's later opens of the file are answered without NDBFS; the initial start keeps the files it writes; a system or node restart opens every file of each log part before it reads the log | Passed on macOS ARM64 (2026-10-31): `ndb_redo_pmem_restarts` with every log part of both nodes mapped at each of the 11 system restarts and at the node's own restart, `ndb_redo_pmem_paths`, the `pmem_redo.cnf` run and the file-mode run. Linux x86_64 to be tested |
| 5b | S2.6 | ndbinfo `redo_log_pmem`: one row per log part in PMEM mode, with its files, mappings, NUMA nodes, persistence domain, copy method, test mode, the write counters of phase 8 and the dirty-shutdown count | Passed on macOS ARM64 (2026-11-02): `ndbinfo`, `ndbinfo_plans`, `ndb_redo_pmem_paths` with the 8 rows and the log part under FileSystemPath, `ndb_redo_paths_file_mode` with no rows, the `pmem_redo.cnf` run and `ndb_redo_pmem_restarts`. Linux x86_64 to be tested |

**Changes in 5a.** File mode is unchanged: the new flag and state are
used under `c_redo_pmem` only.

| File | Change |
|---|---|
| `include/kernel/signaldata/FsCloseReq.hpp`, printer | Keep-open flag (`fileFlag = 2`, `getKeepOpenFlag`, `setKeepOpenFlag`); DBLQH is a friend |
| `src/kernel/blocks/ndbfs/AsyncIoThread.hpp`, `AsyncIoThread.cpp` | `Request::closeKeepOpen`: the IO thread of the file syncs it and does not close or unbind it |
| `src/kernel/blocks/ndbfs/Ndbfs.cpp` | FSCLOSEREQ with the keep-open flag becomes `closeKeepOpen`; its FSCLOSECONF leaves the file open, mapped and bound to its thread; an error gives FSCLOSEREF as for a close. In PMEM mode the bound threads created at start cover `NoOfFragmentLogFiles` files per log part instead of 4, which also raises `MaxNoOfOpenFiles` when it is set too low |
| `src/kernel/blocks/ndbfs/VoidFs.cpp` | `ndbrequire` that no close keeps the file open |
| `src/kernel/blocks/dblqh/Dblqh.hpp`, `DblqhMain.cpp` | `LogFileRecord::m_pmem_fileRef`: the NDBFS file from the first open on, while `fileRef` stays RNIL whenever the file is closed for DBLQH; `m_pmem_base` is no longer cleared at FSCLOSECONF. `closeFile()` sets the keep-open flag in PMEM mode, and `release()` of the open-file cache uses `closeFile()`. `openKeptRedoFile()`: an FSOPENCONF of 2 words to the log part's owner, as from `openFileRw_cache()`, used by `openFileRw()` and `openNextLogfile()` for a kept file. `initFsopenconf` keeps `m_pmem_fileRef` from NDBFS's FSOPENCONF and requires that NDBFS opens a file once. SR and NR: `openAllRedoFilesPmem()` from `startphase3Lab`, state `OPENING_PMEM_MAP_ALL`, counter `LogPartRecord::m_pmem_files_to_map`, one info line per log part, then file 0 as before. `setRedoPmemOpenFlags()` drops `OM_WRITE_BUFFER`. The start log counts `OPENING_PMEM_MAP_ALL` as opening |
| `mysql-test/suite/ndb/t/ndb_redo_pmem_restarts.{test,cnf}`, `r/` | PMEM mode with `nodax`: `testSystemRestart -n SR1` and `-n SR2`, `testNodeRestart -n NoLoad`, one loop each, and the info line of the restarts in both node logs. Both mysqlds are stopped while NDBT runs, as in `ndb_scan_start_restart`: NDBT creates `TEST_DB.T1` from the NDB API, and on a case-insensitive file system (macOS) the mysqld metadata sync retries `CREATE DATABASE TEST_DB` after each system restart and fails the warning check |

**Decisions taken in 5a.**

1. **The close keeps the file in NDBFS but syncs it as a close does.**
   The plan's virtual close, an FSCLOSECONF that DBLQH sends itself,
   would skip the `fsync` that NDBFS does at every close, and today's
   REDO log relies on it: `checkGcpCompleted` takes a file in
   `CLOSING_WRITE_LOG` or `CLOSED` as synced and sends FSSYNCREQ only for
   open files, and the invalidation at a system restart syncs at MByte
   boundaries only and leaves the rest to the close. So `closeFile()`
   sends FSCLOSEREQ with the keep-open flag; NDBFS syncs the file on its
   own IO thread, after the writes queued before, and answers
   FSCLOSECONF. PMEM mode keeps the durability of file mode until phase 8.
2. **The open is the plan's virtual open**, an FSOPENCONF without the
   mapping words to the owner of the log part. `execFSOPENCONF` runs
   unchanged, with the `ERROR_INSERT 5090` delay. `openNextLogfile()`
   may run in an LDM that shares the part; it reads `m_pmem_fileRef`
   under the part's lock, and `initFsopenconf` sets it under the lock.
3. **The initial start needs no change of its own.** The close at the
   end of each file's initialisation keeps the file, so `initFourth` and
   normal operation find every file open. The plan's
   `initNextLogfile()` is not needed.
4. **No `OM_THREAD_POOL`; each kept file keeps its bound IO thread.**
   `checkGcpCompleted` takes a GCP as written when a write at or after
   its last word completes, which holds only if the writes of one file
   complete in order. Pool threads take requests from a shared queue, so
   two writes of a file could complete out of order, and two writes of
   page 0 could land in the wrong order. A node thus has
   `NoOfFragmentLogFiles` × log parts bound threads for the REDO log
   (16 × 4 = 64 by default, 16 in MTR). When phase 8 stops sending
   FSWRITEREQ in PMEM mode, the pool becomes safe.
5. **No `OM_WRITE_BUFFER` in PMEM mode.** The buffer, 256 kB of
   `RG_FILE_BUFFERS` per open file, which `ndbd.cpp` sizes for 4 open
   files per log part, only joins the pages of a write into one
   `pwrite`. With every file open the resource would run out. Without it
   NDBFS writes page by page. Phase 4 decision 2 is corrected here: the
   flag does not change what FSWRITEREQ writes.
6. **SR and NR open all files of a part at once** and wait for all
   before file 0 is read, so that the whole log is mapped before the
   search for its end. A file found under another REDO path is adopted
   as in 4b, with one warning per log part.

**Commands for the pusher (5a).** On Linux x86_64, Linux ARM64 and macOS
ARM64:

```
cmake --build .
cd mysql-test
./mtr ndb.ndb_redo_pmem_restarts
for n in 1 2; do grep -ho "log part [0-9]* are open and mapped, [0-9]* MB" var/mysql_cluster.1/ndbd.$n/ndbd.log | sort | uniq -c; done
./mtr ndb.ndb_redo_pmem_paths
./mtr --defaults-extra-file=suite/ndb/pmem_redo.cnf ndb.ndb_basic ndb.ndb_restart ndb.ndb_restart2 ndb.testNodeRestartGcpSaveAndFileChange
./mtr ndb.ndb_basic ndb.ndb_restart ndb.ndb_redo_log_reader ndb.ndb_redo_paths_file_mode ndb.testNodeRestartGcpSaveAndFileChange
```

`ndb.ndb_redo_pmem_restarts` needs an error-insert build and runs for
several minutes; add `--testcase-timeout=30` if it times out. The grep
counts, per data node, the lines "the 4 REDO log files of log part N
are open and mapped, 64 MB": one per log part at every system restart
and at the node's own restart, 12 for each of parts 0-3 on both nodes
(11 system restarts in SR1 and SR2, one node restart in NoLoad). The
last run is file mode, which must be unchanged:
`closeFile()`, `openFileRw()` and the open-file cache were touched.

The `ndb.ndb_redo_pmem_restarts` run also covers the testSystemRestart
subset of phase 4's gate in `nodax`. `testRedo -n RestartOK`,
`-n RestartFDSR` and `-n CheckNextRedoFileOpened` change the REDO
configuration and restart with `--initial`, so they stay with the
autotest run of phase 8.

**Changes in 5b.** File mode has no rows in the new table and is
otherwise unchanged.

| File | Change |
|---|---|
| `include/debugger/Ndbinfo.hpp`, `src/common/debugger/NdbinfoTables.cpp` | `REDO_LOG_PMEM_TABLEID = 61`, table `ndb$redo_log_pmem` of 24 columns, estimate data nodes × log parts |
| `plugin/ha_ndbinfo_sql.cc` | View `redo_log_pmem`: `redo_path` NULL for FileSystemPath, the NUMA nodes and the dirty-shutdown count NULL when unknown, the persistence domain (`none`, `memory_controller`, `cpu_cache`) and the test mode (`off`, `emulated`, `nodax`) as names |
| `src/kernel/vm/GlobalData.hpp` | `theRedoPmemPath[16]`: the persistence domain and the dirty-shutdown count of each REDO path, indexed by the REDO path number of FsOpenReq; unknown until probed |
| `src/kernel/blocks/ndbfs/Ndbfs.cpp` | `probe_redo_path_pmem()` records what it found in `theRedoPmemPath`; a REDO path that is FileSystemPath gets the probe of FileSystemPath |
| `src/kernel/blocks/dblqh/Dblqh.hpp`, `DblqhMain.cpp` | `LogPartRecord::m_pmem_stats` (`RedoPmemStats`: barriers, bytes copied, filler bytes, timed persists and their 8-bucket histogram), zeroed in `initLogpart`; `m_pmem_mem_numa_node` replaces `m_redo_numa_checked` and keeps the node that `checkRedoPmemPlacement()` checked. `execDBINFO_SCANREQ`: one row per log part of the LDM in PMEM mode, `mapped_bytes` from the files whose `m_pmem_base` is set |
| `mysql-test/suite/ndb/r/ndbinfo.result`, `ndbinfo_plans.result` | The new table: 62 tables, 656 columns, `ndb$redo_log_pmem` with 8 estimated rows of 164 bytes |
| `mysql-test/suite/ndb/t/ndb_redo_pmem_paths.test`, `r/` | The 8 rows after the initial start, 4 files and 64 MB mapped per log part; `redo_path` NULL for log part 1 of node 2 while its files are under FileSystemPath, 0 again after the initial node restart |
| `mysql-test/suite/ndb/t/ndb_redo_paths_file_mode.test`, `r/` | No rows in file mode |

**Decisions taken in 5b.**

1. **The persistence domain and the dirty-shutdown count come from the
   start-time probe of each REDO path**, kept in `GlobalData`, which
   NDBFS writes in its READ_CONFIG_REQ before DBLQH starts. They are
   properties of the device behind a path, not of a file, so the
   `fileInfo` domain bits and the per-file fields of the plan are not
   needed. With `nodax` nothing is probed and both are unknown (NULL).
   This settles 4c decision 7: no `get_redo_path_info()`, no domain
   bits in `fileInfo`.
2. **The memory NUMA node is the one of the first file mapped with
   MAP_SYNC**, as checked in 4b; the files of a log part lie under one
   path. Without MAP_SYNC the memory is the page cache and the node is
   unknown (NULL).
3. **One more column than planned, `redo_path`**: which
   `FileSystemPathRedoLog` entry holds the files of the log part, NULL
   for FileSystemPath. It shows where 4b put each log part and when a
   file was found under another path.
4. **The write counters and the latency histogram are in place and stay
   0** until phase 8 writes the REDO log through the mapping; its persist
   updates them under the log part lock and times one persist in 16.
   The buckets are at most 250 ns, 500 ns, 1, 2, 4, 8 and 16 us, and more.
5. **The view decodes the enumerations and the unknown values**; the
   base table keeps the numbers (`~0` for an unknown NUMA node or
   dirty-shutdown count, 15 for FileSystemPath), as `logspaces` does.

**Commands for the pusher (5b).** On Linux x86_64, Linux ARM64 and macOS
ARM64:

```
cmake --build .
cd mysql-test
./mtr ndb.ndbinfo ndb.ndbinfo_plans ndb.ndb_redo_pmem_paths ndb.ndb_redo_paths_file_mode
./mtr --defaults-extra-file=suite/ndb/pmem_redo.cnf ndb.ndb_basic ndb.ndb_restart
./mtr ndb.ndb_redo_pmem_restarts
```

`ndb.ndbinfo` and `ndb.ndbinfo_plans` were edited by hand for the new
table; if they differ only there, `./mtr --record ndb.ndbinfo
ndb.ndbinfo_plans` and a look at the diff settle it.

`ndb.ndbinfo_plans` also failed on two things that are not 5b, fixed in
separate commits:

- `ndb$config_values` was more than 10 rows from its estimate of 394.
  Phase 3 added four data node parameters that have defaults
  (`RedoLogMode`, `__RedoLogPmemTestMode`,
  `__RedoLogPmemPowerLossEmulation`, `__RedoLogPmemCopyMethod`), 8 rows
  for 2 data nodes; `FileSystemPathRedoLog` has no default and is unset
  in MTR. The constant in `NdbinfoTables.cpp` goes from 197 to 201
  parameters per data node, the estimate to 402.
- `ndb$error_messages` has 942 rows, not 941: error 947 came into
  26.10 with the merge of 26.05-main. 26.10-main fixed the result in
  575c5782b3c after this branch was made; the same line is taken here.

On Linux with
`memmap=` and `emulated`, `SELECT * FROM ndbinfo.redo_log_pmem` should
show `persistence_domain` `none` and the memory NUMA node of the region.

---

## Phase 6: record format and reader module

**Scope.** `implementation_plan.md` pull request 7; write plan S4.1 and
recovery plan S6.2, tests U2-U4 (`impl_step1_recovery_test.md` §4.1).
The bytes of the PMEM format and the restart scan over them, tested on
synthetic logs. Nothing in the data node calls them yet: the writers
come in phase 7, the restart in phase 8. File mode is unchanged.

**Changes.**

| File | Change |
|---|---|
| `src/kernel/blocks/dblqh/PmemRedoFormat.hpp` | New, header-only, namespace `PmemRedo`: geometry, W = 64, record types and flags, record and page-header word numbers, sizes (`PREPARE_MAX` 23130 from `ndb_limits.h`, `RESERVE` 46), `makeW0`/`w0Type`/`w0Flags`/`w0Len`, `padWords`, `prepareLen`, `fdLen`, `maxFdFiles`, `lsn`, the suffix S, `RecChecksum` (one piece per page, chained through the seed), `recordChecksum`, `headerChecksum`, `buildPageHeader` (no mask, R2), the `Reason` codes with `reasonName`, `checkPageHeader` (V1 without the lap), `checkFraming` (V2 on w0), `prepareLenOk`, `fdLenOk`, `checkRecordWords`/`recordOk` for a record inside one page |
| `src/kernel/blocks/dblqh/PmemRedoScan.hpp`, `.cpp` | New: `Pos`, `Geom`, `PartView` (the mapped files of a part), `checkPage` (V1), `checkRecord` (V1-V5 with records over up to 4 pages), `findEnd` (E), `findLastMbyte` (phase 1 step 3), `mbyteStart`, `nextMbyteStart`, `ceilUnit`, `expectedLap`, `posLsn` |
| `src/kernel/blocks/CMakeLists.txt` | `dblqh/PmemRedoScan.cpp` in `ndbblocks` |
| `src/kernel/blocks/dblqh/CMakeLists.txt` | `pmem_redo_format-t`, and `pmem_redo_scan-t` built with `PmemRedoScan.cpp` |
| `src/kernel/blocks/dblqh/pmem_redo_format-t.cpp` | U2, writer side (S4.1): the checksum against xxhash's own `XXH3_64bits` and `XXH3_64bits_withSeed`, `EMPTY_HASH`, two pieces against one; every record type accepted, rejected after a change of any body word or of any word of S, `RF_INVALIDATED` kept by a COMMIT only, a FILLER's body not covered; the framing bounds; the header image and a change of any of its 32 words; `padWords`, `prepareLen`, `fdLen` for every file size, `RESERVE` |
| `src/kernel/blocks/dblqh/pmem_redo_scan-t.cpp` | U2 reader side, U3 and U4. `TestLog` writes a part as the PMEM writer will (format §7) and keeps the old content of every 64-byte line stored since the last fence, so that a crash leaves each line old, new or torn at 8 bytes (crash model A2). Crafted records for every reason code. The cases of recovery §3.3: clean end with a FILLER, the previous lap's record at E (mid-page and at a page start), torn last record, unwritten and torn page header, a PREPARE over 4 pages and a torn spanned header, torn and old mbyte header, zeroed region, the next file's FD torn and the slot lagging, orphans after a hole. Random logs: lap 1-3 over the previous lap (half the time the same records), crash after a random event, E checked against what was written, a restart at E or at an earlier record end, a second crash and the check again; the same with no zeroing must fail |

**Decisions taken while implementing.**

1. **The split of recovery plan Q4:** `PmemRedoFormat.hpp` holds what
   the writers need and what checks one record or one header;
   `PmemRedoScan` holds what reads the mapped files of a part. The
   control area and the last-file slots (S6.3) and their test U5
   (`pmem_redo_slot-t`) come with S6.3 in phase 8, as the S6.2
   signatures say.
2. **The type and flag names live in `PmemRedoFormat.hpp`** for now.
   The `Dblqh.hpp` macros of the write plan (`ZFILLER_TYPE` and the
   others) come with the writers in phase 7, so phase 6 changes no DBLQH
   file.
3. **A record other than NEXT_MBYTE must leave 2 words for a
   NEXT_MBYTE** before the end of its mbyte; a NEXT_MBYTE may end at it.
   This is the placement rule of format §7.1 (`size + 2 ≤ remaining`)
   checked by the reader, and the meaning of "ends before the end of the
   mbyte" in format §3.4.
4. **V5 is strict.** Page 0 holds the FD at word 32 and the FILLER to the
   page end right after it, nothing else. Every other FILLER is at most
   14 words (shorter than W) and ends on a W boundary. The format allowed
   a FILLER of up to 8160 words anywhere, but no writer makes one.
5. **The page header check includes W and the restart generation:** a
   header with another write unit or a restart generation other than 0
   is not this format (`R_HDR_FORMAT`), like a wrong magic.
6. **The FD length is checked against its count of descriptors,**
   1 ≤ nFD ≤ min(files, `maxFdFiles`), since DUMP 2396 can lower
   `cmaxLogFilesInPageZero` below the maximum.
7. **`findEnd` follows a valid NEXT_MBYTE into the next mbyte of the same
   file too**, not only into the next file. In phase 1 that header is
   invalid anyway, since it is how the last mbyte was chosen; the scan
   stays a plain walk of the chain.
8. **`findLastMbyte` is here**, from S6.4: the case "mbyte header torn or
   old" of recovery §3.3 needs it. It reports a valid header after the
   drop, which the caller treats as corruption.
9. **A NEXT_MBYTE at the first record position of an mbyte is valid.**
   The writer never places one there, but nothing in the format forbids
   it, and the test uses it to skip mbytes.
10. **Found for S6.6, the restart that moves the head back across a file
    switch.** The later file keeps page 0, with an FD of the abandoned log
    in the same lap. If writing then crosses into that file and a crash
    leaves the new FD unwritten, the scan accepts the old FD and FILLER.
    The test's restart therefore, after the slot names the head's file,
    zeroes page 0 of every later file up to E's file. The order is: zero,
    slot, page 0 of those files, close the unit; each fenced. Closing the
    unit goes after the slot because it can be a file switch itself (the
    unit ends the last mbyte of the file), which writes the next slot.
    The recovery plan said "zero, then close, then slot"; S6.6 should take
    this order.
11. **The valid reason is `R_VALID`, not `R_OK`:** `R_OK` is a macro of
    `<unistd.h>` (`access()`), which the NDB headers pull in. The first
    build on macOS failed on it.

**Commands for the pusher.** `cmake .` first, because there are new
source files. Then, on Linux x86_64, Linux ARM64 and macOS ARM64:

```
cmake --build .
ctest -R pmem_redo --output-on-failure
./runtime_output_directory/pmem_redo_scan-t --random --loops=10000
```

`ctest` runs `pmem_redo_format-t` and `pmem_redo_scan-t` with 300 random
logs from seed 1; the second run takes 10000 from a time-based seed and
prints it. A failure prints the seed that replays it with
`--random --seed=<seed> --loops=1`. The whole build is needed because
`PmemRedoScan.cpp` is now compiled into `ndbblocks`; no data node code
calls it, so no MTR run is needed for this phase.

**First runs on macOS ARM64 (2026-11-02).** The build failed on `R_OK`
(decision 11). Then random log 0 failed: E before the last fence. The
test writer was wrong, not the scan: `startFile` built the FD in `m_buf`,
which still held the body of the record whose `append()` switched file,
so that record was stored with FD words in its body; for a PREPARE the
key and attrinfo lengths no longer matched and the scan rejected it
(`R_LEN`) correctly. The FD now has its own buffer. The zeroing control
had passed on that same failure, before the restart; it now counts a
log only if it passes with the zeroing and fails without it. After
these fixes all tests passed.

---

## Phase 7: record writers

**Scope.** `implementation_plan.md` pull request 8; write plan S4.2-S4.7
and S5.1. The DBLQH writers of every record in the PMEM format, the
reservation of S4.7, and the LSN helpers and fields of S5.1. They build
the records in the DRAM log pages; moving the pages to the mapping is
phase 8 (S5.2-S5.5), together with the restart that reads them, so that
PMEM mode never writes a log it cannot read. Until then the writers are
not entered: PMEM mode still writes today's format, and file mode is
unchanged.

**Changes.**

| File | Change |
|---|---|
| `src/kernel/blocks/dblqh/PmemRedoFormat.hpp` | `PREPARE_MAX_PAGES` (4); `splitChecksum` (a record built in one buffer, split by a page end), `pagesSpanned`, `pagedChecksum` (a record where it lies in the log pages, one piece per page); the builders `prepareHead`, `commitRecord`, `abortRecord`, `completeRecord`, `completedGciRecord`; the reservation states `RESERVED_NONE/FULL/TAIL`, `RedoRelease { AT_COMMIT, AT_COMPLETE, AT_ABORT }` and `releasedWords` (the table of S4.7) |
| `src/kernel/blocks/dblqh/Dblqh.hpp` | Includes `PmemRedoFormat.hpp`. `LogPartRecord::m_pmem_persisted_lsn`; `TcConnectionrec::m_redo_end_lsn` (0 in the constructor, `seizeTcrec`, `execLQHKEYREQ`); `c_redo_pmem_format`; the declarations below |
| `src/kernel/blocks/dblqh/DblqhMain.cpp` | `c_redo_pmem_format = false` at READ_CONFIG. Dispatch on it in `doWritePrepareLog`, `checkNewMbyte` (the PMEM length), `writeAbortLog`, `writeCommitLog`, `writeCompletedGciLog`, `increment_committed_mbytes` (46 words). A "PMEM format" section after `writeNextLog`: static asserts that the format keeps today's geometry, type numbers and header words; `redoSuffix`, `redoAppendFixed` (S4.2); `writePrepareLogPmem` (S4.3); `writeCommitLogPmem`, `writeAbortLogPmem`, `writeCompletedGciLogPmem` (with error insert 5051), `writeCompleteLog` (no caller until X4) (S4.4); `writeFillerPmem`, `writeNextMbytePmem` (S4.5); `redoBuildPageZero`, `redoPmemHeaderImage` (S4.6); `release_committed_words` (S4.7); `redoLsn`, `redoPosLsn`, `redoAppendLsn`, `redoPmemAddr`, `redoHasUnpersisted`, `redoInitWritePosition` (S5.1) |
| `src/kernel/blocks/dblqh/CMakeLists.txt` | `pmem_redo_writer-t`, built with `PmemRedoScan.cpp` |
| `src/kernel/blocks/dblqh/pmem_redo_writer-t.cpp` | The words of every builder, each record accepted in one page; COMMIT, ABORT, COMPLETE, COMPLETED_GCI and SR_HEAD at every place from inside a page to its last word pair, with `splitChecksum`, accepted by the scan's `checkRecord` with the right next position, and the unsplit checksum rejected where both pieces hold words; PREPAREs of 1 to 4 pages (up to the largest key and log record) from 5 places, with `pagedChecksum` over the pages, accepted, and the checksum of the body in one piece rejected where the pages cut it; the FILLER that closes a unit at every word; the reservation table and the states where a record cannot come |

**Decisions taken while implementing.**

1. **A switch of its own, `c_redo_pmem_format`.** The plan dispatches on
   `c_redo_pmem`, but PMEM mode runs today's format since phase 4 and its
   MTR tests must keep passing until phase 8 brings the copy-out and the
   restart. Phase 8 sets the switch from `c_redo_pmem` (or replaces it by
   `c_redo_pmem`).
2. **The writers build bytes; phase 8 moves them.** `redoEndOfRecord`,
   `redoCopyOut`, `redoPadToUnit`, `redoPersist` and the copy of page 0
   are S5.2-S5.3 and come in phase 8, which adds the end-of-record copy at
   the end of `redoAppendFixed` and `writePrepareLogPmem`, calls
   `writeNextMbytePmem` from `writeNextLog`, and calls `redoBuildPageZero`
   from a `writeFileHeaderOpenPmem` that also copies the page. So phase 7
   adds no dispatch to `writeFileHeaderOpen`, `writeNextLog` or
   `completedLogPage`. The PREPARE's checksum walks the filled list from
   its start page, so it needs phase 8's `completedLogPage`, which only
   links pages: today's writes the list at 8 pages and starts a new one,
   which would cut the walk.
3. **The FD content is `redoBuildPageZero`**, not
   `writeFileHeaderOpenPmem`: the plan's function mixes the bytes (S4.6)
   with the copy (S5.3); the split keeps each phase whole.
4. **No `ZFILLER_TYPE`/`RF_INVALIDATED` macros in `Dblqh.hpp`.** The
   writers use the `PmemRedo::` names, and static asserts check that the
   format keeps today's type numbers, geometry and header word numbers. A
   macro named like a constant of the header would break the header
   wherever it is included after the macro.
5. **The writer and the reader take the checksum independently.** The
   writers use `splitChecksum` and `pagedChecksum` of the format header;
   the scan keeps its own loop in `checkRecord`, so `pmem_redo_writer-t`
   checks one against the other.
6. **The end of what is written (`redoPosLsn`) is the start of the
   current page while that page holds only its header.** So a record
   that ends at a page end ends at the next page's start, as the copy
   will store it, and after a NEXT_MBYTE or page 0 the end is the next
   page's start, which is where phase 8 sets the persisted LSN. The plan's
   "nothing new to persist" then needs only `appendLsn > persisted`.
7. **The reservation states are named `RESERVED_*`, not `RES_*`**, the
   prefix of the `<resolv.h>` macros.
8. **The COMMIT logs `gci_lo`** (format §5.2), which today's COMMIT does
   not; it is set before every COMMIT is written (review point of S4.4).
9. **`release_committed_words` refuses a record in a state where it
   cannot come** (`ndbrequire`): a COMMIT without a reservation, a
   COMPLETE without a durable COMMIT.

**Commands for the pusher.** `cmake .` first, because there is a new
test. Then, on Linux x86_64, Linux ARM64 and macOS ARM64:

```
cmake --build .
ctest -R pmem_redo --output-on-failure
```

File-mode regression (the PMEM writers are not entered, so PMEM mode is
unchanged too; the operation record is 8 bytes larger):

```
cd mysql-test
./mtr --suite=ndb --parallel=auto
./mtr ndb.ndb_redo_pmem_restarts ndb.ndb_redo_pmem_paths
```
