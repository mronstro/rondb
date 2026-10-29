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
| 3 | 4 | Configuration: parameters, path parser, checks, test settings | S2.1–S2.3, S2.7 | Config unit tests, management-server refusals | — | Not started |
| 4 | 5 | NDBFS mapping and placement; PMEM mode with today's format (**M0.2**) | S3.1–S3.4, S2.4, S2.5 | MTR ndb suite and a testSystemRestart subset in `nodax` and on `memmap=` | 2, 3 | Not started |
| 5 | 6 | Initial start and restarts with every file mapped; ndbinfo `redo_log_pmem` | S3.5, S3.6, S2.6 | Initial start, SR and NR in PMEM mode; ndbinfo rows | 4 | Not started |
| 6 | 7 | Record format and reader module | S4.1, S6.2 | Unit tests over synthetic logs on the three platforms | 1 | Not started |
| 7 | 8 | Record writers | S4.2–S4.7, S5.1 | Unit tests; file-mode regression | 6 | Not started |
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

