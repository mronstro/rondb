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
| 1 | 2 | CPU feature detection and CRC32C | S1.1, S1.2 | `NdbHW-t`, `ndb_crc32c-t` on Linux x86_64, Linux ARM64 and macOS ARM64; file-mode regression | — | **Done**: all tests passed (reported 2026-10-28) |
| 2 | 3 | PMEM helper and platform queries | S1.3, S1.4 | `ndb_pmem-t` on a plain file on the three platforms and on `memmap=` | 1 | Not started |
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

## Phase 1: CPU feature detection and CRC32C

**Scope.** `implementation_plan.md` pull request 2; platform plan S1.1 and
S1.2. Nothing in the data node calls the new code yet, so file mode is
unchanged.

**Changes.**

| File | Change |
|---|---|
| `include/portlib/NdbHW.hpp` | `struct ndb_cpu_features` and `Ndb_GetCpuFeatures()` |
| `src/common/portlib/NdbHW.cpp` | Detection, once, on first call, independent of `NdbHW_Init()`: CPUID and XGETBV on x86-64, `getauxval` on Linux ARM64, `sysctlbyname` on macOS ARM64. `TAPTEST(NdbCPU)` prints and checks the features |
| `include/util/ndb_crc32c.h` | `ndb_crc32c(crc, buf, len)` (chains like zlib), `ndb_crc32c_init()`, `ndb_crc32c_implementation()` |
| `src/common/util/ndb_crc32c.cpp` | Port of InnoDB's CRC32C (`storage/innobase/ut/crc32.cc`): slicing-by-8 software and the hardware template with three interleaved streams combined by carry-less multiplication, seeded so it chains. Run-time choice by `Ndb_GetCpuFeatures()`. The unit test is in the same file |
| `src/common/util/CMakeLists.txt` | `ndb_crc32c.cpp` in `ndbgeneral`; `ndb_crc32c-t` |
| `src/common/util/ndb_init.cpp` | `ndb_crc32c_init()` in `ndb_init_internal()` |

**Decisions taken while implementing.**

1. **InnoDB's CRC32C, not another one.** simdjson has no CRC32C. The
   bundled Abseil has one (`extra/abseil/.../absl/crc`), but its hardware
   path is chosen at compile time and needs `__SSE4_2__` and `__PCLMUL__`
   (or `__ARM_FEATURE_CRC32`), which RonDB's build flags do not set, so it
   would run in software there. It is also built only with bundled
   protobuf, as shared libraries that no NDB program links, and it is
   Apache-2.0 code, which cannot be copied into GPLv2 files. InnoDB's
   code chooses the hardware path at run time and is already GPLv2.
2. **`is_avx2_supported()` is left as it is** (always 0). The platform plan
   fixes it in S1.1, but the fix would change nothing in any build:
   - Its only caller, `rondb_calc_hash`, checks it only under
     `#if defined(__AVX2__)`, so without `-mavx2` the AVX2 branch does not
     exist.
   - With `-mavx2`, `xxhash_std.cpp` is compiled with AVX2 as well,
     because `ndb_xxhash.h` chooses the vector code from `__AVX2__`. The
     `XXH_VECTOR_TYPE` define in `xxhash_avx2.cpp` is not read. The two
     functions are then the same code.

   Every XXH3 variant (scalar, SSE2, AVX2, NEON) gives the same hash, so
   the distribution of rows does not depend on this; AVX2 would only make
   keys over 240 bytes faster. A run-time choice that works needs
   `target("avx2")` functions, which belong in their own ticket, not in
   PMEM. `ndb_cpu_features::avx2` is detected correctly.
3. **Loads through `memcpy`** instead of InnoDB's pointer casts, so the
   port has no strict-aliasing questions; compilers emit the same load.
4. **Windows and big-endian** use the software CRC; x86 detection runs only
   with GCC or Clang outside Windows. Neither is a supported platform
   (Q-A5).
5. **CRC-32C or XXH3: open**, to be decided on the Linux x86_64 and
   Linux ARM64 timings.
   - In today's format (E4) a record is checksummed in three pieces:
     `w0` without the invalidation bit, the body from `w2`, and the
     16 bytes of `S`, which are never stored. A spanning record has more
     pieces, around each page header.
   - That format suits CRC-32C, whose chaining costs about 2 ns per piece
     (`crc32c/3`).
   - A format built for XXH3 would hash the body in one call with a fixed
     seed, then mix in `w0` and `S` (`xxh3+mix`). It stays bound to lap and
     position, because a different `S` gives a different checksum.
   - On macOS ARM64, one-shot XXH3 is 2 to 3 times faster than
     `crc32c/3` from 60 to 1000 bytes, and faster at every size from
     60 bytes.
   - Linux x86_64 matters most. There XXH3 uses SSE2, unless built with
     `-mavx2`, which pays only above 240 bytes.
   - Nothing calls `ndb_crc32c` yet, so a switch changes only E3/E4, the
     format document and the reader.

**Commands for the pusher** (from the build directory, configured with
`-DWITH_UNIT_TESTS=1`), on Linux x86_64, Linux ARM64 and macOS ARM64:

```
cmake --build . --target NdbHW-t ndb_crc32c-t rondb_hash-t
ctest -R 'NdbHW-t|ndb_crc32c-t|rondb_hash-t' --output-on-failure
./runtime_output_directory/ndb_crc32c-t      # prints the implementation and timings
```

`ndb_crc32c-t` should report the hardware implementation on all three
platforms (`sse4.2+pclmul` on x86_64, `armv8-crc+pmull` on ARM64); it
warns, without failing, on a CPU or VM CPU model without CRC32
instructions. It also prints the timing table of CRC-32C against XXH3 at
the REDO record sizes (20 bytes to 92 KB). The timings mean something only
from an optimised build (`-DWITH_DEBUG=0`); a debug build measures call
overhead.

**Timings.** These come from `ndb_crc32c-t` in an optimised build, in ns
per checksum. `crc32c/3` and `xxh3/3` checksum the same bytes in three
pieces, 4 + body + 16, as a record is checksummed. `xxh3+mix` (added after
the macOS run below) is a format built for XXH3: the body in one call,
then a seeded XXH3 over the 20 bytes of `w0` and `S` with the body's hash
as seed. Each result feeds the next input, so the loop measures latency
with the data in cache.

macOS ARM64, Apple M5 Pro, `armv8-crc+pmull`, XXH3 with NEON
(2026-10-28):

| bytes | crc32c | crc32c/3 | xxh3 | xxh3/3 |
|---|---|---|---|---|
| 20 | 4.0 | 7.5 | 4.7 | 8.0 |
| 28 | 4.6 | 8.8 | 4.7 | 8.3 |
| 60 | 7.2 | 11.5 | 4.8 | 9.7 |
| 124 | 12.4 | 16.8 | 5.3 | 10.1 |
| 300 | 26.8 | 31.3 | 10.6 | 24.5 |
| 1000 | 61.4 | 65.3 | 18.9 | 55.2 |
| 32768 | 917.0 | 922.1 | 619.0 | 1584.5 |
| 92520 | 2703.2 | 2719.4 | 1791.3 | 4488.5 |

At 92 KB this is 34 GB/s for CRC-32C, 52 GB/s for one-shot XXH3 and
21 GB/s for streaming XXH3. Each extra CRC call costs about 2 ns.

Linux x86_64 and Linux ARM64: to come.
