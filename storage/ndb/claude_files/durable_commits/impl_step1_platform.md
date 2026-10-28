# RONDB-1150 step 1, platform packages S1–S3: implementation plan

Status: **plan, 2026-10-28. No code has been changed.** This is the implementation plan
for steps S1 (portlib), S2 (configuration and start-up checks) and S3 (NDBFS mapping of the
REDO files) of `pmem_redo_design.md` §3. It follows decisions E1–E20 and the answers in §5
of that document. Sibling plans: `impl_step1_lqh_write.md` (S4, S5),
`impl_step1_recovery_test.md` (S6, S7), `impl_next_steps.md`.

Paths are relative to `storage/ndb/` unless they start with the repo root.
[V] = verified in the code at the line given. [I] = inferred.

---

## 0. Summary

| ID | Package | Size |
|---|---|---|
| S1.1 | CPU feature detection in `NdbHW`; fix `is_avx2_supported()` (done) | S, 1–1.5 d |
| S1.2 | `ndb_xxh3`: XXH3 with AVX2 chosen at run time (done) | M, 2–3 d |
| S1.3 | `ndb_pmem` core: map, prefault, copy, store, flush, drain; stubs | M, 3–4 d |
| S1.4 | Platform queries: domain, bad blocks, dirty shutdown, NUMA | M, 3 d |
| S1.5 | Power-loss emulation (`ndb_pmem_emul_*`) | M, 3 d |
| S2.1 | Parameters, CFG ids, path-list parser | M, 2 d |
| S2.2 | Config-time checks in the management server | S, 1.5 d |
| S2.3 | Data node reads the parameters; defence-in-depth refusals | S, 1 d |
| S2.4 | Log part → NUMA node → REDO path | S, 1.5 d |
| S2.5 | Start-time platform checks and messages | M, 2–3 d |
| S2.6 | ndbinfo table `redo_log_pmem` and the stats struct | M, 2 d |
| S2.7 | Test settings (flagged for the architect) | S, 1 d |
| S3.1 | Signals: `OM_MAP_SYNC`, address in FSOPENCONF, FsRef codes | S, 1 d |
| S3.2 | Map, prefault and unmap in the NDBFS IO thread | M, 2 d |
| S3.3 | REDO base paths in NDBFS, initial-start cleanup, lookup | M, 2–3 d |
| S3.4 | DBLQH open flags, address store, FSOPENREF messages | S, 1 d |
| S3.5 | Initial start in PMEM mode (full init, keep mapped) | M, 2 d |
| S3.6 | Map every file at SR/NR start; virtual open and close | M, 3–4 d |

Total about 36–42 person-days.

**Code facts that shaped the plan.**

1. `is_avx2_supported()` returns a static set to 0 and never written
   (`src/common/portlib/NdbHW.cpp:56`, `:507-510`) [V]. Its only caller is
   `rondb_hash.cpp:43`, inside `#if defined(__AVX2__)` [V]. NDB has no CPUID code [V, grep].
   Since step 1 phase 1 it reports the detected AVX2, and `rondb_calc_hash` no longer
   calls it.
2. `NdbHW_Init()` is not called for mysqld (`src/common/util/ndb_init.cpp:113`) [V], so
   `ndb_xxh3` must initialise itself.
3. XXH3 is in the tree as `include/util/ndb_xxhash.h`, for the hash of keys
   (`xxhash_std.cpp`, `xxhash_avx2.cpp`). It chooses its vector code from `__AVX2__` at
   compile time, and the build has no `-mavx2`, so AVX2 was never used [V].
4. NDB unit tests are TAP tests: `NDB_ADD_TEST(name-t src.cpp LIBS ...)` compiles the source
   with `-DTEST_<NAME>` and links `mytap` (`cmake/ndb_add_test.cmake:28-75`); the body is
   `TAPTEST(x)` under `#ifdef TEST_<NAME>` (e.g. `src/common/util/rondb_hash.cpp:278`) [V].
   They build only with `-DWITH_UNIT_TESTS=1` [V].
5. The highest DB config id is 710 (`include/mgmapi/mgmapi_config_parameters.h:316`); 711+
   is free on 26.10-main, 26.05-main and 25.10-main [V, `git show`]. The header warns about
   id collisions after merges [V].
6. REDO files are `V_BLOCK` names `D<8+part>/DBLQH/S<file>.FragLog` under `BP_FS`
   (`DblqhMain.cpp:35541-35548`, `Filename.cpp:39-41`, `:71-121`) [V]. The extension is
   `.FragLog`, not `.FRAGLOG`.
7. `FsOpenReq` bits from `0x20000000` up are free; the highest used is
   `OM_PARTIAL_LAST_BLOCK = 0x10000000` (`FsOpenReq.hpp:146`) [V]. FSOPENCONF is sent with
   5 words (`Ndbfs.cpp:1501`) [V].
8. DBLQH never sets `FsOpenReq::secondFileFlags`; only LGMAN does (`lgman.cpp:1688`)
   [V, grep]. NDBFS copies it into the request (`Ndbfs.cpp:683`) [V].
9. `OM_THREAD_POOL` sends a file to the unbound IO threads (`Ndbfs.cpp:587`) [V]. REDO files
   are opened bound today, one IO thread per open file (`Ndbfs.cpp:386-387`) [V].
10. `OM_INIT` writes every page with `write()` after `posix_fallocate` and
    `FALLOC_FL_ZERO_RANGE`, calling `Dblqh::execFSWRITEREQ` per page
    (`AsyncFile.cpp:383-551`, `DblqhMain.cpp:35733-35790`) [V]. "full" leaves no unwritten
    extents [I].
11. Unencrypted REDO files are `FF_RAW` with payload start 0 (`ndbxfrm_file.cpp:290-295`,
    `:793-797`) [V]: mapping offset = data offset.
12. `Diskless` replaces NDBFS by `VoidFs` (`SimBlockList.cpp:98`), which cannot map [V].
13. Threads bind to their CPUs before they execute any signal (`vm/mt.cpp:7531-7548`) [V].
    NDBFS gets READ_CONFIG_REQ before DBLQH, one block at a time (`NdbcntrMain.cpp:206-211`,
    `:6006`) [V].
14. `NdbHW` knows sockets and L3 groups but not NUMA nodes [V, grep]. `NdbNuma` only sets
    interleaving through a dlopen'ed libnuma (`NdbNuma.cpp:35-215`) [V].
15. `get_base_path()` falls back to `BP_FS` for an empty base path (`Ndbfs.cpp:259-265`) [V].
    A "remove base path" for an unset REDO path would wipe the whole file system.

---

## 1. Interfaces with the other subtasks

**Write side (`impl_step1_lqh_write.md`, S4/S5).**

- S3 ships PMEM mode as "files mapped, kept open, placed per NUMA node, checked". The REDO
  format and the FSWRITEREQ write path stay as today until S4/S5 land. NDBFS keeps every REDO
  file open, so FSWRITEREQ/FSREADREQ on the same `fileRef` keep working, and today's SR and
  NR tests can run against S3.
- `c_redo_pmem` (bool) is set by S2.3 from `RedoLogMode`; S4/S5 add their branches under it.
- S3.4 adds the fields S4/S5 use: `LogFileRecord::m_pmem_base` (plus `m_pmem_fileRef`,
  `m_pmem_domain`, `m_pmem_numa_node`) and `LogPartRecord::m_redo_path_no`. S2.6 adds
  `LogPartRecord::m_pmem_stats`; S5's `redoPersist` increments it.
- S4 owns two writers that S3.5 calls: `redoPmemFormatInitPage()` (per-page callback during
  `OM_INIT`) and `redoPmemInitFile()` (page 0, control area, file 0 page 1). Table in S3.5.
- S1.3's copy includes the write-back of the chosen method, so S5 always calls
  `ndb_pmem_copy_nt()` then `ndb_pmem_drain()`. In-place updates (E9, E10) use
  `ndb_pmem_store32/64()` + `ndb_pmem_flush()` + `ndb_pmem_drain()`; zeroing (E12) uses
  `ndb_pmem_zero()` + `ndb_pmem_drain()`. **All PMEM writes go through these calls**, or the
  emulation of S1.5 misses them.

**Recovery and tests (`impl_step1_recovery_test.md`, S6/S7).**

- S1.5 is the power-loss hook S7 builds on. Contract:
  - `ndb_pmem_emul_enable()` runs before the first map (NDBFS, from
    `__RedoLogPmemPowerLossEmulation`, S2.7).
  - Every PMEM write is visible at once (coherence holds). The pre-image of each line is kept
    until the line is persistent: after `ndb_pmem_drain()` for NT copies and zeroing, after
    `ndb_pmem_flush()` + `ndb_pmem_drain()` for in-place stores.
  - `ndb_pmem_emul_power_fail(seed, keep_permille, tear_permille)` reverts the unpersisted
    lines of all threads (each kept with probability keep/1000, else restored, or torn at
    8-byte granularity) and returns; the caller exits at once.
  - `ndb_pmem_emul_on_crash()` = power fail with keep = 0. S7 wires it into
    `ErrorReporter::handleAssert` (`error/ErrorReporter.cpp:242`),
    `ErrorReporter::handleError` (`:262`) and `handler_error` (`ndbd.cpp:677`).
  - `ndb_pmem_emul_pending()` counts this thread's unpersisted lines. S5 asserts it is 0 at
    `unlock_log_part` in debug builds (E7).
- S2.5 provides the dirty-shutdown count and bad-block state per path. S6 writes the count
  into the control area (layout from S4), compares it at restart, and owns the control-area
  and format-mismatch refusals.

---

## 2. S1: portlib

### S1.1 CPU feature detection

- **Goal.** Real detection for S1.2 and S1.3. Fix `is_avx2_supported()` (fact 1).
  **Done** in step 1 phase 1 (`step1_phases.md`).
- **Change.** `include/portlib/NdbHW.hpp`: `struct ndb_cpu_features` and
  `const ndb_cpu_features *Ndb_GetCpuFeatures()`. `src/common/portlib/NdbHW.cpp`: detect once
  (function-local static), independent of `NdbHW_Init()` (fact 2); `is_avx2_supported()`
  returns `features->avx2`.
  - x86-64 (`<cpuid.h>`): leaf 1 ECX bit 20 SSE4.2, bit 1 PCLMULQDQ, bit 28 AVX, bit 27
    OSXSAVE; EDX bit 19 CLFLUSH. Leaf 7 EBX bit 5 AVX2, bit 16 AVX-512F, bit 23 CLFLUSHOPT,
    bit 24 CLWB; ECX bit 28 MOVDIR64B. AVX/AVX-512 also need the XGETBV(0) state bits [I].
  - aarch64 Linux: `getauxval(AT_HWCAP)` for `HWCAP_CRC32`, `HWCAP_PMULL`, `HWCAP_DCPOP`;
    `AT_HWCAP2` for `HWCAP2_DCPODP`. macOS arm64: `sysctlbyname` for `hw.optional.armv8_crc32`,
    `hw.optional.arm.FEAT_PMULL`, `hw.optional.arm.FEAT_DPB` (`DC CVAP`) and
    `hw.optional.arm.FEAT_DPB2` (`DC CVADP`); all four are 1 on an Apple M5 Pro [V, sysctl].
  - `sse42`, `pclmul`, `arm_crc32` and `arm_pmull` were for CRC32C, which XXH3 replaced
    (S1.2). They stay detected; nothing uses them.
  - macOS x86_64 is not supported (Q-A5): no detection or tests for it.
  ```c++
  struct ndb_cpu_features {
    bool sse42, pclmul, avx, avx2, avx512f, clflush, clflushopt, clwb, movdir64b;  // x86-64
    bool arm_crc32, arm_pmull, arm_dcpop, arm_dcpodp;                              // aarch64
  };
  ```
- **File mode.** Additive. `ndb_xxh3` (S1.2) now makes the AVX2 choice for the hash of keys,
  and every XXH3 implementation gives the same hash; `ndb_xxh3-t` and `rondb_hash-t` check it.
- **Tests.** Extend `TAPTEST(NdbCPU)` (`NdbHW.cpp:4462`): print features; check
  `avx2 ⇒ avx`, `avx512f ⇒ avx`, `is_avx2_supported() == features->avx2`. Run `NdbHW-t`,
  `rondb_hash-t`.
- **Depends** on nothing. **Risk.** XGETBV needs inline asm or `target("xsave")`.

### S1.2 `ndb_xxh3`

- **Goal.** XXH3 with the AVX2 code chosen at run time on x86-64, for the checksum of E4 in
  ndbmtd, `ndb_redo_log_reader` and the tests, and for the hash of keys. **Done** in step 1
  phase 1 (`step1_phases.md`).
- **Where.** `include/util/ndb_xxh3.h`, `src/common/util/ndb_xxh3.cpp`, in `ndbgeneral`
  (`src/common/util/CMakeLists.txt:36-79`) [V]. `ndb_redo_log_reader` links `ndbgeneral`
  (`src/kernel/blocks/dblqh/CMakeLists.txt:24-35`) [V].
  ```c++
  // The results of XXH3_64bits() and XXH3_64bits_withSeed() of ndb_xxhash.h
  Uint64 ndb_xxh3_64(const void *buf, size_t len);
  Uint64 ndb_xxh3_64_seed(const void *buf, size_t len, Uint64 seed);
  void   ndb_xxh3_init();               // idempotent; also done at the first input over 240 bytes
  const char *ndb_xxh3_implementation();  // "avx2", "sse2", "neon", ...
  ```
  E4's checksum is one call on the body (one more seeded call for each page header the
  record crosses), then a seeded call on the 20 bytes of `w0` and `S`.
- **Code.** The XXH3 of `ndb_xxhash.h` (fact 3). On x86-64 the AVX2 code is compiled with
  `target("avx2")` and chosen at run time, as xxhash's own `xxh_x86dispatch.c` does, so the
  build needs no `-mavx2`; SSE2 otherwise. NEON on aarch64. Inputs up to 240 bytes run the
  same scalar code everywhere. All little-endian. `rondb_xxhash_std()` and
  `rondb_calc_hash()` use it; `xxhash_avx2.cpp` and `xxhash_std.cpp` are gone. The AVX2
  branch in `rondb_calc_hash` never ran (fact 1).
- **Dispatch.** An `std::atomic` function pointer for inputs over 240 bytes, which starts at
  a resolver using `Ndb_GetCpuFeatures()`. `ndb_init_internal()` calls `ndb_xxh3_init()`
  for every caller.
- **File mode.** The hash of keys gives the same values as before: every XXH3
  implementation gives the same hash. Nothing else calls it before S4.
- **Tests.** `ndb_xxh3-t` (FOREACH list at `src/common/util/CMakeLists.txt:114-133`): the
  hash of no bytes is `0x2D06800538D394C2`; every implementation the CPU has equals the
  header's XXH3 for all lengths 0..2100 and some long ones, at every alignment, with and
  without seed; informational timing at the REDO record sizes (`step1_phases.md`,
  Timings). `rondb_hash-t` checks the hash of keys.
- **History.** Phase 1 first ported InnoDB's CRC32C (`ndb_crc32c`, commits 77a146884ec and
  4102f7f1c7a). It was removed when the timings favoured XXH3 (`step1_phases.md`,
  decision 5).
- **Depends** on S1.1. **Risk.** The AVX2 functions need `target("avx2")`. A build with
  `-mavx512f` uses the code the build chose instead of the run-time choice.

### S1.3 `ndb_pmem` core

- **Goal.** The helper of E18: map with `MAP_SYNC`, prefault, 64-byte copy, in-place stores,
  flush, drain, for x86, ARM and stubs, with the copy-method switch of E7.
- **Where.** `include/portlib/ndb_pmem.h`, `src/common/portlib/ndb_pmem.cpp`, in `ndbportlib`
  (`src/common/portlib/CMakeLists.txt:51-77`) [V]. Build checks in `ndb_configure.cmake`,
  defines in `include/ndb_config.h.in` (`:25-70`) [V]: `HAVE_MAP_SYNC`,
  `HAVE_MADV_POPULATE_WRITE`, `HAVE_LINUX_FIEMAP_H`, `HAVE_STATX`, `HAVE_MOVDIR64B_INTRINSIC`.
  If the headers lack them, define `MAP_SHARED_VALIDATE 0x03`, `MAP_SYNC 0x80000`,
  `MADV_POPULATE_WRITE 23` on Linux [I, kernel uapi].
  ```c++
  static constexpr size_t NDB_PMEM_LINE = 64;
  enum ndb_pmem_copy_method { NDB_PMEM_COPY_AUTO, NDB_PMEM_COPY_NTSTORE,
                              NDB_PMEM_COPY_MOVDIR64B, NDB_PMEM_COPY_CLWB };
  enum : unsigned { NDB_PMEM_MAP_SYNC_REQUIRED = 0, NDB_PMEM_MAP_SYNC_OPTIONAL = 1 };
  struct ndb_pmem_mapping { void *addr; size_t len; bool map_sync; };

  int  ndb_pmem_init(ndb_pmem_copy_method m);           // idempotent
  const char *ndb_pmem_method_name();                   // "ntstore-avx", "clwb", ...
  int  ndb_pmem_map(int fd, size_t len, unsigned flags, ndb_pmem_mapping *out);
                                                        // 0 or errno; EOPNOTSUPP = no MAP_SYNC
  int  ndb_pmem_unmap(ndb_pmem_mapping *m);
  int  ndb_pmem_prefault(void *addr, size_t len);
  void ndb_pmem_copy_nt(void *dst, const void *src, size_t len);  // dst 64-aligned, len%64==0
  void ndb_pmem_store32(Uint32 *dst, Uint32 v);         // aligned in-place store (E9)
  void ndb_pmem_store64(Uint64 *dst, Uint64 v);         // (E10)
  void ndb_pmem_zero(void *dst, size_t len);            // NT zeroing (E12)
  void ndb_pmem_flush(const void *addr, size_t len);    // after store32/64
  void ndb_pmem_drain();                                // waits for this thread's stores
  ```
- **x86-64.** Copy methods: NT stores (`_mm256_stream_si256` × 2 under `target("avx")`, else
  `_mm_stream_si128` × 4, present on every x86-64); `MOVDIR64B` (`target("movdir64b")` or the
  raw opcode `66 0F 38 F8`); CLWB (stores + `clwb` per line, the benchmark alternative).
  `auto` = MOVDIR64B if present, else NT stores; P6 picks per platform. AVX-512 is left out
  of `auto` (frequency effects) [I]. Flush = `clwb`, else `clflushopt`, else `clflush`.
  Drain = `_mm_sfence()`.
- **aarch64 Linux.** Copy = stores + `DC CVAP` per line (raw `sys #3, c7, c12, #1` for old
  assemblers) if `arm_dcpop`, else `DC CVAC`. Drain = `DSB SY` (hardware §3.2, §9).
- **Map.** Reserve `len + 2 MB` `PROT_NONE`, round to 2 MB, `mmap(MAP_SHARED_VALIDATE |
  MAP_SYNC | MAP_FIXED)` there and release the slack, so 2 MB pages can be used [I].
  `EOPNOTSUPP` or `EINVAL` (old kernel) mean "not DAX". With `OPTIONAL`, retry `MAP_SHARED`
  and set `map_sync = false`.
- **Prefault.** `madvise(MADV_POPULATE_WRITE)` (Linux 5.14+) faults pages writable without
  changing them [I]. Fallback: a volatile read-then-write of one byte per 4 KB page, then
  `clwb` of that line and one `sfence`, so no dirty line stays cached. `MAP_POPULATE` only
  read-faults shared pages (hardware §4.1).
- **macOS arm64** (Q-A5). Map returns `EOPNOTSUPP` unless `OPTIONAL`, then `MAP_SHARED`; the
  device queries are stubs. Copy, flush and drain are the **ARM64 code of Linux**: stores,
  `DC CVAP` per line, `DSB`, chosen by `FEAT_DPB` (Q-A1: the production persist code runs in
  every mode). That user code may execute `DC CVAP` on macOS is [I]; `ndb_pmem-t` would fail
  with `SIGILL` if not, and the fallback is `DC CIVAC`.
- **Stubs** (Windows, others). Map as on macOS. Copy = `memcpy`, flush = no-op, drain =
  `atomic_thread_fence(seq_cst)`. They only need to build.
- **Hot path.** Copy through a function pointer chosen at init (~1 ns against a 200–2000 ns
  persist); drain inline with one `unlikely(emulation)` branch.
- **File mode.** Nothing calls it before S3.2.
- **Tests.** `ndb_pmem-t` (`NDB_ADD_TEST(ndb_pmem-t ndb_pmem.cpp LIBS ndbmgmapi ndbgeneral
  ndbportlib)` next to `NdbHW-t`, `src/common/portlib/CMakeLists.txt:83`):
  - runs on Linux x86_64, Linux ARM64 and macOS ARM64 (Q-A5);
  - a 4 MB file in `$TMPDIR`: `REQUIRED` gives `EOPNOTSUPP` on tmpfs, non-DAX ext4 and macOS;
    `OPTIONAL` maps;
  - each available copy method: random units on every line of a page, drain, unmap, `pread`
    equal; `store32/64` + flush + drain and `zero` read back the same way;
  - after prefault, writing every page adds no minor faults (`getrusage`, Linux);
  - with `NDB_PMEM_DIR` (a DAX mount): `REQUIRED` maps and `map_sync` is true;
  - informational: ns per copy + drain of 1, 2 and 8 lines.
- **Depends** on S1.1. **Risks.** `_movdir64b` needs gcc/clang 10+ [I]; the raw opcode avoids
  it. `MAP_FIXED` replaces only our own reservation [I].

### S1.4 Platform queries

- **Goal.** The queries of E17 and E20.
  ```c++
  enum ndb_pmem_domain { NDB_PMEM_DOMAIN_UNKNOWN = 0,    // not an nd region
                         NDB_PMEM_DOMAIN_NONE = 1,       // empty line (memmap=)
                         NDB_PMEM_DOMAIN_MEMCTRL = 2,    // ADR; CXL always
                         NDB_PMEM_DOMAIN_CPU_CACHE = 3 };// eADR
  struct ndb_pmem_region_info {
    ndb_pmem_domain domain;  // weakest over all regions behind the device
    int numa_node, target_node;  // region attributes, -1 if unknown
    Uint64 dirty_shutdown;   // summed over DIMMs/memdevs; ~0 = not exposed
    Uint32 badblock_ranges;  // on the block device
    bool dax_inode;          // statx STATX_ATTR_DAX
    char device[32], region[256];  // "pmem0", sysfs path for messages
  };
  int ndb_pmem_persistence_domain(int fd, ndb_pmem_domain *dom);
  int ndb_pmem_region_info(int fd, ndb_pmem_region_info *info);
  int ndb_pmem_numa_node(int fd, const void *addr);       // -1 if unknown
  int ndb_pmem_badblocks_overlap(int fd, Uint64 off, Uint64 len, Uint32 *n);
  int ndb_pmem_dirty_shutdown(int fd, Uint64 *count);     // ENOTSUP if absent
  void ndb_pmem_set_sysfs_root(const char *root);         // test hook
  int Ndb_GetThreadNumaNode();   // NdbHW: node of all CPUs this thread may run on, else -1
  ```
- **How, on Linux** [I, hardware note §4.3–§4.4]:
  1. `fstat(fd)` → `major/minor(st_dev)` → `realpath("/sys/dev/block/M:m")`, e.g.
     `.../ndbus0/region0/namespace0.0/block/pmem0` or a partition below it.
  2. Device mapper: recurse into `slaves/*`; weakest domain, summed count, common node or -1.
  3. Walk up to the directory with `persistence_domain` (the region): `cpu_cache`,
     `memory_controller` or empty. No such file (tmpfs is major 0, NVMe has no region) →
     `UNKNOWN`.
  4. Region `numa_node` and `target_node` give E20's placement. Fallback:
     `get_mempolicy(MPOL_F_NODE | MPOL_F_ADDR)` on the prefaulted address via `syscall()`.
     Whether DAX (ZONE_DEVICE) pages report a node there is not verified [I].
  5. Bad blocks: `<blockdev>/badblocks` (`sector count`, 512-byte sectors) plus the partition
     `start`, intersected with the file's `FS_IOC_FIEMAP` extents. No FIEMAP → every range
     counts as overlapping, and the result says so.
  6. Dirty shutdown: region `mapping<k>` files name `nmemX`; sum
     `/sys/bus/nd/devices/nmemX/nfit/dirty_shutdown` (NFIT), `nmemX/papr/dirty_shutdown`
     (PAPR), else `nmemX/dirty_shutdown` (CXL via `cxl_pmem`, kernel-version dependent).
     `memmap=` has no mappings → `ENOTSUP`. **The meaning is device-specific**; verify per
     device in P6 (Q4).
  7. Thread node: parse `/sys/devices/system/node/node*/cpulist` with `parse_mask` (already
     used for `core_cpus_list`, `NdbHW.cpp:2729`) [V] into a new
     `ndb_cpuinfo_data::numa_node`; map `sched_getaffinity(0)` through it.
- **Stubs.** Non-Linux returns `UNKNOWN`, -1, `ENOTSUP`. The sysfs parsing is plain file IO
  and compiles and tests everywhere.
- **Tests.** In `ndb_pmem-t`, a fixture tree via `ndb_pmem_set_sysfs_root()`: `memmap=` (empty
  domain, no mappings), NFIT (`memory_controller`, `mapping0` → `nmem0`, count 3), CXL-like
  (`memory_controller`, no count), eADR (`cpu_cache`), a `badblocks` file with `16 8`. Runs on
  macOS. With `NDB_PMEM_DIR` on Linux: the real region is found and reports `NONE` on
  `memmap=`. `NdbHW-t` prints the thread node.
- **Depends** on S1.3. **Risk.** Odd layouts must give `UNKNOWN`/-1, never a crash. Review the
  CXL path on QEMU's CXL Type 3 device (design §2).

### S1.5 Power-loss emulation

- **Goal.** A mode that loses exactly what a power failure may lose, so S7 catches missing
  barriers. `memmap=` with `kill -9` cannot (hardware §4.6).
  ```c++
  int    ndb_pmem_emul_enable(Uint32 max_pending_per_thread);  // before the first map
  bool   ndb_pmem_emul_active();
  Uint32 ndb_pmem_emul_pending();            // this thread's unpersisted lines
  void   ndb_pmem_emul_power_fail(Uint64 seed, Uint32 keep_permille, Uint32 tear_permille);
  void   ndb_pmem_emul_on_crash();           // power_fail(time seed, 0, 0)
  struct ndb_pmem_emul_stats { Uint64 written, persisted, evicted_early, reverted; };
  void   ndb_pmem_emul_get_stats(ndb_pmem_emul_stats *out);
  ```
- **Mechanism** (an undo log per thread):
  - Each write call (`copy_nt`, `store32/64`, `zero`) saves the 64-byte pre-image of every
    line it touches (once until persisted), then writes the mapping, so all threads see it.
  - Lines from `copy_nt`/`zero` are *flushed*; lines from `store32/64` are *dirty* until
    `ndb_pmem_flush()` covers them.
  - `ndb_pmem_drain()` drops this thread's flushed pre-images: those lines are persistent.
    Dirty lines stay pending, which catches a missing flush.
  - `power_fail` walks every thread's list (global registry, one mutex per list): keep the
    new line with probability keep/1000, else restore it, or with probability tear/1000
    restore a random subset of its eight words.
  - A full list drops its oldest entry: that line "persisted early", which ADR allows.
  - Debug: a line pending in two threads is reported (two writers between fences, against E7).
- Works on any file, DAX or not (macOS, Linux without `memmap=`). `kill -9` without `power_fail` means "every line
  persisted", a legal outcome.
- **Tests** (`ndb_pmem-t`, regular file): 3 lines + drain, 2 lines, `power_fail(seed, 0, 0)`
  → 3 new, 2 old; `store32` + drain without flush → old; `keep = 1000` → all new; torn lines
  have only old or new words; overflow keeps the newest; two threads on one line are reported.
- **Depends** on S1.3. **Risk.** `handler_error` runs in signal context: try-lock each list and
  skip a held one. Emulation roughly doubles write cost; tests only.

---

## 3. S2: configuration and start checks

### S2.1 Parameters

- **Where.** CFG ids after 710 (`mgmapi_config_parameters.h:316`); update the comment that
  says 710 must stay the highest. Entries in `src/common/mgmcommon/ConfigInfo.cpp` inside the
  RonDB block that ends at `:985`, typelibs next to `compiled_interpreter_typelib`
  (`:254-258`) [V].

| Id | Name | Type, default | Restart flag | Meaning |
|---|---|---|---|---|
| 711 `CFG_DB_REDO_LOG_MODE` | `RedoLogMode` | enum `file`\|`pmem`, `file` | `CI_RESTART_INITIAL` | REDO in mapped files on PMEM |
| 712 `CFG_DB_REDO_LOG_PATH` | `FileSystemPathRedoLog` | string, unset = `FileSystemPath` | `CI_RESTART_INITIAL` | One path, or one per NUMA node. **PMEM mode only** (Q-A2): file mode ignores it |
| 713 `CFG_DB_REDO_PMEM_TEST_MODE` | `__RedoLogPmemTestMode` | enum `off`\|`emulated`\|`nodax`, `off` | none | Test setting (S2.7) |
| 714 `CFG_DB_REDO_PMEM_POWER_LOSS_EMUL` | `__RedoLogPmemPowerLossEmulation` | bool, false | none | S1.5 on (S2.7) |
| 715 `CFG_DB_REDO_PMEM_COPY_METHOD` | `__RedoLogPmemCopyMethod` | enum `auto`\|`ntstore`\|`movdir64b`\|`clwb` | none | E7 benchmark switch |

  `DurableCommits` (later step) takes 716.
- **Restart flags.** Like `NoOfFragmentLogParts`, `InitFragmentLogFiles` and
  `EncryptedFileSystem` (`ConfigInfo.cpp:1134-1152`, `:1413-1416`) [V], the two real
  parameters need an initial node restart. The flag only documents it
  (`testConfig.cpp:260-265`) [V]; the data node enforces it (format check S6, missing files
  S3.3).
- **Path syntax** (E20 proposal): `FileSystemPathRedoLog=/mnt/pmem0` for every part, or
  `FileSystemPathRedoLog=0:/mnt/pmem0,1:/mnt/pmem1` per NUMA node. Node ids decimal and
  unique, paths absolute without `,`, at most `NDB_MAX_REDO_LOG_PATHS = 8`. A part whose LDM
  node has no entry uses the first, with a warning. Files go to
  `<path>/ndb_<nodeid>_fs/D<8+part>/DBLQH/S<file>.FragLog`, mirroring `FileSystemPathDD`
  (`Ndbfs.cpp:288-296`, `:315-317`) [V].
- **Parser** in `ndbgeneral`, used by the management server, NDBFS, DBLQH and NDBCNTR:
  `include/util/RedoLogPaths.hpp`, `src/common/util/RedoLogPaths.cpp`.
  ```c++
  static constexpr Uint32 NDB_MAX_REDO_LOG_PATHS = 8;
  struct RedoLogPaths {
    struct Entry { Int32 numa_node; /* -1 = any */ BaseString path; };
    Uint32 count = 0;
    Entry entry[NDB_MAX_REDO_LOG_PATHS];
    int parse(const char *spec, BaseString &err);  // 0 = ok
    Uint32 index_for_node(int numa_node) const;    // else 0
  };
  ```
- **File mode.** Defaults are `file` and unset.
- **Tests.** `RedoLogPaths-t`: single path, two nodes, duplicates, bad node, relative path,
  9 entries, empty entry, trailing comma. `MgmConfig-t`: new values in `test_param_values`
  (`src/mgmsrv/testConfig.cpp:350-401`) [V], and a new check that no two parameters of one
  section share an id under different names (fact 5; aliases may need an allowlist).
- **Depends** on nothing. **Risk.** Id collisions on merge.

### S2.2 Config-time checks in the management server

- **Where.** `checkDbConstraints` (`ConfigInfo.cpp:4112-4233`), a section rule that runs after
  defaults (`:170-185`) and may replace values, as for `TransactionInactiveTimeout`
  (`:4214-4231`) [V]. Per `[ndbd]` section:

| Condition | Action |
|---|---|
| `pmem` and `EncryptedFileSystem=1` | Error: refused in this version (E17, Q5) |
| `pmem` and `Diskless=1` | Error (E17; NDBFS is `VoidFs`, fact 12) |
| `pmem` and `InitFragmentLogFiles=sparse` | Replace by `full`, silently: the default is `sparse` |
| `FileSystemPathRedoLog` does not parse | Error with the parser's message |
| `__RedoLogPmemTestMode` ≠ `off` | Warning: test setting, not power-fail safe |
| `file` and `FileSystemPathRedoLog` set | Warning: has no effect in file mode; the REDO stays under `FileSystemPath` (Q-A2) |
| `pmem`, test mode `off`, no `FileSystemPathRedoLog` | Warning: REDO under `FileSystemPath`, which must be DAX |

- **File mode.** Every check needs `pmem`, except the warning for a path set in file mode.
- **Tests.** `MgmConfig-t`: new `test_redo_log_pmem()` with `create_config()` (`:104`): the
  errors give `NULL`, `InitFragmentLogFiles` reads `full` after `pmem`, bad paths fail. MTR
  `ndb.ndb_redo_pmem_config` with `.ini` files in `mysql-test/suite/ndb/`, as in
  `ndb_config.test:53-54` [V]: `--error 255 --exec $NDB_CONFIG --config-file=... 2>&1` for
  errors, `--query=RedoLogMode,FileSystemPathRedoLog,InitFragmentLogFiles --type=ndbd` for
  accepted files.
- **Depends** on S2.1. **Risk.** The silent replacement; the data node logs it (S2.3).

### S2.3 Data node reads the parameters

- `Dblqh::execREAD_CONFIG_REQ` (`DblqhMain.cpp:2672`): `c_redo_pmem`,
  `c_redo_pmem_test_mode`. In PMEM mode: `progError(NDBD_EXIT_INVALID_CONFIG)` if
  `c_encrypted_filesystem` (`:2763`) or `c_diskless` (`:2754`); `m_use_om_init = 1` after
  `:2765-2778`, with an info line; ignore `ODirect`/`ODirectSyncFlag` for REDO (info line).
- `Ndbfs::execREAD_CONFIG_REQ` (`Ndbfs.cpp:280`): mode, test mode, emulation flag, copy
  method; `ndb_pmem_emul_enable()` and `ndb_pmem_init(method)` before any open; paths (S3.3);
  probes (S2.5).
- `Ndbcntr`: parse the paths for the initial-start cleanup (S3.3).
- `Configuration::get_and_set_redo_buffer` (`vm/Configuration.cpp:1006`) belongs to S5.
- **File mode.** Every read defaults to `file`. **Tests.** S2.2, S3.6. **Depends** on S2.1.

### S2.4 Log part → NUMA node → REDO path

- **Facts.** Part p belongs to LDM worker `p % numLDM` (`DblqhCommon.cpp:30-45`) [V]; only the
  owner opens a part's files, as `clogPartFileSize` counts owned parts
  (`DblqhInit.cpp:153-155`) [V]. Threads are bound before any signal (fact 13). The DBLQH
  worker's READ_CONFIG_REQ runs in its own LDM thread [I].
- **Changes.** In `Dblqh::execREAD_CONFIG_REQ`: `c_ldm_numa_node = Ndb_GetThreadNumaNode()`;
  for each owned part `m_redo_path_no = paths.index_for_node(node)`. Warn once per LDM if the
  node is -1 ("LDM n is not bound to CPUs of one NUMA node; its REDO parts use <path 0>") or
  has no entry. The index travels in FSOPENREQ (S3.1); the memory's node returns in
  FSOPENCONF, and a mismatch gives one warning per part (E17).
- Shared parts follow their owner; single-threaded ndbd uses the process affinity. It works
  for `ThreadConfig` and the automatic thread config, since it reads the applied binding.
- **File mode.** One path or none gives index 0.
- **Tests.** `NdbHW-t` prints the node of a thread bound to CPU 0. Two-socket Linux:
  `ThreadConfig=ldm={count=2,cpubind=<cpu of node 0>,<cpu of node 1>}`, two paths, initial
  start; `ls` shows parts 0, 2 under path 0 and 1, 3 under path 1; ndbinfo shows the nodes.
- **Depends** on S1.4, S2.1, S3.3. **Risk.** A changed binding at a later start; S3.3 finds the
  files anyway.

### S2.5 Start-time platform checks

- **Probe.** New `Ndbfs::probe_redo_path_pmem(i)`, from `Ndbfs::execREAD_CONFIG_REQ`, for each
  REDO base path (or `BP_FS`), PMEM mode only: create `ndb_<id>_pmem_probe.tmp` of 2 MB, map
  `REQUIRED`, `ndb_pmem_region_info()`, unmap, remove. It fails before an initial start writes
  gigabytes. Results go to a read-only table `Ndbfs::get_redo_path_info(i)`, read by DBLQH
  after its own READ_CONFIG (NDBFS runs first, fact 13; `get_base_path()` is already read
  from other threads, `Ndbfs.cpp:257-258`) [V]. The verdict is a pure function
  `Ndbfs::pmem_path_verdict(info, test_mode)` so it can be unit-tested.

| Check | Where | `off` (production) | `emulated` | `nodax` |
|---|---|---|---|---|
| `MAP_SYNC` on the probe | probe | `ERROR_SET(fatal, NDBD_EXIT_INVALID_CONFIG)`: "FileSystemPathRedoLog <p> is not on a DAX file system (mmap MAP_SYNC: <errno>)" | same | skip, `MAP_SHARED` |
| `MAP_SYNC` per file | `AsyncFile::openReq` → FSOPENREF `fsErrNotDax` → `Dblqh::execFSOPENREF` (`DblqhMain.cpp:34548`) | `progError` with the file name | same | skip |
| Domain empty | probe | refuse: "region <r> reports no persistence domain (memmap= emulation?)" | warn, treat as ADR | skip |
| Domain unknown | probe | refuse | refuse | skip |
| `memory_controller`, `cpu_cache` | probe | info line, ndbinfo | same | — |
| Bad blocks on the device | probe | warning with the count | same | skip |
| Bad blocks inside a REDO file | `AsyncFile::openReq` after map (FIEMAP) → `fsErrPmemBadBlocks` | `progError`: "clear with `ndctl clear-errors`, restart with --initial" | same | skip |
| Dirty-shutdown count | probe; S6 compares with the control area | step 1: warning, cluster-log event, ndbinfo (design issue 3) | same | skip |
| ARM without `DC CVAP` | `ndb_pmem_init` in NDBFS | refuse | warning | — |
| Control area or format mismatch | S6, page 0 of file 0 | refuse: "RedoLogMode changed; restart with --initial" | same | same |
| NUMA mismatch | S2.4 | warning | warning | warning |

- **Messages** use `NDBD_EXIT_INVALID_CONFIG` (2350, `ndbd_exit_codes.h:105`) [V] with a text,
  as DBLQH does for a wrong file size (`DblqhMain.cpp:34552-34558`) [V]. No new exit codes.
- **File mode.** No probe, no checks.
- **Tests.** Linux, production mode, `FileSystemPathRedoLog=/dev/shm/redo`: `ndbmtd --initial`
  exits 2350 with "is not on a DAX file system" in the node log. `memmap=` with `off`: "reports
  no persistence domain"; with `emulated` the node starts with a warning. Unit test of
  `pmem_path_verdict` on the S1.4 fixtures.
- **Depends** on S1.4, S2.3, S3.2. **Risk.** False refusals from odd sysfs layouts; messages
  print the sysfs path used.

### S2.6 ndbinfo `redo_log_pmem`

- **A new table.** `logspaces`/`logbuffers` are shared with LGMAN and BACKUP
  (`lgman.cpp:1215`, `:1259`; `Backup.cpp:3462`) [V]; new columns would be meaningless there.
- **Where.** `REDO_LOG_PMEM_TABLEID = 61` after `TRUSTED_CERTS_TABLEID = 60`
  (`include/debugger/Ndbinfo.hpp:107`); `DECLARE_NDBINFO_TABLE` and the list entry in
  `src/common/debugger/NdbinfoTables.cpp` (`:178-205`, `:1404-1464`); the view in
  `plugin/ha_ndbinfo_sql.cc` near `logspaces` (`:446-454`); a case in
  `Dblqh::execDBINFO_SCANREQ` (`DblqhMain.cpp:45629`) modelled on `LOGSPACES` (`:45639-45677`)
  [V]. Estimate `data_nodes * log_parts`; no rows in file mode. Adding `trusted_certs` touched
  the same files plus `ndbinfo.result` and `ndbinfo_plans.result` [V, commit `223210e5351`].
- **Columns.** `node_id`, `log_part`, `ldm_instance`, `files`, `mapped_bytes`,
  `ldm_numa_node`, `mem_numa_node`, `persistence_domain`, `copy_method`, `test_mode`,
  `barriers`, `bytes_copied`, `filler_bytes`, `lat_samples`, `lat_le_250ns`, `lat_le_500ns`,
  `lat_le_1us`, `lat_le_2us`, `lat_le_4us`, `lat_le_8us`, `lat_le_16us`, `lat_gt_16us`,
  `dirty_shutdown_count`.
  ```c++
  struct RedoPmemStats {            // in LogPartRecord (Dblqh.hpp:1864)
    Uint64 barriers, bytes_copied, filler_bytes, lat_samples;
    Uint64 lat_hist[8];
  };
  static constexpr Uint32 NDB_REDO_PMEM_LAT_SAMPLE = 16;   // time 1 persist in 16
  ```
  S5's `redoPersist` updates it under the part mutex and times every 16th persist with
  `NdbTick_getCurrentTicks()` (~20 ns a call [I]; timing all would add 2–20 % on CXL, design
  §2). The owner LDM reads it without the mutex; 64-bit loads do not tear.
- **Tests.** `./mtr --record ndb.ndbinfo ndb.ndbinfo_plans`, review the diff.
  `ndb.ndb_redo_pmem_nodax` checks one row per part and `mapped_bytes = files × size`.
- **Depends** on S3.4; S5 moves the counters. **Risk.** Sampling rate (open question 7).

### S2.7 Test settings (flag for the architect)

**D8 says durable commits require PMEM and refuse to start otherwise.** These settings exist
to develop and test PMEM mode without PMEM hardware. They are hidden (`__` prefix, like
`__debug_mixology_level`, `ConfigInfo.cpp:1774`) [V], warned about by the management server,
logged at every start and shown in ndbinfo.

**Answered (Q-A1, review 10).** No PMEM hardware is available, so PMEM mode must run on normal
DRAM, in release builds too. The code is built for real PMEM: a test mode changes only the map
flags and which start checks run. The format, the non-temporal copy, the flushes, the fences,
the persist points and the recovery are the production code in every mode, with no `#ifdef`
and no separate DRAM write path, so the same code runs on real hardware when it arrives.

| Setting | Effect | Use |
|---|---|---|
| `__RedoLogPmemTestMode=off` | Production rules | Default |
| `=emulated` | `MAP_SYNC` required; empty `persistence_domain` accepted as ADR | `memmap=`: MTR, autotest |
| `=nodax` | `MAP_SYNC` optional (`MAP_SHARED`); domain, bad-block, dirty-shutdown checks skipped; survives a process crash only | macOS ARM64, Linux without `memmap=` |
| `__RedoLogPmemPowerLossEmulation=1` | S1.5 on; every crash is a power failure | S7, any mode |
| `__RedoLogPmemCopyMethod` | Forces a copy method | P6 |
| `__RedoLogPmemPersistDelayNs` | Spins for this many ns after each persist barrier, default 0 (Q-A11). Next free CFG id after 716, checked at merge | Commit latency and throughput for 200–2000 ns hardware, measured on DRAM |

**Durable commits are allowed with `emulated` and `nodax`** (consequence of Q-A1; X4–X7 cannot
be developed otherwise). On DRAM a commit survives a crash of every data-node process, because
the page cache holds the mapped file, but not an OS crash or a power loss;
`__RedoLogPmemPowerLossEmulation` tests that case. The node says so in its log at every start.

---

## 4. S3: NDBFS

### S3.1 Signal changes

- **`FsOpenReq`** (`include/kernel/signaldata/FsOpenReq.hpp`):
  - `OM_MAP_SYNC = 0x20000000`: map and prefault after open. Needs `OM_READWRITE`; excludes
    `OM_GZ`, encryption, `OM_DIRECT`, `OM_APPEND`.
  - `OM_REDO_PATH = 0x40000000`: `secondFileFlags` bits 8–15 hold the REDO path index. A
    `fileFlags` bit is the guard because every sender sets `fileFlags` fully, while
    `secondFileFlags` is uninitialised by all senders but LGMAN (fact 8). Helpers
    `setRedoPathNo()`, `getRedoPathNo()`.
  - `BasePathSpec` (`:161-167`): `BP_REDO_FIRST = 4`, `BP_REDO_LAST = 11`, `BP_MAX = 12`.
- **`FsConf`** (`FsConf.hpp:83-100`): FSOPENCONF grows from 5 to 7 words when mapped:
  `pmem_addr_hi`, `pmem_addr_lo`. `fileInfo` (only `USE_O_DIRECT = 1` today) gets
  `PMEM_MAPPED = 2`, `PMEM_MAP_SYNC = 4`, the domain in bits 4–5, the REDO path index used in
  bits 8–11, memory NUMA node + 1 in bits 16–31 (0 = unknown).
- **`FsRef`** (`FsRef.hpp:54-69`): `fsErrNotDax = FS_ERR_BIT | 16`,
  `fsErrPmemMapFailed = | 17`, `fsErrPmemBadBlocks = | 18`.
- **Printers.** `src/common/debugger/signaldata/FsOpenReq.cpp:62-80`, `FsConf.cpp`, `FsRef.cpp`.
- **File mode.** New bits never set; FSOPENCONF stays 5 words. DBLQH reads only words 0–1
  (`DblqhMain.cpp:34824-34829`) [V]; other receivers use the `FsConf` struct.
- **Tests.** A signal trace of a PMEM open shows the flags. **Size** S.

### S3.2 Map, prefault and unmap in the IO thread

- `AsyncFile.hpp`: member `ndb_pmem_mapping m_pmem` next to `m_file` (`:127-132`) [V].
- `AsyncFile::openReq` (`AsyncFile.cpp:103`): check the flag combination at the top
  (`:124-153`); after the `OM_INIT` block and before `OM_SYNC` (`:550-575`):
  `ndb_pmem_map(m_file.get_os_handle(), data_size, required_or_optional, &m_pmem)`, then
  `ndb_pmem_prefault`, the bad-block overlap check (S2.5) and `ndb_pmem_numa_node`. On error:
  unmap, close, take the existing error exit. `get_os_handle()` exists (`ndb_file.h:230`) [V];
  payload offset is 0 (fact 11). Required vs optional comes from an NDBFS member read by IO
  threads after READ_CONFIG.
- `Request` (`AsyncIoThread.hpp:151-152`): `void *m_pmem_addr`, `Uint32 m_pmem_info`.
- `Ndbfs::report`, open case (`Ndbfs.cpp:1482-1501`): words 5–6 and `fileInfo` bits; 7 words.
- `AsyncFile::closeReq` (`AsyncFile.cpp:682`): `ndb_pmem_unmap` before `m_file.close()`; in
  emulation, assert nothing in the range is pending.
- `Win32AsyncFile`: FSOPENREF `fsErrInvalidParameters`. `VoidFs::execFSOPENREQ`
  (`VoidFs.cpp:102`): `ndbrequire(!(flags & OM_MAP_SYNC))`.
- **Thread pool.** DBLQH sets `OM_THREAD_POOL` (S3.4), so no IO thread is bound to a file
  (`Ndbfs.cpp:587`) [V]; with every file open, bound files would need one thread each.
- **File mode.** All new code is under `OM_MAP_SYNC`.
- **Tests.** `ndb_pmem-t` for the helper; S3.5/S3.6 through NDBFS; trace with
  `NDB_TRACE_OPEN=1` (`Ndbfs.cpp:673-674`) [V].
- **Depends** on S1.3, S3.1. **Risks.** Prefaulting 1 GB takes tens to hundreds of ms (write
  path §2.1); 64 files on `DiskIOThreadPool` threads (default 8, `ConfigInfo.cpp:1154`) [V]
  take seconds, at start only. `LockPagesInMainMemory=1` does `mlockall(MCL_FUTURE)`
  (`NdbMem.cpp:45-49`) [V]: harmless on DAX [I], but with `nodax` it locks the page cache of
  every REDO file, so tests need small REDO sizes.

### S3.3 REDO base paths, cleanup and lookup

- `Ndbfs::execREAD_CONFIG_REQ` (`Ndbfs.cpp:280-377`): for path i build `<path>/ndb_<id>_fs/`
  with the `tmp` of the DD paths (`:287-296`), `do_mkdir`, `validate_path`, store in
  `m_base_path[BP_REDO_FIRST + i]`. If its real path equals `BP_FS`, leave the slot empty
  (REDO stays under `BP_FS`) and log it.
- `get_base_path_param_name` (`:267-278`): extend `param_id[BP_MAX]` with
  `CFG_DB_REDO_LOG_PATH` eight times; a short initialiser compiles and gives wrong names.
- ODirect probe loop (`:464-475`): skip empty REDO slots (they would probe `BP_FS` again).
- `Filename::set` (`Filename.cpp:55-75`): new argument `redo_bp` (default `BP_FS`) for
  `V_BLOCK` names. `Ndbfs::execFSOPENREQ` (`Ndbfs.cpp:601`) passes
  `BP_REDO_FIRST + getRedoPathNo()` only with `OM_REDO_PATH` and a non-empty slot.
- **Lookup.** In `AsyncFile::openReq`, an `OM_REDO_PATH` open without `OM_CREATE` that fails
  with `ENOENT` retries the other non-empty REDO slots and `BP_FS`, and reports the index used
  in `fileInfo` bits 8–11. DBLQH adopts it for the part and warns once. A changed binding,
  NUMA layout or path order then does not stop the node (design issue 4).
- `Ndbcntr::clearFilesystem` (`NdbcntrMain.cpp:5919-5958`): `CLEAR_REDO =
  NDB_MAX_REDO_LOG_PATHS` more steps, `V_BASEPATH` `BP_REDO_FIRST + i`, `ownDirectory = 0`;
  update the end test in `execFSREMOVECONF` (`:5961-5977`). `Ndbfs::execFSREMOVEREQ`
  (`Ndbfs.cpp:705`): `V_BASEPATH` on an empty REDO slot replies FSREMOVECONF at once and never
  falls back to `BP_FS` (fact 15). X6's node-failure file shares the directory (write path
  §10.1); removing it at initial start is right.
- **File mode.** NDBFS treats the parameter as unset (Q-A2): every REDO slot empty → names,
  cleanup and probes as today, whether the parameter is set or not.
- **Tests.** MTR `ndb.ndb_redo_pmem_paths` (PMEM mode with `nodax`, two paths under
  `$MYSQLTEST_VARDIR`):
  after initial start `--file_exists .../ndb_<id>_fs/D8/DBLQH/S0.FragLog` and nothing under
  `FileSystemPath/.../D8`; restart all, node restart, initial node restart; swap the paths and
  restart (lookup); `ndb_redo_log_reader` on the moved file (invocation as in
  `ndb.ndb_redo_log_reader`) [V]. Then file mode with the same paths set: the files are under
  `FileSystemPath`, nothing under the REDO paths, and the management server warns.
- **Depends** on S2.1, S3.1. **Risk.** The cleanup is the one place that can delete data.
  Review it against the `BP_FS` fallback.

### S3.4 DBLQH open flags and address

- `openFileRw` (`DblqhMain.cpp:35612-35672`), `openLogfileInit` (`:35674-35731`): set
  `secondFileFlags = 0` first (fact 8). PMEM mode: `OM_READWRITE | OM_CHECK_SIZE |
  OM_MAP_SYNC | OM_THREAD_POOL` (+ `OM_CREATE | OM_TRUNCATE | OM_INIT` for init); no
  `OM_AUTOSYNC`, `OM_DIRECT`, `OM_WRITE_BUFFER` (256 KB per open file, `Ndbfs.cpp:650-666`) [V],
  `OM_ZEROS_ARE_SPARSE` or encryption. With a REDO path set (PMEM mode only, Q-A2):
  `OM_REDO_PATH` + the part's index.
- `initFsopenconf` (`:34822-34831`): with 7 words and `PMEM_MAPPED`, store `m_pmem_base`,
  `m_pmem_fileRef`, domain, memory node; adopt the path index used.
- `execFSOPENREF` (`:34548-34562`): messages for the three new codes (S2.5). A missing REDO
  file says "not found under FileSystemPathRedoLog or FileSystemPath; was the path changed
  without --initial?".
- `Dblqh.hpp`: `LogFileRecord` (`:2310`) gets `Uint8 *m_pmem_base`, `Uint32 m_pmem_fileRef`,
  `Uint8 m_pmem_domain`, `Int16 m_pmem_numa_node`; `LogPartRecord` (`:1864`) gets
  `Uint8 m_redo_path_no`, `Uint32 m_pmem_files_to_map`, `RedoPmemStats m_pmem_stats`; the block
  gets `bool c_redo_pmem`, `Uint8 c_redo_pmem_test_mode`, `Int32 c_ldm_numa_node`.
- **File mode.** Today's flags, plus a zeroed `secondFileFlags`. **Depends** on S3.1, S2.3.

### S3.5 Initial start in PMEM mode

- **Today** (`InitFragmentLogFiles=full`) [V]: `startphase1Lab` (`DblqhMain.cpp:2219`) opens
  file 0 of part 0 (`:2280-2297`) → `openLogfileInit` with `OM_INIT` → NDBFS writes every page
  and the callback formats the first page of each mbyte and the last page (`:35733-35790`) →
  `openFileInitLab` (`:35351`) → `initWriteEndLab` (`:35371`) → `writeFileHeaderOpen(ZINIT)`
  writes page 0 by FSWRITEREQ (`:36073-36161`) → `initFirstPageLab` (`:35397`) writes
  `COMPLETED_GCI(1)` in file 0 page 1 → `writeInitMbyteLab` closes the file (`:35429-35441`)
  → `closingInitLab` opens the next (`:35443-35457`) → `checkInitCompletedLab` takes the next
  part (`:35459-35513`). Phase 4 (`initFourth`, `:40438`) opens file 0 to read the head.
- **S3 change (before S4).** `openLogfileInit` uses the PMEM flags of S3.4, so every file is
  fully written, fsynced, mapped and prefaulted. `writeInitMbyteLab` does not close it in PMEM
  mode: it marks it `OPEN` and runs the `closingInitLab` logic, factored out as
  `initNextLogfile()`. Pages 0 and 1 are still written by FSWRITEREQ in today's format.
- **After S4 lands, who writes what:**

| Item | Written by | Package |
|---|---|---|
| Every byte zero, `fsync` | NDBFS `OM_INIT` (`AsyncFile.cpp:383-551`) | today; S3.5 sets flags |
| Lap-0 mbyte headers in PMEM format with checksum (format W9) | `Dblqh::execFSWRITEREQ` callback → `redoPmemFormatInitPage()` | S4 writer, S3.5 hook |
| Page 0: header, FD, FILLER | `redoPmemInitFile()` through the mapping | S4 |
| File 0 page 0 control area: static config, both slots, dirty-shutdown count | `redoPmemInitFile()` | S4 (values S2.5) |
| File 0 page 1: header, `COMPLETED_GCI(1)`, FILLER | `redoPmemInitFile()` | S4 |
| Persist | `ndb_pmem_copy_nt` + `ndb_pmem_drain` | S1.3 |
| Keep mapped, next file | `initNextLogfile()` | S3.5 |

  In PMEM mode `openFileInitLab` then calls `redoPmemInitFile()` instead of
  `initWriteEndLab`: no LFO, no FSWRITEREQ; the next file follows by CONTINUEB.
- **File mode.** Branches only under `c_redo_pmem`.
- **Tests.**
  - MTR `ndb.ndb_redo_pmem_nodax`: `.cnf` with `RedoLogMode=pmem`,
    `__RedoLogPmemTestMode=nodax`, `NoOfFragmentLogFiles=4`, `FragmentLogFileSize=16M`,
    `FileSystemPathRedoLog=$MYSQLTEST_VARDIR/pmem`; initial start; one ndbinfo row per part
    with `mapped_bytes = 64M`; load data; restart all nodes; data intact. macOS and Linux.
  - MTR `ndb.ndb_redo_pmem_dax`: same with `emulated`, skipped unless `NDB_PMEM_DIR` is set
    (new `include/have_ndb_pmem.inc`). Setup: kernel `memmap=8G!16G`, then
    `mkfs.xfs -f -m reflink=0 /dev/pmem0 && mount -o dax=always /dev/pmem0 /mnt/pmem0`, then
    `NDB_PMEM_DIR=/mnt/pmem0 ./mtr ndb.ndb_redo_pmem_dax`.
  - After S4: `ndb_redo_log_reader` on file 0 shows the new page 0.
- **Depends** on S3.2–S3.4; S4 for the format. **Risk.** 64 GB of default REDO takes 6–30 s
  at initial start (write path §10.2); document it.

### S3.6 Map every file at start; virtual open and close

- **Today.** SR/NR open file 0 in `startphase3Lab` (`DblqhMain.cpp:2484-2492`) and then open and
  close files in about fifteen states (`Dblqh.hpp:2323-2363`, `execFSOPENCONF`
  `:34421-34546`), including an LRU of open files for REDO execution (`:34529-34536`,
  `openFileRw_cache` `:47333`) [V].
- **Changes.**
  - `startphase3Lab`, SR/NR: in PMEM mode open every file of every owned part at once (state
    `OPENING_PMEM_MAP_ALL`, counter `m_pmem_files_to_map`). When a part reaches 0, file 0 goes
    to `OPEN_SR_FRONTPAGE` through a virtual open.
  - `openFileRw()`/`openFileRw_cache()`, file mapped: **virtual open** = `GSN_FSOPENCONF` to
    `cownref`, `theData[0] = filePtr.i`, `theData[1] = m_pmem_fileRef`, length 2, JBB.
    `execFSOPENCONF` runs unchanged, including the `ERROR_INSERT 5090` delay (`:34427-34439`)
    and the lock in `initFsopenconf`.
  - `closeFile()` (`:41015`): **virtual close** = `GSN_FSCLOSECONF` to self,
    `theData[0] = filePtr.i`; NDBFS keeps the file. `execFSCLOSECONF` sets `fileRef = RNIL`
    (`:34332`); the next virtual open restores it.
  - Initial start's phase 4 (`initFourth`) uses the same virtual open.
  - Until S5, normal operation writes by FSWRITEREQ on the open file, and the file change in
    `initFsopenconf` (`:34833-34844`) works as today; S5 makes the switch synchronous (E15).
- **File mode.** Under `c_redo_pmem` only.
- **Tests.** Today's restart tests must pass with every file mapped:
  - MTR `ndb.ndb_redo_pmem_nodax` plus a node restart and an initial node restart.
  - Autotest with a new `test/run-test/conf-pmem-nodax.cnf` (`RedoLogMode=pmem`,
    `__RedoLogPmemTestMode=nodax`, small REDO): `testSystemRestart -n SR1 T1`, `-n SR2 T1`,
    `testNodeRestart -n NoLoad T1`, `testRedo -n RestartOK T1`, `-n RestartFDSR T1`,
    `-n CheckNextRedoFileOpened T1` (`testRedo.cpp:1861-1947`) [V]. The same with `emulated`
    on `memmap=`.
- **Depends** on S3.4, S3.5. **Risks.** Self-sent FS signals must pass the data-node signal
  scope checks (`claude_files/data_node_security/`); a self send is local. S5/S6 may replace
  the self-signals with direct calls later.

---

## 5. Order

```
S1.1 ─┬─ S1.2
      └─ S1.3 ── S1.4 ── S1.5
S2.1 ── S2.2 ── S2.3 ── S2.7
S3.1 ── S3.2 (S1.3) ── S3.3 (S2.1) ── S3.4 ── S2.4 (S1.4) ── S2.5 ── S3.5 ── S3.6 ── S2.6
```

1. S1.1, S2.1, S3.1 in parallel.
2. S1.2, S1.3; S2.2, S2.3, S2.7.
3. S3.2–S3.4: PMEM mode maps files; today's tests run against it.
4. S1.4, S2.4, S2.5: placement and refusals.
5. S3.5, S3.6: initial start and restarts with every file mapped.
6. S1.5 and S2.6 any time after S1.3 and S3.4 (S7 needs S1.5; S5's counters need S2.6).

S4 can start after S1.2, S1.3 and S3.4.

---

## 6. New symbols, parameters and files

| Kind | Name | Package |
|---|---|---|
| Files | `include/util/ndb_xxh3.h`, `src/common/util/ndb_xxh3.cpp` (replace `xxhash_avx2.cpp`, `xxhash_std.cpp`) | S1.2 |
| Files | `include/portlib/ndb_pmem.h`, `src/common/portlib/ndb_pmem.cpp` | S1.3–S1.5 |
| Files | `include/util/RedoLogPaths.hpp`, `src/common/util/RedoLogPaths.cpp` | S2.1 |
| Functions | `ndb_xxh3_64`, `ndb_xxh3_64_seed`, `ndb_xxh3_init`, `ndb_xxh3_implementation` | S1.2 |
| Functions | `ndb_pmem_init`, `_method_name`, `_map`, `_unmap`, `_prefault`, `_copy_nt`, `_store32`, `_store64`, `_zero`, `_flush`, `_drain` | S1.3 |
| Functions | `ndb_pmem_persistence_domain`, `_region_info`, `_numa_node`, `_badblocks_overlap`, `_dirty_shutdown`, `_set_sysfs_root` | S1.4 |
| Functions | `ndb_pmem_emul_enable`, `_active`, `_pending`, `_power_fail`, `_on_crash`, `_get_stats` | S1.5 |
| Functions | `Ndb_GetCpuFeatures`, `Ndb_GetThreadNumaNode` | S1.1, S1.4 |
| Types | `ndb_cpu_features`, `ndb_pmem_mapping`, `ndb_pmem_copy_method`, `ndb_pmem_domain`, `ndb_pmem_region_info`, `ndb_pmem_emul_stats`, `RedoLogPaths`, `RedoPmemStats` | S1, S2 |
| Field | `ndb_cpuinfo_data::numa_node` | S1.4 |
| Constants | `NDB_PMEM_LINE = 64`, `NDB_MAX_REDO_LOG_PATHS = 8`, `NDB_REDO_PMEM_LAT_SAMPLE = 16` | S1.3, S2.1, S2.6 |
| CFG ids | 711 `CFG_DB_REDO_LOG_MODE`, 712 `CFG_DB_REDO_LOG_PATH`, 713 `CFG_DB_REDO_PMEM_TEST_MODE`, 714 `CFG_DB_REDO_PMEM_POWER_LOSS_EMUL`, 715 `CFG_DB_REDO_PMEM_COPY_METHOD` | S2.1 |
| Parameters | `RedoLogMode`, `FileSystemPathRedoLog`, `__RedoLogPmemTestMode`, `__RedoLogPmemPowerLossEmulation`, `__RedoLogPmemCopyMethod` | S2.1, S2.7 |
| FsOpenReq | `OM_MAP_SYNC = 0x20000000`, `OM_REDO_PATH = 0x40000000`, `setRedoPathNo`, `getRedoPathNo`, `BP_REDO_FIRST = 4`, `BP_REDO_LAST = 11`, `BP_MAX = 12` | S3.1 |
| FsConf | FSOPENCONF words 5–6 `pmem_addr_hi/lo`; `PMEM_MAPPED`, `PMEM_MAP_SYNC`, domain, path, NUMA bits | S3.1 |
| FsRef | `fsErrNotDax`, `fsErrPmemMapFailed`, `fsErrPmemBadBlocks` | S3.1 |
| NDBFS | `AsyncFile::m_pmem`, `Request::m_pmem_addr`, `Request::m_pmem_info`, `Ndbfs::probe_redo_path_pmem`, `get_redo_path_info`, `pmem_path_verdict` | S3.2, S2.5 |
| DBLQH | `c_redo_pmem`, `c_redo_pmem_test_mode`, `c_ldm_numa_node`; `LogFileRecord::m_pmem_base`, `m_pmem_fileRef`, `m_pmem_domain`, `m_pmem_numa_node`; `LogPartRecord::m_redo_path_no`, `m_pmem_files_to_map`, `m_pmem_stats`; state `OPENING_PMEM_MAP_ALL`; `initNextLogfile()` | S3.4–S3.6, S2.4, S2.6 |
| ndbinfo | `REDO_LOG_PMEM_TABLEID = 61`, `ndb$redo_log_pmem`, view `redo_log_pmem` | S2.6 |
| Unit tests | `ndb_xxh3-t`, `ndb_pmem-t`, `RedoLogPaths-t`; extended `NdbHW-t`, `MgmConfig-t` | S1, S2 |
| MTR | `ndb.ndb_redo_pmem_config`, `_paths`, `_nodax`, `_dax`, `include/have_ndb_pmem.inc`; re-recorded `ndb.ndbinfo`, `ndb.ndbinfo_plans` | S2, S3 |
| Autotest | `test/run-test/conf-pmem-nodax.cnf` | S3.6 |

Unit test commands for the architect (`-DWITH_UNIT_TESTS=1`):

```
cmake --build <build> --target ndb_xxh3-t ndb_pmem-t RedoLogPaths-t NdbHW-t MgmConfig-t rondb_hash-t
ctest --test-dir <build> -R 'ndb_xxh3-t|ndb_pmem-t|RedoLogPaths-t|NdbHW-t|MgmConfig-t|rondb_hash-t' --output-on-failure
NDB_PMEM_DIR=/mnt/pmem0 <build>/runtime_output_directory/ndb_pmem-t   # Linux, DAX mount
```

---

## 7. Design issues found

1. **E17 row 1 is too narrow.** It refuses a failing `MAP_SYNC` only "when durable commits
   are configured". In PMEM mode without `MAP_SYNC`, writes land in the page cache and NT
   stores + `sfence` never reach the disk, so the REDO is not durable even at GCP level. The
   write path note says the check applies "with durable commits on or off" (§10.2). This plan
   refuses whenever `RedoLogMode=pmem`, unless a test setting is on. Please confirm and fix E17.
2. **Empty `persistence_domain`**, same point: refused in step 1 too (REDO on `memmap=` is
   REDO in RAM). The write path note limited it to durable commits; E17 does not, and wins.
3. **Dirty shutdown in step 1.** E17/Q4 say "report the node stale", but stale nodes arrive
   with X6. In step 1 the REDO is GCP-durable; a dirty shutdown can lose a GCP-saved tail, so
   the node's REDO may end before the restorable GCI in the sysfile. Step 1 needs an interim
   action. Proposal: record and compare the count (S6), warn, cluster-log event, ndbinfo; S6
   decides what SR does when E lies before the restorable GCI. Refusing until `--initial` can
   stop a whole node group after one power failure.
4. **E20 placement is not stable across starts.** It follows the CPU binding at each start. A
   changed `ThreadConfig`, `NumCPUs`, BIOS NUMA setting or path order moves the expected
   location while the files stay put. S3.3 adds a lookup across all REDO paths; without it the
   node fails with "file not found".
5. **`secondFileFlags` is uninitialised** in DBLQH and in every FSOPENREQ sender except LGMAN
   [V, grep]. Harmless today (only LGMAN's callback reads `OM_FIRST_FILE`). The plan guards
   its use with a `fileFlags` bit and zeroes it in DBLQH.
6. **`MAP_POPULATE` does not prefault a shared mapping for write** (hardware §4.1). The
   fallback touch-loop rewrites a byte per page with its own value, formally a rewrite of a
   persisted unit (E6). The plan prefers `MADV_POPULATE_WRITE` and flushes touched lines.
7. **File names** are `S<n>.FragLog` (`Filename.cpp:39-41`), not `.FRAGLOG`. Cosmetic.
8. **`InitFragmentLogFiles=full` cannot be forced with a warning**: the management server
   cannot tell a default `sparse` from a user's. Replaced silently there, logged by the node.
9. **CXL dirty-shutdown sysfs** depends on the kernel version [I], and the target modules may
   expose no count. "Not exposed" must mean "unknown", not "clean".

---

## 8. Open questions

1. Should `FileSystemPathRedoLog` move the REDO in file mode too? **Answered (Q-A2): no.** File
   mode keeps today's REDO placement; too much relies on it. The parameter is PMEM mode only.
2. Is `node:path,node:path` (plus a plain single path) acceptable? Are 8 entries enough
   (sub-NUMA clustering can give 4 nodes per socket)? **Answered (Q-A3): yes**, both.
3. May the test settings be used in release builds? **Answered (Q-A1): yes.** PMEM mode must
   run on normal DRAM until hardware is available.
4. When `DurableCommits` arrives: allowed with `emulated`? With `nodax`? **Yes, both** (follows
   from Q-A1; S2.7).
5. Interim dirty-shutdown action in step 1: warn (recommended) or refuse until `--initial`?
6. Is ARM in scope? No ARM PMEM hardware was found (hardware §8). The plan builds and tests
   ARM and refuses production PMEM mode on ARM without `DC CVAP`. **Answered (Q-A5):** build
   and unit-test on Linux x86_64, Linux ARM64 and macOS ARM64; macOS x86_64 is not supported.
7. Latency histogram: sample 1 in 16 (recommended) or time every persist? Are the buckets
   right for 200–2000 ns hardware?
8. Copy-method switch as a hidden parameter (this plan) or a compile-time choice?
9. Without FIEMAP, should bad blocks elsewhere on the device refuse the start (conservative)
   or only warn (this plan)?
