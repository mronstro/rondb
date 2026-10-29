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

/**
 * The platform queries of ndb_pmem.h (platform plan S1.4). They read
 * sysfs, which is plain file IO, so the parsing builds and is tested on
 * every platform against a fixture tree (ndb_pmem_set_sysfs_root()).
 *
 * From a file to its region:
 *   fstat -> st_dev M:m -> /sys/dev/block/M:m -> the block device, e.g.
 *   .../ndbus0/region0/namespace0.0/block/pmem0, or a partition below
 *   it. Device mapper and md list the devices below in slaves/. The
 *   region is the closest directory above with persistence_domain; it
 *   also has numa_node, target_node and mapping<k> files naming the
 *   DIMMs or memory devices (nmemX) with their dirty-shutdown counts.
 */

#include <ndb_global.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <string>
#include <vector>

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef __linux__
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#ifndef STATX_ATTR_DAX
#define STATX_ATTR_DAX 0x00200000
#endif
#ifndef MPOL_F_NODE
#define MPOL_F_NODE (1 << 0)
#endif
#ifndef MPOL_F_ADDR
#define MPOL_F_ADDR (1 << 1)
#endif
#endif

#include <portlib/ndb_pmem.h>

namespace {

/* Byte range on a device or in a file */
struct Range {
  Uint64 start;
  Uint64 len;
};

/* Bad-block ranges that overlap any of the extents */
Uint32 count_overlapping(const std::vector<Range> &bad,
                         const std::vector<Range> &extents) {
  Uint32 n = 0;
  for (const Range &b : bad) {
    for (const Range &e : extents) {
      if (b.start < e.start + e.len && e.start < b.start + b.len) {
        n++;
        break;
      }
    }
  }
  return n;
}

ndb_pmem_domain parse_domain(const std::string &s) {
  if (s.empty()) return NDB_PMEM_DOMAIN_NONE;
  if (s == "memory_controller") return NDB_PMEM_DOMAIN_MEMCTRL;
  if (s == "cpu_cache") return NDB_PMEM_DOMAIN_CPU_CACHE;
  return NDB_PMEM_DOMAIN_UNKNOWN;
}

void init_info(ndb_pmem_region_info *info) {
  memset(info, 0, sizeof(*info));
  info->domain = NDB_PMEM_DOMAIN_UNKNOWN;
  info->numa_node = -1;
  info->target_node = -1;
  info->dirty_shutdown = ~Uint64(0);
}

#ifndef _WIN32

std::string g_root;  // Test hook; empty for the real sysfs

std::string join(const std::string &dir, const std::string &name) {
  return dir + "/" + name;
}

std::string parent(const std::string &path) {
  const size_t i = path.find_last_of('/');
  if (i == std::string::npos || i == 0) return std::string();
  return path.substr(0, i);
}

std::string base_name(const std::string &path) {
  const size_t i = path.find_last_of('/');
  return i == std::string::npos ? path : path.substr(i + 1);
}

bool exists(const std::string &path) {
  return access(path.c_str(), F_OK) == 0;
}

bool real_path(const std::string &path, std::string *out) {
  char buf[PATH_MAX];
  if (realpath(path.c_str(), buf) == nullptr) return false;
  *out = buf;
  return true;
}

/* The first line of a file without trailing white space */
bool read_line(const std::string &path, std::string *out) {
  FILE *f = fopen(path.c_str(), "r");
  if (f == nullptr) return false;
  char buf[512];
  const bool got = fgets(buf, sizeof(buf), f) != nullptr;
  fclose(f);
  out->assign(got ? buf : "");
  while (!out->empty() && isspace((unsigned char)out->back())) {
    out->pop_back();
  }
  return true;
}

bool read_number(const std::string &path, long long *v) {
  std::string s;
  if (!read_line(path, &s) || s.empty()) return false;
  char *end = nullptr;
  errno = 0;
  const long long x = strtoll(s.c_str(), &end, 10);
  if (errno != 0 || *end != 0) return false;
  *v = x;
  return true;
}

std::vector<std::string> list_dir(const std::string &dir) {
  std::vector<std::string> names;
  DIR *d = opendir(dir.c_str());
  if (d == nullptr) return names;
  while (struct dirent *e = readdir(d)) {
    if (e->d_name[0] != '.') names.push_back(e->d_name);
  }
  closedir(d);
  std::sort(names.begin(), names.end());
  return names;
}

/* Lines "sector count" of a badblocks file, 512-byte sectors */
std::vector<Range> parse_badblocks(const std::string &path) {
  std::vector<Range> ranges;
  FILE *f = fopen(path.c_str(), "r");
  if (f == nullptr) return ranges;
  unsigned long long sector, count;
  while (fscanf(f, "%llu %llu", &sector, &count) == 2) {
    ranges.push_back({sector * 512, count * 512});
  }
  fclose(f);
  return ranges;
}

/* One block device below the file system, and its region */
struct Device {
  std::string dir;
  std::string region;
  ndb_pmem_domain domain = NDB_PMEM_DOMAIN_UNKNOWN;
  int numa_node = -1;
  int target_node = -1;
  bool dirty_known = false;
  Uint64 dirty = 0;
  std::vector<Range> bad;  // On the disk
  Uint64 part_start = 0;   // Of the partition on the disk
};

std::string find_region(const std::string &dev_dir) {
  std::string d = dev_dir;
  for (int i = 0; i < 32 && !d.empty(); i++) {
    if (exists(join(d, "persistence_domain"))) return d;
    d = parent(d);
  }
  return std::string();
}

/**
 * The summed dirty-shutdown counts of the DIMMs or memory devices of a
 * region, from its mapping<k> files. NFIT DIMMs have nfit/, PAPR ones
 * papr/; CXL memory devices have it directly, depending on the kernel.
 */
bool region_dirty_shutdown(const std::string &region, Uint64 *sum) {
  *sum = 0;
  int mappings = 0;
  for (const std::string &name : list_dir(region)) {
    if (name.compare(0, 7, "mapping") != 0 || name.size() == 7 ||
        !isdigit((unsigned char)name[7])) {
      continue;
    }
    std::string line;
    if (!read_line(join(region, name), &line)) return false;
    const std::string nmem = line.substr(0, line.find(','));
    const std::string dimm = g_root + "/sys/bus/nd/devices/" + nmem;
    const char *files[] = {"nfit/dirty_shutdown", "papr/dirty_shutdown",
                           "dirty_shutdown"};
    long long v = -1;
    for (const char *file : files) {
      if (read_number(join(dimm, file), &v)) break;
    }
    if (v < 0) return false;
    *sum += (Uint64)v;
    mappings++;
  }
  return mappings > 0;
}

void read_device(const std::string &dev_dir, Device *d) {
  d->dir = dev_dir;
  d->region = find_region(dev_dir);
  if (!d->region.empty()) {
    std::string domain;
    read_line(join(d->region, "persistence_domain"), &domain);
    d->domain = parse_domain(domain);
    long long v;
    if (read_number(join(d->region, "numa_node"), &v)) d->numa_node = (int)v;
    if (read_number(join(d->region, "target_node"), &v)) {
      d->target_node = (int)v;
    }
    d->dirty_known = region_dirty_shutdown(d->region, &d->dirty);
  }
  /* The bad blocks of a partition are listed on its disk */
  std::string disk = dev_dir;
  long long start = 0;
  if (exists(join(dev_dir, "partition"))) {
    disk = parent(dev_dir);
    read_number(join(dev_dir, "start"), &start);
  }
  d->part_start = (Uint64)start * 512;
  d->bad = parse_badblocks(join(disk, "badblocks"));
}

/* The devices below dev_dir: itself, or those it is stacked on */
void collect(const std::string &dev_dir, int depth, std::vector<Device> *out) {
  const std::string slaves_dir = join(dev_dir, "slaves");
  const std::vector<std::string> slaves = list_dir(slaves_dir);
  if (!slaves.empty() && depth < 8) {
    for (const std::string &s : slaves) {
      std::string real;
      if (real_path(join(slaves_dir, s), &real)) {
        collect(real, depth + 1, out);
      } else {
        Device unknown;
        unknown.dir = join(slaves_dir, s);
        out->push_back(unknown);
      }
    }
    return;
  }
  Device d;
  read_device(dev_dir, &d);
  out->push_back(d);
}

/**
 * The block device of the file system of fd and the devices below it.
 * false if there is no block device, e.g. tmpfs. errno on fstat failure.
 */
bool find_devices(int fd, std::string *top, std::vector<Device> *devices,
                  int *err) {
  *err = 0;
  struct stat st;
  if (fstat(fd, &st) != 0) {
    *err = errno;
    return false;
  }
  char rel[64];
  snprintf(rel, sizeof(rel), "/sys/dev/block/%u:%u",
           (unsigned)major(st.st_dev), (unsigned)minor(st.st_dev));
  if (!real_path(g_root + rel, top)) return false;
  collect(*top, 0, devices);
  return !devices->empty();
}

bool is_dax_inode(int fd) {
#if defined(__linux__) && defined(STATX_BASIC_STATS)
  struct statx stx;
  if (statx(fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &stx) != 0) return false;
  return (stx.stx_attributes_mask & STATX_ATTR_DAX) != 0 &&
         (stx.stx_attributes & STATX_ATTR_DAX) != 0;
#else
  (void)fd;
  return false;
#endif
}

/**
 * The physical ranges of bytes [off, off + len) of the file, relative
 * to the file system's device. false if they cannot be known.
 */
bool file_extents(int fd, Uint64 off, Uint64 len, std::vector<Range> *out) {
#ifdef __linux__
  const Uint32 count = 64;
  std::vector<Uint64> buf(
      (sizeof(struct fiemap) + count * sizeof(struct fiemap_extent)) /
          sizeof(Uint64) +
      1);
  struct fiemap *fm = reinterpret_cast<struct fiemap *>(buf.data());
  const Uint64 end = off + len;
  Uint64 start = off;
  while (start < end) {
    memset(buf.data(), 0, buf.size() * sizeof(Uint64));
    fm->fm_start = start;
    fm->fm_length = end - start;
    fm->fm_extent_count = count;
    if (ioctl(fd, FS_IOC_FIEMAP, fm) != 0) return false;
    if (fm->fm_mapped_extents == 0) break;
    bool last = false;
    for (Uint32 i = 0; i < fm->fm_mapped_extents; i++) {
      const struct fiemap_extent &e = fm->fm_extents[i];
      if (e.fe_flags & (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC)) {
        return false;
      }
      const Uint64 lo = std::max<Uint64>(e.fe_logical, off);
      const Uint64 hi = std::min<Uint64>(e.fe_logical + e.fe_length, end);
      if (lo < hi) {
        out->push_back({e.fe_physical + (lo - e.fe_logical), hi - lo});
      }
      start = e.fe_logical + e.fe_length;
      if (e.fe_flags & FIEMAP_EXTENT_LAST) last = true;
    }
    if (last) break;
  }
  return true;
#else
  (void)fd;
  (void)off;
  (void)len;
  (void)out;
  return false;
#endif
}

#endif

}  // namespace

void ndb_pmem_set_sysfs_root(const char *root) {
#ifndef _WIN32
  g_root = (root != nullptr) ? root : "";
#else
  (void)root;
#endif
}

int ndb_pmem_get_region_info(int fd, ndb_pmem_region_info *info) {
  init_info(info);
#ifdef _WIN32
  (void)fd;
  return 0;
#else
  info->dax_inode = is_dax_inode(fd);
  std::string top;
  std::vector<Device> devices;
  int err;
  if (!find_devices(fd, &top, &devices, &err)) return err;
  snprintf(info->device, sizeof(info->device), "%s", base_name(top).c_str());
  info->stacked = devices.size() > 1 || devices[0].dir != top;
  bool dirty_known = true;
  Uint64 dirty = 0;
  for (size_t i = 0; i < devices.size(); i++) {
    const Device &d = devices[i];
    if (i == 0) {
      info->domain = d.domain;
      info->numa_node = d.numa_node;
      info->target_node = d.target_node;
      snprintf(info->region, sizeof(info->region), "%s", d.region.c_str());
    } else {
      info->domain = std::min(info->domain, d.domain);
      if (d.numa_node != info->numa_node) info->numa_node = -1;
      if (d.target_node != info->target_node) info->target_node = -1;
    }
    if (d.dirty_known) {
      dirty += d.dirty;
    } else {
      dirty_known = false;
    }
    info->badblock_ranges += (Uint32)d.bad.size();
  }
  if (dirty_known) info->dirty_shutdown = dirty;
  return 0;
#endif
}

int ndb_pmem_persistence_domain(int fd, ndb_pmem_domain *domain) {
  ndb_pmem_region_info info;
  const int r = ndb_pmem_get_region_info(fd, &info);
  *domain = info.domain;
  return r;
}

int ndb_pmem_numa_node(int fd, const void *addr) {
  ndb_pmem_region_info info;
  if (ndb_pmem_get_region_info(fd, &info) == 0 && info.numa_node >= 0) {
    return info.numa_node;
  }
#ifdef __linux__
  if (addr != nullptr) {
    int node = -1;
    if (syscall(SYS_get_mempolicy, &node, nullptr, 0UL, addr,
                (unsigned long)(MPOL_F_NODE | MPOL_F_ADDR)) == 0) {
      return node;
    }
  }
#else
  (void)addr;
#endif
  return -1;
}

int ndb_pmem_dirty_shutdown(int fd, Uint64 *count) {
  ndb_pmem_region_info info;
  const int r = ndb_pmem_get_region_info(fd, &info);
  if (r != 0) return r;
  if (info.dirty_shutdown == ~Uint64(0)) return ENOTSUP;
  *count = info.dirty_shutdown;
  return 0;
}

int ndb_pmem_badblocks_overlap(int fd, Uint64 off, Uint64 len, Uint32 *n,
                               bool *exact) {
  *n = 0;
  *exact = false;
#ifdef _WIN32
  (void)fd;
  (void)off;
  (void)len;
  return 0;
#else
  std::string top;
  std::vector<Device> devices;
  int err;
  if (!find_devices(fd, &top, &devices, &err)) return err;
  Uint32 total = 0;
  for (const Device &d : devices) total += (Uint32)d.bad.size();
  if (total == 0) {
    *exact = true;
    return 0;
  }
  std::vector<Range> extents;
  if (devices.size() > 1 || devices[0].dir != top ||
      !file_extents(fd, off, len, &extents)) {
    *n = total;
    return 0;
  }
  for (Range &e : extents) e.start += devices[0].part_start;
  *n = count_overlapping(devices[0].bad, extents);
  *exact = true;
  return 0;
#endif
}

#ifdef TEST_NDB_PMEM_REGION

#include <util/NdbTap.hpp>

#ifndef _WIN32
#include <ftw.h>
#endif

namespace {

void test_parsing() {
  OK(parse_domain("") == NDB_PMEM_DOMAIN_NONE);
  OK(parse_domain("memory_controller") == NDB_PMEM_DOMAIN_MEMCTRL);
  OK(parse_domain("cpu_cache") == NDB_PMEM_DOMAIN_CPU_CACHE);
  OK(parse_domain("something new") == NDB_PMEM_DOMAIN_UNKNOWN);

  const std::vector<Range> bad = {{100, 10}, {200, 1}};
  OK(count_overlapping(bad, {{0, 100}}) == 0);
  OK(count_overlapping(bad, {{0, 101}}) == 1);
  OK(count_overlapping(bad, {{0, 50}, {105, 5}}) == 1);
  OK(count_overlapping(bad, {{109, 92}}) == 2);
  OK(count_overlapping(bad, {{110, 90}}) == 0);
  OK(count_overlapping({}, {{0, 1000}}) == 0);

  ndb_pmem_region_info info;
  init_info(&info);
  OK(info.domain == NDB_PMEM_DOMAIN_UNKNOWN);
  OK(info.numa_node == -1 && info.target_node == -1);
  OK(info.dirty_shutdown == ~Uint64(0));
}

#ifndef _WIN32

bool make_dirs(const std::string &path) {
  for (size_t i = 1; i <= path.size(); i++) {
    if (i == path.size() || path[i] == '/') {
      const std::string p = path.substr(0, i);
      if (mkdir(p.c_str(), 0755) != 0 && errno != EEXIST) {
        perror(p.c_str());
        return false;
      }
    }
  }
  return true;
}

void put(const std::string &path, const char *content) {
  OK(make_dirs(parent(path)));
  FILE *f = fopen(path.c_str(), "w");
  OK(f != nullptr);
  OK(fputs(content, f) >= 0);
  OK(fclose(f) == 0);
}

void link_to(const std::string &target, const std::string &link) {
  OK(make_dirs(parent(link)));
  OK(symlink(target.c_str(), link.c_str()) == 0);
}

int remove_entry(const char *path, const struct stat *, int, struct FTW *) {
  return remove(path);
}

void remove_tree(const std::string &dir) {
  nftw(dir.c_str(), remove_entry, 16, FTW_DEPTH | FTW_PHYS);
}

/**
 * A fixture: a sysfs tree below root whose /sys/dev/block entry for the
 * test file's device points at dev (relative to root/sys/devices).
 */
struct Fixture {
  std::string root;
  std::string sys;
  Fixture(const std::string &base, const char *name, dev_t st_dev,
          const char *dev)
      : root(join(base, name)), sys(join(root, "sys")) {
    OK(make_dirs(join(sys, "devices/") + dev));
    if (dev[0] != 0) {
      char rel[64];
      snprintf(rel, sizeof(rel), "dev/block/%u:%u", (unsigned)major(st_dev),
               (unsigned)minor(st_dev));
      link_to(join(sys, "devices/") + dev, join(sys, rel));
    }
    ndb_pmem_set_sysfs_root(root.c_str());
  }
  std::string path(const char *rel) const { return join(sys, rel); }
};

const char *const MEMMAP_REGION = "platform/e820_pmem/ndbus0/region0";

void test_fixtures(const char *tmp) {
  char base[1024];
  snprintf(base, sizeof(base), "%s/ndb_pmem_region-t.XXXXXX", tmp);
  OK(mkdtemp(base) != nullptr);
  std::string file_path = join(base, "file");
  const int fd = open(file_path.c_str(), O_CREAT | O_RDWR, 0600);
  OK(fd >= 0);
  OK(ftruncate(fd, 1 << 20) == 0);
  struct stat st;
  OK(fstat(fd, &st) == 0);
  ndb_pmem_region_info info;
  Uint64 count;
  Uint32 n;
  bool exact;

  {
    /* memmap=: an empty domain, no DIMMs, no bad blocks */
    Fixture fx(base, "memmap", st.st_dev,
               "platform/e820_pmem/ndbus0/region0/namespace0.0/block/pmem0");
    const std::string region = fx.path("devices/") + MEMMAP_REGION;
    put(join(region, "persistence_domain"), "\n");
    put(join(region, "numa_node"), "0\n");
    put(join(region, "target_node"), "-1\n");
    put(join(region, "mappings"), "0\n");
    OK(ndb_pmem_get_region_info(fd, &info) == 0);
    OK(info.domain == NDB_PMEM_DOMAIN_NONE);
    OK(info.numa_node == 0);
    OK(info.target_node == -1);
    OK(info.dirty_shutdown == ~Uint64(0));
    OK(info.badblock_ranges == 0);
    OK(!info.stacked);
    OK(strcmp(info.device, "pmem0") == 0);
    OK(base_name(info.region) == "region0");
    OK(ndb_pmem_dirty_shutdown(fd, &count) == ENOTSUP);
    OK(ndb_pmem_numa_node(fd, nullptr) == 0);
    OK(ndb_pmem_badblocks_overlap(fd, 0, 1 << 20, &n, &exact) == 0);
    OK(n == 0 && exact);
  }
  {
    /* NFIT: ADR, two DIMMs with counts 3 and 4, two bad ranges */
    Fixture fx(base, "nfit", st.st_dev,
               "LNXSYSTM:00/ACPI0012:00/ndbus1/region1/namespace1.0/block/pmem1");
    const std::string region =
        fx.path("devices/LNXSYSTM:00/ACPI0012:00/ndbus1/region1");
    put(join(region, "persistence_domain"), "memory_controller\n");
    put(join(region, "numa_node"), "1\n");
    put(join(region, "target_node"), "3\n");
    put(join(region, "mappings"), "2\n");
    put(join(region, "mapping0"), "nmem0,0,1073741824,0\n");
    put(join(region, "mapping1"), "nmem1,0,1073741824,1\n");
    put(fx.path("bus/nd/devices/nmem0/nfit/dirty_shutdown"), "3\n");
    put(fx.path("bus/nd/devices/nmem1/nfit/dirty_shutdown"), "4\n");
    put(join(region, "namespace1.0/block/pmem1/badblocks"), "16 8\n1024 1\n");
    OK(ndb_pmem_get_region_info(fd, &info) == 0);
    OK(info.domain == NDB_PMEM_DOMAIN_MEMCTRL);
    OK(info.numa_node == 1);
    OK(info.target_node == 3);
    OK(info.dirty_shutdown == 7);
    OK(info.badblock_ranges == 2);
    OK(ndb_pmem_dirty_shutdown(fd, &count) == 0 && count == 7);
    OK(ndb_pmem_badblocks_overlap(fd, 0, 1 << 20, &n, &exact) == 0);
    /* The test file is not on this device, so only consistency counts */
    OK(exact ? n <= 2 : n == 2);
  }
  {
    /* CXL-like: ADR, a memory device without a count */
    Fixture fx(base, "cxl", st.st_dev,
               "platform/ACPI0017:00/root0/nvdimm-bridge0/ndbus2/region2/"
               "namespace2.0/block/pmem2");
    const std::string region =
        fx.path("devices/platform/ACPI0017:00/root0/nvdimm-bridge0/ndbus2/"
                "region2");
    put(join(region, "persistence_domain"), "memory_controller\n");
    put(join(region, "mapping0"), "nmem2,0,268435456,0\n");
    OK(ndb_pmem_get_region_info(fd, &info) == 0);
    OK(info.domain == NDB_PMEM_DOMAIN_MEMCTRL);
    OK(info.numa_node == -1);
    OK(ndb_pmem_dirty_shutdown(fd, &count) == ENOTSUP);
  }
  {
    /* eADR, with the count directly in the memory device */
    Fixture fx(base, "eadr", st.st_dev,
               "ndbus3/region3/namespace3.0/block/pmem3");
    const std::string region = fx.path("devices/ndbus3/region3");
    put(join(region, "persistence_domain"), "cpu_cache\n");
    put(join(region, "mapping0"), "nmem3,0,1073741824,0\n");
    put(fx.path("bus/nd/devices/nmem3/dirty_shutdown"), "5\n");
    OK(ndb_pmem_get_region_info(fd, &info) == 0);
    OK(info.domain == NDB_PMEM_DOMAIN_CPU_CACHE);
    OK(ndb_pmem_dirty_shutdown(fd, &count) == 0 && count == 5);
  }
  {
    /* No block device, as on tmpfs */
    Fixture fx(base, "none", st.st_dev, "");
    OK(ndb_pmem_get_region_info(fd, &info) == 0);
    OK(info.domain == NDB_PMEM_DOMAIN_UNKNOWN);
    OK(info.device[0] == 0);
    OK(ndb_pmem_numa_node(fd, nullptr) == -1);
    OK(ndb_pmem_dirty_shutdown(fd, &count) == ENOTSUP);
    OK(ndb_pmem_badblocks_overlap(fd, 0, 1 << 20, &n, &exact) == 0);
    OK(n == 0 && !exact);
  }
  {
    /* A block device that is not on a region, as NVMe */
    Fixture fx(base, "nvme", st.st_dev,
               "pci0000:00/0000:00:01.0/nvme/nvme0/nvme0n1");
    OK(ndb_pmem_get_region_info(fd, &info) == 0);
    OK(info.domain == NDB_PMEM_DOMAIN_UNKNOWN);
    OK(strcmp(info.device, "nvme0n1") == 0);
    OK(info.region[0] == 0);
  }
  {
    /* A partition: the bad blocks are listed on the disk */
    Fixture fx(base, "partition", st.st_dev,
               "ndbus4/region4/namespace4.0/block/pmem4/pmem4p1");
    const std::string region = fx.path("devices/ndbus4/region4");
    put(join(region, "persistence_domain"), "memory_controller\n");
    put(join(region, "namespace4.0/block/pmem4/badblocks"), "16 8\n");
    put(join(region, "namespace4.0/block/pmem4/pmem4p1/partition"), "1\n");
    put(join(region, "namespace4.0/block/pmem4/pmem4p1/start"), "2048\n");
    OK(ndb_pmem_get_region_info(fd, &info) == 0);
    OK(info.domain == NDB_PMEM_DOMAIN_MEMCTRL);
    OK(strcmp(info.device, "pmem4p1") == 0);
    OK(info.badblock_ranges == 1);
    OK(!info.stacked);
  }
  {
    /* Device mapper on two regions: the weakest domain, no single node */
    Fixture fx(base, "dm", st.st_dev, "virtual/block/dm-0");
    const std::string r5 = fx.path("devices/ndbus5/region5");
    const std::string r6 = fx.path("devices/ndbus6/region6");
    put(join(r5, "persistence_domain"), "memory_controller\n");
    put(join(r5, "numa_node"), "0\n");
    put(join(r5, "namespace5.0/block/pmem5/badblocks"), "8 8\n");
    put(join(r6, "persistence_domain"), "\n");
    put(join(r6, "numa_node"), "1\n");
    OK(make_dirs(join(r6, "namespace6.0/block/pmem6")));
    link_to(join(r5, "namespace5.0/block/pmem5"),
            fx.path("devices/virtual/block/dm-0/slaves/pmem5"));
    link_to(join(r6, "namespace6.0/block/pmem6"),
            fx.path("devices/virtual/block/dm-0/slaves/pmem6"));
    OK(ndb_pmem_get_region_info(fd, &info) == 0);
    OK(info.stacked);
    OK(strcmp(info.device, "dm-0") == 0);
    OK(info.domain == NDB_PMEM_DOMAIN_NONE);
    OK(info.numa_node == -1);
    OK(info.badblock_ranges == 1);
    OK(ndb_pmem_badblocks_overlap(fd, 0, 1 << 20, &n, &exact) == 0);
    OK(n == 1 && !exact);
  }

  ndb_pmem_set_sysfs_root(nullptr);
  close(fd);
  remove_tree(base);
}

const char *domain_name(ndb_pmem_domain d) {
  switch (d) {
    case NDB_PMEM_DOMAIN_UNKNOWN:
      return "unknown";
    case NDB_PMEM_DOMAIN_NONE:
      return "none";
    case NDB_PMEM_DOMAIN_MEMCTRL:
      return "memory_controller";
    case NDB_PMEM_DOMAIN_CPU_CACHE:
      return "cpu_cache";
  }
  return "?";
}

/* The real sysfs, for a file in dir; on a DAX mount a region must be found */
void test_real(const char *dir, bool dax) {
  char path[1024];
  snprintf(path, sizeof(path), "%s/ndb_pmem_region-t.XXXXXX", dir);
  const int fd = mkstemp(path);
  OK(fd >= 0);
  ndb_pmem_region_info info;
  OK(ndb_pmem_get_region_info(fd, &info) == 0);
  Uint32 n;
  bool exact;
  OK(ndb_pmem_badblocks_overlap(fd, 0, 4096, &n, &exact) == 0);
  printf("ndb_pmem_region: %s: device '%s', domain %s, numa node %d, "
         "target node %d, dirty shutdown %lld, bad ranges %u (%u here, %s), "
         "%sstacked, DAX inode %s, region '%s'\n",
         dir, info.device, domain_name(info.domain), info.numa_node,
         info.target_node,
         info.dirty_shutdown == ~Uint64(0) ? -1LL
                                           : (long long)info.dirty_shutdown,
         info.badblock_ranges, n, exact ? "exact" : "not exact",
         info.stacked ? "" : "not ", info.dax_inode ? "yes" : "no",
         info.region);
  if (dax) {
    OK(info.domain != NDB_PMEM_DOMAIN_UNKNOWN);
    OK(info.dax_inode);
  }
  close(fd);
  unlink(path);
}

#endif

}  // namespace

TAPTEST(ndb_pmem_region) {
  test_parsing();
#ifndef _WIN32
  const char *tmp = getenv("TMPDIR");
  if (tmp == nullptr || *tmp == 0) tmp = "/tmp";
  test_fixtures(tmp);
  test_real(tmp, false);
  const char *dax_dir = getenv("NDB_PMEM_DIR");
  if (dax_dir != nullptr && *dax_dir != 0) {
    test_real(dax_dir, true);
  } else {
    printf("ndb_pmem_region: set NDB_PMEM_DIR to a DAX directory to test "
           "a real region\n");
  }
#endif
  return 1;
}

#endif
