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
#include <util/RedoLogPaths.hpp>

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <mgmapi_config_parameters.h>

namespace {

bool is_absolute(const char *path) {
#ifdef _WIN32
  if (isalpha((unsigned char)path[0]) && path[1] == ':' &&
      (path[2] == '\\' || path[2] == '/'))
    return true;
  return path[0] == '\\' && path[1] == '\\';
#else
  return path[0] == '/';
#endif
}

void trim(const char *&b, const char *&e) {
  while (b < e && isspace((unsigned char)*b)) b++;
  while (e > b && isspace((unsigned char)e[-1])) e--;
}

}  // namespace

int RedoLogPaths::parse(const char *spec, BaseString &err) {
  count = 0;
  if (spec == nullptr) {
    err.assign("no value");
    return -1;
  }
  Uint32 n = 0;
  const char *p = spec;
  for (;;) {
    const char *end = strchr(p, ',');
    if (end == nullptr) end = p + strlen(p);
    const char *b = p;
    const char *e = end;
    trim(b, e);
    if (b == e) {
      err.assfmt("entry %u is empty", n + 1);
      return -1;
    }
    if (n == NDB_MAX_REDO_LOG_PATHS) {
      err.assfmt("more than %u entries", NDB_MAX_REDO_LOG_PATHS);
      return -1;
    }
    /* A NUMA node is digits and ':' before the path */
    Int32 node = -1;
    const char *d = b;
    while (d < e && isdigit((unsigned char)*d)) d++;
    const char *colon = d;
    while (colon < e && isspace((unsigned char)*colon)) colon++;
    if (d > b && colon < e && *colon == ':') {
      Uint32 value = 0;
      for (const char *c = b; c < d; c++) {
        value = value * 10 + Uint32(*c - '0');
        if (value > NDB_MAX_REDO_LOG_NUMA_NODE) {
          err.assfmt("NUMA node '%.*s' is above %u", int(d - b), b,
                     NDB_MAX_REDO_LOG_NUMA_NODE);
          return -1;
        }
      }
      node = Int32(value);
      b = colon + 1;
      trim(b, e);
      if (b == e) {
        err.assfmt("NUMA node %d has no path", node);
        return -1;
      }
    }
    BaseString path(b, size_t(e - b));
    if (!is_absolute(path.c_str())) {
      err.assfmt("path '%s' is not absolute", path.c_str());
      return -1;
    }
    entry[n].numa_node = node;
    entry[n].path = path;
    n++;
    if (*end == '\0') break;
    p = end + 1;
  }
  for (Uint32 i = 0; i < n; i++) {
    if (n > 1 && entry[i].numa_node == -1) {
      err.assfmt("path '%s' has no NUMA node, needed with several paths",
                 entry[i].path.c_str());
      return -1;
    }
    for (Uint32 j = 0; j < i; j++) {
      if (entry[j].numa_node == entry[i].numa_node) {
        err.assfmt("NUMA node %d is given twice", entry[i].numa_node);
        return -1;
      }
    }
  }
  count = n;
  return 0;
}

Uint32 RedoLogPaths::index_for_node(int numa_node, bool *found) const {
  for (Uint32 i = 0; i < count; i++) {
    if (entry[i].numa_node == -1 || entry[i].numa_node == numa_node) {
      if (found != nullptr) *found = true;
      return i;
    }
  }
  if (found != nullptr) *found = false;
  return 0;
}

namespace {

const char *domain_name(ndb_pmem_domain domain) {
  switch (domain) {
    case NDB_PMEM_DOMAIN_NONE:
      return "none";
    case NDB_PMEM_DOMAIN_MEMCTRL:
      return "memory_controller";
    case NDB_PMEM_DOMAIN_CPU_CACHE:
      return "cpu_cache";
    default:
      return "unknown";
  }
}

void add_warning(RedoPmemVerdict *v, const BaseString &warning) {
  if (v->warning_count < RedoPmemVerdict::MAX_WARNINGS) {
    v->warning[v->warning_count++] = warning;
  }
}

}  // namespace

void redo_pmem_path_verdict(const char *what, const RedoPmemProbe &probe,
                            Uint32 test_mode, RedoPmemVerdict *v) {
  *v = RedoPmemVerdict();
  if (test_mode == NDB_REDO_PMEM_TEST_MODE_NODAX) {
    v->info.assfmt("%s: not checked with __RedoLogPmemTestMode=nodax", what);
    return;
  }
  if (probe.map_err == EOPNOTSUPP) {
    v->refused = true;
    v->refusal.assfmt(
        "%s is not on a DAX file system (mmap MAP_SYNC: %s); "
        "__RedoLogPmemTestMode=nodax runs without persistent memory",
        what, strerror(probe.map_err));
    return;
  }
  if (probe.map_err != 0) {
    v->refused = true;
    v->refusal.assfmt("%s: a file there cannot be mapped (%s)", what,
                      strerror(probe.map_err));
    return;
  }
  const ndb_pmem_region_info &r = probe.region;
  const char *device = r.device[0] != 0 ? r.device : "not found";
  const char *region = r.region[0] != 0 ? r.region : "not found";
  const ndb_pmem_domain domain =
      probe.region_err == 0 ? r.domain : NDB_PMEM_DOMAIN_UNKNOWN;
  if (domain == NDB_PMEM_DOMAIN_UNKNOWN) {
    v->refused = true;
    v->refusal.assfmt(
        "%s is on a DAX file system, but no persistent memory region was "
        "found behind it (device %s, region %s%s%s), so its persistence "
        "domain is not known",
        what, device, region, probe.region_err != 0 ? ", " : "",
        probe.region_err != 0 ? strerror(probe.region_err) : "");
    return;
  }
  if (domain == NDB_PMEM_DOMAIN_NONE) {
    if (test_mode != NDB_REDO_PMEM_TEST_MODE_EMULATED) {
      v->refused = true;
      v->refusal.assfmt(
          "%s: region %s reports no persistence domain (memmap= emulation?), "
          "a REDO log there is lost at a power failure; "
          "__RedoLogPmemTestMode=emulated accepts it for tests",
          what, region);
      return;
    }
    BaseString w;
    w.assfmt(
        "%s: region %s reports no persistence domain, accepted with "
        "__RedoLogPmemTestMode=emulated; the REDO log there is lost at a "
        "power failure",
        what, region);
    add_warning(v, w);
  }
  if (r.badblock_ranges > 0) {
    BaseString w;
    w.assfmt(
        "%s: device %s has %u bad-block ranges; a REDO log file on one of "
        "them is refused when it is opened (clear them with ndctl "
        "clear-errors)",
        what, device, r.badblock_ranges);
    add_warning(v, w);
  }
  char dirty[24] = "not exposed";
  if (r.dirty_shutdown != ~Uint64(0)) {
    BaseString::snprintf(dirty, sizeof(dirty), "%llu",
                         (unsigned long long)r.dirty_shutdown);
  }
  v->info.assfmt(
      "%s: device %s%s, region %s, persistence domain %s, NUMA node %d, "
      "dirty-shutdown count %s, %u bad-block ranges",
      what, device, r.stacked ? " (stacked)" : "", region, domain_name(domain),
      r.numa_node, dirty, r.badblock_ranges);
}

#ifdef TEST_REDOLOGPATHS

#include <NdbTap.hpp>
#include <initializer_list>

namespace {

bool parses(const char *spec, RedoLogPaths &paths) {
  BaseString err;
  const int r = paths.parse(spec, err);
  printf("'%s': %s\n", spec, r == 0 ? "ok" : err.c_str());
  return r == 0;
}

bool fails(const char *spec) {
  RedoLogPaths paths;
  BaseString err;
  const char *shown = spec != nullptr ? spec : "(null)";
  if (paths.parse(spec, err) == 0) {
    printf("'%s': accepted, should fail\n", shown);
    return false;
  }
  printf("'%s': %s\n", shown, err.c_str());
  return paths.count == 0 && err.length() > 0;
}

const char *mode_name(Uint32 test_mode) {
  static const char *const name[] = {"off", "emulated", "nodax"};
  return test_mode < 3 ? name[test_mode] : "?";
}

/* The verdict, printed; true if refused */
bool refused(const RedoPmemProbe &probe, Uint32 test_mode,
             RedoPmemVerdict *v) {
  redo_pmem_path_verdict("FileSystemPathRedoLog /p", probe, test_mode, v);
  printf("verdict %s: %s\n", mode_name(test_mode),
         v->refused ? v->refusal.c_str() : v->info.c_str());
  for (Uint32 i = 0; i < v->warning_count; i++) {
    printf("  warning: %s\n", v->warning[i].c_str());
  }
  return v->refused;
}

RedoPmemProbe probe_of(ndb_pmem_domain domain) {
  RedoPmemProbe p;
  p.region.domain = domain;
  p.region.numa_node = 1;
  p.region.target_node = 1;
  p.region.dirty_shutdown = 3;
  strcpy(p.region.device, "pmem0");
  strcpy(p.region.region, "/sys/devices/ndbus0/region0");
  return p;
}

bool has(const BaseString &s, const char *text) {
  return strstr(s.c_str(), text) != nullptr;
}

void test_verdicts() {
  const Uint32 OFF = NDB_REDO_PMEM_TEST_MODE_OFF;
  const Uint32 EMULATED = NDB_REDO_PMEM_TEST_MODE_EMULATED;
  const Uint32 NODAX = NDB_REDO_PMEM_TEST_MODE_NODAX;
  RedoPmemVerdict v;

  /* DAX on a region with ADR or eADR: accepted */
  const RedoPmemProbe adr = probe_of(NDB_PMEM_DOMAIN_MEMCTRL);
  for (Uint32 mode : {OFF, EMULATED, NODAX}) {
    OK(!refused(adr, mode, &v) && v.warning_count == 0);
  }
  OK(refused(adr, OFF, &v) == false);
  OK(has(v.info, "memory_controller") && has(v.info, "count 3") &&
     has(v.info, "pmem0") && has(v.info, "NUMA node 1"));
  OK(!refused(probe_of(NDB_PMEM_DOMAIN_CPU_CACHE), OFF, &v));
  OK(has(v.info, "cpu_cache"));

  /* No DAX: refused, except with nodax */
  RedoPmemProbe no_dax;
  no_dax.map_err = EOPNOTSUPP;
  OK(refused(no_dax, OFF, &v) && has(v.refusal, "not on a DAX file system"));
  OK(has(v.refusal, "FileSystemPathRedoLog /p"));
  OK(refused(no_dax, EMULATED, &v));
  OK(!refused(no_dax, NODAX, &v));
  RedoPmemProbe no_map;
  no_map.map_err = EACCES;
  OK(refused(no_map, OFF, &v) && has(v.refusal, "cannot be mapped"));

  /* memmap=: no persistence domain, accepted with emulated only */
  RedoPmemProbe memmap = probe_of(NDB_PMEM_DOMAIN_NONE);
  memmap.region.dirty_shutdown = ~Uint64(0);
  OK(refused(memmap, OFF, &v) && has(v.refusal, "no persistence domain"));
  OK(!refused(memmap, EMULATED, &v) && v.warning_count == 1);
  OK(has(v.warning[0], "no persistence domain"));
  OK(has(v.info, "persistence domain none") && has(v.info, "not exposed"));

  /* No region found, or not read: refused, except with nodax */
  const RedoPmemProbe unknown = probe_of(NDB_PMEM_DOMAIN_UNKNOWN);
  OK(refused(unknown, OFF, &v) && has(v.refusal, "not known"));
  OK(refused(unknown, EMULATED, &v));
  OK(!refused(unknown, NODAX, &v));
  RedoPmemProbe unread = adr;
  unread.region_err = ENOENT;
  OK(refused(unread, OFF, &v) && has(v.refusal, strerror(ENOENT)));

  /* Bad blocks on the device: a warning */
  RedoPmemProbe bad = probe_of(NDB_PMEM_DOMAIN_CPU_CACHE);
  bad.region.badblock_ranges = 2;
  OK(!refused(bad, OFF, &v) && v.warning_count == 1);
  OK(has(v.warning[0], "2 bad-block ranges"));
  memmap.region.badblock_ranges = 1;
  OK(!refused(memmap, EMULATED, &v) && v.warning_count == 2);
}

}  // namespace

TAPTEST(RedoLogPaths) {
  RedoLogPaths paths;
  bool found;

  /* One path for every node */
  OK(parses("/mnt/pmem0", paths));
  OK(paths.count == 1);
  OK(paths.entry[0].numa_node == -1);
  OK(strcmp(paths.entry[0].path.c_str(), "/mnt/pmem0") == 0);
  OK(paths.index_for_node(0, &found) == 0 && found);
  OK(paths.index_for_node(3, &found) == 0 && found);
  OK(paths.index_for_node(-1, &found) == 0 && found);

  OK(parses("  /mnt/pmem 0/redo  ", paths));
  OK(strcmp(paths.entry[0].path.c_str(), "/mnt/pmem 0/redo") == 0);
  OK(parses("/mnt/a:b", paths));
  OK(paths.entry[0].numa_node == -1);
  OK(strcmp(paths.entry[0].path.c_str(), "/mnt/a:b") == 0);

  /* One path per node */
  OK(parses("0:/mnt/pmem0,1:/mnt/pmem1", paths));
  OK(paths.count == 2);
  OK(paths.entry[0].numa_node == 0 && paths.entry[1].numa_node == 1);
  OK(strcmp(paths.entry[1].path.c_str(), "/mnt/pmem1") == 0);
  OK(paths.index_for_node(1, &found) == 1 && found);
  OK(paths.index_for_node(0, &found) == 0 && found);
  OK(paths.index_for_node(2, &found) == 0 && !found);
  OK(paths.index_for_node(-1, &found) == 0 && !found);
  OK(paths.index_for_node(1) == 1);

  OK(parses("3:/mnt/pmem3", paths));
  OK(paths.count == 1 && paths.entry[0].numa_node == 3);
  OK(paths.index_for_node(3, &found) == 0 && found);
  OK(paths.index_for_node(0, &found) == 0 && !found);

  OK(parses(" 1 : /p1 , 0:/p0:x ", paths));
  OK(paths.count == 2);
  OK(paths.entry[0].numa_node == 1);
  OK(strcmp(paths.entry[0].path.c_str(), "/p1") == 0);
  OK(strcmp(paths.entry[1].path.c_str(), "/p0:x") == 0);

  OK(parses("0:/a,1:/b,2:/c,3:/d,4:/e,5:/f,6:/g,7:/h", paths));
  OK(paths.count == NDB_MAX_REDO_LOG_PATHS);
  OK(paths.index_for_node(7) == 7);
  OK(parses("1023:/mnt/pmem", paths));

  /* Refused */
  OK(fails(nullptr));
  OK(fails(""));
  OK(fails("   "));
  OK(fails("mnt/pmem0"));
  OK(fails("0:mnt/pmem0"));
  OK(fails("/a,/b"));
  OK(fails("0:/a,/b"));
  OK(fails("0:/a,0:/b"));
  OK(fails("0:/a,1:/b,"));
  OK(fails(",0:/a"));
  OK(fails("0:/a,,1:/b"));
  OK(fails("0:"));
  OK(fails("0: "));
  OK(fails("1024:/a"));
  OK(fails("99999999999:/a"));
  OK(fails("-1:/a"));
  OK(fails("x:/a"));
  OK(fails("1 /a"));
  OK(fails("0:/a,1:/b,2:/c,3:/d,4:/e,5:/f,6:/g,7:/h,8:/i"));

  /* A failure leaves no entries */
  OK(parses("0:/a,1:/b", paths));
  BaseString err;
  OK(paths.parse("0:/a,0:/b", err) != 0);
  OK(paths.count == 0);
  OK(paths.index_for_node(0, &found) == 0 && !found);

  test_verdicts();
  return 1;
}

#endif
