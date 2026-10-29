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
#include <string.h>

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

#ifdef TEST_REDOLOGPATHS

#include <NdbTap.hpp>

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
  return 1;
}

#endif
