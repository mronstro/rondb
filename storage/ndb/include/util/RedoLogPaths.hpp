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
#ifndef REDO_LOG_PATHS_HPP
#define REDO_LOG_PATHS_HPP

#include <ndb_types.h>
#include <util/BaseString.hpp>

/**
 * FileSystemPathRedoLog: where the REDO log files go with
 * RedoLogMode=pmem (pmem_redo_design.md E20). Either one path for every
 * log part:
 *   /mnt/pmem0
 * or one path per NUMA node, a log part taking the path of the node its
 * LDM thread runs on:
 *   0:/mnt/pmem0,1:/mnt/pmem1
 * Node ids are decimal and unique, paths are absolute and hold no ','.
 * Blanks around an entry and around the ':' are ignored. At most
 * NDB_MAX_REDO_LOG_PATHS entries. Used by the management server and the
 * data node.
 */
static constexpr Uint32 NDB_MAX_REDO_LOG_PATHS = 8;
static constexpr Uint32 NDB_MAX_REDO_LOG_NUMA_NODE = 1023;

struct RedoLogPaths {
  struct Entry {
    Int32 numa_node = -1;  // -1: the one path, for every node
    BaseString path;
  };
  Uint32 count = 0;
  Entry entry[NDB_MAX_REDO_LOG_PATHS];

  /* 0, or -1 with the reason in err; count is 0 after a failure */
  int parse(const char *spec, BaseString &err);

  /**
   * The entry for numa_node, else entry 0; *found, if given, tells
   * which. The one path matches every node. 0 if count is 0.
   */
  Uint32 index_for_node(int numa_node, bool *found = nullptr) const;
};

#endif
