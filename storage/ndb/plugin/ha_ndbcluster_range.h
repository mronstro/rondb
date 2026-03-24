/*
   Copyright (c) 2026, 2026, Hopsworks and/or its affiliates.

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

#ifndef HA_NDBCLUSTER_RANGE_H
#define HA_NDBCLUSTER_RANGE_H

#include "sql/partition_info.h"
#include "my_base.h"

/**
  Extract range boundary values from partition_info into an int32 array.
  Handles both RANGE COLUMNS (range_col_array) and RANGE(expr)
  (range_int_array) formats.

  @param part_info  Partition info from MySQL TABLE or altered_table
  @param[out] range_data  Output array, must have space for @p parts elements
  @param parts  Number of partitions

  @return 0 on success, non-zero on error (my_error already called)
*/
int ndb_extract_range_boundaries(const partition_info *part_info,
                                 int32 *range_data, uint parts);

#endif  // HA_NDBCLUSTER_RANGE_H
