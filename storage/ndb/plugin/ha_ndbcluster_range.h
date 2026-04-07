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
#include "sql/field.h"
#include "my_base.h"
#include "storage/ndb/include/ndbapi/NdbDictionary.hpp"

/**
  Determine the NDB boundary type constant from a MySQL partition key field.
  Maps MySQL field types and signedness to NDB_TYPE_* constants.

  @param field  The partition key column (from part_info->part_field_array[0])
  @return NDB_TYPE_* constant (e.g. NDB_TYPE_INT, NDB_TYPE_BIGINT, etc.)
*/
Uint32 ndb_get_range_boundary_type(const Field *field);

/**
  Get the byte length of a range boundary for a given NDB type.
  @param ndb_type  NDB_TYPE_* constant
  @return 4 for 32-bit types, 8 for 64-bit types
*/
Uint32 ndb_get_range_boundary_len(Uint32 ndb_type);

/**
  Extract range boundary values from partition_info into an int32 array.
  Handles both RANGE COLUMNS (range_col_array) and RANGE(expr)
  (range_int_array) formats.  Only supports boundaries that fit in Int32.

  @param part_info  Partition info from MySQL TABLE or altered_table
  @param[out] range_data  Output array, must have space for @p parts elements
  @param parts  Number of partitions

  @return 0 on success, non-zero on error (my_error already called)
*/
int ndb_extract_range_boundaries(const partition_info *part_info,
                                 int32 *range_data, uint parts);

/**
  Extract range boundary values in native width (4 or 8 bytes per boundary).
  For RANGE COLUMNS partitioning with native RangePartition type.

  @param part_info       Partition info
  @param boundary_type   NDB_TYPE_* constant for the partition key column
  @param boundary_len    Byte length per boundary (4 or 8)
  @param[out] range_data Output buffer, must have space for parts * boundary_len bytes
  @param parts           Number of partitions

  @return 0 on success, non-zero on error (my_error already called)
*/
int ndb_extract_range_boundaries_native(const partition_info *part_info,
                                        Uint32 boundary_type,
                                        Uint32 boundary_len,
                                        char *range_data,
                                        uint parts);

/**
  Extract range boundaries from partition_info and apply them to an
  NdbDictionary::Table.  Used during ALTER TABLE ADD/DROP PARTITION
  to update the range map on the altered table definition.

  @param part_info   Partition info from altered_table
  @param tab         NdbDictionary::Table to update (setRangeListData +
                     setRangeBoundaryType)
  @param old_tab     Original table (boundary type is preserved from here)

  @return 0 on success, non-zero on error (my_error already called)
*/
int ndb_set_range_boundaries(const partition_info *part_info,
                             NdbDictionary::Table &tab,
                             const NdbDictionary::Table *old_tab);

#endif  // HA_NDBCLUSTER_RANGE_H
