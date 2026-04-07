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

#include "storage/ndb/plugin/ha_ndbcluster_range.h"

#include <memory>

#include "my_byteorder.h"
#include "mysqld_error.h"
#include "sql/item.h"
#include "ndb_constants.h"

Uint32 ndb_get_range_boundary_type(const Field *field) {
  bool is_unsigned = field->is_flag_set(UNSIGNED_FLAG);
  switch (field->real_type()) {
    case MYSQL_TYPE_TINY:
      return is_unsigned ? NDB_TYPE_TINYUNSIGNED : NDB_TYPE_TINYINT;
    case MYSQL_TYPE_SHORT:
      return is_unsigned ? NDB_TYPE_SMALLUNSIGNED : NDB_TYPE_SMALLINT;
    case MYSQL_TYPE_INT24:
      return is_unsigned ? NDB_TYPE_MEDIUMUNSIGNED : NDB_TYPE_MEDIUMINT;
    case MYSQL_TYPE_LONG:
      return is_unsigned ? NDB_TYPE_UNSIGNED : NDB_TYPE_INT;
    case MYSQL_TYPE_LONGLONG:
      return is_unsigned ? NDB_TYPE_BIGUNSIGNED : NDB_TYPE_BIGINT;
    default:
      /* Unsupported type — fall back to INT. Caller should reject. */
      return NDB_TYPE_INT;
  }
}

Uint32 ndb_get_range_boundary_len(Uint32 ndb_type) {
  switch (ndb_type) {
    case NDB_TYPE_BIGINT:
    case NDB_TYPE_BIGUNSIGNED:
      return 8;
    default:
      return 4;
  }
}

int ndb_extract_range_boundaries_native(const partition_info *part_info,
                                        Uint32 boundary_type,
                                        Uint32 boundary_len,
                                        char *range_data,
                                        uint parts) {
  if (!part_info->column_list) {
    /* RANGE(expr) — not supported for native boundaries, use Int32 path */
    my_error(ER_INTERNAL_ERROR, MYF(0),
             "Native range boundaries require RANGE COLUMNS");
    return 1;
  }

  const uint cols = part_info->num_part_fields;
  for (uint i = 0; i < parts; i++) {
    const part_column_list_val &col_val =
        part_info->range_col_array[i * cols];
    if (col_val.max_value) {
      my_error(ER_LIMITED_PART_RANGE, MYF(0), "NDB");
      return 1;
    }
    if (col_val.item_expression == nullptr) {
      my_error(ER_INTERNAL_ERROR, MYF(0),
               "RANGE COLUMNS: no boundary value");
      return 1;
    }

    longlong val = col_val.item_expression->val_int();

    if (boundary_len == 8) {
      /* 8-byte boundary: BIGINT or BIGUNSIGNED */
      if (boundary_type == NDB_TYPE_BIGUNSIGNED) {
        /* For unsigned, val_int() returns the bit pattern as longlong.
         * Cast to Uint64 preserves the unsigned semantics. */
        Uint64 uval = static_cast<Uint64>(val);
        memcpy(range_data + i * 8, &uval, sizeof(Uint64));
      } else {
        /* BIGINT (signed) — val is already Int64 */
        Int64 sval = static_cast<Int64>(val);
        memcpy(range_data + i * 8, &sval, sizeof(Int64));
      }
    } else {
      /* 4-byte boundary: INT, UNSIGNED, SMALLINT, etc. */
      if (boundary_type == NDB_TYPE_UNSIGNED ||
          boundary_type == NDB_TYPE_SMALLUNSIGNED ||
          boundary_type == NDB_TYPE_MEDIUMUNSIGNED ||
          boundary_type == NDB_TYPE_TINYUNSIGNED) {
        if (val < 0 || val > UINT_MAX32) {
          my_error(ER_LIMITED_PART_RANGE, MYF(0), "NDB");
          return 1;
        }
        Uint32 uval = static_cast<Uint32>(val);
        memcpy(range_data + i * 4, &uval, sizeof(Uint32));
      } else {
        /* Signed 4-byte types */
        if (val < INT_MIN32 || val > INT_MAX32) {
          my_error(ER_LIMITED_PART_RANGE, MYF(0), "NDB");
          return 1;
        }
        Int32 sval = static_cast<Int32>(val);
        memcpy(range_data + i * 4, &sval, sizeof(Int32));
      }
    }
  }
  return 0;
}

int ndb_extract_range_boundaries(const partition_info *part_info,
                                 int32 *range_data, uint parts) {
  if (part_info->column_list) {
    /* RANGE COLUMNS — use range_col_array */
    const uint cols = part_info->num_part_fields;
    for (uint i = 0; i < parts; i++) {
      const part_column_list_val &col_val =
          part_info->range_col_array[i * cols];
      if (col_val.max_value) {
        my_error(ER_LIMITED_PART_RANGE, MYF(0), "NDB");
        return 1;
      } else if (col_val.item_expression != nullptr) {
        longlong val = col_val.item_expression->val_int();
        if (val < INT_MIN32 || val > INT_MAX32) {
          my_error(ER_LIMITED_PART_RANGE, MYF(0), "NDB");
          return 1;
        }
        range_data[i] = static_cast<int32>(val);
      } else {
        my_error(ER_INTERNAL_ERROR, MYF(0),
                 "RANGE COLUMNS: no boundary value");
        return 1;
      }
    }
  } else {
    /* RANGE(expr) — use range_int_array.
     * Old-style partitioning with $PART_FUNC_VALUE shadow column;
     * MAXVALUE is allowed here since ALTER uses copy-table approach.
     */
    for (uint i = 0; i < parts; i++) {
      longlong range_val = part_info->range_int_array[i];
      if (part_info->part_expr->unsigned_flag)
        range_val -= 0x8000000000000000ULL;
      if (range_val < INT_MIN32 || range_val >= INT_MAX32) {
        if ((i != parts - 1) || (range_val != LLONG_MAX)) {
          my_error(ER_LIMITED_PART_RANGE, MYF(0), "NDB");
          return 1;
        }
        range_val = INT_MAX32;
      }
      range_data[i] = static_cast<int32>(range_val);
    }
  }
  return 0;
}

int ndb_set_range_boundaries(const partition_info *part_info,
                             NdbDictionary::Table &tab,
                             const NdbDictionary::Table *old_tab) {
  const uint parts = part_info->num_parts;
  const Uint32 btype = old_tab->getRangeBoundaryType();
  const Uint32 blen = ndb_get_range_boundary_len(btype);

  if (part_info->column_list && blen > 4) {
    /* Native 8-byte boundaries */
    const Uint32 total_bytes = parts * blen;
    std::unique_ptr<char[]> range_data(new (std::nothrow) char[total_bytes]);
    if (!range_data) {
      my_error(ER_OUTOFMEMORY, MYF(ME_FATALERROR), total_bytes);
      return 1;
    }
    if (ndb_extract_range_boundaries_native(part_info, btype, blen,
                                            range_data.get(), parts))
      return 1;
    /* Store as Int32 words (2 words per 8-byte boundary) */
    tab.setRangeListData(
        reinterpret_cast<const Int32 *>(range_data.get()),
        parts * (blen / 4));
  } else {
    /* 4-byte boundaries (or RANGE(expr) fallback) */
    std::unique_ptr<int32[]> range_data(new (std::nothrow) int32[parts]);
    if (!range_data) {
      my_error(ER_OUTOFMEMORY, MYF(ME_FATALERROR), parts * sizeof(int32));
      return 1;
    }
    if (part_info->column_list) {
      if (ndb_extract_range_boundaries_native(part_info, btype, blen,
                                              reinterpret_cast<char *>(range_data.get()),
                                              parts))
        return 1;
    } else {
      if (ndb_extract_range_boundaries(part_info, range_data.get(), parts))
        return 1;
    }
    tab.setRangeListData(range_data.get(), parts);
  }
  tab.setRangeBoundaryType(btype);
  return 0;
}
