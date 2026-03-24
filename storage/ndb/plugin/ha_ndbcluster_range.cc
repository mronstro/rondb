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

#include "my_byteorder.h"
#include "mysqld_error.h"
#include "sql/item.h"

int ndb_extract_range_boundaries(const partition_info *part_info,
                                 int32 *range_data, uint parts) {
  if (part_info->column_list) {
    /* RANGE COLUMNS — use range_col_array */
    const uint cols = part_info->num_part_fields;
    for (uint i = 0; i < parts; i++) {
      const part_column_list_val &col_val =
          part_info->range_col_array[i * cols];
      if (col_val.max_value) {
        range_data[i] = INT_MAX32;
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
    /* RANGE(expr) — use range_int_array */
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
