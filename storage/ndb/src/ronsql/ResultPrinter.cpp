/*
   Copyright (c) 2024, 2024, Hopsworks and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

#include <iomanip>
#include "m_string.h"
#include "ResultPrinter.hpp"
#include "define_formatter.hpp"
#include "RonSQLPreparer.hpp"
#include "mysql/strings/dtoa.h"

using std::endl;
using std::max;
using std::runtime_error;

#define feature_not_implemented(description) \
  throw runtime_error("RonSQL feature not implemented: " description)

DEFINE_FORMATTER(quoted_identifier, LexCString, {
  os.put('`');
  for (Uint32 i = 0; i < value.len; i++)
  {
    char ch = value.str[i];
    if (ch == '`')
      os.write("``", 2);
    else
      os.put(ch);
  }
  os.put('`');
})

static void print_json_string_from_utf8(std::ostream& output_stream, LexString ls, bool utf8_output);
static void print_float_or_double(std::ostream& out, double value, bool is_double, bool json_output, bool tsv_output);
static double convert_result_to_double(NdbAggregator::Result result);
static float convert_result_to_float(NdbAggregator::Result result);

ResultPrinter::ResultPrinter(ArenaMalloc* amalloc,
                             struct SelectStatement* query,
                             DynamicArray<LexCString>* column_names,
                             RonSQLExecParams::OutputFormat output_format,
                             std::basic_ostream<char>* err):
  m_amalloc(amalloc),
  m_query(query),
  m_column_names(column_names),
  m_output_format(output_format),
  m_err(err),
  m_program(amalloc),
  m_groupby_cols(amalloc),
  m_outputs(amalloc),
  m_col_idx_groupby_map(amalloc)
{
  assert(query != NULL);
  assert(amalloc != NULL);
  switch (output_format)
  {
  case RonSQLExecParams::OutputFormat::JSON:
    break;
  case RonSQLExecParams::OutputFormat::JSON_ASCII:
    break;
  case RonSQLExecParams::OutputFormat::TEXT:
    break;
  case RonSQLExecParams::OutputFormat::TEXT_NOHEADER:
    break;
  default:
    abort();
  }
  assert(err != NULL);
  compile();
  optimize();
}

void
ResultPrinter::compile()
{
  std::basic_ostream<char>& err = *m_err;
  DynamicArray<LexCString>& column_names = *m_column_names;
  // Populate m_groupby_columns, an array of the column idxs listed in GROUP BY.
  {
    struct GroupbyColumns* g = m_query->groupby_columns;
    while(g != NULL)
    {
      m_groupby_cols.push(g->col_idx);
      g = g->next;
    }
  }
  // Populate and validate m_outputs, an array of the SELECT expressions.
  // Calculate number_of_aggregates.
  // Populate m_col_idx_groupby_map.
  Uint32 number_of_aggregates = 0;
  {
    struct Outputs* o = m_query->outputs;
    while(o != NULL)
    {
      m_outputs.push(o);
      switch (o->type)
      {
      case Outputs::Type::COLUMN:
        for (Uint32 i = 0; ; i++)
        {
          // Validate that the column appears in the GROUP BY clause
          Uint32 col_idx = o->column.col_idx;
          if (i >= m_groupby_cols.size())
          {
            assert(m_column_names->size() > col_idx);
            err << "Syntax error: SELECT expression refers to ungrouped column "
                << quoted_identifier(column_names[col_idx])
                << " outside of aggregate function." << endl
                << "You can either add this column to the GROUP BY clause, "
                << "or use it within an aggregate function e.g. Sum("
                << quoted_identifier(column_names[col_idx])
                << ")." << endl;
            throw runtime_error("Ungrouped column in non-aggregated SELECT expression.");
            // todo Test for aggregates without groups and groups without aggregates.
          }
          if (m_groupby_cols[i] == col_idx)
          {
            while (m_col_idx_groupby_map.size() < col_idx + 1)
            {
              m_col_idx_groupby_map.push(0);
            }
            m_col_idx_groupby_map[col_idx] = i;
            break;
          }
        }
        break;
      case Outputs::Type::AGGREGATE:
        number_of_aggregates =
          max(number_of_aggregates, o->aggregate.agg_index + 1);
        break;
      case Outputs::Type::AVG:
        number_of_aggregates =
          max(number_of_aggregates, o->avg.agg_index_sum + 1);
        number_of_aggregates =
          max(number_of_aggregates, o->avg.agg_index_count + 1);
        break;
      default:
        abort();
      }
      o = o->next;
    }
  }
  // Allocate registers. Even if some of them won't be used in an optimized
  // program, the memory waste is minimal.
  m_regs_g = m_amalloc->alloc_exc<NdbAggregator::Column>(m_groupby_cols.size());
  m_regs_a = m_amalloc->alloc_exc<NdbAggregator::Result>(number_of_aggregates);
  // Create a correct but non-optimized program
  for (Uint32 i = 0; i < m_groupby_cols.size(); i++)
  {
    Cmd cmd;
    cmd.type = Cmd::Type::STORE_GROUP_BY_COLUMN;
    cmd.store_group_by_column.group_by_idx = i;
    cmd.store_group_by_column.reg_g = i;
    m_program.push(cmd);
  }
  {
    Cmd cmd;
    cmd.type = Cmd::Type::END_OF_GROUP_BY_COLUMNS;
    m_program.push(cmd);
  }
  for (Uint32 i = 0; i < number_of_aggregates; i++)
  {
    Cmd cmd;
    cmd.type = Cmd::Type::STORE_AGGREGATE;
    cmd.store_aggregate.agg_index = i;
    cmd.store_aggregate.reg_a = i;
    m_program.push(cmd);
  }
  {
    Cmd cmd;
    cmd.type = Cmd::Type::END_OF_AGGREGATES;
    m_program.push(cmd);
  }
  switch (m_output_format)
  {
  case RonSQLExecParams::OutputFormat::TEXT:
    m_json_output = false;
    m_utf8_output = true;
    m_tsv_output = true;
    m_tsv_headers = true;
    break;
  case RonSQLExecParams::OutputFormat::TEXT_NOHEADER:
    m_json_output = false;
    m_utf8_output = true;
    m_tsv_output = true;
    m_tsv_headers = false;
    break;
  case RonSQLExecParams::OutputFormat::JSON:
    m_json_output = true;
    m_utf8_output = true;
    m_tsv_output = false;
    m_tsv_headers = false;
    break;
  case RonSQLExecParams::OutputFormat::JSON_ASCII:
    m_json_output = true;
    m_utf8_output = false;
    m_tsv_output = false;
    m_tsv_headers = false;
    break;
  default:
    abort();
  }
  for (Uint32 i = 0; i < m_outputs.size(); i++)
  {
    {
      Cmd cmd;
      cmd.type = Cmd::Type::PRINT_STR;
      bool is_first = i == 0;
      if (m_json_output)
      {
        cmd.print_str.content = LexString{ is_first ? "{" : ",", 1 };
        m_program.push(cmd);
      }
      else if (m_tsv_output && !is_first)
      {
        cmd.print_str.content = LexString{ "\t", 1 };
        m_program.push(cmd);
      }
      else if (m_tsv_output && is_first)
      {
        // The first column is not preceded by a tab.
      }
      else
      {
        abort();
      }
    }
    Outputs* o = m_outputs[i];
    if (m_json_output)
    {
      Cmd cmd;
      cmd.type = Cmd::Type::PRINT_STR_JSON;
      cmd.print_str.content = o->output_name;
      m_program.push(cmd);
    }
    if (m_json_output)
    {
      Cmd cmd;
      cmd.type = Cmd::Type::PRINT_STR;
      cmd.print_str.content = LexString{ ":", 1 };
      m_program.push(cmd);
    }
    switch (o->type) {
      case Outputs::Type::COLUMN:
      {
        // todo indent case, move break inside braces. (This todo from review 2024-08-22 with MR)
        Cmd cmd;
        cmd.type = Cmd::Type::PRINT_GROUP_BY_COLUMN;
        cmd.print_group_by_column.reg_g = m_col_idx_groupby_map[o->column.col_idx];
        m_program.push(cmd);
        break;
      }
      case Outputs::Type::AGGREGATE:
      {
        Cmd cmd;
        cmd.type = Cmd::Type::PRINT_AGGREGATE;
        cmd.print_aggregate.reg_a = o->aggregate.agg_index;
        m_program.push(cmd);
        break;
      }
      case Outputs::Type::AVG:
      {
        Cmd cmd;
        cmd.type = Cmd::Type::PRINT_AVG;
        cmd.print_avg.reg_a_sum = o->avg.agg_index_sum;
        cmd.print_avg.reg_a_count = o->avg.agg_index_count;
        m_program.push(cmd);
        break;
      }
    default:
      abort();
    }
  }
  if (m_json_output)
  {
    Cmd cmd;
    cmd.type = Cmd::Type::PRINT_STR;
    cmd.print_str.content = LexString{ "}\n", 2 };
    m_program.push(cmd);
  }
  else if (m_tsv_output)
  {
    Cmd cmd;
    cmd.type = Cmd::Type::PRINT_STR;
    cmd.print_str.content = LexString{ "\n", 1 };
    m_program.push(cmd);
  }
  else
  {
    abort();
  }
}

void
ResultPrinter::optimize()
{
  // todo
}

void
ResultPrinter::print_result(NdbAggregator* aggregator,
                            std::basic_ostream<char>* out_stream)
{
  assert(out_stream != NULL);
  std::ostream& out = *out_stream;
  if (m_json_output)
  {
    out << '[';
    bool first_record = true;
    for (NdbAggregator::ResultRecord record = aggregator->FetchResultRecord();
         !record.end();
         record = aggregator->FetchResultRecord())
    {
      if (first_record)
      {
        first_record = false;
      }
      else
      {
        out << ',';
      }
      print_record(record, out);
    }
    out << "]\n";
  }
  else if (m_tsv_output)
  {
    bool first_record = true;
    for (NdbAggregator::ResultRecord record = aggregator->FetchResultRecord();
         !record.end();
         record = aggregator->FetchResultRecord())
    {
      if (first_record && m_tsv_headers)
      {
        // Print the column names.
        bool first_column = true;
        for (Uint32 i = 0; i < m_outputs.size(); i++)
        {
          Outputs* o = m_outputs[i];
          if (first_column) first_column = false; else out << '\t';
          out << o->output_name;
        }
        out << '\n';
        first_record = false;
      }
      print_record(record, out);
    }
  }
  else
  {
    abort();
  }
  // ================================================================================
}

DEFINE_FORMATTER(d2, uint, {
  if (value < 10) os << '0';
  os << value;
})

inline void
ResultPrinter::print_record(NdbAggregator::ResultRecord& record, std::ostream& out)
{
  for (Uint32 cmd_index = 0; cmd_index < m_program.size(); cmd_index++)
  {
    Cmd& cmd = m_program[cmd_index];
    switch (cmd.type)
    {
    case Cmd::Type::STORE_GROUP_BY_COLUMN:
      {
        NdbAggregator::Column column = record.FetchGroupbyColumn();
        if (column.end())
        {
          throw std::runtime_error("Got record with fewer GROUP BY columns than expected.");
        }
        m_regs_g[cmd.store_group_by_column.reg_g] = column;
      }
      break;
    case Cmd::Type::END_OF_GROUP_BY_COLUMNS:
      {
        NdbAggregator::Column column = record.FetchGroupbyColumn();
        if (!column.end())
        {
          throw std::runtime_error("Got record with more GROUP BY columns than expected.");
        }
      }
      break;
    case Cmd::Type::STORE_AGGREGATE:
      {
        NdbAggregator::Result result = record.FetchAggregationResult();
        if (result.end())
        {
          throw std::runtime_error("Got record with fewer aggregates than expected.");
        }
        m_regs_a[cmd.store_aggregate.reg_a] = result;
      }
      break;
    case Cmd::Type::END_OF_AGGREGATES:
      {
        NdbAggregator::Result result = record.FetchAggregationResult();
        if (!result.end())
        {
          throw std::runtime_error("Got record with more aggregates than expected.");
        }
      }
      break;
    case Cmd::Type::PRINT_GROUP_BY_COLUMN:
      {
        NdbAggregator::Column column = m_regs_g[cmd.print_group_by_column.reg_g];
        if(column.is_null())
        {
          out << "NULL"; // todo Fix for JSON output format
          break;
        }
        switch (column.type())
        {
        case NdbDictionary::Column::Type::Undefined:     ///< Undefined. Since this is a result, it means SQL NULL.
          feature_not_implemented("Print GROUP BY column of type Undefined (NULL)");
        case NdbDictionary::Column::Type::Tinyint:       ///< 8 bit. 1 byte signed integer
          // Int8 is ultimately defined in terms a char, so we need to type case
          // in order to print as an integer.
          out << Int32(column.data_int8());
          break;
        case NdbDictionary::Column::Type::Tinyunsigned:  ///< 8 bit. 1 byte unsigned integer
          // Uint8 is ultimately defined in terms a char, so we need to type case
          // in order to print as an integer.
          out << Uint32(column.data_uint8());
          break;
        case NdbDictionary::Column::Type::Smallint:      ///< 16 bit. 2 byte signed integer
          out << column.data_int16();
          break;
        case NdbDictionary::Column::Type::Smallunsigned: ///< 16 bit. 2 byte unsigned integer
          out << column.data_uint16();
          break;
        case NdbDictionary::Column::Type::Mediumint:     ///< 24 bit. 3 byte signed integer
          out << column.data_medium();
          break;
        case NdbDictionary::Column::Type::Mediumunsigned:///< 24 bit. 3 byte unsigned integer
          out << column.data_umedium();
          break;
        case NdbDictionary::Column::Type::Int:           ///< 32 bit. 4 byte signed integer
          out << column.data_int32();
          break;
        case NdbDictionary::Column::Type::Unsigned:      ///< 32 bit. 4 byte unsigned integer
          out << column.data_uint32();
          break;
        case NdbDictionary::Column::Type::Bigint:        ///< 64 bit. 8 byte signed integer
          out << column.data_int64();
          break;
        case NdbDictionary::Column::Type::Bigunsigned:   ///< 64 Bit. 8 byte unsigned integer
          out << column.data_uint64();
          break;
        case NdbDictionary::Column::Type::Float:         ///< 32-bit float. 4 bytes float
          feature_not_implemented("Print GROUP BY column of type Float");
        case NdbDictionary::Column::Type::Double:        ///< 64-bit float. 8 byte float
          feature_not_implemented("Print GROUP BY column of type Double");
        case NdbDictionary::Column::Type::Olddecimal:    ///< MySQL < 5.0 signed decimal,  Precision, Scale
          feature_not_implemented("Print GROUP BY column of type Olddecimal");
        case NdbDictionary::Column::Type::Olddecimalunsigned:
          feature_not_implemented("Print GROUP BY column of type Olddecimalunsigned");
        case NdbDictionary::Column::Type::Decimal:       ///< MySQL >= 5.0 signed decimal,  Precision, Scale
          feature_not_implemented("Print GROUP BY column of type Decimal");
        case NdbDictionary::Column::Type::Decimalunsigned:
          feature_not_implemented("Print GROUP BY column of type Decimalunsigned");
        case NdbDictionary::Column::Type::Char:          ///< Len. A fixed array of 1-byte chars
          {
            LexString content = LexString{ column.data(), column.byte_size() };
            // todo it's nowadays ok to put brace on same line. (This todo from review 2024-08-22 with MR)
            while (content.len > 0 && content.str[content.len - 1] == 0x20) {
              content.len--;
            }
            if (m_json_output) {
              print_json_string_from_utf8(out,
                                          content,
                                          m_utf8_output);
            }
            else if (m_tsv_output) {
              out << content; // todo mysql-like escape
            }
            else {
              abort();
            }
            break;
          }
        case NdbDictionary::Column::Type::Varchar:       ///< Length bytes: 1, Max: 255
          {
            LexString content = LexString{ &column.data()[1],
                                           (size_t)column.data()[0] };
            if (m_json_output)
            {
              print_json_string_from_utf8(out,
                                          content,
                                          m_utf8_output);
            }
            else if (m_tsv_output)
            {
              out << content; // todo mysql-like escape
            }
            else
            {
              abort();
            }
            break;
          }
        case NdbDictionary::Column::Type::Binary:        ///< Len
          feature_not_implemented("Print GROUP BY column of type Binary");
        case NdbDictionary::Column::Type::Varbinary:     ///< Length bytes: 1, Max: 255
          feature_not_implemented("Print GROUP BY column of type Varbinary");
        case NdbDictionary::Column::Type::Datetime:      ///< Precision down to 1 sec (sizeof(Datetime) == 8 bytes )
          feature_not_implemented("Print GROUP BY column of type Datetime");
        case NdbDictionary::Column::Type::Date:          ///< Precision down to 1 day(sizeof(Date) == 4 bytes )
          {
            Uint32 date = column.data_uint32();
            Uint32 year = date >> 9;
            Uint32 month = (date >> 5) & 0xf;
            Uint32 day = date & 0x1f;
            out << year << "-" << d2(month) << "-" << d2(day);
            // todo There must be a function somewhere that does this, but I can't find it. Maybe in my_time.cc.
            break;
          }
        case NdbDictionary::Column::Type::Blob:          ///< Binary large object (see NdbBlob)
          feature_not_implemented("Print GROUP BY column of type Blob");
        case NdbDictionary::Column::Type::Text:          ///< Text blob
          feature_not_implemented("Print GROUP BY column of type Text");
        case NdbDictionary::Column::Type::Bit:           ///< Bit, length specifies no of bits
          feature_not_implemented("Print GROUP BY column of type Bit");
        case NdbDictionary::Column::Type::Longvarchar:   ///< Length bytes: 2, little-endian
          feature_not_implemented("Print GROUP BY column of type Longvarchar");
        case NdbDictionary::Column::Type::Longvarbinary: ///< Length bytes: 2, little-endian
          feature_not_implemented("Print GROUP BY column of type Longvarbinary");
        case NdbDictionary::Column::Type::Time:          ///< Time without date
          feature_not_implemented("Print GROUP BY column of type Time");
        case NdbDictionary::Column::Type::Year:          ///< Year 1901-2155 (1 byte)
          feature_not_implemented("Print GROUP BY column of type Year");
        case NdbDictionary::Column::Type::Timestamp:     ///< Unix time
          feature_not_implemented("Print GROUP BY column of type Timestamp");
        case NdbDictionary::Column::Type::Time2:         ///< 3 bytes + 0-3 fraction
          feature_not_implemented("Print GROUP BY column of type Time2");
        case NdbDictionary::Column::Type::Datetime2:     ///< 5 bytes plus 0-3 fraction
          feature_not_implemented("Print GROUP BY column of type Datetime2");
        case NdbDictionary::Column::Type::Timestamp2:    ///< 4 bytes + 0-3 fraction
          feature_not_implemented("Print GROUP BY column of type Timestamp2");
        default:
          abort(); // Unknown type
        }
      }
      break;
    case Cmd::Type::PRINT_AGGREGATE:
      {
        NdbAggregator::Result result = m_regs_a[cmd.print_aggregate.reg_a];
        if(result.is_null())
        {
          out << "NULL";
          break;
        }
        // todo conform format for sum(int) to mysql CLI
        switch (result.type())
        {
        case NdbDictionary::Column::Bigint:
          out << result.data_int64();
          break;
        case NdbDictionary::Column::Bigunsigned:
          out << result.data_uint64();
          break;
        case NdbDictionary::Column::Double:
          print_float_or_double(out,
                                result.data_double(),
                                true,
                                m_json_output,
                                m_tsv_output);
          break;
        case NdbDictionary::Column::Undefined:
          abort();
          break;
        default:
          abort();
        }
      }
      break;
    case Cmd::Type::PRINT_AVG:
      {
        NdbAggregator::Result result_sum = m_regs_a[cmd.print_avg.reg_a_sum];
        NdbAggregator::Result result_count = m_regs_a[cmd.print_avg.reg_a_count];
        // todo this must be tested thoroughly against MySQL.
        double numerator = convert_result_to_double(result_sum);
        double denominator = convert_result_to_double(result_count);
        double result = numerator / denominator;
        print_float_or_double(out,
                              result,
                              true,
                              m_json_output,
                              m_tsv_output);
      }
      break;
    case Cmd::Type::PRINT_STR:
      out.write(cmd.print_str.content.str, cmd.print_str.content.len);
      break;
    case Cmd::Type::PRINT_STR_JSON:
      print_json_string_from_utf8(out,
                                  cmd.print_str.content,
                                  m_utf8_output);
      break;
    default:
      abort();
    }
  }
}

// Print a JSON representation of ls to output_stream, assuming ls is correctly
// UTF-8 encoded. utf8_output determines the output encoding:
// utf8_output == true:  If ls contains invalid UTF-8, the output will likewise
//                       be invalid.
// todo perhaps validate
// utf8_output == false: Use \u escape for characters with code point U+0080 and
//                       above. Crash if ls contains invalid UTF-8.
// todo perhaps throw rather than crash.
static void
print_json_string_from_utf8(std::ostream& out,
                            LexString ls,
                            bool utf8_output)
{
  const char* str = ls.str;
  const char* end = &ls.str[ls.len];
  out << '"';
  while (str < end)
  {
    static const char* hex = "0123456789abcdef";
    char ch = *str;
    if (utf8_output || (ch & 0x80) == 0x00)
    {
      // 1-byte encoding for values 0-7 bits in length if utf8_output == true,
      // or all bytes if utf8_output == false.
      switch (ch)
      {
      case '"':  out << "\\\""; break;
      case '\\': out << "\\\\"; break;
      case '/':  out << "\\/";  break;
      case '\b': out << "\\b";  break;
      case '\f': out << "\\f";  break;
      case '\n': out << "\\n";  break;
      case '\r': out << "\\r";  break;
      case '\t': out << "\\t";  break;
      default:   out << ch;     break;
      }
      str++;
      continue;
    }
    if ((ch & 0xe0) == 0xc0)
    {
      // 2-byte encoding for values 8-11 bits in length
      char ch2 = str[1];
      assert((ch  & 0x3e) != 0x00 &&
             (ch2 & 0xc0) == 0x80);
      Uint32 codepoint = ((ch  & 0x1f) << 6) |
                          (ch2 & 0x3f);
      out << "\\u0"
          << hex[codepoint >> 8]
          << hex[(codepoint >> 4) & 0x0f]
          << hex[codepoint & 0x0f];
      str += 2;
      continue;
    }
    if ((ch & 0xf0) == 0xe0)
    {
      // 3-byte encoding for values 12-16 bits in length
      char ch2 = str[1];
      char ch3 = str[2];
      assert((ch2 & 0xc0) == 0x80 &&
             (ch3 & 0xc0) == 0x80);
      Uint32 codepoint = ((ch  & 0x0f) << 12) |
                         ((ch2 & 0x3f) <<  6) |
                          (ch3 & 0x3f);
      assert((codepoint & 0xf800) != 0xd800);
      out << "\\u"
          << hex[codepoint >> 12]
          << hex[(codepoint >> 8) & 0xf]
          << hex[(codepoint >> 4) & 0xf]
          << hex[codepoint & 0xf];
      str += 3;
      continue;
    }
    if ((ch & 0xf8) == 0xf0)
    {
      // 4-byte encoding for values 17-21 bits in length
      char ch2 = str[1];
      char ch3 = str[2];
      char ch4 = str[3];
      assert((ch2 & 0xc0) == 0x80 &&
             (ch3 & 0xc0) == 0x80 &&
             (ch4 & 0xc0) == 0x80);
      Uint32 codepoint = ((ch  & 0x07) << 18) |
                         ((ch2 & 0x3f) << 12) |
                         ((ch3 & 0x3f) <<  6) |
                          (ch4 & 0x3f);
      assert((codepoint & 0x1f0000) != 0x000000);
      Uint32 sp = codepoint - 0x10000;
      assert((sp & 0x100000) == 0);
      out << "\\ud"
          << hex[(sp >> 18) | 0x8]
          << hex[(sp >> 14) & 0xf]
          << hex[(sp >> 10) & 0xf]
          << "\\ud"
          << hex[((sp >> 8) & 0x3) | 0xc]
          << hex[(sp >> 4) & 0xf]
          << hex[sp & 0xf];
      str += 4;
      continue;
    }
    abort();
  }
  out << '"';
}

inline static void
print_float_or_double(std::ostream& out,
                      double value,
                      bool is_double,
                      bool json_output,
                      bool tsv_output)
{
  // todo perhaps do not evaluate this branch every time
  if (json_output && is_double)
  {
    out << std::fixed << std::setprecision(6) << value;
  }
  else if (json_output && !is_double)
  {
    abort(); // todo test the following
    out << std::fixed << std::setprecision(6) << static_cast<float>(value);
  }
  else if (tsv_output)
  {
    char buffer[129];
    bool error;
    size_t len = my_gcvt(value,
                         is_double ? MY_GCVT_ARG_DOUBLE : MY_GCVT_ARG_FLOAT,
                         128, buffer, &error);
    if (error)
    {
      // value is Inf, -Inf or NaN.
      out << "NULL";
      return;
    }
    assert(len > 0 && buffer[len] ==0);
    out << buffer;
  }
  else
  {
    abort();
  }
}

inline static double
convert_result_to_double(NdbAggregator::Result result)
{
  switch (result.type())
  {
  case NdbDictionary::Column::Type::Bigint:
    return static_cast<double>(result.data_int64());
  case NdbDictionary::Column::Type::Bigunsigned:
    return static_cast<double>(result.data_uint64());
  case NdbDictionary::Column::Type::Double:
    return static_cast<double>(result.data_double());
  default:
    abort();
  }
}

inline static float
convert_result_to_float(NdbAggregator::Result result)
{
  switch (result.type())
  {
  case NdbDictionary::Column::Type::Bigint:
    return static_cast<float>(result.data_int64());
  case NdbDictionary::Column::Type::Bigunsigned:
    return static_cast<float>(result.data_uint64());
  case NdbDictionary::Column::Type::Double:
    return static_cast<float>(result.data_double());
  default:
    abort();
  }
}

void
ResultPrinter::explain(std::basic_ostream<char>* out_stream)
{
  std::ostream& out = *out_stream;
  const char* format_description = "";
  switch(m_output_format)
  {
  case RonSQLExecParams::OutputFormat::JSON:
    format_description = "UTF-8 encoded JSON";
    break;
  case RonSQLExecParams::OutputFormat::JSON_ASCII:
    format_description = "ASCII encoded JSON";
    break;
  case RonSQLExecParams::OutputFormat::TEXT:
    format_description = "mysql-style tab separated";
    break;
  case RonSQLExecParams::OutputFormat::TEXT_NOHEADER:
    format_description = "mysql-style tab separated, header-less";
    break;
  default:
    abort();
  }
  out << "Output in " << format_description << " format.\n"
      << "The program for post-processing and output has " << m_program.size()
      << " instructions.\n";
}
