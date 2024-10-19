/*
 * Copyright (C) 2023, 2024 Hopsworks AB
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "pkr_operation.hpp"
#include "NdbBlob.hpp"
#include "NdbOperation.hpp"
#include "NdbRecAttr.hpp"
#include "NdbTransaction.hpp"
#include "src/db_operations/pk/common.hpp"
#include "src/db_operations/pk/pkr_request.hpp"
#include "src/db_operations/pk/pkr_response.hpp"
#include "src/error_strings.h"
#include "src/logger.hpp"
#include "src/rdrs_const.h"
#include "src/status.hpp"
#include "src/mystring.hpp"
#include "my_compiler.h"
#include "src/rdrs_dal.h"

#include <memory>
#include <mysql_time.h>
#include <algorithm>
#include <tuple>
#include <utility>
#include <my_base.h>
#include <storage/ndb/include/ndbapi/NdbDictionary.hpp>
#include <kernel/ndb_limits.h>
#include <ArenaMalloc.hpp>
#include <util/require.h>
#include "my_byteorder.h"
#include <decimal_utils.hpp>
#include <my_time.h>
#include <libbase64.h>

BatchKeyOperations::BatchKeyOperations() {
}

RS_Status
BatchKeyOperations::init_batch_operations(ArenaMalloc *amalloc,
                                          Uint32 numOps,
                                          RS_Buffer *reqBuffer,
                                          RS_Buffer *respBuffer,
                                          Ndb *ndb_object) {
  RS_Status status = RS_OK;
  bool success = false;
  isBatch = true;
  if (numOps == 1) {
    isBatch = false;
  }
  key_ops = (KeyOperation*)amalloc->alloc_bytes(
    sizeof(KeyOperation) * numOps, 8);
  if (unlikely(key_ops == nullptr)) {
    RS_Status error = RS_SERVER_ERROR(ERROR_067);
    return error;
  }
  for (Uint32 i = 0; i < numOps; i++) {
    PKRRequest *req = new (&key_ops[i].m_req) PKRRequest(&reqBuffer[i]);
    PKRResponse *resp = new (&key_ops[i].m_resp) PKRResponse(&respBuffer[i]);
    (void)resp;
    if (unlikely(ndb_object->setCatalogName(req->DB()) != 0)) {
      status = RS_CLIENT_404_WITH_MSG_ERROR(
        ERROR_011 + std::string(" Database: ") +
        std::string(req->DB()) + " Table: " + req->Table());
      req->MarkInvalidOp(status);
      continue;
    }
    const NdbDictionary::Dictionary *dict = ndb_object->getDictionary();
    const NdbDictionary::Table *tableDict = dict->getTable(req->Table());
    if (tableDict == nullptr) {
      status = RS_CLIENT_404_WITH_MSG_ERROR(
        ERROR_011 + std::string(" Database: ") +
        std::string(req->DB()) + " Table: " + req->Table());
      req->MarkInvalidOp(status);
      continue;
    }
    key_ops[i].m_tableDict = tableDict;
    Uint32 numPrimaryKeys = (Uint32)tableDict->getNoOfPrimaryKeys();
    Uint32 numColumns = (Uint32)tableDict->getNoOfColumns();
    Uint32 numReadColumns = req->ReadColumnsCount();
    const NdbRecord *ndb_record = tableDict->getDefaultRecord();
    key_ops[i].m_ndb_record = ndb_record;
    key_ops[i].m_num_pk_columns = numPrimaryKeys;
    key_ops[i].m_num_table_columns = numColumns;
    key_ops[i].m_num_read_columns = numReadColumns;
    if (unlikely(numPrimaryKeys != req->PKColumnsCount())) {
      status =
        RS_CLIENT_ERROR(
        ERROR_013 + std::string(" Expecting: ") +
        std::to_string(numPrimaryKeys) +
        " Got: " + std::to_string(req->PKColumnsCount()));
      req->MarkInvalidOp(status);
      continue;
    }
    if (unlikely(numColumns < req->ReadColumnsCount())) {
      status = RS_CLIENT_ERROR(ERROR_068);
      req->MarkInvalidOp(status);
      continue;
    }
    Uint32 num_bitmap_words = (numColumns + 31) / 32;
    Uint32 num_bitmap_bytes = 4 * num_bitmap_words;
    Uint8* bitmap_words = (Uint8*)amalloc->alloc_bytes(num_bitmap_bytes, 4);
    key_ops[i].m_bitmap_read_columns = bitmap_words;
    Uint32 row_len = NdbDictionary::getRecordRowLength(ndb_record);
    Uint8* row = (Uint8*)amalloc->alloc_bytes(row_len, 8);
    key_ops[i].m_row = row;
    const NdbDictionary::Column **pkCols = (const NdbDictionary::Column**)
      amalloc->alloc_bytes(numPrimaryKeys * sizeof(NdbDictionary::Column*), 8);
    key_ops[i].m_pkColumns = pkCols;
    const NdbDictionary::Column **readCols = (const NdbDictionary::Column**)
      amalloc->alloc_bytes(numReadColumns * sizeof(NdbDictionary::Column*), 8);
    key_ops[i].m_readColumns = readCols;
    if (bitmap_words == nullptr ||
        pkCols == nullptr ||
        readCols == nullptr ||
        row == nullptr) {
      status = RS_SERVER_ERROR(ERROR_067);
      return status;
    }
    Uint32 pk_bitmap_words[MAX_ATTRIBUTES_IN_TABLE/32];
    memset(bitmap_words, 0, num_bitmap_bytes);
    memset(pk_bitmap_words, 0, num_bitmap_bytes);
    bool failed = false;
    Uint32 j = 0;
    for (; j < numPrimaryKeys; j++) {
      const NdbDictionary::Column *pk_col =
        tableDict->getColumn(req->PKName(j));
      if (pk_col == nullptr || !pk_col->getPrimaryKey()) {
        failed = true;
        break;
      }
      Uint32 col_id = pk_col->getColumnNo();
      Uint32 col_word = col_id / 32;
      Uint32 col_bit = col_id & 31;
      Uint32 col_bit_value = (pk_bitmap_words[col_word] >> col_bit) & 1;
      if (col_bit_value != 0) {
        failed = true;
      }
      Uint32 word = pk_bitmap_words[col_word];
      Uint32 bit_value = 1 << col_bit;
      word |= bit_value;
      pk_bitmap_words[col_word] = word;
      key_ops[i].m_pkColumns[j] = pk_col;
    }
    if (unlikely(failed)) {
      status = RS_CLIENT_ERROR(
        ERROR_014 + std::string(req->PKName(j)));
      req->MarkInvalidOp(status);
      continue;
    }
    j = 0;
    for (; j < numReadColumns; j++) {
      const NdbDictionary::Column *read_col =
        tableDict->getColumn(req->ReadColumnName(j));
      if (read_col == nullptr) {
        failed = true;
        break;
      }
      Uint32 col_id = read_col->getColumnNo();
      Uint32 col_word = col_id / 32;
      Uint32 col_bit = col_id & 31;
      Uint32 col_bit_value = (bitmap_words[col_word] >> col_bit) & 1;
      if (col_bit_value != 0) {
        failed = true;
        break;
      }
      Uint32 word = bitmap_words[col_word];
      Uint32 bit_value = 1 << col_bit;
      word |= bit_value;
      bitmap_words[col_word] = word;
      key_ops[i].m_readColumns[j] = read_col;
    }
    if (unlikely(failed)) {
      status = RS_CLIENT_ERROR(
        ERROR_037 + std::string(req->ReadColumnName(j)));
      status = RS_CLIENT_ERROR(ERROR_037);
      req->MarkInvalidOp(status);
      continue;
    }
    // At least one operation is successfully initialised
    success = true;
  }
  if (success) {
    return RS_OK;
  }
  return status;
}

RS_Status BatchKeyOperations::setup_transaction() {
  const NdbDictionary::Table *table_dict = key_ops[0].m_tableDict;
  ndbTransaction = ndb_object->startTransaction(table_dict);
  if (unlikely(ndbTransaction == nullptr)) {
    return RS_RONDB_SERVER_ERROR(ndb_object->getNdbError(), ERROR_005);
  }
  return RS_OK;
}

/**
 * Set up read operation
 *
 * @return status
 */
RS_Status BatchKeyOperations::setup_read_operation() {

start:
  for (size_t opIdx = 0; opIdx < numOperations; opIdx++) {
    // this sub operation can not be processed
    PKRRequest *req = &key_ops[opIdx].m_req;
    if (unlikely(req->IsInvalidOp())) {
      continue;
    }
    Uint32 numPrimaryKeys = key_ops[opIdx].m_num_pk_columns;
    for (Uint32 colIdx = 0; colIdx < numPrimaryKeys; colIdx++) {
      RS_Status status =
        set_operation_pk_col(key_ops[opIdx].m_pkColumns[colIdx],
                             req,
                             key_ops[opIdx].m_row,
                             key_ops[opIdx].m_ndb_record,
                             colIdx);
      if (status.http_code != SUCCESS) {
        if (isBatch) {
          req->MarkInvalidOp(status);
          goto start;
        } else {
          return status;
        }
      }
    }
    const NdbOperation *operation = ndbTransaction->readTuple(
      key_ops[opIdx].m_ndb_record,
      (const char*)key_ops[opIdx].m_row,
      key_ops[opIdx].m_ndb_record,
      (char*)key_ops[opIdx].m_row,
      NdbOperation::LM_CommittedRead,
      key_ops[opIdx].m_bitmap_read_columns,
      nullptr,
      0);
    if (unlikely(operation == nullptr)) {
      return RS_RONDB_SERVER_ERROR(ndbTransaction->getNdbError(), ERROR_007);
    }
    key_ops[opIdx].m_ndbOperation = operation;
  }
  return RS_OK;
}

RS_Status BatchKeyOperations::execute() {
  if (unlikely(ndbTransaction->execute(NdbTransaction::NoCommit) != 0)) {
    return RS_RONDB_SERVER_ERROR(ndbTransaction->getNdbError(), ERROR_009);
  }
  return RS_OK;
}

RS_Status BatchKeyOperations::create_response() {
  bool found = true;
  for (size_t i = 0; i < numOperations; i++) {
    PKRRequest *req = &key_ops[i].m_req;
    PKRResponse *resp = &key_ops[i].m_resp;
    const NdbOperation *op = key_ops[i].m_ndbOperation;
    resp->SetDB(req->DB());
    resp->SetTable(req->Table());
    resp->SetOperationID(req->OperationId());
    resp->SetNoOfColumns(key_ops[i].m_num_read_columns);
    if (unlikely(req->IsInvalidOp())) {
      resp->SetStatus(req->GetError().http_code, req->GetError().message);
      resp->Close();
      continue;
    }
    found = true;
    if (likely(op->getNdbError().classification == NdbError::NoError)) {
      resp->SetStatus(SUCCESS, "OK");
    } else if (op->getNdbError().classification == NdbError::NoDataFound) {
      found = false;
      resp->SetStatus(NOT_FOUND, "NOT Found");
    } else {      
      //  immediately fail the entire batch
      resp->SetStatus(SERVER_ERROR, op->getNdbError().message);
      resp->Close();
      return RS_RONDB_SERVER_ERROR(
        op->getNdbError(), std::string("SubOperation ") +
        std::string(req->OperationId()) +
        std::string(" failed"));
    }
    if (likely(found)) {
      // iterate over all columns
      RS_Status ret = key_ops[i].append_op_recs(resp);
      if (ret.http_code != SUCCESS) {
        return ret;
      }
    }
    resp->Close();
  }
  if (unlikely(!found && !isBatch)) {
    return RS_CLIENT_404_ERROR();
  }
  return RS_OK;
}

RS_Status KeyOperation::append_op_recs(PKRResponse *resp) {
  for (Uint32 colIdx = 0; colIdx < m_num_read_columns; colIdx++) {
    RS_Status ret = write_col_to_resp(colIdx, resp);
    if (ret.http_code != SUCCESS) {
      return ret;
    }
  }
  return RS_OK;
}

static inline void my_unpack_date(MYSQL_TIME *l_time, const void *d) {
  uchar b[4];
  memcpy(b, d, 3);
  b[3] = 0;
  uint w = (uint)uint3korr(b);
  l_time->day = (w & 31);
  w >>= 5;
  l_time->month = (w & 15);
  w >>= 4;
  l_time->year = w;
  l_time->time_type = MYSQL_TIMESTAMP_DATE;
}

RS_Status KeyOperation::write_col_to_resp(Uint32 colIdx,
                                          PKRResponse *response) {
  const NdbDictionary::Column *col = m_readColumns[colIdx];
  const NdbRecord *ndb_record = m_ndb_record;
  const char *col_name = col->getName();
  Uint32 col_id = col->getColumnNo();
  Uint8 *row = m_row;
  {
    Uint32 null_byte_offset;
    Uint32 null_bit_in_byte;
    bool null_value = NdbDictionary::getNullBitOffset(
      ndb_record, col_id, null_byte_offset, null_bit_in_byte);
    if (null_value) {
      Uint8 null_byte = row[null_byte_offset];
      Uint8 null_bit_value = (null_byte >> null_bit_in_byte) & 1;
      if (null_bit_value) {
        return response->SetColumnDataNull(m_req.ReadColumnName(colIdx));
       }
    }
  }
  Uint32 offset;
  bool ret = NdbDictionary::getOffset(ndb_record, col_id, offset);
  require(ret);
  Uint8 *col_ptr = row + offset;
  switch (col->getType()) {
  case NdbDictionary::Column::Undefined: {
    ///< 4 bytes + 0-3 fraction
    return RS_CLIENT_ERROR(ERROR_018 + std::string(" Column: ") +
      std::string(col_name));
  }
  case NdbDictionary::Column::Tinyint: {
    ///< 8 bit. 1 byte signed integer, can be used in array
    return response->Append_i8(col_name, *(Int8*)col_ptr);
  }
  case NdbDictionary::Column::Tinyunsigned: {
    ///< 8 bit. 1 byte unsigned integer, can be used in array
    return response->Append_iu8(col_name, *(Uint8*)col_ptr);
  }
  case NdbDictionary::Column::Smallint: {
    ///< 16 bit. 2 byte signed integer, can be used in array
    return response->Append_i16(col_name, *(Int16*)col_ptr);
  }
  case NdbDictionary::Column::Smallunsigned: {
    ///< 16 bit. 2 byte unsigned integer, can be used in array
    return response->Append_iu16(col_name, *(Uint16*)col_ptr);
  }
  case NdbDictionary::Column::Mediumint: {
    ///< 24 bit. 3 byte signed integer, can be used in array
    return response->Append_i24(col_name, sint3korr(col_ptr));
  }
  case NdbDictionary::Column::Mediumunsigned: {
    ///< 24 bit. 3 byte unsigned integer, can be used in array
    return response->Append_iu24(col_name, uint3korr(col_ptr));
  }
  case NdbDictionary::Column::Int: {
    ///< 32 bit. 4 byte signed integer, can be used in array
    return response->Append_i32(col_name, *(Int32*)col_ptr);
  }
  case NdbDictionary::Column::Unsigned: {
    ///< 32 bit. 4 byte unsigned integer, can be used in array
    return response->Append_iu32(col_name, *(Uint32*)col_ptr);
  }
  case NdbDictionary::Column::Bigint: {
    ///< 64 bit. 8 byte signed integer, can be used in array
    return response->Append_i64(col_name, *(Int64*)col_ptr);
  }
  case NdbDictionary::Column::Bigunsigned: {
    ///< 64 Bit. 8 byte signed integer, can be used in array
    return response->Append_iu64(col_name, *(Uint64*)col_ptr);
  }
  case NdbDictionary::Column::Float: {
    ///< 32-bit float. 4 bytes float, can be used in array
    return response->Append_f32(col_name, *(float*)col_ptr);
  }
  case NdbDictionary::Column::Double: {
    ///< 64-bit float. 8 byte float, can be used in array
    return response->Append_d64(col_name, *(double*)col_ptr);
  }
  case NdbDictionary::Column::Olddecimal: {
    ///< MySQL < 5.0 signed decimal,  Precision, Scale
    return RS_SERVER_ERROR(
      ERROR_028 + std::string(" Column: ") + std::string(col_name) +
      " Type: " + std::to_string(col->getType()));
  }
  case NdbDictionary::Column::Olddecimalunsigned: {
    ///< MySQL < 5.0 signed decimal,  Precision, Scale
    return RS_SERVER_ERROR(
      ERROR_028 + std::string(" Column: ") + std::string(col_name) +
      " Type: " + std::to_string(col->getType()));
  }
  case NdbDictionary::Column::Decimal:
    ///< MySQL >= 5.0 signed decimal,  Precision, Scale
    [[fallthrough]];
  case NdbDictionary::Column::Decimalunsigned: {
    char decStr[DECIMAL_MAX_STR_LEN_IN_BYTES];
    int precision = col->getPrecision();
    int scale = col->getScale();
    void *bin = (void*)col_ptr;
    int binLen = col->getLength();
    decimal_bin2str(bin,
                    binLen,
                    precision,
                    scale,
                    decStr,
                    DECIMAL_MAX_STR_LEN_IN_BYTES);
    return response->Append_string(col_name, std::string(decStr),
                                   RDRS_FLOAT_DATATYPE);
  }
  case NdbDictionary::Column::Char:
    ///< Len. A fixed array of 1-byte chars
    [[fallthrough]];
  case NdbDictionary::Column::Varchar:
    ///< Length bytes: 1, Max: 255
    [[fallthrough]];
  case NdbDictionary::Column::Longvarchar: {
    ///< Length bytes: 2, little-endian
    const char *dataStart = nullptr;
    const NdbDictionary::Column::ArrayType arrayType =
      col->getArrayType();
    Uint32 attrBytes = col->getLength();
    switch (arrayType) {
    case NdbDictionary::Column::ArrayTypeFixed:
      /**
       *  No prefix length is stored in aRef. Data starts from aRef's first byte
       *  data might be padded with blank or null bytes to fill the whole column
       */
      dataStart = (const char*)col_ptr;
      break;
    case NdbDictionary::Column::ArrayTypeShortVar:
      /**
       * First byte of aRef has the length of data stored
       *  Data starts from second byte of aRef
       */
      dataStart = (const char*)(col_ptr + 1);
      attrBytes = static_cast<Uint8>(col_ptr[0]);
      break;
    case NdbDictionary::Column::ArrayTypeMediumVar:
      /**
       * First two bytes of aRef has the length of data stored
       * Data starts from third byte of aRef
       */
      dataStart = (const char*)(col_ptr + 2);
      attrBytes = static_cast<Uint8>(col_ptr[1]) * 256 +
                  static_cast<Uint8>(col_ptr[0]);
      break;
    default:
      return RS_CLIENT_ERROR(ERROR_019);
    }
    return response->Append_char(col_name,
                                 dataStart,
                                 attrBytes,
                                 col->getCharset());
  }
  case NdbDictionary::Column::Binary:
    [[fallthrough]];
  case NdbDictionary::Column::Varbinary:
    ///< Length bytes: 1, Max: 255
    [[fallthrough]];
  case NdbDictionary::Column::Longvarbinary: {
    ///< Length bytes: 2, little-endian
    const char *dataStart = nullptr;
    const NdbDictionary::Column::ArrayType arrayType =
      col->getArrayType();
    Uint32 attrBytes = col->getLength();
    switch (arrayType) {
    case NdbDictionary::Column::ArrayTypeFixed:
      /**
       *  No prefix length is stored in aRef. Data starts from aRef's first byte
       *  data might be padded with blank or null bytes to fill the whole column
       */
      dataStart = (const char*)col_ptr;
      break;
    case NdbDictionary::Column::ArrayTypeShortVar:
      /**
       * First byte of aRef has the length of data stored
       *  Data starts from second byte of aRef
       */
      dataStart = (const char*)(col_ptr + 1);
      attrBytes = static_cast<Uint8>(col_ptr[0]);
      break;
    case NdbDictionary::Column::ArrayTypeMediumVar:
      /**
       * First two bytes of aRef has the length of data stored
       * Data starts from third byte of aRef
       */
      dataStart = (const char*)(col_ptr + 2);
      attrBytes = static_cast<Uint8>(col_ptr[1]) * 256 +
                  static_cast<Uint8>(col_ptr[0]);
      break;
    default:
      return RS_CLIENT_ERROR(ERROR_019);
    }
    if (attrBytes > MAX_TUPLE_SIZE_IN_BYTES) {
      // TODO error code
    }
    char buffer[MAX_TUPLE_SIZE_IN_BYTES_ENCODED];
    size_t outlen = 0;
    base64_encode(dataStart, attrBytes, (char *)&buffer[0], &outlen, 0);
    return response->Append_string(col_name,
                                   std::string(buffer, outlen),
                                   RDRS_BINARY_DATATYPE);
  }
  case NdbDictionary::Column::Datetime: {
    ///< Precision down to 1 sec (sizeof(Datetime) == 8 bytes )
    return RS_SERVER_ERROR(
      ERROR_028 + std::string(" Column: ") + std::string(col_name) +
      " Type: " + std::to_string(col->getType()));
  }
  case NdbDictionary::Column::Date: {
    ///< Precision down to 1 day(sizeof(Date) == 4 bytes )
    MYSQL_TIME lTime;
    my_unpack_date(&lTime, (char*)col_ptr);
    char to[MAX_DATE_STRING_REP_LENGTH];
    my_date_to_str(lTime, to);
    return response->Append_string(col_name, std::string(to),
                                   RDRS_DATETIME_DATATYPE);
  }
  case NdbDictionary::Column::Blob: {
    ///< Binary large object (see NdbBlob)
    /// Treat it as binary data
    return RS_SERVER_ERROR(
      ERROR_037 + std::string(" Reading column length failed.") +
      std::string(" Column: ") + std::string(col_name) +
      " Type: " + std::to_string(col->getType()));
  }
  case NdbDictionary::Column::Text: {
    ///< Text blob
    return RS_SERVER_ERROR(
      ERROR_037 + std::string(" Reading column length failed.") +
      std::string(" Column: ") + std::string(col_name) +
      " Type: " + std::to_string(col->getType()));
  }
  case NdbDictionary::Column::Bit: {
    Uint32 words = col->getLength() / 8;
    if (col->getLength() % 8 != 0) {
      words += 1;
    }
    require(words <= BIT_MAX_SIZE_IN_BYTES);
    // change endieness
    int i = 0;
    char reversed[BIT_MAX_SIZE_IN_BYTES];
    for (int j = words - 1; j >= 0; j--) {
      reversed[i++] = (char)col_ptr[j];
    }
    char buffer[BIT_MAX_SIZE_IN_BYTES_ENCODED];
    size_t outlen = 0;
    base64_encode(reversed, words, (char *)&buffer[0], &outlen, 0);
    return response->Append_string(col_name,
                                   std::string(buffer, outlen),
                                   RDRS_BIT_DATATYPE);
  }
  case NdbDictionary::Column::Time: {
    ///< Time without date
    return RS_SERVER_ERROR(
      ERROR_028 + std::string(" Column: ") + std::string(col_name) +
      " Type: " + std::to_string(col->getType()));
  }
  case NdbDictionary::Column::Year: {
    ///< Year 1901-2155 (1 byte)
    Int32 year = (uint)(1900 + col_ptr[0]);
    return response->Append_i32(col_name, year);
  }
  case NdbDictionary::Column::Timestamp: {
    ///< Unix time
    return RS_SERVER_ERROR(
      ERROR_028 + std::string(" Column: ") +
      std::string(col_name) +
      " Type: " + std::to_string(col->getType()));
  }
  ///**
  // * Time types in MySQL 5.6 add microsecond fraction.
  // * One should use setPrecision(x) to set number of fractional
  // * digits (x = 0-6, default 0).  Data formats are as in MySQL
  // * and must use correct byte length.  NDB does not check data
  // * itself since any values can be compared as binary strings.
  // */
  case NdbDictionary::Column::Time2: {
    ///< 3 bytes + 0-3 fraction
    uint precision = col->getPrecision();
    longlong numericTime =
      my_time_packed_from_binary((const unsigned char *)col_ptr, precision);
    MYSQL_TIME lTime;
    TIME_from_longlong_time_packed(&lTime, numericTime);
    char to[MAX_DATE_STRING_REP_LENGTH];
    my_TIME_to_str(lTime, to, precision);
    return response->Append_string(col_name,
                                   std::string(to),
                                   RDRS_DATETIME_DATATYPE);
  }
  case NdbDictionary::Column::Datetime2: {
    ///< 5 bytes plus 0-3 fraction
    uint precision = col->getPrecision();
    longlong numericDate =
      my_datetime_packed_from_binary((const unsigned char *)col_ptr, precision);
    MYSQL_TIME lTime;
    TIME_from_longlong_datetime_packed(&lTime, numericDate);
    char to[MAX_DATE_STRING_REP_LENGTH];
    my_TIME_to_str(lTime, to, precision);
    return response->Append_string(col_name,
                                   std::string(to),
                                   RDRS_DATETIME_DATATYPE);
  }
  case NdbDictionary::Column::Timestamp2: {
    ///< 4 bytes + 0-3 fraction
    uint precision = col->getPrecision();
    my_timeval myTV{};
    my_timestamp_from_binary(&myTV, (const unsigned char *)col_ptr, precision);
    Int64 epochIn = myTV.m_tv_sec;
    time_t stdtime(epochIn);
    struct tm *time_info = gmtime(&stdtime);
    MYSQL_TIME lTime  = {};
    lTime.year        = time_info->tm_year + 1900;
    lTime.month       = time_info->tm_mon +1;
    lTime.day         = time_info->tm_mday;
    lTime.hour        = time_info->tm_hour; 
    lTime.minute      = time_info->tm_min; 
    lTime.second      = time_info->tm_sec; 
    lTime.second_part = myTV.m_tv_usec;
    lTime.time_type   = MYSQL_TIMESTAMP_DATETIME;
    char to[MAX_DATE_STRING_REP_LENGTH];
    my_TIME_to_str(lTime, to, precision);
    return response->Append_string(col_name,
                                   std::string(to),
                                   RDRS_DATETIME_DATATYPE);
  }
  }
  return RS_SERVER_ERROR(
    ERROR_028 + std::string(" Column: ") + std::string(col_name) +
    " Type: " + std::to_string(col->getType()));
}

void BatchKeyOperations::close_transaction() {
  ndb_object->closeTransaction(ndbTransaction);
}

RS_Status BatchKeyOperations::perform_operation(
  ArenaMalloc *amalloc,
  Uint32 numOperations,
  RS_Buffer *reqBuffer,
  RS_Buffer *respBuffer,
  Ndb *ndb_object) {

  RS_Status status = init_batch_operations(
    amalloc,
    numOperations,
    reqBuffer,
    respBuffer,
    ndb_object);
  if (unlikely(status.http_code != SUCCESS)) {
    handle_ndb_error(status);
    return status;
  }
  status = setup_transaction();
  if (unlikely(status.http_code != SUCCESS)) {
    handle_ndb_error(status);
    return status;
  }
  status = setup_read_operation();
  if (unlikely(status.http_code != SUCCESS)) {
    handle_ndb_error(status);
    return status;
  }
  status = execute();
  if (unlikely(status.http_code != SUCCESS)) {
    handle_ndb_error(status);
    return status;
  }
  status = create_response();
  if (unlikely(status.http_code != SUCCESS)) {
    handle_ndb_error(status);
    return status;
  }
  close_transaction();
  return RS_OK;
}

RS_Status BatchKeyOperations::abort() {
  if (likely(ndbTransaction != nullptr)) {
    NdbTransaction::CommitStatusType status = ndbTransaction->commitStatus();
    if (status == NdbTransaction::CommitStatusType::Started) {
      ndbTransaction->execute(NdbTransaction::Rollback);
    }
    ndb_object->closeTransaction(ndbTransaction);
  }
  return RS_OK;
}

RS_Status BatchKeyOperations::handle_ndb_error(RS_Status status) {
  // schema errors
  if (UnloadSchema(status)) {
    // no idea which sub-operation threw the error
    // unload all tables used in this operation
    std::list<std::tuple<std::string, std::string>> tables;
    std::unordered_map<std::string, bool> tablesMap;
    for (Uint32 i = 0; i < numOperations; i++) {
      PKRRequest *req = &key_ops[i].m_req;
      if (req->IsInvalidOp()) {
        const char *db = req->DB();
        const char *table = req->Table();
        std::string key(std::string(db) + "|" + std::string(table));
        if (tablesMap.count(key) == 0) {
          tables.push_back(std::make_tuple(std::string(db),
                           std::string(table)));
          tablesMap[key] = true;
        }
      }
    }
    HandleSchemaErrors(ndb_object, status, tables);
  }
  abort();
  return RS_OK;
}

PKROperation::PKROperation(RS_Buffer *reqBuff,
                           RS_Buffer *respBuff,
                           Ndb *ndbObject) {
  SubOpTuple pkOpTuple = SubOpTuple{};
  pkOpTuple.pkRequest = new PKRRequest(reqBuff);
  pkOpTuple.pkResponse = new PKRResponse(respBuff);
  pkOpTuple.ndbOperation = nullptr;
  pkOpTuple.tableDict = nullptr;
  pkOpTuple.primaryKeysCols = nullptr;
  pkOpTuple.primaryKeySizes = nullptr;
  this->subOpTuples.push_back(pkOpTuple);
  this->ndbObject = ndbObject;
  this->noOps = 1;
  this->isBatch = false;
}

PKROperation::PKROperation(Uint32 noOps,
                           RS_Buffer *reqBuffs,
                           RS_Buffer *respBuffs,
                           Ndb *ndbObject) {
  for (Uint32 i = 0; i < noOps; i++) {
    SubOpTuple pkOpTuple = SubOpTuple{};
    pkOpTuple.pkRequest = new PKRRequest(&reqBuffs[i]);
    pkOpTuple.pkResponse = new PKRResponse(&respBuffs[i]);
    pkOpTuple.ndbOperation = nullptr;
    pkOpTuple.tableDict = nullptr;
    pkOpTuple.primaryKeysCols = nullptr;
    pkOpTuple.primaryKeySizes = nullptr;
    this->subOpTuples.push_back(pkOpTuple);
  }
  this->ndbObject = ndbObject;
  this->noOps     = noOps;
  this->isBatch   = true;
}

PKROperation::~PKROperation() {
  for (size_t subOpIdx = 0; subOpIdx < subOpTuples.size(); subOpIdx++) {
    SubOpTuple subOp = subOpTuples[subOpIdx];
    int pkColsCount = subOp.pkRequest->PKColumnsCount();
    if (subOp.primaryKeysCols != nullptr) {
      for (int pkPtrIdx = 0; pkPtrIdx < pkColsCount; pkPtrIdx++) {
        if (subOp.primaryKeysCols[pkPtrIdx] == nullptr) {
          break;
        } else {
          free(subOp.primaryKeysCols[pkPtrIdx]);
        }
      }
      free(subOp.primaryKeysCols);
    }
    if (subOp.primaryKeySizes != nullptr) {
      free(subOp.primaryKeySizes);
    }
    // clear the ColRec Vector
    subOp.recs.clear();
    delete subOp.pkRequest;
    delete subOp.pkResponse;
  }
}

/**
 * start a transaction
 *
 * @return status
 */

RS_Status PKROperation::SetupTransaction() {
  const NdbDictionary::Table *table_dict = subOpTuples[0].tableDict;
  transaction = ndbObject->startTransaction(table_dict);
  if (unlikely(transaction == nullptr)) {
    return RS_RONDB_SERVER_ERROR(ndbObject->getNdbError(), ERROR_005);
  }
  return RS_OK;
}

/**
 * Set up read operation
 *
 * @return status
 */
RS_Status PKROperation::SetupReadOperation() {

start:
  for (size_t opIdx = 0; opIdx < noOps; opIdx++) {
    // this sub operation can not be processed
    if (unlikely(subOpTuples[opIdx].pkRequest->IsInvalidOp())) {
      continue;
    }
    PKRRequest *req = subOpTuples[opIdx].pkRequest;
    const NdbDictionary::Table *tableDict = subOpTuples[opIdx].tableDict;
    std::vector<std::shared_ptr<ColRec>> *recs = &subOpTuples[opIdx].recs;
    // cleaned by destructor
    Int8 **primaryKeysCols =
      (Int8 **)malloc(req->PKColumnsCount() * sizeof(Int8 *));
    Uint32 *primaryKeySizes =
      (Uint32 *)malloc(req->PKColumnsCount() * sizeof(Uint32));
    memset(primaryKeysCols, 0, req->PKColumnsCount() * sizeof(Int8 *));
    memset(primaryKeySizes, 0, req->PKColumnsCount() * sizeof(Uint32));
    subOpTuples[opIdx].primaryKeysCols = primaryKeysCols;
    subOpTuples[opIdx].primaryKeySizes = primaryKeySizes;
    for (Uint32 colIdx = 0; colIdx < req->PKColumnsCount(); colIdx++) {
      RS_Status status =
        SetOperationPKCol(tableDict->getColumn(req->PKName(colIdx)),
                          req,
                          colIdx,
                          &primaryKeysCols[colIdx],
                          &primaryKeySizes[colIdx]);
      if (status.http_code != SUCCESS) {
        if (isBatch) {
          subOpTuples[opIdx].pkRequest->MarkInvalidOp(status);
          goto start;
        } else {
          return status;
        }
      }
    }
    NdbOperation *operation = transaction->getNdbOperation(tableDict);
    if (unlikely(operation == nullptr)) {
      return RS_RONDB_SERVER_ERROR(transaction->getNdbError(), ERROR_007);
    }
    subOpTuples[opIdx].ndbOperation = operation;
    if (unlikely(operation->readTuple(NdbOperation::LM_CommittedRead) != 0)) {
      return RS_SERVER_ERROR(ERROR_022);
    }
    for (Uint32 colIdx = 0; colIdx < req->PKColumnsCount(); colIdx++) {
      int retVal =
        operation->equal(req->PKName(colIdx),
        (char *)primaryKeysCols[colIdx],
        primaryKeySizes[colIdx]);
      if (unlikely(retVal != 0)) {
        return RS_SERVER_ERROR(ERROR_023);
      }
    }
    if (req->ReadColumnsCount() > 0) {
      for (Uint32 i = 0; i < req->ReadColumnsCount(); i++) {
        RS_Status status = GetColValue(tableDict,
                                       operation,
                                       req->ReadColumnName(i),
                                       recs);
        if (unlikely(status.http_code != SUCCESS)) {
          return status;
        }
      }
    } else {
      std::unordered_map<std::string,
                         const NdbDictionary::Column *> *nonPKCols =
        &subOpTuples[opIdx].allNonPKCols;
      std::unordered_map<std::string,
                         const NdbDictionary::Column *>::const_iterator it =
        nonPKCols->begin();
      while (it != nonPKCols->end()) {
        RS_Status status = GetColValue(tableDict,
                                       operation,
                                       it->first.c_str(),
                                       recs);
        if (unlikely(status.http_code != SUCCESS)) {
          return status;
        }
        it++;
      }
    }
  }
  return RS_OK;
}

RS_Status PKROperation::GetColValue(const NdbDictionary::Table *tableDict,
                                    NdbOperation *ndbOperation,
                                    const char *colName,
                                    std::vector<std::shared_ptr<ColRec>> *recs) {
  NdbBlob *blob = nullptr;
  NdbRecAttr *ndbRecAttr = nullptr;
  if (tableDict->getColumn(colName)->getType() == NdbDictionary::Column::Blob ||
      tableDict->getColumn(colName)->getType() == NdbDictionary::Column::Text) {
    blob = ndbOperation->getBlobHandle(colName);
    // failed to read blob column
    if (unlikely(blob == nullptr)) {
      return RS_SERVER_ERROR(
        ERROR_037 + std::string(" Column: ") + std::string(colName));
    }
  }
  ndbRecAttr = ndbOperation->getValue(colName, nullptr);
  if (unlikely(ndbRecAttr == nullptr)) {
    return RS_SERVER_ERROR(
      ERROR_037 + std::string(" Column: ") + std::string(colName));
  }
  auto colRec = std::make_shared<ColRec>(ndbRecAttr, blob);
  recs->push_back(colRec);
  return RS_OK;
}

RS_Status PKROperation::Execute() {
  if (unlikely(transaction->execute(NdbTransaction::NoCommit) != 0)) {
    return RS_RONDB_SERVER_ERROR(transaction->getNdbError(), ERROR_009);
  }
  return RS_OK;
}

RS_Status PKROperation::CreateResponse() {
  bool found = true;
  for (size_t i = 0; i < noOps; i++) {
    PKRRequest *req = subOpTuples[i].pkRequest;
    PKRResponse *resp = subOpTuples[i].pkResponse;
    const NdbOperation *op = subOpTuples[i].ndbOperation;
    std::vector<std::shared_ptr<ColRec>> *recs = &subOpTuples[i].recs;
    resp->SetDB(req->DB());
    resp->SetTable(req->Table());
    resp->SetOperationID(req->OperationId());
    resp->SetNoOfColumns(recs->size());
    if (unlikely(req->IsInvalidOp())) {
      resp->SetStatus(req->GetError().http_code, req->GetError().message);
      resp->Close();
      continue;
    }
    found = true;
    if (likely(op->getNdbError().classification == NdbError::NoError)) {
      resp->SetStatus(SUCCESS, "OK");
    } else if (op->getNdbError().classification == NdbError::NoDataFound) {
      found = false;
      resp->SetStatus(NOT_FOUND, "NOT Found");
    } else {      
      //  immediately fail the entire batch
      resp->SetStatus(SERVER_ERROR, op->getNdbError().message);
      resp->Close();
      return RS_RONDB_SERVER_ERROR(
        op->getNdbError(), std::string("SubOperation ") +
        std::string(req->OperationId()) +
        std::string(" failed"));
    }
    if (likely(found)) {
      // iterate over all columns
      RS_Status ret = AppendOpRecs(resp, recs);
      if (ret.http_code != SUCCESS) {
        return ret;
      }
    }
    resp->Close();
  }
  if (unlikely(!found && !isBatch)) {
    return RS_CLIENT_404_ERROR();
  }
  return RS_OK;
}

RS_Status PKROperation::AppendOpRecs(
  PKRResponse *resp,
  std::vector<std::shared_ptr<ColRec>> *recs) {
  for (Uint32 i = 0; i < recs->size(); i++) {
    RS_Status status = WriteColToRespBuff((*recs)[i], resp);
    if (unlikely(status.http_code != SUCCESS)) {
      return status;
    }
  }
  return RS_OK;
}

RS_Status PKROperation::Init() {
  for (size_t i = 0; i < noOps; i++) {
    PKRRequest *req = subOpTuples[i].pkRequest;
    std::unordered_map<std::string, const NdbDictionary::Column *> *pkCols =
      &subOpTuples[i].allPKCols;
    std::unordered_map<std::string, const NdbDictionary::Column *> *nonPKCols =
      &subOpTuples[i].allNonPKCols;
    if (unlikely(ndbObject->setCatalogName(req->DB()) != 0)) {
      RS_Status error =
          RS_CLIENT_404_WITH_MSG_ERROR(
            ERROR_011 + std::string(" Database: ") +
            std::string(req->DB()) + " Table: " + req->Table());
      if (isBatch) {  // ignore this sub-operation and continue with the rest
        req->MarkInvalidOp(error);
        continue;
      } else {
        return error;
      }
    }
    const NdbDictionary::Dictionary *dict = ndbObject->getDictionary();
    const NdbDictionary::Table *tableDict = dict->getTable(req->Table());
    if (unlikely(tableDict == nullptr)) {
      RS_Status error =
          RS_CLIENT_404_WITH_MSG_ERROR(
            ERROR_011 + std::string(" Database: ") +
            std::string(req->DB()) + " Table: " + req->Table());
      if (isBatch) {  // ignore this sub-operation and continue with the rest
        req->MarkInvalidOp(error);
        continue;
      } else {
        return error;
      }
    }
    subOpTuples[i].tableDict = tableDict;
    // get all primary key columnns
    for (int i = 0; i < tableDict->getNoOfPrimaryKeys(); i++) {
      const char *priName = tableDict->getPrimaryKey(i);
      (*pkCols)[std::string(priName)] = tableDict->getColumn(priName);
    }
    // get all non primary key columnns
    for (int i = 0; i < tableDict->getNoOfColumns(); i++) {
      const NdbDictionary::Column *col = tableDict->getColumn(i);
      std::string colNameStr(col->getName());
      std::unordered_map<std::string,
                         const NdbDictionary::Column *>::const_iterator got =
        (*pkCols).find(colNameStr);
      if (got == pkCols->end()) {  // not found
        (*nonPKCols)[std::string(col->getName())] =
          tableDict->getColumn(col->getName());
      }
    }
  }
  return RS_OK;
}

RS_Status PKROperation::ValidateRequest() {
  // Check primary key columns
  for (size_t i = 0; i < noOps; i++) {
    PKRRequest *req = subOpTuples[i].pkRequest;
    if (unlikely(req->IsInvalidOp())) {
      // this sub-operation was previously marked invalid.
      continue;
    }
    std::unordered_map<std::string, const NdbDictionary::Column *> *pkCols =
      &subOpTuples[i].allPKCols;
    std::unordered_map<std::string, const NdbDictionary::Column *> *nonPKCols =
      &subOpTuples[i].allNonPKCols;
    if (unlikely(req->PKColumnsCount() != pkCols->size())) {
      RS_Status error =
          RS_CLIENT_ERROR(
            ERROR_013 + std::string(" Expecting: ") +
            std::to_string(pkCols->size()) +
            " Got: " + std::to_string(req->PKColumnsCount()));
      if (isBatch) {  // mark bad sub-operation
        req->MarkInvalidOp(error);
        continue;
      }
      return error;
    }
    for (Uint32 i = 0; i < req->PKColumnsCount(); i++) {
      std::unordered_map<std::string,
                         const NdbDictionary::Column *>::const_iterator got =
        pkCols->find(std::string(req->PKName(i)));
      // not found
      if (unlikely(got == pkCols->end())) {
        RS_Status error =
            RS_CLIENT_ERROR(
              ERROR_014 + std::string(" Column: ") +
              std::string(req->PKName(i)));
        if (isBatch) {  // mark bad sub-operation
          req->MarkInvalidOp(error);
          continue;
        }
        return error;
      }
    }
    // Check non primary key columns
    // check that all columns exist
    // check that data return type is supported
    // check for reading blob columns
    if (req->ReadColumnsCount() > 0) {
      for (Uint32 i = 0; i < req->ReadColumnsCount(); i++) {
        std::unordered_map<std::string,
                           const NdbDictionary::Column *>::const_iterator got =
          nonPKCols->find(std::string(req->ReadColumnName(i)));
        // not found
        if (unlikely(got == nonPKCols->end())) {
          RS_Status error = RS_CLIENT_ERROR(
            ERROR_012 + std::string(" Column: ") +
            std::string(req->ReadColumnName(i)));
          if (isBatch) {  // mark bad sub-operation
            req->MarkInvalidOp(error);
            continue;
          }
          return error;
        }
        // check that the data return type is supported
        // for now we only support DataReturnType.DEFAULT
        if (unlikely(req->ReadColumnReturnType(i) > __MAX_TYPE_NOT_A_DRT ||
            DEFAULT_DRT != req->ReadColumnReturnType(i))) {
          RS_Status error = RS_SERVER_ERROR(
            ERROR_025 + std::string(" Column: ") +
            std::string(req->ReadColumnName(i)));
          if (isBatch) {  // mark bad sub-operation
            req->MarkInvalidOp(error);
            continue;
          }
          return error;
        }
      }
    }
  }
  return RS_OK;
}

void PKROperation::CloseTransaction() {
  ndbObject->closeTransaction(transaction);
}

RS_Status PKROperation::PerformOperation() {
  RS_Status status = Init();
  if (unlikely(status.http_code != SUCCESS)) {
    this->HandleNDBError(status);
    return status;
  }
  status = ValidateRequest();
  if (unlikely(status.http_code != SUCCESS)) {
    this->HandleNDBError(status);
    return status;
  }
  status = SetupTransaction();
  if (unlikely(status.http_code != SUCCESS)) {
    this->HandleNDBError(status);
    return status;
  }
  status = SetupReadOperation();
  if (unlikely(status.http_code != SUCCESS)) {
    this->HandleNDBError(status);
    return status;
  }
  status = Execute();
  if (unlikely(status.http_code != SUCCESS)) {
    this->HandleNDBError(status);
    return status;
  }
  status = CreateResponse();
  if (unlikely(status.http_code != SUCCESS)) {
    this->HandleNDBError(status);
    return status;
  }
  CloseTransaction();
  return RS_OK;
}

RS_Status PKROperation::Abort() {
  if (likely(transaction != nullptr)) {
    NdbTransaction::CommitStatusType status = transaction->commitStatus();
    if (status == NdbTransaction::CommitStatusType::Started) {
      transaction->execute(NdbTransaction::Rollback);
    }
    ndbObject->closeTransaction(transaction);
  }
  return RS_OK;
}

RS_Status PKROperation::HandleNDBError(RS_Status status) {
  // schema errors
  if (UnloadSchema(status)) {
    // no idea which sub-operation threw the error
    // unload all tables used in this operation
    std::list<std::tuple<std::string, std::string>> tables;
    std::unordered_map<std::string, bool> tablesMap;
    for (size_t i = 0; i < noOps; i++) {
      PKRRequest *req = subOpTuples[i].pkRequest;
      const char *db = req->DB();
      const char *table = req->Table();
      std::string key(std::string(db) + "|" + std::string(table));
      if (tablesMap.count(key) == 0) {
        tables.push_back(std::make_tuple(std::string(db), std::string(table)));
        tablesMap[key] = true;
      }
    }
    HandleSchemaErrors(ndbObject, status, tables);
  }
  this->Abort();
  return RS_OK;
}
