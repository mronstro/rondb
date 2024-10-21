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
 
#ifndef STORAGE_NDB_REST_SERVER2_SERVER_SRC_DB_OPERATIONS_PK_PKR_OPERATION_HPP_
#define STORAGE_NDB_REST_SERVER2_SERVER_SRC_DB_OPERATIONS_PK_PKR_OPERATION_HPP_

#include "pkr_request.hpp"
#include "pkr_response.hpp"
#include "common.hpp"
#include "src/rdrs_dal.h"

#include <memory>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <NdbApi.hpp>
#include <ArenaMalloc.hpp>

struct KeyOperation {
  Uint32 m_num_pk_columns;
  Uint32 m_num_read_columns;
  Uint32 m_num_table_columns;
  Uint8 *m_bitmap_read_columns;
  Uint8 *m_row;
  const NdbOperation *m_ndbOperation;
  const NdbDictionary::Table *m_tableDict;
  const NdbDictionary::Column **m_pkColumns;
  const NdbDictionary::Column **m_readColumns;
  const NdbRecord *m_ndb_record;
  PKRRequest m_req;
  PKRResponse m_resp;
  RS_Status append_op_recs(PKRResponse *resp);
  RS_Status write_col_to_resp(Uint32 colIdx, PKRResponse *resp);
};

class BatchKeyOperations {
 private:
  Uint32 m_numOperations;
  NdbTransaction *m_ndbTransaction;
  Ndb *m_ndb_object;
  bool m_isBatch;
  struct KeyOperation *m_key_ops;
 public:
   BatchKeyOperations();
   ~BatchKeyOperations();
   RS_Status perform_operation(ArenaMalloc*,
                               Uint32 numOps,
                               RS_Buffer *reqBuffer,
                               RS_Buffer *respBuffer,
                               Ndb *ndb_object);
   RS_Status init_batch_operations(ArenaMalloc*,
                                   Uint32,
                                   RS_Buffer *reqBuffer,
                                   RS_Buffer *respBuffer,
                                   Ndb *ndb_object);
   RS_Status setup_transaction();
   RS_Status setup_read_operation();
   RS_Status execute();
   RS_Status create_response();
   RS_Status append_op_recs(Uint32);
   void close_transaction();
   RS_Status abort();
   RS_Status handle_ndb_error(RS_Status);
};

typedef struct SubOpTuple {
  PKRRequest *pkRequest;
  PKRResponse *pkResponse;
  NdbOperation *ndbOperation;
  const NdbDictionary::Table *tableDict;
  std::vector<std::shared_ptr<ColRec>> recs;
  std::unordered_map<std::string, const NdbDictionary::Column *> allNonPKCols;
  std::unordered_map<std::string, const NdbDictionary::Column *> allPKCols;
  Int8 **primaryKeysCols;
  Uint32 *primaryKeySizes;
} ReqRespTuple;

class PKROperation {
 private:
  Uint32 noOps;
  NdbTransaction *transaction = nullptr;
  Ndb *ndbObject = nullptr;
  bool isBatch = false;
  std::vector<SubOpTuple> subOpTuples;

 public:
  PKROperation(RS_Buffer *reqBuff, RS_Buffer *respBuff, Ndb *ndbObject);

  PKROperation(Uint32 noOps,
               RS_Buffer *reqBuffs,
               RS_Buffer *respBuffs,
               Ndb *ndbObject);
  ~PKROperation();

  /**
   * perform the operation
   */
  RS_Status PerformOperation();

 private:
  /**
   * start a transaction
   *
   * @return status
   */
  RS_Status SetupTransaction();

  /**
   * setup pk read operation
   * @returns status
   */
  RS_Status SetupReadOperation();

  /**
   * Set primary key column values
   * @returns status
   */
  RS_Status SetOperationPKCols();

  /**
   * Execute transaction
   *
   * @return status
   */
  RS_Status Execute();

  /**
   * Close transaction
   */
  void CloseTransaction();

  /**
   * It does clean up and depending on error type
   * it may takes further actions such as unload
   * tables from NDB::Dictionary if it encounters
   * schema invalidation errors
   */
  RS_Status HandleNDBError(RS_Status status);

  /**
   * abort operation
   */
  RS_Status Abort();

  /**
   * create response
   *
   * @return status
   */
  RS_Status CreateResponse();

  /**
   * initialize data structures
   * @return status
   */
  RS_Status Init();

  /**
   * Validate request
   * @return status
   */
  RS_Status ValidateRequest();

  /**
   * Append operation records to response buffer
   * @return status
   */
  RS_Status AppendOpRecs(PKRResponse *resp,
                         std::vector<std::shared_ptr<ColRec>> *recs);

  /**
   * Store NdbRecord or Blob handler in the SubOperation.recs
   * @return status
   */
  RS_Status GetColValue(const NdbDictionary::Table *tableDict,
                        NdbOperation *ndbOperation,
                        const char *colName,
                        std::vector<std::shared_ptr<ColRec>> *recs);
};
#endif  // STORAGE_NDB_REST_SERVER2_SERVER_SRC_DB_OPERATIONS_PK_PKR_OPERATION_HPP_
