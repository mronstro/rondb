/*
 * Copyright (c) 2024, 2024, Hopsworks and/or its affiliates.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2.0,
 * as published by the Free Software Foundation.

 * This program is also distributed with certain software (including
 * but not limited to OpenSSL) that is licensed under separate terms,
 * as designated in a particular file or component or in included license
 * documentation.  The authors of MySQL hereby grant you an additional
 * permission to link the program and your derivative works with the
 * separately licensed software that they have included with MySQL.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License, version 2.0, for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef AGGINTERPRETER_H_
#define AGGINTERPRETER_H_

#include <math.h>
#include <map>
#include <mutex>
#include "Dbtup.hpp"
#include "NdbAggregationCommon.hpp"

#define READ_BUF_WORD_SIZE 2048
#define DECIMAL_BUFF_LENGTH 9
#define AGG_EVICT_NEEDED 1
#define MEM_CHUNK_SIZE 32768

struct MemChunk {
  char* data;
  Uint32 capacity;
  Uint32 used;
  Uint32 live_groups;
  MemChunk* next;
};

class AggInterpreter {
 public:
  AggInterpreter(const Uint32* prog, Uint32 prog_len, Int64 frag_id):
    prog_len_(prog_len), cur_pos_(0),
    inited_(false), n_gb_cols_(0), gb_cols_(nullptr),
    n_agg_results_(0),
    agg_results_(nullptr), agg_prog_start_pos_(0),
    gb_map_(nullptr), n_groups_(0),
    buf_pos_(0), processed_rows_(0),
    result_size_(0), frag_id_(frag_id),
    m_linked_attr_data(nullptr), m_linked_attr_len(0),
    m_use_mutex(false), m_max_groups(0),
    m_chunks(nullptr),
    m_current_chunk(nullptr), m_total_chunk_bytes(0),
    m_memory_budget(0), m_thread_id(0) {
      assert(prog_len_ <= MAX_AGG_PROGRAM_WORD_SIZE);
      prog_ = prog_buf_;
      memcpy(prog_, prog, prog_len * sizeof(Uint32));
      memset(buf_, 0, READ_BUF_WORD_SIZE * sizeof(Uint32));
      memset(decimal_buf_, 0, sizeof(decimal_digit_t) * DECIMAL_BUFF_LENGTH);
      decimal_.buf = decimal_buf_;
      decimal_.len = DECIMAL_BUFF_LENGTH;
  }
  ~AggInterpreter() {
    freeAllChunks();
  }

  bool Init();
  bool OptimizeProgram();

  Int32 ProcessRec(Dbtup* block_tup, Dbtup::KeyReqStruct* req_struct);

  Int32 processRecWithLinkedAttrs(
      Dbtup* block_tup,
      Dbtup::KeyReqStruct* req_struct,
      const Uint32* linked_attr_data,
      Uint32 linked_attr_len);
  Int32 finalizeResults();
  Int32 getResultData(Uint32* buffer, Uint32 buffer_size,
                      Uint32* bytes_written);
  static Int32 mergeAllByBucket(
      AggInterpreter** interpreters,
      Uint32 num_interpreters);
  Int32 mergeFrom(AggInterpreter* other);

  void Print();
  Uint32 PrepareAggResIfNeeded(Signal* signal, bool force);
  Uint32 NumOfResRecords(bool last_time = false);
  static void MergePrint(const AggInterpreter* in1, const AggInterpreter* in2);
  const std::map<GBHashEntry, GBHashEntry, GBHashEntryCmp>* gb_map() {
    return gb_map_;
  }
  std::map<GBHashEntry, GBHashEntry, GBHashEntryCmp>* gb_map_mutable() {
    return gb_map_;
  }
  Uint32 n_gb_cols() const { return n_gb_cols_; }
  Uint32 n_agg_results() const { return n_agg_results_; }
  const AggResItem* agg_results() const { return agg_results_; }
  void setUseMutex(bool v) { m_use_mutex = v; }
  void setMaxGroups(Uint32 v) { m_max_groups = v; }
  Uint32 maxGroups() const { return m_max_groups; }
  Int32 evictOneGroup(Uint32* buf, Uint32 buf_words,
                      Uint32* words_written);
  void initChunkAllocator(Uint32 thread_id, Uint32 budget_pages);
  char* allocGroupData(Uint32 len);
  void freeGroupData(char* ptr);
  void freeAllChunks();
  Int64 frag_id() {
    return frag_id_;
  }
  static void Destruct(AggInterpreter* ptr);

 private:
  Uint32* prog_;
  Uint32 prog_len_;
  Uint32 cur_pos_;
  bool inited_;
  Register registers_[kRegTotal];

  Uint32 n_gb_cols_;
  Uint32* gb_cols_;
  Uint32 n_agg_results_;
  AggResItem* agg_results_;
  Uint32 agg_prog_start_pos_;

  std::map<GBHashEntry, GBHashEntry, GBHashEntryCmp>* gb_map_;
  Uint32 n_groups_;
  Uint32 buf_[READ_BUF_WORD_SIZE];
  Uint32 buf_pos_;
  static Uint32 g_buf_len_;
  Uint64 processed_rows_;
  Uint32 result_size_;
  static Uint32 g_result_header_size_;
  static Uint32 g_result_header_size_per_group_;

  Int64 frag_id_;
  decimal_t decimal_;
  decimal_digit_t decimal_buf_[DECIMAL_BUFF_LENGTH];

  // Linked attribute buffer for join aggregation
  const Uint32* m_linked_attr_data;   // Points to current row's linked attrs
  Uint32 m_linked_attr_len;           // Current length in words

  // MUTEX_BASED locking: protects gb_map_ and accumulators during
  // concurrent access from multiple LDM threads.
  bool m_use_mutex;                   // true for MUTEX_BASED strategy
  std::mutex m_mutex;

  // Group eviction: when m_max_groups > 0 and gb_map_ reaches this
  // limit, processRecWithLinkedAttrs returns AGG_EVICT_NEEDED so the
  // caller can evict a group before retrying.
  Uint32 m_max_groups;                // 0 = unlimited

  // Chunk-based allocator for group data.
  // Allocates from 32KB chunks via lc_ndbd_pool_malloc,
  // with per-chunk reference counting so eviction can free memory.
  MemChunk* m_chunks;                 // linked list head
  MemChunk* m_current_chunk;          // chunk currently bump-allocating from
  Uint32 m_total_chunk_bytes;         // total bytes across all chunks
  Uint32 m_memory_budget;             // max total chunk bytes allowed
  Uint32 m_thread_id;                 // for lc_ndbd_pool_malloc calls

  MemChunk* allocNewChunk();
  MemChunk* findChunk(const char* ptr) const;

  Uint32 prog_buf_[MAX_AGG_PROGRAM_WORD_SIZE];
  Uint32 gb_cols_buf_[MAX_AGG_N_GROUPBY_COLS];
  AggResItem agg_results_buf_[MAX_AGG_N_RESULTS];
  std::map<GBHashEntry, GBHashEntry, GBHashEntryCmp> gb_map_buf_;

};
#endif  // AGGINTERPRETER_H_
