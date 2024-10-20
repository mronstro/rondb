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

/*
 * MOZ
 * Turn off the MOZ_AGG_MOLLOC to use new instead
 * of AggInterpreter's memory alloctor
 */
#define MOZ_AGG_MALLOC 1

#define READ_BUF_WORD_SIZE 2048
#define DECIMAL_BUFF_LENGTH 9
class AggInterpreter {
 public:
#ifdef MOZ_AGG_MALLOC
  AggInterpreter(const Uint32* prog, Uint32 prog_len, bool print, Int64 frag_id/*,
                 Ndbd_mem_manager* mm, void* page_addr, Uint32 page_ref*/):
#else
  AggInterpreter(const Uint32* prog, Uint32 prog_len, bool print, Int64 frag_id):
#endif // MOZ_AGG_MALLOC
    prog_len_(prog_len), cur_pos_(0),
    inited_(false), n_gb_cols_(0), gb_cols_(nullptr),
    n_agg_results_(0),
    agg_results_(nullptr), agg_prog_start_pos_(0),
    gb_map_(nullptr), n_groups_(0),
    buf_pos_(0), print_(print), processed_rows_(0),
    result_size_(0), frag_id_(frag_id)/*, pcount_(0)*/ {
#ifdef MOZ_AGG_MALLOC
      assert(prog_len_ <= MAX_AGG_PROGRAM_WORD_SIZE);
      prog_ = prog_buf_;
#else
      prog_ = new Uint32[prog_len];
#endif // MOZ_AGG_MALLOC
      memcpy(prog_, prog, prog_len * sizeof(Uint32));
      memset(buf_, 0, READ_BUF_WORD_SIZE * sizeof(Uint32));
      memset(decimal_buf_, 0, sizeof(Int32) * DECIMAL_BUFF_LENGTH);
#ifdef MOZ_AGG_MALLOC
      /* For using Ndbd_mem_manager*/
      /*
      mm_ = mm;
      page_addr_ = page_addr;
      page_ref_ = page_ref;
      */
      alloc_len_ = 0;
#endif // MOZ_AGG_MALLOC
  }
  ~AggInterpreter() {
#ifdef MOZ_AGG_MALLOC
#else
    delete[] prog_;
    delete[] gb_cols_;
    delete[] agg_results_;
    if (gb_map_) {
      // MOZ debug
      if (!gb_map_->empty()) {
        /*
         * Moz
         * TODO (Zhao)
         * potential crash here if the API closes scan
         * while lqh is processing, double check.
         *
         * (CHECKED)
         */
        assert(gb_map_->empty());
      }
      for (auto iter = gb_map_->begin(); iter != gb_map_->end(); iter++) {
        delete[] iter->first.ptr;
      }
      delete gb_map_;
    }
#endif // MOZ_AGG_MALLOC
  }

  bool Init();

  Int32 ProcessRec(Dbtup* block_tup, Dbtup::KeyReqStruct* req_struct);
  void Print();
  Uint32 PrepareAggResIfNeeded(Signal* signal, bool force);
  Uint32 NumOfResRecords(bool last_time = false);
  static void MergePrint(const AggInterpreter* in1, const AggInterpreter* in2);
  const std::map<GBHashEntry, GBHashEntry, GBHashEntryCmp>* gb_map() {
    return gb_map_;
  }
  Int64 frag_id() {
    return frag_id_;
  }
#ifdef MOZ_AGG_MALLOC
  static void Destruct(AggInterpreter* ptr);
  /* For using Ndbd_mem_manager*/
  /*
  Ndbd_mem_manager* mm() {
    return mm_;
  }
  Uint32 page_ref() {
    return page_ref_;
  }
  */
#endif // MOZ_AGG_MALLOC

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
  bool print_;
  Uint64 processed_rows_;
  Uint32 result_size_;
  static Uint32 g_result_header_size_;
  static Uint32 g_result_header_size_per_group_;

  Int64 frag_id_;
  Int32 decimal_buf_[DECIMAL_BUFF_LENGTH];

#ifdef MOZ_AGG_MALLOC
  /* For using Ndbd_mem_manager */
  /*
  Ndbd_mem_manager* mm_;
  void* page_addr_;
  Uint32 page_ref_;
  */

  Uint32 prog_buf_[MAX_AGG_PROGRAM_WORD_SIZE];
  Uint32 gb_cols_buf_[MAX_AGG_N_GROUPBY_COLS];
  AggResItem agg_results_buf_[MAX_AGG_N_RESULTS];
  std::map<GBHashEntry, GBHashEntry, GBHashEntryCmp> gb_map_buf_;

  char mem_buf_[MAX_AGG_RESULT_BATCH_BYTES];
  Uint32 alloc_len_;
  char* MemAlloc(Uint32 len);
#endif // MOZ_AGG_MALLOC
};
#endif  // AGGINTERPRETER_H_
