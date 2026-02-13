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
#include <cstring>
#include <mutex>
#include "Dbtup.hpp"
#include "NdbAggregationCommon.hpp"
#include "util/rondb_hash.hpp"

#define READ_BUF_WORD_SIZE 2048
#define DECIMAL_BUFF_LENGTH 9
#define AGG_EVICT_NEEDED 1
#define MEM_CHUNK_SIZE 32768
#define GB_HASH_BUCKET_COUNT 1024

struct MemChunk {
  char* data;
  Uint32 capacity;
  Uint32 used;
  Uint32 live_groups;
  MemChunk* next;
  MemChunk* prev;
  char* group_list;         // singly-linked list of live groups in this chunk
};

/*
 * Chaining hash table for group-by lookup.  All per-thread interpreters
 * use identical bucket count so merge can iterate bucket-by-bucket.
 *
 * Group data layout (GROUP_LINK_OVERHEAD = 24 bytes prepended):
 *   [chunk_next(8)] [hash_next(8)] [key_len(4)] [chunk_offset(4)]
 * Data pointer (from allocGroupData) points past this header.
 * hash_next links entries within the same bucket.
 */
class GBHashTable {
 public:
  static const Uint32 HASH_NEXT_OFFSET = sizeof(char*);
  static const Uint32 KEY_LEN_OFFSET = 2 * sizeof(char*);
  static const Uint32 OVERHEAD = 24;

  class Iterator {
    friend class GBHashTable;
    GBHashTable* m_ht;
    Uint32 m_bucket;
    char** m_prev_link;
    char* m_raw;
   public:
    Iterator() : m_ht(nullptr), m_bucket(0), m_prev_link(nullptr),
                 m_raw(nullptr) {}
    Iterator(GBHashTable* ht, Uint32 bucket, char** prev_link, char* raw)
      : m_ht(ht), m_bucket(bucket), m_prev_link(prev_link), m_raw(raw) {}
    bool valid() const { return m_raw != nullptr; }
    char* data() const { return m_raw + OVERHEAD; }
    Uint32 keyLen() const {
      return *reinterpret_cast<Uint32*>(m_raw + KEY_LEN_OFFSET);
    }
  };

  GBHashTable()
    : m_size(0), m_bucket_count(0), m_bucket_mask(0) {
    memset(m_buckets, 0, sizeof(m_buckets));
  }

  void init(Uint32 bucket_count) {
    m_bucket_count = bucket_count;
    m_bucket_mask = bucket_count - 1;
    m_size = 0;
    memset(m_buckets, 0, bucket_count * sizeof(char*));
  }

  void clear() {
    memset(m_buckets, 0, m_bucket_count * sizeof(char*));
    m_size = 0;
  }

  char* find(const char* key, Uint32 key_len) const {
    Uint32 b = hashKey(key, key_len);
    return findInBucket(b, key, key_len);
  }

  void insert(char* data_ptr, Uint32 key_len) {
    char* raw = data_ptr - OVERHEAD;
    Uint32 b = hashKey(data_ptr, key_len);
    hashNext(raw) = m_buckets[b];
    m_buckets[b] = raw;
    m_size++;
  }

  void erase(char* data_ptr, Uint32 key_len) {
    char* raw = data_ptr - OVERHEAD;
    Uint32 b = hashKey(data_ptr, key_len);
    char** prev = &m_buckets[b];
    while (*prev != nullptr) {
      if (*prev == raw) {
        *prev = hashNext(raw);
        m_size--;
        return;
      }
      prev = &hashNext(*prev);
    }
  }

  Iterator begin() {
    for (Uint32 b = 0; b < m_bucket_count; b++) {
      if (m_buckets[b] != nullptr) {
        return Iterator(this, b, &m_buckets[b], m_buckets[b]);
      }
    }
    return Iterator(this, m_bucket_count, nullptr, nullptr);
  }

  Iterator begin() const {
    GBHashTable* self = const_cast<GBHashTable*>(this);
    for (Uint32 b = 0; b < m_bucket_count; b++) {
      if (m_buckets[b] != nullptr) {
        return Iterator(self, b,
                        const_cast<char**>(&m_buckets[b]), m_buckets[b]);
      }
    }
    return Iterator(self, m_bucket_count, nullptr, nullptr);
  }

  void next(Iterator& it) const {
    char* nxt = hashNext(it.m_raw);
    if (nxt != nullptr) {
      it.m_prev_link = &hashNext(it.m_raw);
      it.m_raw = nxt;
      return;
    }
    for (Uint32 b = it.m_bucket + 1; b < m_bucket_count; b++) {
      if (m_buckets[b] != nullptr) {
        it.m_bucket = b;
        it.m_prev_link = const_cast<char**>(&m_buckets[b]);
        it.m_raw = m_buckets[b];
        return;
      }
    }
    it.m_bucket = m_bucket_count;
    it.m_prev_link = nullptr;
    it.m_raw = nullptr;
  }

  void eraseAndNext(Iterator& it) {
    char* nxt = hashNext(it.m_raw);
    *it.m_prev_link = nxt;
    m_size--;
    if (nxt != nullptr) {
      it.m_raw = nxt;
      return;
    }
    for (Uint32 b = it.m_bucket + 1; b < m_bucket_count; b++) {
      if (m_buckets[b] != nullptr) {
        it.m_bucket = b;
        it.m_prev_link = &m_buckets[b];
        it.m_raw = m_buckets[b];
        return;
      }
    }
    it.m_bucket = m_bucket_count;
    it.m_prev_link = nullptr;
    it.m_raw = nullptr;
  }

  Uint32 size() const { return m_size; }
  bool empty() const { return m_size == 0; }
  Uint32 bucketCount() const { return m_bucket_count; }

  char* findInBucket(Uint32 b, const char* key, Uint32 key_len) const {
    for (char* raw = m_buckets[b]; raw != nullptr;
         raw = hashNext(raw)) {
      char* d = raw + OVERHEAD;
      Uint32 kl = *reinterpret_cast<Uint32*>(raw + KEY_LEN_OFFSET);
      if (kl == key_len && memcmp(d, key, key_len) == 0) {
        return d;
      }
    }
    return nullptr;
  }

  char* popBucketHead(Uint32 b) {
    char* raw = m_buckets[b];
    if (raw == nullptr) return nullptr;
    m_buckets[b] = hashNext(raw);
    m_size--;
    return raw + OVERHEAD;
  }

  void insertRaw(char* data_ptr) {
    char* raw = data_ptr - OVERHEAD;
    Uint32 key_len = *reinterpret_cast<Uint32*>(raw + KEY_LEN_OFFSET);
    Uint32 b = hashKey(data_ptr, key_len);
    hashNext(raw) = m_buckets[b];
    m_buckets[b] = raw;
    m_size++;
  }

  bool bucketEmpty(Uint32 b) const { return m_buckets[b] == nullptr; }

  Uint32 hashKey(const char* key, Uint32 len) const {
    Uint64 h = rondb_xxhash_std(key, len);
    return static_cast<Uint32>(h) & m_bucket_mask;
  }

 private:
  char* m_buckets[GB_HASH_BUCKET_COUNT];
  Uint32 m_size;
  Uint32 m_bucket_count;
  Uint32 m_bucket_mask;

  static char*& hashNext(char* raw) {
    return *reinterpret_cast<char**>(raw + HASH_NEXT_OFFSET);
  }
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
    m_chunks(nullptr), m_chunks_tail(nullptr),
    m_current_chunk(nullptr), m_total_chunk_bytes(0),
    m_memory_budget(0), m_budget_increment(0),
    m_total_available(0), m_thread_id(0),
    m_agg_ops_cached(false) {
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
  Uint32 mergeFrom(AggInterpreter* other, Uint32 max_groups);

  void Print();
  Uint32 PrepareAggResIfNeeded(Signal* signal, bool force);
  Uint32 NumOfResRecords(bool last_time = false);
  static void MergePrint(const AggInterpreter* in1, const AggInterpreter* in2);
  const GBHashTable* gb_map() const {
    return gb_map_;
  }
  GBHashTable* gb_map_mutable() {
    return gb_map_;
  }
  Uint32 val_len() const {
    return n_agg_results_ * sizeof(AggResItem);
  }
  Uint32 n_gb_cols() const { return n_gb_cols_; }
  Uint32 n_agg_results() const { return n_agg_results_; }
  const AggResItem* agg_results() const { return agg_results_; }
  void setUseMutex(bool v) { m_use_mutex = v; }
  void setMaxGroups(Uint32 v) { m_max_groups = v; }
  Uint32 maxGroups() const { return m_max_groups; }
  Int32 evictOneGroup(Uint32* buf, Uint32 buf_words,
                      Uint32* words_written);
  void initChunkAllocator(Uint32 thread_id, Uint32 budget_pages,
                          Uint32 available_pages);
  bool bookMoreMemory();
  char* allocGroupData(Uint32 len, Uint32 key_len);
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

  GBHashTable* gb_map_;
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
  MemChunk* m_chunks;                 // doubly-linked list head
  MemChunk* m_chunks_tail;            // doubly-linked list tail
  MemChunk* m_current_chunk;          // chunk currently bump-allocating from
  Uint32 m_total_chunk_bytes;         // total bytes across all chunks
  Uint32 m_memory_budget;             // current budget (bytes), grows via bookMoreMemory
  Uint32 m_budget_increment;          // bytes added per bookMoreMemory call
  Uint32 m_total_available;           // total available at setup (bytes), booking cap
  Uint32 m_thread_id;                 // for lc_ndbd_pool_malloc calls

  MemChunk* allocNewChunk();

  // Embedded interpreter validation (called at Init time)
  bool validateEmbeddedProgram(const Uint32* emb_prog, Uint32 emb_len);

  // Cached agg ops for merge (avoids recomputing per CONTINUEB batch)
  Uint8 m_cached_agg_ops[MAX_AGG_N_RESULTS];
  bool m_agg_ops_cached;

  Uint32 prog_buf_[MAX_AGG_PROGRAM_WORD_SIZE];
  Uint32 gb_cols_buf_[MAX_AGG_N_GROUPBY_COLS];
  AggResItem agg_results_buf_[MAX_AGG_N_RESULTS];
  GBHashTable gb_map_buf_;

};
#endif  // AGGINTERPRETER_H_
