# RANGE Partitioning for RonDB - Architecture Plan

## 1. Current Partitioning Architecture

### 1.1 Overview

NDB currently supports these partition methods, tracked via `TabRecord::Method` in DBDIH:

| Method | Enum | How fragment is selected |
|--------|------|------------------------|
| `LINEAR_HASH` | 0 | `hashValue & mask` with linear hash extension |
| `NORMAL_HASH` | 2 | `hashValue % partitionCount` |
| `USER_DEFINED` | 3 | Client supplies fragmentId directly |
| `HASH_MAP` | 4 | `Hash2FragmentMap.m_map[hashValue % m_cnt]` (modern default) |

The `DictTabInfo::FragmentType` enum (in `DictTabInfo.hpp:209`) maps to these methods.

### 1.2 Key Data Flow: Primary Key Operation

```
NDB API (client)
  |-- computes hash: rondb_calc_hash() on primary/distribution key columns
  |-- sends TCKEYREQ with hashValue + distributionKeyIndicator
  v
DBTC (DbtcMain.cpp:3141 hash(), :4776 DiGetNodesReq)
  |-- if distributionKeyIndicator: tdistrHashValue = user-supplied value
  |-- else: tdistrHashValue = hash[1] (second word of MD5)
  |-- sends DiGetNodesReq{tableId, hashValue, distr_key_indicator, ...}
  |-- calls c_dih->execDIGETNODESREQ() directly (same thread, RCU-protected)
  v
DBDIH (DbdihMain.cpp:15654 execDIGETNODESREQ)
  |-- if distr_key_indicator: fragId = hashValue (value IS the fragId)
  |-- else if HASH_MAP: fragId = Hash2FragmentMap.m_map[hashValue % m_cnt]
  |-- else if LINEAR_HASH: fragId = hashValue & mask (with extension)
  |-- else if NORMAL_HASH: fragId = hashValue % partitionCount
  |-- else if USER_DEFINED: error (must supply fragId)
  |-- looks up Fragmentstore for fragId -> gets replica nodes
  |-- returns DiGetNodesConf{fragId, nodes[], instanceKey}
  v
DBTC sends LQHKEYREQ to correct LQH instance
```

### 1.3 Key Data Flow: Scan Operation

DBTC iterates over all fragments (or a pruned subset) via `DIH_SCAN_TAB_REQ`,
then sends `SCAN_FRAGREQ` per fragment. DBSPJ uses the same `DIGETNODESREQ`
mechanism (`DbspjMain.cpp:5648`).

### 1.4 Existing RangeListData Support

MySQL's ha_ndbcluster already translates SQL RANGE/LIST partition definitions
into `RangeListData` stored in `DictTabInfo::Table` (ha_ndbcluster.cc:15421).
However, this is purely **metadata for MySQL** -- NDB itself treats these tables
as `UserDefined` and MySQL computes the partition on the client side. NDB
data nodes do NOT use the range boundaries for routing.

### 1.5 Key Structures

| Structure | Location | Purpose |
|-----------|----------|---------|
| `Hash2FragmentMap` | `SimulatedBlock.hpp:2757` | Array mapping hash bucket -> fragId |
| `TabRecord` (DBDIH) | `Dbdih.hpp:664` | Table metadata: method, m_map_ptr_i, totalfragments, partitionCount |
| `Fragmentstore` | `Dbdih.hpp:266` | Per-fragment: replica nodes, partition_id, distributionKey |
| `TabRecord` (DBTC) | `Dbtc.hpp:1641` | Flags only (TR_USER_DEFINED_PARTITIONING, TR_FULLY_REPLICATED) |
| `DiGetNodesReq` | `DiGetNodes.hpp:66` | Signal: tableId, hashValue, distr_key_indicator |
| `DictTabInfo::Table` | `DictTabInfo.hpp:330` | Wire format: FragmentType, RangeListData[], HashMapObjectId |
| `NdbTableImpl` | `NdbDictionaryImpl.hpp` | API: m_range, m_hash_map, m_fragmentType |
| `CreateFragmentationReq` | `CreateFragmentation.hpp:33` | Signal: fragmentationType, noOfFragments, map_ptr_i |

---

## 2. Requirements for RANGE Partitioning

1. **Partition selection based on value ranges** rather than hash.
   - Partition columns must be part of the primary key.
   - The partition key value is compared against range boundaries to find the correct fragment.

2. **Range metadata stored as a binary tree** in DBDIH for efficient lookup.

3. **Initial ALTER TABLE support**:
   - DROP first partition (range)
   - ADD partition at end of range

4. **NDB API should work as-is** except for metadata changes.

5. **Blocks affected**: DBDICT, DBDIH, DBTC, eventually DBSPJ.

---

## 3. Architecture Options

### Option A: New Method `RANGE_PARTITION` in DBDIH with Binary Tree

**Concept**: Add a new `TabRecord::Method::RANGE_PARTITION = 5` and a new
data structure `Range2FragmentMap` (analogous to `Hash2FragmentMap`) that stores
sorted range boundaries and maps value ranges to fragment IDs. The range
lookup happens in `execDIGETNODESREQ` using binary search.

**Key changes**:

1. **New enum values**:
   - `DictTabInfo::FragmentType::RangePartition = 10`
   - `NdbDictionary::Object::FragmentType::RangePartition = 10`
   - `TabRecord::Method::RANGE_PARTITION = 5`

2. **New structure `Range2FragmentMap`** (in `SimulatedBlock.hpp`):
   ```cpp
   struct Range2FragmentMap {
     static constexpr Uint32 MAX_RANGES = MAX_NDB_PARTITIONS;
     Uint32 m_cnt;           // number of range entries
     Uint32 m_num_columns;   // number of partition key columns
     struct RangeEntry {
       Int64 m_upper_bound;  // upper boundary (exclusive)
       Uint16 m_frag_id;     // fragment for values < m_upper_bound
     };
     RangeEntry m_ranges[MAX_RANGES]; // sorted array (binary search)
     Uint32 nextPool;
     Uint32 m_object_id;
   };
   ```
   - The last entry has `m_upper_bound = INT64_MAX` (catch-all).
   - Binary search on `m_upper_bound` gives O(log N) lookup per partition count.

3. **DBDIH `execDIGETNODESREQ`** (DbdihMain.cpp:15654):
   - Add `else if (tabPtr.p->method == TabRecord::RANGE_PARTITION)` branch.
   - The `hashValue` field in `DiGetNodesReq` would carry the **range key value** instead of a hash. For multi-column range keys, a composite representation is needed.
   - Binary search through `Range2FragmentMap::m_ranges[]` to find `fragId`.

4. **DBTC `hash()`** (DbtcMain.cpp:3141):
   - For range-partitioned tables, instead of computing MD5 hash, extract the
     partition key columns' value and pack it into `tdistrHashValue`.
   - This requires DBTC to know the table is range-partitioned (via a flag).

5. **DBDICT**: Store range boundaries in table metadata. Already has
   `RangeListData[]` in `DictTabInfo::Table` -- can extend or reuse.

6. **NDB API**: Either compute the range-to-fragment mapping client-side
   (extend `getPartitionId()`) or pass the raw partition key value and let
   the server resolve it.

**Pros**:
- Clean separation: range lookup is entirely in DBDIH, just like hash lookup.
- Binary search on sorted array is simple, fast, and cache-friendly.
- Minimal signal changes (reuse hashValue field with different semantics).
- Range2FragmentMap can be globally allocated like Hash2FragmentMap, using the
  same RCU-protected g_hash_map pattern.

**Cons**:
- The `hashValue` field in `DiGetNodesReq` is Uint32 -- sufficient for single
  INT column ranges but limits multi-column or 64-bit range key support.
- DBTC must extract the raw partition key value instead of hashing -- requires
  a new code path alongside the existing hash computation.
- A true "binary tree" would need pointers; a sorted array with binary search
  is simpler but functionally equivalent for static ranges.

---

### Option B: Client-Side Range Resolution (Extend USER_DEFINED approach)

**Concept**: Keep the range-to-fragment mapping purely in the NDB API
(client-side). The API resolves range boundaries to a fragment ID and passes it
as `distributionKey` with `distr_key_indicator = 1`. Inside the data nodes,
this looks like `USER_DEFINED` partitioning.

**Key changes**:

1. **NDB API**: Extend `NdbTableImpl::getPartitionId()` to handle a new
   `FragmentType::RangePartition`. Use the existing `m_range` vector to store
   boundaries. Binary search on client side.

2. **No DBTC/DBDIH changes** for basic routing -- they already handle
   `distr_key_indicator = 1` (fragId passed directly).

3. **DBDICT**: Store range boundaries in `RangeListData` (already exists).
   Add new `FragmentType` enum so data nodes know it's range-partitioned.

4. **ALTER TABLE**: Server-side changes in DBDICT for ADD/DROP partition
   metadata, plus redistributing `RangeListData`.

**Pros**:
- Minimal data node changes.
- Reuses existing `USER_DEFINED` / `distr_key_indicator` mechanism.
- Already a pattern MySQL uses today for RANGE partitions on NDB.

**Cons**:
- Range boundaries not available in data nodes -- DBTC cannot validate partition
  assignment, DBDIH cannot do partition pruning for scans.
- All callers (NDB API, MySQL, RDRS, Rondis) must implement range resolution.
- DBSPJ cannot route pushed-down joins correctly without server-side knowledge.
- Not truly "native" range partitioning -- just smarter client-side hinting.
- Does not support server-side scan pruning based on WHERE clause ranges.

---

### Option C: Hybrid -- Server-Side Range Metadata with Client Hint

**Concept**: Store range boundaries in both the NDB API (for fast client-side
partition pruning and `distr_key_indicator`) AND in DBDIH (for server-side
validation and scan pruning). Primary key operations use client-side resolution
(fast path), while scans use server-side range metadata for pruning.

**Key changes**:

1. **Everything from Option A** for metadata and DBDIH.
2. **Client-side fast path**: NDB API computes fragId from range boundaries
   and passes it as `distr_key_indicator = 1`. DBDIH can optionally validate.
3. **Server-side scan pruning**: DBTC/DBDIH can use range metadata to prune
   scan fragments when bounds are known.

**Pros**:
- Best performance: client avoids round-trip for partition resolution.
- Server can validate and optimize scans.
- DBSPJ support feasible.

**Cons**:
- Most complex: range metadata maintained in two places.
- Client and server must stay in sync during ALTER TABLE.

---

## 4. Recommendation

**Option A (New RANGE_PARTITION method in DBDIH)** is recommended as the
primary approach, with client-side optimization added incrementally:

### Rationale

1. **Server-side is essential**: DBSPJ support requires server-side range
   resolution. Scan pruning requires server-side range knowledge.

2. **Clean architecture**: Follows the same pattern as `HASH_MAP` -- a shared
   data structure (`Range2FragmentMap` like `Hash2FragmentMap`) accessed via
   RCU in the hot path.

3. **NDB API as-is**: The user stated the API should work "as-is except for
   metadata changes." If the server resolves ranges, the API just needs to
   pass the partition key value instead of a hash. The existing
   `distr_key_indicator` + `hashValue` mechanism can carry this.

4. **Incremental client-side**: Once server-side works, add client-side
   range resolution as an optimization to avoid the (intra-node) DBTC->DBDIH
   call overhead. But DBTC and DBDIH communicate via direct function call,
   so this overhead is small.

### Key Design Decisions Needed

1. **Single-column vs multi-column range keys**: Start with single-column
   INT/BIGINT? The Uint32 `hashValue` field limits us to 32-bit values unless
   we widen `DiGetNodesReq` or use a different encoding.

2. **Range boundary encoding**: Simple sorted array (binary search) vs actual
   binary tree nodes. A sorted array is simpler and more cache-friendly.

3. **ALTER TABLE mechanics**: How to atomically update `Range2FragmentMap`
   during ADD/DROP PARTITION while concurrent operations are in flight. The
   existing RCU pattern (`NdbSeqLock` on `TabRecord`) should work.

4. **Integration with ha_ndbcluster**: Extend the existing `RangeListData`
   path or create a separate metadata path?

---

## 5. Phased Implementation Plan (High-Level)

### Phase 1: Metadata & Basic Infrastructure
- Add `RangePartition` to `DictTabInfo::FragmentType` and `NdbDictionary::Object::FragmentType`
- Add `RANGE_PARTITION` to `TabRecord::Method`
- Define `Range2FragmentMap` structure
- DBDICT: store/retrieve range boundaries in table metadata
- CREATE TABLE with RANGE partitioning creates `Range2FragmentMap`

### Phase 2: DBDIH Range Lookup
- Implement range binary search in `execDIGETNODESREQ`
- DBTC: extract partition key value for range tables (new code path in `hash()`)
- Basic PK operations work on range-partitioned tables

### Phase 3: Scan Support
- DBTC scan operation: iterate all fragments (no pruning initially)
- Add scan pruning: when bounds are known, only scan relevant fragments

### Phase 4: ALTER TABLE (ADD/DROP PARTITION)
- ALTER TABLE ADD PARTITION: extend `Range2FragmentMap`, add new fragment
- ALTER TABLE DROP PARTITION: remove first range entry, drop fragment
- Handle concurrent operations during reorganization

### Phase 5: DBSPJ Support
- Extend DBSPJ to use range-based routing for pushed-down joins

### Phase 6: NDB API Client-Side Optimization (Optional)
- Client-side range resolution for reduced latency
- Partition pruning at API level

---

## 6. Appendix: Key File Locations

| File | Lines | Content |
|------|-------|---------|
| `storage/ndb/include/kernel/signaldata/DictTabInfo.hpp` | 209-219 | `FragmentType` enum |
| `storage/ndb/include/kernel/signaldata/DiGetNodes.hpp` | 66-94 | `DiGetNodesReq` signal |
| `storage/ndb/include/ndbapi/NdbDictionary.hpp` | 177-187 | API `FragmentType` enum |
| `storage/ndb/src/kernel/vm/SimulatedBlock.hpp` | 2757-2767 | `Hash2FragmentMap` struct |
| `storage/ndb/src/kernel/blocks/dbdih/Dbdih.hpp` | 266-296 | `Fragmentstore` struct |
| `storage/ndb/src/kernel/blocks/dbdih/Dbdih.hpp` | 664-847 | `TabRecord` struct |
| `storage/ndb/src/kernel/blocks/dbdih/Dbdih.hpp` | 711-717 | `Method` enum |
| `storage/ndb/src/kernel/blocks/dbdih/DbdihMain.cpp` | 15654-15915 | `execDIGETNODESREQ` |
| `storage/ndb/src/kernel/blocks/dbdih/DbdihMain.cpp` | 12791-12955 | `execCREATE_FRAGMENTATION_REQ` |
| `storage/ndb/src/kernel/blocks/dbdih/DbdihMain.cpp` | 13900-13928 | Method assignment from FragmentType |
| `storage/ndb/src/kernel/blocks/dbtc/DbtcMain.cpp` | 3141-3207 | `hash()` function |
| `storage/ndb/src/kernel/blocks/dbtc/DbtcMain.cpp` | 4710-4800 | `DiGetNodesReq` preparation |
| `storage/ndb/src/kernel/blocks/dbtc/Dbtc.hpp` | 1641-1716 | DBTC `TableRecord` |
| `storage/ndb/src/kernel/blocks/dbspj/DbspjMain.cpp` | 5643-5680 | DBSPJ `getNodes()` |
| `storage/ndb/src/ndbapi/NdbDictionary.cpp` | 759-782 | `getPartitionId()` |
| `storage/ndb/src/ndbapi/NdbDictionaryImpl.hpp` | 200-270 | `NdbTableImpl` fields |
| `storage/ndb/plugin/ha_ndbcluster.cc` | 15410-15448 | MySQL range partition setup |
| `storage/ndb/include/kernel/signaldata/CreateFragmentation.hpp` | 33-66 | `CreateFragmentationReq` |
