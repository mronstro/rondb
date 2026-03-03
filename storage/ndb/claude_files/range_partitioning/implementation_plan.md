# RANGE Partitioning — Phased Implementation Plan

Reference: `option_a_detailed.md` for full architectural details.

All file paths below are relative to `storage/ndb/`.

---

## Phase 1: Core Infrastructure — Fixed-Size PK Operations

**Goal**: CREATE TABLE with RANGE partitioning works. PK lookups and full
table scans work for fixed-size partition key types (INT, BIGINT, DATE,
DATETIME, TIMESTAMP). No ALTER TABLE, no scan pruning, no DBSPJ, no
transaction hinting.

### Step 1.1: Enum Additions

**`include/kernel/signaldata/DictTabInfo.hpp`**
- Add `RangePartition = 10` to `FragmentType` enum (after `HashMapPartition = 9`)
- Add attribute key `RangeBoundaryType = 166` to the attribute map
- Add `RangeBoundaryType` field to `DictTabInfo::Table` struct

**`include/ndbapi/NdbDictionary.hpp`**
- Add `RangePartition = 10` to `NdbDictionary::Object::FragmentType` enum

**`src/common/debugger/signaldata/DictTabInfo.cpp`**
- Add `RangeBoundaryType` to `TableMapping[]` array (DTI_MAP_INT)

### Step 1.2: Range2FragmentMap Structure

**`src/kernel/vm/SimulatedBlock.hpp`** (new struct, alongside Hash2FragmentMap)
- Define `Range2FragmentMap` struct:
  - Header: `m_cnt`, `m_boundary_len`, `m_boundary_type`, `m_num_columns`,
    `m_object_id`
  - Accessor methods: `frag_ids()`, `boundaries()`, `boundary(i)`,
    static `alloc_size(cnt, blen)`
  - Variable-length frag_id and boundary arrays follow header in same
    allocation (no embedded fixed-size arrays)
- Define `range_compare()` — type-aware comparison (NOT memcmp):
  - Switch on `m_boundary_type` (NDB_TYPE_INT, NDB_TYPE_BIGINT,
    NDB_TYPE_UNSIGNED, NDB_TYPE_BIGUNSIGNED, NDB_TYPE_DATE,
    NDB_TYPE_DATETIME, NDB_TYPE_TIMESTAMP, NDB_TYPE_DATETIME2,
    NDB_TYPE_TIMESTAMP2)
  - Cast to native integer type, compare with `<` / `>`
  - `ndbassert` on unsupported types (VARCHAR etc. deferred to Phase 5)
- Define `range_lookup()` — binary search using `range_compare()`

**No pool declaration** — allocated via `lc_ndbd_pool_malloc`, freed via
`lc_ndbd_pool_free`.

### Step 1.3: DiGetNodesReq Extension

**`include/kernel/signaldata/DiGetNodes.hpp`**
- Add to `DiGetNodesReq`:
  ```cpp
  union {
    const void *rangeKeyPtr;       // pointer to partition key bytes
    Uint32 rangeKeyStorage[2];     // alignment padding
  };
  Uint32 rangeKeyLen;              // length in bytes
  ```
- Update `SignalLength` constant
- These fields only valid via EXECUTE_DIRECT (never sent over wire)

### Step 1.4: DBDIH — TabRecord and Method Assignment

**`src/kernel/blocks/dbdih/Dbdih.hpp`**
- Add `RANGE_PARTITION = 5` to `TabRecord::Method` enum
- Add fields to `TabRecord`:
  ```cpp
  Range2FragmentMap *m_range_ptr;      // current range map
  Range2FragmentMap *m_new_range_ptr;  // during ALTER TABLE (nullptr normally)
  ```
- Initialize both to `nullptr` in TabRecord constructor/init

**`src/kernel/blocks/dbdih/DbdihMain.cpp`**

*execCREATE_FRAGMENTATION_REQ* (around line 12831):
- Add `case DictTabInfo::RangePartition:` — set
  `use_specific_fragment_count = true`, require `noOfFragments > 0`

*Method assignment* (around line 13922):
- Add `case DictTabInfo::RangePartition:` — set
  `tabPtr.p->method = TabRecord::RANGE_PARTITION`, store range map pointer

*execDIGETNODESREQ* (around line 15754):
- Add `else if (method == TabRecord::RANGE_PARTITION)` branch:
  - Read `rangeKeyPtr` and `rangeKeyLen` from the signal
  - Call `range_lookup(m_range_ptr, rangeKey, rangeKeyLen)`
  - If `m_new_range_ptr != nullptr`, also look up in new map (ALTER support)
  - Assign `fragId`

### Step 1.5: DBDICT — Range Map Creation

**`src/kernel/blocks/dbdict/Dbdict.cpp`**

*In `createTable_parse()` or `handleTabInfoInit()`:*
- When `FragmentType == RangePartition`:
  - Read `RangeListData[]` and `RangeListDataLen` from `DictTabInfo::Table`
  - Read `RangeBoundaryType` to determine column type and boundary byte length
  - Validate: boundary type must be a supported fixed-size type (Phase 1)
  - Validate: partition columns marked as DKey, and are part of primary key
  - Compute `alloc_size = Range2FragmentMap::alloc_size(nPartitions, blen)`
  - Call `lc_ndbd_pool_malloc(alloc_size, RG_SCHEMA_MEMORY, getThreadId(), true)`
  - Populate header fields, copy boundaries from `RangeListData[]`, assign
    sequential `frag_ids` (0, 1, 2, ...)
  - Store pointer for passing to DBDIH

*In `create_fragmentation()` (around line 6862):*
- For `RangePartition`: do NOT look up hashMapObjectId. Instead pass the
  `Range2FragmentMap*` pointer and fragment count to DBDIH.

*In `createTab_dih()` (sends DIADDTABREQ to DBDIH, around line 7723):*
- Pass the range map pointer to DBDIH (pointer-in-signal, same node)

*In DROP TABLE:*
- Call `lc_ndbd_pool_free()` on the range map when table is dropped

### Step 1.6: DBTC — Partition Key Extraction

**`src/kernel/blocks/dbtc/Dbtc.hpp`**
- Add `TR_RANGE_PARTITION = (1 << 9)` to `TableRecord` flags enum
- Add member `Uint32 c_range_key_buf[MAX_KEY_SIZE_IN_WORDS]` to `Dbtc` class
- Add to `CacheRecord`:
  ```cpp
  const char *m_range_key_ptr;  // pointer to extracted partition key
  Uint32 m_range_key_len;       // length in bytes
  ```

**`src/kernel/blocks/dbtc/DbtcMain.cpp`**

*In `execTC_SCHVERREQ()` (around line 1026):*
- Set `TR_RANGE_PARTITION` flag when `tabPtr.p->fragmentType == RangePartition`
  (either add `rangePartition` field to `TcSchVerReq` or derive from
  the fragment type stored in `KeyDescriptor` / table metadata)

*In `hash()` (around line 3141):*
- After computing `rondb_calc_hash` for LQH/DBACC (always needed):
- If `TR_RANGE_PARTITION`:
  - Extract partition key columns via `create_distr_key()` into
    `c_range_key_buf`
  - If table has char attrs or var keys, use xfrm'd data from
    `handle_special_hash()` workspace as input to `create_distr_key()`
  - Store pointer and length in `regCachePtr->m_range_key_ptr/len`
  - Set `tdistrHashValue = 0` (not meaningful for range tables)
- Else: existing hash-based distribution logic unchanged

*In DiGetNodesReq preparation (around line 4776):*
- If `TR_RANGE_PARTITION`:
  - Set `req->rangeKeyPtr = regCachePtr->m_range_key_ptr`
  - Set `req->rangeKeyLen = regCachePtr->m_range_key_len`
  - Set `req->distr_key_indicator = 0` (DBDIH uses range lookup, not
    direct fragId)

### Step 1.7: TcSchVerReq / CreateTab Signal

**`include/kernel/signaldata/CreateTab.hpp`**
- Add field `rangePartition` to `TcSchVerReq` (Uint32), increment
  `SignalLength` from 16 to 17
- OR: reuse the `userDefinedPartition` field with a different value
  (e.g., 0 = normal, 1 = user-defined, 2 = range). This avoids signal
  length change but conflates two concepts.
- Prefer separate field for clarity.

**`src/kernel/blocks/dbdict/Dbdict.cpp`**
- In the two locations where `TcSchVerReq` is sent to DBTC and DBSPJ
  (around lines 8034 and 8299):
  - Set `req->rangePartition = (tabPtr.p->fragmentType == DictTabInfo::RangePartition)`

### Step 1.8: NDB API Metadata

**`src/ndbapi/NdbDictionaryImpl.cpp`**
- In table metadata reception: accept `FragmentType::RangePartition`
  without error
- Store range boundaries in existing `m_range` vector (already populated
  from `RangeListData`)

**`src/ndbapi/NdbDictionary.cpp`**
- `getPartitionId()`: for `RangePartition`, return 0 (no hinting yet —
  Phase 6)

### Step 1.9: ha_ndbcluster (MySQL Integration)

**`plugin/ha_ndbcluster.cc`**
- In `create_table_set_up_partition_info()` (around line 15447):
  - Change: when `part_type == RANGE`, set
    `ndbtab.setFragmentType(NDBTAB::RangePartition)` instead of
    `NDBTAB::UserDefined`
  - Mark partition columns with `setPartitionKey(true)` (distribution key)
    so they get `AttributeDKey` flag. Currently RANGE tables do NOT mark
    partition columns as DKey — this must change.
  - Set `RangeBoundaryType` based on the partition expression column type
  - Convert range boundary values to NDB internal format (the existing
    Int32 conversion may need extension for BIGINT/DATE/DATETIME types)

### Step 1.10: Test Plan

- `CREATE TABLE t1 (d DATE, val INT, PRIMARY KEY(d, val)) PARTITION BY RANGE(d) (PARTITION p0 VALUES LESS THAN ('2025-01-01'), PARTITION p1 VALUES LESS THAN ('2025-07-01'), PARTITION p2 VALUES LESS THAN MAXVALUE)`
- INSERT rows spanning all partitions
- PK lookups: verify correct routing to expected fragments
- `SELECT * FROM t1` (full table scan): returns all rows
- INT partition key: `CREATE TABLE t2 (id INT, ...) PARTITION BY RANGE(id) (...)`
- BIGINT partition key: same pattern
- Negative test: INSERT with value exactly at boundary — goes to correct partition
- `DROP TABLE` — verify range map freed (no memory leak)
- Verify non-range tables still work (no regression)

---

## Phase 2: DBSPJ Support

**Goal**: Pushed-down joins work on range-partitioned tables. DBSPJ can
route lookups to the correct fragment using the range map.

**Dependency**: Phase 1 complete.

### Step 2.1: DBSPJ TableRecord Extension

**`src/kernel/blocks/dbspj/Dbspj.hpp`**
- Add `TR_RANGE_PARTITION = 1 << 8` to DBSPJ `TableRecord` enum
- DBSPJ TableRecord is simpler than DBTC's — it does not store
  `noOfDistrKeys`, `hasCharAttr`, etc. These come from the global
  `KeyDescriptor` pool.

### Step 2.2: DBSPJ TcSchVerReq Reception

**`src/kernel/blocks/dbspj/DbspjMain.cpp`**
- In `execTC_SCHVERREQ()` (around line 302):
  - Parse the new `rangePartition` field from `TcSchVerReq`
  - Set `TR_RANGE_PARTITION` flag on `tablePtr.p->m_flags`

### Step 2.3: DBSPJ getNodes() Extension

**`src/kernel/blocks/dbspj/DbspjMain.cpp`**
- In `getNodes()` (around line 5643):
  - Currently hardcodes `distr_key_indicator = 0` with comment
    "userDefinedPartitioning not supported!"
  - Add branch: if `TR_RANGE_PARTITION`:
    - Extract partition key from the key data using `create_distr_key()`
      (from `SimulatedBlock`, available to DBSPJ via inheritance)
    - Store in a local buffer
    - Set `req->rangeKeyPtr` and `req->rangeKeyLen`
    - Keep `req->distr_key_indicator = 0` (DBDIH dispatches via method)
  - Else: existing hash path unchanged

### Step 2.4: DBSPJ computeHash / computePartitionHash

**`src/kernel/blocks/dbspj/DbspjMain.cpp`**
- `computeHash()` and `computePartitionHash()` compute the hash that feeds
  into `getNodes()`. For range tables:
  - The LQH tuple hash is still needed (unchanged)
  - The partition key must be extracted separately for `rangeKeyPtr`
  - Either extend these functions to also extract the partition key,
    or do the extraction in `getNodes()` after the hash is computed

### Step 2.5: DBSPJ Buffer for Range Key

**`src/kernel/blocks/dbspj/Dbspj.hpp`**
- Add `Uint32 c_range_key_buf[MAX_KEY_SIZE_IN_WORDS]` to `Dbspj` class
  (or use a stack-local buffer in `getNodes()` since the key only needs
  to live until `EXECUTE_DIRECT` returns)

### Step 2.6: Test Plan

- CREATE range-partitioned table with foreign key or join target
- Execute pushed-down join (`ndb_join_pushdown = ON`)
- Verify DBSPJ routes to correct fragment (check via `ndbinfo.operations_per_fragment`)
- Compare query results with non-pushed join (must be identical)
- Test with different fixed-size partition key types

---

## Phase 3: ALTER TABLE ADD/DROP PARTITION

**Goal**: Support `ALTER TABLE ADD PARTITION` at end of range and
`ALTER TABLE DROP PARTITION` of first partition. RCU-safe swap of
range maps during concurrent operations.

**Dependency**: Phase 1 complete.

### Step 3.1: DBDICT ALTER TABLE Handling

**`src/kernel/blocks/dbdict/Dbdict.cpp`**

*ADD PARTITION:*
- When processing ALTER TABLE ADD PARTITION for a range table:
  - Parse the new partition definition (boundary value, partition name)
  - Validate: new boundary must be > all existing boundaries (add at end)
  - Allocate new `Range2FragmentMap` via `lc_ndbd_pool_malloc` with
    `cnt = old_cnt + 1`
  - Copy existing boundaries, add new boundary, update catch-all last entry
  - Assign new `frag_id` for the new partition
  - Send `ALTER_TAB_REQ` to DBDIH with new map pointer and `AddFragFlag`

*DROP PARTITION:*
- Validate: only first partition can be dropped
- Allocate new `Range2FragmentMap` with `cnt = old_cnt - 1`
- Copy boundaries [1..old_cnt-1], shift frag_ids
- Send `ALTER_TAB_REQ` to DBDIH with new map pointer and `DropFragFlag`

### Step 3.2: DBDIH ALTER_TAB_REQ Handling

**`src/kernel/blocks/dbdih/DbdihMain.cpp`**

*AlterTablePrepare* (around line 14667):
- For range tables with `AddFragFlag`:
  - Call `add_fragments_to_table()` to create new fragment
  - Store new range map in `m_new_range_ptr`
- For range tables with drop:
  - Store new range map in `m_new_range_ptr`

*AlterTableCommit:*
- Under `NdbSeqLock` write lock on TabRecord:
  - Save `old_ptr = m_range_ptr`
  - Swap: `m_range_ptr = m_new_range_ptr`
  - Set `m_new_range_ptr = nullptr`
  - Update `totalfragments`, `partitionCount`

*AlterTableComplete:*
- After all in-flight operations drain:
  - `lc_ndbd_pool_free(old_ptr)`
- For DROP: call `drop_fragments()` to remove the fragment and its data

### Step 3.3: Dual-Map Lookup During Transition

Already handled in Phase 1 (Section 5.2 of architecture): if
`m_new_range_ptr != nullptr`, DBDIH does a second lookup in the new map
and sets `newFragId` if different. This handles in-flight operations during
the ALTER transition period.

### Step 3.4: ha_ndbcluster ALTER TABLE Wiring

**`plugin/ha_ndbcluster.cc`**
- Wire MySQL's `ALTER TABLE ... ADD PARTITION` for range NDB tables to
  send the appropriate signals
- Wire `ALTER TABLE ... DROP PARTITION` for the first partition only
- Error if user tries to drop a non-first partition or add a non-last partition

### Step 3.5: Test Plan

- CREATE TABLE with 3 range partitions
- INSERT data into all partitions
- ALTER TABLE ADD PARTITION at end — verify new partition works
- INSERT into new partition — verify routing
- Verify existing data unchanged
- ALTER TABLE DROP PARTITION (first) — verify data gone
- Concurrent test: run PK lookups during ALTER, verify no errors
- Full table scan after ALTER — correct results
- Multiple sequential ADD + DROP operations

---

## Phase 4: Scan Pruning

**Goal**: When a scan has WHERE conditions on the partition column, only
scan the relevant fragment(s) instead of all fragments.

**Dependency**: Phase 1 complete. Phase 2 (DBSPJ) desirable but not required.

### Step 4.1: Determine Prunable Scans

A scan can be pruned when the WHERE clause constrains the partition column:
- **Equality**: `WHERE date_col = X` → single fragment
- **Range**: `WHERE date_col BETWEEN X AND Y` → subset of fragments
- **Open range**: `WHERE date_col > X` → suffix of fragments
- **Less than**: `WHERE date_col < X` → prefix of fragments

The scan bounds are already extracted by the NDB API (for ordered index
scans) or by MySQL's condition pushdown.

### Step 4.2: Range Map Query Function

**`src/kernel/vm/SimulatedBlock.hpp`** (or new file)
- Add function: `range_get_fragments(map, low_bound, high_bound, inclusive_flags) → (first_frag_idx, last_frag_idx)`
- Binary search for low bound → first fragment that could contain matching rows
- Binary search for high bound → last fragment
- Return the contiguous range of fragment indices to scan

### Step 4.3: Client-Side Pruning (NDB API)

**`src/ndbapi/NdbScanOperation.cpp`** or **`NdbScanFilter.cpp`**
- When opening a scan on a range-partitioned table:
  - If scan bounds are available and include the partition column:
    - Query the range boundaries stored in `NdbTableImpl::m_range`
    - Determine fragment subset
    - Set the fragment list in the scan request (existing mechanism for
      partition pruning)

### Step 4.4: Server-Side Pruning (DBTC)

**`src/kernel/blocks/dbtc/DbtcMain.cpp`**
- In scan fragment iteration (`sendDihGetNodesLab`, around line 16606):
  - If range table and scan bounds known, skip fragments outside the range
  - This is more complex and may not be needed if client-side pruning
    handles most cases

### Step 4.5: Test Plan

- CREATE range-partitioned table with many partitions
- `EXPLAIN` queries with partition column conditions — verify pruning
- Verify `ndbinfo.operations_per_fragment` shows only relevant fragments scanned
- Compare query results: pruned vs full scan must match
- Edge cases: boundary values, NULL handling, MAXVALUE partition

---

## Phase 5: Variable-Size Boundaries (Tier 2)

**Goal**: Support VARCHAR and other variable-length column types as range
partition keys. Requires a different memory structure since boundary data
can reach several MBytes.

**Dependency**: Phase 1 complete.

### Step 5.1: B-Tree Node Structure

**`src/kernel/vm/SimulatedBlock.hpp`** (or new header)
- Define `RangeTreeNode` struct:
  ```
  struct RangeTreeNode {
    Uint32 m_cnt;                     // entries in this node
    Uint32 m_is_leaf;                 // 1 if leaf, 0 if internal
    // For leaf nodes:
    //   m_frag_ids[i] — fragment ID for range i
    // For internal nodes:
    //   m_children[i] — pointer to child RangeTreeNode
    // Boundary values stored inline after the fixed header
    // Each boundary is variable-length with a length prefix
  };
  ```
- Each node allocated separately via `lc_ndbd_pool_malloc`
- Node size chosen to fit comfortably in one allocation (~4KB-16KB)
- K (fanout) = floor(node_size / max_boundary_len)

### Step 5.2: Root Structure

- `Range2FragmentMap` gets an additional field or variant:
  - `m_is_tree` flag to distinguish flat array (Tier 1) from B-tree (Tier 2)
  - If tree: `m_root_node` pointer to root `RangeTreeNode`
- `range_lookup()` dispatches based on `m_is_tree`

### Step 5.3: Tree Construction

**`src/kernel/blocks/dbdict/Dbdict.cpp`**
- When creating a range map with variable-size boundaries:
  - Determine max boundary length (from xfrm'd boundary data)
  - Choose K (fanout per node)
  - Build bottom-up: create leaf nodes with frag_ids, then internal levels
  - Each level via `lc_ndbd_pool_malloc`

### Step 5.4: Tree Lookup

- Traverse from root, binary search within each node (using `memcmp` on
  xfrm'd bytes — correct for collation-transformed strings)
- Follow child pointer to next level
- At leaf: return frag_id

### Step 5.5: Tree Deallocation

- On DROP TABLE or ALTER TABLE: walk all nodes, `lc_ndbd_pool_free` each
- Must be done after all readers drain (RCU)

### Step 5.6: ha_ndbcluster Extension

**`plugin/ha_ndbcluster.cc`**
- Extend boundary conversion to handle VARCHAR values
- Store xfrm'd (collation-transformed) boundary bytes in `RangeListData`
- Set `RangeBoundaryType` to the VARCHAR type

### Step 5.7: range_compare Extension

**`src/kernel/vm/SimulatedBlock.hpp`**
- For string types in tree nodes: use `memcmp` on xfrm'd bytes (correct
  since xfrm output is designed for byte-order comparison)
- For mixed multi-column keys: compare column by column

### Step 5.8: Test Plan

- `CREATE TABLE t (name VARCHAR(100), id INT, PRIMARY KEY(name, id)) PARTITION BY RANGE(name) (...)`
- Test with various collations (utf8mb4, latin1)
- Verify boundary comparison respects collation ordering
- Verify memory allocation/deallocation (no leaks)
- Large number of partitions with long VARCHAR boundaries — stress memory

---

## Phase 6: NDB API Transaction Hinting

**Goal**: `startTransaction()` picks the optimal TC node by resolving
the range partition locally in the NDB API, avoiding an extra network hop.

**Dependency**: Phase 1 complete. Phase 5 if VARCHAR hinting is needed.

### Step 6.1: Client-Side Range Map

**`src/ndbapi/NdbDictionaryImpl.hpp`**
- `NdbTableImpl` already has `m_range` vector (populated from `RangeListData`)
- Add: `m_range_boundary_type` (Uint32) for the column type
- Add: `m_range_boundary_len` (Uint32) for fixed-size types

### Step 6.2: getPartitionId() for Range Tables

**`src/ndbapi/NdbDictionary.cpp`**
- In `getPartitionId()` (around line 759):
  - Add `case RangePartition:` — extract partition key value from the
    key record, do binary search on `m_range` boundaries using
    type-aware comparison (same `range_compare` logic as server)
  - Return the fragment ID

### Step 6.3: startTransaction() Hinting

**`src/ndbapi/Ndb.cpp`**
- In `startTransaction()` (around line 641):
  - For range tables: call `getPartitionId()` with the key data
  - Use the fragment ID to pick the TC node closest to the data
  - This is the existing mechanism — just needs `getPartitionId()` to
    return the correct fragment for range tables

### Step 6.4: Test Plan

- Benchmark: PK lookups with and without hinting
- Verify `startTransaction()` picks the node owning the fragment
- Multi-node cluster: verify reduced network hops
- Verify hinting works for all fixed-size types
- If Phase 5 done: verify hinting for VARCHAR partition keys

---

## Phase 7: Scan Pruning in DBSPJ

**Goal**: Pushed-down joins that include range conditions on the partition
column prune to the relevant fragment(s).

**Dependency**: Phase 2 (DBSPJ basic support) and Phase 4 (scan pruning
infrastructure) complete.

### Step 7.1: DBSPJ Scan Bounds Awareness

**`src/kernel/blocks/dbspj/DbspjMain.cpp`**
- When DBSPJ performs a scan as part of a pushed-down join:
  - If the table is range-partitioned and the join condition constrains
    the partition column:
    - Use `range_get_fragments()` to determine the fragment subset
    - Scan only those fragments

### Step 7.2: Test Plan

- Pushed-down join with range condition on partition column
- Verify only relevant fragments are scanned
- Compare results with full scan (must be identical)

---

## Phase Summary

| Phase | Description | Partition Key Types | Key Deliverable |
|-------|-------------|--------------------|--------------------|
| 1 | Core infrastructure | INT, BIGINT, DATE, DATETIME, TIMESTAMP | PK lookups + full scans work |
| 2 | DBSPJ support | (same as Phase 1) | Pushed-down joins work |
| 3 | ADD/DROP PARTITION | (same as Phase 1) | ALTER TABLE works |
| 4 | Scan pruning | (same as Phase 1) | Scans skip irrelevant fragments |
| 5 | Variable-size boundaries | VARCHAR, CHAR, multi-column | B-tree range map, string partitions |
| 6 | NDB API transaction hinting | (all supported types) | Optimal TC node selection |
| 7 | DBSPJ scan pruning | (all supported types) | Pushed joins prune fragments |

### Dependency Graph

```
Phase 1 (Core)
  ├──> Phase 2 (DBSPJ)
  │      └──> Phase 7 (DBSPJ Scan Pruning) ←── Phase 4
  ├──> Phase 3 (ADD/DROP PARTITION)
  ├──> Phase 4 (Scan Pruning)
  ├──> Phase 5 (Variable-Size / Tier 2)
  └──> Phase 6 (NDB API Hinting)
```

Phases 2-6 can be done in any order after Phase 1. Phase 7 requires both
Phase 2 and Phase 4.

---

## Files Changed Per Phase

### Phase 1 (13 files)

| # | File | Change |
|---|------|--------|
| 1 | `include/kernel/signaldata/DictTabInfo.hpp` | `RangePartition` enum + `RangeBoundaryType` attr |
| 2 | `include/ndbapi/NdbDictionary.hpp` | `RangePartition` enum |
| 3 | `src/common/debugger/signaldata/DictTabInfo.cpp` | `RangeBoundaryType` in TableMapping |
| 4 | `src/kernel/vm/SimulatedBlock.hpp` | `Range2FragmentMap`, `range_compare()`, `range_lookup()` |
| 5 | `include/kernel/signaldata/DiGetNodes.hpp` | `rangeKeyPtr`, `rangeKeyLen` in DiGetNodesReq |
| 6 | `src/kernel/blocks/dbdih/Dbdih.hpp` | `RANGE_PARTITION` method, `m_range_ptr` fields |
| 7 | `src/kernel/blocks/dbdih/DbdihMain.cpp` | Range branch in DIGETNODESREQ, CREATE_FRAG_REQ, method assignment |
| 8 | `src/kernel/blocks/dbdict/Dbdict.cpp` | Range map allocation, RangeListData parsing, CREATE TABLE flow |
| 9 | `src/kernel/blocks/dbtc/Dbtc.hpp` | `TR_RANGE_PARTITION` flag, range key fields |
| 10 | `src/kernel/blocks/dbtc/DbtcMain.cpp` | `hash()` range path, DiGetNodesReq population, TcSchVerReq handling |
| 11 | `include/kernel/signaldata/CreateTab.hpp` | `rangePartition` field in TcSchVerReq |
| 12 | `src/ndbapi/NdbDictionaryImpl.cpp` | Accept `RangePartition` fragment type |
| 13 | `plugin/ha_ndbcluster.cc` | `RangePartition` type, DKey on partition columns, boundary conversion |

### Phase 2 (2 files)

| # | File | Change |
|---|------|--------|
| 1 | `src/kernel/blocks/dbspj/Dbspj.hpp` | `TR_RANGE_PARTITION` flag, key buffer |
| 2 | `src/kernel/blocks/dbspj/DbspjMain.cpp` | TcSchVerReq handling, getNodes() range path, key extraction |

### Phase 3 (3 files)

| # | File | Change |
|---|------|--------|
| 1 | `src/kernel/blocks/dbdict/Dbdict.cpp` | ALTER TABLE range map creation (ADD/DROP) |
| 2 | `src/kernel/blocks/dbdih/DbdihMain.cpp` | ALTER_TAB_REQ with range map swap, add/drop fragments |
| 3 | `plugin/ha_ndbcluster.cc` | Wire ALTER TABLE ADD/DROP PARTITION for range tables |

### Phase 4 (2-3 files)

| # | File | Change |
|---|------|--------|
| 1 | `src/kernel/vm/SimulatedBlock.hpp` | `range_get_fragments()` function |
| 2 | `src/ndbapi/NdbScanOperation.cpp` | Client-side scan pruning for range tables |
| 3 | `src/kernel/blocks/dbtc/DbtcMain.cpp` | (optional) Server-side scan fragment skip |

### Phase 5 (4 files)

| # | File | Change |
|---|------|--------|
| 1 | `src/kernel/vm/SimulatedBlock.hpp` | `RangeTreeNode`, tree lookup, tree dealloc |
| 2 | `src/kernel/blocks/dbdict/Dbdict.cpp` | B-tree construction from variable-size boundaries |
| 3 | `src/kernel/blocks/dbdih/DbdihMain.cpp` | (minimal: `range_lookup` already dispatches) |
| 4 | `plugin/ha_ndbcluster.cc` | VARCHAR boundary conversion + xfrm |

### Phase 6 (3 files)

| # | File | Change |
|---|------|--------|
| 1 | `src/ndbapi/NdbDictionaryImpl.hpp` | Range boundary type/len fields |
| 2 | `src/ndbapi/NdbDictionary.cpp` | `getPartitionId()` with range binary search |
| 3 | `src/ndbapi/Ndb.cpp` | (minimal: existing hinting already calls getPartitionId) |

### Phase 7 (1 file)

| # | File | Change |
|---|------|--------|
| 1 | `src/kernel/blocks/dbspj/DbspjMain.cpp` | Scan pruning in pushed-down joins |
