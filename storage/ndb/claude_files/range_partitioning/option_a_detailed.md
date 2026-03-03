# Option A: Detailed Architecture - RANGE Partitioning in RonDB

## Table of Contents

1. [Design Overview](#1-design-overview)
2. [Range2FragmentMap Structure](#2-range2fragmentmap-structure)
3. [Partition Key Passing to DBDIH](#3-partition-key-passing-to-dbdih)
4. [DBDICT Changes](#4-dbdict-changes)
5. [DBDIH Changes](#5-dbdih-changes)
6. [DBTC Changes](#6-dbtc-changes)
7. [NDB API Changes](#7-ndb-api-changes)
8. [Scan Operations](#8-scan-operations)
9. [ALTER TABLE: ADD/DROP PARTITION](#9-alter-table-adddrop-partition)
10. [DBSPJ Changes](#10-dbspj-changes)
11. [Concurrency and RCU](#11-concurrency-and-rcu)
12. [Upgrade and Compatibility](#12-upgrade-and-compatibility)
13. [Implementation Phases](#13-implementation-phases)

---

## 1. Design Overview

### 1.1 Core Idea

Add `RANGE_PARTITION` as a new partition method in DBDIH. Range boundaries are
stored in a `Range2FragmentMap` structure (analogous to `Hash2FragmentMap`)
allocated from a global pool. The DBDIH `execDIGETNODESREQ` receives the full
partition key, performs a binary search comparison against the range boundaries,
and maps to a fragment ID.

### 1.2 Supported Partition Key Types

The most common range partition types are:
- **DATE, DATETIME, TIMESTAMP** (stored as integers internally in NDB)
- **INT, BIGINT** (numeric types)
- **VARCHAR, CHAR** (string types, requires collation-aware comparison)
- **Multi-column** (future: RANGE COLUMNS)

The partition columns must be part of the primary key. Typically the full
primary key or a subset of it is used. This is the same constraint as for
hash-based distribution keys.

### 1.3 Value Flow (Primary Key Operation)

```
NDB API
  |-- sends TCKEYREQ with key columns as usual
  |-- does NOT compute any hash for distribution purposes
  |-- (hash computation for distribution is irrelevant for range tables)
  v
DBTC hash() [DbtcMain.cpp:3141]
  |-- computes rondb_calc_hash() for LQH/DBACC tuple placement (always needed)
  |-- extracts partition key columns from keyInfo using create_distr_key()
  |     pattern (same as existing distribution key extraction)
  |-- passes partition key bytes + length to DBDIH via DiGetNodesReq
  v
DBDIH execDIGETNODESREQ [DbdihMain.cpp:15654]
  |-- if method == RANGE_PARTITION:
  |     reads partition key from pointer in DiGetNodesReq
  |     binary search comparison against Range2FragmentMap boundaries
  |     -> fragId
  |-- getFragstore(fragId) -> replica nodes
  |-- Returns DiGetNodesConf{fragId, nodes[], instanceKey}
```

### 1.4 Key Design Principles

1. **DBTC always computes hash for LQH**: `rondb_calc_hash()` (xxhash-based
   for new tables, MD5 for old) produces the tuple hash that DBACC needs for
   hash-index placement within a fragment. This is independent of which
   fragment is selected.

2. **NDB API does NOT compute any hash for range tables**: The API sends key
   columns as before. It does not need to know about range partitioning at
   all for correctness. Transaction hinting (which TC to contact) works
   without range awareness initially -- this is a later optimization.

3. **DBTC extracts partition key using existing create_distr_key() pattern**:
   The `KeyDescriptor` + `AttributeDescriptor::getDKey()` mechanism already
   extracts specific columns from the primary key. For range tables, the
   partition key columns are marked as DKey columns.

4. **Full partition key passed to DBDIH**: Since `DiGetNodesReq` is called
   via `EXECUTE_DIRECT` (same thread, same address space), DBTC can pass a
   pointer to the partition key buffer. DBDIH reads the key bytes and
   compares against range boundaries.

---

## 2. Range2FragmentMap Structure

### 2.1 Memory Allocation Strategy

**NOT an ArrayPool.** Unlike `Hash2FragmentMap` (which uses `ArrayPool` and
has a fixed ~46KB per entry), `Range2FragmentMap` uses `lc_ndbd_pool_malloc`
for dynamic allocation. The reason: with variable-size boundaries (VARCHAR),
the total boundary data can easily reach several MBytes, making a fixed
max-size ArrayPool entry impractical.

There are two tiers depending on boundary size:

**Tier 1: Fixed-size boundaries (≤ 8 bytes)**
Covers INT, BIGINT, DATE, DATETIME, TIMESTAMP — the most common range types.
- All boundaries have the same byte length
- Single `lc_ndbd_pool_malloc` allocation for the entire map
- Simple binary search with `memcmp` on a flat sorted array
- Max size: 8160 * 8 + 8160 * 2 + header ≈ 82KB — fits one allocation

**Tier 2: Variable-size boundaries (VARCHAR, multi-column)**
- Total boundary data can be MBytes (8160 partitions * hundreds of bytes each)
- Requires multiple `lc_ndbd_pool_malloc` allocations
- Smarter lookup structure: B-tree nodes in separately allocated pages
- Each B-tree node fits in a single allocation, contains N boundaries
  and child pointers, binary search within each node

### 2.2 Tier 1: Fixed-Size Range Map

For boundary sizes ≤ 8 bytes. Allocated as a single contiguous block via
`lc_ndbd_pool_malloc(size, RG_SCHEMA_MEMORY, getThreadId(), true)`.

```cpp
/**
 * Range2FragmentMap — fixed-size boundaries (≤ 8 bytes each).
 *
 * Allocated via lc_ndbd_pool_malloc, NOT ArrayPool.
 * Freed via lc_ndbd_pool_free.
 *
 * Layout in memory (single allocation):
 *   Header (m_cnt, m_boundary_len, m_boundary_type, ...)
 *   m_frag_id[m_cnt]        — Uint16 fragment IDs
 *   m_boundaries[m_cnt * m_boundary_len] — packed boundary values
 */
struct Range2FragmentMap {
  Uint32 m_cnt;              // number of partitions (= number of range entries)
  Uint32 m_boundary_len;     // byte length of each boundary (fixed, all same)
  Uint32 m_boundary_type;    // NDB attribute type of the partition key
  Uint32 m_num_columns;     // number of partition key columns (1 for Phase 1)
  Uint32 m_object_id;       // associated table object ID

  /**
   * Variable-length arrays follow the header in the same allocation.
   * Access via helper methods.
   *
   * Entry i is the EXCLUSIVE upper bound for partition i.
   * The last entry is the maximum possible value (catch-all).
   * m_frag_id[i] is the fragment ID for values in partition i.
   *
   * Lookup: binary search using memcmp to find first boundary > key.
   */

  Uint16 *frag_ids() {
    return reinterpret_cast<Uint16 *>(
      reinterpret_cast<char *>(this) + sizeof(Range2FragmentMap));
  }
  const Uint16 *frag_ids() const {
    return reinterpret_cast<const Uint16 *>(
      reinterpret_cast<const char *>(this) + sizeof(Range2FragmentMap));
  }

  char *boundaries() {
    // Aligned after frag_ids array (round up to 8-byte alignment)
    char *after_frags = reinterpret_cast<char *>(frag_ids() + m_cnt);
    Uint64 addr = reinterpret_cast<Uint64>(after_frags);
    addr = (addr + 7) & ~Uint64(7);
    return reinterpret_cast<char *>(addr);
  }
  const char *boundaries() const {
    const char *after_frags =
      reinterpret_cast<const char *>(frag_ids() + m_cnt);
    Uint64 addr = reinterpret_cast<Uint64>(after_frags);
    addr = (addr + 7) & ~Uint64(7);
    return reinterpret_cast<const char *>(addr);
  }

  const char *boundary(Uint32 i) const {
    return boundaries() + i * m_boundary_len;
  }

  /** Total allocation size needed for cnt partitions with blen-byte bounds */
  static Uint32 alloc_size(Uint32 cnt, Uint32 blen) {
    Uint32 sz = sizeof(Range2FragmentMap);
    sz += cnt * sizeof(Uint16);          // frag_ids
    sz = (sz + 7) & ~Uint32(7);         // align to 8
    sz += cnt * blen;                    // boundaries
    return sz;
  }
};
```

### 2.3 Tier 2: Variable-Size Range Map (Future)

For boundaries that exceed 8 bytes (VARCHAR, multi-column composite keys).
The total boundary data can reach several MBytes.

**Structure**: A B-tree where each node is a separate `lc_ndbd_pool_malloc`
allocation. Each node contains:
- Up to K boundaries (where K is chosen so a node fits in ~4KB-16KB)
- Child pointers (indices or pointers to child nodes)
- Binary search within each node narrows the search

**Header structure** (stored in TabRecord or a small root allocation):
```
RangeTreeRoot:
  m_cnt                  // total partitions
  m_root_node            // pointer to root B-tree node
  m_boundary_type        // NDB attribute type
  m_max_boundary_len     // maximum boundary length
  m_num_columns          // number of partition key columns
```

**Lookup**: Start at root, binary search within node to find child, follow
pointer, repeat until leaf. Leaf contains `m_frag_id`. For typical partition
counts (2-64 ranges), the tree is 1-2 levels deep.

Detailed design of Tier 2 is deferred to a later phase. Phase 1 implements
only Tier 1 (fixed-size boundaries ≤ 8 bytes), which covers the most common
range types: DATE, DATETIME, TIMESTAMP, INT, BIGINT.

### 2.4 Boundary Storage Format and Endianness

**Critical**: NDB stores data in **native endian** (little-endian on x86/ARM).
Both the NDB API and data nodes use the same endianness. This means raw
`memcmp` does **NOT** give correct ordering for multi-byte integer types on
little-endian machines, because `memcmp` compares bytes left-to-right
(most-significant-byte first), but little-endian stores the
least-significant byte first.

Range boundaries are stored as **native-endian values** — the same
representation used in the key columns of TCKEYREQ:

- **INT**: 4 bytes, native endian (little-endian on x86/ARM)
- **BIGINT**: 8 bytes, native endian
- **DATE**: stored as Uint32 (3 bytes used), native endian
- **DATETIME**: stored as Int64 (5 or 8 bytes used), native endian
- **TIMESTAMP**: stored as Uint32 (4 bytes), native endian
- **VARCHAR**: variable-length after xfrm (collation transform) — Tier 2

**Consequence**: The binary search comparison must be **type-aware** — cast
to the native integer type and compare with `<` / `>`, NOT `memcmp`.

For Tier 1 (fixed-size ≤ 8 bytes), this is straightforward: the boundary
type (`m_boundary_type`) determines how to interpret and compare the bytes.

### 2.5 Lookup Algorithm (Tier 1)

Since boundaries are native-endian, comparison is done by casting to the
appropriate native integer type based on `m_boundary_type`:

```cpp
/**
 * Compare a partition key value against a boundary value.
 * Both are in native endian format (NOT big-endian / network order).
 * Returns negative if bound < key, 0 if equal, positive if bound > key.
 */
static inline int range_compare(const char *bound, const char *key,
                                Uint32 boundary_type) {
  switch (boundary_type) {
    case NDB_TYPE_INT: {
      Int32 b = *reinterpret_cast<const Int32*>(bound);
      Int32 k = *reinterpret_cast<const Int32*>(key);
      return (b < k) ? -1 : (b > k) ? 1 : 0;
    }
    case NDB_TYPE_UNSIGNED: {
      Uint32 b = *reinterpret_cast<const Uint32*>(bound);
      Uint32 k = *reinterpret_cast<const Uint32*>(key);
      return (b < k) ? -1 : (b > k) ? 1 : 0;
    }
    case NDB_TYPE_BIGINT: {
      Int64 b = *reinterpret_cast<const Int64*>(bound);
      Int64 k = *reinterpret_cast<const Int64*>(key);
      return (b < k) ? -1 : (b > k) ? 1 : 0;
    }
    case NDB_TYPE_BIGUNSIGNED: {
      Uint64 b = *reinterpret_cast<const Uint64*>(bound);
      Uint64 k = *reinterpret_cast<const Uint64*>(key);
      return (b < k) ? -1 : (b > k) ? 1 : 0;
    }
    case NDB_TYPE_DATE:
    case NDB_TYPE_TIMESTAMP: {
      // Stored as Uint32 in native endian
      Uint32 b = *reinterpret_cast<const Uint32*>(bound);
      Uint32 k = *reinterpret_cast<const Uint32*>(key);
      return (b < k) ? -1 : (b > k) ? 1 : 0;
    }
    case NDB_TYPE_DATETIME:
    case NDB_TYPE_TIMESTAMP2:
    case NDB_TYPE_DATETIME2: {
      // Stored as Int64 in native endian
      Int64 b = *reinterpret_cast<const Int64*>(bound);
      Int64 k = *reinterpret_cast<const Int64*>(key);
      return (b < k) ? -1 : (b > k) ? 1 : 0;
    }
    default:
      ndbassert(false);  // Unsupported type for Tier 1
      return 0;
  }
}

/**
 * Binary search: find first entry where boundary[i] > partitionKey
 * @param map       Range map (Tier 1, fixed-size boundaries)
 * @param key       Partition key bytes (native endian)
 * @param key_len   Length of partition key in bytes
 * @return fragment ID
 */
Uint32 range_lookup(const Range2FragmentMap *map,
                    const char *key, Uint32 key_len) {
  Uint32 lo = 0;
  Uint32 hi = map->m_cnt;
  const Uint32 btype = map->m_boundary_type;

  while (lo < hi) {
    Uint32 mid = (lo + hi) >> 1;
    const char *bound = map->boundary(mid);
    int cmp = range_compare(bound, key, btype);
    if (cmp <= 0)   // boundary <= key, search right
      lo = mid + 1;
    else             // boundary > key, search left
      hi = mid;
  }
  // lo = index of first boundary > key = the partition for this key
  ndbassert(lo < map->m_cnt);  // last entry is MAX, always > any key
  return map->frag_ids()[lo];
}
```

For typical partition counts (2-64), this is 1-6 comparisons. The
`range_compare` function compiles to simple load + compare instructions
(no byte-swapping overhead).

### 2.6 Why NOT memcmp

`memcmp` would only work if values were stored in big-endian (network byte
order), but NDB uses **native endian** for both API and data node storage.
On little-endian machines (x86, ARM), `memcmp` gives incorrect results
for multi-byte integers because it compares the least-significant byte
first.

The type-aware `range_compare` function handles this correctly by casting
the raw bytes to the appropriate native integer type and using normal
comparison operators, which the CPU handles natively regardless of endianness.

For Tier 2 (variable-size string boundaries), `memcmp` on xfrm'd
(collation-transformed) byte sequences IS correct, since the xfrm output
is specifically designed to be byte-comparable.

### 2.7 Allocation and Lifetime

Created by DBDICT during CREATE TABLE via `lc_ndbd_pool_malloc` with
`RG_SCHEMA_MEMORY` pool. The pointer is stored in `TabRecord::m_range_ptr`
(a `Range2FragmentMap*`, not a pool index). Accessed by DBDIH under RCU
protection (`NdbSeqLock`). Freed via `lc_ndbd_pool_free` after all readers
have drained (during ALTER TABLE or DROP TABLE).

Since `lc_ndbd_pool_malloc` returns a direct pointer (not a pool index),
`TabRecord` stores `Range2FragmentMap *m_range_ptr` rather than
`Uint32 m_range_ptr_i`.

---

## 3. Partition Key Passing to DBDIH

### 3.1 The Challenge

The existing `DiGetNodesReq::hashValue` is a single Uint32, sufficient for
a hash value but not for arbitrary partition keys (which can be DATE, DATETIME,
BIGINT, or even VARCHAR). We need to pass the full partition key bytes to DBDIH.

### 3.2 Solution: Pointer in DiGetNodesReq

Since `execDIGETNODESREQ` is always called via `EXECUTE_DIRECT` (same thread,
same address space), we can safely pass a pointer. This is an established
pattern -- the signal already carries `void *jamBufferPtr`.

Extend `DiGetNodesReq` in `storage/ndb/include/kernel/signaldata/DiGetNodes.hpp`:

```cpp
class DiGetNodesReq {
  ...
  Uint32 tableId;
  Uint32 hashValue;              // existing: hash for non-range tables
  Uint32 distr_key_indicator;
  Uint32 scan_indicator;
  Uint32 get_next_fragid_indicator;
  Uint32 anyNode;
  Uint32 only_readable_nodes;
  union {
    void *jamBufferPtr;
    Uint32 jamBufferStorage[2];
  };
  // NEW: partition key for range-partitioned tables
  // Only valid when called via EXECUTE_DIRECT.
  // For non-range tables these are ignored.
  union {
    const void *rangeKeyPtr;       // pointer to partition key bytes
    Uint32 rangeKeyStorage[2];
  };
  Uint32 rangeKeyLen;              // length in bytes
};
```

`SignalLength` increases to accommodate the new fields. Since this signal is
only used via `EXECUTE_DIRECT` (never sent over the network), there is no
wire-format compatibility concern.

### 3.3 How DBTC Populates the Partition Key

DBTC extracts partition key columns from the full primary key using the same
mechanism as distribution key extraction (`create_distr_key()` in
`SimulatedBlock.cpp:4659`). This function:

1. Iterates over key attributes via `KeyDescriptor::keyAttr[]`
2. Checks `AttributeDescriptor::getDKey()` for each attribute
3. Copies DKey columns into a destination buffer

For range tables, the partition columns ARE the DKey columns (marked with
`AttributeDKey` flag in table schema). DBTC extracts them into a local buffer
and passes the pointer via `DiGetNodesReq::rangeKeyPtr`.

```
DBTC hash() flow for range tables:
  1. Copy keyInfo into linear buffer (existing code)
  2. rondb_calc_hash() for LQH tuple hash (existing, always needed)
  3. If range table:
     a. create_distr_key() -> extract partition key columns into workspace
     b. Set req->rangeKeyPtr = workspace
     c. Set req->rangeKeyLen = extracted_length
  4. Call c_dih->execDIGETNODESREQ(signal)
```

### 3.4 String Type Handling

For partition keys with CHAR/VARCHAR types that have collations:
- The `xfrm_key_hash()` function (already called in `handle_special_hash`)
  produces collation-normalized bytes
- The range boundaries in `Range2FragmentMap` are stored in the same
  normalized format
- Both key and boundaries use the same `memcmp`-comparable representation

---

## 4. DBDICT Changes

### 4.1 New FragmentType Enum

In `storage/ndb/include/kernel/signaldata/DictTabInfo.hpp`:
```cpp
enum FragmentType {
  AllNodesSmallTable = 0,
  AllNodesMediumTable = 1,
  AllNodesLargeTable = 2,
  SingleFragment = 3,
  DistrKeyHash = 4,
  DistrKeyLin = 5,
  UserDefined = 6,
  DistrKeyOrderedIndex = 8,
  HashMapPartition = 9,
  RangePartition = 10       // NEW
};
```

In `storage/ndb/include/ndbapi/NdbDictionary.hpp`:
```cpp
enum FragmentType {
  ...
  HashMapPartition = 9,
  RangePartition = 10       // NEW
};
```

### 4.2 Table Metadata

Reuse existing fields in `DictTabInfo::Table`:
- `RangeListData[]` / `RangeListDataLen`: stores the range boundary values
  (already exists, used by MySQL for RANGE/LIST partitions on NDB)
- `FragmentType = RangePartition`: distinguishes from the old `UserDefined`
  approach where MySQL computed the partition client-side

Add new field to `DictTabInfo::Table`:
```cpp
RangeBoundaryType = 166,    // NDB attribute type of the partition key column
```

No pool object ID needed since `Range2FragmentMap` uses `lc_ndbd_pool_malloc`
(direct pointer), not an ArrayPool with object IDs.

### 4.3 CREATE TABLE Flow

1. MySQL/API sends `CREATE_TAB_REQ` with:
   - `FragmentType = RangePartition`
   - `RangeListData[]` containing range boundaries in NDB key format
   - Partition columns marked with `AttributeDKey` flag

2. **DBDICT** (`Dbdict.cpp`):
   - Validates partition columns are part of primary key
   - Creates `Range2FragmentMap` via `lc_ndbd_pool_malloc`:
     - Computes `alloc_size(nPartitions, boundary_len)`
     - Parses `RangeListData[]` into boundaries
     - Determines `m_boundary_len` from column type
     - Assigns sequential `frag_ids[]` (0, 1, 2, ...)
   - Passes the `Range2FragmentMap*` pointer to DBDIH via signal
   - Sends `CREATE_FRAGMENTATION_REQ` to DBDIH

3. **DBDIH** assigns fragments to node groups and records
   `method = RANGE_PARTITION`, `m_range_ptr` pointing to the map.

### 4.4 Partition Column Identification

Reuse the existing **distribution key** (`DKey`) mechanism:
- Partition columns are marked with `AttributeDKey` flag in their attribute
  descriptors
- The `KeyDescriptor` (in `KeyDescriptor.hpp:37`) records `noOfDistrKeys`
- `create_distr_key()` (`SimulatedBlock.cpp:4659`) extracts DKey columns
  from the full primary key

This means: for a range-partitioned table with `PARTITION BY RANGE(date_col)`,
`date_col` is marked as both a primary key column and a distribution key
column. DBTC uses `create_distr_key()` to extract just the `date_col` value.

---

## 5. DBDIH Changes

### 5.1 TabRecord Extensions

In `storage/ndb/src/kernel/blocks/dbdih/Dbdih.hpp`:

```cpp
struct TabRecord {
  enum Method {
    LINEAR_HASH = 0,
    NOTDEFINED = 1,
    NORMAL_HASH = 2,
    USER_DEFINED = 3,
    HASH_MAP = 4,
    RANGE_PARTITION = 5   // NEW
  };

  // Existing:
  union {
    Uint32 mask;
    Uint32 m_map_ptr_i;
  };

  // NEW: range map pointers (direct pointers, NOT pool indices)
  // Allocated via lc_ndbd_pool_malloc, freed via lc_ndbd_pool_free
  Range2FragmentMap *m_range_ptr;      // current range map
  Range2FragmentMap *m_new_range_ptr;  // new map during ALTER TABLE (nullptr if none)
  // ... rest unchanged
};
```

### 5.2 execDIGETNODESREQ Extension

In `DbdihMain.cpp:15754`, after the `LINEAR_HASH` / `NORMAL_HASH` branches
and before the `USER_DEFINED` branch:

```cpp
} else if (tabPtr.p->method == TabRecord::RANGE_PARTITION) {
  thrjamDebug(jambuf);
  const Range2FragmentMap *rmap = tabPtr.p->m_range_ptr;
  ndbassert(rmap != nullptr);

  // Read partition key from the pointer passed by DBTC/DBSPJ
  const char *rangeKey = (const char *)req->rangeKeyPtr;
  Uint32 rangeKeyLen = req->rangeKeyLen;

  // Binary search through range boundaries
  fragId = range_lookup(rmap, rangeKey, rangeKeyLen);

  // Handle ALTER TABLE in progress
  const Range2FragmentMap *new_rmap = tabPtr.p->m_new_range_ptr;
  if (unlikely(new_rmap != nullptr)) {
    thrjam(jambuf);
    Uint32 newFrag = range_lookup(new_rmap, rangeKey, rangeKeyLen);
    if (newFrag != fragId) {
      thrjam(jambuf);
      newFragId = newFrag;
    }
  }
}
```

The `range_lookup()` function (Section 2.5) performs the binary search.
For Tier 1 (fixed-size boundaries), this is a simple `memcmp`-based search.
For Tier 2 (variable-size, future), it would traverse B-tree nodes.

### 5.3 execCREATE_FRAGMENTATION_REQ Extension

In `DbdihMain.cpp:12831`, add `RangePartition`:

```cpp
case DictTabInfo::RangePartition: {
  jam();
  use_specific_fragment_count = true;
  if (noOfFragments == 0) {
    jam();
    err = CreateFragmentationRef::InvalidFragmentationType;
  }
  break;
}
```

### 5.4 Method Assignment

At `DbdihMain.cpp:13922`. The `Range2FragmentMap*` pointer is passed from
DBDICT via the `DiAddTabReq` signal (using the pointer-in-signal pattern,
safe because `DIADDTABREQ` is sent within the same node):

```cpp
case DictTabInfo::RangePartition:
  jam();
  tabPtr.p->method = TabRecord::RANGE_PARTITION;
  tabPtr.p->m_range_ptr = req->rangeMapPtr;   // direct pointer
  tabPtr.p->m_new_range_ptr = nullptr;
  break;
```

### 5.5 No Pool Initialization Needed

Unlike `Hash2FragmentMap` which uses `ArrayPool` (requiring `g_hash_map.setSize()`),
`Range2FragmentMap` uses `lc_ndbd_pool_malloc` directly. No pool initialization
is needed — each map is individually malloc'd and free'd.

---

## 6. DBTC Changes

### 6.1 TableRecord Extension

In `storage/ndb/src/kernel/blocks/dbtc/Dbtc.hpp`:

```cpp
struct TableRecord {
  enum {
    ...
    TR_HASH_FUNCTION = (1 << 8),
    TR_RANGE_PARTITION = (1 << 9)    // NEW
  };
  // ... existing fields ...
};
```

### 6.2 hash() Modification

The hash function (`DbtcMain.cpp:3141`) must be modified for range tables:

1. **Always compute tuple hash**: `rondb_calc_hash()` is still called for LQH/DBACC
   (tuple placement within the fragment). The hash function is xxhash-based
   (`rondb_calc_hash` in `rondb_hash.hpp`), not MD5.

2. **Extract partition key**: Use `create_distr_key()` (in `SimulatedBlock.cpp:4659`)
   to extract partition key columns from the full primary key. This is the
   exact same mechanism used today when a table has distribution keys that
   differ from the full primary key. The partition key columns are marked
   with `AttributeDKey` flag.

3. **Pass partition key to DiGetNodesReq**: Store pointer and length in
   the extended DiGetNodesReq fields.

```cpp
void Dbtc::hash(Signal *signal, CacheRecord *const regCachePtr) {
  // ... existing key copy into Tdata32 ...

  Uint32 tmp[4];
  bool use_new_hash_function =
    ((tabPtrP->m_flags & TableRecord::TR_HASH_FUNCTION) != 0);

  if (!regCachePtr->m_special_hash) {
    rondb_calc_hash(tmp, (const char*)Tdata32, keylen, use_new_hash_function);
  } else {
    // ... existing handle_special_hash for collations etc ...
  }

  // Primary key hash -- always needed for LQH/DBACC
  thashValue = tmp[0];

  if (tabPtrP->m_flags & TableRecord::TR_RANGE_PARTITION) {
    jam();
    // For range-partitioned tables: extract partition key columns
    // using the same create_distr_key mechanism used for distribution keys.
    //
    // The partition key columns are the DKey columns. create_distr_key()
    // copies them from the (possibly xfrm'd) key data into workspace.
    //
    // tdistrHashValue is not meaningful for range tables but we set it
    // to 0 for clarity.
    tdistrHashValue = 0;

    // Extract partition key into regCachePtr or a local buffer
    // that will be referenced by DiGetNodesReq::rangeKeyPtr
    const Uint32 *hashInput = Tdata32;
    Uint32 *keyPartLenPtr = nullptr;

    // If special hash was used, hashInput already points to xfrm'd data
    if (regCachePtr->m_special_hash) {
      // hashInput and keyPartLenPtr were set by handle_special_hash
      // (they point to the workspace with xfrm'd key data)
    }

    // Extract partition key columns
    Uint32 pkeyLen = create_distr_key(regCachePtr->tableref,
                                       hashInput,
                                       c_range_key_buf,  // thread-local buffer
                                       keyPartLenPtr);
    // Store for DiGetNodesReq
    regCachePtr->m_range_key_ptr = (const char *)c_range_key_buf;
    regCachePtr->m_range_key_len = pkeyLen * 4;  // words to bytes
  } else if (distKey) {
    jam();
    tdistrHashValue = regCachePtr->distributionKey;
  } else {
    jamDebug();
    tdistrHashValue = tmp[1];
  }
}
```

### 6.3 DiGetNodesReq Preparation

In `DbtcMain.cpp:4776` where DiGetNodesReq is filled:

```cpp
DiGetNodesReq *const req = (DiGetNodesReq *)&signal->theData[0];
req->tableId = Ttableref;
req->hashValue = TdistrHashValue;
req->distr_key_indicator = regCachePtr->distributionKeyIndicator;
req->scan_indicator = 0;
req->anyNode = 0;
req->get_next_fragid_indicator = 0;
req->only_readable_nodes = (regTcPtr->operation == ZREAD);
req->jamBufferPtr = jamBuffer();

// NEW: for range-partitioned tables
if (localTabptr.p->m_flags & TableRecord::TR_RANGE_PARTITION) {
  req->rangeKeyPtr = regCachePtr->m_range_key_ptr;
  req->rangeKeyLen = regCachePtr->m_range_key_len;
  req->distr_key_indicator = 0;  // DBDIH resolves via range lookup
}

c_dih->execDIGETNODESREQ(signal);
```

### 6.4 Thread-Local Buffer

DBTC needs a thread-local buffer for the extracted partition key. Since
`execDIGETNODESREQ` is synchronous (EXECUTE_DIRECT), the buffer only needs
to live for the duration of the call:

```cpp
// In Dbtc class (Dbtc.hpp):
Uint32 c_range_key_buf[MAX_KEY_SIZE_IN_WORDS];
```

Or use the existing `signal->theData` scratch space after the DiGetNodesReq
fields, since the signal buffer is large enough.

---

## 7. NDB API Changes

### 7.1 Minimal Changes for Correctness

For correct operation, the NDB API needs only:

1. **New FragmentType enum value**: `RangePartition = 10` in
   `NdbDictionary.hpp`

2. **Metadata reception**: Accept `RangePartition` fragment type when
   fetching table metadata from DBDICT. Store range boundaries in
   existing `m_range` vector.

3. **No hash computation for distribution**: For range tables, the API
   does NOT compute a distribution hash. The hash is only used for:
   - Transaction hinting (which TC node) -- can be skipped initially
   - LQH tuple hash -- computed by DBTC, not the API

### 7.2 Transaction Hinting (Later Optimization)

Currently `Ndb::startTransaction()` uses `computeHash()` + `getPartitionId()`
to pick a TC node close to the data:

```cpp
// Ndb.cpp:641
return startTransaction(keyRec->table, keyRec->table->getPartitionId(hash));
```

For range tables initially, this hinting will not be range-aware -- the API
will pick an arbitrary TC node. This is correct (operations still succeed)
but suboptimal (may route through an extra network hop).

**Later optimization**: `getPartitionId()` for range tables would do:
- Extract partition key column value from the key record
- Binary search against the `m_range` boundaries stored in `NdbTableImpl`
- Return the correct fragment ID for hinting

This is a performance optimization, not needed for correctness.

### 7.3 What "NDB API as-is" Means

- `NdbOperation::equal()`: unchanged
- `NdbTransaction::startTransaction()`: hinting may be non-optimal initially
- `NdbScanOperation`: scans all fragments; pruning is a later optimization
- `setPartitionId()`: still works for explicit partition selection

---

## 8. Scan Operations

### 8.1 Full Table Scan (Phase 1)

No changes needed. The existing scan mechanism iterates all fragments:

1. DBTC sends `DIH_SCAN_TAB_REQ` -> gets `fragmentCount` (= partition count)
2. DBTC loops `scanNextFragId` from 0 to `fragmentCount - 1`
3. For each fragment, `sendDihGetNodeReq()` (DbtcMain.cpp:16947) calls
   `execDIGETNODESREQ` with `distr_key_indicator = 1` and
   `hashValue = scanFragId` (the fragment ID directly)
4. DBDIH returns node info for that specific fragment ID

This works unchanged for range-partitioned tables because:
- `distr_key_indicator = 1` bypasses the method dispatch entirely
  (line 15730: `fragId = hashValue` directly)
- The range map is not consulted for scans
- Fragment IDs are sequential (0, 1, 2, ...) same as hash tables

### 8.2 Scan Pruning for Range Tables (Later Phase)

When a scan has a WHERE clause with conditions on the partition column:
- **Equality**: `WHERE date_col = '2025-01-15'` -> single fragment
- **Range**: `WHERE date_col BETWEEN '2025-01-01' AND '2025-03-31'` ->
  subset of fragments
- **Open range**: `WHERE date_col > '2025-06-01'` -> suffix of fragments

This requires the scan operation (NDB API or DBTC) to:
1. Know the range boundaries
2. Determine which fragment(s) overlap with the scan bounds
3. Scan only those fragments

Deferred to a later phase.

---

## 9. ALTER TABLE: ADD/DROP PARTITION

### 9.1 Overview

Initial ALTER TABLE support (limited to the simplest cases):
- **ADD PARTITION at end**: Split the last range, add new fragment
- **DROP first PARTITION**: Remove lowest range, drop fragment + data

### 9.2 ADD PARTITION at End

**Scenario**: Table has ranges [MIN, 100), [100, 200), [200, MAX).
User adds partition for [200, 300), last becomes [300, MAX).

**Steps**:
1. DBDICT creates new `Range2FragmentMap` via `lc_ndbd_pool_malloc`
2. DBDICT sends `ALTER_TAB_REQ` + `CREATE_FRAGMENTATION_REQ` to DBDIH
3. DBDIH in `AlterTablePrepare`:
   - Allocates new fragment via `add_fragments_to_table()`
   - Sets `m_new_range_ptr` to new range map pointer
4. DBDIH in `AlterTableCommit`:
   - Under write lock: swaps `m_range_ptr` to new map
   - Updates `totalfragments` and `partitionCount`
5. DBDIH in `AlterTableComplete`:
   - `lc_ndbd_pool_free(old_range_ptr)` after all in-flight operations complete

No data movement needed -- the new fragment starts empty.

### 9.3 DROP First Partition

**Scenario**: Drop [MIN, 100) from the table above.

**Steps**:
1. DBDICT creates new `Range2FragmentMap` (via `lc_ndbd_pool_malloc`) without first entry
2. DBDIH waits for in-flight scans (`AlterTableWaitScan`)
3. Under write lock: saves old ptr, updates `m_range_ptr`, adjusts `totalfragments`
4. Drops fragment via `drop_fragments()`
5. `lc_ndbd_pool_free(old_range_ptr)` after readers drain
6. Data in that fragment is discarded (standard DROP PARTITION semantics)

### 9.4 Concurrency During ALTER

Uses the existing RCU mechanism:
- `NdbSeqLock` on TabRecord protects `execDIGETNODESREQ` readers
- `m_new_range_ptr` provides dual-map support during transition
- Scan count tracking ensures old maps aren't freed prematurely
- Old `Range2FragmentMap` freed via `lc_ndbd_pool_free` only after all
  readers have completed (same pattern as hash map deallocation)

---

## 10. DBSPJ Changes

### 10.1 Current State

DBSPJ calls `execDIGETNODESREQ` the same way as DBTC (`DbspjMain.cpp:5648`):
```cpp
req->hashValue = dst.hashInfo[1];   // distribution hash word
req->distr_key_indicator = 0;
```

### 10.2 Required Changes

For range-partitioned tables, DBSPJ must:

1. Detect range tables via `TR_RANGE_PARTITION` flag
2. Extract partition key columns (same `create_distr_key` pattern)
3. Pass partition key pointer via `DiGetNodesReq`

The `computePartitionHash()` function (`DbspjMain.cpp:5543`) already handles
distribution key extraction. For range tables, instead of hashing the
extracted key, DBSPJ passes it as raw bytes.

```cpp
Uint32 Dbspj::getNodes(Signal *signal, BuildKeyReq &dst, Uint32 tableId) {
  // ...
  DiGetNodesReq *req = (DiGetNodesReq *)&signal->theData[0];
  req->tableId = tableId;

  if (tablePtr.p->m_flags & TableRecord::TR_RANGE_PARTITION) {
    jam();
    // Extract partition key into local buffer
    Uint32 pkeyLen = create_distr_key(tableId, keyData,
                                       c_range_key_buf, keyPartLenPtr);
    req->rangeKeyPtr = (const void *)c_range_key_buf;
    req->rangeKeyLen = pkeyLen * 4;
    req->hashValue = 0;
    req->distr_key_indicator = 0;
  } else {
    req->hashValue = dst.hashInfo[1];
    req->distr_key_indicator = 0;
  }
  // ...
}
```

---

## 11. Concurrency and RCU

### 11.1 Read Path (execDIGETNODESREQ)

Unchanged from the existing `HASH_MAP` pattern:

```cpp
loop:
  Uint32 tab_val = tabPtr.p->m_lock.read_lock();
  Uint32 node_val = m_node_view_lock.read_lock();
  const Range2FragmentMap *rmap = tabPtr.p->m_range_ptr;
  // ... binary search using rmap ...
  // ... extract node info from Fragmentstore ...
  if (unlikely(!tabPtr.p->m_lock.read_unlock(tab_val)))
    goto loop;  // Retry: metadata changed during our read
  if (unlikely(!m_node_view_lock.read_unlock(node_val)))
    goto loop;
```

The `rangeKeyPtr` data is in the caller's local buffer (DBTC or DBSPJ
stack/thread-local), so it remains valid through the retry loop.

The `Range2FragmentMap*` read from `m_range_ptr` is safe because:
- The RCU read lock detects if the pointer was swapped (retry loop)
- The old map is not freed until all readers drain
- The map contents are immutable once published

### 11.2 Write Path

Same pattern as hash map updates during ALTER TABLE. Write lock on
TabRecord, swap `m_range_ptr`, release write lock. Old map freed via
`lc_ndbd_pool_free` after all readers (tracked via scan counting) are done.

---

## 12. Upgrade and Compatibility

### 12.1 Version Gating

Creating range-partitioned tables requires all data nodes to support
`RangePartition`. DBDICT checks node versions before accepting.

### 12.2 DiGetNodesReq Signal Change

The extended `DiGetNodesReq` (with `rangeKeyPtr` and `rangeKeyLen`) is only
used via `EXECUTE_DIRECT`. It is never sent over the wire, so there is no
network protocol compatibility issue.

### 12.3 Backup and Restore

Range boundaries stored in `RangeListData[]` (part of table metadata) are
included in backups. `ndb_restore` needs to handle `FragmentType::RangePartition`.

---

## 13. Implementation Phases

See `implementation_plan.md` for the full step-by-step implementation plan
with detailed per-file changes and test plans.

| Phase | Description | Key Types | Key Deliverable |
|-------|-------------|-----------|-----------------|
| 1 | Core infrastructure (13 files) | INT, BIGINT, DATE, DATETIME, TIMESTAMP | PK lookups + full scans |
| 2 | DBSPJ support (2 files) | (same) | Pushed-down joins work |
| 3 | ADD/DROP PARTITION (3 files) | (same) | ALTER TABLE works |
| 4 | Scan pruning (2-3 files) | (same) | Scans skip fragments |
| 5 | Variable-size boundaries (4 files) | VARCHAR, CHAR, multi-column | B-tree range map |
| 6 | NDB API transaction hinting (3 files) | all | Optimal TC selection |
| 7 | DBSPJ scan pruning (1 file) | all | Pushed joins prune |

Dependency: Phase 1 → all others. Phase 7 requires Phase 2 + Phase 4.

---

## Appendix A: Signal Flow Diagrams

### A.1 CREATE TABLE with RANGE Partitioning

```
MySQL                DBDICT               DBDIH
  |                    |                    |
  |--CREATE_TAB_REQ--->|                    |
  |  FragmentType=10   |                    |
  |  RangeListData=    |                    |
  |   [100,200,MAX]    |                    |
  |  DKey=date_col     |                    |
  |                    |                    |
  |                    |--lc_ndbd_pool_malloc(Range2FragmentMap)
  |                    |  boundaries=[100,200,MAX] (as NDB key bytes)
  |                    |  frag_ids=[0,1,2]
  |                    |  m_boundary_len=4 (DATE = 3-4 bytes)
  |                    |                    |
  |                    |--CREATE_FRAGMENTATION_REQ-->|
  |                    |  fragType=RangePartition    |
  |                    |  noOfFragments=3            |
  |                    |                    |
  |                    |<--CREATE_FRAGMENTATION_CONF-|
  |                    |  fragment placement         |
  |                    |                    |
  |                    |--DIADDTABREQ------>|
  |                    |  Method=RANGE_PART |
  |                    |  rangeMapPtr=ptr   |
  |                    |                    |
  |<--CREATE_TAB_CONF--|                    |
```

### A.2 Primary Key Lookup on Range Table

```
NDB API            DBTC                 DBDIH
  |                  |                    |
  |--TCKEYREQ------->|                    |
  |  key=2025-06-15  |                    |
  |  (no distrib hash)                    |
  |                  |                    |
  |                  |--hash():           |
  |                  |  rondb_calc_hash   |
  |                  |   -> thashValue    |
  |                  |   (for LQH/DBACC)  |
  |                  |                    |
  |                  |  create_distr_key():|
  |                  |   extract date_col |
  |                  |   -> rangeKeyBuf   |
  |                  |                    |
  |                  |--DiGetNodesReq---->|  (EXECUTE_DIRECT)
  |                  |  rangeKeyPtr=buf   |
  |                  |  rangeKeyLen=4     |
  |                  |  distr_key_ind=0   |
  |                  |                    |
  |                  |  RANGE_PARTITION:  |
  |                  |  bsearch boundaries|
  |                  |  -> fragId=1       |
  |                  |                    |
  |                  |<--DiGetNodesConf---|
  |                  |  fragId=1          |
  |                  |  nodes=[3,4]       |
  |                  |                    |
  |                  |--LQHKEYREQ------->LQH on node 3
  |                  |  hashValue=xxh(..) |
  |                  |  (for DBACC)       |
```

### A.3 ALTER TABLE ADD PARTITION

```
MySQL              DBDICT               DBDIH
  |                  |                    |
  |--ALTER TABLE---->|                    |
  |  ADD PARTITION   |                    |
  |  VALUES < 300    |                    |
  |                  |                    |
  |                  |--lc_ndbd_pool_malloc(new Range2FragmentMap):
  |                  |  boundaries=[100,200,300,MAX]
  |                  |  frag_ids=[0,1,2,3]
  |                  |                    |
  |                  |--ALTER_TAB_REQ---->|  (Prepare)
  |                  |  AddFragFlag=1     |
  |                  |                    |
  |                  |  allocates frag 3  |
  |                  |  m_new_range_ptr   |
  |                  |                    |
  |                  |--ALTER_TAB_REQ---->|  (Commit)
  |                  |                    |
  |                  |  write_lock()      |
  |                  |  m_range_ptr = new |
  |                  |  totalfragments=4  |
  |                  |  write_unlock()    |
  |                  |  lc_ndbd_pool_free |
  |                  |   (old range map)  |
  |                  |                    |
  |                  |<--ALTER_TAB_CONF---|
  |<--OK------------|                    |
```

---

## Appendix B: Key Source File Locations

| File | Lines | Content |
|------|-------|---------|
| `include/kernel/signaldata/DictTabInfo.hpp` | 209-219 | `FragmentType` enum |
| `include/kernel/signaldata/DiGetNodes.hpp` | 66-94 | `DiGetNodesReq` signal |
| `include/ndbapi/NdbDictionary.hpp` | 177-187 | API `FragmentType` enum |
| `src/kernel/vm/SimulatedBlock.hpp` | 2757-2767 | `Hash2FragmentMap` (model for Range2FragmentMap) |
| `src/kernel/vm/SimulatedBlock.cpp` | 4659-4699 | `create_distr_key()` - partition key extraction |
| `src/kernel/vm/KeyDescriptor.hpp` | 37-52 | `KeyDescriptor` struct |
| `src/kernel/blocks/dbdih/Dbdih.hpp` | 266-296 | `Fragmentstore` struct |
| `src/kernel/blocks/dbdih/Dbdih.hpp` | 664-847 | `TabRecord` struct with `Method` enum |
| `src/kernel/blocks/dbdih/DbdihMain.cpp` | 15654-15915 | `execDIGETNODESREQ` |
| `src/kernel/blocks/dbdih/DbdihMain.cpp` | 12791-12955 | `execCREATE_FRAGMENTATION_REQ` |
| `src/kernel/blocks/dbdih/DbdihMain.cpp` | 13900-13928 | Method assignment from FragmentType |
| `src/kernel/blocks/dbdih/DbdihMain.cpp` | 14667-14840 | `execALTER_TAB_REQ` |
| `src/kernel/blocks/dbtc/Dbtc.hpp` | 1509-1559 | `CacheRecord` (hash/distribution fields) |
| `src/kernel/blocks/dbtc/Dbtc.hpp` | 1641-1716 | DBTC `TableRecord` |
| `src/kernel/blocks/dbtc/DbtcMain.cpp` | 3141-3207 | `hash()` function |
| `src/kernel/blocks/dbtc/DbtcMain.cpp` | 3210-3274 | `handle_special_hash()` (distkey extraction pattern) |
| `src/kernel/blocks/dbtc/DbtcMain.cpp` | 4710-4800 | `DiGetNodesReq` preparation |
| `src/kernel/blocks/dbtc/DbtcMain.cpp` | 16947-17019 | `sendDihGetNodeReq()` (scan fragment routing) |
| `src/kernel/blocks/dbspj/DbspjMain.cpp` | 5493-5536 | DBSPJ `computeHash()` |
| `src/kernel/blocks/dbspj/DbspjMain.cpp` | 5543-5491 | DBSPJ `computePartitionHash()` |
| `src/kernel/blocks/dbspj/DbspjMain.cpp` | 5643-5680 | DBSPJ `getNodes()` |
| `src/ndbapi/NdbDictionary.cpp` | 759-782 | `getPartitionId()` |
| `src/ndbapi/NdbDictionaryImpl.hpp` | 200-270 | `NdbTableImpl` fields |
| `src/ndbapi/Ndb.cpp` | 636-654 | `startTransaction()` with hinting |
| `plugin/ha_ndbcluster.cc` | 15410-15448 | MySQL RANGE partition setup |
| `include/util/rondb_hash.hpp` | 1-62 | `rondb_calc_hash()` declaration (xxhash-based) |
| `include/kernel/signaldata/CreateFragmentation.hpp` | 33-66 | `CreateFragmentationReq` |
