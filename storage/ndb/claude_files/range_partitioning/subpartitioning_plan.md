# Hash Subpartitioning for RANGE COLUMNS Tables — Implementation Plan

## 1. Overview

Add hash subpartitioning to NDB's native RANGE COLUMNS partitioning so that
each range partition contains N hash subpartitions.  Total fragments =
`num_range_partitions * num_subpartitions`.

**SQL syntax:**
```sql
CREATE TABLE events (
    event_id   BIGINT NOT NULL,
    event_date DATE   NOT NULL,
    payload    VARCHAR(1000),
    PRIMARY KEY (event_id, event_date)
) ENGINE=NDB
PARTITION BY RANGE COLUMNS (event_date)
SUBPARTITION BY KEY()
SUBPARTITIONS 4
(
    PARTITION p2024 VALUES LESS THAN ('2025-01-01'),
    PARTITION p2025 VALUES LESS THAN ('2026-01-01'),
    PARTITION p2026 VALUES LESS THAN ('2027-01-01')
);
-- Creates 3 range partitions * 4 subpartitions = 12 fragments
```

**First iteration scope:**
- `SUBPARTITION BY KEY()` only — hash on the full primary key
- No `SUBPARTITION BY KEY(col)` with specific columns
- No `SUBPARTITION BY HASH(expr)`
- The `hashValue` already computed by DBTC (from `rondb_calc_hash()` on the
  full primary key) is reused — zero additional key extraction needed

## 2. Design

### 2.1 Fragment Layout

With 3 range partitions and 4 subpartitions (12 fragments total):

```
Range P0 (< 2025):  fragId 0,  fragId 1,  fragId 2,  fragId 3
Range P1 (< 2026):  fragId 4,  fragId 5,  fragId 6,  fragId 7
Range P2 (< 2027):  fragId 8,  fragId 9,  fragId 10, fragId 11
```

Fragment allocation spreads across node groups via the existing round-robin
in `execCREATE_FRAGMENTATION_REQ`.  Subpartitions of the same range partition
end up on different node groups (good for parallel scans within a time range).

### 2.2 Lookup Flow

The critical insight: **DBTC already computes and passes both pieces of
information** that DBDIH needs.  No DBTC changes required.

```
NDB API
  │
  ▼
DBTC::hash()
  ├── rondb_calc_hash(fullPK) → hashValue          (already done)
  ├── create_distr_key(fullPK) → rangeKey           (already done)
  └── DiGetNodesReq { hashValue, rangeKeyPtr, rangeKeyLen }
        │
        ▼
DBDIH::execDIGETNODESREQ
  ├── range_lookup(m_range_ptr, rangeKey)  → rangeIdx    (existing)
  ├── subIdx = hashValue % m_num_subpartitions           (NEW)
  └── fragId = frag_ids[rangeIdx * m_num_subpartitions + subIdx]
```

### 2.3 DROP PARTITION

Drops all N subpartitions of the first (oldest) range partition.

Before DROP (3 ranges * 4 subparts = 12 fragments):
```
frag_ids: [0, 1, 2, 3,  4, 5, 6, 7,  8, 9, 10, 11]
           ╰─ P0 ─────╯  ╰─ P1 ────╯  ╰─ P2 ─────╯
m_startFid_offset = 0, totalfragments = 12, m_cnt = 3
```

After DROP P0 (2 ranges * 4 subparts = 8 fragments):
```
frag_ids: [4, 5, 6, 7,  8, 9, 10, 11]
           ╰─ P1 ────╯  ╰─ P2 ─────╯
m_startFid_offset = 4, totalfragments = 8, m_cnt = 2
lower_bound = boundary(0) from old map
```

Key: `m_startFid_offset` increases by `num_subpartitions` (4), not by 1.
The `startFid[]` array in DBDIH shifts down by `num_subpartitions` positions.
All N dropped fragments are released via `execDROP_FRAG_CONF`.

### 2.4 ADD PARTITION

Adds N new subpartitions for the new range partition.

After ADD P3 (3 ranges * 4 subparts = 12 fragments):
```
frag_ids: [4, 5, 6, 7,  8, 9, 10, 11,  12, 13, 14, 15]
           ╰─ P1 ────╯  ╰─ P2 ─────╯   ╰── P3 ──────╯
m_startFid_offset = 4, totalfragments = 12, m_cnt = 3
```

New fragment IDs are sequential: `last_old_fragId + 1` through
`last_old_fragId + num_subpartitions`.

### 2.5 Scan Pruning with Subpartitions

When the WHERE clause constrains the range column to a single range partition,
the scan targets N fragments (all subpartitions) instead of 1.  This is still
a major improvement over scanning all `num_ranges * N` fragments.

When the WHERE clause constrains *both* the range column and other PK columns
(effectively a PK lookup), a single fragment is sufficient.

### 2.6 What Doesn't Change

- **DBTC**: `hashValue` is already computed from full PK and passed in
  `DiGetNodesReq`.  `rangeKeyPtr` extraction is unchanged.  Zero code changes.
- **DBSPJ**: calls `execDIGETNODESREQ` the same way as DBTC.  The DBDIH
  change handles DBSPJ automatically.
- **LQH distribution**: uses `hashValue` within a fragment — orthogonal.
- **Backup/LCP/SUMA**: iterate over fragments by `totalfragments` — works
  because totalfragments is the true fragment count.
- **Signal formats**: `DiGetNodesReq` already carries `hashValue` and
  `rangeKeyPtr` — no signal changes needed.

---

## 3. Phased Implementation

### Phase 1: Range2FragmentMap and DBDIH Lookup

**Goal:** Modify the core data structure and lookup function to support
subpartitions.  Tables created with `num_subpartitions = 1` behave identically
to today.

#### Step 1.1: Range2FragmentMap — Add `m_num_subpartitions`

**File:** `storage/ndb/src/kernel/vm/SimulatedBlock.hpp`

Add field to struct:
```cpp
struct Range2FragmentMap {
  Uint32 m_cnt;              // number of range partitions
  Uint32 m_boundary_len;     // byte length per boundary
  Uint32 m_boundary_type;    // NDB attribute type
  Uint32 m_num_columns;      // partition key columns
  Uint32 m_object_id;        // table object ID
  Uint32 m_has_lower_bound;  // 1 after DROP PARTITION
  Uint32 m_num_subpartitions; // NEW: subpartitions per range partition (>= 1)
  // ...
};
```

#### Step 1.2: Fix `frag_ids` array size in accessors

**File:** `storage/ndb/src/kernel/vm/SimulatedBlock.hpp`

The `frag_ids()` accessor returns a pointer — unchanged (still points after
header).  But `boundaries()` must account for the larger frag_ids array:

```cpp
// BEFORE:
char *boundaries() {
  char *after_frags = reinterpret_cast<char *>(frag_ids() + m_cnt);
  // ...
}

// AFTER:
char *boundaries() {
  Uint32 total_fids = m_cnt * m_num_subpartitions;
  char *after_frags = reinterpret_cast<char *>(frag_ids() + total_fids);
  // ... (same alignment logic)
}
```

Same for `const` overload.

Note: boundaries array stays at `m_cnt` entries (one per range partition).
Only the frag_ids array expands.

#### Step 1.3: Fix `alloc_size()`

**File:** `storage/ndb/src/kernel/vm/SimulatedBlock.hpp`

```cpp
static Uint32 alloc_size(Uint32 cnt, Uint32 blen,
                         bool has_lower_bound = false,
                         Uint32 num_subpartitions = 1) {
  Uint32 sz = sizeof(Range2FragmentMap);
  sz += cnt * num_subpartitions * sizeof(Uint16);  // frag_ids
  sz = (sz + 7) & ~Uint32(7);                      // align to 8
  sz += cnt * blen;                                 // boundaries
  if (has_lower_bound) {
    sz += blen;
  }
  return sz;
}
```

#### Step 1.4: Modify `range_lookup()` to accept `hashValue`

**File:** `storage/ndb/src/kernel/vm/SimulatedBlock.hpp`

```cpp
static inline Uint32 range_lookup(const Range2FragmentMap *map,
                                  const char *key, Uint32 key_len,
                                  Uint32 hashValue = 0) {
  const Uint32 btype = map->m_boundary_type;

  // Lower bound check (unchanged)
  if (map->m_has_lower_bound) {
    int cmp = range_compare(map->lower_bound(), key, btype);
    if (cmp > 0) return RNIL;
  }

  // Binary search for range partition index (unchanged)
  Uint32 lo = 0, hi = map->m_cnt;
  while (lo < hi) {
    Uint32 mid = (lo + hi) >> 1;
    const char *bound = map->boundary(mid);
    int cmp = range_compare(bound, key, btype);
    if (cmp <= 0) lo = mid + 1;
    else          hi = mid;
  }
  if (lo >= map->m_cnt) return RNIL;

  // Subpartition selection (NEW)
  Uint32 sub_idx = 0;
  if (map->m_num_subpartitions > 1) {
    sub_idx = hashValue % map->m_num_subpartitions;
  }
  return map->frag_ids()[lo * map->m_num_subpartitions + sub_idx];
}
```

Backward-compatible: when `m_num_subpartitions == 1` and `hashValue == 0`,
the result is `frag_ids()[lo]` — identical to today.

#### Step 1.5: DBDIH `execDIGETNODESREQ` — pass hashValue

**File:** `storage/ndb/src/kernel/blocks/dbdih/DbdihMain.cpp` (line ~16098)

Change:
```cpp
// BEFORE:
fragId = range_lookup(range_map, rangeKey, rangeKeyLen);

// AFTER:
fragId = range_lookup(range_map, rangeKey, rangeKeyLen, req->hashValue);
```

Same for the `m_new_range_ptr` dual-map lookup:
```cpp
// BEFORE:
newFragId = range_lookup(tabPtr.p->m_new_range_ptr, rangeKey, rangeKeyLen);

// AFTER:
newFragId = range_lookup(tabPtr.p->m_new_range_ptr,
                         rangeKey, rangeKeyLen, req->hashValue);
```

**That's it for DBDIH lookup.**  The `hashValue` is already in
`DiGetNodesReq` from DBTC (line 85 of DiGetNodes.hpp).

---

### Phase 2: DictTabInfo and DBDICT CREATE TABLE

**Goal:** Parse subpartition metadata and create correctly-sized
Range2FragmentMap during CREATE TABLE.

#### Step 2.1: DictTabInfo attribute

**File:** `storage/ndb/include/kernel/signaldata/DictTabInfo.hpp`

```cpp
// Add after RangeStartFidOffset = 169:
RangeNumSubpartitions = 170,
```

Add to Table struct:
```cpp
Uint32 RangeNumSubpartitions;  // default 1
```

**File:** `storage/ndb/src/common/debugger/signaldata/DictTabInfo.cpp`

Add to `TableMapping[]`:
```cpp
DTI_MAP_INT(Table, RangeNumSubpartitions, RangeNumSubpartitions),
```

Add to `Table::init()`:
```cpp
RangeNumSubpartitions = 1;
```

#### Step 2.2: DBDICT CREATE TABLE — allocate expanded map

**File:** `storage/ndb/src/kernel/blocks/dbdict/Dbdict.cpp`

In the Range2FragmentMap allocation during `createTable_parse` /
`handleTabInfoInit`:

```cpp
const Uint32 num_ranges = parts;  // number of range partitions
const Uint32 num_subparts = tablePtr.p->RangeNumSubpartitions;
const Uint32 total_frags = num_ranges * num_subparts;

Uint32 alloc_sz = Range2FragmentMap::alloc_size(
    num_ranges, blen, false, num_subparts);
// ... lc_ndbd_pool_malloc(alloc_sz, ...) ...

rmap->m_cnt = num_ranges;
rmap->m_num_subpartitions = num_subparts;
// ...

// Assign sequential fragment IDs
Uint16 *fids = rmap->frag_ids();
for (Uint32 i = 0; i < total_frags; i++) {
  fids[i] = i;
}
```

And pass `total_frags` as `noOfFragments` to `CREATE_FRAGMENTATION_REQ`
(not `num_ranges`).

#### Step 2.3: DBDICT — store/restore `m_num_subpartitions`

**File:** `storage/ndb/src/kernel/blocks/dbdict/Dbdict.cpp`

When persisting table metadata (DictTabInfo packing), include
`RangeNumSubpartitions`.  On restore (`prepare_add_table`), read it back
and set `rmap->m_num_subpartitions`.

If the attribute is missing (pre-subpartitioning table), default to 1.

#### Step 2.4: DBDICT TableRecord — add field

**File:** `storage/ndb/src/kernel/blocks/dbdict/Dbdict.hpp`

Add to DBDICT's TableRecord:
```cpp
Uint32 m_num_subpartitions;  // 1 for non-subpartitioned range tables
```

---

### Phase 3: ha_ndbcluster — MySQL Integration

**Goal:** Parse MySQL's SUBPARTITION BY KEY() syntax and transmit metadata
to NDB.

#### Step 3.1: Detect subpartitioning in `create_table_set_up_partition_info`

**File:** `storage/ndb/plugin/ha_ndbcluster.cc` (line ~15565)

Currently the RANGE COLUMNS branch checks:
```cpp
if (part_info->part_type == partition_type::RANGE &&
    part_info->column_list &&
    part_info->num_part_fields == 1 &&
    part_info->part_field_array != nullptr)
```

Extend to handle subpartitioning:
```cpp
// After setting RangePartition fragment type and boundaries:

if (part_info->is_sub_partitioned()) {
  // Validate: only KEY() subpartitioning in first iteration
  if (part_info->subpart_type != partition_type::HASH ||
      !part_info->list_of_subpart_fields) {
    my_error(ER_NOT_SUPPORTED_YET, MYF(0),
             "SUBPARTITION BY HASH(expr) with RANGE COLUMNS. "
             "Use SUBPARTITION BY KEY()");
    return 1;
  }
  ndbtab.setNumSubpartitions(part_info->num_subparts);
}
```

Note: MySQL uses `partition_type::HASH` for both `KEY()` and `HASH(expr)`,
distinguished by `list_of_subpart_fields`.

#### Step 3.2: Fragment count must be total fragments

**File:** `storage/ndb/plugin/ha_ndbcluster.cc`

Ensure `setFragmentCount()` is called with the total fragment count.
Currently NDB derives fragment count from the partition count; with
subpartitioning, the SQL layer may pass `num_parts` as the fragment count.
We need:
```cpp
// After boundary setup:
Uint32 total_frags = parts;
if (part_info->is_sub_partitioned()) {
  total_frags = parts * part_info->num_subparts;
}
ndbtab.setFragmentCount(total_frags);
```

Or alternatively: let DBDICT compute `total_frags` from `num_ranges` and
`num_subpartitions`.  The cleanest approach is to set `fragmentCount` to
`num_ranges` and let DBDICT multiply — this keeps the MySQL side simpler.

**Decision:** Set `fragmentCount = num_ranges` (as today).  DBDICT multiplies
by `num_subpartitions` to get `total_frags` for `CREATE_FRAGMENTATION_REQ`.
This means no change to the fragment count path in ha_ndbcluster.

#### Step 3.3: `set_part_info` — partition pruning flag

**File:** `storage/ndb/plugin/ha_ndbcluster.cc` (line ~12256)

The existing check for native RangePartition needs to also accept
subpartitioned range tables:
```cpp
if (m_part_info->part_type == partition_type::RANGE &&
    m_part_info->column_list &&
    m_part_info->num_part_fields == 1) {
  /* Native RangePartition — NDB handles partitioning.
   * Also covers SUBPARTITION BY KEY(). */
}
```

This already works — `is_sub_partitioned()` doesn't change `part_type`.

#### Step 3.4: ALTER TABLE ADD/DROP PARTITION

**File:** `storage/ndb/plugin/ha_ndbcluster.cc`

The existing ALTER TABLE code for range tables already handles ADD and DROP.
For ADD PARTITION, it sends the new boundaries.  For DROP, it sends the
reduced partition list.  The `num_subpartitions` is a table property that
doesn't change during ALTER — it's read from the existing table definition.

Check that ALTER paths correctly propagate `num_subpartitions` in the
DictTabInfo when building the new table definition.

---

### Phase 4: NDB API Metadata

**Goal:** Accept and store `num_subpartitions` in NDB API table metadata.

#### Step 4.1: NdbDictionary API

**File:** `storage/ndb/include/ndbapi/NdbDictionary.hpp`

Add to `NdbDictionary::Table`:
```cpp
void setNumSubpartitions(Uint32 n);
Uint32 getNumSubpartitions() const;
```

#### Step 4.2: NdbDictionaryImpl

**File:** `storage/ndb/src/ndbapi/NdbDictionaryImpl.hpp`

Add to `NdbTableImpl`:
```cpp
Uint32 m_numSubpartitions;  // default 1
```

**File:** `storage/ndb/src/ndbapi/NdbDictionaryImpl.cpp`

In DictTabInfo reception, parse `RangeNumSubpartitions` and store in
`m_numSubpartitions`.  Default to 1 if not present.

---

### Phase 5: DBDIH DROP/ADD PARTITION Handling

**Goal:** DROP removes N fragments, ADD creates N fragments.

#### Step 5.1: DBDIH ALTER_TAB_REQ prepare — DROP

**File:** `storage/ndb/src/kernel/blocks/dbdih/DbdihMain.cpp` (line ~14908)

Currently:
```cpp
connectPtr.p->m_alter.m_new_startFid_offset =
    (tabPtr.p->m_startFid_offset + 1) & 0xFFFF;
connectPtr.p->m_alter.m_totalfragments =
    tabPtr.p->totalfragments - 1;
connectPtr.p->m_alter.m_partitionCount =
    tabPtr.p->partitionCount - 1;
connectPtr.p->m_alter.m_new_startFidSize =
    (tabPtr.p->startFidSize - 1);
```

Change to:
```cpp
const Uint32 nsub = tabPtr.p->m_num_subpartitions;  // NEW field on TabRecord
connectPtr.p->m_alter.m_new_startFid_offset =
    (tabPtr.p->m_startFid_offset + nsub) & 0xFFFF;
connectPtr.p->m_alter.m_totalfragments =
    tabPtr.p->totalfragments - nsub;
connectPtr.p->m_alter.m_partitionCount =
    tabPtr.p->partitionCount - nsub;
connectPtr.p->m_alter.m_new_startFidSize =
    tabPtr.p->startFidSize - nsub;
```

#### Step 5.2: DBDIH commit — shift `startFid[]` by N

**File:** `storage/ndb/src/kernel/blocks/dbdih/DbdihMain.cpp` (line ~16813)

Currently shifts `startFid[]` down by 1:
```cpp
connectPtr.p->m_alter.m_drop_frag_ptrI = tabPtr.p->startFid[0];
const Uint32 newTotal = tabPtr.p->totalfragments;
for (Uint32 i = 0; i < newTotal; i++) {
  tabPtr.p->startFid[i] = tabPtr.p->startFid[i + 1];
}
tabPtr.p->startFid[newTotal] = RNIL64;
```

Change to drop N fragments:
```cpp
const Uint32 nsub = tabPtr.p->m_num_subpartitions;
// Save pool indices of ALL dropped fragments
for (Uint32 s = 0; s < nsub; s++) {
  connectPtr.p->m_alter.m_drop_frag_ptrI[s] = tabPtr.p->startFid[s];
}
const Uint32 newTotal = tabPtr.p->totalfragments;
for (Uint32 i = 0; i < newTotal; i++) {
  tabPtr.p->startFid[i] = tabPtr.p->startFid[i + nsub];
}
for (Uint32 i = newTotal; i < newTotal + nsub; i++) {
  tabPtr.p->startFid[i] = RNIL64;
}
```

Note: `m_drop_frag_ptrI` needs to become an array (or iterate the drop
sequence for each subpartition).  Each dropped fragment gets a
`DROP_FRAG_REQ` / `DROP_FRAG_CONF` cycle.

#### Step 5.3: DBDIH ALTER_TAB_REQ prepare — ADD

**File:** `storage/ndb/src/kernel/blocks/dbdih/DbdihMain.cpp`

Currently adds 1 fragment.  Change to add N:
```cpp
const Uint32 nsub = tabPtr.p->m_num_subpartitions;
connectPtr.p->m_alter.m_totalfragments =
    tabPtr.p->totalfragments + nsub;
connectPtr.p->m_alter.m_partitionCount =
    tabPtr.p->partitionCount + nsub;
connectPtr.p->m_alter.m_new_startFidSize =
    tabPtr.p->startFidSize + nsub;
```

#### Step 5.4: DBDIH TabRecord — add `m_num_subpartitions`

**File:** `storage/ndb/src/kernel/blocks/dbdih/Dbdih.hpp`

Add to `TabRecord`:
```cpp
Uint32 m_num_subpartitions;  // >= 1, set during CREATE TABLE
```

Set from DBDICT during table creation (via `DiAddTabReq` or range map
pointer).  Copy to ordered index tables alongside `m_startFid_offset`.

#### Step 5.5: DBDICT DROP — remove N frag_ids from range map

**File:** `storage/ndb/src/kernel/blocks/dbdict/Dbdict.cpp`

Currently removes first entry from frag_ids:
```cpp
Uint32 num_dropped = old_cnt - new_cnt;
for (Uint32 i = 0; i < new_cnt; i++) {
  new_fids[i] = old_fids[num_dropped + i];
}
```

With subpartitions:
```cpp
Uint32 num_dropped_ranges = old_cnt - new_cnt;  // typically 1
Uint32 nsub = old_rmap->m_num_subpartitions;
Uint32 num_dropped_frags = num_dropped_ranges * nsub;

// Copy surviving fragment IDs
for (Uint32 i = 0; i < new_cnt * nsub; i++) {
  new_fids[i] = old_fids[num_dropped_frags + i];
}
rmap->m_num_subpartitions = nsub;
```

#### Step 5.6: DBDICT ADD — append N frag_ids to range map

**File:** `storage/ndb/src/kernel/blocks/dbdict/Dbdict.cpp`

Currently appends 1:
```cpp
Uint32 last_old_fragid = old_fids[old_cnt - 1];
new_fids[old_cnt] = (last_old_fragid + 1) & 0xFFFF;
```

With subpartitions:
```cpp
Uint32 nsub = old_rmap->m_num_subpartitions;
// Copy old fragment IDs
for (Uint32 i = 0; i < old_cnt * nsub; i++) {
  new_fids[i] = old_fids[i];
}
// Append N new IDs
Uint32 last_fragid = old_fids[old_cnt * nsub - 1];
for (Uint32 j = 0; j < nsub; j++) {
  new_fids[old_cnt * nsub + j] = (last_fragid + 1 + j) & 0xFFFF;
}
rmap->m_num_subpartitions = nsub;
```

---

### Phase 6: Ordered Index Tables and SUMA

**Goal:** Ensure index tables and replication correctly handle subpartitioned
range tables.

#### Step 6.1: Copy `m_num_subpartitions` to ordered index tables

**File:** `storage/ndb/src/kernel/blocks/dbdih/DbdihMain.cpp` (line ~14000)

Currently copies `m_startFid_offset`:
```cpp
tabPtr.p->m_startFid_offset = primTabPtr.p->m_startFid_offset;
```

Add:
```cpp
tabPtr.p->m_num_subpartitions = primTabPtr.p->m_num_subpartitions;
```

#### Step 6.2: SUMA fragment enumeration

**File:** `storage/ndb/src/kernel/blocks/suma/Suma.cpp`

SUMA uses `totalfragments` to enumerate fragments.  Since `totalfragments`
is the true fragment count (num_ranges * num_subparts), SUMA works
without changes.

Verify that any fragment ID conversion (`fragIdToNo` / `fragNoToId`) uses
the correct offset.  Since `m_startFid_offset` increases by `nsub` on DROP,
the conversion `fragId - m_startFid_offset` still yields the correct
array index.

---

### Phase 7: Persistence and Restart

**Goal:** `m_num_subpartitions` survives node and system restarts.

#### Step 7.1: DictTabInfo persistence

`RangeNumSubpartitions` is stored as a DictTabInfo attribute (Step 2.1),
which is already persisted to disk as part of the table schema.  On restart,
DBDICT reads it back and uses it to allocate the Range2FragmentMap with the
correct size.

#### Step 7.2: Verify `prepare_add_table` handles subpartitions

**File:** `storage/ndb/src/kernel/blocks/dbdict/Dbdict.cpp`

The `prepare_add_table` function reconstructs the Range2FragmentMap on
restart.  Ensure it reads `RangeNumSubpartitions` from the table record
and passes it to `Range2FragmentMap::alloc_size()` and sets
`rmap->m_num_subpartitions`.

#### Step 7.3: DBDIH restart — set `m_num_subpartitions`

When DBDIH receives the table via `DiAddTabReq`, it gets the range map
pointer from DBDICT.  The map already contains `m_num_subpartitions`.
DBDIH should also set `tabPtr.p->m_num_subpartitions` from the map.

---

### Phase 8: Scan Pruning (Enhancement)

**Goal:** Range scans prune to N fragments per matching range partition
instead of scanning all fragments.

#### Step 8.1: Range pruning returns fragment set

When a scan WHERE clause constrains the partition column to range partition
`i`, the scan should target fragments:
```
frag_ids[i * nsub + 0], frag_ids[i * nsub + 1], ..., frag_ids[i * nsub + (nsub-1)]
```

This is N fragments instead of `total_fragments`.

#### Step 8.2: Server-side pruning in DBTC

**File:** `storage/ndb/src/kernel/blocks/dbtc/DbtcMain.cpp`

When building the scan fragment list, if the range map is available and the
scan has a range constraint, compute the matching range partition indices
and include only their subpartition fragments.

#### Step 8.3: Client-side pruning in NDB API

**File:** `storage/ndb/src/ndbapi/NdbScanOperation.cpp`

The NDB API has the range boundaries in `m_range`.  When determining
prunable scans, compute matching range partition(s) and generate the
fragment ID set: each matching range partition contributes `nsub`
fragment IDs.

---

## 4. Files Changed Per Phase

| Phase | Files | Description |
|-------|-------|-------------|
| 1 | `SimulatedBlock.hpp`, `DbdihMain.cpp` | Core structure and lookup |
| 2 | `DictTabInfo.hpp`, `DictTabInfo.cpp`, `Dbdict.hpp`, `Dbdict.cpp` | Metadata and CREATE TABLE |
| 3 | `ha_ndbcluster.cc`, `ha_ndbcluster_range.cc` | MySQL integration |
| 4 | `NdbDictionary.hpp`, `NdbDictionaryImpl.hpp`, `NdbDictionaryImpl.cpp` | NDB API |
| 5 | `DbdihMain.cpp`, `Dbdih.hpp`, `Dbdict.cpp` | DROP/ADD PARTITION |
| 6 | `DbdihMain.cpp`, `Suma.cpp` | Index tables and replication |
| 7 | `Dbdict.cpp`, `DbdihMain.cpp` | Restart persistence |
| 8 | `DbtcMain.cpp`, `NdbScanOperation.cpp` | Scan pruning |

**Total estimated new/changed lines:** ~400-600 (much smaller than the
original range partitioning because the infrastructure already exists).

## 5. Dependency Graph

```
Phase 1 (Range2FragmentMap + DBDIH lookup)
  │
  ├──> Phase 2 (DictTabInfo + DBDICT CREATE)
  │      │
  │      ├──> Phase 3 (ha_ndbcluster)
  │      │
  │      └──> Phase 4 (NDB API)
  │
  ├──> Phase 5 (DROP/ADD PARTITION)  ← requires Phase 2
  │
  ├──> Phase 6 (Index tables)  ← requires Phase 5
  │
  ├──> Phase 7 (Persistence)  ← requires Phase 2
  │
  └──> Phase 8 (Scan pruning)  ← independent, enhancment
```

Phases 1-2 are the foundation.  Phase 3 + 4 enable end-to-end testing.
Phase 5 enables the sliding window pattern.  Phases 6-8 are hardening
and optimization.

## 6. Test Plan

### 6.1 Basic CREATE/INSERT/SELECT

```sql
CREATE TABLE t1 (
  id BIGINT NOT NULL,
  d DATE NOT NULL,
  v VARCHAR(100),
  PRIMARY KEY (id, d)
) ENGINE=NDB
PARTITION BY RANGE COLUMNS (d)
SUBPARTITION BY KEY()
SUBPARTITIONS 4
(
  PARTITION p0 VALUES LESS THAN ('2025-01-01'),
  PARTITION p1 VALUES LESS THAN ('2026-01-01'),
  PARTITION p2 VALUES LESS THAN ('2027-01-01')
);

-- 12 fragments total
-- INSERT rows spanning partitions
INSERT INTO t1 VALUES (1, '2024-06-15', 'a');
INSERT INTO t1 VALUES (2, '2025-06-15', 'b');
INSERT INTO t1 VALUES (3, '2026-06-15', 'c');

-- PK lookups route correctly
SELECT * FROM t1 WHERE id = 1 AND d = '2024-06-15';
SELECT * FROM t1 WHERE id = 2 AND d = '2025-06-15';

-- Full scan returns all rows
SELECT * FROM t1 ORDER BY id;
```

### 6.2 DROP/ADD PARTITION

```sql
-- DROP first partition (drops 4 fragments)
ALTER TABLE t1 DROP PARTITION p0 ALGORITHM=INPLACE;

-- Verify data
SELECT * FROM t1 ORDER BY id;  -- only rows from p1, p2

-- Verify lower bound rejection
INSERT INTO t1 VALUES (4, '2024-06-15', 'd');  -- should fail

-- ADD new partition (adds 4 fragments)
ALTER TABLE t1 ADD PARTITION (
  PARTITION p3 VALUES LESS THAN ('2028-01-01')
);

-- Insert into new partition
INSERT INTO t1 VALUES (5, '2027-06-15', 'e');
SELECT * FROM t1 WHERE id = 5 AND d = '2027-06-15';
```

### 6.3 Subpartition Distribution

```sql
-- Verify rows with same date but different IDs go to different subpartitions
-- by inserting many rows and checking fragment distribution via
-- ndb_desc or EXPLAIN
INSERT INTO t1 VALUES (100, '2025-06-15', 'x');
INSERT INTO t1 VALUES (200, '2025-06-15', 'y');
INSERT INTO t1 VALUES (300, '2025-06-15', 'z');
INSERT INTO t1 VALUES (400, '2025-06-15', 'w');
```

### 6.4 Restart Persistence

```sql
-- Create table, insert data, restart nodes, verify data and routing
-- Same pattern as ndb_partition_range_restart.test but with subpartitions
```

### 6.5 Non-subpartitioned tables still work

```sql
-- Verify that RANGE COLUMNS without SUBPARTITION still works identically
CREATE TABLE t2 (
  id BIGINT NOT NULL,
  d DATE NOT NULL,
  PRIMARY KEY (id, d)
) ENGINE=NDB
PARTITION BY RANGE COLUMNS (d) (
  PARTITION p0 VALUES LESS THAN ('2025-01-01'),
  PARTITION p1 VALUES LESS THAN ('2026-01-01')
);
-- Should behave exactly as before (m_num_subpartitions = 1)
```

## 7. Limitations and Future Work

### Current limitations (first iteration)
- **SUBPARTITION BY KEY() only** — hash on full primary key
- **No SUBPARTITION BY KEY(col1, col2)** with specific columns
- **No SUBPARTITION BY HASH(expr)** — no expression evaluation
- **num_subpartitions is immutable** — cannot change after CREATE TABLE
- **No individual subpartition management** — DROP/ADD always operates on
  all subpartitions of a range partition

### Future iterations
- `SUBPARTITION BY KEY(col)` — hash on specific columns (requires separate
  distribution key extraction in DBTC)
- `SUBPARTITION BY HASH(expr)` — requires MySQL partition function evaluation
- Dynamic subpartition count changes (REORGANIZE PARTITION)
- Scan pruning: prune to single subpartition when hash key is known
