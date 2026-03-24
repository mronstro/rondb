# DROP PARTITION Implementation Plan

## Overview

Implement online (inplace) `ALTER TABLE ... DROP PARTITION` for
RANGE COLUMNS tables. Only the **first** partition (lowest range)
can be dropped. Combined with ADD PARTITION at the end, this
enables a sliding window pattern for time-series data.

## Core Design: Circular Fragment Array

Instead of leaving holes or compacting the array, we introduce a
**start offset** into the `startFid[]` array. Fragment IDs form a
circular window within the array:

```
startFid[]:  [ _ | _ | F2 | F3 | F4 | _ | _ ]
                       ^startId      ^startId + partitionCount
```

- `m_startFid_offset` — index of the first live fragment
- `totalfragments` — total allocated size of `startFid[]`
- `partitionCount` — number of live partitions
- Live fragment IDs: `startFid[(m_startFid_offset + i) % totalfragments]`
  for i = 0..partitionCount-1

After many ADD + DROP cycles, the window wraps around:

```
Initial:     [F0 | F1 | F2]        offset=0, count=3
DROP p0:     [ _ | F1 | F2]        offset=1, count=2
ADD p3:      [F3 | F1 | F2]        offset=1, count=3  (F3 reuses slot 0)
DROP p1:     [F3 | _  | F2]        offset=2, count=2
ADD p4:      [F3 | F4 | F2]        offset=2, count=3  (F4 reuses slot 1)
```

This supports continuous ADD/DROP without ever running out of
fragment IDs or needing array compaction.

### Fragment ID Mapping

The Range2FragmentMap's `frag_ids[]` stores physical fragment IDs.
After DROP of the first partition:
- Old: frag_ids = [0, 1, 2], boundaries = [10, 20, MAX]
- New: frag_ids = [1, 2], boundaries = [20, MAX]

The `range_lookup()` returns physical fragment IDs directly. These
IDs are indices into `startFid[]` and remain stable.

When ADD wraps around and reuses a slot:
- frag_ids = [1, 2, 0], boundaries = [20, 30, MAX]
- Fragment 0's slot is reused for the new partition

### Scan Iteration

Scans iterate over **live** fragments only using the circular window:

```cpp
for (Uint32 i = 0; i < partitionCount; i++) {
  Uint32 fragId = (m_startFid_offset + i) % totalfragments;
  getFragstore(tabPtr.p, fragId, fragPtr);
  // ... send SCAN_FRAGREQ — this is always a live fragment
}
```

No need to check for dropped fragments — freed slots are never
visited. After COMPLETE, the dropped fragment's Fragmentstore is
released and the slot is `RNIL64`.

### getFragstore

Continues to work unchanged — fragment IDs are valid indices into
`startFid[]`. Only live fragment IDs are ever looked up (via
range map or scan iteration).

## Phase Flow

```
PREPARE:
  Build new Range2FragmentMap (without first partition)
  Install m_new_range_ptr (dual-map lookup starts)
  → New ops via new map won't route to dropped fragment
  → Old map still exists for in-flight ops (dual-map)
  → REVERT: discard new map, no other changes needed

COMMIT (make_new_table_read_and_writeable):
  Swap m_range_ptr ↔ m_new_range_ptr
  Advance m_startFid_offset
  Reduce partitionCount
  Bump distributionKey on all live fragments
  → All new ops use the new (reduced) range map
  → Scans use new offset+count, never visit dropped slot

COMPLETE:
  Send DROP_FRAG_REQ to LQH for the dropped fragment
  → Deletes data, frees LQH resources
  Release Fragmentstore record, set startFid slot to RNIL64
  Free old range map
  Cleanup
```

## Detailed Changes Per File

### 1. AlterTable.hpp — New Signal Flag

**File:** `include/kernel/signaldata/AlterTable.hpp`

Add `DropFragFlag`:
```cpp
static const Uint32 DROP_FRAG_SHIFT = 16;
static bool getDropFragFlag(Uint32 mask);
static void setDropFragFlag(Uint32 &mask, bool v);
```

### 2. Dbdih.hpp — TabRecord Extensions

**File:** `src/kernel/blocks/dbdih/Dbdih.hpp`

Add to `TabRecord`:
```cpp
Uint32 m_startFid_offset;  // Index of first live fragment in startFid[]
```

Initialize to 0 in TabRecord constructor. Persisted in table file.

Add to `ConnectRecord::m_alter`:
```cpp
Uint32 m_drop_frag_id;         // Fragment ID being dropped
Uint32 m_new_startFid_offset;  // New offset after drop
```

### 3. NdbDictionaryImpl.cpp — Detect DROP and Set Flag

**File:** `src/ndbapi/NdbDictionaryImpl.cpp`

In `NdbDictInterface::alterTable()`, allow fragment count decrease
for RangePartition:

```cpp
if (impl.m_fragmentCount != old_impl.m_fragmentCount) {
    if (impl.m_fragmentType == NdbDictionary::Object::RangePartition) {
      if (impl.m_fragmentCount < old_impl.m_fragmentCount)
        AlterTableReq::setDropFragFlag(change_mask, true);
      else
        AlterTableReq::setAddFragFlag(change_mask, true);
    } else if (impl.m_fragmentType == NdbDictionary::Object::HashMapPartition) {
      AlterTableReq::setAddFragFlag(change_mask, true);
    } else {
      goto invalid_alter_table;
    }
}
```

Handle `PartitionBalance_Specific` for RangePartition similarly.

### 4. Dbdict.cpp — Build New Range Map for DROP

**File:** `src/kernel/blocks/dbdict/Dbdict.cpp`

In `alterTable_parse()`, add DropFragFlag handling:

- Read new `RangeListData` (boundaries without dropped partition)
- Build new `Range2FragmentMap` with `new_cnt = old_cnt - 1`
- New map's `frag_ids[]` = old map's `frag_ids[1..old_cnt-1]`
  (skip the first entry — the dropped partition)
- New map's boundaries = new RangeListData boundaries
- Set `ReorgFragFlag` so DBDIH does map swap at COMMIT
- Validate: the dropped partition is the first one

### 5. DbdihMain.cpp — ALTER Flow for DropFragFlag

#### AlterTablePrepare

```
if (AlterTableReq::getDropFragFlag(req->changeMask)):
  1. Save m_org_totalfragments, m_partitionCount
  2. Get new range map from DBDICT
  3. Install m_new_range_ptr for dual-map lookup
  4. Identify dropped fragment:
     m_drop_frag_id = old_range_map->frag_ids()[0]
  5. Compute new offset:
     m_new_startFid_offset =
       (tabPtr.p->m_startFid_offset + 1) % totalfragments
  6. Save table file, reply ALTER_TAB_CONF
```

No LQH operations in PREPARE. No fragments marked. The dual-map
lookup ensures new operations don't route to the first partition
via the new map (the old map still handles in-flight ops that
already resolved to the old fragment).

#### AlterTableCommit

In `make_new_table_read_and_writeable()`, add DropFragFlag branch:
```
if (DropFragFlag):
  Under write lock:
    Swap m_range_ptr ↔ m_new_range_ptr
    tabPtr.p->m_startFid_offset = m_new_startFid_offset
    tabPtr.p->partitionCount -= 1
    Bump distributionKey on all live fragments
```

After this, scans use the new offset+count and never visit the
dropped fragment's slot. PK ops use the new range map which doesn't
reference the dropped fragment ID.

#### AlterTableComplete

```
if (DropFragFlag):
  1. Send DROP_FRAG_REQ to DBLQH for m_drop_frag_id
     requestInfo = DropFragReq::AlterTableDrop
  2. On DROP_FRAG_CONF:
     Release Fragmentstore (replica records, etc.)
     Set startFid[m_drop_frag_id] = RNIL64
     Free old range map
     send_alter_tab_conf()
```

#### AlterTableRevert

```
if (DropFragFlag):
  Under write lock:
    Set m_new_range_ptr = nullptr
  send_alter_tab_conf()
  // No LQH changes to undo, no fragments modified
```

### 6. ADD PARTITION — Reuse Freed Slots

When ADD PARTITION is called after DROP, the new fragment should
reuse the freed slot in `startFid[]`:

In `add_fragments_to_table()`, for RangePartition tables:
```
new_frag_id = (m_startFid_offset + partitionCount) % totalfragments

If startFid[new_frag_id] != RNIL64:
  // Slot still occupied — array needs growth
  Expand startFid[] array
  new_frag_id = totalfragments  // New slot at end
Else:
  // Reuse freed slot
  Allocate Fragmentstore at startFid[new_frag_id]
```

The range map's new `frag_ids[]` entry points to `new_frag_id`.

### 7. Table File Persistence

`m_startFid_offset` must be persisted in the table file so node
restart reconstructs the correct circular window.

In `writeTableFile` / `readTableFile`:
- Add `m_startFid_offset` to the TabRecord serialization

### 8. ha_ndbcluster.cc — Already Done

The `check_inplace_alter_supported` and `prepare_inplace_alter_table`
changes already handle `DROP_PARTITION`:
- `DROP_PARTITION` is in the `supported` flags
- Range boundaries are extracted via `ndb_extract_range_boundaries()`
- Fragment count and range data are set on `new_tab`

## Sliding Window Example

```sql
-- Initial: 3 monthly partitions
CREATE TABLE events (
  ts DATE NOT NULL, data INT,
  PRIMARY KEY(ts, data))
ENGINE=NDB
PARTITION BY RANGE COLUMNS (ts)
(PARTITION p_jan VALUES LESS THAN ('2026-02-01'),
 PARTITION p_feb VALUES LESS THAN ('2026-03-01'),
 PARTITION p_mar VALUES LESS THAN ('2026-04-01'));

-- End of month: add April, drop January
ALTER TABLE events ADD PARTITION
  (PARTITION p_apr VALUES LESS THAN ('2026-05-01'));
ALTER TABLE events DROP PARTITION p_jan;

-- startFid: [_, F1, F2, F3]  offset=1, count=3
-- F3 (April) added at slot 3, F0 (January) dropped

-- End of next month: add May, drop February
ALTER TABLE events ADD PARTITION
  (PARTITION p_may VALUES LESS THAN ('2026-06-01'));
ALTER TABLE events DROP PARTITION p_feb;

-- startFid: [F4, _, F2, F3]  offset=2, count=3
-- F4 (May) reuses slot 0, F1 (February) dropped

-- This pattern repeats indefinitely with wraparound
```

## Implementation Phases

### Phase A: Signal and Record Infrastructure
1. Add `DropFragFlag` to `AlterTableReq`
2. Add `m_startFid_offset` to `TabRecord`
3. Add `m_drop_frag_id`, `m_new_startFid_offset` to
   `ConnectRecord::m_alter`
4. Persist `m_startFid_offset` in table file read/write

### Phase B: NDB API and DBDICT
1. `NdbDictionaryImpl::alterTable()`: set DropFragFlag for
   RangePartition with decreased fragment count
2. `Dbdict::alterTable_parse()`: build new range map without
   first partition

### Phase C: DBDIH DROP Flow
1. PREPARE: install new range map
2. COMMIT: swap map, advance offset, reduce partitionCount
3. COMPLETE: send DROP_FRAG_REQ, release Fragmentstore, free old map
4. REVERT: discard new range map

### Phase D: ADD PARTITION Slot Reuse
1. Modify `add_fragments_to_table()` for range tables to reuse
   freed slots via circular indexing
2. Handle array growth when no free slots available

### Phase E: Scan Iteration Update
1. Update all scan fragment iteration to use
   `(m_startFid_offset + i) % totalfragments` for range tables
2. Verify full table scans return correct results after DROP

### Phase F: Testing
1. Basic DROP PARTITION: data gone, PK lookups work on survivors
2. ADD+DROP sliding window — multiple cycles
3. Wraparound test — enough cycles to reuse all original slots
4. Concurrent DML during DROP
5. Node restart after DROP
6. SHOW CREATE TABLE after DROP

## Open Questions

1. **How does DBLQH handle DROP_FRAG_REQ for a fragment with
   in-flight scans?**
   By COMPLETE phase, COMMIT has already made the fragment invisible
   to new scans. There may be a brief window where old scans are
   still reading the fragment. Need to verify DBLQH waits for
   running scans or that the scan-wait logic in AlterTableWaitScan
   handles this.

2. **Node restart with circular offset:**
   The table file persists `m_startFid_offset`. During restart,
   fragments are reconstructed from the table file. Slots with
   `RNIL64` are skipped. The offset tells restart which slot is
   the first live fragment.

3. **Backup/restore interaction:**
   New backups reflect the current live partitions. Restoring an
   old backup with more partitions needs special handling in
   ndb_restore.

4. **Maximum `startFid[]` array size:**
   The array grows as needed when ADD exhausts free slots. After
   wraparound stabilizes, the size equals the maximum concurrent
   partition count ever reached. No unbounded growth.
