# DROP PARTITION — MySQL Data Dictionary Integration Plan

## Problem

When NDB's inplace ALTER TABLE DROP PARTITION completes, MySQL
reopens the table and reads partition metadata from the data
dictionary (DD). The crash occurs at `dd_table_share.cc:1664`
in `get_part_column_values()` because the DD partition entries
are inconsistent with the partition definition.

## Root Cause

NDB's `commit_inplace_alter_table()` calls
`ndb_dd_table_fix_partition_count()` which adjusts the DD
partition count to match NDB's fragment count. This function:

1. **Removes partitions from the end** (lines 139-141 in
   `ndb_dd_table.cc`) — but DROP PARTITION removes from the
   front (first partition), so the wrong DD entry is removed.

2. **Adds generic partitions without values** (lines 159-163) —
   for ADD PARTITION, the new DD entries have no
   `dd::Partition_value` entries, causing
   `get_part_column_values` to fail when validating the
   value grid.

## Analysis of the Flow

```
1. ALTER TABLE t DROP PARTITION p0
2. prep_alter_part_table() marks p0 as PART_TO_BE_DROPPED
3. mysql_alter_table() creates altered_table_def (dd::Table):
   - fill_dd_partition_from_create_info() SKIPS p0
   - altered_table_def has correct partition entries
4. NDB handler: check → prepare → commit inplace alter
5. In commit_inplace_alter_table():
   - NDB returns new partition count from ndbtab
   - ndb_dd_table_check_partition_count() compares DD vs NDB
   - If mismatch: ndb_dd_table_fix_partition_count() adjusts DD
6. DD table is stored (sql_table.cc:13918)
7. Table is reopened (sql_table.cc:14102)
   - fill_partitioning_from_dd() reads partitions
   - get_part_column_values() validates — CRASH
```

The issue is in step 5: `ndb_dd_table_fix_partition_count` does
a simplistic remove-from-end or add-with-no-values. This breaks
for RANGE COLUMNS where each partition needs boundary values.

## Solution

### Option A: Fix ndb_dd_table_fix_partition_count (targeted)

For RANGE COLUMNS tables, `ndb_dd_table_fix_partition_count`
should not use the generic remove/add. Instead:

**For DROP (fewer partitions in NDB):**
- Identify WHICH partition was dropped by comparing old and new
  boundary values
- Remove that specific DD partition entry (not just from the end)
- Renumber remaining partitions sequentially

**For ADD (more partitions in NDB):**
- Create DD partition entries with proper boundary values from
  the range map data available in the NDB table definition

### Option B: Let MySQL framework handle it (preferred)

The MySQL inplace ALTER framework already handles partition DD
updates correctly through `altered_table_def`:

1. `fill_dd_partition_from_create_info()` in `dd/dd_table.cc`
   (line 1616) already skips `PART_TO_BE_DROPPED` partitions
2. The resulting `altered_table_def` has the correct DD
   partition entries with proper boundary values

The problem is that NDB's `commit_inplace_alter_table` then
OVERRIDES this by calling `ndb_dd_table_fix_partition_count`
which corrupts the already-correct `altered_table_def`.

**Fix:** In `commit_inplace_alter_table`, skip the partition
count fix for RANGE tables where the `altered_table_def` already
has the correct partition structure:

```cpp
// In commit_inplace_alter_table(), line ~17402:
const bool check_partition_count_result =
    ndb_dd_table_check_partition_count(new_table_def,
                                       ndbtab->getPartitionCount());
if (!check_partition_count_result) {
  // For range tables: the altered_table_def from MySQL already
  // has the correct partitions (with values). Don't override.
  if (ndbtab->getFragmentType() != NdbDictionary::Object::RangePartition) {
    ndb_dd_table_fix_partition_count(new_table_def,
                                     ndbtab->getPartitionCount());
  }
}
```

This works because:
- For RANGE tables, `altered_table_def` already has the correct
  partitions from `fill_dd_partition_from_create_info` which
  properly handled `PART_TO_BE_DROPPED`
- The partition count mismatch is expected: `altered_table_def`
  has the MySQL partition count (logical partitions), while NDB
  may have a different physical fragment count
- For non-RANGE tables (hash, key), the existing fix_partition_count
  logic continues to work

### Option C: Override altered_table_def partitions from NDB metadata

Build the DD partition entries from NDB's range map data in
`commit_inplace_alter_table`. This gives NDB full control over
DD partition metadata but requires more code.

## Recommendation

**Option B** is the simplest and most correct. The MySQL framework
already produces a correct `altered_table_def` with proper
partition boundary values. NDB's partition count "fix" is the thing
that breaks it.

## Implementation Steps

### Step 1: Skip partition count fix for RANGE tables

In `ha_ndbcluster.cc`, `commit_inplace_alter_table()`:

```cpp
if (!check_partition_count_result) {
  if (ndbtab->getFragmentType() !=
      NdbDictionary::Object::RangePartition) {
    ndb_dd_table_fix_partition_count(new_table_def,
                                     ndbtab->getPartitionCount());
  }
}
```

### Step 2: Re-enable DROP_PARTITION in supported flags

In `ha_ndbcluster.cc`, `check_inplace_alter_supported()`:
- Add `Alter_inplace_info::DROP_PARTITION` back to supported flags

### Step 3: Handle ADD_PARTITION DD for RANGE tables

The same fix also addresses ADD_PARTITION: `altered_table_def`
from MySQL already has the correct partition entries for the new
partition (with boundary values from the CREATE info). Skipping
`ndb_dd_table_fix_partition_count` preserves them.

Verify: does `altered_table_def` have the correct partition count
after ADD_PARTITION? If `fill_dd_partition_from_create_info`
includes the new partition with values, yes.

### Step 4: Test

- DROP PARTITION: verify table reopens cleanly, data gone, PK works
- ADD PARTITION: verify new partition has correct boundaries in DD
- Sequential ADD + DROP cycles
- SHOW CREATE TABLE after ADD/DROP

## Discovery Mechanism Analysis

### How Partition Metadata Flows in NDB

Partition boundary values are NOT stored in NDB's `RangeListData`
for DD purposes. Instead, the complete MySQL DD table definition
(including all partition entries with boundary values) is
**serialized as SDI** (Serialized Dictionary Information) and
stored in NDB's extra metadata:

```
CREATE TABLE → ha_ndbcluster.cc:
  ndb_sdi_serialize(thd, table_def, ..., sdi)
  ndbtab.setExtraMetadata(2, sdi.c_str(), sdi.length())
```

When a table is discovered on another MySQL server or after
restart, the SDI is retrieved and deserialized to reconstruct the
full DD table definition including partition boundaries.

### Discovery Path (ndb_dd_client.cc:660-807)

```
ndbcluster_discover()                    [ha_ndbcluster.cc:12409]
  → dd_client.install_table()           [ndb_dd_client.cc:660]
    → ndb_dd_sdi_deserialize(sdi, table_def)  [ndb_dd_sdi.cc:122]
      // Full DD table restored from SDI including partitions
    → ndb_dd_table_check_partition_count(table_def, ndb_num_parts)
    → ndb_dd_table_fix_partition_count(table_def, ndb_num_parts)
      // PROBLEM: may corrupt partition entries
    → thd->dd_client()->store(table_def)
```

**Key insight:** The SDI stored in NDB contains the partition
definition AS IT WAS when the table was last created or altered.
After ALTER TABLE ADD/DROP PARTITION, the SDI is updated with the
new partition structure. So `ndb_dd_sdi_deserialize` produces a
correct DD table with correct partition entries.

The `ndb_dd_table_fix_partition_count` then "fixes" the partition
count — but for RANGE tables, the SDI already has the correct
partition count and boundaries. The "fix" corrupts it.

### Schema Distribution Path

When an online ALTER TABLE is distributed to other MySQL servers:

```
SOT_ONLINE_ALTER_TABLE_COMMIT
  → handle_online_alter_table_commit()  [ha_ndbcluster_binlog.cc:2600]
    → ndb_table_get_serialized_metadata(ndbtab, metadata)
    → dd_client.deserialize_table(sdi, table_def)
    // Recreates event operation, does NOT update DD directly
```

The participant mysqld gets the new SDI from NDB (which was
updated during the ALTER). It deserializes to get the new table
definition. The DD is NOT directly updated here — the table is
invalidated and will be re-discovered on next access.

When re-discovered, `install_table()` is called which
deserializes the SDI (correct) then applies
`fix_partition_count` (potentially corrupts).

### Impact on the Fix

**Option B (skip fix_partition_count for RANGE tables) must be
applied in TWO places:**

1. **`commit_inplace_alter_table()`** — the ALTER originator
   (`ha_ndbcluster.cc:17402`)

2. **`install_table()`** — discovery/rediscovery on any mysqld
   (`ndb_dd_client.cc:700`)

In both cases, the SDI already contains the correct partition
definition. The fix_partition_count call must be skipped for
RANGE tables.

### Updated Implementation Steps

#### Step 1: Skip partition count fix in commit_inplace_alter_table

`ha_ndbcluster.cc`, around line 17402:

```cpp
if (!check_partition_count_result) {
  if (ndbtab->getFragmentType() !=
      NdbDictionary::Object::RangePartition) {
    ndb_dd_table_fix_partition_count(new_table_def,
                                     ndbtab->getPartitionCount());
  }
}
```

#### Step 2: Skip partition count fix in install_table

`ndb_dd_client.cc`, around line 700:

```cpp
if (!check_partition_count_result) {
  // For range tables: SDI already has correct partition entries
  // with boundary values. Don't override with generic entries.
  if (ndbtab->getFragmentType() !=
      NdbDictionary::Object::RangePartition) {
    ndb_dd_table_fix_partition_count(install_table.get(),
                                     ndb_num_partitions);
  }
}
```

This requires passing the NDB table's fragment type to
`install_table()`, or looking it up from the deserialized DD.

#### Step 3: Ensure SDI is updated after ALTER

When ALTER TABLE ADD/DROP PARTITION commits, the new table
metadata (including updated SDI) must be stored in NDB. This
happens in the existing flow:

```
commit_inplace_alter_table()
  → schema_dist_client.alter_table_inplace_commit()
    → NDB stores new table version with updated extra metadata
```

Verify that `ha_ndbcluster.cc`'s alter commit path updates the
SDI. The `altered_table_def` (which has correct partitions) should
be serialized and stored as the new SDI.

#### Step 4: Handle Ndb_metadata::compare for RANGE tables

`ndb_metadata.cc:1792` — `check_partition_info` only compares
partition count. For RANGE tables, NDB's physical fragment count
may differ from the DD partition count (due to the circular
offset design where `totalfragments` is the array size but
`partitionCount` is the live count). Need to use the correct
count for comparison.

Note: partition comparison is currently DISABLED in
`compare_table_def()` (`check_partitioning = false`). So this
is not immediately urgent but should be fixed when comparison
is enabled.

#### Step 5: Re-enable DROP_PARTITION in supported flags

Add `Alter_inplace_info::DROP_PARTITION` back to supported flags
in `check_inplace_alter_supported()`.

#### Step 6: Test

- Single-server: DROP, ADD, ADD+DROP cycles
- Multi-server: verify schema distribution and rediscovery
- Node restart: verify table is correctly rediscovered
- SHOW CREATE TABLE on all servers after ALTER

## Open Questions

1. **Does `ndbtab->getPartitionCount()` return the logical
   partition count (live partitions) or the physical fragment
   count (startFidSize)?**
   For the fix to work, it must return the logical count.
   Verify in DBDICT what `getPartitionCount()` reports after
   DROP PARTITION with circular offset.

2. **Is the SDI updated during ALTER TABLE?**
   The `commit_inplace_alter_table` flow updates `new_table_def`
   and MySQL stores it in the DD. But does the SDI stored in
   NDB's extra metadata also get updated? If not, rediscovery
   on other servers would get stale partition info.

3. **What if `fix_partition_count` is needed for hash-based NDB
   tables with RANGE COLUMNS fragment type?**
   This shouldn't happen — RANGE COLUMNS always uses
   `RangePartition` fragment type. But verify no edge cases.
