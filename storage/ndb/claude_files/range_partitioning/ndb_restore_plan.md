# Plan: ndb_restore Support for RangePartition Tables

## Status: Not yet implemented

## Problem

`ndb_restore -m` fails to restore metadata for tables with `RangePartition` fragment type.
The immediate failure was a test setup bug (`$NDB_BACKUPS` undefined), but proper restore
support needs verification and possibly code changes.

## Tools Assessment

| Tool | Status | Notes |
|------|--------|-------|
| ndb_desc | Working | `operator<<` already handles RangePartition |
| ndb_show_tables | Working | Fragment type is a stored attribute |
| ndb_config | N/A | Cluster config, not table metadata |
| RDRS (REST server) | Working | Uses NDB API transparently, falls back on routing failure |
| RonSQL | Working | Part of RDRS, same NDB API path |
| ndb_restore | Needs work | See below |

## ndb_restore Changes Needed

### File: `storage/ndb/tools/restore/consumer_restore.cpp`

Lines 2850-2889 handle fragment types during metadata restore. Currently only
`HashMapPartition` has special handling. RangePartition falls through to the
default case which may not preserve all required metadata.

DictTabInfo fields that must survive backup/restore:
1. `RangeListData` / `RangeListDataLen` — range boundary values
2. `RangeBoundaryType` — NDB_TYPE_* for comparison
3. `RangeStartFidOffset` — fragment ID offset after DROP PARTITION
4. `RangeLowerBound` / `RangeLowerBoundLen` — lower bound after DROP
5. Fragment count with `PartitionBalance_Specific`

These fields flow through `parseTableInfo` -> NdbTableImpl -> `serializeTableDesc`
-> kernel. The passthrough may work automatically. Need to verify by:

1. Fix test setup: add `--source suite/ndb/include/backup_restore_setup.inc`
2. Run test to see if restore works with just the setup fix
3. If it fails, add explicit RangePartition handling:

```cpp
// In consumer_restore.cpp around line 2850:
if (copy.getFragmentType() == NdbDictionary::Object::RangePartition) {
  copy.setPartitionBalance(NdbDictionary::Object::PartitionBalance_Specific);
  // Range boundaries, boundary type, and offset are preserved
  // via DictTabInfo passthrough in NdbTableImpl
} else if (copy.getFragmentType() == NdbDictionary::Object::HashMapPartition) {
  // ... existing code ...
```

### Test File: `mysql-test/suite/ndb/t/ndb_partition_range_restart2.test`

Add at top:
```
--source suite/ndb/include/backup_restore_setup.inc
```

Add at bottom:
```
--source suite/ndb/include/backup_restore_cleanup.inc
```
