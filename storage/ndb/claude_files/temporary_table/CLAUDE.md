# Temporary Tables in RonDB (RONDB-1034)

## Overview

RonDB temporary tables are NDB API-only tables designed for very fast creation and dropping.
They exist only in memory, are invisible to other NDB API sessions, and bypass most of the
distributed consensus machinery used for normal tables.

## Documentation

- `html/create_drop_table_architecture.html` — Current CREATE/DROP TABLE architecture with
  signal flow diagrams, data structures, and optimization opportunities
- `html/schema_transaction_optimization.html` — Reducing the 11 SchemaTransaction phases:
  3 phases for temp tables (no schema mutex, no disk I/O), 7 phases for normal tables
  (merged START+PARSE, FLUSH+COMMIT, FLUSH+COMPLETE)

## Current Architecture Summary

CREATE TABLE traverses: NDB API → DBDICT → DBLQH/DBTUP/DBACC → DBDIH → DBTC/DBSPJ → SUMA
with ~20+ signal round-trips, disk I/O (schema files, table files), GCP waits, and multi-node
coordination via SchemaTransaction FLUSH broadcasts.

DROP TABLE uses sequential block notification: PREP_DROP_TAB_REQ to DBLQH → DBSPJ → DBTC → DBDIH,
then DROP_TAB_REQ to DBTC → DBSPJ → DBLQH → DBDIH → DBLQH(release), totaling ~12 sequential
round-trips.

### Existing Temp Table Support (Partial)

Already working:
- NDB API: `setTemporary(true)` propagates flag through signals
- DBLQH: sets `logFlag=STATE_FALSE`, `lcpFlag=LCP_STATE_FALSE` (no redo logging, no LCP)
- DBDICT: skips `writeTableFile()` for temp tables
- DBDIH: sets `tabStorage = ST_TEMPORARY`

**Broken**: `TR_Temporary` bit in DBDICT's TableRecord is disabled (`#ifdef DOES_NOT_WORK_CURRENTLY`
at Dbdict.cpp:5843)

## Implementation Plan

### Phase 1: Fix TR_Temporary & Verify Existing Support

**Goal**: Enable the TR_Temporary bit and verify existing optimizations work.

**Changes**:
- Remove `#ifdef DOES_NOT_WORK_CURRENTLY` guard at Dbdict.cpp:5843
- Investigate why it was disabled (likely schema file or restart handling)
- Verify: no disk writes, no logging, no LCP for temp tables

**Files**: `Dbdict.cpp`
**Risk**: Low

### Phase 2: Skip Unnecessary Coordination

**Goal**: Eliminate SUMA, GCP waits, and backup mutex for temp tables.

**Changes**:
- `createTab_alterComplete()`: skip `CREATE_TAB_CONF` to SUMA when TR_Temporary
- Schema transaction complete: skip `WAIT_GCP_REQ` for temp-table-only transactions
- `dropTable_prepare()`: skip backup mutex acquisition for temp tables
- `dropTable_complete_done()`: skip `DROP_TAB_CONF` to SUMA for temp tables
- Skip schema file writes (state transitions) for temp tables

**Files**: `Dbdict.cpp`
**Savings**: ~4 signals + up to 2 seconds GCP wait
**Risk**: Low

### Phase 3: Simplify DBDIH Processing

**Goal**: DBDIH must remain (DBTC uses it for fragment routing) but can be greatly simplified.

**Changes in DBDIH (DbdihMain.cpp)**:
- Skip `ZPACK_TABLE_INTO_PAGES` — no disk persistence needed for temp tables
- Skip table file writes to disk
- Skip `ReplicaRecord` allocation — temp tables have single copy, no replicas
- Simplify fragment allocation — default single fragment, local node only
- Skip LCP queue management and `m_used_log_parts` tracking
- Skip `initTableFile()` for disk storage

**DBDIH still does**:
- Allocate `TabRecord` with `tabStatus = TS_ACTIVE` (DBTC needs this for routing)
- Allocate `Fragmentstore` records (DBTC needs fragment-to-node mapping)
- Route `ADD_FRAGREQ` through DBDICT to DBLQH (fragment creation)
- Handle `PREP_DROP_TAB_REQ` / `DROP_TAB_REQ` (set tabStatus)
- Release fragments on drop

**Files**: `DbdihMain.cpp`, `Dbdih.hpp`
**Savings**: Eliminates all disk I/O in DBDIH + continuation overhead + replica allocation
**Risk**: Medium

### Phase 4: Streamline Block Notifications

**Goal**: Parallelize sequential block notifications during DROP.

**Changes**:
- `dropTable_commit()`: send `PREP_DROP_TAB_REQ` to all blocks in parallel
  (safe for temp tables since no concurrent users from other sessions)
- `dropTable_complete()`: send `DROP_TAB_REQ` to blocks in parallel where independent
  (DBTC + DBSPJ can be parallel, DBLQH release after DBDIH)
- Consider skipping `CONNECT_TABLE_DB_REQ` for temp tables if not needed

**Files**: `Dbdict.cpp`
**Savings**: ~6 round-trips from parallelization
**Risk**: Medium

### Phase 5: Session Isolation

**Goal**: Make temp tables invisible to other NDB API sessions.

**Design**:
- Reserve a range of table IDs for temp tables (per API node)
- Natural isolation: no SUMA notifications means other sessions don't learn about the table
- Filter temp tables from `listTables()` results for non-owning sessions
- Auto-drop all session temp tables on disconnect (API node failure handling)
- Track temp table ownership in DBDICT (API node ID → table ID mapping)

**Files**: `Dbdict.cpp`, `Dbdict.hpp`, `NdbDictionaryImpl.cpp`
**Risk**: Medium

### Phase 6: Lightweight Schema Transaction

**Goal**: Eliminate multi-node coordination overhead for temp tables.

**Changes**:
- For temp tables, skip `SCHEMA_TRANS_IMPL_REQ(RT_FLUSH_PREPARE/COMMIT/COMPLETE)` broadcasts
- Execute all phases locally without waiting for other nodes
- Allocate table IDs from reserved range (avoid schema file scan in `getFreeObjId()`)

**Files**: `Dbdict.cpp`
**Savings**: 3+ network round-trips for multi-node coordination
**Risk**: High — must ensure correctness with concurrent schema operations

### Phase 7: Pre-allocation & Pooling

**Goal**: Minimize allocation latency for rapid create/drop cycles.

**Changes**:
- Pre-allocate pool of temp table IDs
- Pre-allocate Fragrecord/Fragmentstore slots for temp table use
- "Template table" concept: define schema once, rapidly instantiate data-only copies

**Files**: Various
**Risk**: Low

## Signal Flow: Optimized Temp Table

### CREATE (no disk I/O, ~12 signals):
```
API → DBDICT (lightweight schema transaction, no FLUSH broadcasts)
  → DBLQH: CREATE_TAB_REQ (via proxy) → DBTUP
  → DBLQH: LQHADDATTREQ (via proxy)
  → DBDIH: DIADDTABREQ (simplified: no replicas, no disk pack, 1 fragment)
    → DBDICT → DBLQH: LQHFRAGREQ → DBACC + DBTUP
  → DBLQH: TAB_COMMITREQ (via proxy)
  → DBTC + DBSPJ + DBDIH: TAB_COMMITREQ
  → API: CREATE_TABLE_CONF
```

### DROP (parallel, ~5 signals):
```
API → DBDICT (no backup mutex)
  → Parallel PREP_DROP_TAB_REQ: DBLQH + DBSPJ + DBTC + DBDIH
  → Parallel DROP_TAB_REQ: DBLQH(→DBACC+DBTUP) + DBSPJ + DBTC + DBDIH
  → Release DBDICT records
  → API: DROP_TABLE_CONF
```

## Key Source Files

| File | Purpose |
|------|---------|
| `storage/ndb/src/kernel/blocks/dbdict/Dbdict.cpp` | DDL orchestration, SchemaTransaction, TR_Temporary guard |
| `storage/ndb/src/kernel/blocks/dbdict/Dbdict.hpp` | TableRecord (TR_Temporary=0x8), SchemaOp, SchemaTrans |
| `storage/ndb/src/kernel/blocks/dblqh/DblqhMain.cpp` | Fragment creation (LQHFRAGREQ), temp flag, DROP_TAB state machine |
| `storage/ndb/src/kernel/blocks/dblqh/Dblqh.hpp` | Fragrecord (logFlag, lcpFlag, accFragptr, tupFragptr) |
| `storage/ndb/src/kernel/blocks/dbdih/DbdihMain.cpp` | DIADDTABREQ, fragment distribution, sendAddFragreq |
| `storage/ndb/src/kernel/blocks/dbdih/Dbdih.hpp` | TabRecord, Fragmentstore, ReplicaRecord, ST_TEMPORARY |
| `storage/ndb/src/ndbapi/NdbDictionaryImpl.cpp` | Client-side createTable, setTemporary flag |
| `storage/ndb/include/kernel/signaldata/LqhFrag.hpp` | TemporaryTable flag in LQHFRAGREQ |
| `storage/ndb/include/kernel/signaldata/DictTabInfo.hpp` | TableTemporaryFlag serialization |
| `storage/ndb/include/kernel/signaldata/DiAddTab.hpp` | temporaryTable field in DIADDTABREQ |
