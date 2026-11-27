/*
   Copyright (c) 2003, 2026, Oracle and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is designed to work with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have either included with
   the program or referenced in the documentation.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <utility>
#include <vector>

#include <signaldata/DumpStateOrd.hpp>
#include "../../src/ndbapi/NdbInfo.hpp"
#include "HugoTransactions.hpp"
#include "NDBT_ReturnCodes.h"
#include "NDBT_Test.hpp"
#include "NdbConfig.hpp"
#include "NdbRestarter.hpp"
#include "UtilTransactions.hpp"

/**
 * Global vector to keep track of
 * records stored in db
 */

struct SavedRecord {
  Uint64 m_gci;
  Uint32 m_author;
  BaseString m_str;
  SavedRecord(Uint64 _gci, Uint32 _author, BaseString _str) {
    m_gci = _gci;
    m_author = _author;
    m_str.assign(_str);
  }
  SavedRecord() {
    m_gci = 0;
    m_str = "";
  }
};
Vector<SavedRecord> savedRecords;
Uint64 highestExpectedGci;

#define CHECK(b)                                                           \
  if (!(b)) {                                                              \
    ndbout << "ERR: " << step->getName() << " failed on line " << __LINE__ \
           << endl;                                                        \
    result = NDBT_FAILED;                                                  \
    break;                                                                 \
  }

static int maybeExtraBits(Ndb *ndb, NdbDictionary::Table &tab, int when,
                          void *arg) {
  switch (when) {
    case 0:  // Before
      break;
    case 1:  // After
      return 0;
    default:
      return 0;
  }

  /* The ledger on the table variants that durable commits treat apart */
  NDBT_Context *ctx = static_cast<NDBT_Context *>(arg);
  if (ctx != nullptr && ctx->getProperty("LedgerReadBackup", Uint32(0)) != 0) {
    ndbout_c("Creating table %s with READ_BACKUP", tab.getName());
    tab.setReadBackupFlag(true);
  }
  if (ctx != nullptr &&
      ctx->getProperty("LedgerFullyReplicated", Uint32(0)) != 0) {
    ndbout_c("Creating table %s fully replicated", tab.getName());
    tab.setFullyReplicated(true);
  }

  bool useExtendedBits = ((ndb_rand() % 5) != 0);
  Uint32 numGciBits = ndb_rand() % 32;    /* 0 -> 31 */
  Uint32 numAuthorBits = ndb_rand() % 32; /* 0 -> 31 */

  if (useExtendedBits && (numGciBits || numAuthorBits)) {
    ndbout_c("Creating table %s with %u extra Gci and %u extra Author bits",
             tab.getName(), numGciBits, numAuthorBits);
    tab.setExtraRowGciBits(numGciBits);
    tab.setExtraRowAuthorBits(numAuthorBits);
  } else {
    ndbout_c("Table has no extra bits");
  }

  return 0;
}

int runDropTable(NDBT_Context *ctx, NDBT_Step *step) {
  GETNDB(step)->getDictionary()->dropTable(ctx->getTab()->getName());
  return NDBT_OK;
}

int runCreateTable(NDBT_Context *ctx, NDBT_Step *step) {
  runDropTable(ctx, step);

  /* Use extra proc to control whether we have extra bits */
  if (NDBT_Tables::createTable(GETNDB(step), ctx->getTab()->getName(), false,
                               false, maybeExtraBits, ctx) == NDBT_OK) {
    ctx->setTab(
        GETNDB(step)->getDictionary()->getTable(ctx->getTab()->getName()));
    return NDBT_OK;
  }
  return NDBT_FAILED;
}

int runInsertRememberGci(NDBT_Context *ctx, NDBT_Step *step) {
  int result = NDBT_OK;
  int records = ctx->getNumRecords();
  HugoOperations hugoOps(*ctx->getTab());
  HugoCalculator hugoCalc(*ctx->getTab());
  Ndb *pNdb = GETNDB(step);
  int i = 0;

  ndbout_c("Inserting %u records", records);
  Uint64 minGci = ~Uint64(0);
  Uint64 maxGci = 0;
  Uint32 numAuthorBits = ctx->getTab()->getExtraRowAuthorBits();
  Uint32 authorMask = (1 << numAuthorBits) - 1;
  ndbout_c("numAuthor bits is %u, mask is 0x%x", numAuthorBits, authorMask);

  while (i < records) {
    // Insert record and read it in same transaction
    CHECK(hugoOps.startTransaction(pNdb) == 0);
    CHECK(hugoOps.pkInsertRecord(pNdb, i) == 0);
    if (hugoOps.execute_NoCommit(pNdb) != 0) {
      ndbout << "Could not insert record " << i << endl;
      result = NDBT_FAILED;
      break;
    }
    /* Set the author column (if present) */
    Uint32 authorVal = 0;
    if (ctx->getTab()->getExtraRowAuthorBits() > 0) {
      authorVal = (ndb_rand() & authorMask);
      /* Pain here due to need to use NdbRecord */
      char rowBuff[NDB_MAX_TUPLE_SIZE];
      const NdbDictionary::Table *tab = ctx->getTab();
      CHECK(hugoCalc.setValues((Uint8 *)rowBuff, tab->getDefaultRecord(), i,
                               0) == 0);
      NdbOperation::SetValueSpec setValueSpec;
      setValueSpec.column = NdbDictionary::Column::ROW_AUTHOR;
      setValueSpec.value = &authorVal;
      NdbOperation::OperationOptions opts;
      opts.optionsPresent = NdbOperation::OperationOptions::OO_SETVALUE;
      opts.extraSetValues = &setValueSpec;
      opts.numExtraSetValues = 1;

      const NdbOperation *update = hugoOps.getTransaction()->updateTuple(
          tab->getDefaultRecord(), rowBuff, tab->getDefaultRecord(), rowBuff,
          NULL, /* mask */
          &opts, sizeof(opts));
      CHECK(update != NULL);
    }
    /* Read row back */
    CHECK(hugoOps.pkReadRecord(pNdb, i) == 0);
    if (hugoOps.execute_Commit(pNdb) != 0) {
      ndbout << "Did not find record in DB " << i << endl;
      result = NDBT_FAILED;
      break;
    }
    Uint64 gci;
    CHECK(hugoOps.getTransaction()->getGCI(&gci) == 0);

    if (gci < minGci) minGci = gci;
    if (gci > maxGci) maxGci = gci;

    savedRecords.push_back(
        SavedRecord(gci, authorVal, hugoOps.getRecordStr(0)));

    CHECK(hugoOps.closeTransaction(pNdb) == 0);
    i++;
    /* Sleep so that records will have > 1 GCI between them */
    NdbSleep_MilliSleep(10);
  };

  ndbout_c("  Inserted records from gci 0x%x/0x%x to gci 0x%x/0x%x",
           (Uint32)(minGci >> 32), (Uint32)(minGci & 0xffffffff),
           (Uint32)(maxGci >> 32), (Uint32)(maxGci & 0xffffffff));

  highestExpectedGci = maxGci;

  return result;
}

int runRestartAll(NDBT_Context *ctx, NDBT_Step *step) {
  Ndb *pNdb = GETNDB(step);
  NdbRestarter restarter;

  ndbout_c("Restart of all nodes");

  // Restart cluster with abort
  if (restarter.restartAll(false, false, true) != 0) {
    ctx->stopTest();
    return NDBT_FAILED;
  }

  if (restarter.waitClusterStarted(300) != 0) {
    return NDBT_FAILED;
  }

  if (pNdb->waitUntilReady() != 0) {
    return NDBT_FAILED;
  }

  return NDBT_OK;
}

int runRestartOneInitial(NDBT_Context *ctx, NDBT_Step *step) {
  Ndb *pNdb = GETNDB(step);
  NdbRestarter restarter;

  if (restarter.getNumDbNodes() < 2) return NDBT_OK;

  /* We don't restart the Master as we need to know a
   * non-restarted node to reliably get the restartGci
   * afterwards!
   * Should be no real reason not to restart the master.
   */
  int node = restarter.getRandomNotMasterNodeId(rand());
  ndbout_c("Restarting node %u initial", node);

  if (restarter.restartOneDbNode(node, true, /* Initial */
                                 false,      /* Nostart */
                                 true)       /* Abort */
      != 0) {
    ctx->stopTest();
    return NDBT_FAILED;
  }

  if (restarter.waitClusterStarted(300) != 0) {
    return NDBT_FAILED;
  }

  if (pNdb->waitUntilReady() != 0) {
    return NDBT_FAILED;
  }

  return NDBT_OK;
}

int runRestartGciControl(NDBT_Context *ctx, NDBT_Step *step) {
  int records = ctx->getNumRecords();
  Ndb *pNdb = GETNDB(step);
  UtilTransactions utilTrans(*ctx->getTab());

  // Wait until we have enough records in db
  int count = 0;
  while (count < records) {
    if (utilTrans.selectCount(pNdb, 64, &count) != 0) {
      ctx->stopTest();
      return NDBT_FAILED;
    }
    NdbSleep_MilliSleep(10);
  }

  return runRestartAll(ctx, step);
}

int runDetermineRestartGci(NDBT_Context *ctx, NDBT_Step *step) {
  Ndb *pNdb = GETNDB(step);
  Uint32 restartGci;
  int res = pNdb->getDictionary()->getRestartGCI(&restartGci);
  if (res != 0) {
    ndbout << "Failed to retrieve restart gci" << endl;
    ndbout << pNdb->getDictionary()->getNdbError() << endl;
    return NDBT_FAILED;
  }

  ndbout_c("Restart GCI is %u (0x%x)", restartGci, restartGci);

  ndbout_c("Highest expected GCI was 0x%x/0x%x", (Uint32)(highestExpectedGci >> 32),
           (Uint32)(highestExpectedGci & 0xffffffff));

  highestExpectedGci = ((Uint64)restartGci) << 32 | 0xffffffff;
  ndbout_c("Resetting Highest expected GCI to align with restart Gci (0x%x/0x%x)",
           (Uint32)(highestExpectedGci >> 32),
           (Uint32)(highestExpectedGci & 0xffffffff));
  return NDBT_OK;
}

int runRequireExact(NDBT_Context *ctx, NDBT_Step *step) {
  ctx->incProperty("ExactGCI");
  return NDBT_OK;
}

int runVerifyInserts(NDBT_Context *ctx, NDBT_Step *step) {
  int result = NDBT_OK;
  Ndb *pNdb = GETNDB(step);
  UtilTransactions utilTrans(*ctx->getTab());
  HugoOperations hugoOps(*ctx->getTab());
  NdbRestarter restarter;
  Uint32 extraGciBits = ctx->getTab()->getExtraRowGciBits();
  Uint32 firstSaturatedValue = (1 << extraGciBits) - 1;

  int count = 0;
  if (utilTrans.selectCount(pNdb, 64, &count) != 0) {
    return NDBT_FAILED;
  }

  // RULE1: The vector with saved records should have exactly as many
  // records with lower or same gci as there are in DB
  int recordsWithLowerOrSameGci = 0;
  unsigned i;
  for (i = 0; i < savedRecords.size(); i++) {
    if (savedRecords[i].m_gci <= highestExpectedGci)
      recordsWithLowerOrSameGci++;
  }
  if (recordsWithLowerOrSameGci != count) {
    ndbout << "ERR: Wrong number of expected records" << endl;
    result = NDBT_FAILED;
  }

  bool exactGCIonly = ctx->getProperty("ExactGCI", (unsigned)0);

  // RULE2: The records found in db should have same or lower
  // gci as in the vector
  int recordsWithIncorrectGci = 0;
  int recordsWithRoundedGci = 0;
  int recordsWithIncorrectAuthor = 0;
  for (i = 0; i < savedRecords.size(); i++) {
    CHECK(hugoOps.startTransaction(pNdb) == 0);
    /* First read of row to check contents */
    CHECK(hugoOps.pkReadRecord(pNdb, i) == 0);
    /* Second read of row to get GCI */
    NdbTransaction *trans = hugoOps.getTransaction();
    NdbOperation *readOp = trans->getNdbOperation(ctx->getTab());
    CHECK(readOp != NULL);
    CHECK(readOp->readTuple() == 0);
    CHECK(hugoOps.equalForRow(readOp, i) == 0);
    NdbRecAttr *rowGci = readOp->getValue(NdbDictionary::Column::ROW_GCI64);
    NdbRecAttr *rowAuthor = readOp->getValue(NdbDictionary::Column::ROW_AUTHOR);
    CHECK(rowGci != NULL);
    CHECK(rowAuthor != NULL);
    if (hugoOps.execute_Commit(pNdb) != 0) {
      // Record was not found in db'

      // Check record gci
      if (savedRecords[i].m_gci <= highestExpectedGci) {
        ndbout << "ERR: Record " << i << " should have existed" << endl;
        result = NDBT_FAILED;
      } else {
        /* It didn't exist, but that was expected.
         * Let's disappear it, so that it doesn't cause confusion
         * after further restarts.
         */
        savedRecords[i].m_gci = (Uint64(1) << 63) - 1;  // Big number
      }
    } else {
      // Record was found in db
      BaseString str = hugoOps.getRecordStr(0);
      // Check record string
      if (!(savedRecords[i].m_str == str)) {
        ndbout << "ERR: Record " << i << " str did not match " << endl;
        result = NDBT_FAILED;
      }
      // Check record gci in range
      Uint64 expectedRecordGci = savedRecords[i].m_gci;
      if (expectedRecordGci > highestExpectedGci) {
        ndbout << "ERR: Record " << i << " should not have existed" << endl;
        result = NDBT_FAILED;
      }
      bool expectRounding =
          (expectedRecordGci & 0xffffffff) >= firstSaturatedValue;
      Uint64 expectedRoundedGci = (expectedRecordGci | 0xffffffff);
      Uint64 readGci = rowGci->u_64_value();
      Uint64 expectedRead =
          (expectRounding) ? expectedRoundedGci : expectedRecordGci;
      // Check record gci is exactly correct
      if (expectedRead != readGci) {
        if ((!exactGCIonly) && (expectedRoundedGci == readGci)) {
          /* Record rounded, though bits can be represented
           * presumably due to Redo gci truncation
           */
          recordsWithRoundedGci++;
        } else {
          ndbout_c(
              "ERR: Record %u should have GCI 0x%x/0x%x, but has "
              "0x%x/0x%x.",
              i, (Uint32)(expectedRead >> 32),
              (Uint32)(expectedRead & 0xffffffff), (Uint32)(readGci >> 32),
              (Uint32)(readGci & 0xffffffff));
          recordsWithIncorrectGci++;
          result = NDBT_FAILED;
        }
      }

      // Check author value is correct.
      Uint32 expectedAuthor = savedRecords[i].m_author;

      if (rowAuthor->u_32_value() != expectedAuthor) {
        ndbout_c("ERR: Record %u should have Author %d, but has %d.", i,
                 expectedAuthor, rowAuthor->u_32_value());
        recordsWithIncorrectAuthor++;
        result = NDBT_FAILED;
      }
    }

    CHECK(hugoOps.closeTransaction(pNdb) == 0);
  }

  ndbout << "There are " << count << " records in db" << endl;
  ndbout << "There are " << savedRecords.size() << " records in vector" << endl;

  ndbout_c("There are %u records with lower or same gci than 0x%x/0x%x",
           recordsWithLowerOrSameGci, (Uint32)(highestExpectedGci >> 32),
           (Uint32)(highestExpectedGci & 0xffffffff));

  ndbout_c("There are %u records with rounded Gcis.  Exact GCI flag is %u",
           recordsWithRoundedGci, exactGCIonly);

  ndbout << "There are " << recordsWithIncorrectGci
         << " records with incorrect Gci on recovery." << endl;

  ndbout << "There are " << recordsWithIncorrectAuthor
         << " records with incorrect Author on recovery." << endl;

  return result;
}

int runClearGlobals(NDBT_Context *ctx, NDBT_Step *step) {
  savedRecords.clear();
  highestExpectedGci = 0;
  return NDBT_OK;
}

int runClearTable(NDBT_Context *ctx, NDBT_Step *step) {
  int records = ctx->getNumRecords();

  UtilTransactions utilTrans(*ctx->getTab());
  if (utilTrans.clearTable2(GETNDB(step), records, 240) != 0) {
    return NDBT_FAILED;
  }
  return NDBT_OK;
}

int runLoadTable(NDBT_Context *ctx, NDBT_Step *step) {
  int records = ctx->getNumRecords();
  HugoTransactions hugoTrans(*ctx->getTab());
  if (hugoTrans.loadTable(GETNDB(step), records, 512, false, 0, true) != 0) {
    return NDBT_FAILED;
  }
  return NDBT_OK;
}

int runNodeInitialRestarts(NDBT_Context *ctx, NDBT_Step *step) {
  NdbRestarter restarter;
  const Uint32 numRestarts = 4;
  for (Uint32 nr = 0; nr < numRestarts; nr++) {
    if (ctx->isTestStopped()) {
      return NDBT_OK;
    }
    int nodeId = restarter.getNode(NdbRestarter::NS_RANDOM);
    ndbout_c("Restarting node %u", nodeId);

    if (restarter.restartOneDbNode2(nodeId, NdbRestarter::NRRF_INITIAL) != 0) {
      ndbout_c("Error restarting node");
      ctx->stopTest();
      return NDBT_FAILED;
    }

    if (restarter.waitClusterStarted(300) != 0) {
      ctx->stopTest();
      return NDBT_FAILED;
    }

    if (GETNDB(step)->waitUntilReady() != 0) {
      ctx->stopTest();
      return NDBT_FAILED;
    }
  }

  ctx->stopTest();

  return NDBT_OK;
}

int runUpdateVerifyGCI(NDBT_Context *ctx, NDBT_Step *step) {
  HugoOperations hugoOps(*ctx->getTab());
  HugoCalculator hugoCalc(*ctx->getTab());
  Ndb *pNdb = GETNDB(step);

  /* Loop, updating the first record in the table, and checking
   * that it has the GCI it should
   */
  Uint64 loopCount = 0;
  Uint64 distinctCount = 0;
  Uint64 expectedGCI = 0;
  Uint64 lastGoodReadGCI = 0;
  Uint32 extraGciBits = ctx->getTab()->getExtraRowGciBits();
  Uint32 firstSaturatedValue = (1 << extraGciBits) - 1;
  ndbout_c("Extra GCI bits : %u, firstSaturatedValue : %u", extraGciBits,
           firstSaturatedValue);
  int result = NDBT_OK;
  while (!ctx->isTestStopped()) {
    CHECK(hugoOps.startTransaction(pNdb) == 0);
    /* Define a read op to get the 'existing' GCI */
    NdbTransaction *trans = hugoOps.getTransaction();
    CHECK(hugoOps.pkReadRecord(pNdb, 0, 1) == 0);
    NdbOperation *readOp = trans->getNdbOperation(ctx->getTab());
    CHECK(readOp != NULL);
    CHECK(readOp->readTuple() == 0);
    CHECK(hugoOps.equalForRow(readOp, 0) == 0);
    NdbRecAttr *rowGci = readOp->getValue(NdbDictionary::Column::ROW_GCI64);
    CHECK(rowGci != NULL);

    /* Define an update op to set the next GCI */
    CHECK(hugoOps.pkUpdateRecord(pNdb, 0, 1, (int)(loopCount + 1)) == 0);

    if (hugoOps.execute_Commit(pNdb) != 0) {
      if (hugoOps.getNdbError().classification == NdbError::NodeRecoveryError) {
        hugoOps.closeTransaction(pNdb);
        ndbout_c("Temporary error at loopCount %llu", loopCount);
        continue;
      }

      ndbout << "Error executing : " << hugoOps.getNdbError() << endl;
      return NDBT_FAILED;
    }

    /* First check the data is as expected */
    CHECK(hugoCalc.verifyRowValues(&hugoOps.get_row(0)) == 0);
    CHECK((Uint64)hugoCalc.getUpdatesValue(&hugoOps.get_row(0)) == loopCount);
    // ndbout_c("Updates value is %u",
    // hugoCalc.getUpdatesValue(&hugoOps.get_row(0)));

    Uint64 committedGCI;
    CHECK(trans->getGCI(&committedGCI) == 0);
    Uint32 gci_lo = Uint32(committedGCI & 0xffffffff);

    Uint64 saturatedCommittedGCI = (gci_lo >= firstSaturatedValue)
                                       ? committedGCI | 0xffffffff
                                       : committedGCI;
    Uint64 rowGCI64 = rowGci->u_64_value();
#if 0
    ndbout_c("Read row GCI64 0x%x/0x%x. "
             "  Committed GCI64 : 0x%x/0x%x.  Saturated "
             "GCI64 :0x%x/0x%x Last good read : 0x%x/0x%x",
             Uint32(rowGCI64 >> 32),
             Uint32(rowGCI64 & 0xffffffff),
             Uint32(committedGCI >> 32),
             Uint32(committedGCI & 0xffffffff),
             Uint32(saturatedCommittedGCI >> 32),
             Uint32(saturatedCommittedGCI & 0xffffffff),
             Uint32(lastGoodReadGCI >> 32),
             Uint32(lastGoodReadGCI & 0xffffffff));
#endif
    if (rowGCI64 < lastGoodReadGCI) {
      ndbout_c(
          "ERROR : Read row GCI value (0x%x/0x%x) lower than previous value "
          "(0x%x/0x%x)",
          (Uint32)(rowGCI64 >> 32), (Uint32)(rowGCI64 & 0xffffffff),
          Uint32(lastGoodReadGCI >> 32), Uint32(lastGoodReadGCI & 0xffffffff));
    }
    /* We certainly should not read a committed GCI value that's
     * bigger than the read's commit-point GCI
     */
    if (saturatedCommittedGCI < rowGCI64) {
      ndbout_c(
          "ERROR : Saturated committed GCI (0x%x/0x%x) lower than actual read GCI "
          "(0x%x/0x%x)",
          Uint32(saturatedCommittedGCI >> 32),
          Uint32(saturatedCommittedGCI & 0xffffffff), (Uint32)(rowGCI64 >> 32),
          (Uint32)(rowGCI64 & 0xffffffff));
    }
    /* If we've read a committed GCI then we should certainly not
     * be committing at lower values
     */
    if (saturatedCommittedGCI < lastGoodReadGCI) {
      ndbout_c(
          "ERROR : Saturated committed GCI (0x%x/0x%x) lower than a previously"
          "read GCI (0x%x/0x%x)",
          Uint32(saturatedCommittedGCI >> 32),
          Uint32(saturatedCommittedGCI & 0xffffffff),
          Uint32(lastGoodReadGCI >> 32), Uint32(lastGoodReadGCI & 0xffffffff));
    };
    /* If we've previously had a particular committed GCI then we
     * should certainly not now have a lower committed GCI
     */
    if (saturatedCommittedGCI < expectedGCI) {
      ndbout_c(
          "ERROR : Saturated committed GCI (0x%x/0x%x) lower than expected GCI"
          " (0x%x/0x%x)",
          Uint32(saturatedCommittedGCI >> 32),
          Uint32(saturatedCommittedGCI & 0xffffffff), Uint32(expectedGCI >> 32),
          Uint32(expectedGCI & 0xffffffff));
    }

    if (loopCount > 0) {
      if (rowGCI64 != expectedGCI) {
        ndbout_c("MISMATCH : Expected GCI of 0x%x/0x%x, but found 0x%x/0x%x",
                 (Uint32)(expectedGCI >> 32),
                 (Uint32)(expectedGCI & 0xffffffff), (Uint32)(rowGCI64 >> 32),
                 (Uint32)(rowGCI64 & 0xffffffff));
        ndbout_c("At loopcount %llu", loopCount);
        ndbout_c("Last good read GCI 0x%x/0x%x", Uint32(lastGoodReadGCI >> 32),
                 Uint32(lastGoodReadGCI & 0xffffffff));
        ndbout_c("Read committed GCI : 0x%x/0x%x",
                 Uint32(saturatedCommittedGCI >> 32),
                 Uint32(saturatedCommittedGCI & 0xffffffff));
        ndbout_c("Transaction coordinator node : %u",
                 trans->getConnectedNodeId());
        return NDBT_FAILED;
      }

      if (saturatedCommittedGCI != expectedGCI) {
        distinctCount++;
      }
    }

    expectedGCI = saturatedCommittedGCI;
    lastGoodReadGCI = rowGCI64;

    hugoOps.closeTransaction(pNdb);
    loopCount++;

    /* Sleep to avoid excessive updating */
    NdbSleep_MilliSleep(10);
  }

  ndbout_c("%llu updates with %llu distinct GCI values", loopCount,
           distinctCount);

  return result;
}

/**
 * RONDB-1150 (recovery plan S7.4): the GCP-saved ledger. Writer steps
 * insert, update and delete the rows of their own key range in
 * transactions of 1 to 8 rows, and keep the history of each row: the GCI
 * of each committed transaction, and a transaction whose result is
 * unknown, after which the writer leaves its rows alone until they are
 * checked. After a system restart from GCI R a row holds what the last
 * of its committed transactions with a GCI up to R wrote, or what an
 * unknown transaction after it wrote; after a node restart the last
 * committed one, or an unknown one after it. A transaction with an
 * unknown result is in all of its rows or in none. Committed
 * transactions with a GCI after R are lost, which a system restart
 * allows; the count is reported, as durable commits will bring it to 0.
 */
namespace {

constexpr int LEDGER_WRITERS = 4;  // the STEPS of a ledger test case
constexpr Uint32 LEDGER_MAX_ROWS = 8;
const char *const LEDGER_PAUSE = "LedgerPause";
const char *const LEDGER_PARKED = "LedgerParked";

enum LedgerOp : Uint32 { LEDGER_INSERT, LEDGER_UPDATE, LEDGER_DELETE };
enum LedgerState : Uint32 { LEDGER_COMMITTED, LEDGER_UNKNOWN };

struct LedgerTxn {
  Uint64 id;   // writer << 32 | transaction number
  Uint64 gci;  // the commit GCI, 0 when unknown
  Uint32 op;
  Uint32 updates;  // written by an insert or an update
  Uint32 state;
};

struct LedgerRow {
  /* The row as read back when the round started */
  bool exists = false;
  Uint32 updates = 0;
  Uint64 gci = 0;
  /* The transactions of this round on the row, in commit order */
  std::vector<LedgerTxn> txns;
  /* Its last transaction has an unknown result */
  bool blocked = false;
  /* The row as the writer has left it */
  bool curExists = false;
  Uint32 nextUpdates = 0;
};

std::vector<LedgerRow> g_ledger;

/* ROW_GCI64 as committed, or with the low word rounded up */
bool ledgerGciMatches(Uint64 readGci, Uint64 gci) {
  return readGci == gci || readGci == (gci | 0xffffffff);
}

const char *ledgerOpName(Uint32 op) {
  return op == LEDGER_INSERT ? "insert"
                             : op == LEDGER_UPDATE ? "update" : "delete";
}

/* The row r as it is: whether it exists, its updates value and GCI */
int ledgerReadRow(NDBT_Context *ctx, NDBT_Step *step, HugoOperations &hugoOps,
                  HugoCalculator &hugoCalc, Uint32 r, bool *exists,
                  Uint32 *updates, Uint64 *gci) {
  Ndb *pNdb = GETNDB(step);
  for (int attempt = 0; attempt < 100; attempt++) {
    if (hugoOps.startTransaction(pNdb) != 0) {
      NdbSleep_MilliSleep(100);
      continue;
    }
    NdbRecAttr *rowGci = nullptr;
    if (hugoOps.pkReadRecord(pNdb, r) == 0) {
      NdbOperation *readOp =
          hugoOps.getTransaction()->getNdbOperation(ctx->getTab());
      if (readOp != nullptr && readOp->readTuple() == 0 &&
          hugoOps.equalForRow(readOp, r) == 0) {
        rowGci = readOp->getValue(NdbDictionary::Column::ROW_GCI64);
      }
    }
    if (rowGci == nullptr) {
      ndbout_c("ERR: ledger: could not define the read of row %u", r);
      hugoOps.closeTransaction(pNdb);
      return NDBT_FAILED;
    }
    const int res = hugoOps.execute_Commit(pNdb);
    if (res == 0) {
      NDBT_ResultRow &row = hugoOps.get_row(0);
      if (hugoCalc.verifyRowValues(&row) != 0) {
        ndbout_c("ERR: ledger: row %u has wrong values", r);
        hugoOps.closeTransaction(pNdb);
        return NDBT_FAILED;
      }
      *exists = true;
      *updates = hugoCalc.getUpdatesValue(&row);
      *gci = rowGci->u_64_value();
      hugoOps.closeTransaction(pNdb);
      return NDBT_OK;
    }
    if (res == 626) {
      *exists = false;
      *updates = 0;
      *gci = 0;
      hugoOps.closeTransaction(pNdb);
      return NDBT_OK;
    }
    const NdbError err = hugoOps.getNdbError();
    hugoOps.closeTransaction(pNdb);
    if (err.status == NdbError::PermanentError) {
      ndbout << "ERR: ledger: read of row " << r << ": " << err << endl;
      return NDBT_FAILED;
    }
    NdbSleep_MilliSleep(100);
  }
  ndbout_c("ERR: ledger: row %u could not be read", r);
  return NDBT_FAILED;
}

/**
 * G3 of the durable-commits plan: every replica of a fragment of the
 * ledger table, and of its unique indexes, has as many rows and as many
 * fixed- and var-size elements (ndbinfo frag_mem_use, summed over the LDM
 * instances of a node), as include/ndb_assert_frag_replica_consistency.inc
 * checks in MTR. The writers are parked; ndbinfo reads are live, so a
 * difference, or a fragment that fewer nodes report than it has replicas,
 * as just after a node started, is read again for a while.
 */
bool ledgerReplicasAgree(NDBT_Context *ctx, NDBT_Step *step,
                         const char *what,
                         const NdbDictionary::Table *tab = nullptr) {
  if (tab == nullptr) tab = ctx->getTab();
  std::set<Uint32> tableIds = {Uint32(tab->getObjectId())};
  NdbDictionary::Dictionary::List indexes;
  if (GETNDB(step)->getDictionary()->listIndexes(indexes, *tab) != 0) {
    ndbout << "ERR: ledger: the indexes of " << tab->getName() << ": "
           << GETNDB(step)->getDictionary()->getNdbError() << endl;
    return false;
  }
  for (unsigned i = 0; i < indexes.count; i++) {
    if (indexes.elements[i].type == NdbDictionary::Object::UniqueHashIndex) {
      tableIds.insert(indexes.elements[i].id);
    }
  }
  NdbRestarter restarter;
  const size_t replicas = size_t(std::max(restarter.getNumReplicas(), 1));
  NdbInfo ndbinfo(&ctx->m_cluster_connection, "ndbinfo/");
  const NdbInfo::Table *fragMemUse = nullptr;
  if (!ndbinfo.init() ||
      ndbinfo.openTable("ndbinfo/frag_mem_use", &fragMemUse) != 0) {
    ndbout_c("ERR: ledger: ndbinfo frag_mem_use cannot be read");
    return false;
  }
  /* (table, fragment) -> node -> rows, fixed and var-size elements */
  using Counts = std::array<Uint64, 3>;
  std::map<std::pair<Uint32, Uint32>, std::map<Uint32, Counts>> frags;
  char mismatch[256] = "";
  bool agree = false;
  for (int attempt = 0; attempt < 60 && !agree; attempt++) {
    if (attempt > 0) NdbSleep_MilliSleep(500);
    frags.clear();
    NdbInfoScanOperation *scanOp = nullptr;
    if (ndbinfo.createScanOperation(fragMemUse, &scanOp) != 0) continue;
    const NdbInfoRecAttr *nodeId = nullptr;
    const NdbInfoRecAttr *tableId = nullptr;
    const NdbInfoRecAttr *fragNo = nullptr;
    const NdbInfoRecAttr *rows = nullptr;
    const NdbInfoRecAttr *fixedElems = nullptr;
    const NdbInfoRecAttr *varElems = nullptr;
    int ret = scanOp->readTuples();
    if (ret == 0) {
      nodeId = scanOp->getValue("node_id");
      tableId = scanOp->getValue("table_id");
      fragNo = scanOp->getValue("fragment_num");
      rows = scanOp->getValue("rows");
      fixedElems = scanOp->getValue("fixed_elem_count");
      varElems = scanOp->getValue("var_elem_count");
      ret = scanOp->execute();
    }
    while (ret == 0 && (ret = scanOp->nextResult()) == 1) {
      ret = 0;
      if (tableIds.count(tableId->u_32_value()) == 0) continue;
      Counts &c = frags[{tableId->u_32_value(), fragNo->u_32_value()}]
                       [nodeId->u_32_value()];
      c[0] += rows->u_64_value();
      c[1] += fixedElems->u_64_value();
      c[2] += varElems->u_64_value();
    }
    ndbinfo.releaseScanOperation(scanOp);
    if (ret != 0) continue;  // the scan failed
    agree = !frags.empty();
    BaseString::snprintf(mismatch, sizeof(mismatch),
                         "no fragment of table %u in frag_mem_use",
                         tab->getObjectId());
    for (const auto &frag : frags) {
      if (frag.second.size() < replicas) {
        agree = false;
        BaseString::snprintf(mismatch, sizeof(mismatch),
                             "table %u fragment %u: %u of %u replicas",
                             frag.first.first, frag.first.second,
                             Uint32(frag.second.size()), Uint32(replicas));
        break;
      }
      const auto first = frag.second.begin();
      for (const auto &node : frag.second) {
        if (node.second != first->second) {
          agree = false;
          BaseString::snprintf(
              mismatch, sizeof(mismatch),
              "table %u fragment %u: node %u has %llu rows, %llu fixed and "
              "%llu var-size elements, node %u %llu, %llu and %llu",
              frag.first.first, frag.first.second, first->first,
              first->second[0], first->second[1], first->second[2],
              node.first, node.second[0], node.second[1], node.second[2]);
          break;
        }
      }
      if (!agree) break;
    }
  }
  ndbinfo.closeTable(fragMemUse);
  if (!agree) {
    ndbout_c("ERR: ledger after the %s: the replicas differ: %s", what,
             mismatch);
    return false;
  }
  ndbout_c("Ledger after the %s: the replicas of %u fragments agree", what,
           Uint32(frags.size()));
  return true;
}

void ledgerPrintRow(Uint32 r, const LedgerRow &row) {
  ndbout_c("  row %u at the round's start: %s, updates %u, GCI 0x%x/0x%x", r,
           row.exists ? "exists" : "absent", row.updates,
           Uint32(row.gci >> 32), Uint32(row.gci));
  for (const LedgerTxn &t : row.txns) {
    ndbout_c("  writer %u transaction %u: %s, updates %u, %s, GCI 0x%x/0x%x",
             Uint32(t.id >> 32), Uint32(t.id), ledgerOpName(t.op), t.updates,
             t.state == LEDGER_COMMITTED ? "committed" : "unknown result",
             Uint32(t.gci >> 32), Uint32(t.gci));
  }
}

/**
 * Every row against its history, the writers parked; maxGci is the
 * highest GCI that the restart kept, and with allKept no committed
 * transaction may have a later one. The next round starts from the rows
 * as they are.
 */
int ledgerVerify(NDBT_Context *ctx, NDBT_Step *step, Uint64 maxGci,
                 const char *what, bool allKept = false,
                 bool replicas = true) {
  HugoOperations hugoOps(*ctx->getTab());
  HugoCalculator hugoCalc(*ctx->getTab());
  std::map<Uint64, std::pair<Uint32, Uint32>> unknownTxns;  // with, without
  Uint32 kept = 0;
  Uint32 lost = 0;
  Uint64 maxLostGci = 0;
  Uint32 unknownRows = 0;
  Uint32 failures = 0;
  for (Uint32 r = 0; r < g_ledger.size(); r++) {
    LedgerRow &row = g_ledger[r];
    bool exists = false;
    Uint32 updates = 0;
    Uint64 gci = 0;
    if (ledgerReadRow(ctx, step, hugoOps, hugoCalc, r, &exists, &updates,
                      &gci) != NDBT_OK) {
      return NDBT_FAILED;
    }
    bool expExists = row.exists;
    Uint32 expUpdates = row.updates;
    Uint64 expGci = row.gci;
    const LedgerTxn *unknown = nullptr;
    bool rowLost = false;
    for (const LedgerTxn &t : row.txns) {
      if (t.state == LEDGER_UNKNOWN) {
        unknown = &t;
        break;
      }
      if (t.gci > maxGci) {
        /* A later transaction on the row has a GCI at least this one's */
        lost++;
        rowLost = true;
        for (const LedgerTxn &l : row.txns) {
          if (l.state == LEDGER_COMMITTED && l.gci > maxGci) {
            maxLostGci = std::max(maxLostGci, l.gci);
          }
        }
        break;
      }
      kept++;
      expExists = t.op != LEDGER_DELETE;
      expUpdates = t.updates;
      expGci = t.gci;
    }
    bool ok = exists == expExists &&
              (!exists ||
               (updates == expUpdates && ledgerGciMatches(gci, expGci)));
    if (unknown != nullptr) {
      unknownRows++;
      const bool uExists = unknown->op != LEDGER_DELETE;
      const bool asUnknown =
          !ok && exists == uExists &&
          (!exists || (updates == unknown->updates &&
                       (gci >> 32) <= (maxGci >> 32)));
      std::pair<Uint32, Uint32> &seen = unknownTxns[unknown->id];
      if (asUnknown) {
        seen.first++;
      } else {
        seen.second++;
      }
      ok = ok || asUnknown;
    }
    if (allKept && rowLost) {
      failures++;
      ndbout_c(
          "ERR: ledger after the %s: row %u lost a committed transaction "
          "with a GCI after the restart's 0x%x",
          what, r, Uint32(maxGci >> 32));
      ledgerPrintRow(r, row);
    } else if (!ok) {
      failures++;
      ndbout_c(
          "ERR: ledger after the %s: row %u %s, updates %u, GCI 0x%x/0x%x; "
          "expected %s, updates %u, GCI 0x%x/0x%x",
          what, r, exists ? "exists" : "absent", updates, Uint32(gci >> 32),
          Uint32(gci), expExists ? "exists" : "absent", expUpdates,
          Uint32(expGci >> 32), Uint32(expGci));
      ledgerPrintRow(r, row);
    }
    row.exists = exists;
    row.updates = updates;
    row.gci = gci;
    row.txns.clear();
    row.blocked = false;
    row.curExists = exists;
  }
  for (const auto &txn : unknownTxns) {
    if (txn.second.first > 0 && txn.second.second > 0) {
      failures++;
      ndbout_c(
          "ERR: ledger after the %s: transaction %u of writer %u, whose "
          "result was unknown, is in %u of its rows and not in %u",
          what, Uint32(txn.first), Uint32(txn.first >> 32), txn.second.first,
          txn.second.second);
    }
  }
  /* Not after a partial system restart: a replica of some fragments is down */
  if (replicas && !ledgerReplicasAgree(ctx, step, what)) failures++;
  ndbout_c(
      "Ledger after the %s: %u rows, %u row writes kept, %u row writes "
      "acknowledged and lost, %u rows of %u transactions with an unknown "
      "result, %u failures",
      what, Uint32(g_ledger.size()), kept, lost, unknownRows,
      Uint32(unknownTxns.size()), failures);
  if (lost > 0) {
    /* What durable commits are to bring to 0 */
    ndbout_c("Ledger after the %s: restart GCI %u, highest lost GCI 0x%x/0x%x",
             what, Uint32(maxGci >> 32), Uint32(maxLostGci >> 32),
             Uint32(maxLostGci));
  }
  return failures == 0 ? NDBT_OK : NDBT_FAILED;
}

/* False if a writer stopped the test */
bool ledgerSleep(NDBT_Context *ctx, Uint32 seconds) {
  for (Uint32 i = 0; i < 100 * seconds; i++) {
    if (ctx->isTestStopped()) return false;
    NdbSleep_MilliSleep(10);
  }
  return !ctx->isTestStopped();
}

bool ledgerPause(NDBT_Context *ctx) {
  ctx->setProperty(LEDGER_PAUSE, Uint32(1));
  for (int i = 0; i < 30000; i++) {
    if (ctx->getProperty(LEDGER_PARKED, Uint32(0)) == Uint32(LEDGER_WRITERS)) {
      return true;
    }
    if (ctx->isTestStopped()) return false;
    NdbSleep_MilliSleep(10);
  }
  ndbout_c("ERR: ledger: the writers did not stop");
  return false;
}

void ledgerResume(NDBT_Context *ctx) {
  ctx->setProperty(LEDGER_PAUSE, Uint32(0));
}

/**
 * The GCI that the last system restart restored. DBDIH knows it only on
 * the nodes that took part in that restart (crestartGci); a node that
 * joined by a node restart answers 0, as when one node stopped before the
 * other and the other restarted the cluster alone. The API sends
 * WAIT_GCP_REQ to the alive data nodes in turn, so each is asked twice
 * and the highest answer is taken.
 */
bool ledgerRestartGci(Ndb *pNdb, NdbRestarter &restarter, Uint32 *gci) {
  *gci = 0;
  for (int i = 0; i < 2 * restarter.getNumDbNodes(); i++) {
    Uint32 nodeGci = 0;
    if (pNdb->getDictionary()->getRestartGCI(&nodeGci) != 0) {
      ndbout << "ERR: ledger: no restart GCI: "
             << pNdb->getDictionary()->getNdbError() << endl;
      return false;
    }
    *gci = std::max(*gci, nodeGci);
  }
  if (*gci == 0) {
    ndbout_c("ERR: ledger: no data node answered the restart GCI");
    return false;
  }
  return true;
}

/* The check once a system restart is done, the writers parked */
int ledgerCheckRestart(NDBT_Context *ctx, NDBT_Step *step, const char *what,
                       bool allKept) {
  Ndb *pNdb = GETNDB(step);
  NdbRestarter restarter;
  if (restarter.waitClusterStarted(300) != 0 || pNdb->waitUntilReady() != 0) {
    return NDBT_FAILED;
  }
  Uint32 restartGci = 0;
  if (!ledgerRestartGci(pNdb, restarter, &restartGci)) return NDBT_FAILED;
  ndbout_c("Ledger: restart GCI %u", restartGci);
  /**
   * RONDB-1150, X5: with durable commits a restart keeps every
   * acknowledged transaction, after a crash too; the restart GCI is G',
   * up to which phase 2 executed the durable tail.
   */
  allKept = allKept || ctx->getProperty("LedgerDurable", Uint32(0)) != 0;
  return ledgerVerify(ctx, step, (Uint64(restartGci) << 32) | 0xffffffff,
                      what, allKept);
}

/* A system restart with abort while the writers write, then the check */
int ledgerSystemRestart(NDBT_Context *ctx, NDBT_Step *step) {
  NdbRestarter restarter;
  ndbout_c("Ledger: system restart with abort");
  if (restarter.restartAll(false, false, true) != 0) {
    return NDBT_FAILED;
  }
  /* No transaction starts before the check; those under way fail */
  if (!ledgerPause(ctx)) return NDBT_FAILED;
  const int res = ledgerCheckRestart(ctx, step, "system restart", false);
  ledgerResume(ctx);
  return res;
}

/**
 * The writers write for a while after the check of a crash, then, parked,
 * a graceful system restart: the shutdown saves the GCI of every
 * committed transaction (WaitGCPReq::ShutdownSync), so all of them stay.
 * The writers are parked on entry and on return.
 */
int ledgerCleanRestart(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  NdbRestarter restarter;
  ledgerResume(ctx);
  if (!ledgerSleep(ctx, seconds) || !ledgerPause(ctx)) return NDBT_FAILED;
  ndbout_c("Ledger: graceful system restart");
  if (restarter.restartAll() != 0) return NDBT_FAILED;
  return ledgerCheckRestart(ctx, step, "graceful system restart", true);
}

/**
 * RONDB-1150 (recovery plan S7.1): the crash error inserts of the PMEM
 * REDO log, those of the write path and those of a restart; 5162 and 5163
 * act in both (5160 belongs to another test).
 */
const Uint32 LEDGER_WRITE_CODES[] = {5155, 5156, 5157, 5158, 5159, 5161,
                                     5162, 5163, 5164, 5165, 5166, 5171};
const Uint32 LEDGER_RESTART_CODES[] = {5172, 5167, 5168, 5169,
                                       5170, 5162, 5163};
/* Until the data nodes stop at an insert; a file switch takes the longest */
constexpr Uint32 LEDGER_STOP_SECONDS = 600;
/* Restarts until an insert of a restart acts (5169 needs a COMMIT to undo) */
constexpr Uint32 LEDGER_RESTART_ATTEMPTS = 5;

std::vector<int> ledgerDataNodes(NdbRestarter &restarter) {
  std::vector<int> nodes;
  for (int i = 0; i < restarter.getNumDbNodes(); i++) {
    nodes.push_back(restarter.getDbNodeId(i));
  }
  return nodes;
}

/* StopOnError=0 on every data node */
bool ledgerStartsAgainOnError() {
  NdbConfig conf;
  for (int i = 0; i < conf.getNumDbNodes(); i++) {
    Uint32 stop = 1;
    conf.getProperty(conf.getDbNodeId(i), NODE_TYPE_DB, CFG_DB_STOP_ON_ERROR,
                     &stop);
    if (stop != 0) return false;
  }
  return true;
}

/* The crash of an error insert, or of DUMP 2370, leaves the nodes in NOSTART */
bool ledgerNoStartOnCrash(NdbRestarter &restarter,
                          const std::vector<int> &nodes) {
  const int noStart[] = {DumpStateOrd::CmvmiSetRestartOnErrorInsert,
                         1 /* NRT_NoStart_Restart */};
  for (int node : nodes) {
    if (restarter.dumpStateOneNode(node, noStart, 2) != 0) {
      ndbout_c("ERR: ledger: could not set RestartOnErrorInsert in node %d",
               node);
      return false;
    }
  }
  return true;
}

/* Error insert code with its extra value (seed or count) in the nodes */
bool ledgerArm(NdbRestarter &restarter, const std::vector<int> &nodes,
               Uint32 code, Uint32 extra) {
  if (!ledgerNoStartOnCrash(restarter, nodes)) return false;
  for (int node : nodes) {
    if (restarter.insertError2InNode(node, code, extra) != 0) {
      ndbout_c("ERR: ledger: could not set error insert %u in node %d", code,
               node);
      return false;
    }
  }
  return true;
}

/* No error insert, and RestartOnErrorInsert as configured */
void ledgerDisarm(NdbRestarter &restarter) {
  const int reset = DumpStateOrd::CmvmiSetRestartOnErrorInsert;
  restarter.insertErrorInAllNodes(0);
  restarter.dumpStateAllNodes(&reset, 1);
}

/**
 * Waits until the nodes have stopped, one at least at its crash error
 * insert: none of them runs, and one is in NOSTART again. Only the crash
 * of an insert leaves a node in NOSTART, as ledgerArm() set; a node that
 * fails as the cluster or its restart fails exits with StopOnError=1, and
 * starts again with StopOnError=0. A node counts once it has stayed in
 * NOSTART for 2 s, as one that starts again passes through it. Returns
 * the number of nodes in NOSTART; 0 when they all started instead, if
 * started; -1 at the timeout.
 */
int ledgerWaitStopped(NdbRestarter &restarter, const std::vector<int> &nodes,
                      bool started, Uint32 seconds) {
  std::vector<bool> away(nodes.size(), false);
  std::vector<Uint32> noStartPolls(nodes.size(), 0);
  for (Uint32 i = 0; i < 10 * seconds; i++) {
    Uint32 running = 0;
    Uint32 noStart = 0;
    for (size_t n = 0; n < nodes.size(); n++) {
      const int status = restarter.getNodeStatus(nodes[n]);
      if (status != NDB_MGM_NODE_STATUS_NOT_STARTED) {
        away[n] = true;
        noStartPolls[n] = 0;
      } else if (away[n] && ++noStartPolls[n] >= 20) {
        noStart++;
      }
      if (status == NDB_MGM_NODE_STATUS_STARTED) running++;
    }
    if (started && running == nodes.size()) return 0;
    if (noStart > 0 && running == 0) return int(noStart);
    NdbSleep_MilliSleep(100);
  }
  return -1;
}

/**
 * Every node in NOSTART for 2 s: those that did not stop there are
 * restarted into it with abort. A node that exited (StopOnError=1) does
 * not come back.
 */
bool ledgerAllNoStart(NdbRestarter &restarter, const std::vector<int> &nodes) {
  std::vector<Uint32> nextRestart(nodes.size(), 0);  // one each 5 s
  Uint32 stable = 0;
  for (Uint32 i = 0; i < 1200; i++) {
    bool all = true;
    for (size_t n = 0; n < nodes.size(); n++) {
      const int status = restarter.getNodeStatus(nodes[n]);
      if (status == NDB_MGM_NODE_STATUS_NOT_STARTED) continue;
      all = false;
      if ((status == NDB_MGM_NODE_STATUS_STARTING ||
           status == NDB_MGM_NODE_STATUS_STARTED) &&
          i >= nextRestart[n]) {
        ndbout_c("Ledger: node %d restarted with abort into NOSTART",
                 nodes[n]);
        restarter.restartOneDbNode(nodes[n], false, true, true);
        nextRestart[n] = i + 50;
      }
    }
    stable = all ? stable + 1 : 0;
    if (stable >= 20) return true;
    NdbSleep_MilliSleep(100);
  }
  for (int node : nodes) {
    if (restarter.getNodeStatus(node) != NDB_MGM_NODE_STATUS_NOT_STARTED) {
      ndbout_c("ERR: ledger: node %d is not in NOSTART (status %d)%s", node,
               restarter.getNodeStatus(node),
               ledgerStartsAgainOnError()
                   ? ""
                   : "; with StopOnError=1 a node that the stop of another "
                     "fails does not start again");
    }
  }
  return false;
}

/**
 * After the data nodes stopped, one at least at a crash: every node in
 * NOSTART, a system restart, the check, then with clean a graceful system
 * restart and its check. The writers are parked.
 */
int ledgerRestartAfterStop(NDBT_Context *ctx, NDBT_Step *step,
                           NdbRestarter &restarter,
                           const std::vector<int> &nodes, bool clean) {
  if (!ledgerAllNoStart(restarter, nodes) || restarter.startAll() != 0) {
    return NDBT_FAILED;
  }
  int res = ledgerCheckRestart(ctx, step, "system restart", false);
  if (res == NDBT_OK && clean) res = ledgerCleanRestart(ctx, step);
  return res;
}

/**
 * The data nodes stop while the writers write, by the crash error insert
 * or the DUMP that the caller set (what), each node in NOSTART or as the
 * cluster fails; then the restarts of ledgerRestartAfterStop().
 */
int ledgerStopAll(NDBT_Context *ctx, NDBT_Step *step, NdbRestarter &restarter,
                  const std::vector<int> &nodes, const char *what,
                  bool clean) {
  const int stopped =
      ledgerWaitStopped(restarter, nodes, false, LEDGER_STOP_SECONDS);
  if (stopped <= 0) {
    ndbout_c("ERR: ledger: the data nodes did not stop at %s in %u s", what,
             LEDGER_STOP_SECONDS);
    ledgerDisarm(restarter);
    return NDBT_FAILED;
  }
  ndbout_c("Ledger: the data nodes stopped at %s, %d of %u back in NOSTART "
           "so far",
           what, stopped, Uint32(nodes.size()));
  if (!ledgerPause(ctx)) return NDBT_FAILED;
  const int res = ledgerRestartAfterStop(ctx, step, restarter, nodes, clean);
  ledgerResume(ctx);
  return res;
}

/**
 * RONDB-1150, X5.10: with durable commits DUMP 2371 makes a crash of every
 * data node one of all at once: each node stops at the first report of a
 * node failure. Without it (LedgerStopTogether 0) the node that stops
 * last may go on committing without the others, a node failure in the
 * tail (D3, plan §5.4), which the node-failure file of X6 handles: the
 * other node is stale and joins by a node restart.
 */
bool ledgerStopTogether(NDBT_Context *ctx, NdbRestarter &restarter) {
  if (ctx->getProperty("LedgerDurable", Uint32(0)) == 0 ||
      ctx->getProperty("LedgerStopTogether", Uint32(1)) == 0) {
    return true;
  }
  const int together = DumpStateOrd::QmgrStopOnNodeFailure;
  if (restarter.dumpStateAllNodes(&together, 1) != 0) {
    ndbout_c("ERR: ledger: could not send DUMP 2371");
    return false;
  }
  return true;
}

/* A crash error insert of the write path in every data node */
int ledgerWriteCrash(NDBT_Context *ctx, NDBT_Step *step, Uint32 code,
                     Uint32 extra, bool clean) {
  NdbRestarter restarter;
  const std::vector<int> nodes = ledgerDataNodes(restarter);
  char what[64];
  BaseString::snprintf(what, sizeof(what), "error insert %u", code);
  ndbout_c("Ledger: %s in every data node while the writers write", what);
  if (!ledgerStopTogether(ctx, restarter) ||
      !ledgerArm(restarter, nodes, code, extra)) {
    return NDBT_FAILED;
  }
  return ledgerStopAll(ctx, step, restarter, nodes, what, clean);
}

/**
 * A crash error insert of a restart in a system restart: after a system
 * restart with abort the insert is set in every data node in NOSTART, and
 * the start stops at it. Then the restarts of ledgerRestartAfterStop().
 * A node that sees another stop fails the system restart, so this needs
 * StopOnError=0. If the insert did not act, the system restart is checked
 * all the same, and *acted is false.
 */
int ledgerRestartCrashSR(NDBT_Context *ctx, NDBT_Step *step, Uint32 code,
                         bool *acted) {
  NdbRestarter restarter;
  const std::vector<int> nodes = ledgerDataNodes(restarter);
  *acted = false;
  ndbout_c("Ledger: system restart with abort, then error insert %u in "
           "every data node",
           code);
  if (restarter.restartAll(false, true, true) != 0) return NDBT_FAILED;
  if (!ledgerPause(ctx)) return NDBT_FAILED;
  int res = NDBT_FAILED;
  if (restarter.waitClusterNoStart(300) == 0 &&
      ledgerArm(restarter, nodes, code, 0) && restarter.startAll() == 0) {
    const int stopped =
        ledgerWaitStopped(restarter, nodes, true, LEDGER_STOP_SECONDS);
    if (stopped < 0) {
      ndbout_c("ERR: ledger: the system restart with error insert %u did "
               "neither stop nor end in %u s",
               code, LEDGER_STOP_SECONDS);
    } else if (stopped == 0) {
      ndbout_c("Ledger: error insert %u did not act in the system restart",
               code);
      ledgerDisarm(restarter);
      res = ledgerCheckRestart(ctx, step, "system restart", false);
    } else {
      ndbout_c("Ledger: %d of %u data nodes stopped at error insert %u",
               stopped, Uint32(nodes.size()), code);
      *acted = true;
      res = ledgerRestartAfterStop(ctx, step, restarter, nodes, true);
    }
  }
  ledgerResume(ctx);
  return res;
}

/**
 * A crash error insert of a restart in a node restart, while the writers
 * write: the node restarts with abort into NOSTART, the insert is set,
 * and its start stops at it; the next start ends. Every committed
 * transaction is there, and after a graceful system restart too. If the
 * insert did not act, the node restart is checked all the same, and
 * *acted is false.
 */
int ledgerRestartCrashNR(NDBT_Context *ctx, NDBT_Step *step, Uint32 code,
                         bool *acted) {
  NdbRestarter restarter;
  const int node = restarter.getNode(NdbRestarter::NS_RANDOM);
  const std::vector<int> nodes(1, node);
  *acted = false;
  ndbout_c("Ledger: node restart of node %d with abort, then error insert "
           "%u in it",
           node, code);
  if (restarter.restartOneDbNode(node, false, true, true) != 0 ||
      restarter.waitNodesNoStart(&node, 1, 300) != 0 ||
      !ledgerArm(restarter, nodes, code, 0) ||
      restarter.startNodes(&node, 1) != 0) {
    return NDBT_FAILED;
  }
  const int stopped =
      ledgerWaitStopped(restarter, nodes, true, LEDGER_STOP_SECONDS);
  if (stopped < 0) {
    ndbout_c("ERR: ledger: the restart of node %d with error insert %u did "
             "neither stop nor end in %u s",
             node, code, LEDGER_STOP_SECONDS);
    return NDBT_FAILED;
  }
  if (stopped > 0) {
    ndbout_c("Ledger: node %d stopped at error insert %u", node, code);
    *acted = true;
    if (restarter.startNodes(&node, 1) != 0) return NDBT_FAILED;
  } else {
    ndbout_c("Ledger: error insert %u did not act in the node restart", code);
    ledgerDisarm(restarter);
  }
  if (restarter.waitClusterStarted(300) != 0 || !ledgerPause(ctx)) {
    return NDBT_FAILED;
  }
  int res = ledgerVerify(ctx, step, ~Uint64(0), "node restart");
  if (res == NDBT_OK && *acted) res = ledgerCleanRestart(ctx, step);
  ledgerResume(ctx);
  return res;
}

/* RONDB-1150, X6.8: the data nodes but down */
std::vector<int> ledgerOtherNodes(const std::vector<int> &nodes, int down) {
  std::vector<int> rest;
  for (int node : nodes) {
    if (node != down) rest.push_back(node);
  }
  return rest;
}

/**
 * RONDB-1150, X6.8: the data nodes stop, the others of nodes being down
 * already, stop together while the writers write: DUMP 2371 in each, then
 * one restarts with abort into NOSTART and the others stop at its
 * failure, as a power loss of them all. Then every data node is in
 * NOSTART.
 */
bool ledgerStopTogether(NdbRestarter &restarter, const std::vector<int> &nodes,
                        const std::vector<int> &stop) {
  if (stop.empty()) return true;
  const int together = DumpStateOrd::QmgrStopOnNodeFailure;
  if (!ledgerNoStartOnCrash(restarter, stop)) return false;
  for (int node : stop) {
    if (restarter.dumpStateOneNode(node, &together, 1) != 0) {
      ndbout_c("ERR: ledger: could not send DUMP 2371 to node %d", node);
      return false;
    }
  }
  if (restarter.restartOneDbNode(stop[0], false, true, true) != 0) {
    return false;
  }
  return ledgerAllNoStart(restarter, nodes);
}

/* RONDB-1150, X6.8: the data nodes but down (0 for none) stop together */
bool ledgerStopRestTogether(NdbRestarter &restarter,
                            const std::vector<int> &nodes, int down) {
  return ledgerStopTogether(restarter, nodes, ledgerOtherNodes(nodes, down));
}

/**
 * RONDB-1150, X6.8 (plan §5.4): a node failure in the durable tail. GCP
 * saves stop (error insert 7243 in every data node, as any may become
 * master), survivorCode is set in the other nodes, and node x restarts
 * with abort into NOSTART; the writers commit on its peers alone for a
 * while, then the others stop together, so every sysfile still shows x
 * restorable to R. With survivorCode 990 the others stop instead as they
 * record the failure. Then the system restart: x is stale and joins by a
 * node restart, and every acknowledged transaction stays with identical
 * replicas (D3); with 991 the failure is not recorded and the check must
 * fail. *started is false if the cluster did not start.
 */
int ledgerNodeFailureInTail(NDBT_Context *ctx, NDBT_Step *step,
                            Uint32 survivorCode, const char *what,
                            bool *started) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  NdbRestarter restarter;
  const std::vector<int> nodes = ledgerDataNodes(restarter);
  const int x = restarter.getNode(NdbRestarter::NS_RANDOM);
  const std::vector<int> rest = ledgerOtherNodes(nodes, x);
  *started = false;
  ndbout_c("Ledger: %s: GCP saves stopped (error insert 7243), node %d "
           "restarts with abort into NOSTART%s",
           what, x,
           survivorCode == 990   ? ", the others stop as they record it"
           : survivorCode == 991 ? ", the others do not record it"
                                 : "");
  if (restarter.insertErrorInAllNodes(7243) != 0 ||
      (survivorCode != 0 && !ledgerArm(restarter, rest, survivorCode, 0))) {
    ndbout_c("ERR: ledger: could not set the error inserts");
    return NDBT_FAILED;
  }
  /* A GCP save under way ends; R is the last one */
  NdbSleep_MilliSleep(1000);
  if (restarter.restartOneDbNode(x, false, true, true) != 0 ||
      restarter.waitNodesNoStart(&x, 1, 300) != 0) {
    return NDBT_FAILED;
  }
  if (survivorCode == 990) {
    if (!ledgerAllNoStart(restarter, nodes)) return NDBT_FAILED;
  } else if (!ledgerSleep(ctx, seconds) ||
             !ledgerStopRestTogether(restarter, nodes, x)) {
    return NDBT_FAILED;
  }
  if (!ledgerPause(ctx)) return NDBT_FAILED;
  int res = NDBT_FAILED;
  if (restarter.startAll() == 0 && restarter.waitClusterStarted(300) == 0) {
    *started = true;
    res = ledgerCheckRestart(ctx, step, what, true);
  }
  ledgerResume(ctx);
  return res;
}

/**
 * RONDB-1150, X6.8 (X6.7): every data node stops together, and node x
 * reports an unsafe shutdown of its persistent memory at its start (error
 * insert 992, set in NOSTART). x is stale: it runs for president as one
 * not restorable on its own, and joins by a node restart after the
 * system restart; every acknowledged transaction stays.
 */
int ledgerUnsafeShutdown(NDBT_Context *ctx, NDBT_Step *step) {
  NdbRestarter restarter;
  const std::vector<int> nodes = ledgerDataNodes(restarter);
  const int x = restarter.getNode(NdbRestarter::NS_RANDOM);
  ndbout_c("Ledger: every data node stops together; node %d reports an "
           "unsafe shutdown (error insert 992)",
           x);
  if (!ledgerStopRestTogether(restarter, nodes, 0) || !ledgerPause(ctx) ||
      !ledgerArm(restarter, std::vector<int>(1, x), 992, 0) ||
      restarter.startAll() != 0) {
    return NDBT_FAILED;
  }
  const int res =
      ledgerCheckRestart(ctx, step, "system restart after an unsafe shutdown",
                         true);
  ledgerDisarm(restarter);
  ledgerResume(ctx);
  return res;
}

/**
 * RONDB-1150, X6.8 (X6.5, plan §5.5, D5): every data node stops together
 * while the writers write; the system restart runs without node y, one of
 * a node group, after StartPartialTimeout. Every acknowledged transaction
 * stays, also one whose only COMPLETE was in y's log, by the counts of
 * the fallback. Then y joins by a node restart and the replicas agree.
 */
int ledgerPartialSR(NDBT_Context *ctx, NDBT_Step *step) {
  NdbRestarter restarter;
  Ndb *pNdb = GETNDB(step);
  const std::vector<int> nodes = ledgerDataNodes(restarter);
  const int y = restarter.getNode(NdbRestarter::NS_RANDOM);
  const std::vector<int> rest = ledgerOtherNodes(nodes, y);
  ndbout_c("Ledger: every data node stops together; the system restart "
           "runs without node %d",
           y);
  if (!ledgerStopRestTogether(restarter, nodes, 0) || !ledgerPause(ctx) ||
      restarter.startNodes(rest.data(), int(rest.size())) != 0 ||
      restarter.waitNodesStarted(rest.data(), int(rest.size()), 300) != 0 ||
      pNdb->waitUntilReady() != 0) {
    return NDBT_FAILED;
  }
  Uint32 restartGci = 0;
  if (!ledgerRestartGci(pNdb, restarter, &restartGci)) return NDBT_FAILED;
  ndbout_c("Ledger: restart GCI %u without node %d", restartGci, y);
  int res = ledgerVerify(ctx, step, (Uint64(restartGci) << 32) | 0xffffffff,
                         "partial system restart", true, false);
  if (res == NDBT_OK) {
    if (restarter.startNodes(&y, 1) != 0 ||
        restarter.waitClusterStarted(300) != 0) {
      res = NDBT_FAILED;
    } else {
      res = ledgerVerify(ctx, step, ~Uint64(0),
                         "node restart after the partial system restart");
    }
  }
  ledgerResume(ctx);
  return res;
}

/**
 * RONDB-1150, X6.8, X6.9: the system restart of nodes waits for seconds.
 * Returns the node that started, or 0 when every node waited; -1 when a
 * node stopped instead, as one does that ends the restart with an error
 * (2353, say), or is not starting at the end.
 */
static int ledgerRestartWaits(NdbRestarter &restarter,
                              const std::vector<int> &nodes, Uint32 seconds) {
  std::vector<bool> starting(nodes.size(), false);
  for (Uint32 i = 0; i < 10 * seconds; i++) {
    for (size_t k = 0; k < nodes.size(); k++) {
      const int status = restarter.getNodeStatus(nodes[k]);
      if (status == NDB_MGM_NODE_STATUS_STARTED) return nodes[k];
      if (status == NDB_MGM_NODE_STATUS_STARTING) {
        starting[k] = true;
      } else if (status >= 0 && starting[k]) {
        ndbout_c("ERR: ledger: node %d stopped (status %d) instead of "
                 "waiting in the system restart",
                 nodes[k], status);
        return -1;
      }
    }
    NdbSleep_MilliSleep(100);
  }
  for (size_t k = 0; k < nodes.size(); k++) {
    if (restarter.getNodeStatus(nodes[k]) != NDB_MGM_NODE_STATUS_STARTING) {
      ndbout_c("ERR: ledger: node %d is not waiting in the system restart "
               "after %u s",
               nodes[k], seconds);
      return -1;
    }
  }
  return 0;
}

/**
 * RONDB-1150, X6.3: the system restart of nodes ends within seconds, as
 * a node stops that ends it with an error (2353, say). Returns that node;
 * 0 when every node still starts at the end, -1 when a node started.
 */
static int ledgerRestartStops(NdbRestarter &restarter,
                              const std::vector<int> &nodes, Uint32 seconds) {
  std::vector<bool> starting(nodes.size(), false);
  for (Uint32 i = 0; i < 10 * seconds; i++) {
    for (size_t k = 0; k < nodes.size(); k++) {
      const int status = restarter.getNodeStatus(nodes[k]);
      if (status == NDB_MGM_NODE_STATUS_STARTED) return -1;
      if (status == NDB_MGM_NODE_STATUS_STARTING) {
        starting[k] = true;
      } else if (status >= 0 && starting[k]) {
        return nodes[k];
      }
    }
    NdbSleep_MilliSleep(100);
  }
  return 0;
}

/**
 * RONDB-1150, X6.3: every data node stops together, and at its start each
 * takes the failure of every other node as recorded after any GCI (error
 * insert 993, set in NOSTART), as with a node-failure file left by an
 * earlier cluster: every node is stale. The election must still settle on
 * a president, whose check_startup() ends the system restart with 2353,
 * as no node can restore its node group; every node kept itself as its
 * candidate before, and the restart hung. Then every node starts without
 * the error insert and every acknowledged transaction stays. Needs
 * StopOnError=0, so that the node that ends the restart starts again.
 */
int ledgerAllStaleStops(NDBT_Context *ctx, NDBT_Step *step) {
  NdbRestarter restarter;
  const std::vector<int> nodes = ledgerDataNodes(restarter);
  ndbout_c("Ledger: every data node stops together; each finds every other "
           "node stale (error insert 993)");
  if (!ledgerStopRestTogether(restarter, nodes, 0) || !ledgerPause(ctx) ||
      !ledgerArm(restarter, nodes, 993, 0) || restarter.startAll() != 0) {
    return NDBT_FAILED;
  }
  const int stopped = ledgerRestartStops(restarter, nodes, 60);
  if (stopped <= 0) {
    ndbout_c(stopped == 0
                 ? "ERR: ledger: the system restart of stale nodes did not "
                   "end in 60 s; the election hangs"
                 : "ERR: ledger: a node started although every node is "
                   "stale");
    ledgerDisarm(restarter);
    ledgerResume(ctx);
    return NDBT_FAILED;
  }
  ndbout_c("Ledger: node %d ended the system restart of stale nodes",
           stopped);
  int res = NDBT_FAILED;
  if (ledgerAllNoStart(restarter, nodes) && restarter.startAll() == 0) {
    res = ledgerCheckRestart(ctx, step,
                             "system restart after one of stale nodes", true);
  }
  ledgerDisarm(restarter);
  ledgerResume(ctx);
  return res;
}

/**
 * RONDB-1150, X6.8 (X6.4, plan §5.5, D4): node x fails in the durable
 * tail and the writers commit on both node groups; every node stops
 * together, and x's peer y does not start. x is stale, so its node group
 * has no node that can restore it: the system restart waits, 10 s past
 * StartPartialTimeout, until y starts. Then x joins by a node restart and
 * every acknowledged transaction stays.
 */
int ledgerStaleGroupWaits(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  NdbRestarter restarter;
  Uint32 partialMs = 30000;
  {
    NdbConfig conf;
    conf.getProperty(restarter.getDbNodeId(0), NODE_TYPE_DB,
                     CFG_DB_START_PARTIAL_TIMEOUT, &partialMs);
  }
  const Uint32 wait = partialMs / 1000 + 10;
  const std::vector<int> nodes = ledgerDataNodes(restarter);
  const int x = restarter.getNode(NdbRestarter::NS_RANDOM);
  const int y = restarter.getRandomNodeSameNodeGroup(x, ndb_rand());
  const std::vector<int> rest = ledgerOtherNodes(nodes, y);
  ndbout_c("Ledger: GCP saves stopped (error insert 7243), node %d restarts "
           "with abort into NOSTART, the others stop later; the system "
           "restart waits for node %d",
           x, y);
  if (y < 0 || restarter.insertErrorInAllNodes(7243) != 0) {
    return NDBT_FAILED;
  }
  NdbSleep_MilliSleep(1000);
  if (restarter.restartOneDbNode(x, false, true, true) != 0 ||
      restarter.waitNodesNoStart(&x, 1, 300) != 0 || !ledgerSleep(ctx, seconds) ||
      !ledgerStopRestTogether(restarter, nodes, x) || !ledgerPause(ctx) ||
      restarter.startNodes(rest.data(), int(rest.size())) != 0) {
    return NDBT_FAILED;
  }
  const int started = ledgerRestartWaits(restarter, rest, wait);
  if (started != 0) {
    if (started > 0) {
      ndbout_c("ERR: ledger: node %d started without node %d, the only "
               "node that can restore the node group of stale node %d",
               started, y, x);
    }
    ledgerResume(ctx);
    return NDBT_FAILED;
  }
  ndbout_c("Ledger: the system restart waited %u s for node %d; it starts",
           wait, y);
  int res = NDBT_FAILED;
  if (restarter.startNodes(&y, 1) == 0) {
    res = ledgerCheckRestart(ctx, step,
                             "system restart once the stale node's group "
                             "can be restored",
                             true);
  }
  ledgerResume(ctx);
  return res;
}

/**
 * RONDB-1150, X6.9: nodes x and z, of two node groups, fail in the durable
 * tail and record nothing of each other, as nodes that fail together (z
 * has error insert 991 when x fails); the writers commit on their peers y
 * and w alone, which then stop together. Only x and z start: no node
 * group has all its nodes, and nothing here shows that x and z are
 * stale, so the system restart waits, 10 s past StartPartialTimeout and
 * StartPartitionedTimeout, until y and w start. Then x and z are stale
 * and join by node restarts, and every acknowledged transaction stays.
 */
int ledgerPartitionedSRWaits(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  NdbRestarter restarter;
  Uint32 partialMs = 30000;
  Uint32 partitionedMs = 0;
  {
    NdbConfig conf;
    conf.getProperty(restarter.getDbNodeId(0), NODE_TYPE_DB,
                     CFG_DB_START_PARTIAL_TIMEOUT, &partialMs);
    conf.getProperty(restarter.getDbNodeId(0), NODE_TYPE_DB,
                     CFG_DB_START_PARTITION_TIMEOUT, &partitionedMs);
  }
  const Uint32 wait = (partialMs + partitionedMs) / 1000 + 10;
  const std::vector<int> nodes = ledgerDataNodes(restarter);
  const int x = restarter.getNode(NdbRestarter::NS_RANDOM);
  const int z = restarter.getRandomNodeOtherNodeGroup(x, ndb_rand());
  const int y = restarter.getRandomNodeSameNodeGroup(x, ndb_rand());
  const int w =
      z < 0 ? -1 : restarter.getRandomNodeSameNodeGroup(z, ndb_rand());
  if (z < 0 || y < 0 || w < 0) {
    ndbout_c("ERR: ledger: no two node groups of two nodes");
    return NDBT_FAILED;
  }
  const int failed[] = {x, z};
  const std::vector<int> peers = {y, w};
  ndbout_c("Ledger: GCP saves stopped (error insert 7243), nodes %d and %d "
           "fail together, the writers commit on nodes %d and %d, which "
           "stop later; the system restart of nodes %d and %d waits%s",
           x, z, y, w, x, z,
           partitionedMs == 0 ? " (StartPartitionedTimeout=0 waits anyway)"
                              : "");
  if (restarter.insertErrorInAllNodes(7243) != 0 ||
      restarter.insertErrorInNode(z, 991) != 0) {
    ndbout_c("ERR: ledger: could not set the error inserts");
    return NDBT_FAILED;
  }
  /* A GCP save under way ends; R is the last one */
  NdbSleep_MilliSleep(1000);
  if (restarter.restartOneDbNode(x, false, true, true) != 0 ||
      restarter.waitNodesNoStart(&x, 1, 300) != 0 ||
      restarter.restartOneDbNode(z, false, true, true) != 0 ||
      restarter.waitNodesNoStart(failed, 2, 300) != 0 ||
      !ledgerSleep(ctx, seconds) ||
      !ledgerStopTogether(restarter, nodes, peers) || !ledgerPause(ctx) ||
      restarter.startNodes(failed, 2) != 0) {
    return NDBT_FAILED;
  }
  const int started =
      ledgerRestartWaits(restarter, std::vector<int>(failed, failed + 2), wait);
  if (started != 0) {
    if (started > 0) {
      ndbout_c("ERR: ledger: node %d started, with no node group having "
               "all its nodes; nodes %d and %d committed without nodes %d "
               "and %d",
               started, y, w, x, z);
    }
    ledgerResume(ctx);
    return NDBT_FAILED;
  }
  ndbout_c("Ledger: the system restart of nodes %d and %d waited %u s; "
           "nodes %d and %d start",
           x, z, wait, y, w);
  int res = NDBT_FAILED;
  if (restarter.startNodes(peers.data(), int(peers.size())) == 0) {
    res = ledgerCheckRestart(ctx, step,
                             "system restart once a node group has all its "
                             "nodes",
                             true);
  }
  ledgerResume(ctx);
  return res;
}

/* RONDB-1150, X5.9: the column added online in the durable tail */
constexpr const char *LEDGER_SCHEMA_COLUMN = "LEDGER_X59";
/* Rows per transaction of the schema test */
constexpr Uint32 LEDGER_SCHEMA_BATCH = 8;

/* RONDB-1150, X5.9: a copy of the ledger table named name */
const NdbDictionary::Table *ledgerCopyTable(NDBT_Context *ctx, Ndb *pNdb,
                                            const char *name) {
  NdbDictionary::Dictionary *dict = pNdb->getDictionary();
  NdbDictionary::Table copy(*ctx->getTab());
  copy.setName(name);
  (void)dict->dropTable(name);
  if (dict->createTable(copy) != 0) {
    ndbout << "ERR: ledger: create table " << name << ": "
           << dict->getNdbError() << endl;
    return nullptr;
  }
  return dict->getTable(name);
}

/**
 * RONDB-1150, X5.9: rows [0, rows) of tab inserted, or updated, to the
 * updates value, LEDGER_SCHEMA_BATCH rows in each transaction; a
 * temporary error is retried
 */
bool ledgerSchemaWrite(Ndb *pNdb, const NdbDictionary::Table *tab,
                       Uint32 rows, bool insert, Uint32 updates) {
  HugoOperations ops(*tab);
  for (Uint32 r = 0; r < rows; r += LEDGER_SCHEMA_BATCH) {
    const Uint32 n = std::min(LEDGER_SCHEMA_BATCH, rows - r);
    for (int attempt = 0;; attempt++) {
      int res = ops.startTransaction(pNdb);
      if (res == 0) {
        res = insert ? ops.pkInsertRecord(pNdb, r, n, updates)
                     : ops.pkUpdateRecord(pNdb, r, n, updates);
      }
      if (res == 0) res = ops.execute_Commit(pNdb);
      const NdbError err = ops.getNdbError();
      ops.closeTransaction(pNdb);
      if (res == 0) break;
      if (err.status == NdbError::TemporaryError && attempt < 100) {
        NdbSleep_MilliSleep(100);
        continue;
      }
      ndbout << "ERR: ledger: " << (insert ? "insert" : "update")
             << " of rows " << r << "-" << r + n - 1 << " of "
             << tab->getName() << ": " << err << endl;
      return false;
    }
  }
  return true;
}

/* RONDB-1150, X5.9: tab holds rows [0, rows), each at the updates value */
bool ledgerSchemaCheck(Ndb *pNdb, const NdbDictionary::Table *tab,
                       Uint32 rows, Uint32 updates) {
  int count = -1;
  UtilTransactions util(*tab);
  if (util.selectCount(pNdb, 64, &count) != 0 || count != int(rows)) {
    ndbout_c("ERR: ledger: table %s has %d rows, %u expected", tab->getName(),
             count, rows);
    return false;
  }
  HugoOperations ops(*tab);
  HugoCalculator calc(*tab);
  for (Uint32 r = 0; r < rows; r += LEDGER_SCHEMA_BATCH) {
    const Uint32 n = std::min(LEDGER_SCHEMA_BATCH, rows - r);
    int res = ops.startTransaction(pNdb);
    if (res == 0) res = ops.pkReadRecord(pNdb, r, n);
    if (res == 0) res = ops.execute_Commit(pNdb);
    if (res != 0) {
      ndbout << "ERR: ledger: read of rows " << r << "-" << r + n - 1
             << " of " << tab->getName() << ": " << ops.getNdbError() << endl;
      ops.closeTransaction(pNdb);
      return false;
    }
    for (Uint32 i = 0; i < n; i++) {
      NDBT_ResultRow &row = ops.get_row(i);
      if (calc.verifyRowValues(&row) != 0 ||
          Uint32(calc.getUpdatesValue(&row)) != updates) {
        ndbout_c("ERR: ledger: row %u of %s is not at update %u", r + i,
                 tab->getName(), updates);
        ops.closeTransaction(pNdb);
        return false;
      }
    }
    ops.closeTransaction(pNdb);
  }
  return true;
}

/**
 * RONDB-1150, X5.9: tab with a nullable dynamic column added online. It
 * is the last unsigned column, so HugoCalculator counts the updates in
 * it: every row must be updated after this.
 */
const NdbDictionary::Table *ledgerAddColumn(Ndb *pNdb,
                                            const NdbDictionary::Table *tab) {
  NdbDictionary::Dictionary *dict = pNdb->getDictionary();
  NdbDictionary::Table altered(*tab);
  NdbDictionary::Column col(LEDGER_SCHEMA_COLUMN);
  col.setType(NdbDictionary::Column::Unsigned);
  col.setNullable(true);
  col.setDynamic(true);
  altered.addColumn(col);
  const BaseString name(tab->getName());
  if (dict->alterTable(*tab, altered) != 0) {
    ndbout << "ERR: ledger: add column to " << name.c_str() << ": "
           << dict->getNdbError() << endl;
    return nullptr;
  }
  dict->invalidateTable(name.c_str());
  return dict->getTable(name.c_str());
}

/* RONDB-1150, X5.9: tab with a fragment more per data node, online */
const NdbDictionary::Table *ledgerAddPartitions(
    Ndb *pNdb, NdbRestarter &restarter, const NdbDictionary::Table *tab) {
  NdbDictionary::Dictionary *dict = pNdb->getDictionary();
  NdbDictionary::Table altered(*tab);
  altered.setFragmentCount(tab->getFragmentCount() + restarter.getNumDbNodes());
  altered.setPartitionBalance(NdbDictionary::Object::PartitionBalance_Specific);
  const BaseString name(tab->getName());
  if (dict->beginSchemaTrans() != 0 ||
      dict->prepareHashMap(*tab, altered) == -1 ||
      dict->endSchemaTrans() != 0 || dict->alterTable(*tab, altered) != 0) {
    ndbout << "ERR: ledger: add partitions to " << name.c_str() << ": "
           << dict->getNdbError() << endl;
    return nullptr;
  }
  dict->invalidateTable(name.c_str());
  return dict->getTable(name.c_str());
}

}  // namespace

/**
 * The crash error inserts and DUMP 2370 act in PMEM mode only, DUMP 2370
 * with the power-loss emulation (property LedgerPowerLoss)
 */
int runLedgerNeedsPmem(NDBT_Context *ctx, NDBT_Step *step) {
  const bool powerLoss = ctx->getProperty("LedgerPowerLoss", Uint32(0)) != 0;
  const bool durable = ctx->getProperty("LedgerDurable", Uint32(0)) != 0;
  NdbConfig conf;
  for (int i = 0; i < conf.getNumDbNodes(); i++) {
    const int node = conf.getDbNodeId(i);
    Uint32 mode = NDB_REDO_LOG_MODE_FILE;
    Uint32 emul = 0;
    Uint32 durableCommits = 0;
    conf.getProperty(node, NODE_TYPE_DB, CFG_DB_REDO_LOG_MODE, &mode);
    conf.getProperty(node, NODE_TYPE_DB, CFG_DB_REDO_PMEM_POWER_LOSS_EMUL,
                     &emul);
    conf.getProperty(node, NODE_TYPE_DB, CFG_DB_DURABLE_COMMITS,
                     &durableCommits);
    if (mode != NDB_REDO_LOG_MODE_PMEM || (powerLoss && emul == 0) ||
        (durable && durableCommits == 0)) {
      ndbout_c("Node %d: this test needs RedoLogMode=pmem%s%s", node,
               powerLoss ? " and __RedoLogPmemPowerLossEmulation=1" : "",
               durable ? " and __DurableCommits=1" : "");
      return NDBT_SKIPPED;
    }
  }
  return NDBT_OK;
}

int runLedgerInit(NDBT_Context *ctx, NDBT_Step *step) {
  g_ledger.assign(ctx->getNumRecords(), LedgerRow());
  /**
   * RONDB-1150: the cluster decides whether commits are durable, not the
   * test case. Every ledger case run on a cluster with __DurableCommits=1
   * in all data nodes follows the durable rules (LedgerDurable): a node
   * failure abort at commit (4010) is an unknown result, since phase 2 of
   * the restart commits the transaction if its COMMITs were persistent,
   * and a restart keeps every acknowledged transaction.
   */
  if (ctx->getProperty("LedgerDurable", Uint32(0)) == 0) {
    NdbConfig conf;
    const int dbNodes = conf.getNumDbNodes();
    bool durable = dbNodes > 0;
    for (int i = 0; i < dbNodes && durable; i++) {
      Uint32 durableCommits = 0;
      conf.getProperty(conf.getDbNodeId(i), NODE_TYPE_DB,
                       CFG_DB_DURABLE_COMMITS, &durableCommits);
      durable = durableCommits != 0;
    }
    if (durable) {
      ndbout_c("Ledger: __DurableCommits=1 in every data node, the durable "
               "rules apply");
      ctx->setProperty("LedgerDurable", Uint32(1));
    }
  }
  ctx->setProperty(LEDGER_PAUSE, Uint32(0));
  ctx->setProperty(LEDGER_PARKED, Uint32(0));
  return NDBT_OK;
}

int runLedgerWriter(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 writerNo = step->getStepTypeNo();
  const Uint32 range = Uint32(g_ledger.size()) / step->getStepTypeCount();
  const Uint32 first = writerNo * range;
  if (range == 0) {
    ndbout_c("ERR: ledger: fewer records than writers");
    return NDBT_FAILED;
  }
  Ndb *pNdb = GETNDB(step);
  HugoOperations hugoOps(*ctx->getTab());
  Uint32 txnNo = 0;
  Uint32 waits = 0;
  while (!ctx->isTestStopped()) {
    if (ctx->getProperty(LEDGER_PAUSE, Uint32(0)) != 0) {
      ctx->incProperty(LEDGER_PARKED);
      while (ctx->getProperty(LEDGER_PAUSE, Uint32(0)) != 0 &&
             !ctx->isTestStopped()) {
        NdbSleep_MilliSleep(10);
      }
      ctx->decProperty(LEDGER_PARKED);
      continue;
    }
    const Uint32 nRows = 1 + ndb_rand() % std::min(LEDGER_MAX_ROWS, range);
    const Uint32 r0 = first + ndb_rand() % (range - nRows + 1);
    bool blocked = false;
    for (Uint32 r = r0; r < r0 + nRows; r++) blocked |= g_ledger[r].blocked;
    if (blocked) {
      /* Rows with an unknown result wait for the check */
      if (++waits % 64 == 0) NdbSleep_MilliSleep(1);
      continue;
    }
    if (hugoOps.startTransaction(pNdb) != 0) {
      /* The cluster is not there */
      NdbSleep_MilliSleep(100);
      continue;
    }
    LedgerTxn txns[LEDGER_MAX_ROWS];
    bool defined = true;
    for (Uint32 i = 0; i < nRows && defined; i++) {
      LedgerRow &row = g_ledger[r0 + i];
      LedgerTxn &t = txns[i];
      t.id = (Uint64(writerNo) << 32) | txnNo;
      t.gci = 0;
      t.updates = 0;
      t.state = LEDGER_UNKNOWN;
      if (!row.curExists) {
        t.op = LEDGER_INSERT;
        t.updates = row.nextUpdates++;
        defined = hugoOps.pkInsertRecord(pNdb, r0 + i, 1, t.updates) == 0;
      } else if (ndb_rand() % 5 == 0) {
        t.op = LEDGER_DELETE;
        defined = hugoOps.pkDeleteRecord(pNdb, r0 + i, 1) == 0;
      } else {
        t.op = LEDGER_UPDATE;
        t.updates = row.nextUpdates++;
        defined = hugoOps.pkUpdateRecord(pNdb, r0 + i, 1, t.updates) == 0;
      }
    }
    txnNo++;
    if (!defined) {
      hugoOps.closeTransaction(pNdb);
      NdbSleep_MilliSleep(10);
      continue;
    }
    const int res = hugoOps.execute_Commit(pNdb);
    const NdbError err = hugoOps.getTransaction()->getNdbError();
    Uint64 gci = 0;
    /**
     * A commit that the takeover of a failed TC reports (TCKEY_FAILCONF)
     * has no GCI: after a system restart it may be there or not, as a
     * transaction with an unknown result.
     */
    const bool committed = res == 0 &&
                           hugoOps.getTransaction()->getGCI(&gci) == 0 &&
                           gci != 0;
    /**
     * RONDB-1150, X5: with durable commits a transaction whose COMMITs are
     * persistent commits at the restart, also when every data node fails
     * before the API learns it. The API reports that as a node failure
     * abort (4010, Ndb::abortTransactionsAfterNodeFailure()), so such an
     * error at commit is an unknown result here.
     */
    const bool durableUnknown =
        ctx->getProperty("LedgerDurable", Uint32(0)) != 0 &&
        err.status == NdbError::TemporaryError &&
        err.classification == NdbError::NodeRecoveryError;
    if (committed || err.status == NdbError::UnknownResult ||
        err.status == NdbError::Success || durableUnknown) {
      /* Committed, or perhaps */
      for (Uint32 i = 0; i < nRows; i++) {
        LedgerRow &row = g_ledger[r0 + i];
        LedgerTxn &t = txns[i];
        if (committed) {
          t.gci = gci;
          t.state = LEDGER_COMMITTED;
          row.curExists = t.op != LEDGER_DELETE;
        } else {
          row.blocked = true;
        }
        row.txns.push_back(t);
      }
      if (!committed && res == 0) {
        ndbout_c("Ledger: writer %u transaction %u, rows %u-%u: committed "
                 "by a takeover, GCI unknown",
                 writerNo, txnNo - 1, r0, r0 + nRows - 1);
      } else if (!committed) {
        ndbout_c("Ledger: writer %u transaction %u, rows %u-%u: unknown "
                 "result, error %d",
                 writerNo, txnNo - 1, r0, r0 + nRows - 1, err.code);
      }
    } else if (err.status == NdbError::PermanentError) {
      /* The ledger and the rows disagree */
      ndbout << "ERR: ledger: writer " << writerNo << " transaction "
             << txnNo - 1 << ", rows " << r0 << "-" << r0 + nRows - 1 << ": "
             << err << endl;
      for (Uint32 i = 0; i < nRows; i++) {
        ledgerPrintRow(r0 + i, g_ledger[r0 + i]);
      }
      hugoOps.closeTransaction(pNdb);
      ctx->stopTest();
      return NDBT_FAILED;
    } else {
      /* Aborted */
      NdbSleep_MilliSleep(10);
    }
    hugoOps.closeTransaction(pNdb);
  }
  return NDBT_OK;
}

int runLedgerSR(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  int result = NDBT_OK;
  for (int l = 0; l < ctx->getNumLoops() && result == NDBT_OK; l++) {
    if (!ledgerSleep(ctx, seconds)) {
      result = NDBT_FAILED;
      break;
    }
    ndbout_c("Ledger loop %d", l);
    result = ledgerSystemRestart(ctx, step);
  }
  ctx->stopTest();
  return result;
}

/**
 * A node restart with abort while the writers write: every committed
 * transaction stays. Then a system restart.
 */
int runLedgerNR(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  NdbRestarter restarter;
  int result = NDBT_OK;
  for (int l = 0; l < ctx->getNumLoops() && result == NDBT_OK; l++) {
    if (!ledgerSleep(ctx, seconds)) {
      result = NDBT_FAILED;
      break;
    }
    const int node = restarter.getNode(NdbRestarter::NS_RANDOM);
    ndbout_c("Ledger loop %d: node restart of node %d with abort", l, node);
    if (restarter.restartOneDbNode(node, false, false, true) != 0 ||
        restarter.waitClusterStarted(300) != 0) {
      result = NDBT_FAILED;
      break;
    }
    if (!ledgerPause(ctx)) {
      result = NDBT_FAILED;
      break;
    }
    result = ledgerVerify(ctx, step, ~Uint64(0), "node restart");
    ledgerResume(ctx);
    if (result != NDBT_OK) break;
    if (!ledgerSleep(ctx, seconds)) {
      result = NDBT_FAILED;
      break;
    }
    result = ledgerSystemRestart(ctx, step);
  }
  ctx->stopTest();
  return result;
}

/**
 * RONDB-1150 (recovery plan S7.4): every data node stops at its next
 * persist of the REDO log with the copies torn (error insert 5155; with
 * the power-loss emulation the power loss of the stop tears them), then a
 * system restart and the check, and a graceful system restart after which
 * every committed transaction is there.
 */
int runLedgerTornTail(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  int result = NDBT_OK;
  for (int l = 0; l < ctx->getNumLoops() && result == NDBT_OK; l++) {
    if (!ledgerSleep(ctx, seconds)) {
      result = NDBT_FAILED;
      break;
    }
    ndbout_c("Ledger loop %d", l);
    result = ledgerWriteCrash(ctx, step, 5155, 0, true);
  }
  ctx->stopTest();
  return result;
}

/**
 * RONDB-1150, X5.10: a system restart with abort while the writers write,
 * then one with abort with the writers parked, which restarts from G' and
 * replays the old tail as the REDO up to it: with durable commits every
 * acknowledged transaction stays in both.
 */
int runLedgerDurableSR(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  int result = NDBT_OK;
  for (int l = 0; l < ctx->getNumLoops() && result == NDBT_OK; l++) {
    if (!ledgerSleep(ctx, seconds)) {
      result = NDBT_FAILED;
      break;
    }
    ndbout_c("Ledger loop %d", l);
    result = ledgerSystemRestart(ctx, step);
    if (result != NDBT_OK) break;
    NdbRestarter restarter;
    ndbout_c("Ledger: system restart with abort, the writers parked");
    if (!ledgerPause(ctx) || restarter.restartAll(false, false, true) != 0) {
      result = NDBT_FAILED;
      break;
    }
    result = ledgerCheckRestart(ctx, step, "system restart without writes",
                                true);
    ledgerResume(ctx);
  }
  ctx->stopTest();
  return result;
}

/**
 * RONDB-1150, X5.10: the error inserts of phase 2 in system restarts with
 * StopOnError=0, set in every data node in NOSTART after a system restart
 * with abort. Those that stop a node (5186-5189, 7262) must act within
 * LEDGER_RESTART_ATTEMPTS restarts; the next restart reaches the same
 * verdicts and keeps every acknowledged transaction. 5185 (every verdict
 * from the counts) and 5190 (one entry per batch) change phase 2 without
 * a stop: the restart with them is checked. Then every node stale (993,
 * X6.3): the restart must end with an error, not hang.
 */
const Uint32 LEDGER_DURABLE_CRASH_CODES[] = {5186, 5187, 5188, 5189, 7262};
const Uint32 LEDGER_DURABLE_MODE_CODES[] = {5185, 5190};

int runLedgerDurableCrashPoints(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  if (!ledgerStartsAgainOnError()) {
    ndbout_c("Ledger: this test needs StopOnError=0 in every data node");
    ctx->stopTest();
    return NDBT_SKIPPED;
  }
  int result = NDBT_OK;
  for (int l = 0; l < ctx->getNumLoops() && result == NDBT_OK; l++) {
    for (Uint32 code : LEDGER_DURABLE_CRASH_CODES) {
      bool acted = false;
      for (Uint32 a = 0; a < LEDGER_RESTART_ATTEMPTS && !acted; a++) {
        if (!ledgerSleep(ctx, seconds)) {
          result = NDBT_FAILED;
          break;
        }
        ndbout_c("Ledger loop %d: error insert %u, attempt %u", l, code,
                 a + 1);
        result = ledgerRestartCrashSR(ctx, step, code, &acted);
        if (result != NDBT_OK) break;
      }
      if (result != NDBT_OK) break;
      if (!acted) {
        ndbout_c("ERR: ledger: error insert %u did not act in %u restarts",
                 code, LEDGER_RESTART_ATTEMPTS);
        result = NDBT_FAILED;
        break;
      }
    }
    for (Uint32 code : LEDGER_DURABLE_MODE_CODES) {
      if (result != NDBT_OK) break;
      if (!ledgerSleep(ctx, seconds)) {
        result = NDBT_FAILED;
        break;
      }
      ndbout_c("Ledger loop %d: error insert %u", l, code);
      bool acted = false;
      result = ledgerRestartCrashSR(ctx, step, code, &acted);
      if (result == NDBT_OK && acted) {
        ndbout_c("ERR: ledger: error insert %u stopped a node", code);
        result = NDBT_FAILED;
      }
    }
    if (result != NDBT_OK) break;
    if (!ledgerSleep(ctx, seconds)) {
      result = NDBT_FAILED;
      break;
    }
    ndbout_c("Ledger loop %d: every node stale (993)", l);
    result = ledgerAllStaleStops(ctx, step);
  }
  ctx->stopTest();
  return result;
}

/**
 * Each crash error insert of the PMEM REDO log in turn. One of the write
 * path is set in every data node while the writers write, and each node
 * stops at it. One of a restart is set in NOSTART: with StopOnError=0 in
 * every data node after a system restart with abort, else in one node
 * after a node restart with abort, and the start stops at it. Then the
 * next start, the check, a graceful system restart and its check. An
 * insert of a restart that did not act (5169 needs a COMMIT after the
 * restart's GCI) is tried again after more writes.
 */
int runLedgerCrashPoints(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  const bool systemRestarts = ledgerStartsAgainOnError();
  ndbout_c("Ledger: the error inserts of a restart act in %s",
           systemRestarts ? "system restarts (StopOnError=0)"
                          : "node restarts (StopOnError=1)");
  int result = NDBT_OK;
  for (int l = 0; l < ctx->getNumLoops() && result == NDBT_OK; l++) {
    for (Uint32 code : LEDGER_WRITE_CODES) {
      if (!ledgerSleep(ctx, seconds)) {
        result = NDBT_FAILED;
        break;
      }
      ndbout_c("Ledger loop %d: error insert %u", l, code);
      result = ledgerWriteCrash(ctx, step, code, 0, true);
      if (result != NDBT_OK) break;
    }
    for (Uint32 code : LEDGER_RESTART_CODES) {
      if (result != NDBT_OK) break;
      bool acted = false;
      for (Uint32 a = 0; a < LEDGER_RESTART_ATTEMPTS && !acted; a++) {
        if (!ledgerSleep(ctx, seconds)) {
          result = NDBT_FAILED;
          break;
        }
        ndbout_c("Ledger loop %d: error insert %u, attempt %u", l, code,
                 a + 1);
        result = systemRestarts ? ledgerRestartCrashSR(ctx, step, code, &acted)
                                : ledgerRestartCrashNR(ctx, step, code, &acted);
        if (result != NDBT_OK) break;
      }
      if (result == NDBT_OK && !acted) {
        ndbout_c("ERR: ledger: error insert %u did not act in %u restarts",
                 code, LEDGER_RESTART_ATTEMPTS);
        result = NDBT_FAILED;
      }
    }
  }
  ctx->stopTest();
  return result;
}

/**
 * With the power-loss emulation, every data node loses the power while
 * the writers write: at once by DUMP 2370 in even loops, at a random drain
 * of each LDM thread (error insert 5171, the count up to 1000) in odd
 * ones. Then a system restart and the check.
 */
int runLedgerPowerLoss(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  int result = NDBT_OK;
  for (int l = 0; l < ctx->getNumLoops() && result == NDBT_OK; l++) {
    if (!ledgerSleep(ctx, seconds)) {
      result = NDBT_FAILED;
      break;
    }
    if (l % 2 == 1) {
      const Uint32 count = 1 + ndb_rand() % 1000;
      ndbout_c("Ledger loop %d: error insert 5171 at drain %u of each LDM "
               "thread",
               l, count);
      /* The nodes stop one by one: with durable commits a node failure in
         the tail, D3 (X6) */
      ctx->setProperty("LedgerStopTogether", Uint32(0));
      result = ledgerWriteCrash(ctx, step, 5171, count, false);
      ctx->setProperty("LedgerStopTogether", Uint32(1));
      continue;
    }
    ndbout_c("Ledger loop %d: DUMP 2370 in every data node", l);
    NdbRestarter restarter;
    const std::vector<int> nodes = ledgerDataNodes(restarter);
    const int powerLoss = DumpStateOrd::LqhPmemPowerLoss;
    if (!ledgerNoStartOnCrash(restarter, nodes) ||
        !ledgerStopTogether(ctx, restarter) ||
        restarter.dumpStateAllNodes(&powerLoss, 1) != 0) {
      result = NDBT_FAILED;
      break;
    }
    result = ledgerStopAll(ctx, step, restarter, nodes, "DUMP 2370", false);
  }
  ctx->stopTest();
  return result;
}

/**
 * RONDB-1150, X6.8: each loop a node failure in the durable tail (D3),
 * the same with the other nodes stopping as they record it (error insert
 * 990), and an unsafe shutdown of a node's persistent memory (X6.7, error
 * insert 992). The stale node joins by a node restart; every acknowledged
 * transaction stays, with identical replicas.
 */
int runLedgerDurableNodeFailure(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  int result = NDBT_OK;
  for (int l = 0; l < ctx->getNumLoops() && result == NDBT_OK; l++) {
    bool started = false;
    ndbout_c("Ledger loop %d: a node failure in the durable tail (D3)", l);
    result = ledgerSleep(ctx, seconds)
                 ? ledgerNodeFailureInTail(
                       ctx, step, 0,
                       "system restart after a node failure in the tail",
                       &started)
                 : NDBT_FAILED;
    if (result != NDBT_OK) break;
    ndbout_c("Ledger loop %d: the others stop at the record (990)", l);
    result = ledgerSleep(ctx, seconds)
                 ? ledgerNodeFailureInTail(
                       ctx, step, 990,
                       "system restart after the stop at the record of a "
                       "node failure",
                       &started)
                 : NDBT_FAILED;
    if (result != NDBT_OK) break;
    ndbout_c("Ledger loop %d: an unsafe shutdown (992)", l);
    result = ledgerSleep(ctx, seconds) ? ledgerUnsafeShutdown(ctx, step)
                                       : NDBT_FAILED;
  }
  if (result != NDBT_OK) {
    NdbRestarter restarter;
    ledgerDisarm(restarter);
  }
  ctx->stopTest();
  return result;
}

/**
 * RONDB-1150, X6.8: the negative test of D3. With error insert 991 the
 * node failure is not recorded, so the failed node takes part in the
 * system restart as if it had seen the tail, and the check must find the
 * divergence: acknowledged transactions lost, or replicas that differ.
 * It shows that the check of D3 sees what the node-failure file
 * prevents. The table is left diverged and is dropped.
 */
int runLedgerDurableNoNodeFailRecord(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  int result = NDBT_FAILED;
  bool started = false;
  if (ledgerSleep(ctx, seconds)) {
    const int res = ledgerNodeFailureInTail(
        ctx, step, 991, "system restart without the record of a node failure",
        &started);
    if (!started) {
      ndbout_c("ERR: ledger: the cluster did not start after error insert "
               "991");
    } else if (res == NDBT_OK) {
      ndbout_c("ERR: ledger: without the node-failure records the check did "
               "not find the divergence of D3");
    } else {
      ndbout_c("Ledger: without the node-failure records the check found the "
               "divergence of D3, as it must");
      result = NDBT_OK;
    }
  }
  ctx->stopTest();
  return result;
}

/**
 * RONDB-1150, X6.8, at least two node groups: each loop a partial system
 * restart without a node (X6.5, D5), one that waits for the peer of a
 * stale node (X6.4, D4), and one that waits for a node group with all
 * its nodes (X6.9)
 */
int runLedgerDurablePartialSR(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 seconds = ctx->getProperty("LedgerSeconds", Uint32(5));
  NdbRestarter restarter;
  if (restarter.getNumNodeGroups() < 2) {
    ndbout_c("Ledger: this test needs two node groups");
    ctx->stopTest();
    return NDBT_SKIPPED;
  }
  int result = NDBT_OK;
  for (int l = 0; l < ctx->getNumLoops() && result == NDBT_OK; l++) {
    ndbout_c("Ledger loop %d: a partial system restart (D5)", l);
    result = ledgerSleep(ctx, seconds) ? ledgerPartialSR(ctx, step)
                                       : NDBT_FAILED;
    if (result != NDBT_OK) break;
    ndbout_c("Ledger loop %d: a stale node and its absent peer (D4)", l);
    result = ledgerSleep(ctx, seconds) ? ledgerStaleGroupWaits(ctx, step)
                                       : NDBT_FAILED;
    if (result != NDBT_OK) break;
    ndbout_c("Ledger loop %d: two nodes that failed together start alone "
             "(X6.9)",
             l);
    result = ledgerSleep(ctx, seconds) ? ledgerPartitionedSRWaits(ctx, step)
                                       : NDBT_FAILED;
  }
  if (result != NDBT_OK) ledgerDisarm(restarter);
  ctx->stopTest();
  return result;
}

/**
 * RONDB-1150, X5.9: schema changes in the durable tail. GCP saves stop
 * (error insert 7243); then a table S is created and filled, gets a
 * column online and every row updated, gets more partitions online and
 * every row updated again, and a table D, filled before the stop, is
 * dropped; then every data node stops together. After the system restart
 * S has the column, the partitions and every row at its last update,
 * with identical replicas, and D is gone: the replay's schema-version
 * check keeps the records of the changed and the dropped tables apart,
 * and no transaction of S is half applied.
 */
int runLedgerDurableSchema(NDBT_Context *ctx, NDBT_Step *step) {
  const Uint32 rows = ctx->getProperty("LedgerSchemaRows", Uint32(512));
  Ndb *pNdb = GETNDB(step);
  NdbDictionary::Dictionary *dict = pNdb->getDictionary();
  NdbRestarter restarter;
  const std::vector<int> nodes = ledgerDataNodes(restarter);
  int result = NDBT_OK;
  for (int l = 0; l < ctx->getNumLoops() && result == NDBT_OK; l++) {
    char sName[64];
    char dName[64];
    BaseString::snprintf(sName, sizeof(sName), "%s_S%d",
                         ctx->getTab()->getName(), l);
    BaseString::snprintf(dName, sizeof(dName), "%s_D%d",
                         ctx->getTab()->getName(), l);
    result = NDBT_FAILED;
    const NdbDictionary::Table *d = ledgerCopyTable(ctx, pNdb, dName);
    if (d == nullptr || !ledgerSchemaWrite(pNdb, d, rows, true, 0)) break;
    /* GCP saves take D and its rows before R */
    NdbSleep_MilliSleep(3000);
    if (restarter.insertErrorInAllNodes(7243) != 0) break;
    NdbSleep_MilliSleep(1000);
    ndbout_c("Ledger loop %d: GCP saves stopped (error insert 7243); in the "
             "tail %s is created, gets a column and partitions, %s is "
             "dropped",
             l, sName, dName);
    const NdbDictionary::Table *s = ledgerCopyTable(ctx, pNdb, sName);
    if (s == nullptr || !ledgerSchemaWrite(pNdb, s, rows, true, 0)) break;
    s = ledgerAddColumn(pNdb, s);
    if (s == nullptr || !ledgerSchemaWrite(pNdb, s, rows, false, 1)) break;
    s = ledgerAddPartitions(pNdb, restarter, s);
    if (s == nullptr || !ledgerSchemaWrite(pNdb, s, rows, false, 2)) break;
    const Uint32 frags = s->getFragmentCount();
    if (dict->dropTable(dName) != 0) {
      ndbout << "ERR: ledger: drop table " << dName << ": "
             << dict->getNdbError() << endl;
      break;
    }
    if (!ledgerStopRestTogether(restarter, nodes, 0) ||
        restarter.startAll() != 0) {
      break;
    }
    result = ledgerCheckRestart(ctx, step,
                                "system restart after schema changes in the "
                                "tail",
                                true);
    dict->invalidateTable(sName);
    dict->invalidateTable(dName);
    s = dict->getTable(sName);
    if (s == nullptr) {
      ndbout_c("ERR: ledger: table %s is gone after the system restart",
               sName);
      result = NDBT_FAILED;
    } else if (s->getColumn(LEDGER_SCHEMA_COLUMN) == nullptr ||
               s->getFragmentCount() != frags) {
      ndbout_c("ERR: ledger: table %s has %s column %s and %u fragments, "
               "%u expected",
               sName,
               s->getColumn(LEDGER_SCHEMA_COLUMN) == nullptr ? "no" : "the",
               LEDGER_SCHEMA_COLUMN, s->getFragmentCount(), frags);
      result = NDBT_FAILED;
    } else if (!ledgerSchemaCheck(pNdb, s, rows, 2) ||
               !ledgerReplicasAgree(ctx, step, "schema changes in the tail",
                                    s)) {
      result = NDBT_FAILED;
    } else {
      ndbout_c("Ledger: %s has its column, %u fragments and every row of its "
               "last update",
               sName, frags);
    }
    if (dict->getTable(dName) != nullptr) {
      ndbout_c("ERR: ledger: table %s, dropped in the tail, exists after the "
               "system restart",
               dName);
      result = NDBT_FAILED;
    }
    (void)dict->dropTable(sName);
  }
  if (result != NDBT_OK) ledgerDisarm(restarter);
  ctx->stopTest();
  return result;
}

NDBT_TESTSUITE(testRestartGci);
TESTCASE("InsertRestartGci",
         "Verify that only expected records are still in NDB\n"
         "after a restart") {
  INITIALIZER(runCreateTable);
  INITIALIZER(runClearGlobals);
  INITIALIZER(runInsertRememberGci);
  INITIALIZER(runRestartGciControl);
  INITIALIZER(runDetermineRestartGci);
  TC_PROPERTY("ExactGCI",
              Uint32(0)); /* Recovery from Redo == inexact low word */
  VERIFIER(runVerifyInserts);
  /* Restart again - LCP after first restart will mean that this
   * time we recover from LCP, not Redo
   */
  VERIFIER(runRestartAll);
  VERIFIER(runDetermineRestartGci);
  VERIFIER(runVerifyInserts);  // Check GCIs again
  /* Restart again - one node, initial.  This will check
   * COPYFRAG behaviour
   */
  VERIFIER(runRestartOneInitial);
  VERIFIER(runVerifyInserts);  // Check GCIs again
  VERIFIER(runClearTable);
  /* Re-fill table with records, will just be in Redo
   * Then restart, testing COPYFRAG behaviour with
   * non #ffff... low word
   */
  VERIFIER(runClearGlobals);
  VERIFIER(runInsertRememberGci);
  VERIFIER(runRestartOneInitial);
  /* Require exact GCI match from here - no Redo messing it up */
  VERIFIER(runRequireExact);
  VERIFIER(runVerifyInserts);
  /* Now-restart all nodes - all inserts should be
   * in LCP, and should be restored correctly
   */
  VERIFIER(runRestartAll);
  VERIFIER(runDetermineRestartGci);
  VERIFIER(runVerifyInserts);
  FINALIZER(runClearTable);
  FINALIZER(runDropTable);
}
TESTCASE("InitialNodeRestartUpdate",
         "Check that initial node restart (copyfrag) does "
         "not affect GCI recording") {
  INITIALIZER(runCreateTable);
  INITIALIZER(runLoadTable);
  STEP(runNodeInitialRestarts);
  STEP(runUpdateVerifyGCI);
  FINALIZER(runClearTable);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerSR",
         "RONDB-1150 (S7.4): writers keep the GCI of each transaction; "
         "after each system restart with abort every row holds the last of "
         "its transactions with a GCI up to the restart's") {
  TC_PROPERTY("LedgerSeconds", Uint32(5));
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerSR);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerSRReadBackup",
         "RONDB-1150 (X3): as GciLedgerSR on the table with READ_BACKUP, "
         "whose transactions are acknowledged after the complete phase") {
  TC_PROPERTY("LedgerSeconds", Uint32(5));
  TC_PROPERTY("LedgerReadBackup", Uint32(1));
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerSR);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerSRFullyReplicated",
         "RONDB-1150 (X3): as GciLedgerSR on the table fully replicated, "
         "with a replica of every fragment in each node group") {
  TC_PROPERTY("LedgerSeconds", Uint32(5));
  TC_PROPERTY("LedgerFullyReplicated", Uint32(1));
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerSR);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerNR",
         "RONDB-1150 (S7.4): as GciLedgerSR with a node restart with abort "
         "before each system restart, after which every committed "
         "transaction is there") {
  TC_PROPERTY("LedgerSeconds", Uint32(5));
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerNR);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerTornTail",
         "RONDB-1150 (S7.4), PMEM mode: as GciLedgerSR, each data node "
         "stopping at its next persist of the REDO log with the copies torn "
         "(error insert 5155); after a graceful system restart every "
         "committed transaction is there") {
  TC_PROPERTY("LedgerSeconds", Uint32(5));
  INITIALIZER(runLedgerNeedsPmem);
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerTornTail);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerCrashPoints",
         "RONDB-1150 (S7.4), PMEM mode: as GciLedgerTornTail with each crash "
         "error insert of the REDO log, 5155-5172; those of a restart in "
         "system restarts with StopOnError=0, else in node restarts") {
  TC_PROPERTY("LedgerSeconds", Uint32(2));
  INITIALIZER(runLedgerNeedsPmem);
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerCrashPoints);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerPowerLoss",
         "RONDB-1150 (S7.4), PMEM mode with __RedoLogPmemPowerLossEmulation: "
         "as GciLedgerSR, each data node losing the power by DUMP 2370 or "
         "at a random drain (error insert 5171)") {
  TC_PROPERTY("LedgerSeconds", Uint32(5));
  TC_PROPERTY("LedgerPowerLoss", Uint32(1));
  INITIALIZER(runLedgerNeedsPmem);
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerPowerLoss);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerDurableSR",
         "RONDB-1150 (X5.10), PMEM mode with __DurableCommits: as "
         "GciLedgerSR, each system restart with abort followed by one with "
         "the writers parked; every acknowledged transaction stays") {
  TC_PROPERTY("LedgerSeconds", Uint32(5));
  TC_PROPERTY("LedgerDurable", Uint32(1));
  INITIALIZER(runLedgerNeedsPmem);
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerDurableSR);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerDurablePowerLoss",
         "RONDB-1150 (X5.10), PMEM mode with __DurableCommits and "
         "__RedoLogPmemPowerLossEmulation: as GciLedgerPowerLoss; every "
         "acknowledged transaction stays") {
  TC_PROPERTY("LedgerSeconds", Uint32(5));
  TC_PROPERTY("LedgerPowerLoss", Uint32(1));
  TC_PROPERTY("LedgerDurable", Uint32(1));
  INITIALIZER(runLedgerNeedsPmem);
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerPowerLoss);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerDurableCrashPoints",
         "RONDB-1150 (X5.10), PMEM mode with __DurableCommits and "
         "StopOnError=0: the error inserts of phase 2 of a system restart, "
         "5185-5190 and 7262, and every node stale (993), which must end "
         "the restart with an error; every acknowledged transaction "
         "stays") {
  TC_PROPERTY("LedgerSeconds", Uint32(2));
  TC_PROPERTY("LedgerDurable", Uint32(1));
  INITIALIZER(runLedgerNeedsPmem);
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerDurableCrashPoints);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerDurableNodeFailure",
         "RONDB-1150 (X6.8), PMEM mode with __DurableCommits: a node failure "
         "in the durable tail (D3), the stop of the others as they record it "
         "(error insert 990), an unsafe shutdown (992); the stale node "
         "joins by a node restart and every acknowledged transaction "
         "stays") {
  TC_PROPERTY("LedgerSeconds", Uint32(3));
  TC_PROPERTY("LedgerDurable", Uint32(1));
  INITIALIZER(runLedgerNeedsPmem);
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerDurableNodeFailure);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerDurableNoNodeFailRecord",
         "RONDB-1150 (X6.8), PMEM mode with __DurableCommits: as D3 of "
         "GciLedgerDurableNodeFailure with the failure not recorded (error "
         "insert 991); the check must find the divergence") {
  TC_PROPERTY("LedgerSeconds", Uint32(3));
  TC_PROPERTY("LedgerDurable", Uint32(1));
  INITIALIZER(runLedgerNeedsPmem);
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerDurableNoNodeFailRecord);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerDurablePartialSR",
         "RONDB-1150 (X6.8), PMEM mode with __DurableCommits, two node "
         "groups: a system restart without a node (D5), one that waits "
         "for the peer of a stale node (D4), and one that waits for a node "
         "group with all its nodes (X6.9); every acknowledged transaction "
         "stays") {
  TC_PROPERTY("LedgerSeconds", Uint32(3));
  TC_PROPERTY("LedgerDurable", Uint32(1));
  INITIALIZER(runLedgerNeedsPmem);
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEPS(runLedgerWriter, LEDGER_WRITERS);
  STEP(runLedgerDurablePartialSR);
  FINALIZER(runDropTable);
}
TESTCASE("GciLedgerDurableSchema",
         "RONDB-1150 (X5.9), PMEM mode with __DurableCommits: create table, "
         "add column, add partitions and drop table in the durable tail, "
         "then every node stops; the changed tables and their rows are as "
         "acknowledged") {
  TC_PROPERTY("LedgerDurable", Uint32(1));
  INITIALIZER(runLedgerNeedsPmem);
  INITIALIZER(runCreateTable);
  INITIALIZER(runLedgerInit);
  STEP(runLedgerDurableSchema);
  FINALIZER(runDropTable);
}
NDBT_TESTSUITE_END(testRestartGci)

int main(int argc, const char **argv) {
  ndb_init();
  NDBT_TESTSUITE_INSTANCE(testRestartGci);
  testRestartGci.setCreateTable(false);
  return testRestartGci.execute(argc, argv);
}

template class Vector<SavedRecord>;
