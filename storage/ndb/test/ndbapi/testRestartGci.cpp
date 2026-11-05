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
#include <map>
#include <utility>
#include <vector>

#include "HugoTransactions.hpp"
#include "NDBT_ReturnCodes.h"
#include "NDBT_Test.hpp"
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
                               false, maybeExtraBits) == NDBT_OK) {
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
 * highest GCI that the restart kept. The next round starts from the rows
 * as they are.
 */
int ledgerVerify(NDBT_Context *ctx, NDBT_Step *step, Uint64 maxGci,
                 const char *what) {
  HugoOperations hugoOps(*ctx->getTab());
  HugoCalculator hugoCalc(*ctx->getTab());
  std::map<Uint64, std::pair<Uint32, Uint32>> unknownTxns;  // with, without
  Uint32 kept = 0;
  Uint32 lost = 0;
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
    for (const LedgerTxn &t : row.txns) {
      if (t.state == LEDGER_UNKNOWN) {
        unknown = &t;
        break;
      }
      if (t.gci > maxGci) {
        /* A later transaction on the row has a GCI at least this one's */
        lost++;
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
    if (!ok) {
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
  ndbout_c(
      "Ledger after the %s: %u rows, %u row writes kept, %u row writes "
      "acknowledged and lost, %u rows of %u transactions with an unknown "
      "result, %u failures",
      what, Uint32(g_ledger.size()), kept, lost, unknownRows,
      Uint32(unknownTxns.size()), failures);
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

/* A system restart with abort while the writers write, then the check */
int ledgerSystemRestart(NDBT_Context *ctx, NDBT_Step *step) {
  Ndb *pNdb = GETNDB(step);
  NdbRestarter restarter;
  ndbout_c("Ledger: system restart with abort");
  if (restarter.restartAll(false, false, true) != 0) {
    return NDBT_FAILED;
  }
  /* No transaction starts before the check; those under way fail */
  if (!ledgerPause(ctx)) return NDBT_FAILED;
  if (restarter.waitClusterStarted(300) != 0 || pNdb->waitUntilReady() != 0) {
    return NDBT_FAILED;
  }
  Uint32 restartGci = 0;
  if (pNdb->getDictionary()->getRestartGCI(&restartGci) != 0) {
    ndbout << "ERR: ledger: no restart GCI: "
           << pNdb->getDictionary()->getNdbError() << endl;
    return NDBT_FAILED;
  }
  ndbout_c("Ledger: restart GCI %u", restartGci);
  const int res = ledgerVerify(
      ctx, step, (Uint64(restartGci) << 32) | 0xffffffff, "system restart");
  ledgerResume(ctx);
  return res;
}

}  // namespace

int runLedgerInit(NDBT_Context *ctx, NDBT_Step *step) {
  g_ledger.assign(ctx->getNumRecords(), LedgerRow());
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
    const bool committed =
        res == 0 && hugoOps.getTransaction()->getGCI(&gci) == 0;
    if (committed || err.status == NdbError::UnknownResult ||
        err.status == NdbError::Success) {
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
      if (!committed) {
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
NDBT_TESTSUITE_END(testRestartGci)

int main(int argc, const char **argv) {
  ndb_init();
  NDBT_TESTSUITE_INSTANCE(testRestartGci);
  testRestartGci.setCreateTable(false);
  return testRestartGci.execute(argc, argv);
}

template class Vector<SavedRecord>;
