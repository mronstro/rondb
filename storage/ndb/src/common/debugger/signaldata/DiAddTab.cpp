/*
   Copyright (c) 2003, 2025, Oracle and/or its affiliates.
   Copyright (c) 2026, 2026, Hopsworks and/or its affiliates.

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

#include <signaldata/DiAddTab.hpp>

bool printDIADDTABREQ(FILE *output, const Uint32 *theData,
                      Uint32 len, Uint16 /*receiverBlockNo*/) {
  if (len < DiAddTabReq::SignalLength) {
    assert(false);
    return false;
  }

  const DiAddTabReq *const sig =
      (const DiAddTabReq *)theData;
  fprintf(output, " connectPtr: %u,", sig->connectPtr);
  fprintf(output, " tableId: %u,", sig->tableId);
  fprintf(output, " fragType: %x\n", sig->fragType);
  fprintf(output, " kValue: %x,", sig->kValue);
  fprintf(output, " noOfReplicas: %u,", sig->noOfReplicas);
  fprintf(output, " loggedTable: %u\n", sig->loggedTable);
  fprintf(output, " tableType: %u,", sig->tableType);
  fprintf(output, " schemaVersion: %x,", sig->schemaVersion);
  fprintf(output, " primaryTableId: %u\n", sig->primaryTableId);
  fprintf(output, " temporaryTable: %u,", sig->temporaryTable);
  fprintf(output, " schemaTransId: %u,", sig->schemaTransId);
  fprintf(output, " hashMapPtrI: %u\n", sig->hashMapPtrI);
  fprintf(output, " fullyReplicated: %u,", sig->fullyReplicated);
  fprintf(output, " partitionCount: %u\n", sig->partitionCount);
  return true;
}

bool printDIADDTABREF(FILE *output, const Uint32 *theData,
                                   Uint32 len, Uint16 /*receiverBlockNo*/) {
  if (len < DiAddTabRef::SignalLength) {
    assert(false);
    return false;
  }

  const DiAddTabRef *const sig =
      (const DiAddTabRef *)theData;
  fprintf(output, " connectPtr: %x\n", sig->connectPtr);
  fprintf(output, " errorCode: %x\n", sig->errorCode);
  return true;
}

bool printDIADDTABCONF(FILE *output, const Uint32 *theData,
                                    Uint32 len, Uint16 /*receiverBlockNo*/) {
  if (len < DiAddTabConf::SignalLength) {
    assert(false);
    return false;
  }

  const DiAddTabConf *const sig =
      (const DiAddTabConf *)theData;
  fprintf(output, " connectPtr: %x\n", sig->connectPtr);
  return true;
}
