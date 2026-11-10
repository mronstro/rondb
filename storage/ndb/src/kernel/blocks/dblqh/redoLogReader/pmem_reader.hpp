/*
   Copyright (c) 2026, Hopsworks and/or its affiliates.

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

#ifndef PMEM_READER_HPP
#define PMEM_READER_HPP

#include <ndb_types.h>

/**
 * RONDB-1150: ndb_redo_log_reader for the REDO log format of
 * RedoLogMode=pmem (PmemRedoFormat.hpp, recovery plan S6.8). The records
 * are checked as a restart checks them (PmemRedoScan.hpp); the files are
 * never encrypted.
 */
struct PmemReaderOptions {
  bool print;             // the records, not only each mbyte and its end
  bool check;             // exit with 1 when the file holds a corrupt log
  bool dump;              // the FILLERs too
  bool onlyPageHeaders;   // every page header, no records
  bool onlyMbyteHeaders;  // the header of the first page of each mbyte
  bool onlyFileDesc;      // the FD of page 0, then stop
  bool onlyLap;           // the lap and GCIs of every page header
  Uint32 startAtMbyte;    // only this mbyte, when not 0
  bool transidFilter;     // only the records of the transaction transid
  Uint32 transid[2];
};

/* Page 0 of the file has the header of the PMEM format */
bool pmem_redo_file(const char *fileName);

/* Reads one file of a log part; the exit code of the program */
int pmem_reader_main(const char *fileName, const PmemReaderOptions &opts);

/**
 * --find-end: from the files S0.FragLog .. S<n-1>.FragLog of one log part
 * in dir, the end of the log as phase 1 of a restart finds it, printed in
 * the line that the data node logs. The exit code of the program.
 */
int pmem_find_end_main(const char *dir);

#endif
