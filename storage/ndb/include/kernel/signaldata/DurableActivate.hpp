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

#ifndef DURABLE_ACTIVATE_HPP
#define DURABLE_ACTIVATE_HPP

#include "SignalData.hpp"

#define JAM_FILE_ID 576

/**
 * RONDB-1150, X7: online activation of durable commits, ALL SET
 * DurableCommits 1 (impl_next_steps.md §7). The request type says which
 * step a signal belongs to:
 *
 *   Set      CMVMI -> own DIH, with the management server's reference in
 *            senderRef; DIH answers the management server with
 *            SET_CONFIG_PARAM_CONF/REF once durable commits are armed
 *   Request  DIH -> DIH master; CONF (with g) once armed, else REF
 *   Prepare  DIH master -> the DIH of every alive node: map the
 *            node-failure file, check the REDO log mode; CONF or REF
 *   MapFile  DIH -> own QMGR, EXECUTE_DIRECT: map the node-failure file;
 *            QMGR returns an errno in theData[0], 0 when it is mapped
 *
 * The master then takes g at the next gci_hi switch and sends it in
 * every GCP_PREPARE and GCP_COMMIT, and arms durable commits with the
 * sysfile of the save of g - 1.
 */
struct DurableActivateReq {
  static constexpr Uint32 SignalLength = 4;

  enum RequestType { Set = 0, Request = 1, Prepare = 2, MapFile = 3 };

  Uint32 senderRef;
  Uint32 senderData;
  Uint32 requestType;
  Uint32 value;  // Set: the value of DurableCommits, else 0
};

struct DurableActivateConf {
  static constexpr Uint32 SignalLength = 4;

  Uint32 senderRef;
  Uint32 senderData;
  Uint32 requestType;
  Uint32 durableGci;  // Request: g, from which commits are durable
};

struct DurableActivateRef {
  static constexpr Uint32 SignalLength = 4;

  enum ErrorCode {
    NotMaster = 1,        // the receiver is no longer the master
    NotStarted = 2,       // the cluster has not completed its start
    NodeRestart = 3,      // a node restart runs (Q-B7)
    NodeVersion = 4,      // a node of a version without durable commits
    NotPmem = 5,          // a node with RedoLogMode other than pmem
    NodeFailFile = 6,     // a node cannot map its node-failure file
    NodeFailure = 7,      // a node failed before g was chosen
    Busy = 8,             // the node already waits for an activation
    MasterFailure = 9     // the master failed; run SET again
  };

  Uint32 senderRef;
  Uint32 senderData;
  Uint32 requestType;
  Uint32 errorCode;
};

#undef JAM_FILE_ID

#endif
