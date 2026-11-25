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

#ifndef SR_TAIL_HPP
#define SR_TAIL_HPP

#include "SignalData.hpp"

#define JAM_FILE_ID 575

/**
 * RONDB-1150, X5.4: step B of phase 2 of a system restart, the exchange
 * of the in-doubt sets of the durable tail between the DBLQH workers of
 * the SR nodes, aggregated per node by the DBLQH proxy (plan §5.2,
 * impl_next_steps.md X5.4). Each signal goes worker -> own proxy, proxy
 * -> the proxies of the SR nodes (itself included), proxy -> its
 * workers. Signals between two block instances keep their order, so a
 * node's hits reach every worker before its DONE.
 *
 *   SR_TAIL_INDOUBT_REP  the in-doubt transactions of a worker, then of a
 *                        node with the counts of its workers summed;
 *                        section 0: INDOUBT_WORDS words each
 *   SR_TAIL_HIT_REP      transactions of U with a COMPLETE in the tail of
 *                        a part; section 0: HIT_WORDS words each
 *   SR_TAIL_DONE_REP     the sender has sent all its hits; from the proxy
 *                        to its workers once every SR node is done
 */
class SrTailRep {
  friend bool printSR_TAIL_REP(FILE *, const Uint32 *, Uint32, Uint16);

 public:
  static constexpr Uint32 SignalLength = 4;
  static constexpr Uint32 F_LAST = 1;  // the sender's last in-doubt batch
  /* transid1, transid2, COMMITs held, gci_hi, opCount */
  static constexpr Uint32 INDOUBT_WORDS = 5;
  static constexpr Uint32 HIT_WORDS = 2;  // transid1, transid2
  /* Entries per signal, well below the size of a long signal */
  static constexpr Uint32 MAX_ENTRIES = 1000;

  Uint32 nodeId;  // the node whose set or hits these are
  Uint32 flags;
  Uint32 count;   // entries in section 0
  Uint32 total;   // F_LAST: entries the sender sent in all its batches
};

class SrTailDoneRep {
  friend bool printSR_TAIL_DONE_REP(FILE *, const Uint32 *, Uint32, Uint16);

 public:
  static constexpr Uint32 SignalLength = 4;

  Uint32 nodeId;   // the node that is done, 0 from a proxy to its workers
  /* The highest GCI that step A executed, over the sender's parts */
  Uint32 maxGciExecuted;
  Uint32 hits;     // hit entries the sender sent, over all its batches
  Uint32 entries;  // in-doubt entries the sender sent
};

#undef JAM_FILE_ID

#endif
