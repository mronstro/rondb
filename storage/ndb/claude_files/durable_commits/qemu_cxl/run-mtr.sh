#!/bin/bash
# Guest, as the user, after setup-region.sh:
#   run-mtr.sh <build directory> [mtr arguments; default: the two Q1 tests]
# Runs MTR in PMEM mode with the production checks on the CXL mount
# (suite/ndb/pmem_redo_cxl.cnf), with timeouts for TCG, then prints the
# REDO path verdict lines of the data nodes. The log goes to
# <build>/mysql-test/mtr-cxl.log, on the share. CXL_CNF names another
# --defaults-extra-file.
BLD=${1:?usage: run-mtr.sh <build directory> [mtr arguments]}; shift
[ $# -gt 0 ] || set -- ndb.ndb_redo_pmem_ledger ndb.ndb_redo_pmem_restart
cd "$BLD/mysql-test" || exit 1
findmnt var >/dev/null || { echo "run setup-region.sh first" >&2; exit 1; }
findmnt ../runtime_output_directory >/dev/null || { echo "run setup-region.sh first" >&2; exit 1; }
export MTR_NDB_PMEM_DIR=/mnt/pmem0/mtr
./mtr --defaults-extra-file="${CXL_CNF:-suite/ndb/pmem_redo_cxl.cnf}" --testcase-timeout=240 \
  --suite-timeout=720 --force "$@" 2>&1 | tee mtr-cxl.log
grep -n -E '^(RedoLogMode|__RedoLogPmemTestMode)' var/my.cnf
grep -rh 'FileSystemPathRedoLog .*persistence domain' var/mysql_cluster.1 2>/dev/null |
  sed -E 's/^[0-9T:.-]+Z //' | sort | uniq -c
