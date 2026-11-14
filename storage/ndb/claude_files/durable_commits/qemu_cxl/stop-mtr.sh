#!/bin/bash
# Guest, as the user: stop an MTR run started with nohup or setsid, and
# every process it left (the process group first, then by name).
p=$(pgrep -f mysql-test-run.pl | head -1)
[ -n "$p" ] && { pg=$(ps -o pgid= -p $p | tr -d ' '); kill -TERM -- -$pg; sleep 20; }
for n in ndbmtd ndb_mgmd mysqld safe_process rdrs2; do pkill -9 -x $n; done
for p in $(pgrep -f mysql-test-run.pl); do kill -9 $p; done
pgrep -a 'ndbmtd|ndb_mgmd|mysqld|perl' || echo clean
