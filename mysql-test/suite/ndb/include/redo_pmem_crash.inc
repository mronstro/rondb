# RONDB-1150 (recovery plan S7.1): data nodes stop at a crash error
# insert of the REDO log in PMEM mode, then start again.
#
#   REDO_PMEM_CRASH_NODES  the data nodes, comma separated ("2", "1,2")
#   $redo_pmem_crash_mgm   the same for ndb_mgm ("2", "all")
#   $redo_pmem_crash_wait  the ndb_waiter option for them
#                          ("--wait-nodes=2", "")
#   REDO_PMEM_CRASH_CODE   the error insert
#   $redo_pmem_crash_start 1: the nodes wait in NOSTART and the insert
#                          acts in their start; 0: they are started
#
# The nodes stop at the insert, which each node log names, and wait in
# NOSTART (DUMP 2602 1); then they start. For 5167 and 5172, which stop
# phase 1, the next start must find, in every log part, the end of the
# log that the stopped start found; the reason why the record there is
# not valid may change, as 5167 may have zeroed it.

--exec $NDB_MGM -e "$redo_pmem_crash_mgm dump 2602 1" >> $NDB_TOOLS_OUTPUT
--perl
  use strict;
  my $cluster = "$ENV{MYSQLTEST_VARDIR}/mysql_cluster.1";
  my $file = "$ENV{MYSQLTEST_VARDIR}/tmp/redo_pmem_crash.offsets";
  open(my $out, '>', $file) or die "Cannot open $file: $!\n";
  foreach my $node (split(/,/, $ENV{REDO_PMEM_CRASH_NODES})) {
    print $out "crash $node ", ((-s "$cluster/ndbd.$node/ndbd.log") || 0),
               "\n";
  }
  close($out);
EOF
--exec $NDB_MGM -e "$redo_pmem_crash_mgm error $REDO_PMEM_CRASH_CODE" >> $NDB_TOOLS_OUTPUT
if ($redo_pmem_crash_start) {
  --exec $NDB_MGM -e "$redo_pmem_crash_mgm start" >> $NDB_TOOLS_OUTPUT
}

# Each node logs the insert where it stops
--perl
  use strict;
  my $cluster = "$ENV{MYSQLTEST_VARDIR}/mysql_cluster.1";
  my $file = "$ENV{MYSQLTEST_VARDIR}/tmp/redo_pmem_crash.offsets";
  my $code = $ENV{REDO_PMEM_CRASH_CODE};
  open(my $in, '<', $file) or die "Cannot open $file: $!\n";
  my %offset = map { /^crash (\d+) (\d+)$/ ? ($1 => $2) : () } <$in>;
  close($in);
  foreach my $node (sort keys %offset) {
    my $log = "$cluster/ndbd.$node/ndbd.log";
    my $found = 0;
    for (my $i = 0; $i < 300 && !$found; $i++) {
      if (open(my $fh, '<', $log)) {
        seek($fh, $offset{$node}, 0);
        $found = grep { /PMEM REDO error insert $code: / } <$fh>;
        close($fh);
      }
      sleep(1) unless $found;
    }
    die "Node $node did not stop at error insert $code\n" unless $found;
    print "Node $node: stopped at error insert $code\n";
  }
EOF
--exec $NDB_WAITER $redo_pmem_crash_wait --not-started >> $NDB_TOOLS_OUTPUT
--perl
  use strict;
  my $cluster = "$ENV{MYSQLTEST_VARDIR}/mysql_cluster.1";
  my $file = "$ENV{MYSQLTEST_VARDIR}/tmp/redo_pmem_crash.offsets";
  open(my $out, '>>', $file) or die "Cannot open $file: $!\n";
  foreach my $node (split(/,/, $ENV{REDO_PMEM_CRASH_NODES})) {
    print $out "start $node ", ((-s "$cluster/ndbd.$node/ndbd.log") || 0),
               "\n";
  }
  close($out);
EOF
--exec $NDB_MGM -e "$redo_pmem_crash_mgm start" >> $NDB_TOOLS_OUTPUT
--exec $NDB_WAITER >> $NDB_TOOLS_OUTPUT

# The line of phase 1 of each log part, in the stopped start and the next
--perl
  use strict;
  my $cluster = "$ENV{MYSQLTEST_VARDIR}/mysql_cluster.1";
  my $file = "$ENV{MYSQLTEST_VARDIR}/tmp/redo_pmem_crash.offsets";
  my $code = $ENV{REDO_PMEM_CRASH_CODE};
  open(my $in, '<', $file) or die "Cannot open $file: $!\n";
  my (%crash, %start);
  while (my $l = <$in>) {
    $crash{$1} = $2 if $l =~ /^crash (\d+) (\d+)$/;
    $start{$1} = $2 if $l =~ /^start (\d+) (\d+)$/;
  }
  close($in);
  unlink($file);
  exit(0) unless $code == 5167 || $code == 5172;
  foreach my $node (sort keys %crash) {
    my $log = "$cluster/ndbd.$node/ndbd.log";
    open(my $fh, '<', $log) or die "Cannot open $log: $!\n";
    seek($fh, $crash{$node}, 0);
    my (%before, %after);
    my $at = $crash{$node};
    while (my $l = <$fh>) {
      if ($l =~ /(PMEM REDO log part (\d+): last file .*?)\s*$/) {
        my ($part, $end) = ($2, $1);
        $end =~ s/( in lap \d+) \(.*\) (after \d+ records)$/$1 $2/;
        if ($at < $start{$node}) {
          $before{$part} = $end;
        } elsif (!exists $after{$part}) {
          $after{$part} = $end;
        }
      }
      $at = tell($fh);
    }
    close($fh);
    my @parts = sort keys %before;
    my @differ = grep { ($after{$_} // '') ne $before{$_} } @parts;
    if (@parts > 0 && @differ == 0) {
      print "Node $node: the next start found the same end of the log\n";
    } else {
      print "Node $node: the ends of the log differ\n";
      foreach my $part (@differ) {
        print "  stopped: $before{$part}\n",
              "  next:    ", ($after{$part} // "none"), "\n";
      }
    }
  }
EOF
