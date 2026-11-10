# RONDB-1150 (recovery plan S6.8): ndb_redo_log_reader --find-end against
# phase 1 of a restart, for every log part of the data nodes in
# REDO_PMEM_NODES (comma separated), with RedoLogMode=pmem.
#
# With $redo_pmem_find_end_save = 1, while the nodes are stopped: the end
# of each log part's log that the reader finds from its files, and where
# each node's log ends. With $redo_pmem_find_end_save = 0, after the nodes
# have started: the line that phase 1 logged for each log part must be
# the reader's.

if ($redo_pmem_find_end_save) {
--perl
  use strict;
  my $cluster = "$ENV{MYSQLTEST_VARDIR}/mysql_cluster.1";
  my $tmp = "$ENV{MYSQLTEST_VARDIR}/tmp/redo_pmem_find_end";
  my $reader = $ENV{NDB_REDO_LOG_READER};
  open(my $out, '>', $tmp) or die "Cannot open $tmp: $!\n";
  foreach my $node (split(/,/, $ENV{REDO_PMEM_NODES})) {
    my $log = "$cluster/ndbd.$node/ndbd.log";
    print $out "offset $node ", ((-s $log) || 0), "\n";
    foreach my $part (0 .. 3) {
      my $dir = "$cluster/ndbd.$node/ndb_${node}_fs/D" . (8 + $part) .
                "/DBLQH";
      my $line = `$reader --find-end=$dir 2>&1`;
      die "ndb_redo_log_reader --find-end=$dir failed: $line" if $? != 0;
      chomp($line);
      print $out "end $node $line\n";
    }
  }
  close($out);
EOF
}

if (!$redo_pmem_find_end_save) {
--perl
  use strict;
  my $cluster = "$ENV{MYSQLTEST_VARDIR}/mysql_cluster.1";
  my $tmp = "$ENV{MYSQLTEST_VARDIR}/tmp/redo_pmem_find_end";
  open(my $in, '<', $tmp) or die "Cannot open $tmp: $!\n";
  my (%offset, %reader);
  while (my $l = <$in>) {
    chomp($l);
    if ($l =~ /^offset (\d+) (\d+)$/) {
      $offset{$1} = $2;
    } elsif ($l =~ /^end (\d+) (PMEM REDO log part (\d+): .*)$/) {
      $reader{$1}{$3} = $2;
    } else {
      die "Unexpected line in $tmp: $l\n";
    }
  }
  close($in);
  unlink($tmp);
  foreach my $node (sort keys %offset) {
    my $log = "$cluster/ndbd.$node/ndbd.log";
    open(my $fh, '<', $log) or die "Cannot open $log: $!\n";
    seek($fh, $offset{$node}, 0);
    # The first restart after the stop; a second one would find another end
    my %restart;
    while (my $l = <$fh>) {
      if ($l =~ /(PMEM REDO log part (\d+): last file .*?)\s*$/) {
        $restart{$2} = $1 unless exists $restart{$2};
      }
    }
    close($fh);
    foreach my $part (sort keys %{$reader{$node}}) {
      if (defined $restart{$part} && $restart{$part} eq $reader{$node}{$part}) {
        print "Node $node log part $part: the restart found the reader's end\n";
      } else {
        print "Node $node log part $part: the ends differ\n",
              "  reader:  $reader{$node}{$part}\n",
              "  restart: ", ($restart{$part} // "none"), "\n";
      }
    }
  }
EOF
}
