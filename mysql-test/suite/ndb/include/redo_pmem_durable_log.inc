# RONDB-1150 X7: how many lines of the latest start in ndbd.log of each
# data node of mysql_cluster.1 contain LOG_LINE, per node, or in all if
# LOG_SUM is 1. In LOG_LINE, <g> stands for the g that
# redo_pmem_durable_gci.inc read last, and <n> for a GCI, which is kept
# for the next redo_pmem_durable_gci.inc. Only the lines since the latest
# "Start initiated" count, as ndbd.log keeps the earlier starts and MTR
# reruns a failed test on the same cluster. A data node writes its log a
# little after the event, so a line logged as a management command
# returns may not be there yet: with LOG_WAIT above 0 the log is read
# again, for up to 30 s, until each node (with LOG_SUM, all) has that
# many. A line equal to the one before it in ndbd.log is held back until
# a different line comes (the repeat filter of LogHandler), so a count of
# equal lines in a row may stay short for long. Set them with --let, which
# takes the rest of the line, so that the text may hold a semicolon:
#   --let LOG_LINE = <text>
#   --let LOG_SUM = 0 or 1
#   --let LOG_WAIT = 0 or the count to wait for

--perl
  use strict;
  my $vardir = $ENV{MYSQLTEST_VARDIR};
  my $g = '';
  my $gci_file = "$vardir/tmp/redo_pmem_durable_gci.txt";
  if (open(my $fh, '<', $gci_file)) {
    $g = <$fh>;
    chomp $g;
    close($fh);
  }
  my $pattern = join('', map { $_ eq '<n>' ? '(\d+)' :
                               $_ eq '<g>' ? quotemeta($g) : quotemeta($_) }
                         split(/(<n>|<g>)/, $ENV{LOG_LINE}));
  my $wait = $ENV{LOG_WAIT} || 0;
  my $deadline = time() + 30;
  my ($total, %count, %logged);
  while (1) {
    $total = 0;
    %count = ();
    %logged = ();
    foreach my $node (1, 2) {
      my $log = "$vardir/mysql_cluster.1/ndbd.$node/ndbd.log";
      open(my $fh, '<', $log) or die "Cannot open $log: $!\n";
      my $n = 0;
      my $gci;
      while (<$fh>) {
        if (/Start initiated/) {
          $n = 0;
          undef $gci;
        }
        if (/$pattern/) {
          $n++;
          $gci = $1 if defined $1;
        }
      }
      close($fh);
      $total += $n;
      $count{$node} = $n;
      $logged{$gci} = 1 if defined $gci;
    }
    my $done = $ENV{LOG_SUM} ? $total >= $wait
                             : ($count{1} >= $wait && $count{2} >= $wait);
    last if $done || time() >= $deadline;
    select(undef, undef, undef, 0.1);
  }
  if ($ENV{LOG_SUM}) {
    print "all nodes: $total\n";
  } else {
    print "node $_: $count{$_}\n" foreach (1, 2);
  }
  my @gcis = keys %logged;
  print "the nodes logged different GCIs: @gcis\n" if @gcis > 1;
  if (@gcis == 1) {
    my $file = "$vardir/tmp/redo_pmem_durable_logged_gci.txt";
    open(my $fh, '>', $file) or die "Cannot open $file: $!\n";
    print $fh "$gcis[0]\n";
    close($fh);
  }
EOF
