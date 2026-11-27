# RONDB-1150 X7: how many lines of the latest start in ndbd.log of each
# data node of mysql_cluster.1 contain LOG_LINE, per node, or in all if
# LOG_SUM is 1. In LOG_LINE, <g> stands for the g that
# redo_pmem_durable_gci.inc read last, and <n> for a GCI, which is kept
# for the next redo_pmem_durable_gci.inc. Only the lines since the latest
# "Start initiated" count, as ndbd.log keeps the earlier starts and MTR
# reruns a failed test on the same cluster. Set them with --let, which
# takes the rest of the line, so that the text may hold a semicolon:
#   --let LOG_LINE = <text>
#   --let LOG_SUM = 0 or 1

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
  my $total = 0;
  my %logged;
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
    $logged{$gci} = 1 if defined $gci;
    print "node $node: $n\n" unless $ENV{LOG_SUM};
  }
  print "all nodes: $total\n" if $ENV{LOG_SUM};
  my @gcis = keys %logged;
  print "the nodes logged different GCIs: @gcis\n" if @gcis > 1;
  if (@gcis == 1) {
    my $file = "$vardir/tmp/redo_pmem_durable_logged_gci.txt";
    open(my $fh, '>', $file) or die "Cannot open $file: $!\n";
    print $fh "$gcis[0]\n";
    close($fh);
  }
EOF
