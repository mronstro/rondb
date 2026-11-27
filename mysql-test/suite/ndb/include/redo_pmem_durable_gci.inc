# RONDB-1150 X7: g, the first GCI of durable commits, in the sysfile
# (DBDIH/P0.sysfile under D1) of each data node of mysql_cluster.1, read
# with ndb_print_sys_file while the nodes are stopped. Prints g as off, as
# the GCI that redo_pmem_durable_log.inc took from the log last, or as on,
# and keeps g in the vardir for redo_pmem_durable_log.inc.

--perl
  use strict;
  my $print = $ENV{NDB_PRINT_SYS_FILE};
  my $vardir = $ENV{MYSQLTEST_VARDIR};
  my %g;
  foreach my $node (1, 2) {
    my $file = "$vardir/mysql_cluster.1/ndbd.$node/ndb_${node}_fs/D1/DBDIH/P0.sysfile";
    my @out = `$print $file`;
    die "ndb_print_sys_file $file failed\n" if $? != 0;
    $g{$node} = 0;
    foreach (@out) {
      $g{$node} = $1 if /^durableGci = (\d+)/;
    }
  }
  print "nodes 1 and 2 differ in g: $g{1} and $g{2}\n" if $g{1} != $g{2};
  my $g = $g{1};
  my $logged;
  my $logged_file = "$vardir/tmp/redo_pmem_durable_logged_gci.txt";
  if (open(my $fh, '<', $logged_file)) {
    $logged = <$fh>;
    chomp $logged;
    close($fh);
    unlink($logged_file);
  }
  if ($g == 0) {
    print "g: off\n";
  } elsif (defined $logged) {
    print $g == $logged ? "g: the GCI in the log of the restart\n"
                        : "g: $g, not $logged, the GCI in the log\n";
  } else {
    print "g: on\n";
  }
  my $gci_file = "$vardir/tmp/redo_pmem_durable_gci.txt";
  open(my $fh, '>', $gci_file) or die "Cannot open $gci_file: $!\n";
  print $fh "$g\n";
  close($fh);
EOF
