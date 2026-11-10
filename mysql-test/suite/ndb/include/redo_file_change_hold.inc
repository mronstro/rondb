# The data node log checks of ndb_redo_file_change_hold, in data node 1.
#
# REDO_HOLD_STEP=save: the end of the data node log, so that only the
# lines logged after it count.
# REDO_HOLD_STEP=check: waits up to 120 seconds until the data node has
# logged that a REDO log part waits at the end of a file until the next
# file is open, and that commit, abort and GCI records wait there.
--perl
  use strict;
  my $log = "$ENV{MYSQLTEST_VARDIR}/mysql_cluster.1/ndbd.1/ndbd.log";
  my $file = "$ENV{MYSQLTEST_VARDIR}/tmp/ndb_redo_file_change_hold.offset";
  if ($ENV{REDO_HOLD_STEP} eq 'save') {
    open(my $out, '>', $file) or die "Cannot open $file: $!\n";
    print $out ((-s $log) || 0), "\n";
    close($out);
  } else {
    open(my $in, '<', $file) or die "Cannot open $file: $!\n";
    chomp(my $offset = <$in>);
    close($in);
    my ($waited, $records) = (0, 0);
    for (my $try = 0; $try < 240 && !($waited && $records); $try++) {
      select(undef, undef, undef, 0.5) if $try > 0;
      open(my $fh, '<', $log) or die "Cannot open $log: $!\n";
      seek($fh, $offset, 0);
      while (my $line = <$fh>) {
        $waited = 1
          if $line =~ /waits at the end of file \d+ until file \d+ is open/;
        $records = 1
          if $line =~ /GCI records wait at the end of file \d+/;
      }
      close($fh);
    }
    print "Node 1: waited at the end of a file ", ($waited ? "yes" : "no"),
          ", records waited ", ($records ? "yes" : "no"), "\n";
  }
EOF
