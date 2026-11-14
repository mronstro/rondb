# RONDB-1150: where the data nodes of mysql_cluster.1 keep their REDO
# log, the rule of fix_redo_log_path in lib/My/ConfigFactory.pm. With
# RedoLogMode=pmem and MTR_NDB_PMEM_DIR set, a directory on a DAX mount:
# $MTR_NDB_PMEM_DIR/<name of the vardir>/mysql_cluster.1; else the
# cluster's directory in the vardir. Sets $redo_cluster, under which are
# ndbd.N/ndb_N_fs/D8.../DBLQH. redo_pmem_find_end.inc has the same rule in
# perl (a let of an environment variable here did not reach --perl).

--perl
  use strict;
  use File::Basename;
  my $vardir = $ENV{MYSQLTEST_VARDIR};
  my $dir = "$vardir/mysql_cluster.1";
  my $pmem = $ENV{MTR_NDB_PMEM_DIR};
  $dir = "$pmem/" . basename($vardir) . "/mysql_cluster.1"
    if defined $pmem && $pmem ne '';
  my $inc = "$vardir/tmp/redo_pmem_cluster_dir.inc";
  open(my $fh, '>', $inc) or die "Cannot open $inc: $!\n";
  print $fh "let \$redo_cluster = $dir;\n";
  close($fh);
EOF
--source $MYSQLTEST_VARDIR/tmp/redo_pmem_cluster_dir.inc
--remove_file $MYSQLTEST_VARDIR/tmp/redo_pmem_cluster_dir.inc
