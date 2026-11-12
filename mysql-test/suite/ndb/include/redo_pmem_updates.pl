#!/usr/bin/perl
#
# RONDB-1150 (recovery plan S7.1): updates of all rows of test.t1 in the
# background while data nodes stop and restart.
#
# Usage: perl redo_pmem_updates.pl start|stop <vardir>
#
# start detaches a loop that runs one UPDATE after the other, each one
# transaction in its own mysql client, so that an UPDATE that fails,
# while a data node stops or the cluster restarts, ends only its client
# and the next UPDATE follows. All rows then hold the same value. A
# stored procedure that looped over the UPDATEs in one CALL changed no
# row after data node 2 stopped in its first UPDATE (macOS, 2026-11-11),
# so the next error insert of ndb_redo_pmem_crash_points was not reached.
#
# The loop ends at stop or when the mysqltest process that started it
# ends, so that a test that fails before stop does not update the tables
# of the next tests. stop waits until the UPDATE that runs has ended.
#
use strict;
use POSIX ();

my ($action, $vardir) = @ARGV;
die "Usage: perl $0 start|stop <vardir>\n"
  unless defined $vardir && $action =~ /^(start|stop)$/;
my $stop = "$vardir/tmp/redo_pmem_updates.stop";
my $done = "$vardir/tmp/redo_pmem_updates.done";

if ($action eq 'stop') {
  open(my $f, '>', $stop) or die "Cannot write $stop: $!\n";
  close($f);
  for (my $i = 0; $i < 1200 && !-e $done; $i++) {
    select(undef, undef, undef, 0.1);
  }
  die "The updates did not stop\n" unless -e $done;
  unlink($stop, $done);
  exit(0);
}

# The mysqltest process that runs this script, through a shell or not
sub mysqltest_pid {
  my $pid = getppid();
  for (1 .. 4) {
    my $out = `ps -o ppid= -o comm= -p $pid 2>/dev/null`;
    my ($ppid, $comm) = $out =~ /^\s*(\d+)\s+(.*?)\s*$/;
    last unless defined $comm;
    return $pid if $comm =~ /mysqltest/;
    $pid = $ppid;
  }
  die "Cannot find the mysqltest process running $0\n";
}

my $owner = mysqltest_pid();
unlink($stop, $done);

# The loop is detached and holds none of the output of this script,
# which mysqltest reads until the end.
my $pid = fork();
die "fork failed: $!\n" unless defined $pid;
if ($pid == 0) {
  POSIX::setsid();
  open(STDIN, '<', '/dev/null');
  open(STDOUT, '>', '/dev/null');
  open(STDERR, '>', '/dev/null');
  my $i = 0;
  while (!-e $stop && kill(0, $owner)) {
    my $c = chr(ord('A') + $i % 26);
    system("$ENV{MYSQL} test -e \"UPDATE t1 SET b = REPEAT('$c', 250)\"");
    select(undef, undef, undef, 0.1) if $? != 0;
    $i++;
  }
  open(my $f, '>', $done);
  close($f);
  POSIX::_exit(0);
}
exit(0);
