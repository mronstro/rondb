#
# Wait for the backup started with NOWAIT to get its id
# - "start backup nowait" returns before the backup has started, so
#   ndbinfo.backup_id can still hold the id of the previous backup when
#   the test reads it right after.  Wait until the id has passed
#   $old_backup_id, which the caller loaded with include/ndb_backup_id.inc
#   before it started the backup, and leave it in $the_backup_id.
#

let $_done = 0;
let $_id_timeout = 600;
while (!$_done)
{
  --source include/ndb_backup_id.inc

  if ($the_backup_id > $old_backup_id)
  {
    let $_done = 1;
  }

  if (!$_done)
  {
    dec $_id_timeout;
    sleep 0.1;
    if (!$_id_timeout)
    {
      die "Timed out waiting for the backup id to pass $old_backup_id.";
    }
  }
}
