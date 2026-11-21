#
# Wait until a backup started with NOWAIT has taken its backup id
# - START BACKUP NOWAIT returns once the master has the request, before
#   it takes the next backup id from SYSTAB_0, so ndbinfo.backup_id can
#   still show the old id right after it
# - waits until ndbinfo.backup_id is larger than $old_backup_id, for at
#   most 60 seconds
# - the new backup id is left in $the_backup_id
#

let $_id_timeout = 600;
--source include/ndb_backup_id.inc
while ($the_backup_id <= $old_backup_id)
{
  dec $_id_timeout;
  if (!$_id_timeout)
  {
    die Timed out waiting for the backup id to increase after start backup nowait;
  }
  --sleep 0.1
  --source include/ndb_backup_id.inc
}
