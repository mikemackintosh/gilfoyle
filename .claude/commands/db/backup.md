# Database Backup and Restore

Backup and restore PostgreSQL and MySQL databases — logical dumps, compressed backups, point-in-time recovery, and automation.

## Arguments

$ARGUMENTS describes the operation:

Examples:
- `postgres dump <database>` — dump a PostgreSQL database
- `postgres restore <database> <file>` — restore a PostgreSQL dump
- `mysql dump <database>` — dump a MySQL database
- `mysql restore <database> <file>` — restore a MySQL dump
- `schedule` — set up automated backup cron/timer
- `verify <file>` — verify a backup file is valid
- (no args — backup strategy guide)

## Workflow

1. Parse the operation from `$ARGUMENTS`.
2. Show the user the exact commands before executing.
3. **Always confirm before restore operations — they overwrite data.**

### PostgreSQL Backup

```bash
# Plain SQL dump
pg_dump -h localhost -U postgres myapp > myapp_$(date +%Y%m%d_%H%M%S).sql

# Custom format (compressed, supports parallel restore)
pg_dump -h localhost -U postgres -Fc myapp > myapp_$(date +%Y%m%d_%H%M%S).dump

# Directory format (parallel dump)
pg_dump -h localhost -U postgres -Fd -j 4 myapp -f myapp_dump/

# Dump all databases
pg_dumpall -h localhost -U postgres > all_databases_$(date +%Y%m%d_%H%M%S).sql

# Dump specific tables
pg_dump -h localhost -U postgres -t users -t orders myapp > tables.sql

# Schema only (no data)
pg_dump -h localhost -U postgres --schema-only myapp > schema.sql

# Data only (no schema)
pg_dump -h localhost -U postgres --data-only myapp > data.sql

# Compressed with gzip
pg_dump -h localhost -U postgres myapp | gzip > myapp_$(date +%Y%m%d).sql.gz
```

### PostgreSQL Restore

```bash
# From SQL dump
psql -h localhost -U postgres myapp < myapp.sql

# From custom format
pg_restore -h localhost -U postgres -d myapp myapp.dump

# Create database and restore
createdb -h localhost -U postgres myapp_restored
pg_restore -h localhost -U postgres -d myapp_restored myapp.dump

# Parallel restore (custom or directory format)
pg_restore -h localhost -U postgres -d myapp -j 4 myapp.dump

# From gzip
gunzip < myapp.sql.gz | psql -h localhost -U postgres myapp
```

### MySQL Backup

```bash
# Single database
mysqldump -u root -p myapp > myapp_$(date +%Y%m%d_%H%M%S).sql

# With consistent snapshot (InnoDB)
mysqldump -u root -p --single-transaction --routines --triggers myapp > myapp.sql

# All databases
mysqldump -u root -p --all-databases --single-transaction > all_databases.sql

# Specific tables
mysqldump -u root -p myapp users orders > tables.sql

# Schema only
mysqldump -u root -p --no-data myapp > schema.sql

# Compressed
mysqldump -u root -p --single-transaction myapp | gzip > myapp_$(date +%Y%m%d).sql.gz
```

### MySQL Restore

```bash
# From SQL dump
mysql -u root -p myapp < myapp.sql

# Create database and restore
mysql -u root -p -e "CREATE DATABASE myapp_restored;"
mysql -u root -p myapp_restored < myapp.sql

# From gzip
gunzip < myapp.sql.gz | mysql -u root -p myapp
```

### Automated Backup Script

```bash
#!/bin/bash
# /opt/scripts/db-backup.sh
BACKUP_DIR="/backups/db"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

# PostgreSQL
pg_dump -h localhost -U postgres -Fc myapp > "$BACKUP_DIR/myapp_${DATE}.dump"

# MySQL
# mysqldump -u root --single-transaction myapp | gzip > "$BACKUP_DIR/myapp_${DATE}.sql.gz"

# Verify backup
if [ $? -eq 0 ]; then
  echo "[$(date)] Backup successful: myapp_${DATE}" >> "$BACKUP_DIR/backup.log"
else
  echo "[$(date)] BACKUP FAILED" >> "$BACKUP_DIR/backup.log"
  # Send alert
fi

# Cleanup old backups
find "$BACKUP_DIR" -name "myapp_*.dump" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "myapp_*.sql.gz" -mtime +$RETENTION_DAYS -delete
```

### Systemd Timer (preferred over cron)

```ini
# /etc/systemd/system/db-backup.timer
[Unit]
Description=Daily database backup

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true
RandomizedDelaySec=1800

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/db-backup.service
[Unit]
Description=Database backup

[Service]
Type=oneshot
ExecStart=/opt/scripts/db-backup.sh
User=postgres
```

3. Verify backup integrity after completion.

## Security Notes

- **Test restores regularly.** A backup you've never restored is not a backup — it's a hope.
- Backup files contain all data including passwords and PII. Encrypt at rest and restrict access (`chmod 600`).
- Use `--single-transaction` for MySQL InnoDB to get a consistent snapshot without locking tables.
- Store backups off-host (remote storage, S3, etc.). A backup on the same server as the database is useless if the server dies.
- The 3-2-1 rule: 3 copies of data, on 2 different media types, with 1 off-site.
