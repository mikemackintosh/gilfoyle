---
name: Database Administration
description: Database administration for PostgreSQL and MySQL/MariaDB — user management, backup/restore, performance tuning, replication, and troubleshooting.
instructions: |
  Use this skill when the user needs help with database administration — managing PostgreSQL or
  MySQL/MariaDB instances, creating users and granting privileges, performing backups and restores,
  optimizing query performance, setting up replication, or troubleshooting database issues. Always
  show commands before executing. Warn about destructive operations (DROP, TRUNCATE, DELETE without
  WHERE). Recommend backups before schema changes.
---

# Database Administration Skill

## Related Commands
- `/db:postgres` — PostgreSQL administration and management
- `/db:mysql` — MySQL/MariaDB administration and management
- `/db:backup` — Database backup and restore strategies
- `/db:performance` — Query performance analysis and optimization
- `/db:users` — Database user and privilege management

## PostgreSQL

### Connection

```bash
# Connect as postgres superuser
sudo -u postgres psql

# Connect to a specific database
psql -h localhost -U username -d database

# Connection string format
psql "postgresql://user:password@host:5432/database?sslmode=require"
```

### Database Management

```sql
-- List databases
\l

-- Create database
CREATE DATABASE myapp;
CREATE DATABASE myapp OWNER myuser ENCODING 'UTF8';

-- Drop database (DESTRUCTIVE)
-- DROP DATABASE myapp;

-- Connect to a database
\c myapp

-- List tables
\dt
\dt+    -- with sizes

-- Describe a table
\d tablename
\d+ tablename   -- with details

-- Database size
SELECT pg_database.datname, pg_size_pretty(pg_database_size(pg_database.datname))
FROM pg_database ORDER BY pg_database_size(pg_database.datname) DESC;

-- Table sizes
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_catalog.pg_statio_user_tables ORDER BY pg_total_relation_size(relid) DESC;
```

### User Management

```sql
-- Create user
CREATE USER myuser WITH PASSWORD 'securepassword';

-- Create user with specific privileges
CREATE USER readonly WITH PASSWORD 'securepassword';
GRANT CONNECT ON DATABASE myapp TO readonly;
GRANT USAGE ON SCHEMA public TO readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly;

-- Superuser
ALTER USER myuser WITH SUPERUSER;

-- Change password
ALTER USER myuser WITH PASSWORD 'newpassword';

-- List users and roles
\du

-- Drop user
-- DROP USER myuser;
```

### Backup & Restore

```bash
# Dump a single database
pg_dump -h localhost -U postgres myapp > myapp.sql
pg_dump -h localhost -U postgres -Fc myapp > myapp.dump    # Custom format (compressed)

# Dump all databases
pg_dumpall -h localhost -U postgres > all_databases.sql

# Restore from SQL dump
psql -h localhost -U postgres myapp < myapp.sql

# Restore from custom format
pg_restore -h localhost -U postgres -d myapp myapp.dump

# Dump specific tables
pg_dump -h localhost -U postgres -t tablename myapp > table.sql
```

### Configuration

```bash
# Config file location
SHOW config_file;       -- in psql
# Usually /etc/postgresql/<version>/main/postgresql.conf (Debian)
# or /var/lib/pgsql/<version>/data/postgresql.conf (RHEL)

# Key settings
# shared_buffers = 256MB          # 25% of RAM
# effective_cache_size = 768MB    # 50-75% of RAM
# work_mem = 4MB                  # Per-operation memory
# maintenance_work_mem = 128MB    # For VACUUM, CREATE INDEX
# max_connections = 100

# Client authentication
# /etc/postgresql/<version>/main/pg_hba.conf
# TYPE  DATABASE  USER  ADDRESS       METHOD
# local all       all                 peer
# host  all       all   127.0.0.1/32  scram-sha-256
# host  all       all   10.0.0.0/8    scram-sha-256

# Reload config (no restart needed for most settings)
SELECT pg_reload_conf();
# or: systemctl reload postgresql
```

### Monitoring

```sql
-- Active queries
SELECT pid, now() - pg_stat_activity.query_start AS duration, query, state
FROM pg_stat_activity WHERE state != 'idle' ORDER BY duration DESC;

-- Kill a long-running query
SELECT pg_cancel_backend(<pid>);     -- Graceful
SELECT pg_terminate_backend(<pid>);  -- Force

-- Connection count
SELECT count(*) FROM pg_stat_activity;
SELECT datname, count(*) FROM pg_stat_activity GROUP BY datname;

-- Lock contention
SELECT * FROM pg_locks WHERE NOT granted;

-- Replication status
SELECT * FROM pg_stat_replication;
```

## MySQL / MariaDB

### Connection

```bash
# Connect as root
mysql -u root -p

# Connect to a specific database
mysql -h localhost -u username -p database

# Execute a query directly
mysql -u root -p -e "SHOW DATABASES;"
```

### Database Management

```sql
-- List databases
SHOW DATABASES;

-- Create database
CREATE DATABASE myapp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Drop database (DESTRUCTIVE)
-- DROP DATABASE myapp;

-- Use a database
USE myapp;

-- List tables
SHOW TABLES;
SHOW TABLE STATUS;    -- with details

-- Describe a table
DESCRIBE tablename;
SHOW CREATE TABLE tablename;

-- Database sizes
SELECT table_schema, ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.tables GROUP BY table_schema ORDER BY SUM(data_length + index_length) DESC;
```

### User Management

```sql
-- Create user
CREATE USER 'myuser'@'localhost' IDENTIFIED BY 'securepassword';
CREATE USER 'myuser'@'%' IDENTIFIED BY 'securepassword';    -- Remote access

-- Grant privileges
GRANT ALL PRIVILEGES ON myapp.* TO 'myuser'@'localhost';
GRANT SELECT ON myapp.* TO 'readonly'@'localhost';
GRANT SELECT, INSERT, UPDATE ON myapp.* TO 'appuser'@'10.0.%';
FLUSH PRIVILEGES;

-- Show grants
SHOW GRANTS FOR 'myuser'@'localhost';

-- Revoke privileges
REVOKE ALL PRIVILEGES ON myapp.* FROM 'myuser'@'localhost';

-- Change password
ALTER USER 'myuser'@'localhost' IDENTIFIED BY 'newpassword';

-- List users
SELECT user, host, authentication_string FROM mysql.user;

-- Drop user
-- DROP USER 'myuser'@'localhost';
```

### Backup & Restore

```bash
# Dump a single database
mysqldump -u root -p myapp > myapp.sql
mysqldump -u root -p --single-transaction myapp > myapp.sql   # InnoDB consistent

# Dump all databases
mysqldump -u root -p --all-databases > all_databases.sql

# Dump specific tables
mysqldump -u root -p myapp table1 table2 > tables.sql

# Dump structure only (no data)
mysqldump -u root -p --no-data myapp > schema.sql

# Restore
mysql -u root -p myapp < myapp.sql

# Compressed dump and restore
mysqldump -u root -p myapp | gzip > myapp.sql.gz
gunzip < myapp.sql.gz | mysql -u root -p myapp
```

### Configuration

```bash
# Config file location
# /etc/mysql/my.cnf or /etc/my.cnf
# /etc/mysql/mysql.conf.d/mysqld.cnf (Debian)

# Key settings in [mysqld] section
# innodb_buffer_pool_size = 1G     # 50-70% of RAM for dedicated DB server
# max_connections = 151
# innodb_log_file_size = 256M
# query_cache_type = 0             # Disabled in MySQL 8.0+
# slow_query_log = 1
# slow_query_log_file = /var/log/mysql/slow.log
# long_query_time = 2

# Show current settings
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW VARIABLES LIKE 'max_connections';
```

### Monitoring

```sql
-- Show running queries
SHOW PROCESSLIST;
SHOW FULL PROCESSLIST;

-- Kill a query
KILL <id>;

-- InnoDB status
SHOW ENGINE INNODB STATUS\G

-- Connection count
SHOW STATUS LIKE 'Threads_connected';
SHOW STATUS LIKE 'Max_used_connections';

-- Slow query log
SHOW VARIABLES LIKE 'slow_query%';
SHOW VARIABLES LIKE 'long_query_time';
```

## Performance Optimization

### EXPLAIN (both PostgreSQL and MySQL)

```sql
-- Analyse a query execution plan
EXPLAIN SELECT * FROM users WHERE email = 'foo@bar.com';
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'foo@bar.com';  -- Actually runs it

-- Key things to look for:
-- Seq Scan (Postgres) / Full Table Scan (MySQL) = missing index
-- Nested Loop with large row counts = consider join optimization
-- Sort with high cost = consider adding index for ORDER BY
```

### Indexing

```sql
-- Create an index
CREATE INDEX idx_users_email ON users(email);
CREATE UNIQUE INDEX idx_users_email ON users(email);

-- Composite index
CREATE INDEX idx_orders_user_date ON orders(user_id, created_at);

-- Show indexes
-- PostgreSQL
\di
SELECT * FROM pg_indexes WHERE tablename = 'users';

-- MySQL
SHOW INDEX FROM users;

-- Drop index
DROP INDEX idx_users_email;                          -- PostgreSQL
ALTER TABLE users DROP INDEX idx_users_email;        -- MySQL

-- Find missing indexes (PostgreSQL)
SELECT relname, seq_scan, seq_tup_read, idx_scan, idx_tup_fetch
FROM pg_stat_user_tables WHERE seq_scan > 0 ORDER BY seq_tup_read DESC LIMIT 20;
```

### Maintenance

```sql
-- PostgreSQL
VACUUM;                    -- Reclaim space
VACUUM ANALYZE;            -- Reclaim space + update stats
VACUUM FULL tablename;     -- Aggressive (locks table)
ANALYZE tablename;         -- Update query planner stats
REINDEX TABLE tablename;   -- Rebuild indexes

-- MySQL
OPTIMIZE TABLE tablename;  -- Reclaim space + rebuild indexes
ANALYZE TABLE tablename;   -- Update index statistics
CHECK TABLE tablename;     -- Check for errors
REPAIR TABLE tablename;    -- Repair MyISAM table
```
