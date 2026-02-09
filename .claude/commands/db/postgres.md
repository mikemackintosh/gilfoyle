# PostgreSQL Administration

Manage PostgreSQL — databases, configuration, monitoring, replication status, and maintenance.

## Arguments

$ARGUMENTS is optional:
- `status` — show PostgreSQL status and connection info
- `databases` — list databases with sizes
- `config` — show key configuration settings
- `connections` — show active connections and queries
- `locks` — show lock contention
- `replication` — show replication status
- (no args — PostgreSQL overview)

Examples:
- (no args — overview)
- `status`
- `databases`
- `connections`
- `locks`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Status

```bash
echo "=== PostgreSQL Status ==="
systemctl status postgresql --no-pager

echo ""
echo "=== Version ==="
psql --version
sudo -u postgres psql -c "SELECT version();"

echo ""
echo "=== Listening ==="
ss -tlnp | grep postgres
```

### Step 2 — Databases

```sql
-- Database listing with sizes
SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size,
       datcollate, datistemplate
FROM pg_database ORDER BY pg_database_size(datname) DESC;

-- Table sizes in current database
SELECT schemaname, relname, pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
       pg_size_pretty(pg_relation_size(relid)) AS data_size,
       pg_size_pretty(pg_total_relation_size(relid) - pg_relation_size(relid)) AS index_size
FROM pg_catalog.pg_statio_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 20;
```

### Step 3 — Active connections

```sql
-- Connection summary
SELECT datname, usename, state, count(*)
FROM pg_stat_activity GROUP BY datname, usename, state ORDER BY count DESC;

-- Long-running queries (>5 seconds)
SELECT pid, now() - query_start AS duration, usename, query, state, wait_event_type
FROM pg_stat_activity
WHERE state != 'idle' AND now() - query_start > interval '5 seconds'
ORDER BY duration DESC;

-- Blocked queries
SELECT blocked.pid AS blocked_pid, blocked.query AS blocked_query,
       blocking.pid AS blocking_pid, blocking.query AS blocking_query
FROM pg_stat_activity blocked
JOIN pg_locks bl ON bl.pid = blocked.pid
JOIN pg_locks gl ON gl.locktype = bl.locktype AND gl.database IS NOT DISTINCT FROM bl.database
  AND gl.relation IS NOT DISTINCT FROM bl.relation AND gl.page IS NOT DISTINCT FROM bl.page
  AND gl.tuple IS NOT DISTINCT FROM bl.tuple AND gl.pid != bl.pid
JOIN pg_stat_activity blocking ON blocking.pid = gl.pid
WHERE NOT bl.granted;
```

### Step 4 — Configuration

```sql
-- Key settings
SELECT name, setting, unit, context
FROM pg_settings
WHERE name IN ('shared_buffers','effective_cache_size','work_mem','maintenance_work_mem',
  'max_connections','max_wal_size','min_wal_size','checkpoint_completion_target',
  'random_page_cost','effective_io_concurrency','log_min_duration_statement');
```

```bash
# Config file locations
sudo -u postgres psql -c "SHOW config_file;"
sudo -u postgres psql -c "SHOW hba_file;"
sudo -u postgres psql -c "SHOW data_directory;"
```

3. Present findings and flag issues (high connection count, long-running queries, lock contention).

## Security Notes

- Review `pg_hba.conf` — it controls who can connect from where. Avoid `trust` authentication method.
- Use `scram-sha-256` instead of `md5` for password authentication (PostgreSQL 10+).
- `max_connections` should match actual need — each connection uses ~10MB of RAM.
- Monitor `pg_stat_activity` for unexpected connections or queries from unknown users.
- Superuser accounts should be limited. Create role-based access with minimal privileges.
