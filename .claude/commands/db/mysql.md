# MySQL / MariaDB Administration

Manage MySQL/MariaDB — databases, configuration, monitoring, replication status, and maintenance.

## Arguments

$ARGUMENTS is optional:
- `status` — show MySQL status and connection info
- `databases` — list databases with sizes
- `config` — show key configuration settings
- `connections` — show active connections and queries
- `replication` — show replication status
- `innodb` — show InnoDB engine status
- (no args — MySQL overview)

Examples:
- (no args — overview)
- `status`
- `databases`
- `connections`
- `innodb`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Status

```bash
echo "=== MySQL Status ==="
systemctl status mysql --no-pager 2>/dev/null || systemctl status mariadb --no-pager

echo ""
echo "=== Version ==="
mysql --version
mysql -u root -p -e "SELECT VERSION();"

echo ""
echo "=== Listening ==="
ss -tlnp | grep mysql
```

### Step 2 — Databases

```sql
-- Database listing with sizes
SELECT table_schema AS 'Database',
       ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)',
       COUNT(*) AS 'Tables'
FROM information_schema.tables
GROUP BY table_schema ORDER BY SUM(data_length + index_length) DESC;

-- Largest tables
SELECT table_schema, table_name,
       ROUND(data_length / 1024 / 1024, 2) AS 'Data (MB)',
       ROUND(index_length / 1024 / 1024, 2) AS 'Index (MB)',
       table_rows AS 'Rows'
FROM information_schema.tables
ORDER BY data_length + index_length DESC LIMIT 20;
```

### Step 3 — Active connections

```sql
-- Process list
SHOW FULL PROCESSLIST;

-- Connection summary
SELECT user, host, db, command, count(*) AS connections
FROM information_schema.processlist GROUP BY user, host, db, command ORDER BY connections DESC;

-- Long-running queries (>5 seconds)
SELECT id, user, host, db, command, time, state, LEFT(info, 100) AS query
FROM information_schema.processlist
WHERE command != 'Sleep' AND time > 5 ORDER BY time DESC;
```

### Step 4 — Configuration

```sql
-- Key settings
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW VARIABLES LIKE 'max_connections';
SHOW VARIABLES LIKE 'innodb_log_file_size';
SHOW VARIABLES LIKE 'slow_query%';
SHOW VARIABLES LIKE 'long_query_time';
SHOW VARIABLES LIKE 'query_cache%';
SHOW VARIABLES LIKE 'bind_address';

-- Status counters
SHOW STATUS LIKE 'Threads_connected';
SHOW STATUS LIKE 'Max_used_connections';
SHOW STATUS LIKE 'Uptime';
SHOW STATUS LIKE 'Slow_queries';
SHOW STATUS LIKE 'Connections';
```

### Step 5 — InnoDB status

```sql
SHOW ENGINE INNODB STATUS\G
```

3. Present findings and flag issues.

## Security Notes

- Run `mysql_secure_installation` after fresh install — it removes test databases, anonymous users, and disables remote root login.
- `bind_address = 127.0.0.1` limits connections to localhost. Set to `0.0.0.0` only if remote access is needed (and use firewall rules).
- Review user grants: `SELECT user, host FROM mysql.user;` — watch for `'%'` host (accepts from anywhere).
- Enable the slow query log to identify queries that may be vulnerable to SQL injection (they often show up as slow full-table scans).
- Use `caching_sha2_password` (MySQL 8+) instead of `mysql_native_password` for better security.
