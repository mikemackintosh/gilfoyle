# Database Performance Analysis

Analyse and optimise database query performance — EXPLAIN plans, slow query identification, indexing strategy, and configuration tuning.

## Arguments

$ARGUMENTS is optional:
- `explain <query>` — analyse a query execution plan
- `slow` — find and analyse slow queries
- `indexes <table>` — analyse index usage for a table
- `missing` — find missing indexes (tables with high sequential scans)
- `tune` — show tuning recommendations based on current config
- (no args — performance overview)

Examples:
- (no args — performance overview)
- `slow`
- `missing`
- `indexes users`
- `tune`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Detect database engine (PostgreSQL vs MySQL).
3. Show the user the exact commands before executing.

### PostgreSQL Performance

#### Slow Queries

```sql
-- Enable slow query logging (set in postgresql.conf)
-- log_min_duration_statement = 1000   -- log queries taking >1s

-- Top queries by total time (requires pg_stat_statements extension)
SELECT query, calls, total_exec_time, mean_exec_time, rows
FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 20;

-- Currently running long queries
SELECT pid, now() - query_start AS duration, query
FROM pg_stat_activity WHERE state = 'active' AND now() - query_start > interval '5 seconds'
ORDER BY duration DESC;
```

#### EXPLAIN

```sql
-- Execution plan
EXPLAIN SELECT * FROM users WHERE email = 'foo@bar.com';

-- With actual execution (runs the query)
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) SELECT * FROM users WHERE email = 'foo@bar.com';
```

#### Index Analysis

```sql
-- Tables with most sequential scans (need indexes)
SELECT schemaname, relname, seq_scan, seq_tup_read, idx_scan, idx_tup_fetch,
       CASE WHEN seq_scan > 0 THEN seq_tup_read / seq_scan ELSE 0 END AS avg_seq_rows
FROM pg_stat_user_tables
WHERE seq_scan > 100 ORDER BY seq_tup_read DESC LIMIT 20;

-- Unused indexes (wasting space and slowing writes)
SELECT schemaname, relname, indexrelname, idx_scan,
       pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
WHERE idx_scan = 0 AND indexrelname NOT LIKE '%_pkey'
ORDER BY pg_relation_size(indexrelid) DESC;

-- Index hit ratio (should be >99%)
SELECT relname,
       CASE WHEN idx_scan + seq_scan > 0
            THEN round(100.0 * idx_scan / (idx_scan + seq_scan), 1)
            ELSE 0 END AS index_hit_pct
FROM pg_stat_user_tables WHERE idx_scan + seq_scan > 100
ORDER BY index_hit_pct ASC LIMIT 20;
```

#### Cache Hit Ratio

```sql
-- Should be >99%
SELECT sum(heap_blks_read) AS heap_read, sum(heap_blks_hit) AS heap_hit,
       round(sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read))::numeric * 100, 2) AS ratio
FROM pg_statio_user_tables;

-- Index cache hit ratio
SELECT sum(idx_blks_read) AS idx_read, sum(idx_blks_hit) AS idx_hit,
       round(sum(idx_blks_hit) / NULLIF(sum(idx_blks_hit) + sum(idx_blks_read), 0)::numeric * 100, 2) AS ratio
FROM pg_statio_user_indexes;
```

### MySQL Performance

#### Slow Queries

```sql
-- Enable slow query log
SET GLOBAL slow_query_log = 'ON';
SET GLOBAL long_query_time = 1;
SHOW VARIABLES LIKE 'slow_query_log_file';

-- Show slow query count
SHOW GLOBAL STATUS LIKE 'Slow_queries';
```

```bash
# Analyse slow query log
mysqldumpslow -s t /var/log/mysql/slow.log | head -30
```

#### EXPLAIN

```sql
EXPLAIN SELECT * FROM users WHERE email = 'foo@bar.com';
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'foo@bar.com';  -- MySQL 8.0.18+
```

#### Index Analysis

```sql
-- Show indexes for a table
SHOW INDEX FROM users;

-- Index usage stats (MySQL 8.0+ performance_schema)
SELECT object_schema, object_name, index_name, count_star, count_read, count_write
FROM performance_schema.table_io_waits_summary_by_index_usage
WHERE object_schema = 'myapp' ORDER BY count_star DESC;
```

### EXPLAIN Output Cheat Sheet

| Term (PostgreSQL) | Term (MySQL) | Meaning | Action |
|-------------------|-------------|---------|--------|
| Seq Scan | Full Table Scan | Reading entire table | Add an index |
| Index Scan | ref/range | Using an index | Good |
| Bitmap Heap Scan | — | Index scan + table fetch | Acceptable for medium selectivity |
| Nested Loop | nested_loop | Joining with loop | OK for small tables, bad for large |
| Hash Join | hash_join | Hash-based join | Good for large unsorted tables |
| Sort | filesort | Sorting results | Consider index on ORDER BY columns |

3. Present findings with specific index recommendations.

## Security Notes

- `EXPLAIN ANALYZE` actually executes the query. Don't run it on `DELETE` or `UPDATE` statements in production.
- Slow query logs may contain sensitive data (user emails, passwords in WHERE clauses). Restrict log access.
- Missing indexes on auth tables (users, sessions) can make login brute-force faster by not being a bottleneck — but also make legitimate queries slow. Index for correctness first.
- `pg_stat_statements` is one of the most valuable PostgreSQL extensions. Enable it in production.
