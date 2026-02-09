# Database User and Privilege Management

Manage database users, roles, and privileges for PostgreSQL and MySQL — creating users, granting access, auditing permissions, and enforcing least privilege.

## Arguments

$ARGUMENTS describes the operation:

Examples:
- `list` — list all database users and their privileges
- `create <username> <database>` — create a user with access to a database
- `readonly <username> <database>` — create a read-only user
- `audit` — audit current user privileges for security issues
- `revoke <username>` — revoke all privileges from a user
- (no args — user and privilege audit)

## Workflow

1. Parse the operation from `$ARGUMENTS`.
2. Detect database engine (PostgreSQL vs MySQL).
3. Show the user the exact commands before executing.

### PostgreSQL User Management

```sql
-- List all roles
\du
SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolcanlogin, rolreplication
FROM pg_roles WHERE rolname NOT LIKE 'pg_%' ORDER BY rolname;

-- Create a standard user
CREATE USER appuser WITH PASSWORD 'securepassword';
GRANT CONNECT ON DATABASE myapp TO appuser;
GRANT USAGE ON SCHEMA public TO appuser;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO appuser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO appuser;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO appuser;

-- Create a read-only user
CREATE USER readonly WITH PASSWORD 'securepassword';
GRANT CONNECT ON DATABASE myapp TO readonly;
GRANT USAGE ON SCHEMA public TO readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly;

-- Show grants for a user
SELECT grantor, grantee, table_schema, table_name, privilege_type
FROM information_schema.role_table_grants WHERE grantee = 'appuser';

-- Revoke all privileges
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM appuser;
REVOKE ALL PRIVILEGES ON DATABASE myapp FROM appuser;
REVOKE USAGE ON SCHEMA public FROM appuser;

-- Change password
ALTER USER appuser WITH PASSWORD 'newpassword';

-- Lock / disable a user
ALTER USER appuser NOLOGIN;

-- Drop a user
-- REASSIGN OWNED BY appuser TO postgres;
-- DROP OWNED BY appuser;
-- DROP USER appuser;
```

### MySQL User Management

```sql
-- List all users
SELECT user, host, authentication_string, account_locked, password_expired
FROM mysql.user ORDER BY user;

-- Show grants for all users
SELECT CONCAT('SHOW GRANTS FOR ''', user, '''@''', host, ''';') FROM mysql.user;

-- Create a standard user
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'securepassword';
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'appuser'@'localhost';
FLUSH PRIVILEGES;

-- Create a read-only user
CREATE USER 'readonly'@'localhost' IDENTIFIED BY 'securepassword';
GRANT SELECT ON myapp.* TO 'readonly'@'localhost';
FLUSH PRIVILEGES;

-- Create a user for remote access (specific IP)
CREATE USER 'appuser'@'10.0.1.%' IDENTIFIED BY 'securepassword';
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'appuser'@'10.0.1.%';

-- Show grants
SHOW GRANTS FOR 'appuser'@'localhost';

-- Revoke all privileges
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'appuser'@'localhost';
FLUSH PRIVILEGES;

-- Change password
ALTER USER 'appuser'@'localhost' IDENTIFIED BY 'newpassword';

-- Lock / unlock account
ALTER USER 'appuser'@'localhost' ACCOUNT LOCK;
ALTER USER 'appuser'@'localhost' ACCOUNT UNLOCK;

-- Drop a user
-- DROP USER 'appuser'@'localhost';
```

### Privilege Audit

```sql
-- PostgreSQL: Find superusers
SELECT rolname FROM pg_roles WHERE rolsuper = true;

-- PostgreSQL: Find users with CREATE DB
SELECT rolname FROM pg_roles WHERE rolcreatedb = true;

-- MySQL: Find users with GRANT OPTION
SELECT user, host FROM mysql.user WHERE Grant_priv = 'Y';

-- MySQL: Find users with wildcard host
SELECT user, host FROM mysql.user WHERE host = '%';

-- MySQL: Find users with all-database access
SELECT grantee, privilege_type FROM information_schema.user_privileges
WHERE privilege_type = 'ALL PRIVILEGES';
```

3. Present findings with security recommendations.

### Privilege Reference

| Privilege | PostgreSQL | MySQL | Use Case |
|-----------|-----------|-------|----------|
| Read only | `SELECT` | `SELECT` | Reporting, analytics |
| Read/write | `SELECT,INSERT,UPDATE,DELETE` | `SELECT,INSERT,UPDATE,DELETE` | Application user |
| Schema management | `CREATE` | `CREATE,ALTER,DROP` | Migration runner |
| Full admin | `SUPERUSER` | `ALL PRIVILEGES WITH GRANT OPTION` | DBA only |

## Security Notes

- **Principle of least privilege.** Application users should never be superusers or have `DROP`/`CREATE` permissions.
- **Separate users per application.** Don't share database credentials between services.
- MySQL `'user'@'%'` accepts connections from any host. Restrict to specific IPs or `localhost`.
- PostgreSQL `pg_hba.conf` controls network access independently of `GRANT` — both must be correct.
- **Never use the root/postgres superuser for application connections.** Create dedicated users.
- Rotate database passwords regularly. Use environment variables or secret managers, not hardcoded strings.
- `ALTER DEFAULT PRIVILEGES` in PostgreSQL is essential — without it, new tables created later won't inherit grants.
