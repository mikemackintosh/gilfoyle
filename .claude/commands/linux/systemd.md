# Systemd Services and Timers

Manage systemd services, view logs with journalctl, create unit files, and work with timers.

## Arguments

$ARGUMENTS describes the operation:

Examples:
- `status <service>` — show service status and recent logs
- `logs <service>` — show logs for a service
- `failed` — list failed services
- `timers` — list active timers
- `list` — list all running services
- `create <name>` — guide for creating a new unit file
- (no args — overview of services and any failures)

## Workflow

1. Parse the operation from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Service overview

```bash
echo "=== Failed Services ==="
systemctl list-units --type=service --state=failed

echo ""
echo "=== Running Services ==="
systemctl list-units --type=service --state=running --no-pager

echo ""
echo "=== Enabled Services ==="
systemctl list-unit-files --type=service --state=enabled --no-pager
```

### Step 2 — Service details

```bash
# Status with recent logs
systemctl status <service>

# Full logs
journalctl -u <service> --no-pager -n 50

# Logs since last boot
journalctl -u <service> -b

# Logs in a time range
journalctl -u <service> --since "1 hour ago"

# Follow logs
journalctl -u <service> -f
```

### Step 3 — Timers

```bash
echo "=== Active Timers ==="
systemctl list-timers --all --no-pager
```

### Step 4 — Unit file template

When creating a new service, generate a unit file:

```ini
[Unit]
Description=My Application
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=appuser
Group=appgroup
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/bin/server
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/opt/myapp/data

[Install]
WantedBy=multi-user.target
```

```bash
# Install and enable
sudo cp myapp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now myapp
```

### Timer unit template

```ini
# /etc/systemd/system/mybackup.timer
[Unit]
Description=Run backup daily

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=3600

[Install]
WantedBy=timers.target
```

3. Present results and flag:
   - Failed services
   - Services configured to restart but crashing in a loop
   - Services running as root that don't need to

## Security Notes

- Use `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, and `PrivateTmp=yes` in unit files to sandbox services.
- Services should run as dedicated non-root users when possible.
- `journalctl --disk-usage` shows how much space the journal uses. Configure `SystemMaxUse` in `/etc/systemd/journald.conf` to cap it.
- Systemd timers are preferred over cron for new setups — they support randomised delays, dependencies, and logging via journal.
