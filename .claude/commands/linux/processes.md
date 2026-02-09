# Process Management

Monitor and manage Linux processes — listing, resource usage, killing, backgrounding, and resource limits.

## Arguments

$ARGUMENTS is optional:
- `--top` — show top CPU/memory consumers
- `--tree` — show process tree
- `--user <username>` — show processes for a specific user
- `--kill <pid|name>` — kill a process
- `--zombie` — find zombie processes
- `<pid>` — details for a specific process
- (no args — process overview with top consumers)

Examples:
- (no args — process overview)
- `--top`
- `--tree`
- `--zombie`
- `--kill 12345`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — Process overview

```bash
echo "=== Process Count ==="
echo "Total: $(ps aux | wc -l)"
echo "Running: $(ps aux | awk '$8 ~ /R/ {c++} END {print c+0}')"
echo "Zombie: $(ps aux | awk '$8 ~ /Z/ {c++} END {print c+0}')"

echo ""
echo "=== Load Average ==="
uptime

echo ""
echo "=== Top CPU Consumers ==="
ps aux --sort=-%cpu | head -11

echo ""
echo "=== Top Memory Consumers ==="
ps aux --sort=-%mem | head -11
```

### Step 2 — Process tree

```bash
pstree -p -u | head -50
```

### Step 3 — Zombie processes

```bash
echo "=== Zombie Processes ==="
ps aux | awk '$8 == "Z" {print}' | head -20

# Find the parent of zombies
ps aux | awk '$8 == "Z" {print $2}' | xargs -I{} ps -o pid,ppid,cmd -p {} 2>/dev/null
```

### Step 4 — Process details

```bash
# Full details for a PID
ps -p <pid> -o pid,ppid,user,%cpu,%mem,vsz,rss,stat,start,time,cmd

# Open files
ls -la /proc/<pid>/fd/ 2>/dev/null | head -20

# Network connections
ss -tnp | grep "pid=<pid>"

# Environment variables
cat /proc/<pid>/environ 2>/dev/null | tr '\0' '\n'

# Resource limits
cat /proc/<pid>/limits
```

### Step 5 — Kill operations

```bash
# Graceful (SIGTERM)
kill <pid>

# Force (SIGKILL)
kill -9 <pid>

# By name
pkill <name>
killall <name>

# By pattern
pkill -f "pattern"
```

3. Present findings and flag:
   - Processes consuming >80% CPU for extended periods
   - Memory-heavy processes that may cause OOM
   - Zombie processes (indicates parent not reaping children)

## Security Notes

- Processes running as root that don't need to are a privilege escalation risk.
- Check `/proc/<pid>/cmdline` for processes with credentials in command-line arguments (visible to all users via `ps`).
- `kill -9` does not allow graceful shutdown — the process can't clean up temp files, release locks, or flush buffers. Use `kill` (SIGTERM) first.
- The OOM killer (`/proc/<pid>/oom_score`) shows which processes will be killed first under memory pressure.
