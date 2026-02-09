# Performance Monitoring and Tuning

Monitor Linux system performance — CPU, memory, disk I/O, network, and kernel tuning with sysctl.

## Arguments

$ARGUMENTS is optional:
- `--cpu` — focus on CPU usage and load
- `--memory` — focus on memory and swap
- `--disk` — focus on disk I/O
- `--network` — focus on network throughput
- `--sysctl` — show key kernel tunable parameters
- (no args — comprehensive performance overview)

Examples:
- (no args — full overview)
- `--memory`
- `--disk`
- `--sysctl`

## Workflow

1. Parse any arguments from `$ARGUMENTS`.
2. Show the user the exact commands before executing.

### Step 1 — System overview

```bash
echo "=== Uptime and Load ==="
uptime

echo ""
echo "=== CPU Info ==="
nproc
lscpu | grep -E 'Model name|CPU\(s\)|Thread|Core|Socket'

echo ""
echo "=== Memory ==="
free -h

echo ""
echo "=== Swap ==="
swapon --show
```

### Step 2 — CPU performance

```bash
echo "=== CPU Usage (5 samples, 1s interval) ==="
mpstat 1 5 2>/dev/null || vmstat 1 5

echo ""
echo "=== Top CPU Processes ==="
ps aux --sort=-%cpu | head -11
```

### Step 3 — Memory performance

```bash
echo "=== Memory Details ==="
free -h

echo ""
echo "=== Top Memory Processes ==="
ps aux --sort=-%mem | head -11

echo ""
echo "=== OOM Killer Activity ==="
dmesg | grep -i "oom\|out of memory" | tail -10
```

### Step 4 — Disk I/O

```bash
echo "=== Disk I/O (5 samples) ==="
iostat -xz 1 5 2>/dev/null || echo "(iostat not available — install sysstat)"

echo ""
echo "=== Filesystem Usage ==="
df -hT | grep -v tmpfs
```

### Step 5 — Network throughput

```bash
echo "=== Network Interface Stats ==="
cat /proc/net/dev | column -t

echo ""
echo "=== Socket Statistics ==="
ss -s
```

### Step 6 — Key sysctl parameters

```bash
echo "=== Key Kernel Parameters ==="
sysctl vm.swappiness
sysctl vm.dirty_ratio
sysctl vm.dirty_background_ratio
sysctl net.core.somaxconn
sysctl net.ipv4.tcp_max_syn_backlog
sysctl fs.file-max
sysctl fs.file-nr
```

3. Present findings and recommendations.

### Common Sysctl Tuning

| Parameter | Default | Tuned | Purpose |
|-----------|---------|-------|---------|
| `vm.swappiness` | 60 | 10 | Reduce swap usage (keep data in RAM) |
| `vm.dirty_ratio` | 20 | 10 | Limit dirty page cache before forced writeback |
| `net.core.somaxconn` | 128 | 4096 | Increase connection backlog for busy servers |
| `net.ipv4.tcp_max_syn_backlog` | 128 | 4096 | Handle SYN flood better |
| `fs.file-max` | varies | 2097152 | Maximum open file descriptors system-wide |
| `net.ipv4.tcp_tw_reuse` | 0 | 1 | Reuse TIME_WAIT sockets for new connections |

## Security Notes

- High CPU `iowait` indicates disk bottleneck, not CPU bottleneck — look at disk I/O, not CPU scaling.
- OOM killer messages in `dmesg` indicate the system ran out of memory. Identify the memory-hungry process.
- `vm.swappiness=0` on production servers avoids performance degradation from swapping, but risks OOM.
- Sysctl changes via `sysctl -w` are temporary. Persist in `/etc/sysctl.d/*.conf` and apply with `sysctl --system`.
