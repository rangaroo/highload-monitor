# Live Demo Guide

## Setup

Build binaries:
```bash
go build -o pf ./cmd/pf
go build -o analyzer ./cmd/analyzer
```

Set up veth pair:
```bash
sudo ./scripts/netns-setup.sh
```

## Run Demo (3-pane tmux)

Open tmux with 3 panes:
```bash
tmux new-session -s demo -x 120 -y 30
tmux split-window -h
tmux split-window -h
```

### Pane 1 (left): Packet Forwarder

```bash
sudo ./pf -iface veth0 -promisc
```

Expect output:
```
pf started on veth0 (http=:9100 dump=:9101)
```

### Pane 2 (middle): Analyzer

```bash
./analyzer -pf http://localhost:9100 -filter "tcp::" -interval 1s
```

Expect: JSON lines per second showing filter stats (packet count, entropy, cardinality).

### Pane 3 (right): Control + Traffic

Health check:
```bash
curl http://localhost:9100/v1/health
```

Watch stats in a loop:
```bash
watch -n 1 'curl -s http://localhost:9100/v1/stats | jq'
```

In another terminal within pane 3, send traffic:
```bash
# Method 1: nc connect attempt (generates TCP SYN)
nc -w 1 192.168.99.1 443 < /dev/null

# Method 2: persistent iperf-like traffic (if iperf installed)
iperf -c 192.168.99.1 -p 443 -t 5

# Method 3: simple ping (ICMP, not in TCP filter, but pf forwards it)
ping -c 5 192.168.99.1
```

Add a filter dynamically:
```bash
curl -X POST http://localhost:9100/v1/filters \
  -H 'Content-Type: application/json' \
  -d '{"filter":{"protocol":"tcp","dst_port":443}}'
```

List filters:
```bash
curl http://localhost:9100/v1/filters | jq
```

## Expected Behavior

1. **Pane 1 (pf):** logs capture rate, TX rate. On filter Add/Remove, logs cBPF recompile.
2. **Pane 2 (analyzer):** JSON with `filter_id`, `packets`, `bytes`, `unique_src_ips`, `src_entropy_bits`.
3. **Pane 3 (stats):** `rx_packets` and `rx_drops` climb; `rx_drops` must stay **0** throughout.

## Recording (asciinema)

```bash
asciinema rec demo.cast -t "Packet Forwarder Demo" -w 2
```

Then run the demo steps above. Stop recording with Ctrl-D.

Play back:
```bash
asciinema play demo.cast
```

Upload (optional):
```bash
asciinema upload demo.cast
```

## Troubleshooting

**pf won't bind to veth0:**
- Check veth pair exists: `ip link show veth0`
- Ensure running with sufficient privileges (root or CAP_NET_RAW)

**Analyzer connection refused:**
- Check pf is listening on :9100: `curl http://localhost:9100/v1/health`
- Check dump TCP server: `curl http://localhost:9100/v1/dump-endpoint`

**No packets captured:**
- Ensure traffic is actually flowing: `tcpdump -i veth0 -c 5`
- Check veth1 is up and reachable: `ip link show veth1`

**rx_drops > 0:**
- Traffic rate exceeds single-core capacity (expected at high pps).
- Try reducing traffic rate or enabling PACKET_FANOUT (future work).
