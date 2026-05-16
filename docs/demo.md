# Demo Guide

Shows pf capturing and forwarding live traffic, analyzer consuming a
filter's stats stream, and the control plane API - all running on a
veth pair in a network namespace.

## Prerequisites

```bash
# build
go build -o pf ./cmd/pf
go build -o analyzer ./cmd/analyzer
go build -o udpflood ./cmd/udpflood

# veth pair + netns
sudo ./scripts/netns-setup.sh
```

## Quick run (3 separate terminals)

**Terminal 1 - pf:**
```bash
sudo ./pf -iface veth0 -promisc -queues <n> # n - num of cores
```

**Terminal 2 - analyzer** (waits for pf, registers a UDP:443 filter, prints stats):
```bash
./analyzer -pf http://localhost:9100 -filter "udp::443" -interval 1s
```

**Terminal 3 - send traffic + poll stats:**
```bash
# flood traffic into the veth from inside pftest netns
sudo ip netns exec pftest ./udpflood \
  -iface veth1 -dst-ip 192.168.99.1 -dst-port 443 \
  -parallel 4 -duration 10s

# watch pf stats
watch -n 1 'curl -s http://localhost:9100/v1/stats | jq .'

# add a filter manually
curl -X POST http://localhost:9100/v1/filters \
  -H 'Content-Type: application/json' \
  -d '{"filter":{"protocol":"udp","dst_port":443}}'

# list filters
curl -s http://localhost:9100/v1/filters | jq .

# remove a filter (replace 1 with actual id)
curl -X DELETE http://localhost:9100/v1/filters/1
```

## Automated tmux demo (for asciinema)

```bash
# record
asciinema rec demo.cast -t "highload-monitor demo"

# in the recording, run:
sudo ./scripts/demo.sh

# stop with Ctrl-C, then Ctrl-D to end asciinema
```

`scripts/demo.sh` launches pf, starts the analyzer, sends 10s of
traffic, and polls stats -all in one terminal with sleep delays for
readability.

## What to show at the presentation

1. `curl /v1/health` -> `{"status":"ok"}`
2. Start udpflood -> watch `rx_packets` climb in `/v1/stats`, `rx_drops` stays 0
3. `POST /v1/filters` -> analyzer JSON shows `packets`, `unique_src_ips`, `entropy_bits` updating
4. `DELETE /v1/filters/{id}` -> analyzer stops updating that filter
5. Ctrl-C pf -> final log line shows zero `kernel_drops`

## Troubleshooting

| Problem | Fix |
|---|---|
| `bind: permission denied` | run pf with `sudo` |
| `interface not found: veth0` | run `sudo ./scripts/netns-setup.sh` |
| `udpflood: no such network interface: veth1` | veth1 is in pftest netns - prefix with `sudo ip netns exec pftest` |
| analyzer: `connection refused` | pf not running yet, or wrong `-pf` URL |
| `rx_drops > 0` | reduce `-parallel` on udpflood, or increase `-queues` on pf |
