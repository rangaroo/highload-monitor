# highload-monitor

This repo has the **Packet Forwarder (PF)**. A companion **Analyzer** runs as a separate process and consumes the filtered dump stream over TCP.

## What PF does

- Captures every frame from a NIC via `AF_PACKET` TPACKET_V3 (block-based mmap RX ring).
- Forwards every frame back out the same interface via a TPACKET_V2 TX ring.
- Matches frames against a runtime-configurable set of 5-tuple filters.
- Streams matched frames to an analyzer over a binary TCP protocol.
- Exposes filter CRUD + statistics over an HTTP/JSON control plane.

**Success criterion:** `rx_drops == 0` under load. The forward path never blocks on the dump path - if the analyzer is slow, dump frames are counted and dropped instead.

## Status

**Data plane:** capture, forward, filter, dump — all working end-to-end.

**Analyzer:** separate binary consumes the dump stream, maintains per-filter stats (packet count, bytes, unique src/dst IPs via HLL, src IP Shannon entropy).

**Kernel pre-filter:** cBPF compiler + SO_ATTACH_FILTER integration done. Filters are recompiled + reattached on every Add/Remove.

**Open items:**
- `PACKET_FANOUT` for multi-RX-queue scaling
- `sync.Pool` for dump frame copies (perf opt)
- benchmarks.md with measured pps on real hardware

See [docs/architecture.md](docs/architecture.md) for the full design and improvement paths.

## Layout

**Packet Forwarder (pf):**
```
cmd/pf/             daemon: socket + rings, HTTP control, dump server, forwarder loop
internal/afpacket/  TPACKET_V3 RX ring (block-based), TPACKET_V2 TX ring
internal/bpfc/      cBPF compiler: FilterSpec → kernel BPF program
internal/proto/     wire DTOs (FilterSpec, DumpFrame) + Codec/FrameWriter interfaces
scripts/            netns-setup.sh (veth pair), bench-pktgen.sh (pktgen load)
docs/               architecture.md, benchmarks.md
```

**Analyzer (separate binary):**
```
cmd/analyzer/       TCP dump receiver + per-filter stats aggregator
internal/control/   HTTP client for pf control plane
internal/dump/      TCP framed reader (auto-reconnect on disconnect)
internal/stats/     HLL (axiomhq/hyperloglog), Shannon entropy, counters
```

## Requirements

- Linux (uses `AF_PACKET`)
- Go 1.25+
- Root or `CAP_NET_RAW`/`CAP_NET_ADMIN` to open packet sockets

## Build

```sh
go build ./cmd/pf       # Packet Forwarder
go build ./cmd/analyzer # Analyzer
```

## Quick test on a veth pair

**Terminal 1: Set up and start PF**

```sh
sudo ./scripts/netns-setup.sh
sudo ./pf -iface veth0 -promisc
```

**Terminal 2: Run Analyzer**

```sh
./analyzer -pf http://localhost:9100 -filter "tcp::"
```

**Terminal 3: Control plane / traffic generation**

```sh
# health check
curl http://localhost:9100/v1/health

# add a TCP filter (src 192.168.99.0/24, dst port 443)
curl -X POST http://localhost:9100/v1/filters \
  -H 'Content-Type: application/json' \
  -d '{"filter":{"src_ip":"192.168.99.0/24","dst_port":443,"protocol":"tcp"}}'

# generate TCP traffic from veth1 (any port to 443)
nc -vz -w 1 192.168.99.1 443 < /dev/null || true

# watch live stats — rx_drops must stay 0
watch -n1 'curl -s http://localhost:9100/v1/stats | jq'
```

**Analyzer output (Terminal 2):** JSON per second showing per-filter packet count, bytes, unique src/dst IPs, src IP entropy.

## Flags

```
pf -iface <name> [-promisc] [-http :9100] [-dump :9101]
```

| Flag       | Default  | Purpose                                              |
|------------|----------|------------------------------------------------------|
| `-iface`   | (req)    | Interface to capture on                              |
| `-promisc` | false    | Enable promiscuous mode                              |
| `-http`    | `:9100`  | Control plane HTTP listen address                    |
| `-dump`    | `:9101`  | Data plane TCP listen address                        |

## HTTP control plane

| Method | Path                | Purpose                                  |
|--------|---------------------|------------------------------------------|
| GET    | `/v1/health`        | liveness                                 |
| GET    | `/v1/stats`         | rx/tx packets, drops, freeze count       |
| GET    | `/v1/filters`       | list filters                             |
| POST   | `/v1/filters`       | add filter (returns `{id}`)              |
| DELETE | `/v1/filters/{id}`  | remove filter                            |
| GET    | `/v1/dump-endpoint` | discover the TCP dump host:port          |

Filter spec:

```json
{
  "filter": {
    "src_ip":   "10.0.0.0/8",   
    "dst_ip":   "192.168.1.1",  
    "src_port": 0,              
    "dst_port": 443,            
    "protocol": "tcp"           
  }
}
```

All fields optional. Omitted fields = wildcard. CIDR or single-IP both accepted.

## Dump frame format (TCP `:9101`, little-endian)

```
 magic(u16) | ver(u8) | filter_id(u32) | ts_ns(u64) | wire_len(u32) | payload_len(u16) | payload[...]
```

Length-prefixed, no framing markers between frames. Reader does `io.ReadFull` of the 19-byte header then `payload_len` bytes.

## Integration with `pcap-traffic-generator`
