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

Data plane works end-to-end. Open items:
- Unit tests for `FilterEngine` (parseFrame, compileFilter)
- Kernel cBPF pre-filter (`internal/bpfc`) — biggest perf lever still open
- `PACKET_FANOUT` for multi-RX-queue scaling
- `sync.Pool` for the dump frame copies
- `docs/benchmarks.md` with measured pps

See [docs/architecture.md](docs/architecture.md) for the full design and improvement paths.

## Layout

```
cmd/pf/             daemon entry point + HTTP/dump servers, forwarder, filter engine
internal/afpacket/  TPACKET_V3 RX ring + TPACKET_V2 TX ring
internal/proto/     wire DTOs + swappable Codec/FrameWriter interfaces
internal/bpfc/      (stub) cBPF compiler for kernel pre-filter
internal/flow/      (stub) 5-tuple key
internal/pktpool/   (stub) sync.Pool for frame buffers
internal/stats/     (stub) HLL, entropy — analyzer-side, may move
scripts/            netns-setup.sh — veth pair for local testing
docs/               architecture + benchmarks
```

## Requirements

- Linux (uses `AF_PACKET`)
- Go 1.25+
- Root or `CAP_NET_RAW`/`CAP_NET_ADMIN` to open packet sockets

## Build

```sh
go build ./cmd/pf
```

## Quick test on a veth pair

```sh
# 1. set up veth0 (192.168.99.1) ↔ veth1 (192.168.99.2)
sudo ./scripts/netns-setup.sh

# 2. start PF on veth0
sudo ./pf -iface veth0 -promisc

# 3. (other terminal) check health, add a filter
curl http://localhost:9100/v1/health
curl -X POST http://localhost:9100/v1/filters \
  -H 'Content-Type: application/json' \
  -d '{"filter":{"src_ip":"192.168.99.0/24","dst_port":443,"protocol":"tcp"}}'

# 4. (other terminal) generate traffic from veth1
ping -c 10 -I veth1 192.168.99.1

# 5. (other terminal) consume the dump stream
nc 127.0.0.1 9101 | hexdump -C

# 6. watch stats — rx_drops must stay 0
watch -n1 'curl -s http://localhost:9100/v1/stats | jq'
```

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
