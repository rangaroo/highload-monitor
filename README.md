# highload-monitor

Two cooperating Go services for high-rate Linux packet capture and analysis.

- **`pf`** (Packet Forwarder) — captures from a NIC via `AF_PACKET` TPACKET_V3,
  forwards frames back out, and taps matching packets into a dump stream
  consumed by the analyzer. Designed for zero packet loss under load.
- **`analyzer`** — drives the forwarder over an HTTP control API, receives the
  dump stream over a raw TCP connection, and computes per-filter traffic
  statistics (packet counts, unique peers via HyperLogLog, Shannon entropy).

The two services communicate via:

- **HTTP/REST + JSON** for control (`:9100`)
- **Raw TCP, length-prefixed binary frames** for the dump data plane (`:9101`)

No gRPC, no protobuf — stdlib + `golang.org/x/sys/unix` only.

## Status

Work in progress. See `docs/architecture.md` for the design and
`docs/benchmarks.md` for measured throughput.

## Requirements

- Linux (uses `AF_PACKET`)
- Go 1.25+
- Root or `CAP_NET_RAW` to open packet sockets

## Layout

```
cmd/pf/         packet forwarder daemon
cmd/analyzer/   analyzer (control client + dump receiver + stats)
internal/       implementation packages (afpacket, bpfc, flow, ...)
configs/        sample YAML configs
scripts/        netns test setup, bench helpers
docs/           architecture & benchmarks
```

## Build

```sh
go build ./cmd/pf
go build ./cmd/analyzer
```

## Run (dev)

Set up a veth pair and run against it; see `scripts/netns-setup.sh`.
