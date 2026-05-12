# highload-monitor — Architecture

**Repo purpose:** Capture network traffic from a NIC with zero packet loss, forward every frame back out, and stream a filtered subset to a separate analyzer process over TCP. Built for Task 2 of the internship assignment ("сети / highload").

The repo ships one daemon: **Packet Forwarder (PF)**. The companion **Analyzer** lives in a sibling project owned by the pair partner — this document describes only the PF side and the wire contract the analyzer must satisfy.

---

## 1. High-level data flow

```
                        ┌──────────────────────────────┐
                        │      Analyzer (separate)     │
                        │  ┌────────────────────────┐  │
                        │  │ HTTP control client    ├──┼──── HTTP/REST + JSON ────┐
                        │  └────────────────────────┘  │                          │
                        │  ┌────────────────────────┐  │                          │
                        │  │ TCP dump receiver      ◀──┼──── binary frame stream ─┤
                        │  └────────────────────────┘  │                          │
                        │  stats engine (HLL,          │                          │
                        │  entropy, top-N peers)       │                          │
                        └──────────────────────────────┘                          │
                                                                                  │
   NIC                                ┌──────────────────────────────────────────┴───┐
   (any iface, e.g. eth0/veth0)       │                Packet Forwarder              │
                                      │                                              │
   incoming frames ────► AF_PACKET ───►   RX ring (TPACKET_V3, block-based mmap)     │
                         RX socket    │                  │                           │
                                      │                  ▼                           │
                                      │            ┌──────────┐                      │
                                      │            │ Forwarder│  hot loop            │
                                      │            │  .Run()  │                      │
                                      │            └────┬─────┘                      │
                                      │   tap (DumpTap) │      forward (full rate)   │
                                      │            ┌────┴─────┐                      │
                                      │            │          ▼                      │
                                      │  ┌─────────▼────────┐  AF_PACKET TX socket   │
                                      │  │  FilterEngine    │  TX ring (TPACKET_V2) ─┼──► NIC
                                      │  │  5-tuple match   │                        │
                                      │  └────────┬─────────┘                        │
                                      │   matched │ frame (channel, cap=8192)        │
                                      │  ┌────────▼─────────┐                        │
                                      │  │  DumpServer      │  TCP listener :9101    │
                                      │  │  bufio batching  │                        │
                                      │  └──────────────────┘                        │
                                      │                                              │
                                      │  HTTP control server :9100                   │
                                      │  /v1/{health,stats,filters,dump-endpoint}    │
                                      └──────────────────────────────────────────────┘
```

Three independent goroutines run inside the PF process:

1. **Forwarder hot loop** — pulls blocks off the RX ring, taps every frame for filter matching, copies it onto the TX ring. Pure data-plane work. Survives backpressure from any other component because the tap is non-blocking.
2. **Dump server** — owns the TCP listener on :9101. Accepts one analyzer connection at a time, reads from the filter engine's matched-frame channel, batches with `bufio.Writer`, flushes after draining.
3. **HTTP control server** — owns the listener on :9100. Serves filter CRUD, stats, and dump endpoint discovery. Touches the shared `FilterEngine` via its mutex-protected API.

---

## 2. Why AF_PACKET, why not gopacket

We bind directly to a raw `AF_PACKET` socket using `golang.org/x/sys/unix` and `mmap` the ring into the Go process address space. The kernel writes incoming frames into that ring; userspace polls block headers.

| Decision | Reason |
|----------|--------|
| AF_PACKET over `pcap`/`libpcap` | Pure Go, no CGo. Lower per-packet overhead. |
| TPACKET_V3 for RX | Block-based polling. One `poll(2)` returns *many* packets at once instead of one. Critical for zero-loss at high rates. |
| TPACKET_V2 for TX | V3 is RX-only in the kernel. V2 frame-based TX ring is the standard fast path. |
| Not using `gopacket` | gopacket only supports TPACKET_V1/V2 RX; it also allocates per packet via the layers API. We need V3 + zero alloc. |

**Ring geometry** (defaults, [internal/afpacket/types.go](../internal/afpacket/types.go)):
- RX: 1 MiB per block × 64 blocks = **64 MiB ring** per socket
- TX: 2 KiB per frame × 256 frames = **512 KiB ring**
- RX block timeout: 64 ms (kernel retires partially-filled blocks after this)

`Stats.Drops > 0` is the hard failure signal — it means the RX ring overflowed and the kernel dropped frames. This is what we measure against.

---

## 3. Packages

### `internal/afpacket`
Raw socket lifecycle and ring management.

| File | Responsibility |
|------|----------------|
| [types.go](../internal/afpacket/types.go) | Constants (TPACKET_V2=1, V3=2, status bits), `Config`/`TXConfig`, `Stats`, `BlockHeader`/`PacketHeader`/`TXFrameHeader` mirrors of kernel structs |
| [socket.go](../internal/afpacket/socket.go) | `Open(cfg)` — RX socket, PACKET_VERSION=V3, PACKET_RX_RING, mmap, bind, optional promisc + fanout. `Stats()` via raw `getsockopt`. |
| [read.go](../internal/afpacket/read.go) | `PollBlock(timeoutMs)` → `BlockCursor`. `BlockCursor.Next()` walks the `tpacket3_hdr` linked list via `NextOffset`. `ReturnBlock()` hands the block back to the kernel. |
| [tx.go](../internal/afpacket/tx.go) | `OpenTX(cfg)` — TX socket with TPACKET_V2 ring. `Send(frame)` copies to the next slot, marks `TP_STATUS_SEND_REQUEST`, kicks the kernel via `sendmsg(MSG_DONTWAIT)`. |

### `internal/proto`
The wire contract between PF and Analyzer. **Designed as swappable interfaces** so the JSON/binary encoding can be replaced (e.g. protobuf) without touching transport or business logic.

| File | Responsibility |
|------|----------------|
| [codec.go](../internal/proto/codec.go) | `Codec` interface: `Marshal/Unmarshal/MediaType`. `NewJSONCodec()` is the default; a protobuf codec would slot in here. |
| [control.go](../internal/proto/control.go) | HTTP path constants (`/v1/health`, etc.) and DTO structs for every endpoint. |
| [filter.go](../internal/proto/filter.go) | `FilterSpec` — declarative 5-tuple match (src_ip CIDR, dst_ip CIDR, src_port, dst_port, protocol). |
| [frame.go](../internal/proto/frame.go) | `DumpFrame` payload + `FrameWriter`/`FrameReader` interfaces. `binaryFrameRW` implements a 19-byte header followed by the raw frame. |

**Dump frame layout** (binary, little-endian):

```
 0       2      3            7           15          19          variable
 ┌───────┬──────┬────────────┬───────────┬───────────┬───────────────────┐
 │ magic │ ver  │ filter_id  │ ts_ns     │ wire_len  │ payload (raw frame)│
 │ u16   │ u8   │ u32        │ u64       │ u32 + u16 │                   │
 └───────┴──────┴────────────┴───────────┴───────────┴───────────────────┘
```

### `cmd/pf`
Wire-up code. Everything in `package main`.

| File | Responsibility |
|------|----------------|
| [main.go](../cmd/pf/main.go) | Flag parsing, opens RX+TX rings, constructs FilterEngine → Forwarder → DumpServer → HTTP Server. Goroutine fan-out + signal handling. |
| [forward.go](../cmd/pf/forward.go) | `Forwarder` with `DumpTap` interface. `Run(ctx)` is the hot loop: PollBlock → walk → tap → TX. Atomic counters for rx/tx/tap. |
| [filter_engine.go](../cmd/pf/filter_engine.go) | `FilterEngine`. Pre-compiles each `FilterSpec` to `compiledFilter` (parsed `*net.IPNet`, protocol byte). `parseFrame` extracts the 5-tuple from a raw frame with zero allocations. Match → copy → non-blocking send onto `chan proto.DumpFrame` (cap 8192). |
| [http_server.go](../cmd/pf/http_server.go) | All HTTP handlers. Uses the injected `Codec` for body serialization. |
| [dump_server.go](../cmd/pf/dump_server.go) | TCP accept loop (one connection at a time). `stream()` reads frames, batches with a 256 KiB `bufio.Writer`, flushes after each drain cycle. |

---

## 4. Control plane (HTTP/JSON on :9100)

| Method | Path                  | Body                | Response                       |
|--------|-----------------------|---------------------|--------------------------------|
| GET    | `/v1/health`          | —                   | `{"status":"ok"}`              |
| GET    | `/v1/stats`           | —                   | `{rx_packets, rx_drops, tx_packets, freeze_q_count}` |
| GET    | `/v1/filters`         | —                   | `{"filters":[{id,spec}, ...]}` |
| POST   | `/v1/filters`         | `{"filter":{...}}`  | `201` + `{"id":"<n>"}`         |
| DELETE | `/v1/filters/{id}`    | —                   | `204`                          |
| GET    | `/v1/dump-endpoint`   | —                   | `{"addr":"host:port"}`         |

The analyzer flow is:
1. `GET /v1/health` — sanity check
2. `GET /v1/dump-endpoint` — discover the TCP port
3. Open TCP connection, begin reading `DumpFrame`s
4. `POST /v1/filters` — register interest in specific 5-tuples
5. Poll `GET /v1/stats` periodically for drop visibility

---

## 5. Data plane (binary TCP stream on :9101)

One persistent TCP connection per analyzer. Only one analyzer at a time — the dump server accepts a single connection, streams until it dies, then loops back to `Accept`.

**Backpressure rule:** if the analyzer reads slowly, the matched-frame channel (cap 8192) fills up. `FilterEngine.Tap()` does a non-blocking send; on a full channel it increments a drop counter and moves on. **The forward path never blocks on the dump path.** Forwarding correctness > analyzer completeness.

**Batching:** `DumpServer.stream()` uses a 256 KiB `bufio.Writer`. The inner loop pulls one frame off the channel, writes it, then drains *every* additional frame currently available (non-blocking `select` with `default`), writes them all, and does a single `Flush()`. At high match rates this trades ~10–100× fewer syscalls for a small latency penalty.

---

## 6. State of the repo (as of 2026-05-11)

### Done
- [x] AF_PACKET TPACKET_V3 RX ring open/poll/iterate/return
- [x] AF_PACKET TPACKET_V2 TX ring send + slot waiting via `poll(2)`
- [x] Forwarder hot loop with `DumpTap` interface (decouples filter from forward)
- [x] FilterEngine: 5-tuple compile (CIDR + protocol), zero-alloc frame parsing, non-blocking tap, drop counter
- [x] HTTP control server with full CRUD, swappable `Codec`
- [x] TCP dump server with bufio batching, single-connection accept loop
- [x] Wire-up in `cmd/pf/main.go`, graceful shutdown
- [x] `scripts/netns-setup.sh` veth pair for local testing

### Left (priority order)
1. **Unit tests** for `FilterEngine.parseFrame` (synthetic frames → expected 5-tuple), `compileFilter` (CIDR edge cases), and the binary frame writer/reader round-trip.
2. **`internal/bpfc`** — compile the union of active filters into cBPF, attach via `SO_ATTACH_FILTER` *to the RX socket*. This is the single biggest perf lever still on the table: it drops unwanted packets in the kernel before they cross the ring.
3. **`PACKET_FANOUT` per NIC queue** — currently single-socket. Multi-socket fanout with `PACKET_FANOUT_HASH` lets us scale to >1 core for capture. Needs `runtime.LockOSThread` + `unix.SchedSetaffinity` per goroutine.
4. **`internal/pktpool`** — `sync.Pool` for frame copies in `FilterEngine.Tap`. Currently every match does `make([]byte, len(payload))`; under load this is the biggest GC source.
5. **Benchmarks doc** — measure pps per vCPU on veth + real NIC, document where loss appears.
6. **Demo recording** — asciinema of analyzer connecting, adding a filter, watching stats.

---

## 7. Improvement paths (speed-focused)

Listed roughly in order from "biggest win, smallest change" to "biggest win, largest rewrite".

### Tier 1 — additions to the current design
| Change | Expected gain | Cost |
|--------|---------------|------|
| **kernel cBPF pre-filter** | Drops uninteresting packets before they cross the RX ring. If 90% of traffic doesn't match any filter, that's 10× less ring pressure. | ~100 LOC for the 5-tuple compiler. Already planned. |
| **`PACKET_FANOUT` + per-CPU goroutines** | Linear scaling with cores up to NIC RX queue count. Each core gets its own RX ring + 5-tuple matcher. | Goroutine pinning + careful avoidance of cross-core sharing on the hot path. |
| **`sync.Pool` for matched-frame copies** | Removes the per-match `make([]byte)`. Cuts GC pause time on burst traffic. | Lifecycle is tricky — analyzer must release the buffer back to PF, which is impossible across process boundary. The pool only helps if we copy into a pooled buffer and release after writing to the TCP socket. |
| **Huge pages for mmap rings** | TLB misses on a 64 MiB ring add up. `MAP_HUGETLB` (or transparent huge pages) eliminates them. | One-line mmap flag change + a sysctl knob. |
| **`SO_BUSY_POLL`** | Lower wake-up latency under low load. | Trades CPU for latency. Tune via socket option. |

### Tier 2 — replace JSON/HTTP with binary
| Change | Expected gain | Cost |
|--------|---------------|------|
| **Protobuf for control plane** | Smaller payloads, faster decode. Less ceremony than JSON for typed messages. The `Codec` interface is already designed for this — just add `protoCodec{}` and switch the constructor. | One package + dependency. ~200 LOC. |
| **Length-prefixed binary control protocol over a single TCP connection** | One persistent connection, one protocol, no HTTP overhead. Useful if filter churn rate is high. | Throws away HTTP tooling (curl, browser inspection). Not worth it for this assignment. |
| **Cap'n Proto / FlatBuffers for dump frames** | Zero-copy decode on the analyzer side. Currently the analyzer copies the payload out of the TCP buffer. | Adds a schema dependency; payload structure is so simple that the gain is marginal here. |

### Tier 3 — kernel bypass
| Change | Expected gain | Cost |
|--------|---------------|------|
| **AF_XDP (XSK)** | Zero-copy from the NIC driver to userspace via UMEM. Bypasses the AF_PACKET protocol layer entirely. Typical gain: 5–10× pps over AF_PACKET on the same hardware. | Requires kernel ≥ 4.18, XDP-capable NIC driver, much more setup. Frames arrive into a UMEM ring you manage yourself; you re-publish to the FILL ring after consuming. There's a Go port of libxdp but it's CGo. Pure-Go bindings exist (`asavie/xdp`) but are less mature. |
| **DPDK** | Full userspace driver. No kernel involvement on the data path. 80+ Mpps per core achievable. | CGo. Massive dependency. Not realistic in pure Go. Out of scope for this assignment. |
| **io_uring for the TCP dump path** | Submit batches of `send` operations without per-call syscall overhead. Useful at very high match rates. | `golang.org/x/sys` doesn't expose io_uring directly. Need a third-party library or CGo. |

### Tier 4 — analyzer-side and NIC offloads
| Change | Expected gain | Cost |
|--------|---------------|------|
| **GRO/LRO disabled on the capture iface** | Prevents the NIC/kernel from coalescing TCP segments into super-packets, which corrupts per-flow statistics. | `ethtool -K iface gro off lro off`. Already standard practice for capture. |
| **Hardware timestamping** | Replaces `tpacket3_hdr.{sec,nsec}` (kernel timestamp) with NIC PHC timestamp. Nanosecond-accurate. | Needs NIC support, `SO_TIMESTAMPING_TX_HARDWARE`/`_RX_HARDWARE`. Only matters for sub-microsecond timing analyses. |
| **`PACKET_RX_RING`'s `PACKET_QDISC_BYPASS` for TX** | Skips the kernel queueing discipline on the TX socket. Lower TX latency. | One setsockopt. Trivial to add. |

### What I'd actually do next, in order
If we had another week:
1. cBPF pre-filter — biggest no-cost win.
2. Multi-queue fanout — linear scaling per core.
3. Benchmarks + docs — quantify everything above.
4. AF_XDP exploration — risky but is the answer if the grading bar is ≥10 Gbps in pure Go.

---

## 8. Build, run, test

```bash
# build
go build ./...

# run on a real NIC (needs CAP_NET_RAW or root)
sudo ./pf -iface eth0 -promisc

# run on a local veth pair for testing
sudo ./scripts/netns-setup.sh
sudo ./pf -iface veth0 -promisc

# in another terminal: add a filter
curl -X POST http://localhost:9100/v1/filters \
  -H 'Content-Type: application/json' \
  -d '{"filter":{"src_ip":"192.168.99.0/24","dst_port":443,"protocol":"tcp"}}'

# check stats
curl -s http://localhost:9100/v1/stats | jq

# connect a dump consumer
nc 127.0.0.1 9101 | hexdump -C
```

The hard pass criterion for grading is `rx_drops == 0` under sustained load. The benchmarking harness (still to be written) lives in `scripts/bench.sh` and uses `tgen` from the sibling `pcap-traffic-generator` repo as the load source.
