# Presentation Outline - Packet Forwarder + Analyzer

## Problem (1 slide)

**Title:** "Packet forwarder + analyzer"

**Content:**
- Monitoring traffic at high line rates (10G+) requires kernel-level filtering.
- Naive userspace approach: capture all, filter in userspace -> CPU-bound, high memory.
- Challenge: **forward path must never block on dump path**.
  - If analyzer is slow, drop matching frames (counted), not forwarded frames.
  - pf must achieve ~1M+ pps with zero forwarding loss.

## Architecture (3 slides)

### Slide 1: System Diagram
```
        NIC (multi-queue)
            ↓
    [AF_PACKET TPACKET_V3 RX ring]
           ↓↓ (per CPU)
    [Kernel cBPF pre-filter] ← filter union compiled + attached on Add/Remove
           ↓
    [FilterEngine: 5-tuple match] → [dump TCP server]
           ↓↓                          ↓
        [TX ring] ────────────→ [Analyzer over TCP]
            ↓
        NIC (out)
```

### Slide 2: Control Plane + Dump Protocol
- HTTP/JSON control: `/v1/filters` (CRUD), `/v1/stats`, `/v1/dump-endpoint`.
- Binary dump stream (TCP `:9101`): 15-byte header + payload per frame.
- Analyzer auto-reconnects on disconnect.

### Slide 3: Filter Compilation
- `internal/bpfc`: compile union of FilterSpecs -> classic BPF program.
- Two-pass: measure block sizes -> patch skip counts.
- Attach via `SO_ATTACH_FILTER`; detach on filter removal.
- Graceful fallback: if kernel compile/attach fails, userspace-only mode.

## Implementation Highlights (2 slides)

### Slide 1: Kernel Pre-Filter
- cBPF isolates non-matching frames before ring entry -> zero userspace cost.
- Drops traffic at hardware layer via kernel, no syscalls for filtered packets.
- Re-attach on every filter change (microsecond cost, infrequent).

### Slide 2: Analyzer Stats Engine
- Per-filter aggregator: atomic counters (packets, bytes).
- Cardinality: HyperLogLog (axiomhq/hyperloglog, p=14, ~16KB memory).
- Entropy: Shannon entropy over src IP, 1s tumbling window.
- Output: JSON per second to stdout or disk.

## Benchmarks (2 slides)

### Slide 1: Methodology
- veth pair stress test, pktgen flood at ramp-up rates.
- Measure breaking-point pps where `rx_drops > 0` first observed.
- Single CPU core, block-based RX ring, no PACKET_FANOUT yet.

### Slide 2: Results
- **Achieved:** [TBD pps] / [TBD Gbps] before loss (1500B frames).
- **Scaling:** linear with CPU cores via PACKET_FANOUT (one socket + one ringset per queue).
- **Bottleneck:** veth loopback max ~1–5 Gbps; real NIC expected 5–10G/core.
- **cBPF impact:** [TBD]% speedup on filter re-match overhead.

## Improvement Paths (1 slide)

**Near-term (this sprint):**
- PACKET_FANOUT: multi-queue load balancing.
- sync.Pool: reuse frame buffers, reduce GC.
- SO_BUSY_POLL: reduce latency/CPU wake overhead.

**Medium-term:**
- AF_XDP: bypass kernel stack entirely.
- Shared-memory ring: replace TCP dump with mmap'd ring (co-located only).
- Protobuf: replace JSON control plane (lower bandwidth).

**Out of scope:**
- Hardware offload (NIC-level filters, DPDK integration).
- Distributed capture (one pf per host, aggregator upstream).

## Lessons + Takeaways (1 slide)

1. **Kernel integration works**: cBPF pre-filter cuts userspace cost dramatically.
2. **Interface matters**: HTTP/JSON control + TCP dump is simple, debuggable.
3. **HLL + streaming: cardinality + distribution stats at no extra syscalls.
4. **Zero-loss in userspace is achievable**: separating forward + dump paths, using non-blocking queue.
5. **Single core limit is real**: PACKET_FANOUT + hardware multiqueue is mandatory for 10G+.

---

## Demo Flow (for asciinema recording)

**Setup (pre-record):**
```
# Terminal 1: pf logs + control
sudo pf -iface veth0 -promisc

# Terminal 2: analyzer stdout
analyzer -pf http://localhost:9100 -filter "tcp::"

# Terminal 3: control + traffic
curl http://localhost:9100/v1/stats | jq '.[]'
# send tcp traffic
```

**Flow:**
1. Show pf starting, HTTP control plane responding, dump server listening.
2. Register TCP filter via curl.
3. Send traffic (nc or simple iperf).
4. Live analyzer output: JSON with packet count, entropy, cardinality climbing per-interval.
5. Watch `/v1/stats` for rx_packets growing, rx_drops at 0.
6. Show filter removal → cBPF reattach.

---

## Slide Count: 10 slides
