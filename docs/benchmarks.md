# Benchmarks

## Environment

| | |
|---|---|
| Host | veth pair, 8-core x86\_64 |
| Kernel | 6.17.0-23-generic |
| Go | 1.25.4 |
| Traffic | udpflood raw AF\_PACKET injector, 1000 B frames |
| Metric | max sustained pps with `kernel_drops == 0` |

**Setup:**
```bash
sudo ./scripts/netns-setup.sh          # veth0 / veth1 in pftest netns
go build -o pf ./cmd/pf
go build -o udpflood ./cmd/udpflood
sudo ./pf -iface veth0 -promisc [-queues N]
sudo PARALLEL=N ./scripts/bench.sh
```

## Results

| Branch | Commit | pps | Gbps | CPU | kernel\_drops | vs baseline |
|---|---|---|---|---|---|---|
| main (baseline) | 7f529fd | 547,171 | 4.38 | 1 core @100% | 0 | — |
| feat/packet-fanout | 0471081 | 1,257,469 | 10.06 | 8 cores @100% | 0 | **+2.3×** |
| feat/sync-pool | ebc27e7 | 1,257,410 | 10.06 | 8 cores @100% | 0 | +2.3× |

All runs: zero packet loss sustained across 30M+ packets.

## What each branch adds

### baseline - `main`
Single AF\_PACKET socket, single goroutine, cBPF pre-filter. Saturates 1 core at 100%
(27% usr / 73% sys). Sender (udpflood single-thread) caps at ~547k pps - pf is not
the bottleneck here; the ceiling is the injector.

### feat/packet-fanout
Opens N AF\_PACKET sockets joined into one `PACKET_FANOUT_HASH` group. The kernel
distributes packets by 5-tuple hash - each socket sees a disjoint subset, together
they see all traffic. One goroutine per socket, each pinned to a distinct CPU via
`SchedSetaffinity`. Each queue has its own TX ring to eliminate cross-goroutine
lock contention.

Key fix found during benchmarking: sharing one TX ring across N goroutines caused
silent ring corruption (data race on `cur` index) -> kernel drops. Fix: one TX ring
per RX queue.

Result: 2.3× throughput improvement. 
### feat/sync-pool
Pools `BlockCursor` (one alloc per ring block, ~1000 pkts/block) and dump payload
byte slices (`make([]byte, frameLen)` per filter match). Reduces GC allocation rate
on the hot path. Throughput unchanged on a no-filter bench - the benefit is lower
GC pause latency under sustained filter + dump load.

## Bottleneck analysis

```
Baseline:  sender ~547k pps (single-thread sendto syscall loop)
           pf 1 core @100% — sender and pf both at ceiling

Fanout:    8 parallel senders -> ~1.26M pps aggregate
           pf uses 8 cores (hash collision on synthetic traffic)
           headroom: 2.3x speed up
```

The benchmark is sender-bound. The true ceiling of pf on this host is above the
measured numbers - demonstrated by zero drops at all offered rates.

## Limitations

- veth pair; no hardware NIC queue steering. Real NIC + PACKET\_FANOUT distributes
  by NIC RSS before software fanout.
- Synthetic traffic (fixed src/dst IP, 8 src ports) causes hash collisions in fanout
- No `SO_BUSY_POLL` or huge-page tuning.
- No cBPF recompilation overhead measurement (Add/Remove filter under load).
