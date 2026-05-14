# Benchmarks

## Methodology

**Goal:** measure maximum packet rate before `rx_drops > 0` (zero-loss criterion).

**Setup:**
- veth pair (veth0 <-> veth1) on single host, same netns
- pf on veth0 with cBPF pre-filter active (union of all registered filters)
- pktgen on veth1 flooding veth0 at increasing rates
- TCP/UDP traffic with randomized 5-tuple to stress filter matching

**Procedure:**
```bash
sudo ./scripts/netns-setup.sh
sudo ./pf -iface veth0 -promisc &
sudo ./scripts/bench-pktgen.sh
```

## Results

### Single RX Queue (No PACKET_FANOUT)

| Rate (pps) | RX Packets | RX Drops | Breaking Point |
|------------|-----------|---------|-----------------|
| TBD | TBD | TBD | TBD |

**Achieved:** TBD pps / TBD Gbps before loss (1500B frames).

**CPU:** single core saturated. Linear scaling with `PACKET_FANOUT` (multi-queue) expected per core.

### With cBPF Pre-Filter

Kernel pre-filter (SO_ATTACH_FILTER) drops non-matching frames before they hit the ring, reducing userspace overhead.

**Speedup vs. userspace-only:** TBD% (measured by comparing drop-onset rates with/without kernel filter attached).

## Limitations

- veth pair maxes out around 1–5 Gbps on modern CPUs (single queue, loopback overhead).
- Real NIC + PACKET_FANOUT: expected 5–10G per core.
- No `sync.Pool` reuse optimized yet (frames are copied per match); future work.
- No huge pages or SO_BUSY_POLL tuning.

## Next Steps

- Profile CPU + memory on sustained 1Mpps load.
- Measure cBPF filter recompilation overhead (Add/Remove filter under load).
- Benchmark with real hardware (10G NIC + multi-queue).
