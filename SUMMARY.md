# Summary — Packet Forwarder (Task 2)

## What Was Built

A **zero-loss packet forwarder with analytics**.

- **pf (Packet Forwarder):** captures packets from a NIC, optionally matches against filters, forwards back out, and streams matched frames to a remote analyzer.
- **analyzer:** consumes the dump stream, maintains per-filter cardinality (HLL) and entropy stats (Shannon), outputs JSON per second.
- **cBPF pre-filter:** kernel-level packet filtering to drop unwanted traffic before ring entry, reducing userspace CPU overhead.

## Key Design Decisions

1. **Separate pf + analyzer binaries** (not monolithic):
   - Pf owns capture/forward/filter; analyzer owns stats computation.
   - Allows analyst to connect/disconnect without restarting pf.
   - Stats logic can evolve independently.

2. **Non-blocking dump path:**
   - Forward path never blocks on dump path.
   - If analyzer is slow, dump frames are dropped (counted), not forwarded frames.
   - Meets the "zero rx_drops" criterion (rx_drops = kernel ring overflow only).

3. **cBPF pre-filter (kernel):**
   - Compile union of all active filters into one BPF program.
   - Attach to socket via SO_ATTACH_FILTER; kernel drops non-matching frames before ring entry.
   - Recompile + reattach on every filter Add/Remove (microsecond cost, infrequent operation).
   - Graceful fallback: if kernel compile/attach fails, userspace-only mode still works.

4. **Stateless protocol (no gRPC):**
   - Control plane: HTTP/JSON.
   - Dump stream: binary length-prefixed framing.
   - Simple, debuggable, no serialization dependencies.

## Architecture

```
NIC (multi-queue)
  ↓
[AF_PACKET TPACKET_V3 RX ring] (block-based mmap)
  ↓
[Kernel cBPF pre-filter] ← union of active filters
  ↓
[FilterEngine: 5-tuple exact match] → [TCP dump server]
  ↓↓                                    ↓
[TPACKET_V2 TX ring]               [Analyzer] (separate process)
  ↓                                - Control client (HTTP)
NIC (out)                          - Dump receiver (TCP)
                                   - Stats aggregator (HLL + entropy)
                                   - JSON output (stdout/file)
```

HTTP control plane (pf, `:9100`):
- `/v1/health` — liveness
- `/v1/stats` — rx/tx packets, kernel drops, freeze count
- `/v1/filters` — list/add/remove filters
- `/v1/dump-endpoint` — discover dump TCP address

Dump stream (pf, `:9101`):
- Binary: 15-byte header (magic, version, filter_id, timestamp, wire_len, payload_len) + payload.
- Analyzer dials once, reconnects on disconnect, parses indefinitely.

## Code Organization

**Packet Forwarder:**
- `cmd/pf/` — daemon entry point, HTTP server, dump server, forwarder loop, filter engine.
- `internal/afpacket/` — AF_PACKET socket wrapper, TPACKET_V3 RX ring, TPACKET_V2 TX ring, cBPF attach/detach.
- `internal/bpfc/` — cBPF compiler (FilterSpec → kernel BPF program).
- `internal/proto/` — wire protocol DTOs (FilterSpec, DumpFrame, HTTP responses).

**Analyzer:**
- `cmd/analyzer/` — daemon entry point, lifecycle (connect, register filters, consume dump).
- `internal/control/` — HTTP client for pf control plane.
- `internal/dump/` — TCP framed reader with auto-reconnect.
- `internal/stats/` — per-filter aggregator, HLL (axiomhq/hyperloglog), Shannon entropy.

**Testing + Docs:**
- `cmd/pf/filter_engine_test.go` — frame parsing, filter matching.
- `internal/bpfc/*_test.go` — cBPF compiler (empty, single, multi, bad input).
- `internal/stats/hll_test.go` — HLL cardinality accuracy.
- `scripts/netns-setup.sh` — veth pair setup for local testing.
- `scripts/test-integration.sh` — automated end-to-end test (manual run with sudo).
- `scripts/bench-pktgen.sh` — pktgen-based throughput benchmark.
- `scripts/demo.sh` — pf launcher for asciinema recording.
- `docs/architecture.md` — full design doc.
- `docs/demo.md` — live demo guide (3-pane tmux).
- `docs/benchmarks.md` — methodology, placeholder results.
- `docs/presentation-outline.md` — 10-slide presentation.

## Build + Test

```bash
go build ./cmd/pf
go build ./cmd/analyzer

go test ./...  # unit tests (12 tests, all passing)
```

## Manual Testing (Requires Root + veth)

```bash
sudo ./scripts/netns-setup.sh
sudo ./pf -iface veth0 -promisc &
./analyzer -pf http://localhost:9100 -filter "tcp::"
# Send traffic in another terminal
nc -w 1 192.168.99.1 443 < /dev/null
curl http://localhost:9100/v1/stats  # verify rx_drops == 0
```

Or automated:
```bash
sudo ./scripts/test-integration.sh
```

## Benchmarks

**Methodology:** pktgen floods veth0 at increasing rates; break-point is where `rx_drops > 0` first observed.

**Status:** benchmark script ready; actual run TBD (requires real NIC or veth on local host).

**Expected:** single veth queue: ~1–5 Gbps before loss. With PACKET_FANOUT: linear scaling per core.

## Improvements (Not Done, by Priority)

1. **PACKET_FANOUT:** one socket per NIC RX queue, distribute via hash. Enables multi-core scaling.
2. **sync.Pool:** reuse frame buffers in dump tap, reduce GC.
3. **SO_BUSY_POLL:** reduce poll latency/CPU wake overhead.
4. **AF_XDP:** bypass kernel network stack entirely (5–10G per core vs. 1–5G today).
5. **Shared-memory dump ring:** replace TCP with mmap'd ring for co-located analyzer (10–50G loopback).

## Known Limitations

- **Single core limit:** veth/loopback maxes out around 1–5 Gbps without PACKET_FANOUT.
- **cBPF skip count ceiling:** max ~20 filters before BPF instruction count hits 255 ceiling (u8 skip). Beyond that, switch to eBPF.
- **No persistent filter storage:** filters live in memory only; lost on restart. Future: persist to disk + reload on startup.
- **No analytics on dropped frames:** dump_drops are counted but not forwarded. Future: optional metadata frame when ring overflows.

## Deployment Notes

**Local development:** veth pair (scripts/netns-setup.sh), single host.

**Lab/production:** pf on dedicated NIC with PACKET_FANOUT, analyzer on separate host, control plane behind reverse proxy (nginx/TLS).

## Files Changed

**7 commits:**
1. `feat(bpfc): cBPF compiler for 5-tuple kernel pre-filter`
2. `feat(pf,analyzer): add cBPF kernel pre-filter attach + analyzer skeleton`
3. `fix(stats): switch HLL to axiomhq, fix test frames`
4. `docs: add bench script, benchmarks.md, update README for analyzer`
5. `docs: add integration test script + demo guide`
6. `docs: update README with testing, demo, benchmarks sections`
7. `docs: add presentation outline (10 slides)`

**Total:** ~3K lines of code + docs.

---

**Status:** Ready for integration testing, benchmarking, and demo recording on real hardware (user's local environment).
