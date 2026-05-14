package stats

import (
	"encoding/binary"
	"sync"
	"sync/atomic"

	"github.com/rangaroo/highload-monitor/internal/proto"
)

const ethHdrLen = 14

// FilterStats holds the live counters for one filter_id.
type FilterStats struct {
	Packets      atomic.Uint64
	Bytes        atomic.Uint64
	UniqueSrcIPs *HLL
	UniqueDstIPs *HLL
	SrcEntropy   *EntropyWindow
}

func newFilterStats() *FilterStats {
	return &FilterStats{
		UniqueSrcIPs: NewHLL(),
		UniqueDstIPs: NewHLL(),
		SrcEntropy:   NewEntropyWindow(),
	}
}

// FilterSnapshot is the JSON-encoded view of one filter's stats at a tick.
type FilterSnapshot struct {
	FilterID         uint32  `json:"filter_id"`
	Packets          uint64  `json:"packets"`
	Bytes            uint64  `json:"bytes"`
	UniqueSrcIPs     uint64  `json:"unique_src_ips"`
	UniqueDstIPs     uint64  `json:"unique_dst_ips"`
	SrcEntropyBits   float64 `json:"src_entropy_bits"`
	SrcWindowPackets uint64  `json:"src_window_packets"`
}

// Snapshot is the top-level periodic stats dump.
type Snapshot struct {
	Filters []FilterSnapshot `json:"filters"`
}

// Aggregator dispatches DumpFrames to per-filter FilterStats by filter_id.
//
// Concurrency: a single sync.RWMutex protects the map. The hot Ingest path
// takes only the read lock; we upgrade to the write lock only on first sight
// of a new filter_id (rare — filters are created via control plane, not in
// the stream).
type Aggregator struct {
	mu      sync.RWMutex
	filters map[uint32]*FilterStats
}

func NewAggregator() *Aggregator {
	return &Aggregator{filters: make(map[uint32]*FilterStats)}
}

// Ingest pulls 5-tuple fields out of the frame payload and updates the
// matching filter's counters. Frames that aren't IPv4 are still counted at
// the packet/byte level but skip the IP-specific stats.
func (a *Aggregator) Ingest(f *proto.DumpFrame) {
	fs := a.statsFor(f.FilterID)
	fs.Packets.Add(1)
	fs.Bytes.Add(uint64(len(f.Payload)))

	srcIP, _, ok := parseIPv4(f.Payload)
	if !ok {
		return
	}
	srcBytes := []byte{
		byte(srcIP >> 24),
		byte(srcIP >> 16),
		byte(srcIP >> 8),
		byte(srcIP),
	}
	fs.UniqueSrcIPs.Add(srcBytes)
	fs.SrcEntropy.Add(srcIP)

	if _, dstIP, ok := parseIPv4(f.Payload); ok {
		dstBytes := []byte{
			byte(dstIP >> 24),
			byte(dstIP >> 16),
			byte(dstIP >> 8),
			byte(dstIP),
		}
		fs.UniqueDstIPs.Add(dstBytes)
	}
}

func (a *Aggregator) statsFor(id uint32) *FilterStats {
	a.mu.RLock()
	fs, ok := a.filters[id]
	a.mu.RUnlock()
	if ok {
		return fs
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if fs, ok := a.filters[id]; ok {
		return fs
	}
	fs = newFilterStats()
	a.filters[id] = fs
	return fs
}

// Snapshot returns a JSON-encodable point-in-time view of every filter.
// EntropyWindow.Snapshot resets the window as a side effect — that's
// intentional, the JSON output is per-interval.
func (a *Aggregator) Snapshot() Snapshot {
	a.mu.RLock()
	defer a.mu.RUnlock()

	out := Snapshot{Filters: make([]FilterSnapshot, 0, len(a.filters))}
	for id, fs := range a.filters {
		h, n := fs.SrcEntropy.Snapshot()
		out.Filters = append(out.Filters, FilterSnapshot{
			FilterID:         id,
			Packets:          fs.Packets.Load(),
			Bytes:            fs.Bytes.Load(),
			UniqueSrcIPs:     fs.UniqueSrcIPs.Estimate(),
			UniqueDstIPs:     fs.UniqueDstIPs.Estimate(),
			SrcEntropyBits:   h,
			SrcWindowPackets: n,
		})
	}
	return out
}

// parseIPv4 returns (srcIP, dstIP, ok) as host-order uint32s.
//
// Expects raw Ethernet frame (no link-layer stripping). Returns ok=false on
// non-IPv4, truncated payload, or invalid IHL.
func parseIPv4(data []byte) (uint32, uint32, bool) {
	if len(data) < ethHdrLen+20 {
		return 0, 0, false
	}
	if binary.BigEndian.Uint16(data[12:14]) != 0x0800 {
		return 0, 0, false
	}
	ip := data[ethHdrLen:]
	if (ip[0] >> 4) != 4 {
		return 0, 0, false
	}
	src := binary.BigEndian.Uint32(ip[12:16])
	dst := binary.BigEndian.Uint32(ip[16:20])
	return src, dst, true
}
