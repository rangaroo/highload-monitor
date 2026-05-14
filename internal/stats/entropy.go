package stats

import (
	"math"
	"sync"
)

// EntropyWindow computes Shannon entropy over the values added since the
// last Reset.
//
// We keep an exact per-value count map rather than a count-min sketch.
// Reason: at analyzer scale (one process draining one TCP stream), the map
// is bounded by the unique-value count, which for a single filter on a
// 1s window is small (≤ 100k IPs in pathological cases, < 1 MB). A sketch
// would trade memory for accuracy without buying us anything here.
//
// The hot path Add() is one map lookup + one increment under a mutex.
// Snapshot() walks the map once and is called once per interval.
type EntropyWindow struct {
	mu     sync.Mutex
	counts map[uint32]uint64
	total  uint64
}

// NewEntropyWindow returns an empty entropy window keyed by uint32 values
// (e.g. IPv4 addresses stored as host-order uint32).
func NewEntropyWindow() *EntropyWindow {
	return &EntropyWindow{counts: make(map[uint32]uint64)}
}

// Add records one occurrence of v.
func (e *EntropyWindow) Add(v uint32) {
	e.mu.Lock()
	e.counts[v]++
	e.total++
	e.mu.Unlock()
}

// Snapshot returns the Shannon entropy (in bits) over the window's contents
// and clears the window in one atomic step. A window with 0 observations
// returns 0.
//
// Resetting on snapshot gives "entropy per interval" - the natural unit for
// a live monitoring view.
func (e *EntropyWindow) Snapshot() (entropyBits float64, totalSeen uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.total == 0 {
		return 0, 0
	}

	total := float64(e.total)
	var h float64
	for _, c := range e.counts {
		p := float64(c) / total
		h -= p * math.Log2(p)
	}

	entropyBits = h
	totalSeen = e.total

	// Reset.
	e.counts = make(map[uint32]uint64)
	e.total = 0

	return entropyBits, totalSeen
}
