package stats

import (
	"sync"

	"github.com/axiomhq/hyperloglog"
)

// HLL wraps axiomhq/hyperloglog for cardinality estimation.
//
// Concurrency: protected by its own mutex. The Add path is on the hot
// per-frame ingest loop, so we keep the lock window tiny.
type HLL struct {
	mu  sync.Mutex
	hll *hyperloglog.Sketch
}

// NewHLL returns an empty estimator (precision 14, ~16KB memory).
func NewHLL() *HLL {
	hll := hyperloglog.New14()
	return &HLL{hll: hll}
}

// Add hashes b and updates the sketch.
func (h *HLL) Add(b []byte) {
	h.mu.Lock()
	h.hll.Insert(b)
	h.mu.Unlock()
}

// Estimate returns the current cardinality estimate.
func (h *HLL) Estimate() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hll.Estimate()
}

// Reset clears the sketch.
func (h *HLL) Reset() {
	h.mu.Lock()
	h.hll = hyperloglog.New14()
	h.mu.Unlock()
}
