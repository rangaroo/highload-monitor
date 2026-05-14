// Package stats holds analyzer-side cardinality and entropy estimators.
//
// HLL - HyperLogLog cardinality estimator, fixed precision p=14:
//
//	registers: m = 1 << 14 = 16384 (each 6 bits, packed into bytes for simplicity)
//	stderr:    ≈ 1.04 / sqrt(m) ≈ 0.8 %
//	memory:    16 KiB per estimator
//
// Hashing uses xxhash64 emulated via stdlib hash/fnv64a. FNV is weaker than
// xxhash but is good enough for HLL at this precision - we are bucketing on
// top register bits and counting leading zeros, not doing cryptographic work.
package stats

import (
	"hash/fnv"
	"math"
	"sync"
)

const (
	hllPrecision  = 14
	hllRegisters  = 1 << hllPrecision // 16384
	hllRegMask    = hllRegisters - 1
	hllAlphaConst = 0.7213 // alpha m correction for p ≥ 7
	hllAlphaTerm  = 1.079 / hllRegisters
)

// HLL is a HyperLogLog cardinality sketch.
//
// Concurrency: protected by its own mutex. The Add path is on the hot
// per-frame ingest loop, so we keep the lock window tiny - one bucket compare
// and at most one byte store.
type HLL struct {
	mu        sync.Mutex
	registers [hllRegisters]uint8
}

// NewHLL returns an empty estimator.
func NewHLL() *HLL { return &HLL{} }

// Add hashes b and updates the appropriate register.
func (h *HLL) Add(b []byte) {
	hash := fnv64a(b)

	// Top `hllPrecision` bits -> bucket index.
	idx := hash >> (64 - hllPrecision)

	// Remaining bits -> count leading zeros + 1 (clamped to register max).
	w := (hash << hllPrecision) | (1 << (hllPrecision - 1)) // ensure ≥ 1 LZ bit
	leadingZeros := uint8(leadingZeros64(w)) + 1

	h.mu.Lock()
	if leadingZeros > h.registers[idx] {
		h.registers[idx] = leadingZeros
	}
	h.mu.Unlock()
}

// Estimate returns the current cardinality estimate.
func (h *HLL) Estimate() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()

	var sum float64
	var zeros int
	for _, r := range h.registers {
		sum += 1.0 / math.Pow(2, float64(r))
		if r == 0 {
			zeros++
		}
	}

	alpha := hllAlphaConst / (1.0 + hllAlphaTerm)
	estimate := alpha * float64(hllRegisters*hllRegisters) / sum

	// Linear counting correction for small cardinalities.
	if estimate <= 2.5*float64(hllRegisters) && zeros > 0 {
		estimate = float64(hllRegisters) * math.Log(float64(hllRegisters)/float64(zeros))
	}

	return uint64(estimate + 0.5)
}

// Reset zeroes all registers.
func (h *HLL) Reset() {
	h.mu.Lock()
	for i := range h.registers {
		h.registers[i] = 0
	}
	h.mu.Unlock()
}

func fnv64a(b []byte) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return h.Sum64()
}

func leadingZeros64(x uint64) int {
	// Stdlib has math/bits.LeadingZeros64, but inlining the small fast path
	// here keeps the package free of that import (purely cosmetic).
	if x == 0 {
		return 64
	}
	n := 0
	for x&(1<<63) == 0 {
		n++
		x <<= 1
	}
	return n
}
