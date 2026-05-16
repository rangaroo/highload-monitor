package main

import (
	"context"
	"log"
	"runtime"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/rangaroo/highload-monitor/internal/afpacket"
)

// DumpTap is called for every forwarded frame.
type DumpTap interface {
	Tap(f afpacket.Frame)
}

// ForwarderStats holds counters snapshot from a running Forwarder.
type ForwarderStats struct {
	RXPackets  uint64
	TXPackets  uint64
	TapPackets uint64
}

// Forwarder reads packetso off an RX ring, optionally taps them
// for dumping, and write them back out via a TX ring.
type Forwarder struct {
	rx  *afpacket.RXRing
	tx  *afpacket.TXRing
	tap DumpTap // nil = no dump tapping

	rxPkts  atomic.Uint64
	txPkts  atomic.Uint64
	tapPkts atomic.Uint64
}

// NewForwarder creates a Forwarder, `tap` may be nil.
func NewForwarder(rx *afpacket.RXRing, tx *afpacket.TXRing, tap DumpTap) *Forwarder {
	return &Forwarder{rx: rx, tx: tx, tap: tap}
}

// Run is the hot loop. It blocks until ctx is cancelled or a fatal error occurs.
func (f *Forwarder) Run(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		cur, err := f.rx.PollBlock(100) // 100 ms timeout to check ctx
		if err != nil {
			return err
		}
		if cur == nil {
			continue // timeout, recheck ctx
		}

		for {
			frame, ok := cur.Next()
			if !ok {
				break
			}

			f.rxPkts.Add(1)

			if f.tap != nil {
				f.tap.Tap(frame)
				f.tapPkts.Add(1)
			}

			if err := f.tx.Send(frame.Data); err != nil {
				log.Printf("tx send: %v", err)
				continue
			}
			f.txPkts.Add(1)
		}

		cur.ReturnBlock()
	}
}

func (f *Forwarder) Stats() ForwarderStats {
	return ForwarderStats{
		RXPackets:  f.rxPkts.Load(),
		TXPackets:  f.txPkts.Load(),
		TapPackets: f.tapPkts.Load(),
	}
}

// RXStats returns kernel-level drop counters from the RX ring.
func (f *Forwarder) RXStats() (afpacket.Stats, error) {
	return f.rx.Stats()
}

// pinToCPU locks the calling goroutine to its OS thread and sets CPU affinity
// to the given logical CPU index. Best-effort: errors are non-fatal.
func pinToCPU(cpu int) error {
	runtime.LockOSThread()
	var mask unix.CPUSet
	mask.Set(cpu)
	return unix.SchedSetaffinity(0, &mask)
}
