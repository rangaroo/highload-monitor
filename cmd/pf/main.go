package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rangaroo/highload-monitor/internal/afpacket"
)

func main() {
	iface := flag.String("iface", "", "network interface to capture on (required)")
	promisc := flag.Bool("promisc", false, "enable promiscuous mode")
	flag.Parse()

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "usage: pf -iface <name> [-promisc]")
		os.Exit(1)
	}

	ring, err := afpacket.Open(afpacket.Config{
		Interface:   *iface,
		Promiscuous: *promisc,
	})
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer ring.Close()

	log.Printf("capturing on %s (block=%dKiB x %d blocks)",
		*iface,
		ring.BlockSize()/1024,
		ring.BlockCount(),
	)

	// ticker prints running totals every 2 second
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var totalPkts, totalBytes uint64
	start := time.Now()

	for {
		select {
		case <-sig:
			printFinal(ring, totalPkts, totalBytes, time.Since(start))
			return
		case <-ticker.C:
			printStatus(ring, totalPkts, totalBytes, time.Since(start))
		default:
			cur, err := ring.PollBlock(200) // 200 ms timeout
			if err != nil {
				log.Printf("poll: %v", err)
				continue
			}
			if cur == nil {
				continue // timeout, loop back to check signals/ticker
			}
			for {
				f, ok := cur.Next()
				if !ok {
					break
				}
				totalPkts++
				totalBytes += uint64(f.WireLen)
			}
			cur.ReturnBlock()
		}
	}

}

func printStatus(ring *afpacket.RXRing, pkts, bytes uint64, elapsed time.Duration) {
	s, err := ring.Stats()
	if err != nil {
		log.Printf("stats: %v", err)
		return
	}
	secs := elapsed.Seconds()
	log.Printf("pkts=%d  bytes=%d  pps=%.0f  drops%d  freeze=%d",
		pkts, bytes, float64(pkts)/secs, s.Drops, s.FreezeQCount)
}

func printFinal(ring *afpacket.RXRing, pkts, bytes uint64, elapsed time.Duration) {
	fmt.Println()
	printStatus(ring, pkts, bytes, elapsed)
}
