package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/rangaroo/highload-monitor/internal/afpacket"
	"github.com/rangaroo/highload-monitor/internal/proto"
)

func main() {
	iface := flag.String("iface", "", "network interface to capture on (required)")
	promisc := flag.Bool("promisc", false, "enable promiscuous mode")
	httpAddr := flag.String("http", ":9100", "HTTP control plane listen address")
	dumpAddr := flag.String("dump", ":9101", "TCP dump stream listen address")
	queues := flag.Int("queues", runtime.NumCPU(), "number of RX queues (PACKET_FANOUT sockets)")
	flag.Parse()

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "usage: pf -iface <name> [-promisc] [-queues N] [-http :9100] [-dump :9101]")
		os.Exit(1)
	}

	if *queues < 1 {
		*queues = 1
	}

	// TX ring - shared across all RX goroutines (per-slot ownership makes it safe)
	tx, err := afpacket.OpenTX(afpacket.TXConfig{
		Interface: *iface,
	})
	if err != nil {
		log.Fatalf("open tx: %v", err)
	}
	defer tx.Close()

	// Open N RX sockets joined into the same PACKET_FANOUT_HASH group.
	// The kernel distributes packets by 5-tuple hash so each socket sees a
	// disjoint subset; together they see all traffic with no duplication.
	const fanoutGroup = 1 // arbitrary non-zero group ID
	rxRings := make([]*afpacket.RXRing, *queues)
	for i := range rxRings {
		cfg := afpacket.Config{
			Interface:   *iface,
			Promiscuous: *promisc,
		}
		if *queues > 1 {
			cfg.FanoutGroup = fanoutGroup
			cfg.FanoutType = 0 // packetFanoutHash
		}
		rxRings[i], err = afpacket.Open(cfg)
		if err != nil {
			log.Fatalf("open rx[%d]: %v", i, err)
		}
		defer rxRings[i].Close()
	}

	log.Printf("pf started on %s with %d RX queue(s) (http=%s dump=%s)", *iface, *queues, *httpAddr, *dumpAddr)

	// filter engine wired to all RX rings (attaches cBPF to each)
	engine := NewFilterEngine(rxRings...)

	// one Forwarder per RX ring; they all share the TX ring
	forwarders := make([]*Forwarder, *queues)
	for i, rx := range rxRings {
		forwarders[i] = NewForwarder(rx, tx, engine)
	}

	// dump server - streams matched frames to Analyzer over TCP
	ds := NewDumpServer(*dumpAddr, engine.Frames(), proto.NewBinaryFrameWriter())

	// HTTP control server - uses forwarders[0] for stats (aggregated below)
	codec := proto.NewJSONCodec()
	srv := NewServer(codec, engine, forwarders[0], *dumpAddr)
	httpSrv := &http.Server{
		Addr:    *httpAddr,
		Handler: srv.Handler(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// start one goroutine per forwarder, each pinned to a distinct CPU
	fwdErrCh := make(chan error, *queues)
	var fwdWg sync.WaitGroup
	for i, fwd := range forwarders {
		fwdWg.Add(1)
		go func(idx int, f *Forwarder) {
			defer fwdWg.Done()
			if err := pinToCPU(idx); err != nil {
				log.Printf("warn: could not pin queue %d to cpu %d: %v", idx, idx, err)
			}
			if err := f.Run(ctx); err != nil {
				fwdErrCh <- err
			}
		}(i, fwd)
	}

	// start dump server
	dumpErr := make(chan error, 1)
	go func() { dumpErr <- ds.Run(ctx) }()

	// start HTTP server
	httpErr := make(chan error, 1)
	go func() {
		log.Printf("http control on %s", *httpAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			httpErr <- err
		}
	}()

	select {
	case <-sig:
		log.Println("shutting down")
		cancel()
		httpSrv.Close()
	case err := <-fwdErrCh:
		log.Fatalf("forwarder: %v", err)
	case err := <-dumpErr:
		log.Fatalf("dump server: %v", err)
	case err := <-httpErr:
		log.Fatalf("http server: %v", err)
	}

	// aggregate stats across all forwarders
	var totalRX, totalTX, totalTap uint64
	for _, f := range forwarders {
		s := f.Stats()
		totalRX += s.RXPackets
		totalTX += s.TXPackets
		totalTap += s.TapPackets
	}
	var totalDrops uint32
	for _, rx := range rxRings {
		ks, _ := rx.Stats()
		totalDrops += ks.Drops
	}
	log.Printf("final: rx=%d tx=%d tap=%d kernel_drops=%d filter_drops=%d dump_sent=%d",
		totalRX, totalTX, totalTap, totalDrops, engine.Drops(), ds.Sent())
}
