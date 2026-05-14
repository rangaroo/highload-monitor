package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/rangaroo/highload-monitor/internal/afpacket"
	"github.com/rangaroo/highload-monitor/internal/proto"
)

func main() {
	iface := flag.String("iface", "", "network interface to capture on (required)")
	promisc := flag.Bool("promisc", false, "enable promiscuous mode")
	httpAddr := flag.String("http", ":9100", "HTTP control plane listen address")
	dumpAddr := flag.String("dump", ":9101", "TCP dump stream listen address")
	flag.Parse()

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "usage: pf -iface <name> [-promisc] [-http :9100] [-dump :9101]")
		os.Exit(1)
	}

	// RX ring - captures from NIC
	rx, err := afpacket.Open(afpacket.Config{
		Interface:   *iface,
		Promiscuous: *promisc,
	})
	if err != nil {
		log.Fatalf("open rx: %v", err)
	}
	defer rx.Close()

	// TX ring - forwards packets back out the same interface
	tx, err := afpacket.OpenTX(afpacket.TXConfig{
		Interface: *iface,
	})
	if err != nil {
		log.Fatalf("open tx: %v", err)
	}
	defer tx.Close()

	// filter engine - userspace 5-tuple match + dump tap
	engine := NewFilterEngine(rx)

	// forwarder - RX -> tap -> TX hot loop
	fwd := NewForwarder(rx, tx, engine)

	// dump server - streams matched frames to Analyzer over TCP
	ds := NewDumpServer(*dumpAddr, engine.Frames(), proto.NewBinaryFrameWriter())

	// HTTP control server
	codec := proto.NewJSONCodec()
	srv := NewServer(codec, engine, fwd, *dumpAddr)
	httpSrv := &http.Server{
		Addr:    *httpAddr,
		Handler: srv.Handler(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// start forwarder
	fwdErr := make(chan error, 1)
	go func() { fwdErr <- fwd.Run(ctx) }()

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

	log.Printf("pf started on %s (http=%s dump=%s)", *iface, *httpAddr, *dumpAddr)

	select {
	case <-sig:
		log.Println("shutting down")
		cancel()
		httpSrv.Close()
	case err := <-fwdErr:
		log.Fatalf("forwarder: %v", err)
	case err := <-dumpErr:
		log.Fatalf("dump server: %v", err)
	case err := <-httpErr:
		log.Fatalf("http server: %v", err)
	}

	// print final stats
	fs := fwd.Stats()
	ks, _ := rx.Stats()
	log.Printf("final: rx=%d tx=%d tap=%d kernel_drops=%d filter_drops=%d dump_sent=%d",
		fs.RXPackets, fs.TXPackets, fs.TapPackets,
		ks.Drops, engine.Drops(), ds.Sent())
}
