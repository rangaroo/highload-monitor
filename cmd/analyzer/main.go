// Analyzer connects to a running pf instance, registers one or more filters,
// then consumes the dump stream and prints per-filter statistics.
//
// Lifecycle:
//  1. health-check the control plane
//  2. register filters from -filter flags
//  3. resolve the dump TCP endpoint
//  4. start the dump receiver
//  5. tick once a second emitting JSON aggregates to stdout
//  6. on SIGINT/SIGTERM: remove the filters we registered and exit
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rangaroo/highload-monitor/internal/control"
	"github.com/rangaroo/highload-monitor/internal/dump"
	"github.com/rangaroo/highload-monitor/internal/proto"
	"github.com/rangaroo/highload-monitor/internal/stats"
)

// filterFlag is a repeated -filter flag parsed as protocol:src_cidr:dst_port.
//
// Format examples:
//
//	tcp:10.0.0.0/8:443        # tcp from 10/8 to dst port 443
//	udp::53                   # udp to dst port 53, any src
//	tcp:::                    # all tcp (3 empty fields after "tcp")
//	::443                     # any proto to dst 443
//
// Order is fixed: protocol:src_ip:dst_port. Empty field = wildcard.
type filterFlag []proto.FilterSpec

func (f *filterFlag) String() string { return fmt.Sprintf("%v", *f) }

func (f *filterFlag) Set(s string) error {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		return fmt.Errorf("bad filter %q (want protocol:src_ip:dst_port)", s)
	}
	spec := proto.FilterSpec{
		Protocol: parts[0],
		SrcIP:    parts[1],
	}
	if parts[2] != "" {
		var port uint16
		if _, err := fmt.Sscanf(parts[2], "%d", &port); err != nil {
			return fmt.Errorf("bad dst_port %q: %w", parts[2], err)
		}
		spec.DstPort = port
	}
	*f = append(*f, spec)
	return nil
}

func main() {
	var filters filterFlag
	pfAddr := flag.String("pf", "http://localhost:9100", "pf control plane base URL")
	dumpAddrOverride := flag.String("dump", "", "override dump TCP address (host:port); empty = discover via /v1/dump-endpoint")
	interval := flag.Duration("interval", 1*time.Second, "stats output interval")
	flag.Var(&filters, "filter", "filter spec protocol:src_ip:dst_port (repeat for many)")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("shutting down")
		cancel()
	}()

	cc := control.New(*pfAddr)

	if err := cc.Health(ctx); err != nil {
		log.Fatalf("pf not healthy at %s: %v", *pfAddr, err)
	}
	log.Printf("connected to pf %s", *pfAddr)

	registered := registerFilters(ctx, cc, filters)
	defer cleanupFilters(cc, registered)

	dumpAddr := *dumpAddrOverride
	if dumpAddr == "" {
		ep, err := cc.DumpEndpoint(ctx)
		if err != nil {
			log.Fatalf("dump endpoint: %v", err)
		}
		dumpAddr = ep
		if strings.HasPrefix(dumpAddr, ":") {
			// pf returns ":9101" form when bound to all interfaces; rewrite for dialing
			host, _, _ := net.SplitHostPort(*pfAddr)
			if host == "" {
				host = "localhost"
			}
			dumpAddr = host + dumpAddr
		}
	}
	log.Printf("dump endpoint %s", dumpAddr)

	agg := stats.NewAggregator()

	// dump receiver feeds the aggregator
	dumpErr := make(chan error, 1)
	go func() {
		dumpErr <- dump.Run(ctx, dumpAddr, func(f *proto.DumpFrame) {
			agg.Ingest(f)
		})
	}()

	// stats printer
	tick := time.NewTicker(*interval)
	defer tick.Stop()

	enc := json.NewEncoder(os.Stdout)
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-dumpErr:
			if !errors.Is(err, context.Canceled) {
				log.Printf("dump receiver exited: %v", err)
			}
			return
		case <-tick.C:
			snap := agg.Snapshot()
			if err := enc.Encode(snap); err != nil {
				log.Printf("encode stats: %v", err)
			}
		}
	}
}

func registerFilters(ctx context.Context, cc *control.Client, filters []proto.FilterSpec) []proto.FilterID {
	var ids []proto.FilterID
	for _, spec := range filters {
		id, err := cc.AddFilter(ctx, spec)
		if err != nil {
			log.Fatalf("add filter %+v: %v", spec, err)
		}
		log.Printf("registered filter id=%s spec=%+v", id, spec)
		ids = append(ids, id)
	}
	return ids
}

func cleanupFilters(cc *control.Client, ids []proto.FilterID) {
	if len(ids) == 0 {
		return
	}
	// fresh ctx - main one is canceled by the time defer runs
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, id := range ids {
		if err := cc.RemoveFilter(ctx, id); err != nil {
			log.Printf("remove filter %s: %v", id, err)
		}
	}
}
