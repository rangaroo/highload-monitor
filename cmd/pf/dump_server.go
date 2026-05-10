package main

import (
	"bufio"
	"context"
	"log"
	"net"
	"sync/atomic"

	"github.com/rangaroo/highload-monitor/internal/proto"
)

const dumpWriteBufSize = 256 << 10 // 256 KiB write buffer  per connection

// DumpServer listens for a single Analyzer TCP connection and streams
// matched DumpFrames from the FilterEngine channel.
type DumpServer struct {
	addr   string
	frames <-chan proto.DumpFrame
	fw     proto.FrameWriter
	sent   atomic.Uint64 // frames written to Analyzer
}

func NewDumpServer(addr string, frames <-chan proto.DumpFrame, fw proto.FrameWriter) *DumpServer {
	return &DumpServer{addr: addr, frames: frames, fw: fw}
}

// Run accepts one Analyzer connection at a time and streams frames until
// ctx is cancelled or the listener fails fatally.
func (d *DumpServer) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", d.addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	log.Printf("dump server listening on %s", d.addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}

			log.Printf("dump accept: %v", err)
			continue
		}

		log.Printf("dump: analyzer connected from %s", conn.RemoteAddr())
		d.stream(ctx, conn)
		log.Printf("dump: analyzer disconnected")
	}
}

// stream() writes frames to conn until it errors or ctx is cancelled.
func (d *DumpServer) stream(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	buf := bufio.NewWriterSize(conn, dumpWriteBufSize)

	for {
		// block until at least one frame is available or ctx done
		select {
		case <-ctx.Done():
			return

		case df := <-d.frames:
			if err := d.fw.WriteFrame(buf, &df); err != nil {
				log.Printf("dump write: %v", err)
				return
			}
			d.sent.Add(1)

		drain:
			for {
				select {
				case df2 := <-d.frames:
					if err := d.fw.WriteFrame(buf, &df2); err != nil {
						log.Printf("dump write: %v", err)
						return
					}
					d.sent.Add(1)
				default:
					break drain
				}
			}

			if err := buf.Flush(); err != nil {
				log.Printf("dump flush: %v", err)
				return
			}
		}
	}
}

// Sent returns the number of frames written to the Analyzer.
func (d *DumpServer) Sent() uint64 { return d.sent.Load() }

// Addr returns the address the server listens on.
func (d *DumpServer) Addr() string { return d.addr }
