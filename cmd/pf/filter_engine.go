package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/rangaroo/highload-monitor/internal/afpacket"
	"github.com/rangaroo/highload-monitor/internal/proto"
)

const (
	dumpChanSize = 8192
	ethHdrLen    = 14
	ethTypeIPv4  = 0x0800
)

// parsedFrame holds the 5-tuple extracted from a raw Ethernet frame.
type parsedFrame struct {
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	ipProto uint8
	valid   bool
}

// compiledFilter is a FilterSpec with pre-parsed CIDRs for fast matching.
type compiledFilter struct {
	numID   uint32
	spec    proto.FilterSpec
	srcNet  *net.IPNet // nil = match any src IP
	dstNet  *net.IPNet // nil = match any dst IP
	ipProto uint8      // 0 = any
}

func (cf compiledFilter) matches(p parsedFrame) bool {
	if cf.ipProto != 0 && cf.ipProto != p.ipProto {
		return false
	}
	if cf.srcNet != nil && !cf.srcNet.Contains(p.srcIP) {
		return false
	}
	if cf.dstNet != nil && !cf.dstNet.Contains(p.dstIP) {
		return false
	}
	if cf.spec.SrcPort != 0 && cf.spec.SrcPort != p.srcPort {
		return false
	}
	if cf.spec.DstPort != 0 && cf.spec.DstPort != p.dstPort {
		return false
	}
	return true
}

// FilterEngine maintains active filters and implements DumpTap.
type FilterEngine struct {
	mu      sync.RWMutex
	filters map[string]compiledFilter
	nextID  atomic.Uint32
	ch      chan proto.DumpFrame
	drops   atomic.Uint64 // matched frames dropped because ch was full
}

func NewFilterEngine() *FilterEngine {
	return &FilterEngine{
		filters: make(map[string]compiledFilter),
		ch:      make(chan proto.DumpFrame, dumpChanSize),
	}
}

// Add compiles spec and registers it. Returns the assigned string ID.
func (e *FilterEngine) Add(spec proto.FilterSpec) (proto.FilterID, error) {
	cf, err := compileFilter(spec)
	if err != nil {
		return "", err
	}
	cf.numID = e.nextID.Add(1)
	id := strconv.FormatUint(uint64(cf.numID), 10)

	e.mu.Lock()
	e.filters[id] = cf
	e.mu.Unlock()

	return id, nil
}

// Remove deletes a filter by ID.
func (e *FilterEngine) Remove(id proto.FilterID) {
	e.mu.Lock()
	delete(e.filters, id)
	e.mu.Unlock()
}

// List returns all active filters paired with their IDs.
func (e *FilterEngine) List() []proto.FilterEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make([]proto.FilterEntry, 0, len(e.filters))

	for id, cf := range e.filters {
		out = append(out, proto.FilterEntry{ID: id, Filter: cf.spec})
	}

	return out
}

// Tap implements DumpTap. Called on every forwarded frame.
func (e *FilterEngine) Tap(f afpacket.Frame) {
	p := parseFrame(f.Data)
	if !p.valid {
		return
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, cf := range e.filters {
		if !cf.matches(p) {
			continue
		}

		// copy payload - f.Data points into mmap, invalid after ReturnBlock
		payload := make([]byte, len(f.Data))
		copy(payload, f.Data)

		df := proto.DumpFrame{
			FilterID:    cf.numID,
			TimeStampNs: uint64(f.Timestamp.UnixNano()),
			WireLen:     f.WireLen,
			Payload:     payload,
		}

		select {
		case e.ch <- df:
		default:
			e.drops.Add(1)
		}
	}
}

// Frames returns the channel the dump server drains.
func (e *FilterEngine) Frames() <-chan proto.DumpFrame { return e.ch }

// Drops returns how many matched frames were dropped dur to a full channel.
func (e *FilterEngine) Drops() uint64 { return e.drops.Load() }

func parseFrame(data []byte) parsedFrame {
	if len(data) < ethHdrLen+20 { // 20 = min IPv4 header
		return parsedFrame{}
	}

	etherType := binary.BigEndian.Uint16(data[12:14])
	if etherType != ethTypeIPv4 {
		return parsedFrame{}
	}

	ip := data[ethHdrLen:]
	ihl := int(ip[0]&0x0f) * 4
	if len(ip) < ihl+4 { // need at least stc/dst ports after IP header
		return parsedFrame{}
	}

	p := parsedFrame{
		srcIP:   net.IP(ip[12:16]),
		dstIP:   net.IP(ip[16:20]),
		ipProto: ip[9],
		valid:   true,
	}

	l4 := ip[ihl:]
	if (p.ipProto == 6 || p.ipProto == 17) && len(l4) >= 4 {
		p.srcPort = binary.BigEndian.Uint16(l4[0:2])
		p.dstPort = binary.BigEndian.Uint16(l4[2:4])
	}

	return p
}

// compileFilter pre-parses CIDR strings in spec.
func compileFilter(spec proto.FilterSpec) (compiledFilter, error) {
	cf := compiledFilter{spec: spec}

	if spec.SrcIP != "" {
		_, n, err := net.ParseCIDR(spec.SrcIP)
		if err != nil {
			// try as plain IP (exact match /32)
			ip := net.ParseIP(spec.SrcIP)
			if ip == nil {
				return cf, fmt.Errorf("invalid src_ip %q", spec.SrcIP)
			}
			n = &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
		}
		cf.srcNet = n
	}
	if spec.DstIP != "" {
		_, n, err := net.ParseCIDR(spec.DstIP)
		if err != nil {
			ip := net.ParseIP(spec.DstIP)
			if ip == nil {
				return cf, fmt.Errorf("invalid dst_ip %q", spec.DstIP)
			}
			n = &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
		}
		cf.dstNet = n
	}

	switch spec.Protocol {
	case "tcp":
		cf.ipProto = 6
	case "udp":
		cf.ipProto = 17
	case "icmp":
		cf.ipProto = 1
	case "":
		cf.ipProto = 0
	default:
		return cf, fmt.Errorf("unknown protocol %q (use tcp/udp/icmp)", spec.Protocol)
	}

	return cf, nil
}
