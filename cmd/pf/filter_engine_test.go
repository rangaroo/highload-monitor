package main

import (
	"net"
	"testing"

	"github.com/rangaroo/highload-monitor/internal/proto"
)

func TestParseFrame(t *testing.T) {
	tests := []struct {
		name      string
		frame     []byte
		wantValid bool
		wantProto uint8
	}{
		{
			name:      "truncated",
			frame:     []byte{1, 2, 3},
			wantValid: false,
		},
		{
			name: "non-ipv4",
			frame: func() []byte {
				b := make([]byte, 34)
				// eth type @ 12:14
				b[12], b[13] = 0x08, 0x06 // ARP
				return b
			}(),
			wantValid: false,
		},
		{
			name: "ipv4 tcp",
			frame: func() []byte {
				b := make([]byte, 50) // eth(14) + ip(20) + l4(8+) = 42+
				b[12], b[13] = 0x08, 0x00 // IPv4
				b[14] = 0x45               // version 4, IHL 5 @ offset 14
				b[23] = 6                  // proto TCP @ offset 14+9
				return b
			}(),
			wantValid: true,
			wantProto: 6,
		},
		{
			name: "ipv4 udp",
			frame: func() []byte {
				b := make([]byte, 50)
				b[12], b[13] = 0x08, 0x00 // IPv4
				b[14] = 0x45
				b[23] = 17 // proto UDP @ offset 14+9
				return b
			}(),
			wantValid: true,
			wantProto: 17,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := parseFrame(tt.frame)
			if p.valid != tt.wantValid {
				t.Fatalf("valid=%v, want %v", p.valid, tt.wantValid)
			}
			if tt.wantValid && p.ipProto != tt.wantProto {
				t.Fatalf("proto=%d, want %d", p.ipProto, tt.wantProto)
			}
		})
	}
}

func TestCompiledFilterMatches(t *testing.T) {
	tests := []struct {
		name    string
		filter  compiledFilter
		packet  parsedFrame
		wantOk  bool
	}{
		{
			name: "match all",
			filter: compiledFilter{
				ipProto: 0,
				srcNet:  nil,
				dstNet:  nil,
				spec:    proto.FilterSpec{},
			},
			packet: parsedFrame{
				srcIP:   net.ParseIP("10.0.0.1"),
				dstIP:   net.ParseIP("8.8.8.8"),
				srcPort: 1234,
				dstPort: 443,
				ipProto: 6,
				valid:   true,
			},
			wantOk: true,
		},
		{
			name: "match protocol",
			filter: compiledFilter{
				ipProto: 6, // TCP
				srcNet:  nil,
				dstNet:  nil,
				spec:    proto.FilterSpec{Protocol: "tcp"},
			},
			packet: parsedFrame{
				srcIP:   net.ParseIP("10.0.0.1"),
				dstIP:   net.ParseIP("8.8.8.8"),
				ipProto: 6,
				valid:   true,
			},
			wantOk: true,
		},
		{
			name: "mismatch protocol",
			filter: compiledFilter{
				ipProto: 6, // TCP
				srcNet:  nil,
				dstNet:  nil,
				spec:    proto.FilterSpec{Protocol: "tcp"},
			},
			packet: parsedFrame{
				ipProto: 17, // UDP
				valid:   true,
			},
			wantOk: false,
		},
		{
			name: "match src cidr",
			filter: compiledFilter{
				ipProto: 0,
				srcNet: func() *net.IPNet {
					_, n, _ := net.ParseCIDR("10.0.0.0/8")
					return n
				}(),
				dstNet: nil,
				spec:   proto.FilterSpec{SrcIP: "10.0.0.0/8"},
			},
			packet: parsedFrame{
				srcIP:   net.ParseIP("10.1.2.3"),
				dstIP:   net.ParseIP("192.168.1.1"),
				ipProto: 0,
				valid:   true,
			},
			wantOk: true,
		},
		{
			name: "mismatch src cidr",
			filter: compiledFilter{
				ipProto: 0,
				srcNet: func() *net.IPNet {
					_, n, _ := net.ParseCIDR("10.0.0.0/8")
					return n
				}(),
				dstNet: nil,
				spec:   proto.FilterSpec{SrcIP: "10.0.0.0/8"},
			},
			packet: parsedFrame{
				srcIP:   net.ParseIP("192.168.1.1"),
				dstIP:   net.ParseIP("8.8.8.8"),
				ipProto: 0,
				valid:   true,
			},
			wantOk: false,
		},
		{
			name: "match dst port",
			filter: compiledFilter{
				ipProto: 0,
				srcNet:  nil,
				dstNet:  nil,
				spec:    proto.FilterSpec{DstPort: 443},
			},
			packet: parsedFrame{
				srcIP:   net.ParseIP("10.0.0.1"),
				dstIP:   net.ParseIP("8.8.8.8"),
				srcPort: 1234,
				dstPort: 443,
				ipProto: 0,
				valid:   true,
			},
			wantOk: true,
		},
		{
			name: "mismatch dst port",
			filter: compiledFilter{
				ipProto: 0,
				srcNet:  nil,
				dstNet:  nil,
				spec:    proto.FilterSpec{DstPort: 443},
			},
			packet: parsedFrame{
				dstPort: 80,
				valid:   true,
			},
			wantOk: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.matches(tt.packet); got != tt.wantOk {
				t.Fatalf("matches=%v, want %v", got, tt.wantOk)
			}
		})
	}
}
