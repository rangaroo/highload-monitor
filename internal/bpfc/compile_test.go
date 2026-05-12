package bpfc

import (
	"testing"

	"github.com/rangaroo/highload-monitor/internal/proto"
	"golang.org/x/net/bpf"
)

func TestCompileEmpty(t *testing.T) {
	// Empty filter set → accept everything.
	raw, err := Compile(nil)
	if err != nil {
		t.Fatalf("Compile(nil): %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("want 1 instruction (Ret), got %d", len(raw))
	}
}

func TestCompileSingleFilterRunsInVM(t *testing.T) {
	specs := []proto.FilterSpec{
		{SrcIP: "10.0.0.0/8", DstPort: 443, Protocol: "tcp"},
	}
	raw, err := Compile(specs)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// Convert to []bpf.Instruction so we can run via the in-process VM.
	insns := make([]bpf.Instruction, len(raw))
	for i, r := range raw {
		insns[i] = r.Disassemble()
	}
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}

	// Build a synthetic IPv4 TCP frame: Eth + IP + TCP, src 10.1.2.3:1234 → dst 8.8.8.8:443.
	frame := makeFrame(10, 1, 2, 3, 8, 8, 8, 8, 1234, 443, 6 /*TCP*/)
	n, err := vm.Run(frame)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n == 0 {
		t.Fatalf("expected match (non-zero return), got 0")
	}

	// Now a frame that violates the filter: src 192.168.1.1 (not in 10.0.0.0/8).
	frame2 := makeFrame(192, 168, 1, 1, 8, 8, 8, 8, 1234, 443, 6)
	n2, err := vm.Run(frame2)
	if err != nil {
		t.Fatalf("Run2: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("expected no match, got %d", n2)
	}
}

func TestCompileMultiFilterUnion(t *testing.T) {
	specs := []proto.FilterSpec{
		{Protocol: "tcp", DstPort: 443},
		{Protocol: "udp", DstPort: 53},
	}
	raw, err := Compile(specs)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	insns := make([]bpf.Instruction, len(raw))
	for i, r := range raw {
		insns[i] = r.Disassemble()
	}
	vm, err := bpf.NewVM(insns)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}

	// TCP/443 → match
	if n, _ := vm.Run(makeFrame(1, 2, 3, 4, 5, 6, 7, 8, 1000, 443, 6)); n == 0 {
		t.Errorf("TCP/443 should match")
	}
	// UDP/53 → match (second filter)
	if n, _ := vm.Run(makeFrame(1, 2, 3, 4, 5, 6, 7, 8, 1000, 53, 17)); n == 0 {
		t.Errorf("UDP/53 should match")
	}
	// TCP/80 → no match
	if n, _ := vm.Run(makeFrame(1, 2, 3, 4, 5, 6, 7, 8, 1000, 80, 6)); n != 0 {
		t.Errorf("TCP/80 should not match")
	}
}

func TestCompileRejectsBadProtocol(t *testing.T) {
	_, err := Compile([]proto.FilterSpec{{Protocol: "icmp"}})
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestCompileRejectsBadCIDR(t *testing.T) {
	_, err := Compile([]proto.FilterSpec{{SrcIP: "not-a-cidr"}})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

// makeFrame builds a minimal Ethernet + IPv4 + TCP/UDP frame for VM testing.
// Returns a buffer with valid header lengths; payload is empty.
func makeFrame(sa, sb, sc, sd, da, db, dc, dd byte, sport, dport uint16, ipProto byte) []byte {
	const ethHdr = 14
	const ipHdr = 20
	const l4MinHdr = 8 // enough for src/dst port + a couple of fields
	buf := make([]byte, ethHdr+ipHdr+l4MinHdr)

	// Ethernet
	// dst mac 6 bytes (zero), src mac 6 bytes (zero), ethertype = 0x0800
	buf[12] = 0x08
	buf[13] = 0x00

	// IPv4
	buf[ethHdr+0] = 0x45 // version 4, IHL 5 → 20 bytes
	buf[ethHdr+9] = ipProto
	buf[ethHdr+12] = sa
	buf[ethHdr+13] = sb
	buf[ethHdr+14] = sc
	buf[ethHdr+15] = sd
	buf[ethHdr+16] = da
	buf[ethHdr+17] = db
	buf[ethHdr+18] = dc
	buf[ethHdr+19] = dd

	// L4 ports
	off := ethHdr + ipHdr
	buf[off+0] = byte(sport >> 8)
	buf[off+1] = byte(sport)
	buf[off+2] = byte(dport >> 8)
	buf[off+3] = byte(dport)

	return buf
}
