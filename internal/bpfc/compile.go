// Package bpfc compiles a set of FilterSpecs into a classic BPF program
// suitable for attaching to an AF_PACKET socket via SO_ATTACH_FILTER.
//
// The kernel runs the program on every received frame. Frames that no filter
// accepts are dropped before they cross the AF_PACKET RX ring, eliminating
// userspace overhead for traffic we don't care about.
//
// Compiled program structure:
//
//	check ethertype == IPv4              (drop on mismatch)
//	X := IPv4 header length              (BPF_LDX | MSH on byte 14)
//	filter 1: proto, src, dst, sport, dport checks → accept on full match
//	(on any mismatch in filter 1, jump to filter 2 start)
//	filter 2: ...
//	...
//	drop                                 (no filter matched)
//
// cBPF skip counts are u8 (max 255). With ~12 instructions per filter that
// gives a safe ceiling around 20 filters in the union.

package bpfc

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/rangaroo/highload-monitor/internal/proto"
	"golang.org/x/net/bpf"
)

const (
	ethTypeIPv4 = 0x0800
	protoTCP    = 6
	protoUDP    = 17

	// Byte offsets into the frame.
	offEthertype = 12 // Ethernet ethertype field
	offIPStart   = 14 // start of IPv4 header
	offIPProto   = offIPStart + 9
	offIPSrc     = offIPStart + 12
	offIPDst     = offIPStart + 16
	// L4 ports use BPF_IND with X = IPHL, so offsets are relative to that.
	offL4Sport = offIPStart // X holds IPHL, so X+14 lands at first L4 byte
	offL4Dport = offIPStart + 2

	snapLen = 0xFFFF // accept up to 64 KiB; kernel clamps to actual frame
)

// Compile turns a slice of FilterSpecs into a cBPF program.
// An empty input compiles to "accept everything", matching the pre-filter-disabled state.
func Compile(specs []proto.FilterSpec) ([]bpf.RawInstruction, error) {
	if len(specs) == 0 {
		return bpf.Assemble([]bpf.Instruction{bpf.RetConstant{Val: snapLen}})
	}

	// Pre-compile each filter's per-filter instruction sequence so we know
	// its length in advance. Skip targets are resolved in pass 2.
	blocks := make([][]bpf.Instruction, len(specs))
	for i, s := range specs {
		ins, err := compileFilter(s)
		if err != nil {
			return nil, fmt.Errorf("filter %d: %w", i, err)
		}
		blocks[i] = ins
	}

	// Two prologue instructions before the first filter block:
	//   [0] LoadAbsolute{Ethertype, 2}
	//   [1] JumpIf{NotEqual, IPv4, skipToDrop}
	// Then we need an LDX | MSH on byte 14 to put IPHL into X. That's one more.
	//   [2] LoadMemShift{14}
	// After all filter blocks comes the drop instruction.
	//   [tail] RetConstant{0}
	// Plus one accept instruction reached by per-filter "match" jumps.
	//   [tail-1] RetConstant{snapLen}
	//
	// We lay the program out as:
	//   prologue (3 insns)
	//   filter1 (each non-match jump targets filter2 start)
	//   filter2 (each non-match jump targets filter3 start)
	//   ...
	//   filterN (each non-match jump targets DROP)
	//   ACCEPT (1 insn)
	//   DROP   (1 insn)
	// Per-filter, the final instruction is a Jump{} to ACCEPT.

	const prologueLen = 3
	// Total length and per-block start position.
	starts := make([]int, len(blocks)+1) // starts[i] = absolute index where block i begins; starts[N] = after last block
	starts[0] = prologueLen
	for i, b := range blocks {
		starts[i+1] = starts[i] + len(b)
	}
	acceptIdx := starts[len(blocks)]
	dropIdx := acceptIdx + 1
	_ = dropIdx // dropIdx is just acceptIdx+1; used for skip math below

	out := make([]bpf.Instruction, 0, dropIdx+1)

	// Prologue.
	// [0] Load ethertype (2 bytes at offset 12).
	out = append(out, bpf.LoadAbsolute{Off: offEthertype, Size: 2})
	// [1] If not IPv4, skip ahead to DROP.
	out = append(out, bpf.JumpIf{
		Cond:      bpf.JumpNotEqual,
		Val:       ethTypeIPv4,
		SkipTrue:  uint8(dropIdx - 2), // 2 is current PC after this insn executes
		SkipFalse: 0,
	})
	// [2] Load X = (mem[14] & 0xf) << 2 (IPv4 header length in bytes).
	out = append(out, bpf.LoadMemShift{Off: offIPStart})

	// Per-filter blocks. Each block's last instruction is a Jump{} to ACCEPT.
	// Within a block, mismatch jumps target the next block's start (or DROP for the last block).
	for i, block := range blocks {
		nextBlockStart := starts[i+1]
		matchFallThrough := acceptIdx // on full match we end up at ACCEPT
		blockStart := starts[i]

		mismatchTarget := nextBlockStart
		if i == len(blocks)-1 {
			// last filter: mismatch goes to DROP
			mismatchTarget = dropIdx
		}

		patched, err := patchBlock(block, blockStart, mismatchTarget, matchFallThrough)
		if err != nil {
			return nil, fmt.Errorf("patch filter %d: %w", i, err)
		}
		out = append(out, patched...)
	}

	// ACCEPT, DROP.
	out = append(out, bpf.RetConstant{Val: snapLen})
	out = append(out, bpf.RetConstant{Val: 0})

	return bpf.Assemble(out)
}

// compileFilter emits the match instructions for a single FilterSpec.
// Every conditional inside uses placeholder skip values (placeholderSkip)
// which patchBlock rewrites into real PC-relative offsets.
//
// The final instruction of the block is a placeholder Jump{} that
// patchBlock rewrites to land on the ACCEPT instruction.
func compileFilter(s proto.FilterSpec) ([]bpf.Instruction, error) {
	var ins []bpf.Instruction

	// Protocol check.
	if s.Protocol != "" {
		var p uint32
		switch s.Protocol {
		case "tcp":
			p = protoTCP
		case "udp":
			p = protoUDP
		default:
			return nil, fmt.Errorf("unsupported protocol %q (want tcp|udp)", s.Protocol)
		}
		ins = append(ins,
			bpf.LoadAbsolute{Off: offIPProto, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: p, SkipTrue: placeholderSkip},
		)
	}

	// Source IP / CIDR.
	if s.SrcIP != "" {
		ip, mask, err := parseIPOrCIDR(s.SrcIP)
		if err != nil {
			return nil, fmt.Errorf("src_ip: %w", err)
		}
		ins = append(ins,
			bpf.LoadAbsolute{Off: offIPSrc, Size: 4},
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: mask},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: ip, SkipTrue: placeholderSkip},
		)
	}

	// Destination IP / CIDR.
	if s.DstIP != "" {
		ip, mask, err := parseIPOrCIDR(s.DstIP)
		if err != nil {
			return nil, fmt.Errorf("dst_ip: %w", err)
		}
		ins = append(ins,
			bpf.LoadAbsolute{Off: offIPDst, Size: 4},
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: mask},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: ip, SkipTrue: placeholderSkip},
		)
	}

	// Source port (TCP/UDP both put the port at L4+0).
	if s.SrcPort != 0 {
		ins = append(ins,
			bpf.LoadIndirect{Off: offL4Sport, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(s.SrcPort), SkipTrue: placeholderSkip},
		)
	}

	// Destination port.
	if s.DstPort != 0 {
		ins = append(ins,
			bpf.LoadIndirect{Off: offL4Dport, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(s.DstPort), SkipTrue: placeholderSkip},
		)
	}

	// Final instruction: unconditional jump to ACCEPT. Real skip filled in by patchBlock.
	ins = append(ins, bpf.Jump{Skip: placeholderJumpSkip})

	if len(ins) == 1 {
		// Spec was entirely empty (all fields unset).
		// Treat as "match anything" — keep just the final accept jump.
	}
	return ins, nil
}

// placeholderSkip marks JumpIf skip slots (u8) that patchBlock will rewrite.
const placeholderSkip = uint8(0xFF)

// placeholderJumpSkip marks bpf.Jump skip slots (u32) that patchBlock will rewrite.
const placeholderJumpSkip = uint32(0xFFFFFFFF)

// patchBlock rewrites placeholder skip counts in a single filter's instructions
// so that:
//   - every mismatch-jump (a JumpIf with SkipTrue==placeholderSkip) targets mismatchAbs
//   - the final unconditional Jump targets matchAbs
//
// blockStart is the absolute PC index where this block begins in the final program.
func patchBlock(block []bpf.Instruction, blockStart, mismatchAbs, matchAbs int) ([]bpf.Instruction, error) {
	out := make([]bpf.Instruction, len(block))
	for i, ins := range block {
		pc := blockStart + i // PC of this instruction

		switch v := ins.(type) {
		case bpf.JumpIf:
			if v.SkipTrue == placeholderSkip {
				skip := mismatchAbs - (pc + 1)
				if skip < 0 || skip > 255 {
					return nil, fmt.Errorf("skip out of range: %d", skip)
				}
				v.SkipTrue = uint8(skip)
			}
			out[i] = v

		case bpf.Jump:
			if v.Skip == placeholderJumpSkip {
				skip := matchAbs - (pc + 1)
				if skip < 0 || skip > math_maxU32 {
					return nil, fmt.Errorf("match jump skip out of range: %d", skip)
				}
				v.Skip = uint32(skip)
			}
			out[i] = v

		default:
			out[i] = ins
		}
	}
	return out, nil
}

// math_maxU32 is 2^32-1; bpf.Jump.Skip is u32 so this is the practical ceiling.
const math_maxU32 = int(^uint32(0))

// parseIPOrCIDR accepts either an exact IPv4 address ("10.0.0.1") or a CIDR
// ("10.0.0.0/8"). Returns the network address and mask as host-order uint32
// (the cBPF accumulator after LoadAbsolute is host-order on the wire bytes,
// which for IPv4 fields means big-endian - and BPF's K values are compared
// against that as a uint32, so we pack the four bytes via BigEndian).
func parseIPOrCIDR(s string) (ipBE, maskBE uint32, err error) {
	if _, ipnet, e := net.ParseCIDR(s); e == nil {
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			return 0, 0, fmt.Errorf("not IPv4: %s", s)
		}
		return binary.BigEndian.Uint32(ip4), binary.BigEndian.Uint32(ipnet.Mask), nil
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return 0, 0, fmt.Errorf("invalid IP/CIDR: %s", s)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, 0, fmt.Errorf("not IPv4: %s", s)
	}
	return binary.BigEndian.Uint32(ip4), 0xFFFFFFFF, nil
}
