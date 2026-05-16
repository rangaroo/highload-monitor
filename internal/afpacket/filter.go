package afpacket

import (
	"fmt"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// AttachFilter loads a compiled classic BPF program into the kernel and
// attaches it to this socket via SO_ATTACH_FILTER. The kernel runs the
// program on every received frame; frames the program returns 0 for are
// dropped before they enter the RX ring, so they never cost userspace
// cycles.
//
// Calling AttachFilter again replaces any previously attached filter
// atomically (the kernel does this for us - no detach needed in between).
//
// Caller owns the slice; we copy what we need before the syscall returns.
func (r *RXRing) AttachFilter(raw []bpf.RawInstruction) error {
	if len(raw) == 0 {
		return fmt.Errorf("empty BPF program")
	}
	if len(raw) > 0xFFFF {
		return fmt.Errorf("BPF program too long: %d insns (max 65535)", len(raw))
	}

	// bpf.RawInstruction has identical layout to struct sock_filter
	// (u16 code, u8 jt, u8 jf, u32 k) so we can hand the kernel the slice
	// pointer directly. The kernel copies the program internally during
	// setsockopt, so the slice can be freed after this returns.
	prog := unix.SockFprog{
		Len:    uint16(len(raw)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&raw[0])),
	}

	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(r.fd),
		unix.SOL_SOCKET,
		unix.SO_ATTACH_FILTER,
		uintptr(unsafe.Pointer(&prog)),
		unsafe.Sizeof(prog),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("setsockopt SO_ATTACH_FILTER: %w", errno)
	}
	return nil
}

// DetachFilter removes any classic BPF program currently attached to the
// socket. Safe to call when no filter is attached - the kernel returns
// ENOENT, which we squash.
func (r *RXRing) DetachFilter() error {
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(r.fd),
		unix.SOL_SOCKET,
		unix.SO_DETACH_FILTER,
		0, 0, 0,
	)
	if errno != 0 && errno != unix.ENOENT && errno != unix.EINVAL {
		return fmt.Errorf("setsockopt SO_DETACH_FILTER: %w", errno)
	}
	return nil
}
