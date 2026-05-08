package afpacket

import (
	"fmt"
	"net"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// OpenTX opens an AF_PACKET socket with a TPACKET_V2 TX ring bound to cfg.Interface
func OpenTX(cfg TXConfig) (*TXRing, error) {
	if cfg.FrameSize == 0 {
		cfg.FrameSize = defaultTXFrameSize
	}
	if cfg.FrameCount == 0 {
		cfg.FrameCount = defaultTXFrameCount
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	ok := false
	defer func() {
		if !ok {
			unix.Close(fd)
		}
	}()

	// switch to TPACKET_V2 for the TX ring
	v := uint32(tpacketV2)
	if err := setsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, v); err != nil {
		return nil, fmt.Errorf("set PACKET_VERSION: %w", err)
	}

	// blockSize must be a page multiple; two frames per block
	blockSize := defaultTXBlockSize
	if blockSize < cfg.FrameSize {
		blockSize = cfg.FrameSize * 2
	}
	blockNr := (cfg.FrameSize * cfg.FrameCount) / blockSize

	req := unix.TpacketReq{
		Block_size: uint32(blockSize),
		Block_nr:   uint32(blockNr),
		Frame_size: uint32(cfg.FrameSize),
		Frame_nr:   uint32(cfg.FrameCount),
	}
	if err := setsockoptTpacketReq(fd, unix.SOL_PACKET, unix.PACKET_TX_RING, req); err != nil {
		return nil, fmt.Errorf("set PACKET_TX_RING: %w", err)
	}

	mmapSize := blockSize * blockNr
	mmap, err := unix.Mmap(fd, 0, mmapSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap: %w", err)
	}

	frames := make([][]byte, cfg.FrameCount)
	for i := range frames {
		start := i * cfg.FrameSize
		frames[i] = mmap[start : start+cfg.FrameSize]
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		unix.Munmap(mmap)
		return nil, fmt.Errorf("interface %q: %w", cfg.Interface, err)
	}
	sll := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, &sll); err != nil {
		unix.Munmap(mmap)
		return nil, fmt.Errorf("bind: %w", err)
	}

	ok = true
	return &TXRing{
		fd:         fd,
		mmap:       mmap,
		frames:     frames,
		frameSize:  cfg.FrameSize,
		frameCount: cfg.FrameCount,
	}, nil
}

// Send copies frame into the next available TX slot and signals the kernel to send it.
// Blocks with poll(2) if the ring is full.
// frame must be a raw Ethernet frame (L2 and up), max frameSize - sizeof(TXFrameHeader) bytes.
func (t *TXRing) Send(frame []byte) error {
	hdr := t.waitForSlot()

	// mac offset = size of TXFrameHeader (aligned to TPACKET_ALIGNMENT=16)
	const macOffset = uint16(32) // sizeof(TXFrameHeader) padded to 16-byte boundary
	dst := t.frames[t.cur][macOffset:]
	n := copy(dst, frame)

	hdr.Mac = macOffset
	hdr.Len = uint32(n)
	hdr.SnapLen = uint32(n)

	// mark slot ready - kernel sends after sendmsg
	atomic.StoreUint32(&hdr.Status, tpStatusSendRequest)

	t.cur = (t.cur + 1) % t.frameCount

	// kick the kernel; MSG_DONTWAIT so we don't block if TX queue is briefly busy
	_, err := unix.SendmsgN(t.fd, nil, nil, nil, unix.MSG_DONTWAIT)
	if err == unix.EAGAIN || err == unix.ENOBUFS {
		err = nil // kernel will drain and pick up pending frames
	}
	return err
}

// Close releases the mmap and closes the socket
func (t *TXRing) Close() error {
	unix.Munmap(t.mmap)
	return unix.Close(t.fd)
}

// waitForSlot spins+polls until the current slot is available (kernel-owned)
func (t *TXRing) waitForSlot() *TXFrameHeader {
	for {
		hdr := (*TXFrameHeader)(unsafe.Pointer(&t.frames[t.cur][0])) //nolint:unsafeptr
		status := atomic.LoadUint32(&hdr.Status)
		if status == tpStatusAvailable {
			return hdr
		}
		// ring full: poll until kernel frees at least one slot
		fds := []unix.PollFd{{Fd: int32(t.fd), Events: unix.POLLOUT | unix.POLLERR}}
		unix.Poll(fds, -1) //nolint:errcheck
	}
}

// setsockoptTpacketReq calls setsockopt with a TpacketReq (V1/V2) value.
func setsockoptTpacketReq(fd, level, opt int, req unix.TpacketReq) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(opt),
		uintptr(unsafe.Pointer(&req)),
		unsafe.Sizeof(req),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
