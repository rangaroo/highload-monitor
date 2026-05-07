package afpacket

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

func Open(cfg Config) (*RXRing, error) {
	cfg = applyDefaults(cfg)

	// raw L2 socket
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

	// switch to TPACKET_V3
	v := uint32(tpacketV3)
	if err := setsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, v); err != nil {
		return nil, fmt.Errorf("set PACKET_VERSION: %w", err)
	}

	req := unix.TpacketReq3{
		Block_size:     uint32(cfg.BlockSize),
		Block_nr:       uint32(cfg.BlockCount),
		Frame_size:     uint32(cfg.BlockSize),
		Frame_nr:       uint32(cfg.BlockCount),
		Retire_blk_tov: uint32(cfg.BlockTimeout),
	}
	if err := setsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, req); err != nil {
		return nil, fmt.Errorf("set PACKET_RX_RING: %w", err)
	}

	// mmap the ring into userspace
	// Size = blockSize * blockCount. The mapping is shared (MAP_SHARED)
	// so writes by the kernel are immediately visible here.
	mmapSize := cfg.BlockSize * cfg.BlockCount
	mmap, err := unix.Mmap(fd, 0, mmapSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap: %w", err)
	}

	// build per-block sub-slices so we can index by block number without
	// pointer arithmetic at read time.
	blocks := make([][]byte, cfg.BlockCount)
	for i := range blocks {
		start := i * cfg.BlockSize
		blocks[i] = mmap[start : start+cfg.BlockSize]
	}

	// bind the chosen interface
	// SLL = sockaddr_ll; ifindex identifies the NIC
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

	// optionally enable promiscuous mode
	// in promisc mode the NIC hands up frames destined for other MACs too
	if cfg.Promiscuous {
		mreq := unix.PacketMreq{
			Ifindex: int32(iface.Index),
			Type:    unix.PACKET_MR_PROMISC,
		}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
			unix.Munmap(mmap)
			return nil, fmt.Errorf("promisc: %w", err)
		}
	}

	// optionally join a PACKET_FANOUT group
	// multiple sockets in the same group share NIC traffic
	// each gets a different subset of packets; together they see all traffic
	// the fanout type (hash/LB) determines how packets are partitioned
	if cfg.FanoutGroup != 0 {
		fanoutVal := uint32(cfg.FanoutGroup) | (uint32(cfg.FanoutType) << 16)
		if err := setsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT, fanoutVal); err != nil {
			unix.Munmap(mmap)
			return nil, fmt.Errorf("fanout: %w", err)
		}
	}

	ok = true
	return &RXRing{
		fd:     fd,
		mmap:   mmap,
		blocks: blocks,
		cfg:    cfg,
	}, nil
}

// Close() releases the mmap and closes the socket
func (r *RXRing) Close() error {
	unix.Munmap(r.mmap)
	return unix.Close(r.fd)
}

// Stats() returns the kernel's drop counters for this socket
func (r *RXRing) Stats() (Stats, error) {
	// tpacket_stats_v3 is 12 bytes: packets u32, drops u32, freeze_q_cnt u32
	var raw [12]byte
	size := uint32(len(raw))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(r.fd),
		unix.SOL_PACKET,
		unix.PACKET_STATISTICS,
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return Stats{}, fmt.Errorf("getsockopt PACKET_STATISTICS: %w", errno)
	}
	return Stats{
		Packets:      *(*uint32)(unsafe.Pointer(&raw[0])),
		Drops:        *(*uint32)(unsafe.Pointer(&raw[4])),
		FreezeQCount: *(*uint32)(unsafe.Pointer(&raw[8])),
	}, nil
}

// FD returns the raw socket file descriptor, needed for poll(2).
func (r *RXRing) FD() int { return r.fd }

// BlockSize returns the configured block size in bytes.
func (r *RXRing) BlockSize() int { return r.cfg.BlockSize }

// BlockCount returns the number of blocks in the ring.
func (r *RXRing) BlockCount() int { return r.cfg.BlockCount }

// applyDefaults fills in zero Config fields with the package defaults.
func applyDefaults(cfg Config) Config {
	if cfg.BlockSize == 0 {
		cfg.BlockSize = defaultBlockSize
	}
	if cfg.BlockCount == 0 {
		cfg.BlockCount = defaultBlockCount
	}
	if cfg.BlockTimeout == 0 {
		cfg.BlockTimeout = defaultBlockTimeout
	}
	return cfg
}

// htons converts a uint16 from host to network byte order (big-endian)
func htons(v uint16) uint16 {
	return (v>>8)&0xff | (v&0xff)<<8
}

// setsockoptInt calls setsockopt with a uint32 value
func setsockoptInt(fd, level, opt int, val uint32) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(opt),
		uintptr(unsafe.Pointer(&val)),
		4,
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// setsockoptTpacketReq3 calls setsockopt with a TpacketReq3 value.
func setsockoptTpacketReq3(fd, level, opt int, req unix.TpacketReq3) error {
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
