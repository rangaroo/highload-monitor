package afpacket

// Kernel constants from <linux/if_packet.h> not exposed by golang.org/x/sys/unix.
const (
	// tpacket version enum (TPACKET_V1=0, TPACKET_V2=1, TPACKET_V3=2)
	tpacketV2 = 1 // frame-based TX ring
	tpacketV3 = 2 // block-based RX ring

	// RX block status bits (BlockHeader.Status)
	tpStatusKernel = 0      // kernel owns block
	tpStatusUser   = 1 << 0 // userspace owns block, safe to read

	// TX frame status bits (TXFrameHeader.Status)
	tpStatusAvailable   = 0 // slot free, kernel owns
	tpStatusSendRequest = 1 // userspace filled, ready to send
	tpStatusSending     = 2 // kernel currently transmitting
	tpStatusWrongFormat = 4 // kernel rejected frame (bad length etc.)

	// PACKET_FANOUT subtypes
	packetFanoutHash = 0 // symmetric 5-tuple hash
	packetFanoutLB   = 1 // round-robin
)

// Default ring geometry. Changing these is the primary lever for tuning
// throughput vs memory usage. blockSize must be a multiple of the page size
// (4096 on x86-64) and a multiple of TPACKET_ALIGNMENT (16).
const (
	defaultBlockSize    = 1 << 20 // 1 MiB per block
	defaultBlockCount   = 64      // 64 MiB total RX ring per queue
	defaultBlockTimeout = 64      // ms before kernel retires a partially-filled block
)

// Config holds user-supplied parameters for opening an AF_PACKET RX ring.
// Zero values are replaced with the defaults above when opening.
type Config struct {
	Interface    string // NIC name, e.g. "veth0"
	BlockSize    int    // mmap block size in bytes
	BlockCount   int    // number of blocks in the ring
	BlockTimeout int    // block retirement timeout in milliseconds
	FanoutGroup  uint16 // PACKET_FANOUT group ID; 0 = single-socket, no fanout
	FanoutType   int    // fanout algorithm (packetFanoutHash / packetFanoutLB)
	Promiscuous  bool   // enable promiscuous mode on the interface
}

// Stats mirrors tpacket_stats_v3 from <linux/if_packet.h>.
// Retrieved via getsockopt(PACKET_STATISTICS) on the socket.
//
// Drops > 0 means the RX ring overflowed — packets were lost.
// That is the critical metric for the no-loss requirement.
type Stats struct {
	Packets      uint32 // total packets delivered to the ring
	Drops        uint32 // packets dropped because the ring was full
	FreezeQCount uint32 // times the NIC queue was frozen waiting for ring space
}

// BlockHeader mirrors the fixed-size prefix of tpacket_block_desc.
// It is overlaid directly onto the mmap'd memory — no copy.
//
// Layout in memory (simplified):
//
//	[BlockHeader][...packet data...]
//
// After reading all packets in a block, write tpStatusKernel back into
// Status to return ownership to the kernel.
type BlockHeader struct {
	Version          uint32 // must equal tpacketV3; sanity check on read
	OffsetToPriv     uint32 // ignored in standard usage
	Status           uint32 // tpStatusKernel or tpStatusUser
	NumPkts          uint32 // number of packets packed into this block
	OffsetToFirstPkt uint32 // byte offset from the start of the block to the first PacketHeader
	BlkLen           uint32 // total used length of the block in bytes
	SeqNum           uint64 // monotonically increasing; gaps indicate dropped blocks
}

// PacketHeader mirrors tpacket3_hdr from <linux/if_packet.h>.
// Each packet inside a block begins with this header.
//
// To read the raw frame bytes:
//
//	start := unsafe.Pointer(hdr)
//	frame := (*[65536]byte)(unsafe.Pointer(uintptr(start) + uintptr(hdr.Mac)))[:]
//
// To advance to the next packet:
//
//	if hdr.NextOffset == 0 { break } // last packet in block
//	hdr = (*PacketHeader)(unsafe.Pointer(uintptr(start) + uintptr(hdr.NextOffset)))
type PacketHeader struct {
	NextOffset uint32 // byte offset to the next PacketHeader (0 = last in block)
	Sec        uint32 // capture timestamp — seconds
	Nsec       uint32 // capture timestamp — nanoseconds
	SnapLen    uint32 // bytes captured (may be less than Len if snaplen was set)
	Len        uint32 // original on-wire length of the frame
	Status     uint32 // per-packet status bits (tp_status)
	Mac        uint16 // offset from PacketHeader to the Ethernet header
	Net        uint16 // offset from PacketHeader to the IP header
	// Variable-length padding follows to align the frame on TPACKET_ALIGNMENT.
	// The raw frame bytes start at offset Mac from this struct.
}

// RXRing owns all state for a single TPACKET_V3 receive ring.
// One RXRing maps to one AF_PACKET socket bound to one NIC queue.
// Create via Open; do not copy after creation.
type RXRing struct {
	fd     int      // raw AF_PACKET socket file descriptor
	mmap   []byte   // the entire mmap'd ring region (blockSize * blockCount bytes)
	blocks [][]byte // per-block sub-slices into mmap for fast indexing
	cfg    Config   // resolved configuration (defaults filled in)
	cur    int      // index of the next block to read (wraps at blockCount)
}

// TX ring geometry defaults.
// frameSize must be >= TPACKET2_HDRLEN + max frame bytes, aligned to 16.
// blockSize must be a page multiple; blockSize = frameSize * framesPerBlock.
const (
	defaultTXFrameSize  = 2048 // covers 1500-byte MTU + tpacket2_hdr overhead
	defaultTXFrameCount = 256  // 512 KiB total TX ring per queue
	defaultTXBlockSize  = 4096 // one page per block (2 frames per block)
)

// TXConfig holds parameters for opening a TPACKET_V2 TX ring.
type TXConfig struct {
	Interface  string
	FrameSize  int // default: defaultTXFrameSize
	FrameCount int // default: defaultTXFrameCount
}

// TXFrameHeader mirrors tpacket2_hdr from <linux/if_packet.h>.
// Overlaid on each TX slot in the mmap'd ring.
// Write the frame bytes after this header at offset Mac, then set
// Status = tpStatusSendRequest and call sendmsg to kick the kernel.
type TXFrameHeader struct {
	Status  uint32
	Len     uint32 // frame length (set by kernel on TX completion)
	SnapLen uint32
	Mac     uint16 // offset from header start to frame bytes
	Net     uint16
	Sec     uint32
	Nsec    uint32
	VlanTCI uint16
	VLANID  uint16
	_       [4]byte // padding to TPACKET_ALIGNMENT
}

// TXRing owns all state for a single TPACKET_V2 transmit ring.
// Create via OpenTX; do not copy after creation.
type TXRing struct {
	fd         int
	mmap       []byte
	frames     [][]byte // per-frame slices into mmap
	frameSize  int
	frameCount int
	cur        int // next slot to use
}
