package afpacket

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var cursorPool = sync.Pool{
	New: func() any { return new(BlockCursor) },
}

// Frame is a zero-copy view of one captured packet inside an RX block.
// Data points into mmap'd memory. Do not hold it after calling ReturnBlock.
type Frame struct {
	Data      []byte
	Timestamp time.Time
	SnapLen   uint32
	WireLen   uint32
}

// PollBlock() blocks until the next ring block is ready and returns a cursor.
// timeoutMs is passed to poll(2); use -1 to block indefinitely.
// Returns (nil, nil) on timeout.
func (r *RXRing) PollBlock(timeoutMs int) (*BlockCursor, error) {
	for {
		hdr := r.blockHeader(r.cur)

		if hdr.Status&tpStatusUser != 0 {
			c := cursorPool.Get().(*BlockCursor)
			*c = BlockCursor{
				ring:  r,
				idx:   r.cur,
				hdr:   hdr,
				count: int(hdr.NumPkts),
			}
			r.cur = (r.cur + 1) % len(r.blocks)
			return c, nil
		}

		if r.fd < 0 {
			return nil, nil // Interrupt() was called; signal clean shutdown
		}
		fds := []unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN | unix.POLLERR}}
		n, err := unix.Poll(fds, timeoutMs)
		if err != nil {
			if err == unix.EINTR {
				continue // signal interrupted poll; retry
			}
			if err == unix.EBADF {
				return nil, nil // fd closed by Interrupt(); clean shutdown
			}
			return nil, err
		}
		if n == 0 {
			return nil, nil // timeout
		}
	}
}

// BlockCursor iterates packets inside one RX block.
type BlockCursor struct {
	ring  *RXRing
	idx   int
	hdr   *BlockHeader
	count int
	pos   int
	cur   uintptr // pointer to current PacketHeader in mmap'd memory
}

// Next returns the next Frame in the block.
// Returns (Frame{}, false) when the block is exhausted.
func (c *BlockCursor) Next() (Frame, bool) {
	if c.pos >= c.count {
		return Frame{}, false
	}

	if c.pos == 0 {
		// first packet starts at OffsetToFirstPkt from block base.
		blockBase := uintptr(unsafe.Pointer(&c.ring.blocks[c.idx][0]))
		c.cur = blockBase + uintptr(c.hdr.OffsetToFirstPkt)
	}

	pkt := (*PacketHeader)(unsafe.Pointer(c.cur)) //nolint:unsafeptr
	f := Frame{
		Data:      unsafe.Slice((*byte)(unsafe.Pointer(c.cur+uintptr(pkt.Mac))), pkt.SnapLen),
		Timestamp: time.Unix(int64(pkt.Sec), int64(pkt.Nsec)),
		SnapLen:   pkt.SnapLen,
		WireLen:   pkt.Len,
	}

	if pkt.NextOffset != 0 {
		c.cur += uintptr(pkt.NextOffset)
	}
	c.pos++
	return f, true
}

// ReturnBlock gives the block back to the kernel and returns the cursor to the pool.
// Must be called exactly once. All Frame values from this cursor are invalid after.
func (c *BlockCursor) ReturnBlock() {
	c.hdr.Status = tpStatusKernel
	cursorPool.Put(c)
}

// Len returns the total number of packets in this block.
func (c *BlockCursor) Len() int { return c.count }

// blockHeader casts the start of block i to a *BlockHeader.
func (r *RXRing) blockHeader(i int) *BlockHeader {
	return (*BlockHeader)(unsafe.Pointer(&r.blocks[i][0])) //nolint:unsafeptr
}
