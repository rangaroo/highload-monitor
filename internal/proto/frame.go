package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	frameMagic   uint16 = 0x4846 // "HF"
	frameVersion uint8  = 1
)

// DumpFrame is one captured packet sent from PF to analyzer over TCP
type DumpFrame struct {
	FilterID    uint32 // which active filter matched this packet
	TimeStampNs uint64 // capture time
	WireLen     uint32
	Payload     []byte
}

// FrameWriter encodes DumpFrames onto a stream
type FrameWriter interface {
	WriteFrame(w io.Writer, f *DumpFrame) error
}

// FrameReader decodes DumpFrames into a stream
type FrameReader interface {
	ReadFrame(r io.Reader) (*DumpFrame, error)
}

// NewBinaryFrameWrite returns a FrameWriter using the compact binary format
func NewBinaryFrameWriter() FrameWriter { return binaryFrameRW{} }

// NewBinaryFrameReader returns a FrameReader using the compact binary format
func NewBinaryFrameReader() FrameReader { return binaryFrameRW{} }

// binary wire format is little endian
// [magic u16][version u8][filter_id u32][ts_ns u64][pkt_len u16][payload...]
type binaryFrameRW struct{}

func (binaryFrameRW) WriteFrame(w io.Writer, f *DumpFrame) error {
	payLen := uint16(len(f.Payload))
	hdr := [15]byte{}
	binary.LittleEndian.PutUint16(hdr[0:], frameMagic)
	hdr[2] = frameVersion
	binary.LittleEndian.PutUint32(hdr[3:], f.FilterID)
	binary.LittleEndian.PutUint64(hdr[7:], f.TimeStampNs)
	binary.LittleEndian.PutUint16(hdr[13:], payLen)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(f.Payload)
	return err
}

func (binaryFrameRW) ReadFrame(r io.Reader) (*DumpFrame, error) {
	var hdr [15]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if magic := binary.LittleEndian.Uint16(hdr[0:]); magic != frameMagic {
		return nil, fmt.Errorf("bad frame magic 0x%04x", magic)
	}
	if ver := hdr[2]; ver != frameVersion {
		return nil, fmt.Errorf("unsupported frame version %d", ver)
	}
	payLen := binary.LittleEndian.Uint16(hdr[13:])
	payload := make([]byte, payLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return &DumpFrame{
		FilterID:    binary.LittleEndian.Uint32(hdr[3:]),
		TimeStampNs: binary.LittleEndian.Uint64(hdr[7:]),
		WireLen:     uint32(payLen),
		Payload:     payload,
	}, nil
}
