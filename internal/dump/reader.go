// Package dump consumes the pf TCP dump stream.
//
// One persistent TCP connection per analyzer. Framing handled by
// proto.NewBinaryFrameReader. The Run loop dials, then pumps DumpFrames
// to the provided handler until ctx is canceled or the connection closes.
package dump

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/rangaroo/highload-monitor/internal/proto"
)

// Handler receives one frame at a time. It MUST return quickly - the read
// loop blocks on it. Heavy stat work belongs in a goroutine fed by a channel
// the handler writes to.
type Handler func(*proto.DumpFrame)

// Run dials addr, then reads frames forever, dispatching each to h.
//
// On disconnect or error it sleeps backoff and reconnects, indefinitely.
// Returns only when ctx is canceled. Per-error logging is the caller's job -
// Run swallows transient errors silently so a slow analyzer cluster doesn't
// flood logs.
func Run(ctx context.Context, addr string, h Handler) error {
	const (
		minBackoff = 200 * time.Millisecond
		maxBackoff = 5 * time.Second
	)
	backoff := minBackoff

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		conn, err := dial(ctx, addr)
		if err != nil {
			if !sleep(ctx, backoff) {
				return ctx.Err()
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = minBackoff

		readErr := pump(ctx, conn, h)
		_ = conn.Close()

		if errors.Is(readErr, context.Canceled) {
			return readErr
		}
		// any other error: reconnect after backoff
		if !sleep(ctx, backoff) {
			return ctx.Err()
		}
	}
}

func dial(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	d.Timeout = 3 * time.Second
	return d.DialContext(ctx, "tcp", addr)
}

func pump(ctx context.Context, conn net.Conn, h Handler) error {
	reader := proto.NewBinaryFrameReader()
	br := bufio.NewReaderSize(conn, 64*1024)

	// Tie reads to ctx via a goroutine that closes the conn when ctx is done.
	// Without this io.ReadFull would block past cancellation.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-done:
		}
	}()

	for {
		frame, err := reader.ReadFrame(br)
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("dump: connection closed by pf")
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("dump read: %w", err)
		}
		h(frame)
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
