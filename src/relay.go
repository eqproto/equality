package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// RelayConfig holds configuration for relay operations
type RelayConfig struct {
	Clock     time.Duration
	FrameSize int
	Verbose   bool
}

// DirectionalRelay handles bidirectional communication between two connections
type DirectionalRelay struct {
	ctx       context.Context
	proto     net.Conn      // Protocol connection (EQ side)
	plain     net.Conn      // Plain connection
	config    RelayConfig
	closeChan chan struct{}
	once      sync.Once
	wg        sync.WaitGroup
}

// NewDirectionalRelay creates a new relay for bidirectional communication
func NewDirectionalRelay(ctx context.Context, proto, plain net.Conn, cfg RelayConfig) *DirectionalRelay {
	return &DirectionalRelay{
		ctx:       ctx,
		proto:     proto,
		plain:     plain,
		config:    cfg,
		closeChan: make(chan struct{}),
	}
}

// Start begins bidirectional relaying
func (r *DirectionalRelay) Start() error {
	defer r.cleanup()

	r.wg.Add(2)

	errChan := make(chan error, 2)

	// Protocol -> Plain: read EQ frames, write plain data
	go func() {
		defer r.wg.Done()
		errChan <- r.recvFrames()
	}()

	// Plain -> Protocol: read plain data, send in EQ frames
	go func() {
		defer r.wg. Done()
		errChan <- r.sendFrames()
	}()

	r.wg.Wait()
	close(errChan)

	var retErr error
	for err := range errChan {
		if err != nil && retErr == nil {
			retErr = err
		}
	}

	return retErr
}

// recvFrames reads EQ frames and writes plain data
func (r *DirectionalRelay) recvFrames() error {
	buf := make([]byte, r. config.FrameSize)

	for {
		select {
		case <-r. ctx.Done():
			return r.ctx.Err()
		case <-r.closeChan:
			return nil
		default:
		}

		// Set read deadline
		deadline := time.Now().Add(5 * time.Second)
		if err := r.proto.SetReadDeadline(deadline); err != nil {
			return fmt.Errorf("set read deadline: %w", err)
		}

		n, err := io.ReadFull(r.proto, buf)

		// Clear deadline
		_ = r.proto.SetReadDeadline(time.Time{})

		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			if netErr, ok := err.(net. Error); ok && netErr. Timeout() {
				continue
			}
			return fmt. Errorf("read frame: %w", err)
		}

		if n != r. config.FrameSize {
			return fmt.Errorf("incomplete frame: got %d bytes, expected %d", n, r.config.FrameSize)
		}

		frame := &Frame{}
		if err := frame.Unmarshal(buf); err != nil {
			return fmt.Errorf("unmarshal frame: %w", err)
		}

		switch frame.Type {
		case TypeData:
			if len(frame.Data) > 0 {
				if _, err := r.plain.Write(frame.Data); err != nil {
					return fmt.Errorf("write plain data: %w", err)
				}
			}

		case TypePadding:
			// Ignore padding

		case TypeClose:
			return nil

		default:
			return fmt.Errorf("unknown frame type: %d", frame.Type)
		}
	}
}

// sendFrames reads plain data and sends in EQ frames
func (r *DirectionalRelay) sendFrames() error {
	ticker := time.NewTicker(r.config.Clock)
	defer ticker.Stop()

	readBuf := make([]byte, 65535)
	pending := make([]byte, 0, MaxPendingBytes)
	dataSize := r.config.FrameSize - 3

	plainClosed := false

	for {
		select {
		case <-r.ctx. Done():
			return sendCloseFrame(r.proto, r.config. FrameSize)

		case <-r.closeChan:
			return sendCloseFrame(r.proto, r.config.FrameSize)

		case <-ticker. C:
			// Try to read more data if space available
			if ! plainClosed && len(pending) < MaxPendingBytes {
				deadline := time.Now().Add(time. Millisecond)
				if err := r.plain.SetReadDeadline(deadline); err != nil {
					return fmt.Errorf("set read deadline: %w", err)
				}

				n, err := r.plain.Read(readBuf)

				_ = r.plain.SetReadDeadline(time.Time{})

				if n > 0 {
					pending = append(pending, readBuf[:n]...)
				}

				if err == io.EOF {
					plainClosed = true
				} else if err != nil {
					if netErr, ok := err.(net.Error); ! ok || !netErr.Timeout() {
						plainClosed = true
					}
				}
			}

			// Send data frame if available, otherwise padding
			if plainClosed && len(pending) == 0 {
				return sendCloseFrame(r.proto, r.config.FrameSize)
			}

			if len(pending) > 0 {
				size := len(pending)
				if size > dataSize {
					size = dataSize
				}

				frame := &Frame{
					Type:   TypeData,
					Length: uint16(size),
					Data:   pending[:size],
				}

				frameBytes, err := frame.Marshal(r.config.FrameSize)
				if err != nil {
					return fmt.Errorf("marshal frame: %w", err)
				}

				if _, err := r.proto.Write(frameBytes); err != nil {
					return fmt.Errorf("write frame: %w", err)
				}

				pending = pending[size:]
			} else {
				frame := &Frame{
					Type:   TypePadding,
					Length: 0,
				}

				frameBytes, err := frame. Marshal(r.config.FrameSize)
				if err != nil {
					return fmt. Errorf("marshal padding frame: %w", err)
				}

				if _, err := r.proto.Write(frameBytes); err != nil {
					return fmt.Errorf("write padding frame: %w", err)
				}
			}
		}
	}
}

// Close gracefully closes the relay
func (r *DirectionalRelay) Close() {
	r.once.Do(func() {
		close(r.closeChan)
	})
}

// cleanup closes connections safely
func (r *DirectionalRelay) cleanup() {
	_ = r.proto.Close()
	_ = r.plain.Close()
}

// sendCloseFrame sends a close frame
func sendCloseFrame(conn net.Conn, frameSize int) error {
	frame := &Frame{
		Type:   TypeClose,
		Length: 0,
	}

	buf, err := frame.Marshal(frameSize)
	if err != nil {
		return err
	}

	_, err = conn.Write(buf)
	return err
}

// ClientRelay handles client-side (SOCKS -> EQ) relaying
func ClientRelay(ctx context.Context, socksConn, eqConn net.Conn, cfg RelayConfig) error {
	relay := NewDirectionalRelay(ctx, eqConn, socksConn, cfg)
	return relay.Start()
}

// ServerRelay handles server-side (EQ -> target) relaying
func ServerRelay(ctx context.Context, eqConn, targetConn net.Conn, cfg RelayConfig) error {
	relay := NewDirectionalRelay(ctx, eqConn, targetConn, cfg)
	return relay.Start()
}