package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// Server manages the main proxy server
type Server struct {
	config      *Config
	ctx         context.Context
	cancel      context.CancelFunc
	activeConns sync.WaitGroup
	verbose     bool
}

// NewServer creates a new server instance
func NewServer(cfg *Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		config:  cfg,
		ctx:     ctx,
		cancel:  cancel,
		verbose: cfg. Verbose,
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt. Fprintf(os.Stderr, "Usage: %s <config.xml>\n", os.Args[0])
		os.Exit(1)
	}

	cfg, err := LoadConfig(os. Args[1])
	if err != nil {
		log. Fatalf("Failed to load config: %v", err)
	}

	if err := ValidateConfig(cfg); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	server := NewServer(cfg)

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall. SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nReceived shutdown signal, gracefully closing connections...")
		server. Shutdown()
	}()

	// Start appropriate mode
	if cfg.In.Type == "socks" {
		if err := server.RunClient(); err != nil {
			log. Fatalf("Client error: %v", err)
		}
	} else if cfg.In.Type == "eq" {
		if err := server.RunServer(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	} else {
		log.Fatalf("Unknown mode: %s (expected 'socks' or 'eq')", cfg.In.Type)
	}
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() {
	s.cancel()

	shutdownTimeout := 10 * time.Second
	if s.config.ShutdownTimeout > 0 {
		shutdownTimeout = time.Duration(s.config.ShutdownTimeout) * time.Second
	}

	done := make(chan struct{})
	go func() {
		s.activeConns.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("All connections closed gracefully")
	case <-time.After(shutdownTimeout):
		log.Println("Timeout waiting for connections, forcing exit")
	}
	os.Exit(0)
}

// RunClient runs the SOCKS5 client mode
func (s *Server) RunClient() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.In.Port))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	log.Printf("Client listening on :%d (SOCKS5)", s.config.In.Port)
	log.Printf("Forwarding to %s:%d with frame=%d, clock=%dms",
		s.config.Out. Server, s.config.Out.Port, s.config.Out.Frame, s.config.Out.Clock)

	for {
		select {
		case <-s. ctx.Done():
			return nil
		default:
		}

		// Set accept timeout to allow shutdown checks
		if tcpLn, ok := ln.(*net.TCPListener); ok {
			tcpLn.SetDeadline(time.Now().Add(time.Second))
		}

		conn, err := ln.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			select {
			case <-s. ctx.Done():
				return nil
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		s.activeConns.Add(1)
		go func() {
			defer s.activeConns.Done()
			if err := s.handleSOCKS(conn); err != nil {
				if s.verbose {
					log.Printf("SOCKS error: %v", err)
				}
			}
		}()
	}
}

// handleSOCKS processes a SOCKS5 client connection
func (s *Server) handleSOCKS(conn net.Conn) error {
	defer conn.Close()

	// Read SOCKS version identifier/method selection message
	buf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(DefaultTimeout))
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		return fmt.Errorf("read handshake: %w", err)
	}

	if n < 2 || buf[0] != 5 {
		return fmt. Errorf("invalid SOCKS version: %d", buf[0])
	}

	if err := SOCKS5AuthResponse(conn); err != nil {
		return fmt.Errorf("write auth response: %w", err)
	}

	// Read SOCKS request
	conn.SetReadDeadline(time.Now().Add(DefaultTimeout))
	n, err = conn. Read(buf)
	conn. SetReadDeadline(time. Time{})

	if err != nil {
		return fmt. Errorf("read request: %w", err)
	}

	host, port, err := ParseSOCKS5Request(buf[:n])
	if err != nil {
		SOCKS5ErrorResponse(conn, SOCKS5ErrorUnsupportedAddr)
		return fmt.Errorf("parse request: %w", err)
	}

	target := FormatTarget(host, port)

	// Connect to EQ server
	eqConn, err := s.connectToServer(target)
	if err != nil {
		SOCKS5ErrorResponse(conn, SOCKS5ErrorConnectionFailed)
		return fmt. Errorf("connect to server: %w", err)
	}
	defer eqConn.Close()

	if err := SOCKS5SuccessResponse(conn); err != nil {
		return fmt.Errorf("write success response: %w", err)
	}

	log.Printf("Proxying: %s -> %s", conn.RemoteAddr(), target)

	cfg := RelayConfig{
		Clock:     time.Duration(s.config.Out.Clock) * time.Millisecond,
		FrameSize: s.config.Out.Frame,
		Verbose:   s.verbose,
	}

	if err := ClientRelay(s.ctx, conn, eqConn, cfg); err != nil {
		if s.verbose {
			log. Printf("Relay error: %v", err)
		}
	}

	log.Printf("Closed: %s -> %s", conn.RemoteAddr(), target)
	return nil
}

// connectToServer establishes a TLS connection to the EQ server
func (s *Server) connectToServer(target string) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", s.config.Out.Server, s.config.Out.Port)

	tlsConfig := &tls.Config{
		ServerName:         s.config.Out.Server,
		InsecureSkipVerify: false,
	}

	ctx, cancel := context.WithTimeout(s.ctx, DefaultTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	tlsConn := tls.Client(conn, tlsConfig)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	if err := s.sendAuth(tlsConn, target, nonce); err != nil {
		tlsConn.Close()
		return nil, fmt. Errorf("auth: %w", err)
	}

	return tlsConn, nil
}

// sendAuth sends authentication frame to server
func (s *Server) sendAuth(conn net.Conn, target string, nonce []byte) error {
	conn.SetWriteDeadline(time.Now().Add(DefaultTimeout))
	defer conn.SetWriteDeadline(time.Time{})

	frame, err := BuildAuthFrame(s.config.Out.SID, target, nonce, s.config.Out.Frame)
	if err != nil {
		return fmt.Errorf("build auth frame: %w", err)
	}

	buf, err := frame.Marshal(s.config.Out.Frame)
	if err != nil {
		return fmt.Errorf("marshal auth frame: %w", err)
	}

	_, err = conn.Write(buf)
	return err
}

// RunServer runs the EQ server mode
func (s *Server) RunServer() error {
	ln, err := s.createListener()
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	addr := fmt.Sprintf(":%d", s.config.In.Port)
	log.Printf("Server listening on %s (frame=%d, clock=%dms)", addr, s.config.In.Frame, s.config.In.Clock)
	if s.config.In.SSL != nil {
		log.Printf("TLS enabled")
	}

	for {
		select {
		case <-s. ctx.Done():
			return nil
		default:
		}

		if tcpLn, ok := ln. (*net.TCPListener); ok {
			tcpLn. SetDeadline(time.Now().Add(time.Second))
		}

		conn, err := ln.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			select {
			case <-s.ctx.Done():
				return nil
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		s.activeConns.Add(1)
		go func() {
			defer s.activeConns.Done()
			if err := s.handleClient(conn); err != nil {
				if s.verbose {
					log.Printf("Client error: %v", err)
				}
			}
		}()
	}
}

// createListener creates appropriate listener (TLS or plain)
func (s *Server) createListener() (net.Listener, error) {
	addr := fmt.Sprintf(":%d", s.config.In.Port)

	if s.config.In. SSL != nil {
		cert, err := tls.LoadX509KeyPair(s.config.In.SSL.Crt, s.config.In. SSL.Key)
		if err != nil {
			return nil, fmt.Errorf("load certificates: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		return tls.Listen("tcp", addr, tlsConfig)
	}

	return net.Listen("tcp", addr)
}

// handleClient processes an EQ client connection
func (s *Server) handleClient(eqConn net.Conn) error {
	defer eqConn.Close()

	// Read auth frame with timeout
	buf := make([]byte, s.config.In.Frame)
	eqConn.SetReadDeadline(time.Now(). Add(DefaultTimeout))
	n, err := io.ReadFull(eqConn, buf)
	eqConn.SetReadDeadline(time.Time{})

	if err != nil {
		return fmt.Errorf("read auth frame: %w", err)
	}

	if n != s.config.In.Frame {
		return fmt.Errorf("incomplete auth frame: got %d, expected %d", n, s. config.In.Frame)
	}

	frame := &Frame{}
	if err := frame. Unmarshal(buf); err != nil {
		return fmt.Errorf("unmarshal auth frame: %w", err)
	}

	if frame.Type != TypeAuth {
		return fmt. Errorf("expected auth frame, got type %d", frame.Type)
	}

	auth, err := ParseAuthData(frame.Data)
	if err != nil {
		return fmt.Errorf("parse auth data: %w", err)
	}

	if ! IsAuthTimestampValid(auth.Timestamp, 300) {
		return fmt. Errorf("timestamp outside acceptable window")
	}

	valid, err := VerifyAuth(auth, s.config.In.SIDs. Items)
	if err != nil || !valid {
		return fmt. Errorf("authentication failed")
	}

	target := string(auth.Target)
	if target == "" && s.config.In. Reverse != nil {
		target = fmt.Sprintf("%s:%d", s.config.In. Reverse.Host, s.config.In. Reverse.Port)
	}

	if target == "" {
		return fmt.Errorf("no target specified")
	}

	// Connect to target server
	ctx, cancel := context.WithTimeout(s.ctx, DefaultTimeout)
	defer cancel()

	targetConn, err := (&net.Dialer{}). DialContext(ctx, "tcp", target)
	if err != nil {
		return fmt. Errorf("dial target %s: %w", target, err)
	}
	defer targetConn.Close()

	log.Printf("Proxying: %s -> %s", eqConn.RemoteAddr(), target)

	cfg := RelayConfig{
		Clock:     time. Duration(s.config.In.Clock) * time.Millisecond,
		FrameSize: s.config.In. Frame,
		Verbose:   s.verbose,
	}

	if err := ServerRelay(s.ctx, eqConn, targetConn, cfg); err != nil {
		if s.verbose {
			log.Printf("Relay error: %v", err)
		}
	}

	log.Printf("Closed: %s -> %s", eqConn.RemoteAddr(), target)
	return nil
}