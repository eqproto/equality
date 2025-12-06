package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
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

const (
	Version   = "89.0"
	TypeAuth  = 0
	TypeData  = 1
	TypePad   = 2
	TypeClose = 3
	MinFrame  = 100
	MaxFrame  = 65535
	MaxPend   = 1048576
	Timeout   = 30 * time.Second
)

type Config struct {
	XMLName xml.Name `xml:"config"`
	Ver     int      `xml:"ver,attr"`
	In      struct {
		Type    string `xml:"type,attr"`
		Port    int    `xml:"port,attr"`
		Clock   int    `xml:"clock,attr,omitempty"`
		Frame   int    `xml:"frame,attr,omitempty"`
		Key     string `xml:"key,attr"`
		Crt     string `xml:"crt,attr"`
		Reverse *struct {
			Host string `xml:"host,attr"`
			Port int    `xml:"port,attr"`
		} `xml:"reverse,omitempty"`
		SID []string `xml:"sid,omitempty"`
	} `xml:"in"`
	Out struct {
		Type   string `xml:"type,attr"`
		Server string `xml:"server,attr,omitempty"`
		Port   int    `xml:"port,attr,omitempty"`
		SID    string `xml:"sid,attr,omitempty"`
		Clock  int    `xml:"clock,attr,omitempty"`
		Frame  int    `xml:"frame,attr,omitempty"`
	} `xml:"out"`
	Verbose bool `xml:"verbose,attr,omitempty"`
}

type Frame struct {
	Type   uint8
	Length uint16
	Data   []byte
}

type Server struct {
	cfg    *Config
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime)
	logInfo("equality %s started", Version)

	configPath := "config.xml"
	if len(os.Args) >= 2 {
		configPath = os.Args[1]
	}

	f, err := os.Open(configPath)
	if err != nil {
		logFatal("config failed to open %s: %v", configPath, err)
	}
	cfg := &Config{}
	if err := xml.NewDecoder(f).Decode(cfg); err != nil {
		f.Close()
		logFatal("config failed to parse %s: %v", configPath, err)
	}
	f.Close()
	logInfo("config loaded from %s", configPath)

	if err := validateConfig(cfg); err != nil {
		logFatal("config invalid: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{cfg: cfg, ctx: ctx, cancel: cancel}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		logInfo("shutdown signal received")
		cancel()
		s.wg.Wait()
		logInfo("shutdown complete")
		os.Exit(0)
	}()

	if cfg.In.Type == "socks" {
		s.runClient()
	} else {
		s.runServer()
	}
}

func validateConfig(cfg *Config) error {
	if cfg.In.Type == "socks" {
		if cfg.In.Port == 0 {
			return fmt.Errorf("in.port must be set")
		}
		if cfg.Out.Server == "" {
			return fmt.Errorf("out.server must be set for client mode")
		}
		if cfg.Out.Port == 0 {
			return fmt.Errorf("out.port must be set")
		}
		if cfg.Out.SID == "" {
			return fmt.Errorf("out.sid must be set")
		}
		if cfg.Out.Frame == 0 {
			cfg.Out.Frame = 4096
			logWarn("config out.frame not set, using default %d", cfg.Out.Frame)
		}
		if cfg.Out.Frame < MinFrame || cfg.Out.Frame > MaxFrame {
			return fmt.Errorf("out.frame must be between %d and %d", MinFrame, MaxFrame)
		}
		if cfg.Out.Clock == 0 {
			cfg.Out.Clock = 100
			logWarn("config out.clock not set, using default %dms", cfg.Out.Clock)
		}
		if cfg.Out.Clock < 1 {
			return fmt.Errorf("out.clock must be at least 1ms")
		}
	} else {
		if cfg.In.Port == 0 {
			return fmt.Errorf("in.port must be set")
		}
		if cfg.In.Key == "" || cfg.In.Crt == "" {
			return fmt.Errorf("in.key and in.crt must be set (TLS is mandatory)")
		}
		if len(cfg.In.SID) == 0 {
			return fmt.Errorf("in.sid must contain at least one entry")
		}
		if cfg.In.Frame == 0 {
			cfg.In.Frame = 4096
			logWarn("config in.frame not set, using default %d", cfg.In.Frame)
		}
		if cfg.In.Frame < MinFrame || cfg.In.Frame > MaxFrame {
			return fmt.Errorf("in.frame must be between %d and %d", MinFrame, MaxFrame)
		}
		if cfg.In.Clock == 0 {
			cfg.In.Clock = 100
			logWarn("config in.clock not set, using default %dms", cfg.In.Clock)
		}
		if cfg.In.Clock < 1 {
			return fmt.Errorf("in.clock must be at least 1ms")
		}
	}
	return nil
}

func (s *Server) runClient() {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.In.Port))
	if err != nil {
		logFatal("client failed to bind :%d: %v", s.cfg.In.Port, err)
	}
	defer ln.Close()
	logInfo("client listening :%d -> %s:%d", s.cfg.In.Port, s.cfg.Out.Server, s.cfg.Out.Port)

	for {
		if tcpLn, ok := ln.(*net.TCPListener); ok {
			tcpLn.SetDeadline(time.Now().Add(time.Second))
		}
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				logError("client accept error: %v", err)
				continue
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleSocks(conn)
		}()
	}
}

func (s *Server) handleSocks(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 512)

	c.SetReadDeadline(time.Now().Add(Timeout))
	n, err := c.Read(buf)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		logDebug("socks greeting failed from %s: %v", c.RemoteAddr(), err)
		return
	}
	if n < 2 || buf[0] != 5 {
		logDebug("socks invalid greeting from %s (len=%d)", c.RemoteAddr(), n)
		return
	}

	if _, err := c.Write([]byte{5, 0}); err != nil {
		logDebug("socks auth response failed to %s: %v", c.RemoteAddr(), err)
		return
	}

	c.SetReadDeadline(time.Now().Add(Timeout))
	n, err = c.Read(buf)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		logDebug("socks request failed from %s: %v", c.RemoteAddr(), err)
		return
	}

	host, port := parseSocks(buf[:n])
	if host == "" {
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		logDebug("socks invalid request format from %s", c.RemoteAddr())
		return
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	eq := s.dialEQ(target)
	if eq == nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		logError("socks failed to establish tunnel to %s", target)
		return
	}
	defer eq.Close()

	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		logDebug("socks success response failed to %s: %v", c.RemoteAddr(), err)
		return
	}
	logInfo("proxy %s -> %s", c.RemoteAddr(), target)

	relay(s.ctx, eq, c, s.cfg.Out.Frame, time.Duration(s.cfg.Out.Clock)*time.Millisecond)
}

func parseSocks(buf []byte) (string, uint16) {
	if len(buf) < 4 || buf[0] != 5 || buf[1] != 1 {
		return "", 0
	}
	switch buf[3] {
	case 1:
		if len(buf) < 10 {
			return "", 0
		}
		return fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7]),
			binary.BigEndian.Uint16(buf[8:10])
	case 3:
		if len(buf) < 5 {
			return "", 0
		}
		l := int(buf[4])
		if len(buf) < 5+l+2 {
			return "", 0
		}
		return string(buf[5 : 5+l]), binary.BigEndian.Uint16(buf[5+l : 5+l+2])
	}
	return "", 0
}

func (s *Server) dialEQ(target string) net.Conn {
	addr := fmt.Sprintf("%s:%d", s.cfg.Out.Server, s.cfg.Out.Port)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: Timeout}, "tcp", addr, &tls.Config{
		ServerName:         s.cfg.Out.Server,
		InsecureSkipVerify: false,
	})
	if err != nil {
		logError("dialeq failed to connect %s: %v", addr, err)
		return nil
	}
	logDebug("dialeq tls established to %s", addr)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		logError("dialeq failed to generate nonce: %v", err)
		conn.Close()
		return nil
	}

	ts := time.Now().Unix()
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", s.cfg.Out.SID, ts, hex.EncodeToString(nonce))))
	auth := fmt.Sprintf("%s|%d|%s|%s", hex.EncodeToString(hash[:]), ts, hex.EncodeToString(nonce), target)

	if len(auth) > s.cfg.Out.Frame-3 {
		logError("dialeq auth payload too large (%d > %d)", len(auth), s.cfg.Out.Frame-3)
		conn.Close()
		return nil
	}

	frame := &Frame{Type: TypeAuth, Length: uint16(len(auth)), Data: []byte(auth)}
	frameBuf, err := frame.marshal(s.cfg.Out.Frame)
	if err != nil {
		logError("dialeq failed to marshal auth: %v", err)
		conn.Close()
		return nil
	}

	conn.SetWriteDeadline(time.Now().Add(Timeout))
	_, err = conn.Write(frameBuf)
	conn.SetWriteDeadline(time.Time{})

	if err != nil {
		logError("dialeq failed to send auth: %v", err)
		conn.Close()
		return nil
	}

	logDebug("dialeq authenticated for target %s", target)
	return conn
}

func (s *Server) runServer() {
	addr := fmt.Sprintf(":%d", s.cfg.In.Port)

	cert, err := tls.LoadX509KeyPair(s.cfg.In.Crt, s.cfg.In.Key)
	if err != nil {
		logFatal("server failed to load certificate: %v", err)
	}

	ln, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		logFatal("server failed to bind %s: %v", addr, err)
	}
	defer ln.Close()
	logInfo("server listening %s", addr)

	for {
		if tcpLn, ok := ln.(*net.TCPListener); ok {
			tcpLn.SetDeadline(time.Now().Add(time.Second))
		}
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				logError("server accept error: %v", err)
				continue
			}
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleIncoming(conn)
		}()
	}
}

func (s *Server) handleIncoming(c net.Conn) {
	defer c.Close()

	peek := make([]byte, 3)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadFull(c, peek)
	c.SetReadDeadline(time.Time{})

	if err != nil || n != 3 {
		logDebug("incoming failed to peek header from %s (n=%d, err=%v)", c.RemoteAddr(), n, err)
		s.reverseProxy(c, peek[:n])
		return
	}

	if peek[0] != TypeAuth {
		logDebug("incoming not auth frame from %s (type=%d)", c.RemoteAddr(), peek[0])
		s.reverseProxy(c, peek)
		return
	}

	length := binary.BigEndian.Uint16(peek[1:3])
	if length == 0 || int(length) > s.cfg.In.Frame-3 {
		logDebug("incoming invalid auth length from %s (%d > %d)", c.RemoteAddr(), length, s.cfg.In.Frame-3)
		s.reverseProxy(c, peek)
		return
	}

	rest := make([]byte, s.cfg.In.Frame-3)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err = io.ReadFull(c, rest)
	c.SetReadDeadline(time.Time{})

	if err != nil || n != s.cfg.In.Frame-3 {
		logDebug("incoming failed to read frame body from %s (n=%d, expected=%d, err=%v)",
			c.RemoteAddr(), n, s.cfg.In.Frame-3, err)
		combined := append(peek, rest[:n]...)
		s.reverseProxy(c, combined)
		return
	}

	buf := append(peek, rest...)
	frame := &Frame{}
	if err := frame.unmarshal(buf); err != nil {
		logDebug("incoming unmarshal failed from %s: %v", c.RemoteAddr(), err)
		s.reverseProxy(c, buf)
		return
	}

	parts := split(frame.Data, '|')
	if len(parts) != 4 {
		logDebug("incoming auth format invalid from %s (parts=%d)", c.RemoteAddr(), len(parts))
		s.reverseProxy(c, buf)
		return
	}

	var ts int64
	if _, err := fmt.Sscanf(string(parts[1]), "%d", &ts); err != nil {
		logDebug("incoming invalid timestamp from %s: %v", c.RemoteAddr(), err)
		s.reverseProxy(c, buf)
		return
	}

	now := time.Now().Unix()
	if now-ts > 300 || now-ts < -300 {
		logWarn("incoming timestamp out of range from %s (delta=%d)", c.RemoteAddr(), now-ts)
		s.reverseProxy(c, buf)
		return
	}

	valid := false
	for _, sid := range s.cfg.In.SID {
		hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", sid, ts, string(parts[2]))))
		if string(parts[0]) == hex.EncodeToString(hash[:]) {
			valid = true
			break
		}
	}

	if !valid {
		logWarn("incoming auth validation failed from %s", c.RemoteAddr())
		s.reverseProxy(c, buf)
		return
	}

	target := string(parts[3])
	ctx, cancel := context.WithTimeout(s.ctx, Timeout)
	defer cancel()
	tc, err := (&net.Dialer{}).DialContext(ctx, "tcp", target)
	if err != nil {
		logError("incoming failed to dial target %s: %v", target, err)
		return
	}
	defer tc.Close()

	logInfo("tunnel %s -> %s", c.RemoteAddr(), target)
	relay(s.ctx, c, tc, s.cfg.In.Frame, time.Duration(s.cfg.In.Clock)*time.Millisecond)
}

func (s *Server) reverseProxy(c net.Conn, initial []byte) {
	if s.cfg.In.Reverse == nil {
		logDebug("reverse no config for %s, closing", c.RemoteAddr())
		return
	}
	target := net.JoinHostPort(s.cfg.In.Reverse.Host, fmt.Sprintf("%d", s.cfg.In.Reverse.Port))
	tc, err := net.DialTimeout("tcp", target, Timeout)
	if err != nil {
		logError("reverse failed to connect %s: %v", target, err)
		return
	}
	defer tc.Close()

	if len(initial) > 0 {
		if _, err := tc.Write(initial); err != nil {
			logError("reverse failed to write initial data: %v", err)
			return
		}
	}

	logInfo("reverse %s -> %s", c.RemoteAddr(), target)

	done := make(chan struct{}, 2)
	go func() { io.Copy(tc, c); done <- struct{}{} }()
	go func() { io.Copy(c, tc); done <- struct{}{} }()
	<-done
}

func relay(ctx context.Context, proto, plain net.Conn, frameSize int, clock time.Duration) {
	done := make(chan struct{})
	go recvFrames(ctx, proto, plain, frameSize, done)
	go sendFrames(ctx, proto, plain, frameSize, clock, done)
	<-done
}

func recvFrames(ctx context.Context, proto, plain net.Conn, frameSize int, done chan struct{}) {
	defer func() { close(done) }()
	buf := make([]byte, frameSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		proto.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := io.ReadFull(proto, buf)
		proto.SetReadDeadline(time.Time{})

		if err != nil {
			return
		}
		if n != frameSize {
			return
		}

		frame := &Frame{}
		if err := frame.unmarshal(buf); err != nil {
			return
		}

		switch frame.Type {
		case TypeData:
			if len(frame.Data) > 0 {
				if _, err := plain.Write(frame.Data); err != nil {
					return
				}
			}
		case TypeClose:
			return
		}
	}
}

func sendFrames(ctx context.Context, proto, plain net.Conn, frameSize int, clock time.Duration, done chan struct{}) {
	ticker := time.NewTicker(clock)
	defer ticker.Stop()

	readBuf := make([]byte, 65535)
	pending := make([]byte, 0, MaxPend)
	dataSize := frameSize - 3
	closed := false

	for {
		select {
		case <-ctx.Done():
			sendClose(proto, frameSize)
			return
		case <-done:
			sendClose(proto, frameSize)
			return
		case <-ticker.C:
			if !closed && len(pending) < MaxPend {
				plain.SetReadDeadline(time.Now().Add(time.Millisecond))
				n, err := plain.Read(readBuf)
				plain.SetReadDeadline(time.Time{})
				if n > 0 {
					pending = append(pending, readBuf[:n]...)
				}
				if err == io.EOF || (err != nil && !isTimeout(err)) {
					closed = true
				}
			}

			if closed && len(pending) == 0 {
				sendClose(proto, frameSize)
				return
			}

			var frame *Frame
			if len(pending) > 0 {
				size := len(pending)
				if size > dataSize {
					size = dataSize
				}
				frame = &Frame{Type: TypeData, Length: uint16(size), Data: pending[:size]}
				pending = pending[size:]
			} else {
				frame = &Frame{Type: TypePad, Length: 0}
			}

			frameBuf, err := frame.marshal(frameSize)
			if err != nil {
				return
			}
			if _, err := proto.Write(frameBuf); err != nil {
				return
			}
		}
	}
}

func sendClose(c net.Conn, frameSize int) {
	frame := &Frame{Type: TypeClose, Length: 0}
	buf, _ := frame.marshal(frameSize)
	c.Write(buf)
}

func (f *Frame) marshal(frameSize int) ([]byte, error) {
	if frameSize < 3 {
		return nil, fmt.Errorf("frameSize too small")
	}
	if int(f.Length) > frameSize-3 {
		return nil, fmt.Errorf("data too large for frame")
	}
	buf := make([]byte, frameSize)
	buf[0] = f.Type
	binary.BigEndian.PutUint16(buf[1:3], f.Length)
	if f.Length > 0 {
		copy(buf[3:], f.Data[:f.Length])
	}
	if int(f.Length) < frameSize-3 {
		if _, err := rand.Read(buf[3+f.Length:]); err != nil {
			return nil, fmt.Errorf("failed to generate padding: %w", err)
		}
	}
	return buf, nil
}

func (f *Frame) unmarshal(buf []byte) error {
	if len(buf) < 3 {
		return fmt.Errorf("buffer too short")
	}
	f.Type = buf[0]
	f.Length = binary.BigEndian.Uint16(buf[1:3])
	if f.Length > uint16(len(buf)-3) {
		return fmt.Errorf("length field exceeds buffer")
	}
	if f.Length > 0 {
		f.Data = make([]byte, f.Length)
		copy(f.Data, buf[3:3+f.Length])
	}
	return nil
}

func split(data []byte, sep byte) [][]byte {
	parts := make([][]byte, 0, 4)
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == sep {
			parts = append(parts, data[start:i])
			start = i + 1
		}
	}
	parts = append(parts, data[start:])
	return parts
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// Unified logging
func logInfo(format string, v ...interface{}) {
	log.Printf("info "+format, v...)
}

func logWarn(format string, v ...interface{}) {
	log.Printf("warn "+format, v...)
}

func logError(format string, v ...interface{}) {
	log.Printf("error "+format, v...)
}

func logFatal(format string, v ...interface{}) {
	log.Fatalf("fatal "+format, v...)
}

func logDebug(format string, v ...interface{}) {
	// Only logs if verbose is enabled - checked by caller
	log.Printf("debug "+format, v...)
}
