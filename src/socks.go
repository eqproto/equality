package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseSOCKS5Request parses a SOCKS5 request and extracts host and port
func ParseSOCKS5Request(buf []byte) (host string, port uint16, err error) {
	if len(buf) < 4 {
		return "", 0, fmt.Errorf("request too short: %d bytes", len(buf))
	}

	if buf[0] != 5 {
		return "", 0, fmt.Errorf("invalid SOCKS version: %d", buf[0])
	}

	if buf[1] != 1 { // CONNECT command
		return "", 0, fmt.Errorf("unsupported command: %d", buf[1])
	}

	// buf[2] is reserved
	addrType := buf[3]

	switch addrType {
	case 1: // IPv4
		if len(buf) < 10 {
			return "", 0, fmt.Errorf("IPv4 address incomplete: got %d bytes, need 10", len(buf))
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		port = parsePort(buf[8:10])

	case 3: // Domain name
		if len(buf) < 5 {
			return "", 0, fmt.Errorf("domain name incomplete: length byte missing")
		}
		length := int(buf[4])
		if len(buf) < 5+length+2 {
			return "", 0, fmt.Errorf("domain name incomplete: got %d bytes, need %d",
				len(buf), 5+length+2)
		}
		host = string(buf[5 : 5+length])
		port = parsePort(buf[5+length : 5+length+2])

	case 4: // IPv6
		if len(buf) < 22 {
			return "", 0, fmt.Errorf("IPv6 address incomplete: got %d bytes, need 22", len(buf))
		}
		host = formatIPv6(buf[4:20])
		port = parsePort(buf[20:22])

	default:
		return "", 0, fmt.Errorf("unsupported address type: %d", addrType)
	}

	if host == "" {
		return "", 0, fmt.Errorf("empty host address")
	}

	return host, port, nil
}

// parsePort extracts port from 2-byte big-endian buffer
func parsePort(buf []byte) uint16 {
	if len(buf) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(buf)
}

// formatIPv6 formats 16-byte IPv6 address with leading zeros removed
func formatIPv6(buf []byte) string {
	if len(buf) != 16 {
		return ""
	}
	var parts [8]string
	for i := 0; i < 8; i++ {
		val := binary.BigEndian. Uint16(buf[i*2 : i*2+2])
		parts[i] = strconv.FormatInt(int64(val), 16)
	}
	return "[" + strings.Join(parts[:], ":") + "]"
}

// FormatTarget combines host and port into "host:port"
func FormatTarget(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// SOCKS5AuthResponse sends a SOCKS5 authentication response
func SOCKS5AuthResponse(conn net.Conn) error {
	_, err := conn.Write([]byte{5, 0}) // SOCKS5, no auth required
	return err
}

// SOCKS5SuccessResponse sends a successful CONNECT response
func SOCKS5SuccessResponse(conn net. Conn) error {
	_, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

// SOCKS5ErrorResponse sends a SOCKS5 error response
func SOCKS5ErrorResponse(conn net.Conn, errorCode uint8) error {
	response := []byte{5, errorCode, 0, 1, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(response)
	return err
}

const (
	SOCKS5ErrorUnsupportedCmd           = 7
	SOCKS5ErrorUnsupportedAddr          = 8
	SOCKS5ErrorConnectionFailed         = 1
)