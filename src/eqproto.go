package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	TypeAuth    = 0
	TypeData    = 1
	TypePadding = 2
	TypeClose   = 3
)

// Frame represents an EQ protocol frame
type Frame struct {
	Type   uint8
	Length uint16
	Data   []byte
}

// Marshal encodes frame into buffer of specified size
func (f *Frame) Marshal(frameSize int) ([]byte, error) {
	if frameSize < 3 {
		return nil, fmt. Errorf("frame size too small: %d", frameSize)
	}

	buf := make([]byte, frameSize)
	buf[0] = f.Type

	if f.Length > uint16(frameSize-3) {
		return nil, fmt.Errorf("frame data too large: %d > %d", f.Length, frameSize-3)
	}

	binary.BigEndian.PutUint16(buf[1:3], f.Length)

	if f.Length > 0 {
		if len(f.Data) < int(f.Length) {
			return nil, fmt.Errorf("insufficient data: have %d, need %d", len(f.Data), f.Length)
		}
		copy(buf[3:], f.Data[:f.Length])
	}

	// Fill padding with random data
	if int(f.Length) < frameSize-3 {
		if _, err := rand.Read(buf[3+f.Length:]); err != nil {
			return nil, fmt.Errorf("generate random padding: %w", err)
		}
	}

	return buf, nil
}

// Unmarshal decodes frame from buffer
func (f *Frame) Unmarshal(buf []byte) error {
	if len(buf) < 3 {
		return fmt.Errorf("buffer too small: %d bytes", len(buf))
	}

	f.Type = buf[0]
	f.Length = binary.BigEndian.Uint16(buf[1:3])

	if f.Length > uint16(len(buf)-3) {
		return fmt.Errorf("truncated frame data: length=%d, available=%d", f.Length, len(buf)-3)
	}

	if f.Length > 0 {
		f.Data = make([]byte, f.Length)
		copy(f.Data, buf[3:3+f. Length])
	} else {
		f.Data = nil
	}

	return nil
}

// AuthData represents authentication frame content
type AuthData struct {
	Hash      string
	Timestamp int64
	Nonce     []byte
	Target    string
}

// BuildAuthFrame creates an authentication frame
func BuildAuthFrame(sid, target string, nonce []byte, frameSize int) (*Frame, error) {
	if len(nonce) != 16 {
		return nil, fmt.Errorf("nonce must be 16 bytes, got %d", len(nonce))
	}

	timestamp := time.Now().Unix()
	hashInput := fmt.Sprintf("%s:%d:%s", sid, timestamp, hex.EncodeToString(nonce))
	hash := sha256.Sum256([]byte(hashInput))

	// Build auth data: hash|timestamp|nonce|target
	authStr := fmt.Sprintf("%s|%d|%s|%s",
		hex.EncodeToString(hash[:]),
		timestamp,
		hex.EncodeToString(nonce),
		target)

	if len(authStr) > frameSize-3 {
		return nil, fmt.Errorf("auth data too large: %d > %d", len(authStr), frameSize-3)
	}

	return &Frame{
		Type:   TypeAuth,
		Length: uint16(len(authStr)),
		Data:   []byte(authStr),
	}, nil
}

// ParseAuthData parses authentication frame data
func ParseAuthData(data []byte) (*AuthData, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty auth data")
	}

	// Split by pipe character with bounds checking
	parts := make([][]byte, 0, 4)
	start := 0

	for i := 0; i < len(data); i++ {
		if data[i] == '|' {
			parts = append(parts, data[start:i])
			start = i + 1
		}
	}
	parts = append(parts, data[start:])

	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid auth data format: expected 4 parts, got %d", len(parts))
	}

	var timestamp int64
	_, err := fmt.Sscanf(string(parts[1]), "%d", &timestamp)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}

	return &AuthData{
		Hash:      string(parts[0]),
		Timestamp: timestamp,
		Nonce:     parts[2],
		Target:    string(parts[3]),
	}, nil
}

// VerifyAuth validates authentication using provided SIDs
func VerifyAuth(auth *AuthData, sids []string) (bool, error) {
	if len(auth.Nonce) != 32 { // hex-encoded 16 bytes
		return false, fmt. Errorf("invalid nonce length: %d", len(auth.Nonce))
	}

	for _, sid := range sids {
		hashInput := fmt.Sprintf("%s:%d:%s",
			sid, auth.Timestamp, string(auth.Nonce))
		expectedHash := sha256.Sum256([]byte(hashInput))
		expectedHashStr := hex.EncodeToString(expectedHash[:])

		if auth.Hash == expectedHashStr {
			return true, nil
		}
	}

	return false, nil
}

// IsAuthTimestampValid checks if timestamp is within acceptable window
func IsAuthTimestampValid(timestamp int64, maxDriftSecs int64) bool {
	now := time.Now().Unix()
	drift := now - timestamp
	return drift >= -maxDriftSecs && drift <= maxDriftSecs
}