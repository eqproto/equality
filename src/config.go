package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"time"
)

const (
	MaxFrameSize    = 65535
	MinFrameSize    = 100
	MaxPendingBytes = 1024 * 1024
	DefaultTimeout  = 30 * time.Second
)

type Config struct {
	XMLName         xml.Name  `xml:"config"`
	Ver             int       `xml:"ver,attr"`
	In              InConfig  `xml:"in"`
	Out             OutConfig `xml:"out"`
	ShutdownTimeout int       `xml:"shutdown_timeout,attr,omitempty"`
	Verbose         bool      `xml:"verbose,attr,omitempty"`
}

type InConfig struct {
	Type    string     `xml:"type,attr"`
	Port    int        `xml:"port,attr"`
	Clock   int        `xml:"clock,attr,omitempty"`
	Frame   int        `xml:"frame,attr,omitempty"`
	Reverse *Reverse   `xml:"reverse,omitempty"`
	SSL     *SSLConfig `xml:"ssl,omitempty"`
	SIDs    *SIDList   `xml:"sid,omitempty"`
}

type OutConfig struct {
	Type   string `xml:"type,attr"`
	Server string `xml:"server,attr,omitempty"`
	Port   int    `xml:"port,attr,omitempty"`
	SID    string `xml:"sid,attr,omitempty"`
	Clock  int    `xml:"clock,attr,omitempty"`
	Frame  int    `xml:"frame,attr,omitempty"`
}

type Reverse struct {
	Host string `xml:"host,attr"`
	Port int    `xml:"port,attr"`
}

type SSLConfig struct {
	Key    string `xml:"key,attr"`
	Crt    string `xml:"crt,attr"`
	RootCA string `xml:"rootca,attr,omitempty"`
}

type SIDList struct {
	Items []string `xml:"item"`
}

// LoadConfig loads and parses the XML configuration file
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt. Errorf("cannot open config file: %w", err)
	}
	defer f.Close()

	cfg := &Config{}
	decoder := xml.NewDecoder(f)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("cannot parse XML: %w", err)
	}

	return cfg, nil
}

// ValidateConfig performs comprehensive configuration validation
func ValidateConfig(cfg *Config) error {
	if cfg.In.Port <= 0 || cfg.In.Port > 65535 {
		return fmt.Errorf("invalid in.port: %d (must be 1-65535)", cfg.In.Port)
	}

	if cfg.In.Type == "eq" {
		if err := validateEQInConfig(cfg.In); err != nil {
			return err
		}
	} else if cfg.In.Type == "socks" {
		// SOCKS client mode validation
	} else {
		return fmt.Errorf("invalid in.type: %s (must be 'socks' or 'eq')", cfg.In.Type)
	}

	// Добавить эту проверку:
	if cfg.Out.Type == "eq" {
		if err := validateEQOutConfig(cfg.Out); err != nil {
			return err
		}
	} else if cfg.Out.Type == "freedom" {
		// Freedom mode - direct connect
	} else if cfg.Out.Type != "" {
		return fmt.Errorf("invalid out.type: %s (must be 'eq' or 'freedom')", cfg.Out.Type)
	}

	return nil
}

func validateEQInConfig(in InConfig) error {
	if in.Clock <= 0 {
		return fmt.Errorf("in.clock must be positive for eq type")
	}
	if in.Frame < MinFrameSize {
		return fmt.Errorf("in.frame must be at least %d bytes", MinFrameSize)
	}
	if in.Frame > MaxFrameSize {
		return fmt.Errorf("in. frame must not exceed %d bytes", MaxFrameSize)
	}
	if in.SIDs == nil || len(in.SIDs. Items) == 0 {
		return fmt.Errorf("at least one SID required for server mode")
	}
	for _, sid := range in.SIDs.Items {
		if len(sid) < 16 {
			return fmt.Errorf("SID too short (min 16 chars): %s", sid)
		}
	}
	return nil
}

func validateEQOutConfig(out OutConfig) error {
	if out.Clock <= 0 {
		return fmt.Errorf("out. clock must be positive for eq type")
	}
	if out. Frame < MinFrameSize {
		return fmt.Errorf("out.frame must be at least %d bytes", MinFrameSize)
	}
	if out. Frame > MaxFrameSize {
		return fmt.Errorf("out.frame must not exceed %d bytes", MaxFrameSize)
	}
	if out.Server == "" {
		return fmt. Errorf("out.server required for eq type")
	}
	if out.SID == "" {
		return fmt.Errorf("out.sid required for eq type")
	}
	if len(out.SID) < 16 {
		return fmt. Errorf("out.sid too short (min 16 chars)")
	}
	return nil
}