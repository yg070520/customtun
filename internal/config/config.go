package config

import (
	"time"
)

const (
	DefaultDomain   = "jatus.top"
	MaxTunnelsPerIP = 3
	MaxTotalTunnels = 1000

	// SSH handshake timeout
	SSHHandshakeTimeout = 30 * time.Second

	// Connection rate limiting (new connections per IP)
	MaxConnectionsPerMinute = 10              // max new connections per IP per minute
	ConnectionRateWindow    = 1 * time.Minute // sliding window for connection rate

	// IP blocking
	BlockDuration          = 1 * time.Hour // how long to block abusive IPs
	RateLimitViolationsMax = 10            // violations before auto-block

	// Shutdown timeout
	ShutdownTimeout = 10 * time.Second
)

// Config holds runtime configuration loaded from environment
type Config struct {
	SSHAddr     string
	HostKeyPath string
	Domain      string
}

// Default returns configuration with default values
func Default() *Config {
	return &Config{
		SSHAddr:     ":8888",
		HostKeyPath: "host_key",
		Domain:      DefaultDomain,
	}
}
