package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"

	"tunnl.gg/internal/config"
	"tunnl.gg/internal/subdomain"
)

// Server manages SSH connections
type Server struct {
	activeSubdomains map[string]string // subdomain -> sessionID (ownership tracking)
	ipConnections    map[string]int
	sshConns         map[string][]*ssh.ServerConn
	mu               sync.RWMutex
	sshConfig        *ssh.ServerConfig
	domain           string
	caddyAdminURL    string

	// Abuse protection
	abuseTracker *AbuseTracker
}

// New creates a new server instance
func New(hostKeyPath string, domain string, caddyAdminURL string) (*Server, error) {
	s := &Server{
		activeSubdomains: make(map[string]string),
		ipConnections:    make(map[string]int),
		sshConns:         make(map[string][]*ssh.ServerConn),
		abuseTracker:     NewAbuseTracker(),
		domain:           domain,
		caddyAdminURL:    caddyAdminURL,
	}

	s.abuseTracker.SetOnBlockCallback(func(ip string) {
		connCount := s.CloseAllForIP(ip)
		if connCount > 0 {
			log.Printf("Closed %d SSH connection(s) for blocked IP %s", connCount, ip)
		}
	})

	s.sshConfig = &ssh.ServerConfig{
		NoClientAuth: true,
	}

	hostKey, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load host key: %w", err)
	}
	s.sshConfig.AddHostKey(hostKey)

	return s, nil
}

// Domain returns the configured domain
func (s *Server) Domain() string {
	return s.domain
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("Generating new host key at %s", path)

		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		pemBlock := &pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: edkey.MarshalED25519PrivateKey(priv),
		}

		if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600); err != nil {
			return nil, err
		}
	}

	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ssh.ParsePrivateKey(keyBytes)
}

// GenerateUniqueSubdomain generates a subdomain that doesn't collide with existing ones
func (s *Server) GenerateUniqueSubdomain() (string, error) {
	const maxAttempts = 10
	for i := 0; i < maxAttempts; i++ {
		sub, err := subdomain.Generate()
		if err != nil {
			return "", err
		}

		s.mu.RLock()
		_, exists := s.activeSubdomains[sub]
		s.mu.RUnlock()

		if !exists {
			return sub, nil
		}
	}
	return "", fmt.Errorf("failed to generate unique subdomain after %d attempts", maxAttempts)
}

// AddSubdomain adds a subdomain to the active set with ownership tracking.
// sessionID uniquely identifies the connection that owns this subdomain.
func (s *Server) AddSubdomain(sub string, sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeSubdomains[sub] = sessionID
}

// RemoveSubdomain removes a subdomain only if the caller is the current owner.
// Returns true if the subdomain was actually removed.
func (s *Server) RemoveSubdomain(sub string, sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeSubdomains[sub] == sessionID {
		delete(s.activeSubdomains, sub)
		return true
	}
	return false
}

// ForceReleaseSubdomain removes a subdomain regardless of ownership.
// Used during subdomain takeover.
func (s *Server) ForceReleaseSubdomain(sub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.activeSubdomains, sub)
}

// IsSubdomainTaken checks if a subdomain is currently in use
func (s *Server) IsSubdomainTaken(sub string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.activeSubdomains[sub]
	return exists
}

// CheckAndReserveConnection checks if a new connection from the given IP is allowed
// and atomically reserves a slot if allowed.
// Caller MUST call DecrementIPConnection when done if this returns nil.
func (s *Server) CheckAndReserveConnection(clientIP string) error {
	if expiry := s.abuseTracker.GetBlockExpiry(clientIP); !expiry.IsZero() {
		remaining := time.Until(expiry).Round(time.Minute)
		return fmt.Errorf("IP %s is temporarily blocked. Try again in %v", clientIP, remaining)
	}

	if !s.abuseTracker.CheckConnectionRate(clientIP) {
		return fmt.Errorf("connection rate limit exceeded: max %d connections per minute", config.MaxConnectionsPerMinute)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ipConnections[clientIP] >= config.MaxTunnelsPerIP {
		return fmt.Errorf("rate limit exceeded: max %d connections per IP", config.MaxTunnelsPerIP)
	}
	if len(s.activeSubdomains) >= config.MaxTotalTunnels {
		return fmt.Errorf("server capacity reached: max %d total connections", config.MaxTotalTunnels)
	}

	s.ipConnections[clientIP]++
	return nil
}

// DecrementIPConnection decrements the connection count for an IP
func (s *Server) DecrementIPConnection(clientIP string) {
	s.mu.Lock()
	s.ipConnections[clientIP]--
	if s.ipConnections[clientIP] <= 0 {
		delete(s.ipConnections, clientIP)
	}
	s.mu.Unlock()
}

// RegisterSSHConn registers an SSH connection for an IP (for forced closure on block)
func (s *Server) RegisterSSHConn(clientIP string, conn *ssh.ServerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sshConns[clientIP] = append(s.sshConns[clientIP], conn)
}

// UnregisterSSHConn removes an SSH connection from tracking
func (s *Server) UnregisterSSHConn(clientIP string, conn *ssh.ServerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	conns := s.sshConns[clientIP]
	newConns := make([]*ssh.ServerConn, 0, len(conns))
	for _, c := range conns {
		if c != conn {
			newConns = append(newConns, c)
		}
	}

	if len(newConns) == 0 {
		delete(s.sshConns, clientIP)
	} else {
		s.sshConns[clientIP] = newConns
	}
}

// CloseAllForIP closes all SSH connections for a specific IP
func (s *Server) CloseAllForIP(ip string) int {
	s.mu.Lock()
	sshConns := s.sshConns[ip]
	connsCopy := make([]*ssh.ServerConn, len(sshConns))
	copy(connsCopy, sshConns)
	delete(s.sshConns, ip)
	s.mu.Unlock()

	for _, conn := range connsCopy {
		conn.Close()
	}

	return len(connsCopy)
}

// Stop gracefully stops the server's background goroutines
func (s *Server) Stop() {
	s.abuseTracker.Stop()
}
