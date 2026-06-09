package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type caddyRoute struct {
	ID       string        `json:"@id"`
	Match    []caddyMatch  `json:"match"`
	Handle   []caddyHandle `json:"handle"`
	Terminal bool          `json:"terminal"`
}

type caddyMatch struct {
	Host []string `json:"host"`
}

type caddyHandle struct {
	Handler   string          `json:"handler"`
	Upstreams []caddyUpstream `json:"upstreams"`
	Transport *caddyTransport `json:"transport,omitempty"`
}

type caddyUpstream struct {
	Dial string `json:"dial"`
}

type caddyTransport struct {
	Protocol string    `json:"protocol"`
	TLS      *caddyTLS `json:"tls,omitempty"`
}

type caddyTLS struct {
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

// registerCaddyRoute adds a reverse proxy route to Caddy for the given subdomain.
// The route proxies traffic from `domain` to `backendAddr` (e.g. 127.0.0.1:xxxxx).
// scheme should be "http" or "https"; when "https", a TLS transport is added.
func (s *Server) registerCaddyRoute(subdomain, domain, backendAddr, scheme string) error {
	handle := caddyHandle{
		Handler:   "reverse_proxy",
		Upstreams: []caddyUpstream{{Dial: backendAddr}},
	}
	if scheme == "https" {
		handle.Transport = &caddyTransport{
			Protocol: "http",
			TLS:      &caddyTLS{InsecureSkipVerify: true},
		}
	}
	route := caddyRoute{
		ID:       "tunnel-" + subdomain,
		Match:    []caddyMatch{{Host: []string{domain}}},
		Handle:   []caddyHandle{handle},
		Terminal: true,
	}

	body, err := json.Marshal(route)
	if err != nil {
		return fmt.Errorf("failed to marshal route: %w", err)
	}

	url := s.caddyAdminURL + "/config/apps/http/servers/srv0/routes/0"
	req, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("caddy API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// probeScheme detects whether the backend at addr speaks HTTP or HTTPS.
// It sends a plain HTTP GET to the address; if the backend requires TLS
// (evidenced by a TLS-bytes error or an HTTP 400 body mentioning SSL/HTTPS),
// it returns "https". Otherwise it returns "http".
func probeScheme(addr string) string {
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get("http://" + addr + "/")
	if err == nil {
		defer resp.Body.Close()
		// Some HTTPS servers (nginx, Apache) respond with HTTP 400 and a body
		// like "The plain HTTP request was sent to HTTPS port".
		if resp.StatusCode == http.StatusBadRequest {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			lower := strings.ToLower(string(body))
			if strings.Contains(lower, "ssl") || strings.Contains(lower, "https") {
				return "https"
			}
		}
		return "http"
	}

	// If the HTTP client received TLS bytes in response to a plain HTTP request,
	// the error message contains "malformed HTTP response".
	if strings.Contains(err.Error(), "malformed HTTP response") {
		return "https"
	}

	return "http"
}

// removeCaddyRoute removes a previously registered Caddy route by its @id.
func (s *Server) removeCaddyRoute(subdomain string) error {
	url := s.caddyAdminURL + "/id/tunnel-" + subdomain
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("caddy API unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
