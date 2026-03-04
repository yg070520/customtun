package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
}

type caddyUpstream struct {
	Dial string `json:"dial"`
}

// registerCaddyRoute adds a reverse proxy route to Caddy for the given subdomain.
// The route proxies traffic from `domain` to `backendAddr` (e.g. 127.0.0.1:xxxxx).
func (s *Server) registerCaddyRoute(subdomain, domain, backendAddr string) error {
	route := caddyRoute{
		ID:   "tunnel-" + subdomain,
		Match: []caddyMatch{{Host: []string{domain}}},
		Handle: []caddyHandle{{
			Handler:   "reverse_proxy",
			Upstreams: []caddyUpstream{{Dial: backendAddr}},
		}},
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
