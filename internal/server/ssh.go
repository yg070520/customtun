package server

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"tunnl.gg/internal/config"
	"tunnl.gg/internal/subdomain"
)

// ANSI color codes
const (
	ansiReset     = "\033[0m"
	ansiGray      = "\033[38;5;245m"
	ansiBoldGreen = "\033[1;32m"
	ansiPurple    = "\033[38;5;141m"
	ansiRed       = "\033[1;31m"
	ansiYellow    = "\033[33m"
)

type tcpipForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

type bindInfo struct {
	addr string
	port uint32
}

// HandleSSHConnection handles a new SSH connection
func (s *Server) HandleSSHConnection(conn net.Conn) {
	clientIP := "unknown"
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if tcpAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
			clientIP = tcpAddr.IP.String()
		}
		tcpConn.SetNoDelay(true)
	}

	// Do SSH handshake
	conn.SetDeadline(time.Now().Add(config.SSHHandshakeTimeout))
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	conn.SetDeadline(time.Time{})
	defer sshConn.Close()

	// Check rate limits after handshake
	if err := s.CheckAndReserveConnection(clientIP); err != nil {
		log.Printf("Connection rejected from %s: %v", clientIP, err)
		go ssh.DiscardRequests(reqs)
		s.sendErrorAndClose(sshConn, chans, err.Error())
		return
	}
	defer s.DecrementIPConnection(clientIP)

	// Track SSH connection for forced closure on IP block
	s.RegisterSSHConn(clientIP, sshConn)
	defer s.UnregisterSSHConn(clientIP, sshConn)

	log.Printf("New SSH connection from %s", sshConn.RemoteAddr())

	// Create tunnel listener on random local port
	tunnelListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Printf("Failed to create tunnel listener: %v", err)
		go ssh.DiscardRequests(reqs)
		return
	}
	defer tunnelListener.Close()

	// Handle global requests — capture tcpip-forward bind info
	bindCh := make(chan bindInfo, 1)
	go func() {
		for req := range reqs {
			switch req.Type {
			case "tcpip-forward":
				var fwdReq tcpipForwardRequest
				if err := ssh.Unmarshal(req.Payload, &fwdReq); err != nil {
					req.Reply(false, nil)
					continue
				}
				select {
				case bindCh <- bindInfo{fwdReq.BindAddr, fwdReq.BindPort}:
				default:
				}
				req.Reply(true, nil)
			case "cancel-tcpip-forward":
				req.Reply(true, nil)
			default:
				req.Reply(false, nil)
			}
		}
	}()

	// Collect session channel and bind info concurrently.
	// We need to determine the mode of operation:
	//   1. Embedded subdomain via -R (supports -N/-f, no session channel needed)
	//   2. Interactive mode (session channel required for prompt)
	sessionReceived := make(chan ssh.NewChannel, 1)
	go func() {
		for newChannel := range chans {
			if newChannel.ChannelType() == "session" {
				sessionReceived <- newChannel
				return
			}
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}()

	// Session ID for ownership tracking (unique per connection)
	sessionID := fmt.Sprintf("%p", sshConn)

	// Wait for tcpip-forward first to detect embedded subdomain.
	var bind bindInfo
	var hasBind bool
	var embeddedSub string

	select {
	case bind = <-bindCh:
		hasBind = true
		embeddedSub = extractSubdomainFromBindAddr(bind.addr)
	case <-time.After(5 * time.Second):
		// No bind info yet
	}

	// --- Mode 1: Embedded subdomain (supports -f, -N, no session channel needed) ---
	if embeddedSub != "" {
		sub := embeddedSub

		// Release in-memory tracking if subdomain is held by another session
		if s.IsSubdomainTaken(sub) {
			log.Printf("Force takeover of subdomain (in-memory): %s", sub)
			s.ForceReleaseSubdomain(sub)
		}

		// Always try to remove old Caddy route
		log.Printf("Removing old Caddy route for %s (if any)", sub)
		_ = s.removeCaddyRoute(sub)

		s.AddSubdomain(sub, sessionID)
		defer func() {
			if s.RemoveSubdomain(sub, sessionID) {
				if err := s.removeCaddyRoute(sub); err != nil {
					log.Printf("Failed to remove Caddy route for %s: %v", sub, err)
				}
			}
		}()

		domain := fmt.Sprintf("%s.%s", sub, s.domain)
		listenerAddr := tunnelListener.Addr().String()

		log.Printf("Registering Caddy route: %s -> %s", domain, listenerAddr)
		if err := s.registerCaddyRoute(sub, domain, listenerAddr); err != nil {
			log.Printf("Failed to register Caddy route for %s: %v", sub, err)
			return
		}
		log.Printf("Caddy route registered: %s -> %s", domain, listenerAddr)
		log.Printf("Subdomain assigned: %s -> %s (client: %s, forward port: %d)",
			domain, listenerAddr, sshConn.RemoteAddr(), bind.port)

		// Accept connections on tunnel listener and forward to SSH client
		go func() {
			for {
				tcpConn, err := tunnelListener.Accept()
				if err != nil {
					return
				}
				go s.forwardToSSH(sshConn, tcpConn, bind.addr, bind.port)
			}
		}()

		// Optionally handle session channel if present (for interactive -t usage),
		// but always keep connection alive via sshConn.Wait()
		go func() {
			select {
			case sessionChannel, ok := <-sessionReceived:
				if !ok {
					return
				}
				channel, requests, err := sessionChannel.Accept()
				if err != nil {
					return
				}
				go func() {
					for req := range requests {
						switch req.Type {
						case "pty-req", "shell":
							if req.WantReply {
								req.Reply(true, nil)
							}
						default:
							if req.WantReply {
								req.Reply(false, nil)
							}
						}
					}
				}()

				fmt.Fprintf(channel, ansiGray+"Using subdomain: "+ansiPurple+"%s"+ansiReset+"\r\n", domain)
				message := "\r\n" +
					ansiBoldGreen + "Connection successful!" + ansiReset + "\r\n" +
					ansiGray + "Assigned domain: " + ansiPurple + domain + ansiReset + "\r\n" +
					ansiGray + "Forwarding:     " + ansiPurple + fmt.Sprintf("%s -> localhost:%d", domain, bind.port) + ansiReset + "\r\n" +
					ansiGray + "Press Ctrl+C to disconnect." + ansiReset + "\r\n\r\n"
				fmt.Fprint(channel, message)

				// Read but don't close sshConn on channel EOF — let sshConn.Wait() handle lifecycle
				buf := make([]byte, 1)
				for {
					_, err := channel.Read(buf)
					if err != nil {
						break
					}
					if buf[0] == 0x03 { // Ctrl+C
						sshConn.Close()
						return
					}
				}
			}
		}()

		// Keep connection alive until SSH connection itself closes
		sshConn.Wait()
		log.Printf("SSH connection closed for subdomain: %s", sub)
		return
	}

	// --- Mode 2: Interactive mode (session channel required) ---
	var sessionChannel ssh.NewChannel
	select {
	case sessionChannel = <-sessionReceived:
	case <-time.After(5 * time.Second):
		log.Printf("Connection from %s rejected: no session channel and no embedded subdomain", sshConn.RemoteAddr())
		return
	}

	channel, requests, err := sessionChannel.Accept()
	if err != nil {
		log.Printf("Failed to accept session channel: %v", err)
		return
	}

	// Handle session requests (pty-req, shell, etc.)
	go func(reqs <-chan *ssh.Request) {
		for req := range reqs {
			switch req.Type {
			case "pty-req", "shell":
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "signal":
				if req.WantReply {
					req.Reply(true, nil)
				}
				sshConn.Close()
				return
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}(requests)

	// Interactive subdomain selection
	sub := s.promptSubdomain(channel, sshConn)
	if sub == "" {
		return // connection closed during prompt
	}

	s.AddSubdomain(sub, sessionID)
	defer func() {
		if s.RemoveSubdomain(sub, sessionID) {
			if err := s.removeCaddyRoute(sub); err != nil {
				log.Printf("Failed to remove Caddy route for %s: %v", sub, err)
			}
		}
	}()

	domain := fmt.Sprintf("%s.%s", sub, s.domain)
	listenerAddr := tunnelListener.Addr().String()

	// Register route with Caddy
	log.Printf("Registering Caddy route: %s -> %s", domain, listenerAddr)
	if err := s.registerCaddyRoute(sub, domain, listenerAddr); err != nil {
		log.Printf("Failed to register Caddy route for %s: %v", sub, err)
		fmt.Fprintf(channel, ansiRed+"  Failed to register route: %s"+ansiReset+"\r\n", err)
		return
	}
	log.Printf("Caddy route registered: %s -> %s", domain, listenerAddr)

	// Wait for tcpip-forward info if we don't have it yet
	if !hasBind {
		fmt.Fprintf(channel, ansiGray+"Waiting for port forwarding (-R) ..."+ansiReset+"\r\n")
		select {
		case bind = <-bindCh:
		case <-time.After(30 * time.Second):
			fmt.Fprintf(channel, ansiRed+"  Timeout: no port forwarding received.\r\n"+
				"  Use: ssh -p 2222 -t -R <port>:localhost:<port> %s"+ansiReset+"\r\n", s.domain)
			return
		}
	}

	log.Printf("Subdomain assigned: %s -> %s (client: %s, forward port: %d)",
		domain, listenerAddr, sshConn.RemoteAddr(), bind.port)

	message := "\r\n" +
		ansiBoldGreen + "Connection successful!" + ansiReset + "\r\n" +
		ansiGray + "Assigned domain: " + ansiPurple + domain + ansiReset + "\r\n" +
		ansiGray + "Forwarding:     " + ansiPurple + fmt.Sprintf("%s -> localhost:%d", domain, bind.port) + ansiReset + "\r\n" +
		ansiGray + "Press Ctrl+C to disconnect." + ansiReset + "\r\n\r\n"

	fmt.Fprint(channel, message)

	// Accept connections on the tunnel listener and forward to SSH client
	go func() {
		for {
			tcpConn, err := tunnelListener.Accept()
			if err != nil {
				return
			}
			go s.forwardToSSH(sshConn, tcpConn, bind.addr, bind.port)
		}
	}()

	// Read from channel to detect disconnect or Ctrl+C
	buf := make([]byte, 1)
	for {
		_, err := channel.Read(buf)
		if err != nil {
			break
		}
		if buf[0] == 0x03 { // Ctrl+C
			sshConn.Close()
			break
		}
	}

	log.Printf("SSH connection closed for subdomain: %s", sub)
}

// forwardToSSH forwards a TCP connection to the SSH client via forwarded-tcpip channel
func (s *Server) forwardToSSH(sshConn *ssh.ServerConn, tcpConn net.Conn, bindAddr string, bindPort uint32) {
	defer tcpConn.Close()

	var originAddr string
	var originPort uint32
	if tcpAddr, ok := tcpConn.RemoteAddr().(*net.TCPAddr); ok {
		originAddr = tcpAddr.IP.String()
		originPort = uint32(tcpAddr.Port)
	} else {
		originAddr = "0.0.0.0"
		originPort = 0
	}

	channel, reqs, err := sshConn.OpenChannel("forwarded-tcpip", ssh.Marshal(&forwardedTCPPayload{
		Addr:       bindAddr,
		Port:       bindPort,
		OriginAddr: originAddr,
		OriginPort: originPort,
	}))
	if err != nil {
		log.Printf("Failed to open forwarded-tcpip channel: %v", err)
		return
	}
	defer channel.Close()

	go ssh.DiscardRequests(reqs)

	done := make(chan struct{})
	go func() {
		io.Copy(channel, tcpConn)
		channel.CloseWrite()
	}()
	go func() {
		defer close(done)
		io.Copy(tcpConn, channel)
	}()
	<-done
}

// extractSubdomainFromBindAddr checks if the bind address from a tcpip-forward
// request contains a subdomain name (rather than an IP address).
// This allows clients to specify a subdomain via: ssh -R <subdomain>:<port>:localhost:<port> host
// Returns the subdomain name, or "" if the address is not a subdomain.
func extractSubdomainFromBindAddr(addr string) string {
	addr = strings.TrimSpace(strings.ToLower(addr))
	if addr == "" || addr == "localhost" || addr == "0.0.0.0" || addr == "::" {
		return ""
	}
	// Skip if it's a valid IP address
	if net.ParseIP(addr) != nil {
		return ""
	}
	// Validate as a custom subdomain
	if err := subdomain.ValidateCustom(addr); err != nil {
		return ""
	}
	return addr
}

// promptSubdomain interactively prompts the user through the SSH channel to enter
// a subdomain or press Enter for a random one. Returns the chosen subdomain or "" on failure.
func (s *Server) promptSubdomain(channel ssh.Channel, sshConn *ssh.ServerConn) string {
	const maxAttempts = 5

	welcome := "\r\n" +
		ansiBoldGreen + "Welcome to " + s.domain + "!" + ansiReset + "\r\n" +
		ansiGray + "You can choose a custom subdomain or get a random one." + ansiReset + "\r\n" +
		ansiGray + "Rules: 3-32 chars, lowercase letters, numbers, and hyphens only." + ansiReset + "\r\n\r\n"
	fmt.Fprint(channel, welcome)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		prompt := ansiYellow + "Enter subdomain (or press Enter for random): " + ansiReset
		fmt.Fprint(channel, prompt)

		input, err := readLine(channel)
		if err != nil {
			return "" // connection closed
		}

		input = strings.TrimSpace(strings.ToLower(input))

		// Empty input => generate random subdomain
		if input == "" {
			sub, err := s.GenerateUniqueSubdomain()
			if err != nil {
				fmt.Fprintf(channel, ansiRed+"  Error generating subdomain: %s"+ansiReset+"\r\n", err)
				return ""
			}
			return sub
		}

		// Validate format
		if err := subdomain.ValidateCustom(input); err != nil {
			fmt.Fprintf(channel, ansiRed+"  Invalid: %s"+ansiReset+"\r\n", err)
			continue
		}

		// Check availability
		if s.IsSubdomainTaken(input) {
			fmt.Fprintf(channel, ansiRed+"  Subdomain \"%s\" is already taken."+ansiReset+"\r\n", input)
			continue
		}

		return input
	}

	fmt.Fprintf(channel, ansiRed+"  Too many attempts. Disconnecting."+ansiReset+"\r\n")
	return ""
}

// readLine reads a line from the SSH channel character by character,
// handling backspace and echoing characters back. Returns on Enter or error.
func readLine(channel ssh.Channel) (string, error) {
	var line []byte
	buf := make([]byte, 1)

	for {
		_, err := channel.Read(buf)
		if err != nil {
			return "", err
		}

		ch := buf[0]

		switch {
		case ch == 0x03: // Ctrl+C
			fmt.Fprint(channel, "\r\n")
			return "", fmt.Errorf("interrupted")
		case ch == 0x04: // Ctrl+D
			fmt.Fprint(channel, "\r\n")
			return "", fmt.Errorf("EOF")
		case ch == '\r' || ch == '\n': // Enter
			fmt.Fprint(channel, "\r\n")
			return string(line), nil
		case ch == 127 || ch == 0x08: // Backspace / Delete
			if len(line) > 0 {
				line = line[:len(line)-1]
				fmt.Fprint(channel, "\b \b")
			}
		case ch == 0x15: // Ctrl+U - clear line
			for len(line) > 0 {
				line = line[:len(line)-1]
				fmt.Fprint(channel, "\b \b")
			}
		case ch >= 32 && ch < 127: // Printable ASCII
			if len(line) < 32 { // Max subdomain length
				line = append(line, ch)
				channel.Write(buf) // Echo the character
			}
		}
	}
}

// sendErrorAndClose sends an error message to the client and closes the connection
func (s *Server) sendErrorAndClose(sshConn *ssh.ServerConn, chans <-chan ssh.NewChannel, errMsg string) {
	select {
	case newChannel, ok := <-chans:
		if !ok {
			return
		}
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			return
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range requests {
				if req.Type == "pty-req" || req.Type == "shell" {
					if req.WantReply {
						req.Reply(true, nil)
					}
				} else if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}()
		fmt.Fprintf(channel, "\r\n  ERROR: %s\r\n\r\n", errMsg)
		channel.Close()
	case <-time.After(3 * time.Second):
		return
	}
}
