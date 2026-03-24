package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"tunnl.gg/internal/server"
)

func main() {
	cfg := struct {
		SSHAddr       string
		HostKeyPath   string
		Domain        string
		CaddyAdminURL string
	}{
		SSHAddr:       ":8888",
		HostKeyPath:   "/host_key",
		Domain:        "jatus.top",
		CaddyAdminURL: "http://localhost:2019",
	}

	if v := os.Getenv("SSH_ADDR"); v != "" {
		cfg.SSHAddr = v
	}
	if v := os.Getenv("HOST_KEY_PATH"); v != "" {
		cfg.HostKeyPath = v
	}
	if v := os.Getenv("DOMAIN"); v != "" {
		cfg.Domain = v
	}
	if v := os.Getenv("CADDY_ADMIN_URL"); v != "" {
		cfg.CaddyAdminURL = v
	}

	srv, err := server.New(cfg.HostKeyPath, cfg.Domain, cfg.CaddyAdminURL)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start SSH server
	sshListener, err := net.Listen("tcp", cfg.SSHAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.SSHAddr, err)
	}
	log.Printf("SSH server listening on %s", cfg.SSHAddr)

	sshShutdown := make(chan struct{})
	sshDone := make(chan struct{})
	go func() {
		defer close(sshDone)
		for {
			conn, err := sshListener.Accept()
			if err != nil {
				select {
				case <-sshShutdown:
					return
				default:
				}
				log.Printf("Failed to accept SSH connection: %v", err)
				continue
			}
			go srv.HandleSSHConnection(conn)
		}
	}()

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("Received signal %v, shutting down...", sig)

	close(sshShutdown)
	sshListener.Close()
	<-sshDone

	srv.Stop()
	log.Println("Shutdown complete")
}
