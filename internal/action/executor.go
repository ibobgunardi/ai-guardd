package action

import (
	"bufio"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

// Executor runs as root and listens for ban requests over a Unix socket
type Executor struct {
	SocketPath string
}

func NewExecutor(socketPath string) *Executor {
	if socketPath == "" {
		socketPath = "/run/ai-guardd.sock"
	}
	return &Executor{SocketPath: socketPath}
}

func (e *Executor) Start() error {
	// Clean up existing socket
	if _, err := os.Stat(e.SocketPath); err == nil {
		os.Remove(e.SocketPath)
	}

	ln, err := net.Listen("unix", e.SocketPath)
	if err != nil {
		return err
	}

	// Ensure the socket is accessible by the analyzer group/user
	// In production, we'd set specific permissions (e.g. 0660)
	os.Chmod(e.SocketPath, 0666)

	log.Printf("[EXECUTOR] Listening on %s", e.SocketPath)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[EXECUTOR] Accept error: %v", err)
			continue
		}
		go e.handleConnection(conn)
	}
}

func (e *Executor) handleConnection(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		action := parts[0]
		target := parts[1]

		// Final safety check: target MUST be a valid IP
		if net.ParseIP(target) == nil {
			log.Printf("[EXECUTOR] Rejected invalid target: %s", target)
			continue
		}

		if action == "ban" {
			e.banIP(target)
		} else if action == "unban" {
			e.unbanIP(target)
		}
	}
}

func (e *Executor) banIP(ip string) {
	log.Printf("[EXECUTOR] Banning IP: %s", ip)
	// Actually execute iptables
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("[EXECUTOR] Failed to ban %s: %v", ip, err)
	}
}

func (e *Executor) unbanIP(ip string) {
	log.Printf("[EXECUTOR] Unbanning IP: %s", ip)
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("[EXECUTOR] Failed to unban %s: %v", ip, err)
	}
}
