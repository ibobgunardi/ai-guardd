package action

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"strings"
)

const executorSocketMode os.FileMode = 0o660

// Executor runs as root and listens for ban requests over a Unix socket
type Executor struct {
	SocketPath string
	runCommand commandRunner
}

func NewExecutor(socketPath string) *Executor {
	if socketPath == "" {
		socketPath = "/run/ai-guardd.sock"
	}
	return &Executor{
		SocketPath: socketPath,
		runCommand: runSystemCommand,
	}
}

func (e *Executor) Start() error {
	ln, err := e.listen()
	if err != nil {
		return err
	}

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

func (e *Executor) listen() (net.Listener, error) {
	if err := removeStaleSocket(e.SocketPath); err != nil {
		return nil, err
	}

	ln, err := net.Listen("unix", e.SocketPath)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(e.SocketPath, executorSocketMode); err != nil {
		ln.Close()
		os.Remove(e.SocketPath)
		return nil, fmt.Errorf("failed to restrict executor socket permissions: %w", err)
	}

	return ln, nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to inspect executor socket path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket executor path %q", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove stale executor socket: %w", err)
	}

	return nil
}

func (e *Executor) handleConnection(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) != 2 {
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
	if err := e.run(firewallCommand(ip), "-A", "INPUT", "-s", ip, "-j", "DROP"); err != nil {
		log.Printf("[EXECUTOR] Failed to ban %s: %v", ip, err)
	}
}

func (e *Executor) unbanIP(ip string) {
	log.Printf("[EXECUTOR] Unbanning IP: %s", ip)
	if err := e.run(firewallCommand(ip), "-D", "INPUT", "-s", ip, "-j", "DROP"); err != nil {
		log.Printf("[EXECUTOR] Failed to unban %s: %v", ip, err)
	}
}

func (e *Executor) run(name string, args ...string) error {
	if e.runCommand != nil {
		return e.runCommand(name, args...)
	}
	return runSystemCommand(name, args...)
}
