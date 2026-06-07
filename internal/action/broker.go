package action

import (
	"ai-guardd/internal/types"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type commandRunner func(name string, args ...string) error

// Broker handles the execution of suggested actions
type Broker struct {
	mu             sync.RWMutex
	ActiveDefense  bool
	Allowlist      []string
	DiscordWebhook string
	ExecutorSocket string
	runCommand     commandRunner
}

// NewBroker creates a new action broker
func NewBroker(activeDefense bool, allowlist []string, discordWebhook string, executorSocket string) *Broker {
	return &Broker{
		ActiveDefense:  activeDefense,
		Allowlist:      allowlist,
		DiscordWebhook: discordWebhook,
		ExecutorSocket: executorSocket,
		runCommand:     runSystemCommand,
	}
}

// UpdateConfig updates the broker's configuration safely at runtime
func (b *Broker) UpdateConfig(activeDefense bool, allowlist []string, discordWebhook string, executorSocket string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ActiveDefense = activeDefense
	b.Allowlist = allowlist
	b.DiscordWebhook = discordWebhook
	b.ExecutorSocket = executorSocket
	log.Println("[CONFIG] Broker configuration updated dynamically")
}

// Execute processes the event and its suggested action
func (b *Broker) Execute(evt *types.Event) error {
	if evt == nil || evt.SuggestedAction == nil {
		return nil
	}

	act := evt.SuggestedAction

	// 0. Always Notify if configured (Async)
	b.mu.RLock()
	webhook := b.DiscordWebhook
	activeDefense := b.ActiveDefense
	allowlist := b.Allowlist
	b.mu.RUnlock()

	if webhook != "" {
		go b.sendDiscordAlert(evt)
	}

	// 1. Check Allowlist
	if isAllowedTarget(act.Target, allowlist) {
		log.Printf("[SAFETY] Action BLOCKED by Allowlist for IP: %s", act.Target)
		return nil
	}

	// 2. Strict Input Validation (Prevent Command Injection)
	// Only validate IP for networking bans, skip for generic actions if needed
	if act.Type == "ban_ip" {
		if !isValidIP(act.Target) {
			log.Printf("[SECURITY] Action BLOCKED: Invalid IP/Target potential injection: %s", act.Target)
			return nil
		}
	}

	// Special Case: notify_admin is handled by the Discord call above
	if act.Type == "notify_admin" {
		log.Printf("[NOTIFY] Admin notification triggered for: %s", evt.Summary)
		return nil
	}
	if act.Type != "ban_ip" {
		log.Printf("[ACTION] Ignoring unsupported action type: %s", act.Type)
		return nil
	}

	b.mu.RLock()
	executorSocket := b.ExecutorSocket
	b.mu.RUnlock()

	if executorSocket != "" {
		if !activeDefense {
			log.Printf("[SAFE MODE] Would send to executor: ban %s", act.Target)
			return nil
		}
		return b.sendToExecutor("ban", act.Target)
	}

	cmdStr := b.buildCommand(act)
	if cmdStr == "" {
		return nil
	}

	if !activeDefense {
		log.Printf("[SAFE MODE] Would execute: %s", cmdStr)
		return nil
	}

	log.Printf("[ACTIVE DEFENSE] Executing: %s", cmdStr)

	return b.executeCommand(act)
}

// sendDiscordAlert sends a JSON payload to Discord
func (b *Broker) sendDiscordAlert(evt *types.Event) {
	type discordMsg struct {
		Content string `json:"content"`
	}

	msg := discordMsg{
		Content: fmt.Sprintf("**[%s] AI-Guardd Alert**\n**Summary**: %s\n**Risk**: %s\n**Source**: %s\n**Action**: %s %s\n\n`%s`",
			time.Now().Format("15:04:05"), evt.Summary, evt.Risk, evt.Source, evt.SuggestedAction.Type, evt.SuggestedAction.Target, evt.Explanation),
	}

	body, _ := json.Marshal(msg)

	// Fire and forget, but with timeout
	b.mu.RLock()
	webhook := b.DiscordWebhook
	b.mu.RUnlock()

	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(webhook, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("Failed to send Discord alert: %v", err)
		return
	}
	defer resp.Body.Close()
}

func (b *Broker) buildCommand(act *types.SuggestedAction) string {
	// Double check validation here just in case
	if act.Type == "ban_ip" && !isValidIP(act.Target) {
		return ""
	}

	switch act.Type {
	case "ban_ip":
		// Example: iptables -A INPUT -s 1.2.3.4 -j DROP
		// Target is now guaranteed to be a valid IP, so safe to inject.
		return fmt.Sprintf("iptables -A INPUT -s %s -j DROP # Duration: %s", act.Target, act.Duration)
	default:
		return ""
	}
}

func (b *Broker) executeCommand(act *types.SuggestedAction) error {
	run := b.runCommand
	if run == nil {
		run = runSystemCommand
	}

	switch act.Type {
	case "ban_ip":
		if err := run("iptables", "-A", "INPUT", "-s", act.Target, "-j", "DROP"); err != nil {
			return fmt.Errorf("failed to ban IP %s: %w", act.Target, err)
		}
		return nil
	default:
		return nil
	}
}

func runSystemCommand(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func (b *Broker) sendToExecutor(action, target string) error {
	conn, err := net.Dial("unix", b.ExecutorSocket)
	if err != nil {
		return fmt.Errorf("failed to connect to executor: %w", err)
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "%s %s\n", action, target)
	if err != nil {
		return fmt.Errorf("failed to send command to executor: %w", err)
	}

	log.Printf("[BROKER] Command sent to privileged executor: %s %s", action, target)
	return nil
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isAllowedTarget(target string, allowlist []string) bool {
	targetIP := net.ParseIP(target)

	for _, allowed := range allowlist {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		if allowed == target {
			return true
		}

		if targetIP == nil {
			continue
		}

		if allowedIP := net.ParseIP(allowed); allowedIP != nil && allowedIP.Equal(targetIP) {
			return true
		}

		if _, network, err := net.ParseCIDR(allowed); err == nil && network.Contains(targetIP) {
			return true
		}
	}

	return false
}
