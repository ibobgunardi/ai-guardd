package action

import (
	"ai-guardd/internal/types"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

// Broker handles the execution of suggested actions
type Broker struct {
	ActiveDefense  bool
	Allowlist      []string
	DiscordWebhook string
}

// NewBroker creates a new action broker
func NewBroker(activeDefense bool, allowlist []string, discordWebhook string) *Broker {
	return &Broker{
		ActiveDefense:  activeDefense,
		Allowlist:      allowlist,
		DiscordWebhook: discordWebhook,
	}
}

// Execute processes the event and its suggested action
func (b *Broker) Execute(evt *types.Event) error {
	if evt == nil || evt.SuggestedAction == nil {
		return nil
	}

	act := evt.SuggestedAction

	// 0. Always Notify if configured (Async)
	if b.DiscordWebhook != "" {
		go b.sendDiscordAlert(evt)
	}

	// 1. Check Allowlist
	for _, allowed := range b.Allowlist {
		if allowed == act.Target {
			log.Printf("[SAFETY] Action BLOCKED by Allowlist for IP: %s", act.Target)
			return nil
		}
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

	cmdStr := b.buildCommand(act)
	if cmdStr == "" {
		return nil
	}

	if !b.ActiveDefense {
		log.Printf("[SAFE MODE] Would execute: %s", cmdStr)
		return nil
	}

	log.Printf("[ACTIVE DEFENSE] Executing: %s", cmdStr)

	return nil
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
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(b.DiscordWebhook, "application/json", bytes.NewBuffer(body))
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

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
