package ingest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"
)

// JournalEntry represents the JSON structure from journalctl
type JournalEntry struct {
	Timestamp        string `json:"__REALTIME_TIMESTAMP"` // Microseconds as string
	Message          string `json:"MESSAGE"`
	SyslogIdentifier string `json:"SYSLOG_IDENTIFIER"`
	PID              string `json:"_PID"`
	UID              string `json:"_UID"`  // User ID
	Comm             string `json:"_COMM"` // Command Name (e.g. sshd)
}

// JournalReader follows the systemd journal via CLI
type JournalReader struct {
	cmd *exec.Cmd
}

func NewJournalReader() *JournalReader {
	return &JournalReader{}
}

func (j *JournalReader) Start() (<-chan LogLine, error) {
	// Command: journalctl -f -o json
	cmd := exec.Command("journalctl", "-f", "-o", "json")

	// Create pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to pipe journalctl: %w", err)
	}

	if err := cmd.Start(); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("journalctl not found (not a systemd system?)")
		}
		return nil, fmt.Errorf("failed to start journalctl: %w", err)
	}
	j.cmd = cmd

	out := make(chan LogLine)

	go func() {
		defer close(out)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()

			var entry JournalEntry
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				// Malformed line (maybe partial), skip
				continue
			}

			// SECURITY: Anti-Spoofing Check for Critical Services
			// If it claims to be sshd, ensure it is running as root (UID 0) or is actually sshd binary
			if entry.SyslogIdentifier == "sshd" {
				// SSHD must be root (UID 0) in most setups
				if entry.UID != "0" {
					// Detects "logger -t sshd" from non-root user
					log.Printf("[SECURITY] Dropped SPOOFED sshd log from UID %s (PID %s)", entry.UID, entry.PID)
					continue
				}
			}

			// Format: "Processname[PID]: Message" to mimic syslog for existing parsers
			content := fmt.Sprintf("%s[%s]: %s", entry.SyslogIdentifier, entry.PID, entry.Message)

			out <- LogLine{
				Source:    "journald",
				Timestamp: time.Now().Unix(), // Parsing __REALTIME_TIMESTAMP is complex (microseconds), using Now() for MVP
				Content:   content,
			}
		}

		// If scanner stops, command might have died
		_ = cmd.Wait()
	}()

	return out, nil
}

func (j *JournalReader) Stop() error {
	if j.cmd != nil && j.cmd.Process != nil {
		return j.cmd.Process.Kill()
	}
	return nil
}
