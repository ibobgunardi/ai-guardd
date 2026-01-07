package parser

import (
	"regexp"
	"strings"
)

// SSHParser extracts events from sshd logs
type SSHParser struct {
	// Pre-compiled regexes
	reFailed        *regexp.Regexp
	reFailedInvalid *regexp.Regexp
	reAccepted      *regexp.Regexp
}

// NewSSHParser creates a new SSH log parser
func NewSSHParser() *SSHParser {
	return &SSHParser{
		// Failed password for invalid user root from 1.2.3.4 ...
		reFailedInvalid: regexp.MustCompile(`Failed password for invalid user (\S+) from (\S+)`),
		// Failed password for root from 1.2.3.4 ...
		reFailed: regexp.MustCompile(`Failed password for (\S+) from (\S+)`),
		// Accepted password for root from 1.2.3.4 ...
		reAccepted: regexp.MustCompile(`Accepted \w+ for (\S+) from (\S+)`),
	}
}

// Parse implements the Parser interface
func (p *SSHParser) Parse(line string) *ParsedEvent {
	// Basic check to see if it's an sshd line
	if !strings.Contains(line, "sshd") {
		return nil
	}

	// TODO: Parse timestamp from syslog header (Dec 10 12:34:56 ...)
	// For now, we assume "now" or let the detector use the ingest timestamp
	// But sticking to the "ParsedEvent" structure:

	evt := &ParsedEvent{
		Source: "ssh",
		Raw:    line,
	}

	// Check for "Invalid user" first (more specific)
	if matches := p.reFailedInvalid.FindStringSubmatch(line); len(matches) > 2 {
		evt.Type = "login_failed"
		evt.User = matches[1]
		evt.IP = matches[2]
		return evt
	}

	// Check for standard failed
	if matches := p.reFailed.FindStringSubmatch(line); len(matches) > 2 {
		evt.Type = "login_failed"
		evt.User = matches[1]
		evt.IP = matches[2]
		return evt
	}

	// Check for accepted
	if matches := p.reAccepted.FindStringSubmatch(line); len(matches) > 2 {
		evt.Type = "login_success"
		evt.User = matches[1]
		evt.IP = matches[2]
		return evt
	}

	return nil
}
