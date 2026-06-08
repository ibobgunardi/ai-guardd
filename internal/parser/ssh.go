package parser

import (
	"regexp"
	"time"
)

var syslogTimestampRE = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+`)

const syslogTimestampLayout = "Jan _2 15:04:05"

// SSHParser extracts events from sshd logs
type SSHParser struct {
	// Pre-compiled regexes
	reFailed        *regexp.Regexp
	reFailedInvalid *regexp.Regexp
	reInvalidUser   *regexp.Regexp
	reAccepted      *regexp.Regexp
}

// NewSSHParser creates a new SSH log parser
func NewSSHParser() *SSHParser {
	return &SSHParser{
		// Failed <method> for invalid user root from 1.2.3.4 ...
		reFailedInvalid: regexp.MustCompile(`Failed \S+ for invalid user (\S+) from (\S+)`),
		// Invalid user root from 1.2.3.4 ...
		reInvalidUser: regexp.MustCompile(`Invalid user (\S+) from (\S+)`),
		// Failed <method> for root from 1.2.3.4 ...
		reFailed: regexp.MustCompile(`Failed \S+ for (\S+) from (\S+)`),
		// Accepted <method> for root from 1.2.3.4 ...
		reAccepted: regexp.MustCompile(`Accepted \S+ for (\S+) from (\S+)`),
	}
}

// Parse implements the Parser interface
func (p *SSHParser) Parse(line string) *ParsedEvent {
	evt := &ParsedEvent{
		Source:    "ssh",
		Timestamp: parseSyslogTimestamp(line, time.Now()),
		Raw:       line,
	}

	// Check for "Invalid user" first (more specific)
	if matches := p.reFailedInvalid.FindStringSubmatch(line); len(matches) > 2 {
		evt.Type = "login_failed"
		evt.User = matches[1]
		evt.IP = matches[2]
		return evt
	}

	// Check for standalone invalid user lines
	if matches := p.reInvalidUser.FindStringSubmatch(line); len(matches) > 2 {
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

func parseSyslogTimestamp(line string, now time.Time) time.Time {
	matches := syslogTimestampRE.FindStringSubmatch(line)
	if len(matches) < 2 {
		return time.Time{}
	}

	parsed, err := time.ParseInLocation(syslogTimestampLayout, matches[1], now.Location())
	if err != nil {
		return time.Time{}
	}

	timestamp := time.Date(now.Year(), parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), 0, now.Location())
	if timestamp.After(now.Add(30 * 24 * time.Hour)) {
		timestamp = timestamp.AddDate(-1, 0, 0)
	}
	return timestamp
}
