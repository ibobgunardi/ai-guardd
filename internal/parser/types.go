package parser

import "time"

// ParsedEvent represents a normalized detected action from a log
type ParsedEvent struct {
	Timestamp time.Time
	Source    string // "ssh", "nginx", "syslog"
	Type      string // "login_failed", "http_request", "sudo_fail"
	IP        string
	User      string
	Raw       string

	// HTTP specific
	Method     string
	URL        string
	StatusCode int
	UserAgent  string
}

// Parser defines the interface for log parsers
type Parser interface {
	Parse(line string) *ParsedEvent
}
