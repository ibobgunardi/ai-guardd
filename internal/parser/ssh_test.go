package parser

import (
	"testing"
	"time"
)

func TestSSHParser_Parse_Success(t *testing.T) {
	parser := NewSSHParser()

	// Test failed login
	line := "Failed password for invalid user admin from 192.168.1.100 port 52944 ssh2"
	evt := parser.Parse(line)

	if evt == nil {
		t.Fatal("Expected parsed event, got nil")
	}
	if evt.Type != "login_failed" {
		t.Errorf("Expected type 'login_failed', got '%s'", evt.Type)
	}
	if evt.User != "admin" {
		t.Errorf("Expected user 'admin', got '%s'", evt.User)
	}
	if evt.IP != "192.168.1.100" {
		t.Errorf("Expected IP '192.168.1.100', got '%s'", evt.IP)
	}
}

func TestSSHParser_Parse_StandaloneInvalidUser(t *testing.T) {
	parser := NewSSHParser()

	line := "Invalid user deploy from 203.0.113.42 port 42422"
	evt := parser.Parse(line)

	if evt == nil {
		t.Fatal("Expected parsed event, got nil")
	}
	if evt.Type != "login_failed" {
		t.Errorf("Expected type 'login_failed', got '%s'", evt.Type)
	}
	if evt.User != "deploy" {
		t.Errorf("Expected user 'deploy', got '%s'", evt.User)
	}
	if evt.IP != "203.0.113.42" {
		t.Errorf("Expected IP '203.0.113.42', got '%s'", evt.IP)
	}
}

func TestSSHParser_Parse_FailedPublickey(t *testing.T) {
	parser := NewSSHParser()

	line := "Failed publickey for deploy from 203.0.113.43 port 51234 ssh2"
	evt := parser.Parse(line)

	if evt == nil {
		t.Fatal("Expected parsed event, got nil")
	}
	if evt.Type != "login_failed" {
		t.Errorf("Expected type 'login_failed', got '%s'", evt.Type)
	}
	if evt.User != "deploy" {
		t.Errorf("Expected user 'deploy', got '%s'", evt.User)
	}
	if evt.IP != "203.0.113.43" {
		t.Errorf("Expected IP '203.0.113.43', got '%s'", evt.IP)
	}
}

func TestSSHParser_Parse_FailedPublickeyInvalidUser(t *testing.T) {
	parser := NewSSHParser()

	line := "Failed publickey for invalid user oracle from 203.0.113.44 port 51235 ssh2"
	evt := parser.Parse(line)

	if evt == nil {
		t.Fatal("Expected parsed event, got nil")
	}
	if evt.Type != "login_failed" {
		t.Errorf("Expected type 'login_failed', got '%s'", evt.Type)
	}
	if evt.User != "oracle" {
		t.Errorf("Expected user 'oracle', got '%s'", evt.User)
	}
	if evt.IP != "203.0.113.44" {
		t.Errorf("Expected IP '203.0.113.44', got '%s'", evt.IP)
	}
}

func TestSSHParser_Parse_Accepted(t *testing.T) {
	parser := NewSSHParser()

	line := "Accepted password for root from 10.0.0.5 port 22 ssh2"
	evt := parser.Parse(line)

	if evt == nil {
		t.Fatal("Expected parsed event, got nil")
	}
	if evt.Type != "login_success" {
		t.Errorf("Expected type 'login_success', got '%s'", evt.Type)
	}
	if evt.User != "root" {
		t.Errorf("Expected user 'root', got '%s'", evt.User)
	}
}

func TestSSHParser_Parse_AcceptedKeyboardInteractive(t *testing.T) {
	parser := NewSSHParser()

	line := "Accepted keyboard-interactive/pam for admin from 10.0.0.6 port 22 ssh2"
	evt := parser.Parse(line)

	if evt == nil {
		t.Fatal("Expected parsed event, got nil")
	}
	if evt.Type != "login_success" {
		t.Errorf("Expected type 'login_success', got '%s'", evt.Type)
	}
	if evt.User != "admin" {
		t.Errorf("Expected user 'admin', got '%s'", evt.User)
	}
	if evt.IP != "10.0.0.6" {
		t.Errorf("Expected IP '10.0.0.6', got '%s'", evt.IP)
	}
}

func TestSSHParser_Parse_SyslogTimestamp(t *testing.T) {
	parser := NewSSHParser()
	now := time.Now()
	prefix := now.Format(syslogTimestampLayout)
	line := prefix + " host sshd[1234]: Failed password for deploy from 203.0.113.45 port 51236 ssh2"

	evt := parser.Parse(line)

	if evt == nil {
		t.Fatal("Expected parsed event, got nil")
	}
	want := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), 0, now.Location())
	if !evt.Timestamp.Equal(want) {
		t.Fatalf("Timestamp = %s, want %s", evt.Timestamp, want)
	}
}

func TestParseSyslogTimestampUsesPreviousYearForFutureDate(t *testing.T) {
	location := time.FixedZone("test", 0)
	now := time.Date(2026, time.January, 2, 3, 0, 0, 0, location)
	line := "Dec 31 23:59:59 host sshd[1234]: Failed password for root from 203.0.113.46 port 51237 ssh2"

	got := parseSyslogTimestamp(line, now)

	want := time.Date(2025, time.December, 31, 23, 59, 59, 0, location)
	if !got.Equal(want) {
		t.Fatalf("parseSyslogTimestamp() = %s, want %s", got, want)
	}
}

func TestSSHParser_Parse_Invalid(t *testing.T) {
	parser := NewSSHParser()

	// Test with non-matching line
	line := "This is not an SSH log line"
	evt := parser.Parse(line)

	if evt != nil {
		t.Error("Expected nil for invalid line, got event")
	}
}
