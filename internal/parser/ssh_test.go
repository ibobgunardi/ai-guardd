package parser

import (
	"testing"
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

func TestSSHParser_Parse_Invalid(t *testing.T) {
	parser := NewSSHParser()

	// Test with non-matching line
	line := "This is not an SSH log line"
	evt := parser.Parse(line)

	if evt != nil {
		t.Error("Expected nil for invalid line, got event")
	}
}
