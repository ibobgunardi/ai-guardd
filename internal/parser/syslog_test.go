package parser

import (
	"testing"
	"time"
)

func TestSyslogParser_Parse_MySQLAccessDenied(t *testing.T) {
	parser := NewSyslogParser()

	line := "mysqld[1234]: Access denied for user 'root'@'203.0.113.25' (using password: YES)"
	evt := parser.Parse(line)

	if evt == nil {
		t.Fatal("Expected parsed event, got nil")
	}
	if evt.Type != "login_failed" {
		t.Errorf("Type = %q", evt.Type)
	}
	if evt.Source != "mysql" {
		t.Errorf("Source = %q", evt.Source)
	}
	if evt.User != "root" {
		t.Errorf("User = %q", evt.User)
	}
	if evt.IP != "203.0.113.25" {
		t.Errorf("IP = %q", evt.IP)
	}
}

func TestSyslogParser_Parse_MySQLAnonymousUser(t *testing.T) {
	parser := NewSyslogParser()

	line := "mysqld[1234]: Access denied for user ''@'localhost' (using password: NO)"
	evt := parser.Parse(line)

	if evt == nil {
		t.Fatal("Expected parsed event, got nil")
	}
	if evt.Type != "login_failed" {
		t.Errorf("Type = %q", evt.Type)
	}
	if evt.Source != "mysql" {
		t.Errorf("Source = %q", evt.Source)
	}
	if evt.User != "" {
		t.Errorf("User = %q", evt.User)
	}
	if evt.IP != "localhost" {
		t.Errorf("IP = %q", evt.IP)
	}
}

func TestSyslogParser_Parse_MySQLSyslogTimestamp(t *testing.T) {
	parser := NewSyslogParser()
	prefix := time.Now().Format(syslogTimestampLayout)
	line := prefix + " host mysqld[1234]: Access denied for user 'root'@'203.0.113.25' (using password: YES)"

	evt := parser.Parse(line)

	if evt == nil {
		t.Fatal("Expected parsed event, got nil")
	}
	if evt.Timestamp.IsZero() {
		t.Fatal("Expected timestamp to be parsed")
	}
	if got := evt.Timestamp.Format(syslogTimestampLayout); got != prefix {
		t.Fatalf("Timestamp = %q, want %q", got, prefix)
	}
}

func TestSyslogParser_Parse_SudoAuthFailure(t *testing.T) {
	parser := NewSyslogParser()

	line := "sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1000 euid=0 tty=/dev/pts/0 ruser=deploy rhost= user=deploy"
	evt := parser.Parse(line)

	if evt == nil {
		t.Fatal("Expected parsed event, got nil")
	}
	if evt.Type != "priv_escalation_fail" {
		t.Errorf("Type = %q", evt.Type)
	}
	if evt.Source != "syslog_sudo" {
		t.Errorf("Source = %q", evt.Source)
	}
	if evt.User != "deploy" {
		t.Errorf("User = %q", evt.User)
	}
	if evt.IP != "local" {
		t.Errorf("IP = %q", evt.IP)
	}
}

func TestSyslogParser_Parse_SudoSyslogTimestamp(t *testing.T) {
	parser := NewSyslogParser()
	prefix := time.Now().Format(syslogTimestampLayout)
	line := prefix + " host sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1000 euid=0 tty=/dev/pts/0 ruser=deploy rhost= user=deploy"

	evt := parser.Parse(line)

	if evt == nil {
		t.Fatal("Expected parsed event, got nil")
	}
	if evt.Timestamp.IsZero() {
		t.Fatal("Expected timestamp to be parsed")
	}
	if got := evt.Timestamp.Format(syslogTimestampLayout); got != prefix {
		t.Fatalf("Timestamp = %q, want %q", got, prefix)
	}
}
