package parser

import "testing"

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
