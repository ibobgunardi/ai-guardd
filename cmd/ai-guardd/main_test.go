package main

import (
	"ai-guardd/internal/ingest"
	"ai-guardd/internal/parser"
	"ai-guardd/internal/types"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveAuditLogPathUsesOverride(t *testing.T) {
	got, err := resolveAuditLogPath("missing-config.yml", "custom-audit.jsonl")
	if err != nil {
		t.Fatalf("resolveAuditLogPath() error = %v", err)
	}
	if got != "custom-audit.jsonl" {
		t.Fatalf("path = %q", got)
	}
}

func TestResolveAuditLogPathUsesConfig(t *testing.T) {
	configPath := writeMainTestConfig(t, `
output:
  audit_log_path: "/var/log/ai-guardd/audit.jsonl"
`)

	got, err := resolveAuditLogPath(configPath, "")
	if err != nil {
		t.Fatalf("resolveAuditLogPath() error = %v", err)
	}
	if got != "/var/log/ai-guardd/audit.jsonl" {
		t.Fatalf("path = %q", got)
	}
}

func TestResolveAuditLogPathUsesConfigDefault(t *testing.T) {
	configPath := writeMainTestConfig(t, `output: {}`)

	got, err := resolveAuditLogPath(configPath, "")
	if err != nil {
		t.Fatalf("resolveAuditLogPath() error = %v", err)
	}
	if got != "audit.log" {
		t.Fatalf("path = %q", got)
	}
}

func TestSanitizeStripsTerminalControlRunes(t *testing.T) {
	input := "safe\x1b[31m red\x7f \u009b31m text"
	got := sanitize(input)
	want := "safe[31m red 31m text"

	if got != want {
		t.Fatalf("sanitize() = %q, want %q", got, want)
	}
}

func TestSanitizeKeepsNewlineAndTab(t *testing.T) {
	input := "line one\n\tline two"
	got := sanitize(input)

	if got != input {
		t.Fatalf("sanitize() = %q, want %q", got, input)
	}
}

func TestFormatSuggestedAction(t *testing.T) {
	action := &types.SuggestedAction{
		Type:     "ban_ip",
		Target:   "203.0.113.10",
		Duration: "1h",
	}

	got := formatSuggestedAction(action)
	want := "ban_ip 203.0.113.10 (1h)"
	if got != want {
		t.Fatalf("formatSuggestedAction() = %q, want %q", got, want)
	}
}

func TestFormatSuggestedActionHandlesNil(t *testing.T) {
	got := formatSuggestedAction(nil)
	if got != "none" {
		t.Fatalf("formatSuggestedAction(nil) = %q", got)
	}
}

func TestApplyIngestTimestampFillsMissingTimestamp(t *testing.T) {
	event := &parser.ParsedEvent{}
	ingestTimestamp := int64(1780830000)

	applyIngestTimestamp(event, ingestTimestamp)

	want := time.Unix(ingestTimestamp, 0)
	if !event.Timestamp.Equal(want) {
		t.Fatalf("Timestamp = %s, want %s", event.Timestamp, want)
	}
}

func TestApplyIngestTimestampKeepsParsedTimestamp(t *testing.T) {
	parsedTimestamp := time.Unix(1780830000, 0)
	event := &parser.ParsedEvent{Timestamp: parsedTimestamp}

	applyIngestTimestamp(event, parsedTimestamp.Add(time.Hour).Unix())

	if !event.Timestamp.Equal(parsedTimestamp) {
		t.Fatalf("Timestamp = %s, want %s", event.Timestamp, parsedTimestamp)
	}
}

func TestApplyIngestTimestampIgnoresEmptyTimestamp(t *testing.T) {
	event := &parser.ParsedEvent{}

	applyIngestTimestamp(event, 0)

	if !event.Timestamp.IsZero() {
		t.Fatalf("Timestamp = %s, want zero", event.Timestamp)
	}
}

func TestParseLogMessageRoutesJournaldSudo(t *testing.T) {
	cfg := &types.Config{}
	cfg.Input.EnableJournal = true

	event := parseLogMessage(
		ingest.LogLine{
			Source:  "sudo",
			Content: "sudo[1234]: pam_unix(sudo:auth): authentication failure; logname= uid=1000 euid=0 tty=/dev/pts/0 ruser=deploy rhost= user=deploy",
		},
		cfg,
		parser.NewSSHParser(),
		parser.NewHTTPParser("web_server"),
		parser.NewSyslogParser(),
	)

	if event == nil {
		t.Fatal("expected journald sudo event to parse")
	}
	if event.Source != "syslog_sudo" {
		t.Fatalf("Source = %q", event.Source)
	}
	if event.Type != "priv_escalation_fail" {
		t.Fatalf("Type = %q", event.Type)
	}
}

func TestParseLogMessageRoutesJournaldMySQL(t *testing.T) {
	cfg := &types.Config{}
	cfg.Input.EnableJournal = true

	event := parseLogMessage(
		ingest.LogLine{
			Source:  "mysqld",
			Content: "mysqld[1234]: Access denied for user 'root'@'203.0.113.25' (using password: YES)",
		},
		cfg,
		parser.NewSSHParser(),
		parser.NewHTTPParser("web_server"),
		parser.NewSyslogParser(),
	)

	if event == nil {
		t.Fatal("expected journald MySQL event to parse")
	}
	if event.Source != "mysql" {
		t.Fatalf("Source = %q", event.Source)
	}
	if event.Type != "login_failed" {
		t.Fatalf("Type = %q", event.Type)
	}
	if event.IP != "203.0.113.25" {
		t.Fatalf("IP = %q", event.IP)
	}
}

func TestParseLogMessageNormalizesJournalSource(t *testing.T) {
	cfg := &types.Config{}
	cfg.Input.EnableJournal = true

	event := parseLogMessage(
		ingest.LogLine{
			Source:  " MySQL ",
			Content: "mysqld[1234]: Access denied for user 'root'@'203.0.113.26' (using password: YES)",
		},
		cfg,
		parser.NewSSHParser(),
		parser.NewHTTPParser("web_server"),
		parser.NewSyslogParser(),
	)

	if event == nil {
		t.Fatal("expected normalized journald source to parse")
	}
	if event.Source != "mysql" {
		t.Fatalf("Source = %q", event.Source)
	}
	if event.IP != "203.0.113.26" {
		t.Fatalf("IP = %q", event.IP)
	}
}

func TestParseLogMessageIgnoresJournalSourcesWhenDisabled(t *testing.T) {
	cfg := &types.Config{}

	event := parseLogMessage(
		ingest.LogLine{
			Source:  "sudo",
			Content: "sudo[1234]: pam_unix(sudo:auth): authentication failure; user=deploy",
		},
		cfg,
		parser.NewSSHParser(),
		parser.NewHTTPParser("web_server"),
		parser.NewSyslogParser(),
	)

	if event != nil {
		t.Fatalf("expected journald source to be ignored when disabled, got %#v", event)
	}
}

func writeMainTestConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return path
}
