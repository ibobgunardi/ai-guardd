package main

import (
	"ai-guardd/internal/types"
	"os"
	"path/filepath"
	"testing"
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

func writeMainTestConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return path
}
