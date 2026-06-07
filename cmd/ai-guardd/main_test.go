package main

import (
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

func writeMainTestConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return path
}
