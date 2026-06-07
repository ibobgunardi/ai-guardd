package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigExpandsEnvironmentVariables(t *testing.T) {
	t.Setenv("AI_GUARDD_TEST_WEBHOOK", "https://example.invalid/webhook")
	t.Setenv("AI_GUARDD_TEST_AUDIT_PATH", "/var/log/ai-guardd/audit.jsonl")
	t.Setenv("AI_GUARDD_TEST_RULE_DURATION", "45m")

	path := writeConfig(t, `
notification:
  discord_webhook: "${AI_GUARDD_TEST_WEBHOOK}"

detection:
  local_llm_url: "${AI_GUARDD_TEST_LLM_URL}"
  rules:
    - name: "ssh_brute_force"
      type: "threshold"
      metric: "failed_logins"
      threshold: 3
      action: "ban_ip"
      duration: "${AI_GUARDD_TEST_RULE_DURATION}"
      risk: "high"
      summary: "SSH Brute Force Detected"

output:
  audit_log_path: "${AI_GUARDD_TEST_AUDIT_PATH}"
`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Notification.DiscordWebhook != "https://example.invalid/webhook" {
		t.Fatalf("DiscordWebhook = %q", cfg.Notification.DiscordWebhook)
	}
	if cfg.Output.AuditLogPath != "/var/log/ai-guardd/audit.jsonl" {
		t.Fatalf("AuditLogPath = %q", cfg.Output.AuditLogPath)
	}
	if got := cfg.Detection.Rules[0].Duration; got != "45m" {
		t.Fatalf("rule duration = %q", got)
	}
	if cfg.Detection.LocalLLMUrl != "http://localhost:11434/api/generate" {
		t.Fatalf("LocalLLMUrl default = %q", cfg.Detection.LocalLLMUrl)
	}
}

func TestLoadConfigDefaultsAuditLogPath(t *testing.T) {
	path := writeConfig(t, `output: {}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.Output.AuditLogPath != "audit.log" {
		t.Fatalf("AuditLogPath default = %q", cfg.Output.AuditLogPath)
	}
}

func TestLoadConfigDefaultsDashboardPort(t *testing.T) {
	path := writeConfig(t, `dashboard: {}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.Dashboard.Port != ":8080" {
		t.Fatalf("Dashboard.Port default = %q", cfg.Dashboard.Port)
	}
}

func TestLoadConfigKeepsDashboardPort(t *testing.T) {
	path := writeConfig(t, `
dashboard:
  port: ":9091"
`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.Dashboard.Port != ":9091" {
		t.Fatalf("Dashboard.Port = %q", cfg.Dashboard.Port)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return path
}
