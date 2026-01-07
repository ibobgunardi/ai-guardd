package types

import "time"

// RiskLevel defines the severity of an event
type RiskLevel string

const (
	RiskInfo     RiskLevel = "info"
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// Event represents a detected security event
type Event struct {
	ID              string           `json:"id"`
	Timestamp       time.Time        `json:"timestamp"`
	Source          string           `json:"source"`
	Risk            RiskLevel        `json:"risk"`
	Confidence      float64          `json:"confidence"`
	Summary         string           `json:"summary"`
	Explanation     string           `json:"explanation"`
	Evidence        []Evidence       `json:"evidence"`
	SuggestedAction *SuggestedAction `json:"suggested_action,omitempty"`
	Mode            string           `json:"mode"` // e.g. "advisory"
}

// Evidence holds key-value pairs supporting the detection
type Evidence struct {
	Type  string      `json:"type"`
	Value interface{} `json:"value"` // Can be count (int), score (float), or raw string
}

// SuggestedAction defines what the user should do
type SuggestedAction struct {
	Type     string `json:"type"`     // e.g. "ban_ip"
	Target   string `json:"target"`   // e.g. "45.x.x.x"
	Duration string `json:"duration"` // e.g. "24h"
}

// DetectionRule defines a configurable detection rule
type DetectionRule struct {
	Name      string    `yaml:"name"`
	Type      string    `yaml:"type"`      // "threshold"
	Metric    string    `yaml:"metric"`    // "failed_logins", "http_404_count"
	Threshold int       `yaml:"threshold"` // e.g. 5
	Action    string    `yaml:"action"`    // "ban_ip"
	Duration  string    `yaml:"duration"`  // "1h"
	Risk      RiskLevel `yaml:"risk"`      // "high"
	Summary   string    `yaml:"summary"`   // Alert message
}

// Config represents the application configuration
type Config struct {
	Input struct {
		AuthLogPath   string `yaml:"auth_log_path"`
		SyslogPath    string `yaml:"syslog_path"`
		WebLogPath    string `yaml:"web_log_path"` // Nginx/Apache
		EnableDocker  bool   `yaml:"enable_docker_logs"`
		EnableJournal bool   `yaml:"enable_journald"`
	} `yaml:"input"`

	Detection struct {
		EnableLocalLLM bool   `yaml:"enable_local_llm"`
		LocalLLMUrl    string `yaml:"local_llm_url"`   // e.g. http://localhost:11434/api/generate
		LocalLLMModel  string `yaml:"local_llm_model"` // e.g. tinyllama
		ExternalAI     bool   `yaml:"allow_external_ai"`

		// Phase 3
		ActiveDefense bool     `yaml:"active_defense"` // DANGEROUS: Executes actions
		Allowlist     []string `yaml:"allowlist"`      // Safe IPs that are never banned

		// Phase 7: Configurable Rules
		Rules []DetectionRule `yaml:"rules"`
	} `yaml:"detection"`

	Notification struct {
		DiscordWebhook string `yaml:"discord_webhook"`
	} `yaml:"notification"`

	Action struct {
		ExecutorSocket string `yaml:"executor_socket"`
	} `yaml:"action"`

	Dashboard struct {
		Enabled bool   `yaml:"enabled"`
		Port    string `yaml:"port"`
	} `yaml:"dashboard"`

	Output struct {
		AuditLogPath string `yaml:"audit_log_path"`
		Format       string `yaml:"format"` // json, text
	} `yaml:"output"`
}
