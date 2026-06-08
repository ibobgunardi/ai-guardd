package detect

import (
	"ai-guardd/internal/parser"
	"ai-guardd/internal/types"
	"testing"
	"time"
)

func TestEngine_ProcessEvent_NilEvent(t *testing.T) {
	engine := NewEngine(nil)

	if alert := engine.ProcessEvent(nil); alert != nil {
		t.Fatalf("ProcessEvent(nil) = %#v", alert)
	}
}

func TestEngine_ProcessEvent_SSHBruteForce(t *testing.T) {
	// Create engine with default rules
	engine := NewEngine(nil)

	// Simulate 5 failed logins from same IP
	for i := 0; i < 5; i++ {
		evt := &parser.ParsedEvent{
			Type:   "login_failed",
			IP:     "192.168.1.100",
			User:   "admin",
			Source: "ssh_auth",
		}

		alert := engine.ProcessEvent(evt)

		if i < 4 {
			// First 4 attempts should not trigger alert
			if alert != nil {
				t.Errorf("Iteration %d: Expected no alert yet, got one", i)
			}
		} else {
			// 5th attempt should trigger
			if alert == nil {
				t.Fatal("Expected alert on 5th attempt, got nil")
			}
			if alert.Risk != types.RiskHigh {
				t.Errorf("Expected high risk, got %s", alert.Risk)
			}
			if alert.SuggestedAction == nil || alert.SuggestedAction.Type != "ban_ip" {
				t.Error("Expected ban_ip action")
			}
		}
	}
}

func TestEngine_ProcessEvent_CustomRule(t *testing.T) {
	// Create engine with custom threshold
	rules := []types.DetectionRule{
		{
			Name:      "custom_ssh",
			Type:      "threshold",
			Metric:    "failed_logins",
			Threshold: 3, // Lower threshold
			Action:    "ban_ip",
			Duration:  "30m",
			Risk:      types.RiskMedium,
			Summary:   "Custom SSH Alert",
		},
	}

	engine := NewEngine(rules)

	// Should trigger after 3 attempts
	for i := 0; i < 3; i++ {
		evt := &parser.ParsedEvent{
			Type:   "login_failed",
			IP:     "10.0.0.50",
			User:   "test",
			Source: "ssh_auth",
		}

		alert := engine.ProcessEvent(evt)

		if i < 2 {
			if alert != nil {
				t.Errorf("Iteration %d: Unexpected alert", i)
			}
		} else {
			if alert == nil {
				t.Fatal("Expected alert on 3rd attempt, got nil")
			}
			if alert.Summary != "Custom SSH Alert" {
				t.Errorf("Expected custom summary, got %s", alert.Summary)
			}
		}
	}
}

func TestEngine_ProcessEvent_IgnoresZeroThresholdRule(t *testing.T) {
	engine := NewEngine([]types.DetectionRule{
		{
			Name:      "invalid_threshold",
			Type:      "threshold",
			Metric:    "failed_logins",
			Threshold: 0,
			Action:    "ban_ip",
			Duration:  "30m",
			Risk:      types.RiskHigh,
			Summary:   "Invalid threshold",
		},
	})

	alert := engine.ProcessEvent(&parser.ParsedEvent{
		Type:   "login_failed",
		IP:     "198.51.100.10",
		User:   "deploy",
		Source: "ssh_auth",
	})

	if alert != nil {
		t.Fatalf("expected zero-threshold rule to be ignored, got %#v", alert)
	}
}

func TestEngine_ProcessEvent_IgnoresNegativeThresholdRule(t *testing.T) {
	engine := NewEngine([]types.DetectionRule{
		{
			Name:      "invalid_threshold",
			Type:      "threshold",
			Metric:    "http_404_count",
			Threshold: -1,
			Action:    "ban_ip",
			Duration:  "30m",
			Risk:      types.RiskMedium,
			Summary:   "Invalid threshold",
		},
	})

	alert := engine.ProcessEvent(&parser.ParsedEvent{
		Type:       "http_request",
		IP:         "198.51.100.11",
		URL:        "/missing",
		StatusCode: 404,
		Source:     "nginx",
	})

	if alert != nil {
		t.Fatalf("expected negative-threshold rule to be ignored, got %#v", alert)
	}
}

func TestEngine_ProcessEvent_RootLogin(t *testing.T) {
	engine := NewEngine(nil)

	evt := &parser.ParsedEvent{
		Type:   "login_success",
		IP:     "1.2.3.4",
		User:   "root",
		Source: "ssh_auth",
	}

	alert := engine.ProcessEvent(evt)

	if alert == nil {
		t.Fatal("Expected root login alert, got nil")
	}
	if alert.Summary != "Suspicious Root Login" {
		t.Errorf("Expected Suspicious Root Login, got %s", alert.Summary)
	}
}

func TestEngine_ProcessEvent_RootLoginUsesParsedTimestamp(t *testing.T) {
	engine := NewEngine(nil)
	timestamp := time.Date(2026, time.June, 8, 4, 30, 0, 0, time.UTC)

	alert := engine.ProcessEvent(&parser.ParsedEvent{
		Type:      "login_success",
		IP:        "1.2.3.4",
		User:      "root",
		Source:    "ssh_auth",
		Timestamp: timestamp,
	})

	if alert == nil {
		t.Fatal("Expected root login alert, got nil")
	}
	if !alert.Timestamp.Equal(timestamp) {
		t.Fatalf("Timestamp = %s, want %s", alert.Timestamp, timestamp)
	}
}

func TestEngine_ProcessEvent_DatabaseBruteForceKeepsIPBan(t *testing.T) {
	engine := NewEngine([]types.DetectionRule{
		{
			Name:      "database_bruteforce",
			Type:      "threshold",
			Metric:    "failed_logins",
			Threshold: 1,
			Action:    "ban_ip",
			Duration:  "30m",
			Risk:      types.RiskHigh,
			Summary:   "Login Failures",
		},
	})

	alert := engine.ProcessEvent(&parser.ParsedEvent{
		Type:   "login_failed",
		IP:     "203.0.113.90",
		User:   "root",
		Source: "mysql",
	})

	if alert == nil {
		t.Fatal("Expected database brute-force alert, got nil")
	}
	if alert.Source != "mysql" {
		t.Fatalf("Source = %q", alert.Source)
	}
	if alert.Summary != "Database Brute Force Detected" {
		t.Fatalf("Summary = %q", alert.Summary)
	}
	if alert.SuggestedAction == nil {
		t.Fatal("Expected suggested action")
	}
	if alert.SuggestedAction.Type != "ban_ip" {
		t.Fatalf("Action type = %q", alert.SuggestedAction.Type)
	}
	if alert.SuggestedAction.Target != "203.0.113.90" {
		t.Fatalf("Action target = %q", alert.SuggestedAction.Target)
	}
}

func TestEngine_ProcessEvent_DatabaseBruteForceNotifiesForHost(t *testing.T) {
	engine := NewEngine([]types.DetectionRule{
		{
			Name:      "database_bruteforce",
			Type:      "threshold",
			Metric:    "failed_logins",
			Threshold: 1,
			Action:    "ban_ip",
			Duration:  "30m",
			Risk:      types.RiskHigh,
			Summary:   "Login Failures",
		},
	})

	alert := engine.ProcessEvent(&parser.ParsedEvent{
		Type:   "login_failed",
		IP:     "localhost",
		User:   "root",
		Source: "mysql",
	})

	if alert == nil {
		t.Fatal("Expected database brute-force alert, got nil")
	}
	if alert.Source != "mysql" {
		t.Fatalf("Source = %q", alert.Source)
	}
	if alert.SuggestedAction == nil {
		t.Fatal("Expected suggested action")
	}
	if alert.SuggestedAction.Type != "notify_admin" {
		t.Fatalf("Action type = %q", alert.SuggestedAction.Type)
	}
	if alert.SuggestedAction.Target != "admin" {
		t.Fatalf("Action target = %q", alert.SuggestedAction.Target)
	}
	if alert.SuggestedAction.Duration != "0" {
		t.Fatalf("Action duration = %q", alert.SuggestedAction.Duration)
	}
}

func TestEngine_ProcessEvent_PrivEscalationFailure(t *testing.T) {
	engine := NewEngine(nil)

	evt := &parser.ParsedEvent{
		Type:   "priv_escalation_fail",
		User:   "deploy",
		Source: "syslog_sudo",
		Raw:    "sudo: pam_unix(sudo:auth): authentication failure; user=deploy",
	}

	alert := engine.ProcessEvent(evt)

	if alert == nil {
		t.Fatal("Expected privilege escalation alert, got nil")
	}
	if alert.Summary != "Privilege Escalation Failure" {
		t.Errorf("Summary = %q", alert.Summary)
	}
	if alert.Source != "syslog_sudo" {
		t.Errorf("Source = %q", alert.Source)
	}
	if alert.Risk != types.RiskMedium {
		t.Errorf("Risk = %s", alert.Risk)
	}
	if alert.SuggestedAction == nil || alert.SuggestedAction.Type != "notify_admin" {
		t.Fatalf("SuggestedAction = %#v", alert.SuggestedAction)
	}
}

func TestEngine_ProcessEvent_HTTPThresholdUsesParsedTimestamp(t *testing.T) {
	engine := NewEngine([]types.DetectionRule{
		{
			Name:      "web_scanning",
			Type:      "threshold",
			Metric:    "http_404_count",
			Threshold: 1,
			Action:    "ban_ip",
			Duration:  "30m",
			Risk:      types.RiskMedium,
			Summary:   "Web Scanning Detected",
		},
	})
	timestamp := time.Date(2026, time.June, 8, 4, 45, 0, 0, time.UTC)

	alert := engine.ProcessEvent(&parser.ParsedEvent{
		Type:       "http_request",
		IP:         "198.51.100.20",
		URL:        "/missing",
		StatusCode: 404,
		Source:     "nginx",
		Timestamp:  timestamp,
	})

	if alert == nil {
		t.Fatal("Expected HTTP threshold alert, got nil")
	}
	if !alert.Timestamp.Equal(timestamp) {
		t.Fatalf("Timestamp = %s, want %s", alert.Timestamp, timestamp)
	}
}
