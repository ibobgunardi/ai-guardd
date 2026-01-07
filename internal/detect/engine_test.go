package detect

import (
	"ai-guardd/internal/parser"
	"ai-guardd/internal/types"
	"testing"
)

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
