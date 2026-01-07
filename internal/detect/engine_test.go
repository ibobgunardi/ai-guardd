package detect

import (
	"ai-guardd/internal/parser"
	"testing"
	"time"
)

func TestEngine_BruteForceDetection(t *testing.T) {
	e := NewEngine()

	// Simulate 4 failures (Should not alert)
	ip := "192.168.1.1"
	for i := 0; i < 4; i++ {
		evt := &parser.ParsedEvent{
			Timestamp: time.Now(),
			Type:      "login_failed",
			IP:        ip,
			User:      "root",
		}
		alert := e.ProcessEvent(evt)
		if alert != nil {
			t.Errorf("Unexpected alert at attempt %d", i+1)
		}
	}

	// Simulate 5th failure (Should alert)
	evt := &parser.ParsedEvent{
		Timestamp: time.Now(),
		Type:      "login_failed",
		IP:        ip,
		User:      "root",
	}
	alert := e.ProcessEvent(evt)
	if alert == nil {
		t.Fatal("Expected alert after 5th failure, got nil")
	}

	if alert.Risk != "high" {
		t.Errorf("Expected High risk, got %s", alert.Risk)
	}

	if alert.SuggestedAction.Type != "ban_ip" {
		t.Errorf("Expected ban_ip action, got %s", alert.SuggestedAction.Type)
	}

	t.Logf("Alert Generated: %+v", alert)
}
