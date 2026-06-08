package explain

import (
	"ai-guardd/internal/types"
	"strings"
	"testing"
)

func TestTemplateExplainerRejectsNilEvent(t *testing.T) {
	explainer := NewTemplateExplainer()

	err := explainer.Explain(nil)
	if err == nil {
		t.Fatal("expected nil event error")
	}
	if !strings.Contains(err.Error(), "event is nil") {
		t.Fatalf("error = %v", err)
	}
}

func TestTemplateExplainerFillsWhitespaceExplanation(t *testing.T) {
	explainer := NewTemplateExplainer()
	event := &types.Event{
		Source:      "ssh",
		Risk:        types.RiskHigh,
		Summary:     "test alert",
		Explanation: " \t\n ",
	}

	err := explainer.Explain(event)
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}

	want := "Detected test alert from ssh. Risk: high."
	if event.Explanation != want {
		t.Fatalf("Explanation = %q, want %q", event.Explanation, want)
	}
}

func TestTemplateExplainerKeepsExistingExplanation(t *testing.T) {
	explainer := NewTemplateExplainer()
	event := &types.Event{
		Source:      "ssh",
		Risk:        types.RiskHigh,
		Summary:     "test alert",
		Explanation: "already explained",
	}

	err := explainer.Explain(event)
	if err != nil {
		t.Fatalf("Explain returned error: %v", err)
	}

	if event.Explanation != "already explained" {
		t.Fatalf("Explanation = %q", event.Explanation)
	}
}
