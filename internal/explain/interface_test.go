package explain

import (
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
