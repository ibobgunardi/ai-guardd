package explain

import (
	"ai-guardd/internal/types"
	"fmt"
)

// Explainer defines how alerts are enriched with human-readable context
type Explainer interface {
	Explain(event *types.Event) error
}

// TemplateExplainer uses static string templates (Offline/Fast)
type TemplateExplainer struct{}

func NewTemplateExplainer() *TemplateExplainer {
	return &TemplateExplainer{}
}

func (e *TemplateExplainer) Explain(event *types.Event) error {
	// If explanation is already set by detector, we might append or leave it.
	// For now, we ensure it exists.
	if event.Explanation == "" {
		event.Explanation = fmt.Sprintf("Detected %s from %s. Risk: %s.", event.Summary, event.Source, event.Risk)
	}
	return nil
}
