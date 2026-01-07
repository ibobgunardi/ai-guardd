package detect

import (
	"ai-guardd/internal/feature"
	"ai-guardd/internal/parser"
	"ai-guardd/internal/types"
	"fmt"
	"time"
)

// Engine is the core detection engine
type Engine struct {
	features *feature.Accumulator
}

// NewEngine creates a new detection engine
func NewEngine() *Engine {
	return &Engine{
		features: feature.NewAccumulator(1 * time.Hour), // Keep history for 1 hour
	}
}

func (e *Engine) checkThresholds(feat *feature.FeatureVector) *types.Event {
	// Rule 1: High Velocity Brute Force
	if feat.FailedLogins >= 5 {
		return &types.Event{
			ID:          fmt.Sprintf("evt_%d", time.Now().UnixNano()),
			Timestamp:   time.Now(),
			Source:      "ssh_auth",
			Risk:        types.RiskHigh,
			Confidence:  0.9,
			Summary:     "SSH Brute Force Detected",
			Explanation: fmt.Sprintf("IP %s attempted %d SSH logins using %d distinct usernames.", feat.IP, feat.FailedLogins, len(feat.DistinctUsers)),
			Evidence: []types.Evidence{
				{Type: "ssh_fail_count", Value: feat.FailedLogins},
				{Type: "distinct_users", Value: len(feat.DistinctUsers)},
			},
			SuggestedAction: &types.SuggestedAction{
				Type:     "ban_ip",
				Target:   feat.IP,
				Duration: "1h",
			},
			Mode: "advisory",
		}
	}

	// Rule 2: HTTP 404 Flood (Scanning)
	if feat.Http404Count >= 20 {
		return &types.Event{
			ID:          fmt.Sprintf("evt_%d", time.Now().UnixNano()),
			Timestamp:   time.Now(),
			Source:      "nginx",
			Risk:        types.RiskMedium,
			Confidence:  0.8,
			Summary:     "Web Scanning Detected (404 Flood)",
			Explanation: fmt.Sprintf("IP %s triggered %d 404 errors across %d distinct paths.", feat.IP, feat.Http404Count, len(feat.DistinctPaths)),
			Evidence: []types.Evidence{
				{Type: "http_404_count", Value: feat.Http404Count},
				{Type: "distinct_paths", Value: len(feat.DistinctPaths)},
			},
			SuggestedAction: &types.SuggestedAction{
				Type:     "ban_ip",
				Target:   feat.IP,
				Duration: "30m",
			},
			Mode: "advisory",
		}
	}

	return nil
}

// ProcessEvent applies rules to a new event
func (e *Engine) ProcessEvent(evt *parser.ParsedEvent) *types.Event {
	// 1. Suspicious Success (Immediate Rule)
	if evt.Type == "login_success" {
		if evt.User == "root" {
			return &types.Event{
				ID:          fmt.Sprintf("evt_%d_root", time.Now().UnixNano()),
				Timestamp:   time.Now(),
				Source:      evt.Source,
				Risk:        types.RiskHigh,
				Confidence:  1.0,
				Summary:     "Suspicious Root Login",
				Explanation: fmt.Sprintf("Successful login for 'root' from IP %s. Root logins are discouraged.", evt.IP),
				Evidence:    []types.Evidence{{Type: "user", Value: "root"}},
				SuggestedAction: &types.SuggestedAction{
					Type:     "notify_admin", // New action type? Or just log
					Target:   "admin",
					Duration: "0",
				},
				Mode: "advisory", // Never auto-ban success unless super confident
			}
		}
		// Reset failures on success?
		// e.features.Reset(evt.IP)
		return nil
	}

	if evt.Type == "login_failed" {
		feat := e.features.AddFailure(evt.IP, evt.User)

		// Specialized DB check?
		// Since we reuse AddFailure, the "FailedLogins" count increases.
		// The generic rule (Rule 1) will trigger "SSH Brute Force Detected".
		// We should verify if we want to change the Summary based on Source.
		event := e.checkThresholds(feat)
		if event != nil && evt.Source == "mysql" {
			event.Summary = "Database Brute Force Detected"
			event.Explanation = fmt.Sprintf("IP %s attempted %d database logins using %d distinct usernames.", feat.IP, feat.FailedLogins, len(feat.DistinctUsers))
			event.Source = "mysql"
		}
		return event
	}

	if evt.Type == "http_request" && evt.StatusCode == 404 {
		feat := e.features.AddHttp404(evt.IP, evt.URL)
		return e.checkThresholds(feat)
	}

	return nil
}
