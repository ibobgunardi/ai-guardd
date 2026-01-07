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
	rules    []types.DetectionRule
}

// NewEngine creates a new detection engine with configurable rules
func NewEngine(rules []types.DetectionRule) *Engine {
	// If no rules provided, use defaults
	if len(rules) == 0 {
		rules = getDefaultRules()
	}
	return &Engine{
		features: feature.NewAccumulator(1 * time.Hour), // Keep history for 1 hour
		rules:    rules,
	}
}

// getDefaultRules returns the built-in detection rules
func getDefaultRules() []types.DetectionRule {
	return []types.DetectionRule{
		{
			Name:      "ssh_brute_force",
			Type:      "threshold",
			Metric:    "failed_logins",
			Threshold: 5,
			Action:    "ban_ip",
			Duration:  "1h",
			Risk:      types.RiskHigh,
			Summary:   "SSH Brute Force Detected",
		},
		{
			Name:      "web_scanning",
			Type:      "threshold",
			Metric:    "http_404_count",
			Threshold: 20,
			Action:    "ban_ip",
			Duration:  "30m",
			Risk:      types.RiskMedium,
			Summary:   "Web Scanning Detected (404 Flood)",
		},
	}
}

func (e *Engine) checkThresholds(feat *feature.FeatureVector) *types.Event {
	// Evaluate all rules against the feature vector
	for _, rule := range e.rules {
		if rule.Type != "threshold" {
			continue
		}

		var currentValue int
		var evidence []types.Evidence

		switch rule.Metric {
		case "failed_logins":
			currentValue = feat.FailedLogins
			evidence = []types.Evidence{
				{Type: "ssh_fail_count", Value: feat.FailedLogins},
				{Type: "distinct_users", Value: len(feat.DistinctUsers)},
			}
		case "http_404_count":
			currentValue = feat.Http404Count
			evidence = []types.Evidence{
				{Type: "http_404_count", Value: feat.Http404Count},
				{Type: "distinct_paths", Value: len(feat.DistinctPaths)},
			}
		default:
			continue
		}

		if currentValue >= rule.Threshold {
			explanation := ""
			if rule.Metric == "failed_logins" {
				explanation = fmt.Sprintf("IP %s attempted %d SSH logins using %d distinct usernames.", feat.IP, feat.FailedLogins, len(feat.DistinctUsers))
			} else if rule.Metric == "http_404_count" {
				explanation = fmt.Sprintf("IP %s triggered %d 404 errors across %d distinct paths.", feat.IP, feat.Http404Count, len(feat.DistinctPaths))
			}

			return &types.Event{
				ID:          fmt.Sprintf("evt_%d", time.Now().UnixNano()),
				Timestamp:   time.Now(),
				Source:      "rule_engine",
				Risk:        rule.Risk,
				Confidence:  0.9,
				Summary:     rule.Summary,
				Explanation: explanation,
				Evidence:    evidence,
				SuggestedAction: &types.SuggestedAction{
					Type:     rule.Action,
					Target:   feat.IP,
					Duration: rule.Duration,
				},
				Mode: "advisory",
			}
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

// GetState returns current tracked features for persistence
func (e *Engine) GetState() map[string]*feature.FeatureVector {
	return e.features.GetAll()
}

// LoadState restores features from a map (e.g. from database)
func (e *Engine) LoadState(vectors map[string]*feature.FeatureVector) {
	e.features.ReplaceAll(vectors)
}
