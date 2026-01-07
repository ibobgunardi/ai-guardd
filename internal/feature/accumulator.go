package feature

import (
	"sync"
	"time"
)

// FeatureVector represents the current state of an entity (IP)
type FeatureVector struct {
	IP            string
	FailedLogins  int
	DistinctUsers map[string]bool
	FirstSeen     time.Time
	LastSeen      time.Time

	// HTTP Features
	Http404Count  int
	DistinctPaths map[string]bool
}

// Accumulator tracks events over time
type Accumulator struct {
	mu       sync.Mutex
	features map[string]*FeatureVector
	window   time.Duration
}

// NewAccumulator creates a new feature accumulator
func NewAccumulator(window time.Duration) *Accumulator {
	acc := &Accumulator{
		features: make(map[string]*FeatureVector),
		window:   window,
	}
	// Start cleanup loop
	go acc.cleanupLoop()
	return acc
}

const (
	MaxTrackedIPs = 5000
	MaxUsersPerIP = 50
	MaxPathsPerIP = 50
)

// AddFailure records a failed login attempt
func (a *Accumulator) AddFailure(ip, user string) *FeatureVector {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Anti-DoS: Check global IP limit
	if len(a.features) >= MaxTrackedIPs {
		if _, exists := a.features[ip]; !exists {
			// Table full. Evict the least interesting entry to make room.
			a.evictLowPriority()
		}
	}

	feat, exists := a.features[ip]
	if !exists {
		feat = &FeatureVector{
			IP:            ip,
			DistinctUsers: make(map[string]bool),
			DistinctPaths: make(map[string]bool),
			FirstSeen:     time.Now(),
		}
		a.features[ip] = feat
	}

	feat.FailedLogins++

	// Anti-DoS: Check per-IP Map limit
	if len(feat.DistinctUsers) < MaxUsersPerIP {
		feat.DistinctUsers[user] = true
	}

	feat.LastSeen = time.Now()

	return feat
}

// AddHttp404 records a 404 error
func (a *Accumulator) AddHttp404(ip, path string) *FeatureVector {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.features) >= MaxTrackedIPs {
		if _, exists := a.features[ip]; !exists {
			a.evictLowPriority()
		}
	}

	feat, exists := a.features[ip]
	if !exists {
		feat = &FeatureVector{
			IP:            ip,
			DistinctUsers: make(map[string]bool),
			DistinctPaths: make(map[string]bool),
			FirstSeen:     time.Now(),
		}
		a.features[ip] = feat
	}

	feat.Http404Count++

	if len(feat.DistinctPaths) < MaxPathsPerIP {
		feat.DistinctPaths[path] = true
	}

	feat.LastSeen = time.Now()

	return feat
}

// GetFeatures returns the current feature vector for an IP
func (a *Accumulator) GetFeatures(ip string) *FeatureVector {
	a.mu.Lock()
	defer a.mu.Unlock()
	if feat, ok := a.features[ip]; ok {
		// Return copy to be safe? For now pointer is okay if we are careful
		return feat
	}
	return nil
}

func (a *Accumulator) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		a.mu.Lock()
		now := time.Now()
		for ip, feat := range a.features {
			if now.Sub(feat.LastSeen) > a.window {
				delete(a.features, ip)
			}
		}
		a.mu.Unlock()
	}
}

// evictLowPriority removes one entry: prioritizing low failure counts and old timestamps
// Caller must hold lock.
func (a *Accumulator) evictLowPriority() {
	var bestIP string
	var lowestLogins int = 1000000
	var oldestTime time.Time = time.Now()

	count := 0
	// Heuristic scan (limit scan to 100 entries to avoid complete massive freeze if table is huge?)
	// But 5000 is small enough to scan all.
	for ip, feat := range a.features {
		// Preference 1: Lowest Failures (Noise)
		if feat.FailedLogins < lowestLogins {
			lowestLogins = feat.FailedLogins
			oldestTime = feat.LastSeen
			bestIP = ip
		} else if feat.FailedLogins == lowestLogins {
			// Preference 2: Oldest (Stale)
			if feat.LastSeen.Before(oldestTime) {
				oldestTime = feat.LastSeen
				bestIP = ip
			}
		}
		count++
		// Safety break if map gets ridiculously large in future
		if count > 10000 {
			break
		}
	}

	if bestIP != "" {
		delete(a.features, bestIP)
	} else {
		// Should not happen if map not empty, but just in case of race/logic
		// Delete random by iteration
		for k := range a.features {
			delete(a.features, k)
			break
		}
	}
}
