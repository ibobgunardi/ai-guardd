package feature

import (
	"sync"
	"testing"
	"time"
)

func TestAccumulator_AddFailure(t *testing.T) {
	acc := NewAccumulator(1 * time.Hour)

	feat := acc.AddFailure("192.168.1.1", "admin")

	if feat.IP != "192.168.1.1" {
		t.Errorf("Expected IP 192.168.1.1, got %s", feat.IP)
	}
	if feat.FailedLogins != 1 {
		t.Errorf("Expected 1 failed login, got %d", feat.FailedLogins)
	}
	if !feat.DistinctUsers["admin"] {
		t.Error("Expected admin in distinct users")
	}
}

func TestAccumulator_AddFailure_Multiple(t *testing.T) {
	acc := NewAccumulator(1 * time.Hour)

	// Add multiple failures from same IP
	acc.AddFailure("10.0.0.1", "user1")
	acc.AddFailure("10.0.0.1", "user2")
	feat := acc.AddFailure("10.0.0.1", "user3")

	if feat.FailedLogins != 3 {
		t.Errorf("Expected 3 failures, got %d", feat.FailedLogins)
	}
	if len(feat.DistinctUsers) != 3 {
		t.Errorf("Expected 3 distinct users, got %d", len(feat.DistinctUsers))
	}
}

func TestAccumulator_Concurrency(t *testing.T) {
	acc := NewAccumulator(1 * time.Hour)

	// Spawn multiple goroutines to add failures concurrently
	var wg sync.WaitGroup
	ip := "1.2.3.4"
	iterations := 100

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				acc.AddFailure(ip, "user")
			}
		}(i)
	}

	wg.Wait()

	feat := acc.GetFeatures(ip)
	if feat == nil {
		t.Fatal("Expected feature vector, got nil")
	}

	expected := 10 * iterations
	if feat.FailedLogins != expected {
		t.Errorf("Expected %d failures, got %d", expected, feat.FailedLogins)
	}
}

func TestAccumulator_GetAll_ReplaceAll(t *testing.T) {
	acc := NewAccumulator(1 * time.Hour)

	acc.AddFailure("1.1.1.1", "user1")
	acc.AddFailure("2.2.2.2", "user2")

	// Export state
	state := acc.GetAll()

	if len(state) != 2 {
		t.Errorf("Expected 2 entities, got %d", len(state))
	}

	// Create new accumulator and restore
	acc2 := NewAccumulator(1 * time.Hour)
	acc2.ReplaceAll(state)

	feat := acc2.GetFeatures("1.1.1.1")
	if feat == nil || feat.FailedLogins != 1 {
		t.Error("State was not properly restored")
	}
}

func TestAccumulator_GetAllReturnsIndependentCopy(t *testing.T) {
	acc := NewAccumulator(1 * time.Hour)

	acc.AddFailure("1.1.1.1", "admin")
	state := acc.GetAll()
	state["1.1.1.1"].FailedLogins = 99
	state["1.1.1.1"].DistinctUsers["mutated"] = true

	feat := acc.GetFeatures("1.1.1.1")
	if feat.FailedLogins != 1 {
		t.Fatalf("FailedLogins = %d, want 1", feat.FailedLogins)
	}
	if feat.DistinctUsers["mutated"] {
		t.Fatal("GetAll result should not share distinct user map with accumulator")
	}
}

func TestAccumulator_GetFeaturesReturnsIndependentCopy(t *testing.T) {
	acc := NewAccumulator(1 * time.Hour)

	acc.AddFailure("1.1.1.1", "admin")
	feat := acc.GetFeatures("1.1.1.1")
	feat.FailedLogins = 99
	feat.DistinctUsers["mutated"] = true

	got := acc.GetFeatures("1.1.1.1")
	if got.FailedLogins != 1 {
		t.Fatalf("FailedLogins = %d, want 1", got.FailedLogins)
	}
	if got.DistinctUsers["mutated"] {
		t.Fatal("GetFeatures result should not share distinct user map with accumulator")
	}
}

func TestAccumulator_ReplaceAllCopiesInputState(t *testing.T) {
	acc := NewAccumulator(1 * time.Hour)
	input := map[string]*FeatureVector{
		"2.2.2.2": {
			IP:            "2.2.2.2",
			FailedLogins:  2,
			DistinctUsers: map[string]bool{"root": true},
			FirstSeen:     time.Now(),
			LastSeen:      time.Now(),
			DistinctPaths: map[string]bool{"/admin": true},
		},
	}

	acc.ReplaceAll(input)
	input["2.2.2.2"].FailedLogins = 50
	input["2.2.2.2"].DistinctUsers["mutated"] = true

	feat := acc.GetFeatures("2.2.2.2")
	if feat.FailedLogins != 2 {
		t.Fatalf("FailedLogins = %d, want 2", feat.FailedLogins)
	}
	if feat.DistinctUsers["mutated"] {
		t.Fatal("ReplaceAll should not share distinct user map with input")
	}
}

func TestAccumulator_ReplaceAllInitializesMissingMaps(t *testing.T) {
	acc := NewAccumulator(1 * time.Hour)
	acc.ReplaceAll(map[string]*FeatureVector{
		"3.3.3.3": {
			IP:           "3.3.3.3",
			FailedLogins: 1,
			FirstSeen:    time.Now(),
			LastSeen:     time.Now(),
		},
	})

	feat := acc.AddFailure("3.3.3.3", "admin")
	if !feat.DistinctUsers["admin"] {
		t.Fatalf("DistinctUsers after update = %#v", feat.DistinctUsers)
	}

	feat = acc.AddHttp404("3.3.3.3", "/login")
	if !feat.DistinctPaths["/login"] {
		t.Fatalf("DistinctPaths after update = %#v", feat.DistinctPaths)
	}
}
