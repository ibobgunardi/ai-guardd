package state

import (
	"ai-guardd/internal/feature"
	"testing"
	"time"
)

func TestDecodeBoolMap(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want map[string]bool
	}{
		{name: "valid", raw: `{"admin":true,"root":true}`, want: map[string]bool{"admin": true, "root": true}},
		{name: "empty", raw: "", want: map[string]bool{}},
		{name: "null", raw: "null", want: map[string]bool{}},
		{name: "invalid", raw: "{", want: map[string]bool{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeBoolMap(tt.raw)
			if got == nil {
				t.Fatal("map should be initialized")
			}
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d", len(got), len(tt.want))
			}
			for key, want := range tt.want {
				if got[key] != want {
					t.Fatalf("got[%q] = %v, want %v", key, got[key], want)
				}
			}
		})
	}
}

func TestDecodedFeatureMapsCanBeUpdated(t *testing.T) {
	loaded := map[string]*feature.FeatureVector{
		"203.0.113.7": {
			IP:            "203.0.113.7",
			FailedLogins:  2,
			DistinctUsers: decodeBoolMap(""),
			FirstSeen:     time.Now().Add(-time.Minute),
			LastSeen:      time.Now(),
			Http404Count:  5,
			DistinctPaths: decodeBoolMap("null"),
		},
	}

	acc := feature.NewAccumulator(time.Hour)
	acc.ReplaceAll(loaded)

	loginFeat := acc.AddFailure("203.0.113.7", "admin")
	if !loginFeat.DistinctUsers["admin"] {
		t.Fatalf("DistinctUsers after update = %#v", loginFeat.DistinctUsers)
	}

	httpFeat := acc.AddHttp404("203.0.113.7", "/.env")
	if !httpFeat.DistinctPaths["/.env"] {
		t.Fatalf("DistinctPaths after update = %#v", httpFeat.DistinctPaths)
	}
}
