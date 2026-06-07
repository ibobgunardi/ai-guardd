package dashboard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeEventStore struct {
	events    []EventRecord
	err       error
	lastLimit int
}

func (s *fakeEventStore) ListEvents(limit int) ([]EventRecord, error) {
	s.lastLimit = limit
	if s.err != nil {
		return nil, s.err
	}
	return s.events, nil
}

func (s *fakeEventStore) GetStats() (*Stats, error) {
	return &Stats{}, nil
}

func (s *fakeEventStore) GetServerInfo() (*ServerInfo, error) {
	return &ServerInfo{ID: "localhost", Hostname: "localhost", LastSeen: time.Now(), Status: "active"}, nil
}

func TestHandleAPIEventsClampsLimit(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  int
	}{
		{name: "default", query: "", want: defaultEventLimit},
		{name: "invalid", query: "?limit=abc", want: defaultEventLimit},
		{name: "negative", query: "?limit=-1", want: 1},
		{name: "zero", query: "?limit=0", want: 1},
		{name: "normal", query: "?limit=25", want: 25},
		{name: "oversized", query: "?limit=10000", want: maxEventLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeEventStore{events: []EventRecord{{ID: 1}}}
			server := &Server{store: store}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/events"+tt.query, nil)
			rec := httptest.NewRecorder()

			server.handleAPIEvents(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if store.lastLimit != tt.want {
				t.Fatalf("limit = %d, want %d", store.lastLimit, tt.want)
			}
		})
	}
}

func TestHandleAPIEventsReturnsStoreErrors(t *testing.T) {
	store := &fakeEventStore{err: errors.New("store unavailable")}
	server := &Server{store: store}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	rec := httptest.NewRecorder()

	server.handleAPIEvents(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if store.lastLimit != defaultEventLimit {
		t.Fatalf("limit = %d, want %d", store.lastLimit, defaultEventLimit)
	}
}
