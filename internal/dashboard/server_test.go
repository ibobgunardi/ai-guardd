package dashboard

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeEventStore struct {
	events    []EventRecord
	err       error
	statsErr  error
	serverErr error
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
	if s.statsErr != nil {
		return nil, s.statsErr
	}
	return &Stats{}, nil
}

func (s *fakeEventStore) GetServerInfo() (*ServerInfo, error) {
	if s.serverErr != nil {
		return nil, s.serverErr
	}
	return &ServerInfo{ID: "localhost", Hostname: "localhost", LastSeen: time.Now(), Status: "active"}, nil
}

func TestHandleDashboardRendersPage(t *testing.T) {
	store := &fakeEventStore{events: []EventRecord{{ID: 1, Summary: "test alert"}}}
	server := &Server{
		store:     store,
		templates: template.Must(template.New("dashboard.html").Parse(`{{len .Events}} {{.Server.Hostname}}`)),
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	server.handleDashboard(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != "1 localhost" {
		t.Fatalf("body = %q", got)
	}
	if store.lastLimit != defaultEventLimit {
		t.Fatalf("limit = %d, want %d", store.lastLimit, defaultEventLimit)
	}
}

func TestHandleDashboardReturnsStoreErrors(t *testing.T) {
	tests := []struct {
		name  string
		store *fakeEventStore
	}{
		{name: "events", store: &fakeEventStore{err: errors.New("events unavailable")}},
		{name: "stats", store: &fakeEventStore{statsErr: errors.New("stats unavailable")}},
		{name: "server", store: &fakeEventStore{serverErr: errors.New("server unavailable")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				store:     tt.store,
				templates: template.Must(template.New("dashboard.html").Parse(`ok`)),
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()

			server.handleDashboard(rec, req)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
			}
		})
	}
}

func TestHandleDashboardReturnsTemplateErrors(t *testing.T) {
	server := &Server{
		store:     &fakeEventStore{},
		templates: template.Must(template.New("other.html").Parse(`ok`)),
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	server.handleDashboard(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestHandleDashboardReturnsNotFoundForUnknownPaths(t *testing.T) {
	store := &fakeEventStore{events: []EventRecord{{ID: 1}}}
	server := &Server{
		store:     store,
		templates: template.Must(template.New("dashboard.html").Parse(`ok`)),
	}
	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	rec := httptest.NewRecorder()

	server.handleDashboard(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if store.lastLimit != 0 {
		t.Fatalf("store was loaded with limit %d", store.lastLimit)
	}
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
