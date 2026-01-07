package dashboard

import (
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strconv"
)

//go:embed templates/*
var templatesFS embed.FS

// Placeholder for static files
// //go:embed static/*
// var staticFS embed.FS

// Server represents the dashboard HTTP server
type Server struct {
	store     EventStore
	templates *template.Template
	port      string
}

// NewServer creates a new dashboard server
func NewServer(store EventStore, port string) (*Server, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	return &Server{
		store:     store,
		templates: tmpl,
		port:      port,
	}, nil
}

// Start starts the HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Web UI
	mux.HandleFunc("/", s.handleDashboard)

	// API endpoints
	mux.HandleFunc("/api/v1/events", s.handleAPIEvents)
	mux.HandleFunc("/api/v1/stats", s.handleAPIStats)
	mux.HandleFunc("/api/v1/servers", s.handleAPIServers)

	// Static files (disabled until we add files)
	// mux.Handle("/static/", http.FileServer(http.FS(staticFS)))

	log.Printf("[DASHBOARD] Starting on %s", s.port)
	return http.ListenAndServe(s.port, mux)
}

// handleDashboard renders the main dashboard page
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	events, _ := s.store.ListEvents(100)
	stats, _ := s.store.GetStats()
	server, _ := s.store.GetServerInfo()

	data := map[string]interface{}{
		"Events": events,
		"Stats":  stats,
		"Server": server,
	}

	s.templates.ExecuteTemplate(w, "dashboard.html", data)
}

// handleAPIEvents returns events as JSON
func (s *Server) handleAPIEvents(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	events, err := s.store.ListEvents(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

// handleAPIStats returns statistics as JSON
func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleAPIServers returns server list (always single server in Phase 1)
func (s *Server) handleAPIServers(w http.ResponseWriter, r *http.Request) {
	server, err := s.store.GetServerInfo()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Return as array for multi-server compatibility
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]interface{}{server})
}
