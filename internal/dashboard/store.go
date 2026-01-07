package dashboard

import (
	"database/sql"
	"time"
)

// EventStore defines the interface for event storage (SQLite now, PostgreSQL later)
type EventStore interface {
	ListEvents(limit int) ([]EventRecord, error)
	GetStats() (*Stats, error)
	GetServerInfo() (*ServerInfo, error)
}

// EventRecord represents a security event for display
type EventRecord struct {
	ID          int64
	ServerID    string
	Timestamp   time.Time
	Source      string
	Risk        string
	Summary     string
	IPAddress   string
	ActionTaken string
	Explanation string
}

// Stats represents dashboard statistics
type Stats struct {
	TotalEvents     int
	HighRiskCount   int
	MediumRiskCount int
	BannedIPsCount  int
	TopAttackers    []TopAttacker
}

// TopAttacker represents an IP with attack count
type TopAttacker struct {
	IP    string
	Count int
}

// ServerInfo represents server metadata
type ServerInfo struct {
	ID       string
	Hostname string
	LastSeen time.Time
	Status   string
}

// SQLiteStore implements EventStore using SQLite
type SQLiteStore struct {
	db       *sql.DB
	serverID string
}

// NewSQLiteStore creates a new SQLite-backed event store
func NewSQLiteStore(db *sql.DB, serverID string) *SQLiteStore {
	return &SQLiteStore{
		db:       db,
		serverID: serverID,
	}
}

// ListEvents returns recent events
func (s *SQLiteStore) ListEvents(limit int) ([]EventRecord, error) {
	// For now, we'll query from the existing audit log table
	// In Phase 2, we'll create a dedicated events table
	query := `
		SELECT 
			id, timestamp, source, risk, summary, 
			COALESCE(json_extract(suggested_action, '$.target'), '') as ip_address,
			COALESCE(json_extract(suggested_action, '$.type'), '') as action_taken,
			explanation
		FROM events
		WHERE server_id = ?
		ORDER BY timestamp DESC
		LIMIT ?
	`

	rows, err := s.db.Query(query, s.serverID, limit)
	if err != nil {
		// Table might not exist yet, return empty
		return []EventRecord{}, nil
	}
	defer rows.Close()

	var events []EventRecord
	for rows.Next() {
		var e EventRecord
		e.ServerID = s.serverID
		err := rows.Scan(&e.ID, &e.Timestamp, &e.Source, &e.Risk,
			&e.Summary, &e.IPAddress, &e.ActionTaken, &e.Explanation)
		if err != nil {
			continue
		}
		events = append(events, e)
	}

	return events, nil
}

// GetStats returns dashboard statistics
func (s *SQLiteStore) GetStats() (*Stats, error) {
	stats := &Stats{}

	// Total events
	s.db.QueryRow("SELECT COUNT(*) FROM events WHERE server_id = ?", s.serverID).Scan(&stats.TotalEvents)

	// High risk count
	s.db.QueryRow("SELECT COUNT(*) FROM events WHERE server_id = ? AND risk = 'high'", s.serverID).Scan(&stats.HighRiskCount)

	// Medium risk count
	s.db.QueryRow("SELECT COUNT(*) FROM events WHERE server_id = ? AND risk = 'medium'", s.serverID).Scan(&stats.MediumRiskCount)

	// Top attackers (from feature_vectors table)
	rows, err := s.db.Query(`
		SELECT ip, failed_logins 
		FROM feature_vectors 
		ORDER BY failed_logins DESC 
		LIMIT 5
	`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ta TopAttacker
			rows.Scan(&ta.IP, &ta.Count)
			stats.TopAttackers = append(stats.TopAttackers, ta)
		}
	}

	return stats, nil
}

// GetServerInfo returns server metadata
func (s *SQLiteStore) GetServerInfo() (*ServerInfo, error) {
	// For single-server mode, return static info
	return &ServerInfo{
		ID:       s.serverID,
		Hostname: "localhost",
		LastSeen: time.Now(),
		Status:   "active",
	}, nil
}

// InitSchema ensures the events table exists with server_id column
func InitSchema(db *sql.DB) error {
	// Check if events table exists and has server_id column
	query := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		server_id TEXT NOT NULL DEFAULT 'localhost',
		timestamp DATETIME NOT NULL,
		source TEXT,
		risk TEXT,
		summary TEXT,
		explanation TEXT,
		suggested_action TEXT,
		evidence TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_events_server ON events(server_id, timestamp);
	`

	_, err := db.Exec(query)
	return err
}
