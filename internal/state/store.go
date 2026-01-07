package state

import (
	"ai-guardd/internal/feature"
	"database/sql"
	"encoding/json"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Create table if not exists
	query := `
	CREATE TABLE IF NOT EXISTS feature_vectors (
		ip TEXT PRIMARY KEY,
		failed_logins INTEGER,
		distinct_users TEXT,
		first_seen DATETIME,
		last_seen DATETIME,
		http_404_count INTEGER,
		distinct_paths TEXT
	);`
	_, err = db.Exec(query)
	if err != nil {
		return nil, err
	}

	return &Store{db: db}, nil
}

func (s *Store) SaveAll(vectors map[string]*feature.FeatureVector) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO feature_vectors 
		(ip, failed_logins, distinct_users, first_seen, last_seen, http_404_count, distinct_paths) 
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, v := range vectors {
		usersJson, _ := json.Marshal(v.DistinctUsers)
		pathsJson, _ := json.Marshal(v.DistinctPaths)

		_, err = stmt.Exec(
			v.IP,
			v.FailedLogins,
			string(usersJson),
			v.FirstSeen,
			v.LastSeen,
			v.Http404Count,
			string(pathsJson),
		)
		if err != nil {
			log.Printf("[STATE] Failed to save vector for %s: %v", v.IP, err)
		}
	}

	return tx.Commit()
}

func (s *Store) LoadAll() (map[string]*feature.FeatureVector, error) {
	rows, err := s.db.Query("SELECT ip, failed_logins, distinct_users, first_seen, last_seen, http_404_count, distinct_paths FROM feature_vectors")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	vectors := make(map[string]*feature.FeatureVector)
	for rows.Next() {
		var v feature.FeatureVector
		var usersJson, pathsJson string
		var firstSeen, lastSeen time.Time

		err = rows.Scan(
			&v.IP,
			&v.FailedLogins,
			&usersJson,
			&firstSeen,
			&lastSeen,
			&v.Http404Count,
			&pathsJson,
		)
		if err != nil {
			continue
		}

		v.FirstSeen = firstSeen
		v.LastSeen = lastSeen
		json.Unmarshal([]byte(usersJson), &v.DistinctUsers)
		json.Unmarshal([]byte(pathsJson), &v.DistinctPaths)

		vectors[v.IP] = &v
	}

	return vectors, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}
