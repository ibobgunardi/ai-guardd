package audit

import (
	"ai-guardd/internal/types"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Logger handles appending events to the audit log
type Logger struct {
	mu       sync.Mutex
	filePath string
}

// NewLogger creates a new audit logger
func NewLogger(filePath string) *Logger {
	return &Logger{
		filePath: filePath,
	}
}

// LogEvent writes an event to the audit log in a thread-safe manner
func (l *Logger) LogEvent(evt types.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open audit log: %w", err)
	}
	defer f.Close()

	// Strict JSON Output per requirements
	encoder := json.NewEncoder(f)
	if err := encoder.Encode(evt); err != nil {
		return fmt.Errorf("failed to encode event: %w", err)
	}

	return nil
}
