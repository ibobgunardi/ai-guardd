package audit

import (
	"ai-guardd/internal/types"
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestLogEventCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "security", "audit.jsonl")
	logger := NewLogger(path)

	if err := logger.LogEvent(testEvent("evt-1")); err != nil {
		t.Fatalf("LogEvent() error = %v", err)
	}

	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat parent directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected parent path to be a directory")
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit log: %v", err)
	}
	if runtime.GOOS != "windows" {
		if got := fileInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("file mode = %v, want %v", got, os.FileMode(0o600))
		}
	}
}

func TestLogEventAppendsJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger := NewLogger(path)

	if err := logger.LogEvent(testEvent("evt-1")); err != nil {
		t.Fatalf("LogEvent() first error = %v", err)
	}
	if err := logger.LogEvent(testEvent("evt-2")); err != nil {
		t.Fatalf("LogEvent() second error = %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer file.Close()

	var ids []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var evt types.Event
		if err := json.Unmarshal(scanner.Bytes(), &evt); err != nil {
			t.Fatalf("decode event: %v", err)
		}
		ids = append(ids, evt.ID)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit log: %v", err)
	}

	if len(ids) != 2 {
		t.Fatalf("line count = %d, want 2", len(ids))
	}
	if ids[0] != "evt-1" || ids[1] != "evt-2" {
		t.Fatalf("ids = %#v", ids)
	}
}

func testEvent(id string) types.Event {
	return types.Event{
		ID:        id,
		Timestamp: time.Unix(1780830000, 0).UTC(),
		Source:    "test",
		Risk:      types.RiskHigh,
		Summary:   "test alert",
		Mode:      "advisory",
	}
}
