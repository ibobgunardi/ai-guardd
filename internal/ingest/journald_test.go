package ingest

import (
	"testing"
	"time"
)

func TestJournalTimestampParsesRealtimeMicroseconds(t *testing.T) {
	fallback := time.Unix(100, 0)

	got := journalTimestamp("1780830000123456", fallback)
	if got != 1780830000 {
		t.Fatalf("journalTimestamp() = %d, want 1780830000", got)
	}
}

func TestJournalTimestampUsesFallbackForInvalidValues(t *testing.T) {
	fallback := time.Unix(200, 0)

	tests := []string{"", "not-a-timestamp", "-1"}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			got := journalTimestamp(raw, fallback)
			if got != fallback.Unix() {
				t.Fatalf("journalTimestamp(%q) = %d, want %d", raw, got, fallback.Unix())
			}
		})
	}
}

func TestJournalSourceUsesSyslogIdentifier(t *testing.T) {
	got := journalSource(JournalEntry{
		SyslogIdentifier: "sudo",
		Comm:             "ignored",
	})

	if got != "sudo" {
		t.Fatalf("journalSource() = %q, want sudo", got)
	}
}

func TestJournalSourceFallsBackToComm(t *testing.T) {
	got := journalSource(JournalEntry{Comm: "mysqld"})

	if got != "mysqld" {
		t.Fatalf("journalSource() = %q, want mysqld", got)
	}
}

func TestJournalSourceUsesGenericFallback(t *testing.T) {
	got := journalSource(JournalEntry{
		SyslogIdentifier: " ",
		Comm:             "\t",
	})

	if got != "journald" {
		t.Fatalf("journalSource() = %q, want journald", got)
	}
}
