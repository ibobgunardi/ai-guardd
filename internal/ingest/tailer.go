package ingest

import (
	"fmt"
	"log"

	"github.com/nxadm/tail"
)

// LogLine represents a raw line from a log source
type LogLine struct {
	Source    string
	Timestamp int64 // wall clock detection arrival
	Content   string
}

// Ingester defines the interface for log sources
type Ingester interface {
	Start() (<-chan LogLine, error)
	Stop() error
}

// FileTailer implements Ingester for a single file
type FileTailer struct {
	path string
	t    *tail.Tail
}

// NewFileTailer creates a new tailer for a path
func NewFileTailer(path string) *FileTailer {
	return &FileTailer{
		path: path,
	}
}

// Start begins tailing the file and returns a channel of lines
func (f *FileTailer) Start() (<-chan LogLine, error) {
	// Config for tailing (follow, reopen on rotate)
	config := tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      true, // Fallback for some filesystems/docker mounts
		Logger:    tail.DiscardingLogger,
	}

	log.Printf("Starting tailer for %s (waiting if not present)", f.path)

	t, err := tail.TailFile(f.path, config)
	if err != nil {
		return nil, fmt.Errorf("failed to tail file %s: %w", f.path, err)
	}
	f.t = t

	out := make(chan LogLine)

	go func() {
		defer close(out)
		for line := range t.Lines {
			if line.Err != nil {
				// We don't log every error to avoid spamming if a file is rotated
				continue
			}
			out <- LogLine{
				Source:    f.path,
				Timestamp: line.Time.Unix(),
				Content:   line.Text,
			}
		}
	}()

	return out, nil
}

// Stop stops the tailing
func (f *FileTailer) Stop() error {
	if f.t != nil {
		return f.t.Stop()
	}
	return nil
}
