package action

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRemoveStaleSocketRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "executor.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := removeStaleSocket(path); err == nil {
		t.Fatal("expected regular file to be rejected")
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("regular file should not be removed: %v", err)
	}
}

func TestExecutorListenRestrictsSocketPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket file modes are not portable on Windows")
	}

	path := filepath.Join(t.TempDir(), "executor.sock")
	executor := NewExecutor(path)
	listener, err := executor.listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := info.Mode().Perm(); got != executorSocketMode {
		t.Fatalf("socket mode = %v, want %v", got, executorSocketMode)
	}
}
