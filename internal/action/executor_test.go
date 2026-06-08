package action

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
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

func TestExecutorRunsValidCommands(t *testing.T) {
	executor := NewExecutor("")
	var calls []string
	executor.runCommand = func(name string, args ...string) error {
		calls = append(calls, fmt.Sprintf("%s %v", name, args))
		return nil
	}

	handleExecutorInput(t, executor, "ban 203.0.113.10\nunban 203.0.113.10\n")

	want := []string{
		"iptables [-A INPUT -s 203.0.113.10 -j DROP]",
		"iptables [-D INPUT -s 203.0.113.10 -j DROP]",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
}

func TestExecutorUsesIP6TablesForIPv6Commands(t *testing.T) {
	executor := NewExecutor("")
	var calls []string
	executor.runCommand = func(name string, args ...string) error {
		calls = append(calls, fmt.Sprintf("%s %v", name, args))
		return nil
	}

	handleExecutorInput(t, executor, "ban 2001:db8::10\nunban 2001:db8::10\n")

	want := []string{
		"ip6tables [-A INPUT -s 2001:db8::10 -j DROP]",
		"ip6tables [-D INPUT -s 2001:db8::10 -j DROP]",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %#v, want %#v", calls, want)
	}
}

func TestExecutorRejectsMalformedCommands(t *testing.T) {
	executor := NewExecutor("")
	called := false
	executor.runCommand = func(name string, args ...string) error {
		called = true
		return nil
	}

	handleExecutorInput(t, executor, "ban 203.0.113.10 extra\nunban\nban not-an-ip\n")

	if called {
		t.Fatal("malformed executor commands should not run iptables")
	}
}

func handleExecutorInput(t *testing.T, executor *Executor, input string) {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		executor.handleConnection(serverConn)
		close(done)
	}()

	if _, err := clientConn.Write([]byte(input)); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := clientConn.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
	<-done
}
