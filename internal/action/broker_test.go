package action

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"ai-guardd/internal/types"
)

func TestIsAllowedTargetMatchesExactIP(t *testing.T) {
	allowlist := []string{"127.0.0.1", "192.0.2.10"}

	if !isAllowedTarget("192.0.2.10", allowlist) {
		t.Fatal("expected exact IP allowlist entry to match")
	}
	if isAllowedTarget("192.0.2.11", allowlist) {
		t.Fatal("did not expect neighboring IP to match exact allowlist entry")
	}
}

func TestIsAllowedTargetMatchesCIDR(t *testing.T) {
	allowlist := []string{"10.0.0.0/8", "2001:db8::/32"}

	if !isAllowedTarget("10.20.30.40", allowlist) {
		t.Fatal("expected IPv4 CIDR allowlist entry to match")
	}
	if !isAllowedTarget("2001:db8::10", allowlist) {
		t.Fatal("expected IPv6 CIDR allowlist entry to match")
	}
	if isAllowedTarget("172.16.0.1", allowlist) {
		t.Fatal("did not expect IP outside CIDR ranges to match")
	}
}

func TestIsAllowedTargetIgnoresInvalidAllowlistEntries(t *testing.T) {
	allowlist := []string{"not-a-cidr", "10.0.0.0/33", ""}

	if isAllowedTarget("10.0.0.5", allowlist) {
		t.Fatal("invalid allowlist entries should not match a valid target")
	}
	if !isAllowedTarget("not-a-cidr", allowlist) {
		t.Fatal("literal allowlist entries should still match the same literal target")
	}
}

func TestExecuteActiveDefenseRunsIPTablesWithoutExecutor(t *testing.T) {
	broker := NewBroker(true, nil, "", "")
	var gotName string
	var gotArgs []string
	broker.runCommand = func(name string, args ...string) error {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return nil
	}

	err := broker.Execute(banEvent("203.0.113.10"))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if gotName != "iptables" {
		t.Fatalf("command name = %q", gotName)
	}
	wantArgs := []string{"-A", "INPUT", "-s", "203.0.113.10", "-j", "DROP"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", gotArgs, wantArgs)
	}
}

func TestExecuteActiveDefenseUsesIP6TablesForIPv6(t *testing.T) {
	broker := NewBroker(true, nil, "", "")
	var gotName string
	var gotArgs []string
	broker.runCommand = func(name string, args ...string) error {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return nil
	}

	err := broker.Execute(banEvent("2001:db8::10"))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if gotName != "ip6tables" {
		t.Fatalf("command name = %q", gotName)
	}
	wantArgs := []string{"-A", "INPUT", "-s", "2001:db8::10", "-j", "DROP"}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("command args = %#v, want %#v", gotArgs, wantArgs)
	}
}

func TestExecuteSafeModeDoesNotRunIPTables(t *testing.T) {
	broker := NewBroker(false, nil, "", "")
	called := false
	broker.runCommand = func(name string, args ...string) error {
		called = true
		return nil
	}

	err := broker.Execute(banEvent("203.0.113.20"))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if called {
		t.Fatal("safe mode should not run iptables")
	}
}

func TestExecuteAllowlistBlocksIPTables(t *testing.T) {
	broker := NewBroker(true, []string{"203.0.113.0/24"}, "", "")
	called := false
	broker.runCommand = func(name string, args ...string) error {
		called = true
		return nil
	}

	err := broker.Execute(banEvent("203.0.113.30"))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if called {
		t.Fatal("allowlisted target should not run iptables")
	}
}

func TestNewBrokerCopiesAllowlist(t *testing.T) {
	allowlist := []string{"203.0.113.0/24"}
	broker := NewBroker(true, allowlist, "", "")
	allowlist[0] = "198.51.100.0/24"

	called := false
	broker.runCommand = func(name string, args ...string) error {
		called = true
		return nil
	}

	err := broker.Execute(banEvent("203.0.113.40"))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if called {
		t.Fatal("mutating caller allowlist should not unblock target")
	}
}

func TestUpdateConfigCopiesAllowlist(t *testing.T) {
	broker := NewBroker(true, nil, "", "")
	allowlist := []string{"203.0.113.0/24"}
	broker.UpdateConfig(true, allowlist, "", "")
	allowlist[0] = "198.51.100.0/24"

	called := false
	broker.runCommand = func(name string, args ...string) error {
		called = true
		return nil
	}

	err := broker.Execute(banEvent("203.0.113.41"))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if called {
		t.Fatal("mutating updated allowlist should not unblock target")
	}
}

func TestExecuteReturnsIPTablesError(t *testing.T) {
	broker := NewBroker(true, nil, "", "")
	broker.runCommand = func(name string, args ...string) error {
		return errors.New("iptables failed")
	}

	err := broker.Execute(banEvent("203.0.113.40"))
	if err == nil {
		t.Fatal("expected Execute() error")
	}
	if !strings.Contains(err.Error(), "failed to ban IP 203.0.113.40") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteIgnoresUnsupportedActionWithExecutor(t *testing.T) {
	broker := NewBroker(true, nil, "", "missing-executor.sock")

	err := broker.Execute(&types.Event{
		Summary: "unsupported action",
		SuggestedAction: &types.SuggestedAction{
			Type:   "restart_service",
			Target: "ssh",
		},
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func banEvent(target string) *types.Event {
	return &types.Event{
		Summary: "test alert",
		SuggestedAction: &types.SuggestedAction{
			Type:     "ban_ip",
			Target:   target,
			Duration: "1h",
		},
	}
}
