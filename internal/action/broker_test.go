package action

import "testing"

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
