package proxy_test

import (
	"context"
	"github.com/metabbe3/cerberus/internal/proxy"
	"net"
	"testing"
)

// DNS-rebinding / IP-normalization guard tests (Argon round 2).

func TestNormalizeIPStringUnwrapsV4MappedV6(t *testing.T) {
	cases := map[string]string{
		"::ffff:10.0.0.1":   "10.0.0.1",
		"[::ffff:10.0.0.1]": "10.0.0.1",
		"10.0.0.1":          "10.0.0.1",
		"8.8.8.8":           "8.8.8.8",
		"2001:db8::1":       "2001:db8::1",
	}
	for in, want := range cases {
		if got := proxy.NormalizeIPString(in); got != want {
			t.Errorf("proxy.NormalizeIPString(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDenyHostIPBlocksProdCIDR(t *testing.T) {
	eng := setupTestEngine(t) // fixture engine with testdata shield
	if err := proxy.DenyHostIP(context.Background(), eng, "10.0.0.1"); err == nil {
		t.Fatal("10.0.0.1 (prod CIDR) must be denied by dial guard")
	}
	if err := proxy.DenyHostIP(context.Background(), eng, "8.8.8.8"); err != nil {
		t.Fatalf("8.8.8.8 must be allowed: %v", err)
	}
}

func TestDenyHostIPBlocksV4MappedV6Prod(t *testing.T) {
	eng := setupTestEngine(t)
	if err := proxy.DenyHostIP(context.Background(), eng, "::ffff:10.0.0.1"); err == nil {
		t.Fatal("::ffff:10.0.0.1 must normalize to 10.0.0.1 and be denied")
	}
}

func TestNormalizeIPRejectsGarbage(t *testing.T) {
	if ip := net.ParseIP(proxy.NormalizeIPString("not-an-ip")); ip != nil {
		t.Fatal("garbage host must not parse to an IP after normalization")
	}
}
