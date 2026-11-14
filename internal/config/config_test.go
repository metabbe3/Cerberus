package config

import (
	"reflect"
	"testing"
	"time"
)

// env makes a getenv func from a map (missing keys → "").
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoad_RequiresAdminToken(t *testing.T) {
	t.Parallel()
	if _, err := Load(nil, env(nil)); err == nil {
		t.Fatal("want error when CERBERUS_ADMIN_TOKEN is empty")
	}
}

// The admin token is env-only: a secret on argv leaks via ps//proc/cmdline,
// so -admin-token must not exist (unknown flag → startup error).
func TestLoad_AdminTokenFlagRejected(t *testing.T) {
	t.Parallel()
	if _, err := Load([]string{"-admin-token", "tok"}, env(map[string]string{"CERBERUS_ADMIN_TOKEN": "envtok"})); err == nil {
		t.Fatal("-admin-token accepted; want unknown-flag error")
	}
}

func TestLoad_Defaults(t *testing.T) {
	t.Parallel()
	c, err := Load(nil, env(map[string]string{"CERBERUS_ADMIN_TOKEN": "tok"}))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Addr:                ":8089",
		PolicyDir:           "policies",
		DataFile:            "data/prod.json",
		AuditDB:             "cerberus.db",
		AuditRetentionDays:  30,
		AdminToken:          "tok",
		LogLevel:            "info",
		CacheSize:           10000,
		EvalTimeout:         3 * time.Second,
		ClusterSyncInterval: 60 * time.Second,
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("got %+v, want %+v", c, want)
	}
}

func TestLoad_ParsesTimeout(t *testing.T) {
	t.Parallel()
	c, err := Load(nil, env(map[string]string{
		"CERBERUS_ADMIN_TOKEN":  "tok",
		"CERBERUS_EVAL_TIMEOUT": "25ms",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.EvalTimeout != 25*time.Millisecond {
		t.Fatalf("got %v, want 25ms", c.EvalTimeout)
	}
	// Invalid duration must fail startup, not fall back silently.
	if _, err := Load(nil, env(map[string]string{
		"CERBERUS_ADMIN_TOKEN":  "tok",
		"CERBERUS_EVAL_TIMEOUT": "soon",
	})); err == nil {
		t.Fatal("want error for invalid CERBERUS_EVAL_TIMEOUT")
	}
}

func TestLoad_FlagOverridesEnv(t *testing.T) {
	t.Parallel()
	c, err := Load(
		[]string{"-addr", ":2222", "-cache-size", "9"},
		env(map[string]string{
			"CERBERUS_ADMIN_TOKEN": "envtok",
			"CERBERUS_ADDR":        ":1111",
			"CERBERUS_CACHE_SIZE":  "7",
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":2222" {
		t.Errorf("addr: got %q, want :2222", c.Addr)
	}
	if c.CacheSize != 9 {
		t.Errorf("cache size: got %d, want 9", c.CacheSize)
	}
	if c.AdminToken != "envtok" {
		t.Errorf("admin token: got %q, want envtok", c.AdminToken)
	}
	// Env value survives when no flag overrides it.
	if c.EvalTimeout != 3*time.Second {
		t.Errorf("eval timeout default: got %v", c.EvalTimeout)
	}
}

func TestLoad_BundlePubKey(t *testing.T) {
	t.Parallel()
	c, err := Load(nil, env(map[string]string{
		"CERBERUS_ADMIN_TOKEN":   "tok",
		"CERBERUS_BUNDLE_PUBKEY": "dGVzdC1rZXk=",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.BundlePubKey != "dGVzdC1rZXk=" {
		t.Fatalf("bundle pubkey from env: got %q, want dGVzdC1rZXk=", c.BundlePubKey)
	}

	c, err = Load(
		[]string{"-bundle-pubkey", "ZmxhZy1rZXk="},
		env(map[string]string{
			"CERBERUS_ADMIN_TOKEN":   "tok",
			"CERBERUS_BUNDLE_PUBKEY": "ZW52LWtleQ==",
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if c.BundlePubKey != "ZmxhZy1rZXk=" {
		t.Fatalf("bundle pubkey from flag: got %q, want ZmxhZy1rZXk=", c.BundlePubKey)
	}
}

func TestLoad_ClusterConfig(t *testing.T) {
	t.Parallel()
	c, err := Load(
		[]string{"-node-id", "node-alpha", "-peers", "http://10.0.0.1:8089, https://10.0.0.2:8089", "-cluster-sync-interval", "15s"},
		env(map[string]string{
			"CERBERUS_ADMIN_TOKEN": "tok",
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if c.NodeID != "node-alpha" {
		t.Errorf("NodeID: got %q, want node-alpha", c.NodeID)
	}
	if len(c.Peers) != 2 || c.Peers[0] != "http://10.0.0.1:8089" || c.Peers[1] != "https://10.0.0.2:8089" {
		t.Errorf("Peers: got %v, want [http://10.0.0.1:8089 https://10.0.0.2:8089]", c.Peers)
	}
	if c.ClusterSyncInterval != 15*time.Second {
		t.Errorf("ClusterSyncInterval: got %v, want 15s", c.ClusterSyncInterval)
	}
}

func TestLoad_ClusterConfig_EnvFallback(t *testing.T) {
	t.Parallel()
	c, err := Load(nil, env(map[string]string{
		"CERBERUS_ADMIN_TOKEN":           "tok",
		"CERBERUS_NODE_ID":               "node-beta",
		"CERBERUS_CLUSTER_PEERS":         "http://node1:8089,http://node2:8089",
		"CERBERUS_CLUSTER_SYNC_INTERVAL": "30s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.NodeID != "node-beta" {
		t.Errorf("NodeID: got %q, want node-beta", c.NodeID)
	}
	if len(c.Peers) != 2 || c.Peers[0] != "http://node1:8089" || c.Peers[1] != "http://node2:8089" {
		t.Errorf("Peers: got %v", c.Peers)
	}
	if c.ClusterSyncInterval != 30*time.Second {
		t.Errorf("ClusterSyncInterval: got %v, want 30s", c.ClusterSyncInterval)
	}
}

func TestLoad_ClusterConfig_InvalidPeerURL(t *testing.T) {
	t.Parallel()
	_, err := Load(
		[]string{"-peers", "ftp://invalid-peer:8089"},
		env(map[string]string{"CERBERUS_ADMIN_TOKEN": "tok"}),
	)
	if err == nil {
		t.Fatal("expected error for non-http/https peer URL, got nil")
	}
}
