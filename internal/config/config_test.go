package config

import (
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
	// A flag-supplied token satisfies the requirement too.
	if _, err := Load([]string{"-admin-token", "tok"}, env(nil)); err != nil {
		t.Fatalf("flag -admin-token rejected: %v", err)
	}
}

func TestLoad_Defaults(t *testing.T) {
	t.Parallel()
	c, err := Load(nil, env(map[string]string{"CERBERUS_ADMIN_TOKEN": "tok"}))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Addr:        ":8089",
		PolicyDir:   "policies",
		DataFile:    "data/prod.json",
		AuditDB:     "cerberus.db",
		AdminToken:  "tok",
		LogLevel:    "info",
		CacheSize:   10000,
		EvalTimeout: 10 * time.Millisecond,
	}
	if c != want {
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
		[]string{"-addr", ":2222", "-cache-size", "9", "-admin-token", "flagtok"},
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
	if c.AdminToken != "flagtok" {
		t.Errorf("admin token: got %q, want flagtok", c.AdminToken)
	}
	// Env value survives when no flag overrides it.
	if c.EvalTimeout != 10*time.Millisecond {
		t.Errorf("eval timeout default: got %v", c.EvalTimeout)
	}
}
