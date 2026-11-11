package store

import (
	"context"
	"strings"
	"os"
	"testing"
)

// Integration test against a live PostgreSQL. Skipped when
// CERBERUS_TEST_PG_DSN is unset so CI without PG stays green.
// The DSN MUST point at a throwaway database (name must start with
// "cerberus_test"): this test writes and deletes rows and once clobbered a
// live table by mistake. Live databases are refused, not assumed safe.
func testPG(t *testing.T) *PG {
	t.Helper()
	dsn := os.Getenv("CERBERUS_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("CERBERUS_TEST_PG_DSN not set")
	}
	if !strings.Contains(dsn, "/cerberus_test") {
		t.Skipf("refusing to run against a non-test database (dsn must target /cerberus_test)")
	}
	p, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestRoundTripSaveLoad(t *testing.T) {
	p := testPG(t)
	ctx := context.Background()

	doc := map[string]any{
		"config": map[string]any{"bypass_unknown_keys": false},
		"agents": map[string]any{
			"k-pgtest-a": map[string]any{"name": "pg-a", "allowed_tool_calls": []any{"read*"}},
			"k-pgtest-b": map[string]any{"name": "pg-b", "team_id": "t1", "allowed_models": []any{"glm-*"}},
		},
		"teams":            map[string]any{"t1": map[string]any{"allowed_tools": []any{"http_get"}}},
		"blocked_patterns": []any{"jailbreak", "system override"},
		"domains":          map[string]any{"api.example.com": map[string]any{"allow": true}},
		"prod_shield":      map[string]any{"cidrs": []any{"10.0.0.0/8"}},
		"ssh":              map[string]any{"allow_hosts": []any{"*.teknikal.id"}},
	}
	if err := p.SaveData(ctx, doc); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := p.LoadData(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := got["agents"].(map[string]any)["k-pgtest-a"]; !ok {
		t.Fatalf("agent a missing after round-trip: %v", got["agents"])
	}
	if _, ok := got["agents"].(map[string]any)["k-pgtest-b"]; !ok {
		t.Fatalf("agent b missing after round-trip")
	}
	if got["config"].(map[string]any)["bypass_unknown_keys"] != false {
		t.Fatalf("config not round-tripped: %v", got["config"])
	}
	pats, _ := got["blocked_patterns"].([]string)
	if len(pats) != 2 {
		t.Fatalf("blocked_patterns not round-tripped: %v", got["blocked_patterns"])
	}

	// Removal semantics: agent b dropped from doc -> disabled (absent on load).
	doc2 := map[string]any{
		"config":          map[string]any{"bypass_unknown_keys": false},
		"agents":          map[string]any{"k-pgtest-a": map[string]any{"name": "pg-a"}},
		"blocked_patterns": []any{"jailbreak"},
	}
	if err := p.SaveData(ctx, doc2); err != nil {
		t.Fatalf("save2: %v", err)
	}
	got2, err := p.LoadData(ctx)
	if err != nil {
		t.Fatalf("load2: %v", err)
	}
	if _, ok := got2["agents"].(map[string]any)["k-pgtest-b"]; ok {
		t.Fatalf("agent b should be disabled after removal")
	}

	// Templates CRUD.
	if err := p.UpsertTemplate(ctx, "pgtest-tpl", "PG Test", "desc", "ai", map[string]any{"budget_limit": 5}); err != nil {
		t.Fatalf("upsert template: %v", err)
	}
	tpls, err := p.ListTemplates(ctx)
	if err != nil {
		t.Fatalf("list templates: %v", err)
	}
	found := false
	for _, tpl := range tpls {
		if tpl["id"] == "pgtest-tpl" {
			found = true
		}
	}
	if !found {
		t.Fatalf("template not listed")
	}
	if err := p.DeleteTemplate(ctx, "pgtest-tpl"); err != nil {
		t.Fatalf("delete template: %v", err)
	}
	// builtin protected
	if err := p.DeleteTemplate(ctx, "research-readonly"); err == nil {
		t.Fatalf("builtin template must not be deletable")
	}
}
