package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
)

const (
	policyDir = "../../policies"
	testData  = "../../policies/testdata/data.json"
)

// loadTestData returns the fixture data document used by the Rego tests.
func loadTestData(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(testData)
	if err != nil {
		t.Fatalf("read fixture data: %v", err)
	}
	return b
}

func TestLoad_BuildsQuery(t *testing.T) {
	ctx := context.Background()
	snap, err := Load(ctx, policyDir, loadTestData(t), 1)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if snap.Epoch != 1 {
		t.Fatalf("Epoch = %d, want 1", snap.Epoch)
	}
	if snap.Loaded.IsZero() {
		t.Fatal("Loaded not set")
	}
	if snap.Data == nil {
		t.Fatal("Data nil")
	}

	input := map[string]any{
		"stage":     "tool",
		"key_id":    "k-glob",
		"tool_call": "kubernetes_get_pods",
		"args":      map[string]any{},
	}
	rs, err := snap.Query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("results = %d, want 1", len(rs))
	}
	d, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		t.Fatalf("decision type %T, want map[string]any", rs[0].Expressions[0].Value)
	}
	if d["decision"] != "allow" || d["rule_id"] != "ai.tool.allow" {
		t.Fatalf("decision = %v, want allow/ai.tool.allow", d)
	}
}

func TestLoad_BadRegoReturnsErrCompile(t *testing.T) {
	dir := t.TempDir()
	broken := "package gateway.authz\n\nthis is not rego(\n"
	if err := os.WriteFile(filepath.Join(dir, "broken.rego"), []byte(broken), 0o600); err != nil {
		t.Fatalf("write broken rego: %v", err)
	}
	_, err := Load(context.Background(), dir, []byte("{}"), 1)
	if !errors.Is(err, ErrCompile) {
		t.Fatalf("err = %v, want ErrCompile", err)
	}
}

func TestLoad_StrictDataRejectsUnknownTopLevelKey(t *testing.T) {
	_, err := Load(context.Background(), policyDir, []byte(`{"bogus":1}`), 1)
	if !errors.Is(err, ErrData) {
		t.Fatalf("err = %v, want ErrData", err)
	}
}

func TestLoad_StrictDataRejectsBadJSON(t *testing.T) {
	_, err := Load(context.Background(), policyDir, []byte(`{nope`), 1)
	if !errors.Is(err, ErrData) {
		t.Fatalf("err = %v, want ErrData", err)
	}
}

func TestLoad_CompilesMaskers(t *testing.T) {
	snap, err := Load(context.Background(), policyDir, loadTestData(t), 1)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rules := snap.Maskers["k-glob"]
	if len(rules) != 2 {
		t.Fatalf("Maskers[k-glob] = %d rules, want 2", len(rules))
	}
	if rules[0].Transform != "redact" || rules[1].Transform != "mask" {
		t.Fatalf("transforms = %s,%s, want redact,mask", rules[0].Transform, rules[1].Transform)
	}
	if len(snap.Maskers) != 1 {
		t.Fatalf("Maskers has %d keys, want 1 (only k-glob masks)", len(snap.Maskers))
	}
}
