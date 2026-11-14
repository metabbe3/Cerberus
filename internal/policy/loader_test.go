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
	if len(snap.Modules) == 0 {
		t.Fatal("Modules map is empty, want parsed modules")
	}
	if len(snap.Stages) == 0 {
		t.Fatal("Stages map is empty, want parsed stages")
	}
	if len(snap.RuleIDs) == 0 {
		t.Fatal("RuleIDs map is empty, want parsed rule IDs")
	}
	if !snap.RuleIDs["ai.tool.allow"] {
		t.Fatal("RuleIDs does not contain ai.tool.allow")
	}
	if !snap.Stages["tool"] || !snap.Stages["ssh"] {
		t.Fatal("Stages does not contain tool or ssh")
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
	_, err := Load(context.Background(), dir, loadTestData(t), 1)
	if !errors.Is(err, ErrCompile) {
		t.Fatalf("err = %v, want ErrCompile", err)
	}
}

func TestLoad_RejectsNullAndEmptyDocument(t *testing.T) {
	for _, doc := range []string{"null", "{}"} {
		_, err := Load(context.Background(), policyDir, []byte(doc), 1)
		if !errors.Is(err, ErrData) {
			t.Fatalf("Load(%s): err = %v, want ErrData", doc, err)
		}
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

func TestLoad_AppleDoubleAndHiddenRegoSkipped(t *testing.T) {
	dir := t.TempDir()
	validRego := "package gateway.authz\n\ndefault decision = {\"decision\": \"allow\", \"rule_id\": \"test.ok\"}\n"
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(validRego), 0o600); err != nil {
		t.Fatalf("write valid rego: %v", err)
	}

	brokenAppleDouble := "package gateway.authz\n\nthis is invalid apple double syntax ((((\n"
	if err := os.WriteFile(filepath.Join(dir, "._evil.rego"), []byte(brokenAppleDouble), 0o600); err != nil {
		t.Fatalf("write apple double rego: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".hidden.rego"), []byte(brokenAppleDouble), 0o600); err != nil {
		t.Fatalf("write hidden rego: %v", err)
	}

	snap, err := Load(context.Background(), dir, loadTestData(t), 1)
	if err != nil {
		t.Fatalf("Load failed: %v (._evil.rego or .hidden.rego was not skipped)", err)
	}
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
}

func BenchmarkDecodeData(b *testing.B) {
	data, err := os.ReadFile(testData)
	if err != nil {
		b.Fatalf("read fixture: %v", err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := decodeData(data); err != nil {
			b.Fatalf("decodeData: %v", err)
		}
	}
}
