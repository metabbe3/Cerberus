package masking

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
)

func TestApply_Redact(t *testing.T) {
	rules, err := Compile([]Spec{{Pattern: "sk-[A-Za-z0-9]+", Transform: "redact"}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	out, changed := Apply(rules, "args", "token sk-abc123")
	if out != "token [REDACTED]" {
		t.Fatalf("out = %q, want %q", out, "token [REDACTED]")
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
}

func TestApply_Mask(t *testing.T) {
	rules, err := Compile([]Spec{{Pattern: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", Transform: "mask"}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	out, _ := Apply(rules, "args", "nick@example.com")
	if out != "ni************om" {
		t.Fatalf("out = %q, want %q", out, "ni************om")
	}

	short, err := Compile([]Spec{{Pattern: ".+", Transform: "mask"}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	out, _ = Apply(short, "args", "abc")
	if out != "***" {
		t.Fatalf("out = %q, want %q", out, "***")
	}
}

func TestApply_Hash(t *testing.T) {
	rules, err := Compile([]Spec{{Pattern: "sk-[A-Za-z0-9]+", Transform: "hash"}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	sum := sha256.Sum256([]byte("sk-abc"))
	want := "sha256:" + hex.EncodeToString(sum[:])[:16]
	out, changed := Apply(rules, "args", "sk-abc")
	if out != want {
		t.Fatalf("out = %q, want %q", out, want)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
}

// Real decoded JSON leaves are float64, bool and nil — all must pass through
// untouched (Review Focus 4), and a secret used as an object key is masked too.
func TestApply_JSONLeavesAndKeys(t *testing.T) {
	rules, err := Compile([]Spec{{Pattern: "sk-[A-Za-z0-9]+", Transform: "redact"}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var in map[string]any
	if err := json.Unmarshal([]byte(`{"n": 1.5, "b": true, "z": null, "sk-keysecret": "v", "s": "sk-x"}`), &in); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out, changed := Apply(rules, "args", in)
	if !changed {
		t.Fatal("changed = false, want true")
	}
	got := out.(map[string]any)
	if got["n"] != 1.5 || got["b"] != true || got["z"] != nil {
		t.Fatalf("non-string leaves changed: n=%v b=%v z=%v", got["n"], got["b"], got["z"])
	}
	if _, ok := got["z"]; !ok {
		t.Fatal("null leaf dropped; want key z kept with nil value")
	}
	if got["s"] != "[REDACTED]" {
		t.Fatalf("s = %v, want [REDACTED]", got["s"])
	}
	if _, leaked := got["sk-keysecret"]; leaked {
		t.Fatalf("secret object key survived masking: %v", got)
	}
	if got["[REDACTED]"] != "v" {
		t.Fatalf("masked key missing its value: %v", got)
	}
	if _, ok := in["sk-keysecret"]; !ok {
		t.Fatal("Apply mutated its input map")
	}
}

func TestApply_Nested(t *testing.T) {
	rules, err := Compile([]Spec{{Pattern: "sk-[A-Za-z0-9]+", Transform: "redact"}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	in := map[string]any{"a": []any{"sk-x", 42, map[string]any{"b": "sk-y"}}}
	out, changed := Apply(rules, "args", in)
	if !changed {
		t.Fatal("changed = false, want true")
	}
	got, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("out type = %T, want map[string]any", out)
	}
	arr, ok := got["a"].([]any)
	if !ok {
		t.Fatalf("out[a] type = %T, want []any", got["a"])
	}
	if arr[0] != "[REDACTED]" {
		t.Fatalf("out[a][0] = %v, want [REDACTED]", arr[0])
	}
	if arr[1] != 42 {
		t.Fatalf("out[a][1] = %v, want 42 untouched", arr[1])
	}
	inner, ok := arr[2].(map[string]any)
	if !ok {
		t.Fatalf("out[a][2] type = %T, want map[string]any", arr[2])
	}
	if inner["b"] != "[REDACTED]" {
		t.Fatalf("out[a][2][b] = %v, want [REDACTED]", inner["b"])
	}
	// input not mutated
	orig := in["a"].([]any)
	if orig[0] != "sk-x" {
		t.Fatalf("input mutated: in[a][0] = %v", orig[0])
	}
	if orig[2].(map[string]any)["b"] != "sk-y" {
		t.Fatalf("input mutated: in[a][2][b] = %v", orig[2].(map[string]any)["b"])
	}
}

func TestApply_ScopeFilter(t *testing.T) {
	rules, err := Compile([]Spec{
		{Pattern: "secret", Transform: "redact", Scope: "response"},
		{Pattern: "open", Transform: "redact", Scope: ""},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	out, _ := Apply(rules, "args", "secret open")
	if out != "secret [REDACTED]" {
		t.Fatalf("out = %q, want %q", out, "secret [REDACTED]")
	}
	out, _ = Apply(rules, "response", "secret open")
	if out != "[REDACTED] [REDACTED]" {
		t.Fatalf("out = %q, want %q", out, "[REDACTED] [REDACTED]")
	}
}

func TestCompile_BadRegexErrors(t *testing.T) {
	if _, err := Compile([]Spec{{Pattern: "([", Transform: "redact"}}); err == nil {
		t.Fatal("Compile with bad regex: err = nil, want error")
	}
}

func TestCompile_EmptyMatchPatternRejected(t *testing.T) {
	// \d* matches "" and would insert the transform output at every
	// character position, blowing up args, the LRU cache, SSE and SQLite.
	for _, pattern := range []string{`\d*`, "x*", ""} {
		if _, err := Compile([]Spec{{Pattern: pattern, Transform: "redact"}}); err == nil {
			t.Fatalf("Compile(%q): err = nil, want error", pattern)
		}
	}
	// Patterns that require at least one character stay legal.
	if _, err := Compile([]Spec{{Pattern: ".+", Transform: "redact"}}); err != nil {
		t.Fatalf("Compile(.+): %v", err)
	}
}

func TestCompile_BadTransformErrors(t *testing.T) {
	if _, err := Compile([]Spec{{Pattern: "x", Transform: "base64"}}); err == nil {
		t.Fatal("Compile with unknown transform: err = nil, want error")
	}
}

func TestApply_NoRulesReturnsSameChangedFalse(t *testing.T) {
	out, changed := Apply(nil, "args", "plain")
	if changed || out != "plain" {
		t.Fatalf("Apply(nil) = %v, %v; want same value, false", out, changed)
	}
	m := map[string]any{"k": "v"}
	out, changed = Apply(nil, "args", m)
	if changed || !reflect.DeepEqual(out, m) {
		t.Fatalf("Apply(nil, map) = %v, %v; want same map, false", out, changed)
	}
}
