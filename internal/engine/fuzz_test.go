package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/policy"
)

func FuzzDecide(f *testing.F) {
	store, err := policy.NewStore(context.Background(), policyDir, testData)
	if err != nil {
		f.Fatalf("NewStore: %v", err)
	}

	eng, err := New(store, nil, Options{
		CacheSize:   1000,
		EvalTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		f.Fatalf("engine.New: %v", err)
	}

	// Seed corpuses from brief requirements:
	// 1. Stage aneh
	f.Add("%%%$$$@@@", "k-open", "model1", "{}", "10.0.")
	f.Add("\x00\x00\x00", "k-open", "model1", "{}", "192.168.")
	f.Add("unknown_stage", "k-open", "model1", `{"cmd": "ls"}`, "localhost")

	// 2. Args bukan object (raw string, array, null, number, malformed)
	f.Add("tool", "k-open", "model1", `"not an object"`, "10.0.1.2:80")
	f.Add("tool", "k-open", "model1", `[1, 2, 3]`, "::1")
	f.Add("tool", "k-open", "model1", `null`, "10.0.")
	f.Add("tool", "k-open", "model1", `12345`, "prod-db")
	f.Add("tool", "k-open", "model1", `{invalid-json`, "")

	// 3. String 10MB seed (simulated large string)
	f.Add("llm", "k-open", "m1", `{"prompt": "`+strings.Repeat("A", 10000)+`"}`, "")

	// 4. Unicode null bytes
	f.Add("llm", "k-open\x00admin", "m1\x00evil", `{"prompt": "hello\u0000world"}`, "10.0.\x00")

	// 5. IP partial and host without port
	f.Add("http", "k-open", "", `{"method": "CONNECT"}`, "10.0.")
	f.Add("http", "k-open", "", `{"method": "GET"}`, "localhost")
	f.Add("http", "k-open", "", `{"method": "GET"}`, "::::")
	f.Add("http", "k-open", "", `{"method": "GET"}`, "192.168.1.1")
	f.Add("http", "k-open", "", `{"method": "GET"}`, "103.22.201.5:443")

	ctx := context.Background()

	f.Fuzz(func(t *testing.T, stage, keyID, model, rawArgs, resource string) {
		// Parse rawArgs into map if valid JSON object, else pass nil or wrapped
		var args map[string]any
		_ = json.Unmarshal([]byte(rawArgs), &args)

		in := Input{
			Stage:    stage,
			KeyID:    keyID,
			Model:    model,
			Resource: resource,
			ToolCall: "test-tool",
			Args:     args,
		}

		// Invariant: Decide MUST NEVER panic under any malformed or unexpected input
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC on input: %+v: %v", in, r)
			}
		}()

		d := eng.Decide(ctx, in)

		// Malformed stages or unknown stages must always deny (fail-closed)
		if stage != "llm" && stage != "tool" && stage != "http" && stage != "docker" {
			if d.Allowed() {
				t.Errorf("malformed stage %q unexpectedly allowed: rule_id=%s", stage, d.RuleID)
			}
		}

		// Decision must never have empty Decision string
		if d.Decision == "" {
			t.Errorf("empty decision string on input: %+v", in)
		}
	})
}
