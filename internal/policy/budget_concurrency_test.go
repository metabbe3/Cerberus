package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/open-policy-agent/opa/v1/rego"
)

// 8A.6: Budget concurrency: 20 goroutine decide paralel vs budget hampir habis -> tidak ada overshoot
func TestBudgetConcurrency_NoOvershoot(t *testing.T) {
	repoRoot := ""
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			repoRoot = dir
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root")
		}
		dir = parent
	}

	policyDir := filepath.Join(repoRoot, "policies")
	dataPath := filepath.Join(repoRoot, "policies", "testdata", "data.json")

	store, err := policy.NewStore(context.Background(), policyDir, dataPath)
	if err != nil {
		t.Fatalf("policy.NewStore: %v", err)
	}

	// k-glob in data.json has budget_limit = 50.
	// Starting with budget nearly exhausted: $49.0 spent, remaining = $1.00.
	// 20 goroutines each attempt to spend $0.50 concurrently.
	// Only 2 requests ($1.00 total) can be admitted before hitting the limit of $50.00.
	const (
		numGoroutines  = 20
		initialSpentUS = 4900 // cents: $49.00
		spendPerReqUS  = 50   // cents: $0.50
		budgetLimitUS  = 5000 // cents: $50.00
	)

	var spentUS atomic.Int64
	spentUS.Store(initialSpentUS)

	var (
		wg            sync.WaitGroup
		allowed       atomic.Int64
		denied        atomic.Int64
		totalAdmitted atomic.Int64
	)

	snap := store.Current()
	ctx := context.Background()

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			// Atomic spend allocation
			for {
				cur := spentUS.Load()
				if cur+spendPerReqUS > budgetLimitUS {
					// Budget would be exceeded: evaluate policy with projected cumulative spend
					input := map[string]any{
						"stage":  "llm",
						"key_id": "k-glob",
						"model":  "m1",
						"context": map[string]any{
							"budget_spent_usd": float64(cur+spendPerReqUS) / 100.0,
							"spend_usd":        float64(spendPerReqUS) / 100.0,
						},
					}
					rs, err := snap.Query.Eval(ctx, rego.EvalInput(input))
					if err != nil {
						t.Errorf("Eval error: %v", err)
						return
					}
					if len(rs) > 0 && len(rs[0].Expressions) > 0 {
						dec, ok := rs[0].Expressions[0].Value.(map[string]any)
						if ok && dec["decision"] == "deny" {
							denied.Add(1)
						}
					}
					return
				}

				if spentUS.CompareAndSwap(cur, cur+spendPerReqUS) {
					// Successfully allocated spend within budget
					input := map[string]any{
						"stage":  "llm",
						"key_id": "k-glob",
						"model":  "m1",
						"context": map[string]any{
							"budget_spent_usd": float64(cur) / 100.0,
							"spend_usd":        float64(spendPerReqUS) / 100.0,
						},
					}
					rs, err := snap.Query.Eval(ctx, rego.EvalInput(input))
					if err != nil {
						t.Errorf("Eval error: %v", err)
						return
					}
					if len(rs) > 0 && len(rs[0].Expressions) > 0 {
						dec, ok := rs[0].Expressions[0].Value.(map[string]any)
						if ok && dec["decision"] == "allow" {
							allowed.Add(1)
							totalAdmitted.Add(spendPerReqUS)
						}
					}
					return
				}
			}
		}()
	}

	wg.Wait()

	if totalAdmitted.Load() > (budgetLimitUS - initialSpentUS) {
		t.Fatalf("budget overshoot! admitted %d cents, max allowable %d cents",
			totalAdmitted.Load(), budgetLimitUS-initialSpentUS)
	}

	if allowed.Load() != 2 {
		t.Fatalf("expected exactly 2 allowed requests within budget, got %d", allowed.Load())
	}
	if denied.Load() != numGoroutines-2 {
		t.Fatalf("expected %d denied requests, got %d", numGoroutines-2, denied.Load())
	}
}
