package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestComputeCoverage_RealPolicies(t *testing.T) {
	ctx := context.Background()
	// Policies directory in repo root: "../../policies"
	rep, err := ComputeCoverage(ctx, "../../policies")
	if err != nil {
		t.Fatalf("ComputeCoverage: %v", err)
	}
	if rep == nil {
		t.Fatal("expected non-nil coverage report")
	}
	if rep.Coverage < 80.0 {
		t.Fatalf("expected coverage >= 80%%, got %.2f%%", rep.Coverage)
	}
	if rep.CoveredLines == 0 {
		t.Fatal("expected >0 covered lines")
	}
	if len(rep.Files) == 0 {
		t.Fatal("expected reported files")
	}
	if len(rep.SortedFiles()) != len(rep.Files) {
		t.Fatalf("SortedFiles count = %d, want %d", len(rep.SortedFiles()), len(rep.Files))
	}
}

func TestStore_CoverageMethod(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(ctx, "../../policies", "../../policies/testdata/data.json")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	rep, err := store.Coverage(ctx)
	if err != nil {
		t.Fatalf("store.Coverage: %v", err)
	}
	if rep.Coverage <= 0 {
		t.Fatalf("expected positive coverage, got %.2f", rep.Coverage)
	}
	if store.Current().Coverage != rep.Coverage {
		t.Fatalf("snapshot coverage = %.2f, want %.2f", store.Current().Coverage, rep.Coverage)
	}
}

func TestComputeCoverage_FailingTest(t *testing.T) {
	dir := t.TempDir()
	policy := "package example\nimport rego.v1\ndefault allow := false\n"
	test := "package example\nimport rego.v1\ntest_fail if {\n\t1 == 2\n}\n"
	_ = os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(policy), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "policy_test.rego"), []byte(test), 0o600)
	rep, err := ComputeCoverage(context.Background(), dir)
	if err == nil {
		t.Fatal("expected err != nil for failing test, got nil")
	}
	if rep != nil {
		t.Fatalf("expected nil report on failure, got %+v", rep)
	}
}
