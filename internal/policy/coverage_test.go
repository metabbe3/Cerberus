package policy

import (
	"context"
	"testing"
)

func TestComputeCoverage_RealPolicies(t *testing.T) {
	// Policies directory in repo root: "../../policies"
	rep, err := ComputeCoverage("../../policies")
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
