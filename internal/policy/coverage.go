package policy

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/cover"
	"github.com/open-policy-agent/opa/v1/tester"
)

// FileCoverage represents line coverage metrics for a single Rego file.
type FileCoverage struct {
	Coverage        float64 `json:"coverage"`
	CoveredLines    int     `json:"covered_lines"`
	NotCoveredLines int     `json:"not_covered_lines"`
}

// CoverageReport represents test coverage across policies.
type CoverageReport struct {
	Coverage        float64                 `json:"coverage"`
	CoveredLines    int                     `json:"covered_lines"`
	NotCoveredLines int                     `json:"not_covered_lines"`
	TotalLines      int                     `json:"total_lines"`
	Files           map[string]FileCoverage `json:"files,omitempty"`
}

// ComputeCoverage executes Rego tests under policyDir and returns an OPA-style coverage report.
func ComputeCoverage(policyDir string) (*CoverageReport, error) {
	ctx := context.Background()
	modules, store, err := tester.Load([]string{policyDir}, nil)
	if err != nil {
		return nil, fmt.Errorf("load policies for coverage: %w", err)
	}
	if len(modules) == 0 {
		return &CoverageReport{Files: make(map[string]FileCoverage)}, nil
	}

	cov := cover.New()
	runner := tester.NewRunner(). //nolint:staticcheck // SA1019: SetCoverageQueryTracer migration deferred
					SetModules(modules).
					SetStore(store).
					SetCoverageTracer( //nolint:staticcheck // SA1019: SetCoverageQueryTracer migration deferred
			cov)

	ch, err := runner.RunTests(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("run tests for coverage: %w", err)
	}
	for range ch {
		// drain results
	}

	rep := cov.Report(modules)
	fileReports := make(map[string]FileCoverage, len(rep.Files))
	for path, fr := range rep.Files {
		rel := path
		if strings.HasPrefix(path, policyDir) {
			rel = strings.TrimPrefix(path, policyDir)
			rel = strings.TrimPrefix(rel, string(filepath.Separator))
		}
		fileReports[rel] = FileCoverage{
			Coverage:        fr.Coverage,
			CoveredLines:    fr.CoveredLines,
			NotCoveredLines: fr.NotCoveredLines,
		}
	}

	return &CoverageReport{
		Coverage:        rep.Coverage,
		CoveredLines:    rep.CoveredLines,
		NotCoveredLines: rep.NotCoveredLines,
		TotalLines:      rep.CoveredLines + rep.NotCoveredLines,
		Files:           fileReports,
	}, nil
}

// SortedFiles returns file paths sorted alphabetically.
func (r *CoverageReport) SortedFiles() []string {
	if r == nil || len(r.Files) == 0 {
		return nil
	}
	keys := make([]string, 0, len(r.Files))
	for k := range r.Files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
