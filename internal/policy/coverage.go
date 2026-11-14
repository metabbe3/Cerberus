package policy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
func ComputeCoverage(ctx context.Context, policyDir string) (*CoverageReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Full rego suite in-process is expensive (247 tests; ~minutes under -race on
	// 2-core CI runners). CERBERUS_SKIP_POLICY_SUITE=1 makes coverage a no-op:
	// bundle activation keeps DryRunSmoke; the suite stays enforced by `make opa-test`.
	if os.Getenv("CERBERUS_SKIP_POLICY_SUITE") == "1" {
		return &CoverageReport{Files: make(map[string]FileCoverage)}, nil
	}
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

	timeout := 60 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if rem := time.Until(deadline); rem > 0 && rem < timeout {
			timeout = rem
		}
	}
	runner.SetTimeout(timeout)

	ch, err := runner.RunTests(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("run tests for coverage: %w", err)
	}
	var testErr error
	for tr := range ch {
		if testErr == nil {
			if tr.Error != nil {
				testErr = fmt.Errorf("test %s: %w", tr.Name, tr.Error)
			} else if tr.Fail {
				testErr = fmt.Errorf("test %s failed", tr.Name)
			}
		}
	}
	if testErr != nil {
		return nil, testErr
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
