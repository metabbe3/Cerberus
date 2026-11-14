package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

// RuleFamilies evaluated by Cerberus policy coverage harness.
var StandardRuleFamilies = []string{
	"authz",
	"shield.prod",
	"shield.cmd",
	"shield.container",
	"shellguard",
	"ai.llm",
	"ai.tool",
	"http",
	"docker",
	"ssh",
	"db",
	"k8s",
	"chain",
}

// StageReport summarizes metrics for an individual stage.
type StageReport struct {
	Stage       string  `json:"stage"`
	Samples     int64   `json:"samples"`
	Duration    string  `json:"duration"`
	TPS         float64 `json:"tps"`
	P50MS       float64 `json:"p50_ms"`
	P99MS       float64 `json:"p99_ms"`
	HitsAllow   int64   `json:"hits_allow"`
	HitsDeny    int64   `json:"hits_deny"`
	Flaky       int64   `json:"flaky"`
	Escapes     int64   `json:"escapes"`
	ChainBroken int64   `json:"chain_broken,omitempty"`
	PUB99       float64 `json:"p_ub99"`
}

// RuleFamilyCoverage metrics for a single rule family.
type RuleFamilyCoverage struct {
	Family string  `json:"family"`
	Hits   int64   `json:"hits"`
	Ratio  float64 `json:"ratio"`
}

// MonteCarloReport represents the full statistical coverage evaluation.
type MonteCarloReport struct {
	Version          string                        `json:"version"`
	GeneratedAt      time.Time                     `json:"generated_at"`
	MasterSeed       uint64                        `json:"master_seed"`
	TotalSamples     int64                         `json:"total_samples"`
	TotalDuration    string                        `json:"total_duration"`
	OverallTPS       float64                       `json:"overall_tps"`
	OverallP50MS     float64                       `json:"overall_p50_ms"`
	OverallP99MS     float64                       `json:"overall_p99_ms"`
	TotalAllow       int64                         `json:"total_allow"`
	TotalDeny        int64                         `json:"total_deny"`
	TotalFlaky       int64                         `json:"total_flaky"`
	TotalEscapes     int64                         `json:"total_escapes"`
	TotalChainBroken int64                         `json:"total_chain_broken,omitempty"`
	OverallPUB99     float64                       `json:"overall_p_ub99"`
	Stages           map[string]StageReport        `json:"stages"`
	CoverageMatrix   map[string]RuleFamilyCoverage `json:"coverage_matrix"`
	DeadRules        []string                      `json:"dead_rules"`
	FlakyRecords     []FlakyRecord                 `json:"flaky_records,omitempty"`
	Escapes          []EscapeRecord                `json:"escapes,omitempty"`
}

// ComputePUB99 calculates the 99% binomial upper bound for escape rate (alpha = 0.01).
func ComputePUB99(n int64, k int64) float64 {
	if n <= 0 {
		return 0.0
	}
	if k >= n {
		return 1.0
	}
	if k <= 0 {
		// Zero-failure binomial upper bound: 1 - alpha^(1/n)
		return 1.0 - math.Pow(0.01, 1.0/float64(n))
	}
	// Wilson score upper bound with z=2.575829 (99% confidence level)
	z := 2.5758293035489004
	z2 := z * z
	nf := float64(n)
	p := float64(k) / nf
	term := (p * (1.0 - p) / nf) + (z2 / (4.0 * nf * nf))
	if term < 0 {
		return 1.0
	}
	num := p + (z2 / (2.0 * nf)) + z*math.Sqrt(term)
	den := 1.0 + (z2 / nf)
	ub := num / den
	if ub > 1.0 || math.IsNaN(ub) {
		return 1.0
	}
	return ub
}

// Percentile computes the p-th percentile from sorted latencies in milliseconds.
func Percentile(sorted []float64, pct float64) float64 {
	if len(sorted) == 0 {
		return 0.0
	}
	idx := int(pct * float64(len(sorted)-1))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// PrintTerminalTable outputs the terminal summary table as requested in Argon §4.
func PrintTerminalTable(stages []StageReport, total StageReport) {
	fmt.Println("\n" + strings.Repeat("=", 105))
	fmt.Println("CERBERUS MONTE CARLO STATISTICAL POLICY COVERAGE HARNESS")
	fmt.Println(strings.Repeat("=", 105))
	fmt.Printf("%-8s | %8s | %8s | %8s | %8s | %7s | %7s | %6s | %7s | %10s\n",
		"stage", "samples", "TPS", "p50(ms)", "p99(ms)", "allow", "deny", "flaky", "escapes", "p_ub99")
	fmt.Println(strings.Repeat("-", 105))

	for _, s := range stages {
		fmt.Printf("%-8s | %8d | %8.0f | %8.2f | %8.2f | %7d | %7d | %6d | %7d | %10.6f\n",
			s.Stage, s.Samples, s.TPS, s.P50MS, s.P99MS, s.HitsAllow, s.HitsDeny, s.Flaky, s.Escapes, s.PUB99)
	}
	fmt.Println(strings.Repeat("-", 105))
	fmt.Printf("%-8s | %8d | %8.0f | %8.2f | %8.2f | %7d | %7d | %6d | %7d | %10.6f\n",
		total.Stage, total.Samples, total.TPS, total.P50MS, total.P99MS, total.HitsAllow, total.HitsDeny, total.Flaky, total.Escapes, total.PUB99)
	fmt.Println(strings.Repeat("=", 105))
}

// BuildCoverageMatrix tallies rule family hits and calculates dead rules.
func BuildCoverageMatrix(ruleHits map[string]int64, totalRequests int64) (map[string]RuleFamilyCoverage, []string) {
	matrix := make(map[string]RuleFamilyCoverage)
	var dead []string

	for _, fam := range StandardRuleFamilies {
		hits := ruleHits[fam]
		var ratio float64
		if totalRequests > 0 {
			ratio = float64(hits) / float64(totalRequests)
		}
		matrix[fam] = RuleFamilyCoverage{
			Family: fam,
			Hits:   hits,
			Ratio:  ratio,
		}
		if hits == 0 {
			dead = append(dead, fam)
		}
	}
	sort.Strings(dead)
	return matrix, dead
}

// WriteReportJSON persists the report to the output file.
func WriteReportJSON(path string, rep *MonteCarloReport) error {
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report json: %w", err)
	}
	return os.WriteFile(path, b, 0600)
}
