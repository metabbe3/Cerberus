package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RunnerConfig holds CLI options and test parameters.
type RunnerConfig struct {
	DecideURL     string
	AdminToken    string
	SpacePath     string
	MasterSeed    uint64
	NPerStage     int
	OutPath       string
	ExplainSample float64
	Concurrency   int
	Timeout       time.Duration
}

// Runner drives the entire Monte Carlo statistical coverage evaluation.
type Runner struct {
	cfg      RunnerConfig
	space    *ScenarioSpace
	sampler  *Sampler
	client   *http.Client
	oracle   *Oracle
	flaky    *FlakyDetector
	ruleHits map[string]int64
	hitsMu   sync.Mutex
}

// NewRunner creates a new Runner instance.
func NewRunner(cfg RunnerConfig, space *ScenarioSpace) *Runner {
	tr := &http.Transport{
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 512,
		IdleConnTimeout:     90 * time.Second,
	}
	cli := &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
	}

	return &Runner{
		cfg:      cfg,
		space:    space,
		sampler:  NewSampler(space),
		client:   cli,
		oracle:   NewOracle(cli, cfg.DecideURL, cfg.AdminToken, space.OracleChains),
		flaky:    NewFlakyDetector(cli, cfg.DecideURL, cfg.AdminToken, cfg.ExplainSample),
		ruleHits: make(map[string]int64),
	}
}

// Run executes all stages and generates the comprehensive report.
func (rn *Runner) Run(ctx context.Context) (*MonteCarloReport, error) {
	stages := []string{"tool", "llm", "http", "db", "k8s", "docker", "ssh", "chains"}
	stageReports := make([]StageReport, 0, len(stages))
	var allLats []float64
	var totalAllow, totalDeny, totalFlaky, totalEscapes int64
	var totalSamples int64

	globalStart := time.Now()

	for _, stage := range stages {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		rep, lats, err := rn.runStage(ctx, stage)
		if err != nil {
			return nil, fmt.Errorf("run stage %s: %w", stage, err)
		}

		stageReports = append(stageReports, rep)
		allLats = append(allLats, lats...)
		totalAllow += rep.HitsAllow
		totalDeny += rep.HitsDeny
		totalFlaky += rep.Flaky
		totalEscapes += rep.Escapes
		totalSamples += rep.Samples
	}

	totalDur := time.Since(globalStart)
	sort.Float64s(allLats)

	overallTPS := 0.0
	if totalDur.Seconds() > 0 {
		overallTPS = float64(totalSamples) / totalDur.Seconds()
	}

	totalRep := StageReport{
		Stage:     "TOTAL",
		Samples:   totalSamples,
		Duration:  totalDur.String(),
		TPS:       overallTPS,
		P50MS:     Percentile(allLats, 0.50),
		P99MS:     Percentile(allLats, 0.99),
		HitsAllow: totalAllow,
		HitsDeny:  totalDeny,
		Flaky:     totalFlaky,
		Escapes:   totalEscapes,
		PUB99:     ComputePUB99(totalSamples, totalEscapes),
	}

	// Print terminal output table
	PrintTerminalTable(stageReports, totalRep)

	// Build coverage matrix
	rn.hitsMu.Lock()
	matrix, dead := BuildCoverageMatrix(rn.ruleHits, totalSamples)
	rn.hitsMu.Unlock()

	stagesMap := make(map[string]StageReport, len(stageReports))
	for _, sr := range stageReports {
		stagesMap[sr.Stage] = sr
	}

	rep := &MonteCarloReport{
		Version:        "1.0.0",
		GeneratedAt:    time.Now().UTC(),
		MasterSeed:     rn.cfg.MasterSeed,
		TotalSamples:   totalSamples,
		TotalDuration:  totalDur.String(),
		OverallTPS:     overallTPS,
		OverallP50MS:   totalRep.P50MS,
		OverallP99MS:   totalRep.P99MS,
		TotalAllow:     totalAllow,
		TotalDeny:      totalDeny,
		TotalFlaky:     totalFlaky,
		TotalEscapes:   totalEscapes,
		OverallPUB99:   totalRep.PUB99,
		Stages:         stagesMap,
		CoverageMatrix: matrix,
		DeadRules:      dead,
		FlakyRecords:   rn.flaky.Records(),
		Escapes:        rn.oracle.Escapes(),
	}

	return rep, nil
}

func (rn *Runner) runStage(ctx context.Context, stage string) (StageReport, []float64, error) {
	stageID := StageNameToID[stage]
	nSamples := rn.cfg.NPerStage
	if stage == "chains" {
		// Double samples for 2-tool chains or max(N, len(chains)*20)
		nSamples = rn.cfg.NPerStage * 2
	}

	var allowCnt, denyCnt, flakyCnt, escapeCnt int64
	var latsMu sync.Mutex
	lats := make([]float64, 0, nSamples)

	start := time.Now()
	conc := rn.cfg.Concurrency
	if conc < 1 {
		conc = 16
	}

	// Work distribution across workers
	tasks := make(chan uint64, conc*4)
	var wg sync.WaitGroup

	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range tasks {
				select {
				case <-ctx.Done():
					return
				default:
				}

				r := NewSampleRand(rn.cfg.MasterSeed, stageID, idx)

				if stage == "chains" {
					// Run oracle chains
					chainIdx := int(idx % uint64(len(rn.space.OracleChains))) //nolint:gosec // G115 modulo bounded by slice length
					chain := rn.space.OracleChains[chainIdx]

					t0 := time.Now()
					escs, stepAllows, stepDenies, err := rn.oracle.RunChain(ctx, chain, rn.cfg.MasterSeed, idx)
					el := time.Since(t0).Seconds() * 1000

					latsMu.Lock()
					lats = append(lats, el)
					latsMu.Unlock()

					if err == nil {
						if len(escs) > 0 {
							atomic.AddInt64(&escapeCnt, int64(len(escs)))
						}
						atomic.AddInt64(&allowCnt, int64(stepAllows))
						atomic.AddInt64(&denyCnt, int64(stepDenies))
					}
					continue
				}

				// Normal Stage Request
				payload := rn.sampler.SampleStageRequest(stage, r, idx)
				rawBytes, err := json.Marshal(payload)
				if err != nil {
					continue
				}

				// Execute decide request
				t0 := time.Now()
				resp, err := rn.sendDecide(ctx, rawBytes)
				el := time.Since(t0).Seconds() * 1000

				latsMu.Lock()
				lats = append(lats, el)
				latsMu.Unlock()

				if err != nil {
					continue
				}

				if resp.Decision == "allow" {
					atomic.AddInt64(&allowCnt, 1)
				} else {
					atomic.AddInt64(&denyCnt, 1)
				}

				// Record rule family hit
				fam := mapRuleToFamily(resp.RuleID)
				rn.hitsMu.Lock()
				rn.ruleHits[fam]++
				rn.ruleHits["authz"]++ // Every evaluated request passes authz
				rn.hitsMu.Unlock()

				// Flaky Layer 1: Idempotency Burst for every 50th sample
				if idx%50 == 0 {
					flBefore := len(rn.flaky.Records())
					_ = rn.flaky.CheckIdempotencyBurst(ctx, stage, idx, rawBytes)
					if len(rn.flaky.Records()) > flBefore {
						atomic.AddInt64(&flakyCnt, 1)
					}
				}

				// Flaky Layer 2: Canonical JSON permutation
				if idx%100 == 0 {
					flBefore := len(rn.flaky.Records())
					_ = rn.flaky.CheckCanonicalJSONPermutation(ctx, stage, idx, payload)
					if len(rn.flaky.Records()) > flBefore {
						atomic.AddInt64(&flakyCnt, 1)
					}
				}

				// Flaky Layer 3: Cache vs Explain Diff (sample 5%)
				if rn.cfg.ExplainSample > 0 {
					flBefore := len(rn.flaky.Records())
					_ = rn.flaky.CheckExplainDiff(ctx, stage, idx, rawBytes, r)
					if len(rn.flaky.Records()) > flBefore {
						atomic.AddInt64(&flakyCnt, 1)
					}
				}
			}
		}()
	}

	// Dispatch tasks
	limit := uint64(0)
	if nSamples > 0 {
		limit = uint64(nSamples)
	}
	for i := uint64(0); i < limit; i++ {
		tasks <- i
	}
	close(tasks)
	wg.Wait()

	dur := time.Since(start)
	sort.Float64s(lats)

	tps := 0.0
	if dur.Seconds() > 0 {
		tps = float64(len(lats)) / dur.Seconds()
	}

	report := StageReport{
		Stage:     stage,
		Samples:   int64(len(lats)),
		Duration:  dur.String(),
		TPS:       tps,
		P50MS:     Percentile(lats, 0.50),
		P99MS:     Percentile(lats, 0.99),
		HitsAllow: allowCnt,
		HitsDeny:  denyCnt,
		Flaky:     flakyCnt,
		Escapes:   escapeCnt,
		PUB99:     ComputePUB99(int64(len(lats)), escapeCnt),
	}

	return report, lats, nil
}

func (rn *Runner) sendDecide(ctx context.Context, body []byte) (*DecisionResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rn.cfg.DecideURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if rn.cfg.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+rn.cfg.AdminToken)
	}

	resp, err := rn.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var d DecisionResponse
	if err := json.Unmarshal(respBody, &d); err != nil {
		return &DecisionResponse{
			Decision: "deny",
			RuleID:   fmt.Sprintf("http_%d", resp.StatusCode),
			Reason:   string(respBody),
		}, nil
	}

	return &d, nil
}

func mapRuleToFamily(ruleID string) string {
	if ruleID == "" {
		return "unknown"
	}
	parts := strings.Split(ruleID, ".")
	if len(parts) >= 2 {
		if parts[0] == "shield" && len(parts) >= 2 {
			return parts[0] + "." + parts[1] // shield.prod, shield.cmd, shield.container
		}
		if parts[0] == "ai" && len(parts) >= 2 {
			return parts[0] + "." + parts[1] // ai.llm, ai.tool
		}
		return parts[0] // authz, http, docker, ssh, db, k8s, chain, shellguard, ops
	}
	return ruleID
}
