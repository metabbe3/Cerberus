package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestDeterministicGoldenVerdicts verifies regression determinism across 20 fixed seed samples.
func TestDeterministicGoldenVerdicts(t *testing.T) {
	spacePath := filepath.Join(".", "scenario-space.json")
	space, err := LoadScenarioSpace(spacePath)
	if err != nil {
		t.Fatalf("LoadScenarioSpace: %v", err)
	}

	sampler := NewSampler(space)
	const masterSeed = uint64(20261114)

	// Collect SHA-256 hashes for 20 fixed-seed samples across stages
	hashes := make([]string, 20)
	stages := []string{"tool", "llm", "http", "db", "k8s", "docker", "ssh"}

	for i := uint64(0); i < 20; i++ {
		stage := stages[i%uint64(len(stages))]
		stageID := StageNameToID[stage]
		r := NewSampleRand(masterSeed, stageID, i)

		payload := sampler.SampleStageRequest(stage, r, i)
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("sample %d marshal failed: %v", i, err)
		}
		h := sha256.Sum256(b)
		hashes[i] = hex.EncodeToString(h[:])
	}

	// Repeat generation in parallel to verify concurrency does not alter deterministic output
	t.Run("ConcurrentReproducibility", func(t *testing.T) {
		t.Parallel()
		for i := uint64(0); i < 20; i++ {
			stage := stages[i%uint64(len(stages))]
			stageID := StageNameToID[stage]
			r := NewSampleRand(masterSeed, stageID, i)

			payload := sampler.SampleStageRequest(stage, r, i)
			b, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("sample %d marshal failed: %v", i, err)
			}
			h := sha256.Sum256(b)
			gotHash := hex.EncodeToString(h[:])

			if gotHash != hashes[i] {
				t.Fatalf("deterministic mismatch at sample %d: got %s, want %s", i, gotHash, hashes[i])
			}
		}
	})
}

// TestDummyEngineHarness executes the full Monte Carlo runner against an httptest dummy engine.
func TestDummyEngineHarness(t *testing.T) {
	var decideCount int64

	// Mock Cerberus engine
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&decideCount, 1)

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		stage, _ := in["stage"].(string)
		isExplain := r.URL.Query().Get("explain") == "true"

		// Deterministic response based on stage
		decision := "allow"
		ruleID := stage + ".allow"
		reason := "allowed by policy"

		// For chains or adversarial commands, deny
		if stage == "chains" || stage == "docker" || stage == "db" {
			decision = "deny"
			ruleID = stage + ".sensitive_operation"
			reason = "blocked by security policy"
		}

		resp := DecisionResponse{
			Decision: decision,
			RuleID:   ruleID,
			Reason:   reason,
			Epoch:    1,
			Cached:   !isExplain,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	spacePath := filepath.Join(".", "scenario-space.json")
	space, err := LoadScenarioSpace(spacePath)
	if err != nil {
		t.Fatalf("LoadScenarioSpace: %v", err)
	}

	tmpOut := filepath.Join(t.TempDir(), "test-mc-report.json")
	cfg := RunnerConfig{
		DecideURL:     srv.URL,
		AdminToken:    "test-token",
		SpacePath:     spacePath,
		MasterSeed:    42,
		NPerStage:     25, // Quick run for test
		OutPath:       tmpOut,
		ExplainSample: 0.10,
		Concurrency:   4,
		Timeout:       5 * time.Second,
	}

	runner := NewRunner(cfg, space)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rep, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("runner.Run: %v", err)
	}

	if rep.TotalSamples == 0 {
		t.Fatalf("expected >0 total samples, got 0")
	}

	if err := WriteReportJSON(tmpOut, rep); err != nil {
		t.Fatalf("WriteReportJSON: %v", err)
	}

	// Verify report file was written and can be read back
	data, err := os.ReadFile(filepath.Clean(tmpOut))
	if err != nil {
		t.Fatalf("read written report: %v", err)
	}
	var loaded MonteCarloReport
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal written report: %v", err)
	}

	if loaded.TotalSamples != rep.TotalSamples {
		t.Fatalf("loaded samples mismatch: %d != %d", loaded.TotalSamples, rep.TotalSamples)
	}
}

// TestFlakyDetector verifies detection of non-deterministic verdicts.
func TestFlakyDetector(t *testing.T) {
	var callCount int64

	// Mock server that returns divergent verdicts
	flakySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		cnt := atomic.AddInt64(&callCount, 1)
		decision := "allow"
		ruleID := "test.allow"
		if cnt%2 == 0 {
			decision = "deny"
			ruleID = "test.deny"
		}
		_ = json.NewEncoder(w).Encode(DecisionResponse{
			Decision: decision,
			RuleID:   ruleID,
			Reason:   "flaky test simulation",
		})
	}))
	defer flakySrv.Close()

	detector := NewFlakyDetector(flakySrv.Client(), flakySrv.URL, "tok", 1.0)
	payload := []byte(`{"stage":"tool","key_id":"k-open"}`)

	ctx := context.Background()
	_ = detector.CheckIdempotencyBurst(ctx, "tool", 50, payload)

	recs := detector.Records()
	if len(recs) == 0 {
		t.Fatal("expected flaky records from alternating server, got 0")
	}
	if recs[0].Type != FlakyTypeIdempotencyBurst {
		t.Fatalf("expected FlakyTypeIdempotencyBurst, got %s", recs[0].Type)
	}
}

// TestComputePUB99 tests exact binomial upper bound math.
func TestComputePUB99(t *testing.T) {
	// Zero failures: N=5000, k=0 -> 1 - 0.01^(1/5000) ~ 0.0009197
	ub0 := ComputePUB99(5000, 0)
	if ub0 <= 0 || ub0 > 0.001 {
		t.Fatalf("expected PUB99 for N=5000, k=0 < 0.001, got %.6f", ub0)
	}

	// N=45000, k=0 -> ~ 0.000102
	ubTotal := ComputePUB99(45000, 0)
	if ubTotal <= 0 || ubTotal > 0.0002 {
		t.Fatalf("expected PUB99 for N=45000, k=0 < 0.0002, got %.6f", ubTotal)
	}

	// Failures: N=5000, k=5 -> should be > 0.001
	ub5 := ComputePUB99(5000, 5)
	if ub5 <= ub0 {
		t.Fatalf("expected PUB99 for k=5 (%.6f) > k=0 (%.6f)", ub5, ub0)
	}
}

// TestOracleEscape verifies escape detection and repro_curl generation.
func TestOracleEscape(t *testing.T) {
	// Mock server that returns allow for a sensitive action
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(DecisionResponse{
			Decision: "allow",
			RuleID:   "test.bypass_open",
			Reason:   "unexpected allow",
		})
	}))
	defer srv.Close()

	chain := OracleChain{
		ID:   "TEST-01",
		Name: "test_escape",
		Step1: map[string]any{
			"stage":  "http",
			"action": "GET",
		},
		Expected1: OracleVerdict{
			Decision:   "deny",
			RuleFamily: "shield.prod.",
		},
	}

	oracle := NewOracle(srv.Client(), srv.URL, "adm-token", []OracleChain{chain})
	escs, _, _, err := oracle.RunChain(context.Background(), chain, 1234, 0)
	if err != nil {
		t.Fatalf("RunChain: %v", err)
	}

	if len(escs) != 1 {
		t.Fatalf("expected 1 escape recorded, got %d", len(escs))
	}
	if escs[0].ActualDecision != "allow" {
		t.Fatalf("expected actual decision 'allow', got %s", escs[0].ActualDecision)
	}
	if !strings.Contains(escs[0].ReproCurl, "curl -s -X POST") {
		t.Fatalf("invalid repro_curl: %s", escs[0].ReproCurl)
	}
}
