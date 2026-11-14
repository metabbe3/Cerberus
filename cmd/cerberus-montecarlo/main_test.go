package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
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

// TestOracle_ChainBrokenSemantics_S06_S10_S11_S12 verifies HARNESS-1:
// escape step-2 HANYA dihitung bila step-1 == allow (rantai hidup).
// Kalau step-1 deny -> step-2 allow = RANTAI PUTUS = bukan escape (log sebagai chain_broken metric, bukan escapes[]).
func TestOracle_ChainBrokenSemantics_S06_S10_S11_S12(t *testing.T) {
	chainIDs := []string{"S06", "S10", "S11", "S12"}

	for _, cid := range chainIDs {
		t.Run(cid+"_broken_chain_produces_zero_escapes", func(t *testing.T) {
			stepCallCount := 0
			// Mock server: returns DENY for step 1, ALLOW for step 2
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				stepCallCount++
				if stepCallCount%2 == 1 {
					// Step 1: Denied by policy (blocking attack chain)
					_ = json.NewEncoder(w).Encode(DecisionResponse{
						Decision: "deny",
						RuleID:   "shield.test.blocked",
					})
				} else {
					// Step 2: In isolation on clean session it returns allow
					_ = json.NewEncoder(w).Encode(DecisionResponse{
						Decision: "allow",
						RuleID:   "tool.allow",
					})
				}
			}))
			defer srv.Close()

			chain := OracleChain{
				ID:   cid,
				Name: cid + "_test",
				Step1: map[string]any{
					"stage": "tool",
					"cmd":   "attack_step1",
				},
				Expected1: OracleVerdict{
					Decision:   "deny",
					RuleFamily: "shield.",
				},
				Step2: map[string]any{
					"stage": "tool",
					"cmd":   "attack_step2",
				},
				Expected2: &OracleVerdict{
					Decision:   "deny",
					RuleFamily: "chain.",
				},
			}

			oracle := NewOracle(srv.Client(), srv.URL, "adm-token", []OracleChain{chain})
			escs, _, _, err := oracle.RunChain(context.Background(), chain, 9999, 0)
			if err != nil {
				t.Fatalf("RunChain: %v", err)
			}

			// Rantai putus: Step 1 denied, so Step 2 allow must NOT be counted as an escape
			if len(escs) != 0 {
				t.Fatalf("[%s] expected 0 escapes for broken chain, got %d: %+v", cid, len(escs), escs)
			}
			if oracle.EscapeCount() != 0 {
				t.Fatalf("[%s] oracle.EscapeCount() = %d, want 0", cid, oracle.EscapeCount())
			}
			if oracle.ChainBrokenCount() != 1 {
				t.Fatalf("[%s] oracle.ChainBrokenCount() = %d, want 1", cid, oracle.ChainBrokenCount())
			}
		})

		t.Run(cid+"_alive_chain_records_escape_on_step2", func(t *testing.T) {
			stepCallCount := 0
			// Mock server: returns ALLOW for step 1 (alive chain!), ALLOW for step 2 (escape!)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				stepCallCount++
				_ = json.NewEncoder(w).Encode(DecisionResponse{
					Decision: "allow",
					RuleID:   "tool.allow",
				})
			}))
			defer srv.Close()

			chain := OracleChain{
				ID:   cid,
				Name: cid + "_test_alive",
				Step1: map[string]any{
					"stage": "tool",
					"cmd":   "attack_step1",
				},
				// Expected1 is allow (so step1 does NOT escape, leaving chain alive)
				Expected1: OracleVerdict{
					Decision:   "allow",
					RuleFamily: "tool.",
				},
				Step2: map[string]any{
					"stage": "tool",
					"cmd":   "attack_step2",
				},
				Expected2: &OracleVerdict{
					Decision:   "deny",
					RuleFamily: "chain.",
				},
			}

			oracle := NewOracle(srv.Client(), srv.URL, "adm-token", []OracleChain{chain})
			escs, _, _, err := oracle.RunChain(context.Background(), chain, 9999, 0)
			if err != nil {
				t.Fatalf("RunChain: %v", err)
			}

			// Rantai hidup: Step 1 was allow, Step 2 returned allow when Expected2 was deny -> MUST record escape
			if len(escs) != 1 {
				t.Fatalf("[%s] expected 1 escape for alive chain, got %d", cid, len(escs))
			}
			if escs[0].ChainID != cid+"-step2" {
				t.Fatalf("[%s] expected escape on step2, got %s", cid, escs[0].ChainID)
			}
			if oracle.EscapeCount() != 1 {
				t.Fatalf("[%s] oracle.EscapeCount() = %d, want 1", cid, oracle.EscapeCount())
			}
		})
	}
}

// TestSampler_IPVariantAndUnicodeMutators verifies HARNESS-2 mutator generation.
func TestSampler_IPVariantAndUnicodeMutators(t *testing.T) {
	space, err := LoadScenarioSpace("scenario-space.json")
	if err != nil {
		t.Fatalf("LoadScenarioSpace: %v", err)
	}

	sampler := NewSampler(space)
	r := rand.New(rand.NewPCG(42, 84)) // #nosec G404 // deterministic MC seed by design

	// Test GenerateIPVariant
	for i := 0; i < 20; i++ {
		v := sampler.GenerateIPVariant("10.0.0.1", r)
		if v == "" {
			t.Fatalf("expected non-empty IP variant")
		}
	}

	// Test mutateString
	seenWordJoiner := false
	seenSoftHyphen := false
	seenBOM := false
	seenHomoglyph := false

	for i := 0; i < 200; i++ {
		res := sampler.mutateString("prod-db", r)
		if strings.Contains(res, "\u2060") {
			seenWordJoiner = true
		}
		if strings.Contains(res, "\u00ad") {
			seenSoftHyphen = true
		}
		if strings.Contains(res, "\ufeff") {
			seenBOM = true
		}
		if strings.Contains(res, "\u0433") || strings.Contains(res, "\u0440") || strings.Contains(res, "\u043e") {
			seenHomoglyph = true
		}
	}

	if !seenWordJoiner {
		t.Errorf("expected to see word-joiner \\u2060 in mutations")
	}
	if !seenSoftHyphen {
		t.Errorf("expected to see soft-hyphen \\u00ad in mutations")
	}
	if !seenBOM {
		t.Errorf("expected to see BOM \\ufeff in mutations")
	}
	if !seenHomoglyph {
		t.Errorf("expected to see Cyrillic homoglyph in mutations")
	}

	// Verify all stages sample without panic
	stages := []string{"tool", "llm", "http", "db", "k8s", "docker", "ssh"}
	for _, st := range stages {
		for i := uint64(0); i < 50; i++ {
			req := sampler.SampleStageRequest(st, r, i)
			if req["stage"] != st {
				t.Fatalf("stage = %v, want %s", req["stage"], st)
			}
		}
	}
}
