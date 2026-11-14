// Command cerberus-montecarlo is the Layer 3 statistical policy coverage harness for Cerberus.
// It performs reproducible Monte Carlo sampling across 7 policy stages and 2-tool chaining attacks,
// with 3-layer flaky policy detection and binomial escape-rate bounds.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	flagURL           = flag.String("url", "http://127.0.0.1:18089/v1/decide", "Cerberus engine /v1/decide endpoint")
	flagToken         = flag.String("token", "", "Admin bearer token (or set CERBERUS_ADMIN_TOKEN)")
	flagSpace         = flag.String("space", "cmd/cerberus-montecarlo/scenario-space.json", "Path to scenario-space.json specification")
	flagSeed          = flag.Uint64("seed", 20261114, "Master random seed for deterministic PRNG")
	flagNPerStage     = flag.Int("n-per-stage", 5000, "Number of samples per stage (confidence >= 99% requires >= 4606)")
	flagOut           = flag.String("out", "mc-report.json", "Output JSON report path")
	flagExplainSample = flag.Float64("explain-sample", 0.05, "Fraction of samples to cross-verify against /v1/decide?explain=true")
	flagConcurrency   = flag.Int("concurrency", 16, "Number of concurrent worker goroutines")
	flagTimeout       = flag.Duration("timeout", 10*time.Second, "HTTP request timeout")

	// Compatibility flags with loadgen-stress
	_ = flag.Int("levels", 4, "Concurrency levels (loadgen compatibility)")
	_ = flag.Int("start", 4, "Starting concurrency (loadgen compatibility)")
	_ = flag.Duration("dur", 15*time.Second, "Duration per level (loadgen compatibility)")
)

func main() {
	if code := run(); code != 0 {
		os.Exit(code)
	}
}

func run() int {
	flag.Parse()

	tok := *flagToken
	if tok == "" {
		tok = os.Getenv("CERBERUS_ADMIN_TOKEN")
	}

	space, err := LoadScenarioSpace(*flagSpace)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load scenario space: %v\n", err)
		return 1
	}

	cfg := RunnerConfig{
		DecideURL:     *flagURL,
		AdminToken:    tok,
		SpacePath:     *flagSpace,
		MasterSeed:    *flagSeed,
		NPerStage:     *flagNPerStage,
		OutPath:       *flagOut,
		ExplainSample: *flagExplainSample,
		Concurrency:   *flagConcurrency,
		Timeout:       *flagTimeout,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	runner := NewRunner(cfg, space)
	fmt.Printf("Starting Cerberus Monte Carlo harness [master_seed=%d, n_per_stage=%d, concurrency=%d] -> %s\n",
		cfg.MasterSeed, cfg.NPerStage, cfg.Concurrency, cfg.DecideURL)

	rep, err := runner.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "monte carlo harness execution failed: %v\n", err)
		return 1
	}

	if err := WriteReportJSON(*flagOut, rep); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write report JSON to %s: %v\n", *flagOut, err)
		return 1
	}
	fmt.Printf("\nReport written to: %s\n", *flagOut)

	// Release Gate check (Argon §3):
	// "Jika ada k>0 escape, tolak rilis (target k=0)."
	if rep.TotalEscapes > 0 {
		fmt.Printf("\n[FAIL] RELEASE REJECTED: %d policy escape(s) detected! Check %s escapes[] for repro_curl\n",
			rep.TotalEscapes, *flagOut)
		return 1
	}

	if rep.TotalFlaky > 0 {
		fmt.Printf("\n[WARN] %d flaky verdict(s) detected! Check %s flaky_records[]\n",
			rep.TotalFlaky, *flagOut)
	}

	fmt.Printf("\n[PASS] MONTE CARLO COVERAGE VERIFIED: 0 escapes detected (p_ub99 = %.6f)\n", rep.OverallPUB99)
	return 0
}
