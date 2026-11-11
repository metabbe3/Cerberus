package engine

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	dto "github.com/prometheus/client_model/go"
)

// Engine metrics, registered once on prometheus.DefaultRegisterer at package
// init so multiple Engines never double-register.
var (
	decisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "cerberus_decisions_total",
		Help: "Decision outcomes by stage, decision, and rule_id.",
	}, []string{"stage", "decision", "rule_id"})

	cacheHitsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cerberus_cache_hits_total",
		Help: "Decisions that skipped a fresh eval (LRU hit or shared flight).",
	})

	cacheMissesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cerberus_cache_misses_total",
		Help: "Decisions that required a policy eval (after singleflight).",
	})

	evalDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "cerberus_eval_duration_seconds",
		Help:    "OPA eval duration per decision (cache misses only).",
		Buckets: []float64{0.000025, 0.000050, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01},
	})

	evalTimeoutsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cerberus_eval_timeouts_total",
		Help: "Evals that exceeded the eval timeout and were denied fail-closed.",
	})

	policyEpoch = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cerberus_policy_epoch",
		Help: "Epoch of the currently live policy snapshot.",
	})
)

// EngineStats returns the current cache hits and misses totals from metrics.
func EngineStats() (hits uint64, misses uint64) {
	var m1 dto.Metric
	if err := cacheHitsTotal.Write(&m1); err == nil && m1.Counter != nil {
		hits = uint64(m1.Counter.GetValue())
	}
	var m2 dto.Metric
	if err := cacheMissesTotal.Write(&m2); err == nil && m2.Counter != nil {
		misses = uint64(m2.Counter.GetValue())
	}
	return hits, misses
}
