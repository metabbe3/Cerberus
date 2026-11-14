package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestLatencyStatsAndFailClosed(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(context.Background(), filepath.Join(dir, "audit.db"), Options{})
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	ctx := context.Background()
	now := time.Now()

	// Emit events with various latencies and rule IDs
	l.Emit(Event{
		Time:      now.Add(-10 * time.Minute),
		Stage:     "tool",
		KeyID:     "k-1",
		Decision:  "allow",
		RuleID:    "tools.allowed",
		LatencyUS: 1000,
	})
	l.Emit(Event{
		Time:      now.Add(-8 * time.Minute),
		Stage:     "tool",
		KeyID:     "k-2",
		Decision:  "allow",
		RuleID:    "tools.allowed",
		LatencyUS: 3000,
	})
	l.Emit(Event{
		Time:      now.Add(-5 * time.Minute),
		Stage:     "tool",
		KeyID:     "k-3",
		Decision:  "deny",
		RuleID:    "internal.timeout",
		LatencyUS: 10000,
	})
	l.Emit(Event{
		Time:      now.Add(-2 * time.Minute),
		Stage:     "tool",
		KeyID:     "k-4",
		Decision:  "deny",
		RuleID:    "internal.eval_error",
		LatencyUS: 5000,
	})

	// Wait for queue flush to SQLite
	time.Sleep(300 * time.Millisecond)

	stats, err := l.LatencyStats(ctx, now.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("LatencyStats failed: %v", err)
	}

	if stats.FailClosedCount != 2 {
		t.Errorf("expected 2 fail closed events, got %d", stats.FailClosedCount)
	}
	if stats.FailClosedRate != 0.5 {
		t.Errorf("expected fail closed rate 0.5, got %f", stats.FailClosedRate)
	}
	if stats.P50US == 0 {
		t.Errorf("expected non-zero p50 latency, got %f", stats.P50US)
	}
	if stats.P99US < stats.P50US {
		t.Errorf("expected p99 >= p50, got p99=%f, p50=%f", stats.P99US, stats.P50US)
	}
}
