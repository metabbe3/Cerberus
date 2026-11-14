package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/metabbe3/cerberus/internal/policy"
)

type mockAuditCounter struct {
	counts map[string]int64
}

func (m *mockAuditCounter) DailyToolCallsCount(_ context.Context, keyID string, _ time.Time) (int64, error) {
	return m.counts[keyID], nil
}

func TestLimiter_RequestsPerMinuteAndBurst(t *testing.T) {
	data := map[string]any{
		"agents": map[string]any{
			"k-test": map[string]any{
				"rate_limit": map[string]any{
					"requests_per_minute": 60,
					"bursts":              2,
				},
			},
		},
	}

	snap := &policy.Snapshot{
		Epoch: 1,
		Data:  data,
	}

	store := policy.NewStoreWithSnapshot(snap)

	lim := NewLimiter(store, nil)
	ctx := context.Background()

	// First 2 requests (burst) should be allowed
	v1 := lim.Allow(ctx, "k-test", "llm")
	if !v1.Allowed {
		t.Fatalf("first request should be allowed: %v", v1.Reason)
	}

	v2 := lim.Allow(ctx, "k-test", "llm")
	if !v2.Allowed {
		t.Fatalf("second request should be allowed: %v", v2.Reason)
	}

	// Third request immediately after should be denied (burst consumed)
	v3 := lim.Allow(ctx, "k-test", "llm")
	if v3.Allowed {
		t.Fatalf("third request should be denied (burst exceeded)")
	}
	if v3.RuleID != "ops.rate_limited" {
		t.Errorf("expected rule_id ops.rate_limited, got %s", v3.RuleID)
	}
	if v3.RetryAfter < 1 {
		t.Errorf("expected RetryAfter >= 1, got %d", v3.RetryAfter)
	}

	// Unknown key or unconstrained agent should always pass
	vUnk := lim.Allow(ctx, "k-other", "llm")
	if !vUnk.Allowed {
		t.Errorf("unconstrained agent should be allowed")
	}
}

func TestLimiter_ToolCallsPerHour(t *testing.T) {
	data := map[string]any{
		"agents": map[string]any{
			"k-tool": map[string]any{
				"rate_limit": map[string]any{
					"tool_calls_per_hour": 1,
					"bursts":              1,
				},
			},
		},
	}

	snap := &policy.Snapshot{
		Epoch: 1,
		Data:  data,
	}

	store := policy.NewStoreWithSnapshot(snap)

	lim := NewLimiter(store, nil)
	ctx := context.Background()

	// First tool call allowed
	v1 := lim.Allow(ctx, "k-tool", "tool")
	if !v1.Allowed {
		t.Fatalf("first tool call should be allowed")
	}

	// Second tool call denied
	v2 := lim.Allow(ctx, "k-tool", "tool")
	if v2.Allowed {
		t.Fatalf("second tool call should be denied")
	}
	if v2.RuleID != "ops.rate_limited" {
		t.Errorf("expected ops.rate_limited, got %s", v2.RuleID)
	}
}

func TestLimiter_DailyToolQuotaAndAlert(t *testing.T) {
	data := map[string]any{
		"agents": map[string]any{
			"k-quota": map[string]any{
				"rate_limit": map[string]any{
					"daily_tool_calls": 3,
				},
			},
		},
	}

	snap := &policy.Snapshot{
		Epoch: 1,
		Data:  data,
	}

	store := policy.NewStoreWithSnapshot(snap)

	mockAudit := &mockAuditCounter{
		counts: map[string]int64{
			"k-quota": 2, // Already did 2 today
		},
	}

	lim := NewLimiter(store, mockAudit)
	ctx := context.Background()

	// Call 1 today (total now 3) -> allowed (last remaining)
	v1 := lim.Allow(ctx, "k-quota", "tool")
	if !v1.Allowed {
		t.Fatalf("3rd tool call should be allowed (limit is 3): %v", v1.Reason)
	}

	// Call 2 today (total 4 > 3) -> hard stop
	v2 := lim.Allow(ctx, "k-quota", "tool")
	if v2.Allowed {
		t.Fatalf("4th tool call should be hard stopped")
	}
	if v2.RuleID != "ops.rate_limited" {
		t.Errorf("expected ops.rate_limited, got %s", v2.RuleID)
	}
	if v2.RetryAfter <= 0 {
		t.Errorf("expected positive RetryAfter, got %d", v2.RetryAfter)
	}
}

func TestLimiter_ResetOnEpoch(t *testing.T) {
	data := map[string]any{
		"agents": map[string]any{
			"k-reset": map[string]any{
				"rate_limit": map[string]any{
					"requests_per_minute": 60,
					"bursts":              1,
				},
			},
		},
	}

	snap := &policy.Snapshot{
		Epoch: 1,
		Data:  data,
	}

	store := policy.NewStoreWithSnapshot(snap)

	lim := NewLimiter(store, nil)
	ctx := context.Background()

	// 1st allowed
	if !lim.Allow(ctx, "k-reset", "llm").Allowed {
		t.Fatalf("should allow 1st")
	}

	// 2nd denied
	if lim.Allow(ctx, "k-reset", "llm").Allowed {
		t.Fatalf("should deny 2nd")
	}

	// Reset epoch
	lim.Reset(2)

	// Now should be allowed again
	if !lim.Allow(ctx, "k-reset", "llm").Allowed {
		t.Fatalf("should allow after reset epoch")
	}
}

type errorThenSuccessAuditCounter struct {
	calls      atomic.Int32
	shouldFail atomic.Bool
	count      int64
}

func (m *errorThenSuccessAuditCounter) DailyToolCallsCount(_ context.Context, _ string, _ time.Time) (int64, error) {
	m.calls.Add(1)
	if m.shouldFail.Load() {
		return 0, errors.New("database connection refused")
	}
	return m.count, nil
}

func TestLimiter_DailyToolQuota_RetryOnError(t *testing.T) {
	data := map[string]any{
		"agents": map[string]any{
			"k-retry": map[string]any{
				"rate_limit": map[string]any{
					"daily_tool_calls": 3,
				},
			},
		},
	}

	snap := &policy.Snapshot{
		Epoch: 1,
		Data:  data,
	}

	store := policy.NewStoreWithSnapshot(snap)

	mockAudit := &errorThenSuccessAuditCounter{}
	mockAudit.shouldFail.Store(true)

	lim := NewLimiter(store, mockAudit)
	ctx := context.Background()

	// 1st call fails to query audit log, should not lock dailyChecked, allowed
	v1 := lim.Allow(ctx, "k-retry", "tool")
	if !v1.Allowed {
		t.Fatalf("first call should be allowed despite audit query failure: %v", v1.Reason)
	}
	if mockAudit.calls.Load() != 1 {
		t.Fatalf("expected 1 audit call, got %d", mockAudit.calls.Load())
	}

	// 2nd call: audit counter recovers and reports 3 calls already today
	mockAudit.shouldFail.Store(false)
	mockAudit.count = 3

	// Limiter must retry calling DailyToolCallsCount because it failed previously
	v2 := lim.Allow(ctx, "k-retry", "tool")
	if mockAudit.calls.Load() != 2 {
		t.Fatalf("expected 2 audit calls (retry occurred), got %d", mockAudit.calls.Load())
	}
	if v2.Allowed {
		t.Fatalf("second call should be denied (quota exhausted after retry retrieved count)")
	}

	// 3rd call: dailyChecked is now true, so DailyToolCallsCount should NOT be called again
	v3 := lim.Allow(ctx, "k-retry", "tool")
	if v3.Allowed {
		t.Fatalf("third call should be denied")
	}
	if mockAudit.calls.Load() != 2 {
		t.Fatalf("expected audit calls to remain 2 after successful check, got %d", mockAudit.calls.Load())
	}
}

func TestLimiter_UnkeyedIncrementsMetric(t *testing.T) {
	before := testutil.ToFloat64(RateLimitUnkeyedTotal)

	lim := NewLimiter(nil, nil)
	v := lim.Allow(context.Background(), "", "tool")
	if !v.Allowed {
		t.Fatal("empty keyID should be allowed")
	}

	after := testutil.ToFloat64(RateLimitUnkeyedTotal)
	if after != before+1 {
		t.Fatalf("expected RateLimitUnkeyedTotal to increment by 1, got before=%v, after=%v", before, after)
	}
}

type slowAuditCounter struct {
	delay time.Duration
	count int64
}

func (s *slowAuditCounter) DailyToolCallsCount(_ context.Context, _ string, _ time.Time) (int64, error) {
	time.Sleep(s.delay)
	return s.count, nil
}

func TestLimiter_ConcurrentAllow_NoDeadlockWithSlowAudit(t *testing.T) {
	data := map[string]any{
		"agents": map[string]any{
			"k-conc": map[string]any{
				"rate_limit": map[string]any{
					"daily_tool_calls":    100,
					"requests_per_minute": 1000,
					"bursts":              1000,
				},
			},
		},
	}
	snap := &policy.Snapshot{Epoch: 1, Data: data}
	store := policy.NewStoreWithSnapshot(snap)

	slowAudit := &slowAuditCounter{
		delay: 100 * time.Millisecond,
		count: 5,
	}

	lim := NewLimiter(store, slowAudit)
	ctx := context.Background()

	const numGoroutines = 50
	var wg sync.WaitGroup
	errCh := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := lim.Allow(ctx, "k-conc", "tool")
			if !v.Allowed {
				errCh <- fmt.Errorf("unexpected deny: %s", v.Reason)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(3 * time.Second):
		t.Fatal("deadlock or timeout: 50 concurrent Allow calls did not finish within 3s")
	}

	close(errCh)
	for err := range errCh {
		t.Errorf("error in concurrent Allow: %v", err)
	}
}

func TestLimiter_New_OnSwapLifecycle(t *testing.T) {
	snap := &policy.Snapshot{Epoch: 1}
	store := policy.NewStoreWithSnapshot(snap)
	initial := store.SwapCallbacksLen()

	for i := 0; i < 100; i++ {
		lim := NewLimiter(store, nil)
		lim.Close()
	}

	if store.SwapCallbacksLen() != initial {
		t.Fatalf("expected callbacks len %d, got %d", initial, store.SwapCallbacksLen())
	}
}
