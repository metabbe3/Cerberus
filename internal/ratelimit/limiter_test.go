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

func (m *mockAuditCounter) DailyTeamCallsCount(_ context.Context, teamKeys []string, _ time.Time) (int64, error) {
	var total int64
	for _, k := range teamKeys {
		total += m.counts[k]
	}
	return total, nil
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

func (m *errorThenSuccessAuditCounter) DailyTeamCallsCount(_ context.Context, _ []string, _ time.Time) (int64, error) {
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

func (s *slowAuditCounter) DailyTeamCallsCount(_ context.Context, _ []string, _ time.Time) (int64, error) {
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

func TestLimiter_TeamQuota_TwoKeysOneTeam_BothBlocked(t *testing.T) {
	data := map[string]any{
		"agents": map[string]any{
			"k-alpha": map[string]any{
				"team_id": "team-eng",
				"rate_limit": map[string]any{
					"requests_per_minute": 120,
					"bursts":              10,
				},
			},
			"k-beta": map[string]any{
				"team_id": "team-eng",
				"rate_limit": map[string]any{
					"requests_per_minute": 120,
					"bursts":              10,
				},
			},
		},
		"teams": map[string]any{
			"team-eng": map[string]any{
				"name": "Engineering",
				"quota": map[string]any{
					"requests_per_minute": 60,
					"bursts":              4,
				},
			},
		},
	}

	snap := &policy.Snapshot{Epoch: 1, Data: data}
	store := policy.NewStoreWithSnapshot(snap)
	lim := NewLimiter(store, nil)
	defer lim.Close()

	ctx := context.Background()

	// 2 calls from k-alpha
	for i := 0; i < 2; i++ {
		v := lim.Allow(ctx, "k-alpha", "http")
		if !v.Allowed {
			t.Fatalf("k-alpha call %d should be allowed: %v", i+1, v.Reason)
		}
	}

	// 2 calls from k-beta -> total team calls = 4 (burst limit reached)
	for i := 0; i < 2; i++ {
		v := lim.Allow(ctx, "k-beta", "http")
		if !v.Allowed {
			t.Fatalf("k-beta call %d should be allowed: %v", i+1, v.Reason)
		}
	}

	// 5th call from k-alpha must be blocked by team quota
	vAlpha := lim.Allow(ctx, "k-alpha", "http")
	if vAlpha.Allowed {
		t.Fatal("k-alpha 5th call should be blocked by team quota")
	}
	if vAlpha.RuleID != "ops.tenant_quota_exceeded" {
		t.Errorf("k-alpha RuleID = %q, want ops.tenant_quota_exceeded", vAlpha.RuleID)
	}

	// 5th call from k-beta must also be blocked by team quota
	vBeta := lim.Allow(ctx, "k-beta", "http")
	if vBeta.Allowed {
		t.Fatal("k-beta should also be blocked by team quota")
	}
	if vBeta.RuleID != "ops.tenant_quota_exceeded" {
		t.Errorf("k-beta RuleID = %q, want ops.tenant_quota_exceeded", vBeta.RuleID)
	}
}

func TestLimiter_TeamQuota_ConcurrentRace20Keys(t *testing.T) {
	agents := make(map[string]any)
	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("k-agent-%d", i)
		agents[key] = map[string]any{
			"team_id": "team-race",
			"rate_limit": map[string]any{
				"requests_per_minute": 600,
				"bursts":              100,
			},
		}
	}

	data := map[string]any{
		"agents": agents,
		"teams": map[string]any{
			"team-race": map[string]any{
				"quota": map[string]any{
					"requests_per_minute": 60,
					"bursts":              5,
				},
			},
		},
	}

	snap := &policy.Snapshot{Epoch: 1, Data: data}
	store := policy.NewStoreWithSnapshot(snap)
	lim := NewLimiter(store, nil)
	defer lim.Close()

	ctx := context.Background()
	var allowedCount atomic.Int64
	var blockedCount atomic.Int64

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(keyID string) {
			defer wg.Done()
			v := lim.Allow(ctx, keyID, "http")
			if v.Allowed {
				allowedCount.Add(1)
			} else if v.RuleID == "ops.tenant_quota_exceeded" {
				blockedCount.Add(1)
			}
		}(fmt.Sprintf("k-agent-%d", i))
	}
	wg.Wait()

	if allowed := allowedCount.Load(); allowed != 5 {
		t.Errorf("expected exactly 5 allowed requests (burst capacity), got %d", allowed)
	}
	if blocked := blockedCount.Load(); blocked != 15 {
		t.Errorf("expected exactly 15 blocked requests with ops.tenant_quota_exceeded, got %d", blocked)
	}
}

func TestLimiter_TeamQuota_DailyToolCalls(t *testing.T) {
	data := map[string]any{
		"agents": map[string]any{
			"k-tool-1": map[string]any{
				"team_id": "team-tools",
				"rate_limit": map[string]any{
					"daily_tool_calls": 100,
				},
			},
			"k-tool-2": map[string]any{
				"team_id": "team-tools",
				"rate_limit": map[string]any{
					"daily_tool_calls": 100,
				},
			},
		},
		"teams": map[string]any{
			"team-tools": map[string]any{
				"quota": map[string]any{
					"daily_tool_calls": 3,
				},
			},
		},
	}

	snap := &policy.Snapshot{Epoch: 1, Data: data}
	store := policy.NewStoreWithSnapshot(snap)
	mockAudit := &mockAuditCounter{counts: map[string]int64{}}
	lim := NewLimiter(store, mockAudit)
	defer lim.Close()

	ctx := context.Background()

	// k-tool-1 does 2 tool calls
	for i := 0; i < 2; i++ {
		v := lim.Allow(ctx, "k-tool-1", "tool")
		if !v.Allowed {
			t.Fatalf("k-tool-1 call %d should be allowed: %v", i+1, v.Reason)
		}
	}

	// k-tool-2 does 1 tool call -> reaches team limit of 3
	v := lim.Allow(ctx, "k-tool-2", "tool")
	if !v.Allowed {
		t.Fatalf("k-tool-2 1st call should be allowed: %v", v.Reason)
	}

	// Next call from k-tool-1 should be rejected for team quota
	v1 := lim.Allow(ctx, "k-tool-1", "tool")
	if v1.Allowed {
		t.Fatal("k-tool-1 should be blocked by team daily tool quota")
	}
	if v1.RuleID != "ops.tenant_quota_exceeded" {
		t.Errorf("v1 RuleID = %q, want ops.tenant_quota_exceeded", v1.RuleID)
	}

	// Next call from k-tool-2 should also be rejected
	v2 := lim.Allow(ctx, "k-tool-2", "tool")
	if v2.Allowed {
		t.Fatal("k-tool-2 should be blocked by team daily tool quota")
	}
	if v2.RuleID != "ops.tenant_quota_exceeded" {
		t.Errorf("v2 RuleID = %q, want ops.tenant_quota_exceeded", v2.RuleID)
	}
}

func TestLimiter_TeamQuota_BudgetUSD(t *testing.T) {
	data := map[string]any{
		"agents": map[string]any{
			"k-budget-1": map[string]any{
				"team_id": "team-fin",
			},
			"k-budget-2": map[string]any{
				"team_id": "team-fin",
			},
		},
		"teams": map[string]any{
			"team-fin": map[string]any{
				"quota": map[string]any{
					"budget_limit_usd": 10.0,
				},
			},
		},
	}

	snap := &policy.Snapshot{Epoch: 1, Data: data}
	store := policy.NewStoreWithSnapshot(snap)
	lim := NewLimiter(store, nil)
	defer lim.Close()

	ctx := context.Background()

	// Initial spend is 0, calls allowed
	if v := lim.Allow(ctx, "k-budget-1", "llm"); !v.Allowed {
		t.Fatalf("initial call should be allowed: %v", v.Reason)
	}

	// Record $6 spend from key 1
	lim.RecordSpend("k-budget-1", 6.0)
	if s := lim.GetTeamSpend("k-budget-1"); s != 6.0 {
		t.Errorf("spend for k-budget-1 = %v, want 6.0", s)
	}
	if s := lim.GetTeamSpend("k-budget-2"); s != 6.0 {
		t.Errorf("spend for k-budget-2 = %v, want 6.0", s)
	}

	// Record $5 spend from key 2 -> total $11 exceeds $10
	lim.RecordSpend("k-budget-2", 5.0)
	if s := lim.GetTeamSpend("k-budget-1"); s != 11.0 {
		t.Errorf("total spend = %v, want 11.0", s)
	}

	// Both keys should now be blocked by team budget
	v1 := lim.Allow(ctx, "k-budget-1", "llm")
	if v1.Allowed {
		t.Fatal("k-budget-1 should be blocked by team budget")
	}
	if v1.RuleID != "ops.tenant_quota_exceeded" {
		t.Errorf("v1 RuleID = %q, want ops.tenant_quota_exceeded", v1.RuleID)
	}

	v2 := lim.Allow(ctx, "k-budget-2", "llm")
	if v2.Allowed {
		t.Fatal("k-budget-2 should be blocked by team budget")
	}
	if v2.RuleID != "ops.tenant_quota_exceeded" {
		t.Errorf("v2 RuleID = %q, want ops.tenant_quota_exceeded", v2.RuleID)
	}
}
