package ratelimit

import (
	"context"
	"testing"
	"time"

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

	// Call 2 today (total 4 > 3) -> hard stop + quota alert
	v2 := lim.Allow(ctx, "k-quota", "tool")
	if v2.Allowed {
		t.Fatalf("4th tool call should be hard stopped")
	}
	if !v2.IsQuotaAlert {
		t.Errorf("expected IsQuotaAlert=true")
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
