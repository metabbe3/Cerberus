package ratelimit

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/metabbe3/cerberus/internal/policy"
)

// AuditCounter provides today's tool calls count for daily quota enforcement.
type AuditCounter interface {
	DailyToolCallsCount(ctx context.Context, keyID string, today time.Time) (int64, error)
}

// Config defines rate limiting parameters for an agent key.
type Config struct {
	RequestsPerMinute int `json:"requests_per_minute"`
	Bursts            int `json:"bursts"`
	ToolCallsPerHour  int `json:"tool_calls_per_hour"`
	DailyToolCalls    int `json:"daily_tool_calls"`
}

// Verdict represents the outcome of rate limit evaluation.
type Verdict struct {
	Allowed      bool
	RetryAfter   int
	RuleID       string
	Reason       string
	IsQuotaAlert bool
}

type tokenBucket struct {
	capacity float64
	tokens   float64
	rate     float64 // tokens per second
	last     time.Time
}

func newTokenBucket(ratePerSec float64, capacity float64) *tokenBucket {
	return &tokenBucket{
		capacity: capacity,
		tokens:   capacity,
		rate:     ratePerSec,
		last:     time.Now(),
	}
}

func (tb *tokenBucket) allow(now time.Time) (bool, int) {
	if tb.rate <= 0 {
		return true, 0
	}
	elapsed := now.Sub(tb.last).Seconds()
	tb.last = now
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true, 0
	}
	needed := 1.0 - tb.tokens
	waitSec := int(math.Ceil(needed / tb.rate))
	if waitSec < 1 {
		waitSec = 1
	}
	return false, waitSec
}

type keyLimiter struct {
	mu           sync.Mutex
	cfg          Config
	reqBucket    *tokenBucket
	toolBucket   *tokenBucket
	dailyCount   int64
	dayStamp     string
	dailyChecked bool
}

// Limiter coordinates token-bucket rate limiting and daily tool call quotas across keys.
type Limiter struct {
	store    *policy.Store
	audit    AuditCounter
	mu       sync.RWMutex
	keys     map[string]*keyLimiter
	curEpoch uint64
}

// NewLimiter creates a new Limiter backed by a policy store and optional audit counter.
func NewLimiter(store *policy.Store, audit AuditCounter) *Limiter {
	l := &Limiter{
		store: store,
		audit: audit,
		keys:  make(map[string]*keyLimiter),
	}
	if store != nil {
		store.OnSwap(func(snap *policy.Snapshot) {
			l.Reset(snap.Epoch)
		})
		if cur := store.Current(); cur != nil {
			l.curEpoch = cur.Epoch
		}
	}
	return l
}

// Reset clears in-memory rate limiter states when policy snapshot epoch changes.
func (l *Limiter) Reset(epoch uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = make(map[string]*keyLimiter)
	l.curEpoch = epoch
}

// Allow evaluates whether an incoming request from keyID at stage is within rate limits.
func (l *Limiter) Allow(ctx context.Context, keyID string, stage string) Verdict {
	if keyID == "" || l.store == nil {
		return Verdict{Allowed: true}
	}

	snap := l.store.Current()
	if snap == nil {
		return Verdict{Allowed: true}
	}

	cfg, ok := extractRateLimitConfig(snap.Data, keyID)
	if !ok {
		return Verdict{Allowed: true}
	}

	kl := l.getOrInitKeyLimiter(keyID, cfg)
	kl.mu.Lock()
	defer kl.mu.Unlock()

	now := time.Now()

	// 1. Check requests_per_minute token bucket
	if kl.reqBucket != nil {
		allowed, waitSec := kl.reqBucket.allow(now)
		if !allowed {
			return Verdict{
				Allowed:    false,
				RetryAfter: waitSec,
				RuleID:     "ops.rate_limited",
				Reason:     fmt.Sprintf("requests per minute limit exceeded (%d/min)", cfg.RequestsPerMinute),
			}
		}
	}

	// 2. Check stage == "tool" specific limits
	if stage == "tool" {
		// Tool calls per hour token bucket
		if kl.toolBucket != nil {
			allowed, waitSec := kl.toolBucket.allow(now)
			if !allowed {
				return Verdict{
					Allowed:    false,
					RetryAfter: waitSec,
					RuleID:     "ops.rate_limited",
					Reason:     fmt.Sprintf("tool calls per hour limit exceeded (%d/hr)", cfg.ToolCallsPerHour),
				}
			}
		}

		// Daily tool calls quota
		if cfg.DailyToolCalls > 0 {
			todayStr := now.UTC().Format("20060102")
			if kl.dayStamp != todayStr {
				kl.dayStamp = todayStr
				kl.dailyCount = 0
				kl.dailyChecked = false
			}

			if !kl.dailyChecked && l.audit != nil {
				if cnt, err := l.audit.DailyToolCallsCount(ctx, keyID, now.UTC()); err == nil {
					kl.dailyCount = cnt
				}
				kl.dailyChecked = true
			}

			if kl.dailyCount >= int64(cfg.DailyToolCalls) {
				// Retry-After until next UTC midnight
				nextDay := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day()+1, 0, 0, 0, 0, time.UTC)
				waitSec := int(nextDay.Sub(now.UTC()).Seconds())
				if waitSec < 1 {
					waitSec = 1
				}
				return Verdict{
					Allowed:      false,
					RetryAfter:   waitSec,
					RuleID:       "ops.rate_limited",
					Reason:       fmt.Sprintf("daily tool calls quota exceeded (%d/%d)", kl.dailyCount, cfg.DailyToolCalls),
					IsQuotaAlert: true,
				}
			}

			// Increment daily tool call count
			kl.dailyCount++
		}
	}

	return Verdict{Allowed: true}
}

func (l *Limiter) getOrInitKeyLimiter(keyID string, cfg Config) *keyLimiter {
	l.mu.RLock()
	kl, exists := l.keys[keyID]
	l.mu.RUnlock()
	if exists {
		return kl
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if kl, exists = l.keys[keyID]; exists {
		return kl
	}

	kl = &keyLimiter{
		cfg:      cfg,
		dayStamp: time.Now().UTC().Format("20060102"),
	}

	if cfg.RequestsPerMinute > 0 {
		capacity := float64(cfg.Bursts)
		if capacity <= 0 {
			capacity = float64(cfg.RequestsPerMinute)
		}
		ratePerSec := float64(cfg.RequestsPerMinute) / 60.0
		kl.reqBucket = newTokenBucket(ratePerSec, capacity)
	}

	if cfg.ToolCallsPerHour > 0 {
		capacity := float64(cfg.ToolCallsPerHour)
		if cfg.Bursts > 0 && float64(cfg.Bursts) < capacity {
			capacity = float64(cfg.Bursts)
		}
		ratePerSec := float64(cfg.ToolCallsPerHour) / 3600.0
		kl.toolBucket = newTokenBucket(ratePerSec, capacity)
	}

	l.keys[keyID] = kl
	return kl
}

func extractRateLimitConfig(data map[string]any, keyID string) (Config, bool) {
	if data == nil {
		return Config{}, false
	}
	agents, ok := data["agents"].(map[string]any)
	if !ok {
		return Config{}, false
	}
	agent, ok := agents[keyID].(map[string]any)
	if !ok {
		return Config{}, false
	}
	rawRL, ok := agent["rate_limit"]
	if !ok {
		return Config{}, false
	}
	rlMap, ok := rawRL.(map[string]any)
	if !ok {
		return Config{}, false
	}

	getInt := func(keys ...string) int {
		for _, k := range keys {
			if v, exists := rlMap[k]; exists {
				switch n := v.(type) {
				case float64:
					return int(n)
				case int:
					return n
				case int64:
					return int(n)
				}
			}
		}
		return 0
	}

	cfg := Config{
		RequestsPerMinute: getInt("requests_per_minute", "requests_per_min", "rpm"),
		Bursts:            getInt("bursts", "burst"),
		ToolCallsPerHour:  getInt("tool_calls_per_hour", "tool_calls_hourly", "tph"),
		DailyToolCalls:    getInt("daily_tool_calls", "tool_calls_per_day", "daily_quota"),
	}

	if cfg.RequestsPerMinute <= 0 && cfg.ToolCallsPerHour <= 0 && cfg.DailyToolCalls <= 0 {
		return Config{}, false
	}
	return cfg, true
}
