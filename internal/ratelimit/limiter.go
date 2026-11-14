// Package ratelimit provides token-bucket per-key and per-team rate limiting and quotas for decide calls.
package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/metabbe3/cerberus/internal/policy"
)

// RateLimitUnkeyedTotal tracks rate limit evaluations requested without a keyID.
var RateLimitUnkeyedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "rate_limit_unkeyed_total",
	Help: "Total number of rate-limit evaluations requested without a keyID.",
})

// AuditCounter provides today's tool calls count for daily quota enforcement.
type AuditCounter interface {
	DailyToolCallsCount(ctx context.Context, keyID string, today time.Time) (int64, error)
	DailyTeamCallsCount(ctx context.Context, teamKeys []string, today time.Time) (int64, error)
}

// Config defines rate limiting parameters for an agent key.
const dayLayout = "20060102"

var (
	rpmAliases        = []string{"requests_per_minute", "requests_per_min", "rpm"}
	burstAliases      = []string{"bursts", "burst"}
	toolHourlyAliases = []string{"tool_calls_per_hour", "tool_calls_hourly", "tph"}
	dailyQuotaAliases = []string{"daily_tool_calls", "tool_calls_per_day", "daily_quota"}
	budgetAliases     = []string{"budget_limit_usd", "budget_limit", "budget_limit_daily"}
)

// Config defines rate limiting parameters for an agent key.
type Config struct {
	RequestsPerMinute int `json:"requests_per_minute"`
	Bursts            int `json:"bursts"`
	ToolCallsPerHour  int `json:"tool_calls_per_hour"`
	DailyToolCalls    int `json:"daily_tool_calls"`
}

// TeamConfig defines rate limiting and quota parameters for a team across all its keys.
type TeamConfig struct {
	RequestsPerMinute int     `json:"requests_per_minute"`
	Bursts            int     `json:"bursts"`
	ToolCallsPerHour  int     `json:"tool_calls_per_hour"`
	DailyToolCalls    int     `json:"daily_tool_calls"`
	BudgetLimitUSD    float64 `json:"budget_limit_usd"`
}

// Verdict represents the outcome of rate limit evaluation.
type Verdict struct {
	Allowed    bool
	RetryAfter int
	RuleID     string
	Reason     string
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
	mu            sync.Mutex
	reqBucket     *tokenBucket
	toolBucket    *tokenBucket
	dailyCount    int64
	dayStamp      string
	dailyChecked  bool
	lastAuditWarn time.Time
}

type teamLimiter struct {
	mu            sync.Mutex
	reqBucket     *tokenBucket
	toolBucket    *tokenBucket
	dailyCount    int64
	dayStamp      string
	dailyChecked  bool
	spendUSD      float64
	spendDayStamp string
	lastAuditWarn time.Time
}

// Limiter coordinates token-bucket rate limiting and daily tool call quotas across keys and teams.
type Limiter struct {
	store      *policy.Store
	audit      AuditCounter
	mu         sync.RWMutex
	keys       map[string]*keyLimiter
	teams      map[string]*teamLimiter
	cancelSwap func()
}

// Close unsubscribes the limiter from store swap events.
func (l *Limiter) Close() {
	if l.cancelSwap != nil {
		l.cancelSwap()
		l.cancelSwap = nil
	}
}

// NewLimiter creates a new Limiter backed by a policy store and optional audit counter.
func NewLimiter(store *policy.Store, audit AuditCounter) *Limiter {
	l := &Limiter{
		store: store,
		audit: audit,
		keys:  make(map[string]*keyLimiter),
		teams: make(map[string]*teamLimiter),
	}
	if store != nil {
		l.cancelSwap = store.OnSwap(func(snap *policy.Snapshot) {
			l.Reset(snap.Epoch)
		})
	}
	return l
}

// Reset clears in-memory rate limiter states when policy snapshot epoch changes.
func (l *Limiter) Reset(_ uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = make(map[string]*keyLimiter)
	l.teams = make(map[string]*teamLimiter)
}

// GetTeamSpend returns the accumulated USD spend for the team that owns keyID today (UTC).
func (l *Limiter) GetTeamSpend(keyID string) float64 {
	if l == nil || l.store == nil || keyID == "" {
		return 0
	}
	snap := l.store.Current()
	if snap == nil {
		return 0
	}
	teamID := extractTeamID(snap.Data, keyID)
	if teamID == "" {
		return 0
	}
	l.mu.RLock()
	tl, ok := l.teams[teamID]
	l.mu.RUnlock()
	if !ok {
		return 0
	}
	tl.mu.Lock()
	defer tl.mu.Unlock()
	todayStr := time.Now().UTC().Format(dayLayout)
	if tl.spendDayStamp != todayStr {
		tl.spendDayStamp = todayStr
		tl.spendUSD = 0
	}
	return tl.spendUSD
}

// RecordSpend accumulates USD spend for the team that owns keyID today (UTC).
func (l *Limiter) RecordSpend(keyID string, usd float64) {
	if l == nil || l.store == nil || keyID == "" || usd <= 0 {
		return
	}
	snap := l.store.Current()
	if snap == nil {
		return
	}
	teamID := extractTeamID(snap.Data, keyID)
	if teamID == "" {
		return
	}
	teamCfg, _ := extractTeamConfig(snap.Data, teamID)
	tl := l.getOrInitTeamLimiter(teamID, teamCfg)
	tl.mu.Lock()
	defer tl.mu.Unlock()
	todayStr := time.Now().UTC().Format(dayLayout)
	if tl.spendDayStamp != todayStr {
		tl.spendDayStamp = todayStr
		tl.spendUSD = 0
	}
	tl.spendUSD += usd
}

// Allow evaluates whether an incoming request from keyID at stage is within key and team rate limits.
func (l *Limiter) Allow(ctx context.Context, keyID string, stage string) Verdict {
	if keyID == "" {
		RateLimitUnkeyedTotal.Inc()
		return Verdict{Allowed: true}
	}
	if l.store == nil {
		return Verdict{Allowed: true}
	}

	snap := l.store.Current()
	if snap == nil {
		return Verdict{Allowed: true}
	}

	agentCfg, hasAgentCfg := extractRateLimitConfig(snap.Data, keyID)
	teamID := extractTeamID(snap.Data, keyID)
	var teamCfg TeamConfig
	var hasTeamCfg bool
	if teamID != "" {
		teamCfg, hasTeamCfg = extractTeamConfig(snap.Data, teamID)
	}

	if !hasAgentCfg && !hasTeamCfg {
		return Verdict{Allowed: true}
	}

	var tl *teamLimiter
	var fetchedTeamCount int64
	var didFetchTeam bool
	var fetchTeamErr error

	if hasTeamCfg {
		tl = l.getOrInitTeamLimiter(teamID, teamCfg)
		if stage == "tool" && teamCfg.DailyToolCalls > 0 && l.audit != nil {
			todayStr := time.Now().UTC().Format(dayLayout)
			tl.mu.Lock()
			needsFetch := tl.dayStamp != todayStr || !tl.dailyChecked
			tl.mu.Unlock()

			if needsFetch {
				teamKeys := extractTeamKeys(snap.Data, teamID)
				fetchedTeamCount, fetchTeamErr = l.audit.DailyTeamCallsCount(ctx, teamKeys, time.Now().UTC())
				didFetchTeam = true
			}
		}
	}

	var kl *keyLimiter
	var fetchedKeyCount int64
	var didFetchKey bool
	var fetchKeyErr error

	if hasAgentCfg {
		kl = l.getOrInitKeyLimiter(keyID, agentCfg)
		if stage == "tool" && agentCfg.DailyToolCalls > 0 && l.audit != nil {
			todayStr := time.Now().UTC().Format(dayLayout)
			kl.mu.Lock()
			needsFetch := kl.dayStamp != todayStr || !kl.dailyChecked
			kl.mu.Unlock()

			if needsFetch {
				fetchedKeyCount, fetchKeyErr = l.audit.DailyToolCallsCount(ctx, keyID, time.Now().UTC())
				didFetchKey = true
			}
		}
	}

	now := time.Now()
	todayStr := now.UTC().Format(dayLayout)

	// 1. Team level evaluation
	if hasTeamCfg && tl != nil {
		tl.mu.Lock()
		if tl.dayStamp != todayStr {
			tl.dayStamp = todayStr
			tl.dailyCount = 0
			tl.dailyChecked = false
		}
		if tl.spendDayStamp != todayStr {
			tl.spendDayStamp = todayStr
			tl.spendUSD = 0
		}

		// Team RPM check
		if tl.reqBucket != nil {
			allowed, waitSec := tl.reqBucket.allow(now)
			if !allowed {
				tl.mu.Unlock()
				return Verdict{
					Allowed:    false,
					RetryAfter: waitSec,
					RuleID:     "ops.tenant_quota_exceeded",
					Reason:     fmt.Sprintf("team %s requests per minute limit exceeded (%d/min)", teamID, teamCfg.RequestsPerMinute),
				}
			}
		}

		// Team tool checks
		if stage == "tool" {
			if tl.toolBucket != nil {
				allowed, waitSec := tl.toolBucket.allow(now)
				if !allowed {
					if tl.reqBucket != nil {
						tl.reqBucket.tokens += 1.0
					}
					tl.mu.Unlock()
					return Verdict{
						Allowed:    false,
						RetryAfter: waitSec,
						RuleID:     "ops.tenant_quota_exceeded",
						Reason:     fmt.Sprintf("team %s tool calls per hour limit exceeded (%d/hr)", teamID, teamCfg.ToolCallsPerHour),
					}
				}
			}

			if teamCfg.DailyToolCalls > 0 {
				if !tl.dailyChecked && didFetchTeam {
					if fetchTeamErr != nil {
						if now.Sub(tl.lastAuditWarn) >= time.Minute {
							tl.lastAuditWarn = now
							slog.Warn("ratelimit: failed to fetch daily team calls count; retrying on next call",
								"team_id", teamID, "err", fetchTeamErr)
						}
					} else {
						tl.dailyCount = fetchedTeamCount
						tl.dailyChecked = true
					}
				}

				if tl.dailyCount >= int64(teamCfg.DailyToolCalls) {
					nextDay := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day()+1, 0, 0, 0, 0, time.UTC)
					waitSec := int(nextDay.Sub(now.UTC()).Seconds())
					if waitSec < 1 {
						waitSec = 1
					}
					if tl.reqBucket != nil {
						tl.reqBucket.tokens += 1.0
					}
					if tl.toolBucket != nil {
						tl.toolBucket.tokens += 1.0
					}
					tl.mu.Unlock()
					return Verdict{
						Allowed:    false,
						RetryAfter: waitSec,
						RuleID:     "ops.tenant_quota_exceeded",
						Reason:     fmt.Sprintf("team %s daily tool calls quota exceeded (%d/%d)", teamID, tl.dailyCount, teamCfg.DailyToolCalls),
					}
				}
			}
		}

		// Team budget limit check
		if teamCfg.BudgetLimitUSD > 0 && tl.spendUSD >= teamCfg.BudgetLimitUSD {
			nextDay := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day()+1, 0, 0, 0, 0, time.UTC)
			waitSec := int(nextDay.Sub(now.UTC()).Seconds())
			if waitSec < 1 {
				waitSec = 1
			}
			if tl.reqBucket != nil {
				tl.reqBucket.tokens += 1.0
			}
			tl.mu.Unlock()
			return Verdict{
				Allowed:    false,
				RetryAfter: waitSec,
				RuleID:     "ops.tenant_quota_exceeded",
				Reason:     fmt.Sprintf("team %s budget limit exceeded ($%.2f/$%.2f)", teamID, tl.spendUSD, teamCfg.BudgetLimitUSD),
			}
		}
		tl.mu.Unlock()
	}

	// 2. Key level evaluation
	if hasAgentCfg && kl != nil {
		kl.mu.Lock()
		defer kl.mu.Unlock()

		if kl.reqBucket != nil {
			allowed, waitSec := kl.reqBucket.allow(now)
			if !allowed {
				// Refund team RPM token
				if tl != nil {
					tl.mu.Lock()
					if tl.reqBucket != nil {
						tl.reqBucket.tokens += 1.0
					}
					tl.mu.Unlock()
				}
				return Verdict{
					Allowed:    false,
					RetryAfter: waitSec,
					RuleID:     "ops.rate_limited",
					Reason:     fmt.Sprintf("requests per minute limit exceeded (%d/min)", agentCfg.RequestsPerMinute),
				}
			}
		}

		if stage == "tool" {
			if kl.toolBucket != nil {
				allowed, waitSec := kl.toolBucket.allow(now)
				if !allowed {
					if tl != nil {
						tl.mu.Lock()
						if tl.reqBucket != nil {
							tl.reqBucket.tokens += 1.0
						}
						if tl.toolBucket != nil {
							tl.toolBucket.tokens += 1.0
						}
						tl.mu.Unlock()
					}
					return Verdict{
						Allowed:    false,
						RetryAfter: waitSec,
						RuleID:     "ops.rate_limited",
						Reason:     fmt.Sprintf("tool calls per hour limit exceeded (%d/hr)", agentCfg.ToolCallsPerHour),
					}
				}
			}

			if agentCfg.DailyToolCalls > 0 {
				if kl.dayStamp != todayStr {
					kl.dayStamp = todayStr
					kl.dailyCount = 0
					kl.dailyChecked = false
				}

				if !kl.dailyChecked && didFetchKey {
					if fetchKeyErr != nil {
						if now.Sub(kl.lastAuditWarn) >= time.Minute {
							kl.lastAuditWarn = now
							slog.Warn("ratelimit: failed to fetch daily tool calls count; retrying on next call",
								"key_id", keyID, "err", fetchKeyErr)
						}
					} else {
						kl.dailyCount = fetchedKeyCount
						kl.dailyChecked = true
					}
				}

				if kl.dailyCount >= int64(agentCfg.DailyToolCalls) {
					nextDay := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day()+1, 0, 0, 0, 0, time.UTC)
					waitSec := int(nextDay.Sub(now.UTC()).Seconds())
					if waitSec < 1 {
						waitSec = 1
					}
					if tl != nil {
						tl.mu.Lock()
						if tl.reqBucket != nil {
							tl.reqBucket.tokens += 1.0
						}
						if tl.toolBucket != nil {
							tl.toolBucket.tokens += 1.0
						}
						tl.mu.Unlock()
					}
					return Verdict{
						Allowed:    false,
						RetryAfter: waitSec,
						RuleID:     "ops.rate_limited",
						Reason:     fmt.Sprintf("daily tool calls quota exceeded (%d/%d)", kl.dailyCount, agentCfg.DailyToolCalls),
					}
				}

				kl.dailyCount++
			}
		}
	}

	// 3. Increment team tool daily count if stage == "tool" and daily quota configured
	if hasTeamCfg && tl != nil && stage == "tool" && teamCfg.DailyToolCalls > 0 {
		tl.mu.Lock()
		tl.dailyCount++
		tl.mu.Unlock()
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
		dayStamp: time.Now().UTC().Format(dayLayout),
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

func (l *Limiter) getOrInitTeamLimiter(teamID string, cfg TeamConfig) *teamLimiter {
	l.mu.RLock()
	tl, exists := l.teams[teamID]
	l.mu.RUnlock()
	if exists {
		return tl
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if tl, exists = l.teams[teamID]; exists {
		return tl
	}

	tl = &teamLimiter{
		dayStamp:      time.Now().UTC().Format(dayLayout),
		spendDayStamp: time.Now().UTC().Format(dayLayout),
	}

	if cfg.RequestsPerMinute > 0 {
		capacity := float64(cfg.Bursts)
		if capacity <= 0 {
			capacity = float64(cfg.RequestsPerMinute)
		}
		ratePerSec := float64(cfg.RequestsPerMinute) / 60.0
		tl.reqBucket = newTokenBucket(ratePerSec, capacity)
	}

	if cfg.ToolCallsPerHour > 0 {
		capacity := float64(cfg.ToolCallsPerHour)
		if cfg.Bursts > 0 && float64(cfg.Bursts) < capacity {
			capacity = float64(cfg.Bursts)
		}
		ratePerSec := float64(cfg.ToolCallsPerHour) / 3600.0
		tl.toolBucket = newTokenBucket(ratePerSec, capacity)
	}

	l.teams[teamID] = tl
	return tl
}

func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	default:
		return 0
	}
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}

func extractTeamID(data map[string]any, keyID string) string {
	if data == nil || keyID == "" {
		return ""
	}
	agents, ok := data["agents"].(map[string]any)
	if !ok {
		return ""
	}
	agent, ok := agents[keyID].(map[string]any)
	if !ok {
		return ""
	}
	teamID, ok := agent["team_id"].(string)
	if !ok {
		return ""
	}
	return teamID
}

func extractTeamKeys(data map[string]any, teamID string) []string {
	if data == nil || teamID == "" {
		return nil
	}
	agents, ok := data["agents"].(map[string]any)
	if !ok {
		return nil
	}
	var keys []string
	for k, v := range agents {
		if ag, ok := v.(map[string]any); ok {
			if tid, ok := ag["team_id"].(string); ok && tid == teamID {
				keys = append(keys, k)
			}
		}
	}
	return keys
}

func extractTeamConfig(data map[string]any, teamID string) (TeamConfig, bool) {
	if data == nil || teamID == "" {
		return TeamConfig{}, false
	}
	teams, ok := data["teams"].(map[string]any)
	if !ok {
		return TeamConfig{}, false
	}
	team, ok := teams[teamID].(map[string]any)
	if !ok {
		return TeamConfig{}, false
	}

	getInt := func(keys []string) int {
		for _, k := range keys {
			if v, exists := team[k]; exists {
				if n := toInt(v); n > 0 {
					return n
				}
			}
			if q, ok := team["quota"].(map[string]any); ok {
				if v, exists := q[k]; exists {
					if n := toInt(v); n > 0 {
						return n
					}
				}
			}
			if rl, ok := team["rate_limit"].(map[string]any); ok {
				if v, exists := rl[k]; exists {
					if n := toInt(v); n > 0 {
						return n
					}
				}
			}
		}
		return 0
	}

	getFloat := func(keys []string) float64 {
		for _, k := range keys {
			if v, exists := team[k]; exists {
				if n := toFloat(v); n > 0 {
					return n
				}
			}
			if q, ok := team["quota"].(map[string]any); ok {
				if v, exists := q[k]; exists {
					if n := toFloat(v); n > 0 {
						return n
					}
				}
			}
			if rl, ok := team["rate_limit"].(map[string]any); ok {
				if v, exists := rl[k]; exists {
					if n := toFloat(v); n > 0 {
						return n
					}
				}
			}
		}
		return 0
	}

	cfg := TeamConfig{
		RequestsPerMinute: getInt(rpmAliases),
		Bursts:            getInt(burstAliases),
		ToolCallsPerHour:  getInt(toolHourlyAliases),
		DailyToolCalls:    getInt(dailyQuotaAliases),
		BudgetLimitUSD:    getFloat(budgetAliases),
	}

	if cfg.RequestsPerMinute <= 0 && cfg.ToolCallsPerHour <= 0 && cfg.DailyToolCalls <= 0 && cfg.BudgetLimitUSD <= 0 {
		return TeamConfig{}, false
	}
	return cfg, true
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

	getInt := func(keys []string) int {
		for _, k := range keys {
			if v, exists := rlMap[k]; exists {
				if n := toInt(v); n > 0 {
					return n
				}
			}
		}
		return 0
	}

	cfg := Config{
		RequestsPerMinute: getInt(rpmAliases),
		Bursts:            getInt(burstAliases),
		ToolCallsPerHour:  getInt(toolHourlyAliases),
		DailyToolCalls:    getInt(dailyQuotaAliases),
	}

	if cfg.RequestsPerMinute <= 0 && cfg.ToolCallsPerHour <= 0 && cfg.DailyToolCalls <= 0 {
		return Config{}, false
	}
	return cfg, true
}
