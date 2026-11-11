// Package cerberus provides a lightweight Go client SDK for integrating
// Cerberus policy evaluation directly into tool runners and agents.
package cerberus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrDenied is returned when Cerberus denies tool execution.
type ErrDenied struct {
	RuleID string
	Reason string
}

func (e *ErrDenied) Error() string {
	return fmt.Sprintf("cerberus: tool execution denied by rule %q: %s", e.RuleID, e.Reason)
}

// Decision represents the evaluation verdict from Cerberus.
type Decision struct {
	Decision   string         `json:"decision"`
	RuleID     string         `json:"rule_id"`
	Reason     string         `json:"reason"`
	MaskedArgs map[string]any `json:"masked_args,omitempty"`
	Epoch      uint64         `json:"epoch,omitempty"`
	Cached     bool           `json:"cached"`
}

// Allowed returns true if the decision is "allow".
func (d Decision) Allowed() bool {
	return d.Decision == "allow"
}

// ClientOptions configures the Cerberus client.
type ClientOptions struct {
	BaseURL      string
	KeyID        string
	HTTPClient   *http.Client
	MaxRetries   int
	RetryDelay   time.Duration
	CacheTTL     time.Duration
	DisableCache bool
}

// Metrics records telemetry counters for the client.
type Metrics struct {
	TotalCalls   atomic.Uint64
	AllowedCalls atomic.Uint64
	DeniedCalls  atomic.Uint64
	CacheHits    atomic.Uint64
	CacheMisses  atomic.Uint64
	Retries      atomic.Uint64
	Errors       atomic.Uint64
}

// MetricsSnapshot is a point-in-time copy of client telemetry.
type MetricsSnapshot struct {
	TotalCalls   uint64
	AllowedCalls uint64
	DeniedCalls  uint64
	CacheHits    uint64
	CacheMisses  uint64
	Retries      uint64
	Errors       uint64
}

type cachedVerdict struct {
	decision  Decision
	expiresAt time.Time
}

// Client provides policy queries to Cerberus with client-side caching and retries.
type Client struct {
	opts       ClientOptions
	httpClient *http.Client
	cache      sync.Map // hash -> cachedVerdict
	metrics    Metrics
}

// NewClient creates a new Cerberus client.
func NewClient(opts ClientOptions) *Client {
	if opts.BaseURL == "" {
		opts.BaseURL = "http://127.0.0.1:8089"
	}
	opts.BaseURL = strings.TrimRight(opts.BaseURL, "/")
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = 3
	}
	if opts.RetryDelay <= 0 {
		opts.RetryDelay = 50 * time.Millisecond
	}
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = 60 * time.Second
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}

	return &Client{
		opts:       opts,
		httpClient: httpClient,
	}
}

// Metrics returns a snapshot of telemetry counters.
func (c *Client) Metrics() MetricsSnapshot {
	return MetricsSnapshot{
		TotalCalls:   c.metrics.TotalCalls.Load(),
		AllowedCalls: c.metrics.AllowedCalls.Load(),
		DeniedCalls:  c.metrics.DeniedCalls.Load(),
		CacheHits:    c.metrics.CacheHits.Load(),
		CacheMisses:  c.metrics.CacheMisses.Load(),
		Retries:      c.metrics.Retries.Load(),
		Errors:       c.metrics.Errors.Load(),
	}
}

// DecideTool evaluates a tool call with tool name and arguments.
func (c *Client) DecideTool(ctx context.Context, tool string, args any) (Decision, error) {
	c.metrics.TotalCalls.Add(1)

	argsMap, err := normalizeArgs(args)
	if err != nil {
		c.metrics.Errors.Add(1)
		return Decision{}, fmt.Errorf("cerberus: normalize args: %w", err)
	}

	hash := hashToolCall(tool, argsMap)

	// Check local cache
	if !c.opts.DisableCache {
		if val, ok := c.cache.Load(hash); ok {
			cv := val.(cachedVerdict)
			if time.Now().Before(cv.expiresAt) {
				c.metrics.CacheHits.Add(1)
				d := cv.decision
				d.Cached = true
				if d.Allowed() {
					c.metrics.AllowedCalls.Add(1)
				} else {
					c.metrics.DeniedCalls.Add(1)
				}
				return d, nil
			}
			c.cache.Delete(hash)
		}
	}
	c.metrics.CacheMisses.Add(1)

	// Send POST /v1/decide
	reqBody := map[string]any{
		"stage":     "tool",
		"key_id":    c.opts.KeyID,
		"tool_call": tool,
		"args":      argsMap,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		c.metrics.Errors.Add(1)
		return Decision{}, fmt.Errorf("cerberus: marshal request: %w", err)
	}

	dec, err := c.doWithRetry(ctx, bodyBytes)
	if err != nil {
		c.metrics.Errors.Add(1)
		return Decision{}, err
	}

	if dec.Allowed() {
		c.metrics.AllowedCalls.Add(1)
	} else {
		c.metrics.DeniedCalls.Add(1)
	}

	// Cache successful policy verdicts
	if !c.opts.DisableCache && !strings.HasPrefix(dec.RuleID, "internal.") {
		c.cache.Store(hash, cachedVerdict{
			decision:  dec,
			expiresAt: time.Now().Add(c.opts.CacheTTL),
		})
	}

	return dec, nil
}

func (c *Client) doWithRetry(ctx context.Context, body []byte) (Decision, error) {
	var lastErr error
	delay := c.opts.RetryDelay

	for attempt := 0; attempt < c.opts.MaxRetries; attempt++ {
		if attempt > 0 {
			c.metrics.Retries.Add(1)
			select {
			case <-ctx.Done():
				return Decision{}, ctx.Err()
			case <-time.After(delay):
				delay *= 2
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opts.BaseURL+"/v1/decide", bytes.NewReader(body))
		if err != nil {
			return Decision{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		if c.opts.KeyID != "" {
			req.Header.Set("X-Cerberus-Key", c.opts.KeyID)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode >= 500 {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("server error status %d", resp.StatusCode)
			continue
		}

		defer func() { _ = resp.Body.Close() }()

		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return Decision{}, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBytes))
		}

		var dec Decision
		if err := json.Unmarshal(respBytes, &dec); err != nil {
			return Decision{}, fmt.Errorf("unmarshal decision: %w", err)
		}
		return dec, nil
	}

	return Decision{}, fmt.Errorf("cerberus: request failed after %d attempts: %w", c.opts.MaxRetries, lastErr)
}

func normalizeArgs(args any) (map[string]any, error) {
	if args == nil {
		return map[string]any{}, nil
	}
	if m, ok := args.(map[string]any); ok {
		return m, nil
	}
	data, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	var res map[string]any
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func hashToolCall(tool string, args map[string]any) string {
	b, _ := json.Marshal(args)
	h := sha256.New()
	h.Write([]byte(tool))
	h.Write([]byte{0})
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// ToolExecutor is a standard tool execution function signature.
type ToolExecutor func(ctx context.Context, tool string, args any) (any, error)

// GuardedExecutor wraps tool execution with Cerberus policy authorization.
type GuardedExecutor struct {
	client *Client
}

// NewGuardedExecutor constructs a GuardedExecutor.
func NewGuardedExecutor(client *Client) *GuardedExecutor {
	return &GuardedExecutor{client: client}
}

// Execute checks Cerberus policy before executing the given function.
func (g *GuardedExecutor) Execute(ctx context.Context, tool string, args any, fn func(ctx context.Context, args any) (any, error)) (any, error) {
	if g.client == nil {
		return nil, errors.New("cerberus: guard has nil client")
	}

	dec, err := g.client.DecideTool(ctx, tool, args)
	if err != nil {
		return nil, fmt.Errorf("cerberus check: %w", err)
	}

	if !dec.Allowed() {
		return nil, &ErrDenied{
			RuleID: dec.RuleID,
			Reason: dec.Reason,
		}
	}

	effectiveArgs := args
	if dec.MaskedArgs != nil {
		effectiveArgs = dec.MaskedArgs
	}

	return fn(ctx, effectiveArgs)
}

// Wrap provides a 1-line middleware wrapper around any ToolExecutor.
func (g *GuardedExecutor) Wrap(next ToolExecutor) ToolExecutor {
	return func(ctx context.Context, tool string, args any) (any, error) {
		return g.Execute(ctx, tool, args, func(ctx context.Context, guardedArgs any) (any, error) {
			return next(ctx, tool, guardedArgs)
		})
	}
}
