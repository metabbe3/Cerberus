// Package engine evaluates decisions against the live policy snapshot with a
// bounded LRU cache, singleflight, and an eval timeout. Decide never returns
// an error: every failure mode maps to a deny with an internal.* rule_id
// (fail-closed, ADR-0001 §7).
package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2"
	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/config"
	"github.com/metabbe3/cerberus/internal/masking"
	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/metabbe3/cerberus/internal/util"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
	"golang.org/x/sync/singleflight"
)

// Sink receives every decision for asynchronous audit (satisfied by
// *audit.Logger; Task 7 wires the HTTP layer between the two).
type Sink interface {
	Emit(audit.Event)
}

// noopSink discards events when no audit logger is wired in.
type noopSink struct{}

func (noopSink) Emit(audit.Event) {}

// Options configures an Engine. Zero values take the defaults 10000 and 10ms.
type Options struct {
	CacheSize   int
	EvalTimeout time.Duration
}

const (
	defaultCacheSize   = config.DefaultCacheSize
	defaultEvalTimeout = config.DefaultEvalTimeout
)

// Engine is the hot path: Store.Current (atomic load) → LRU → singleflight →
// prepared-query eval → masking. It holds no mutex of its own; the LRU and
// singleflight group are concurrency-safe.
type Engine struct {
	store *policy.Store
	sink  Sink
	opts  Options
	cache *lru.Cache[string, Decision]
	sf    singleflight.Group
	// evalHook, when non-nil, runs at the top of every eval. Test seam for
	// pinning leader/waiter interleavings; nil in production.
	evalHook func()
}

// New builds an Engine over store. sink may be nil (events are discarded).
func New(store *policy.Store, sink Sink, opts Options) (*Engine, error) {
	if store == nil {
		return nil, errors.New("engine: nil store")
	}
	if store.Current() == nil {
		return nil, errors.New("engine: store has no snapshot")
	}
	if opts.CacheSize <= 0 {
		opts.CacheSize = defaultCacheSize
	}
	if opts.EvalTimeout <= 0 {
		opts.EvalTimeout = defaultEvalTimeout
	}
	if sink == nil {
		sink = noopSink{}
	}
	cache, err := lru.New[string, Decision](opts.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("engine: lru: %w", err)
	}
	// The gauge lives at the swap, not in Decide: a reload with no traffic
	// must still move it, and an old in-flight request must never drag it
	// backwards.
	store.OnSwap(func(snap *policy.Snapshot) {
		policyEpoch.Set(float64(snap.Epoch))
		SetBundleRevision(snap.Revision)
	})
	policyEpoch.Set(float64(store.Current().Epoch))
	SetBundleRevision(store.Current().Revision)
	return &Engine{store: store, sink: sink, opts: opts, cache: cache}, nil
}

// TraceEntry captures one rule or expression evaluation in an explain trace.
type TraceEntry struct {
	Op       string `json:"op"`
	Rule     string `json:"rule,omitempty"`
	Location string `json:"location,omitempty"`
	Result   string `json:"result,omitempty"`
}

// Decision is the public decision contract (golden-tested in Task 7).
type Decision struct {
	Decision    string         `json:"decision"`
	RuleID      string         `json:"rule_id"`
	Reason      string         `json:"reason"`
	MaskedArgs  map[string]any `json:"masked_args"` // null when no rule changed a string
	Epoch       uint64         `json:"epoch"`
	Cached      bool           `json:"cached"`
	LatencyUS   int64          `json:"-"`
	Trace       []TraceEntry   `json:"trace,omitempty"`
	PrettyTrace string         `json:"pretty_trace,omitempty"`
}

// Allowed reports whether the decision is "allow".
func (d Decision) Allowed() bool {
	return d.Decision == "allow"
}

// Decide answers one request. It never returns an error and never blocks on a
// mutex: cache hit ~100ns, miss goes through singleflight so N identical
// concurrent requests share one eval.
func (e *Engine) Decide(ctx context.Context, in Input) Decision {
	start := time.Now()
	snap := e.store.Current()
	sum := cacheKey(snap.Epoch, in)
	key := hex.EncodeToString(sum[:])
	epochStr := strconv.FormatUint(snap.Epoch, 10)

	var d Decision
	if hit, ok := e.cache.Get(key); ok {
		cacheHitsTotal.Inc()
		cacheHitsEpoch.WithLabelValues(epochStr).Inc()
		hit.Cached = true
		d = hit
	} else {
		// evaled is written only by the goroutine whose closure singleflight
		// actually runs (the leader); waiters' closures never execute, so each
		// caller reads its own untouched copy — race-free by construction.
		var evaled bool
		res, _, _ := e.sf.Do(key, func() (any, error) {
			// Re-check: a flight may have filled the cache between our Get
			// miss and this fn running, which would double-count the miss.
			// This caller skipped a fresh eval: it counts as a hit below.
			if hit, ok := e.cache.Get(key); ok {
				return hit, nil
			}
			evaled = true
			cacheMissesTotal.Inc()
			cacheMissesEpoch.WithLabelValues(epochStr).Inc()
			// Detach from the leader's request ctx: one client's disconnect
			// must not fail-closed the eval for every waiter on the flight.
			// EvalTimeout still bounds the work.
			d := e.eval(context.WithoutCancel(ctx), snap, in)
			if !strings.HasPrefix(d.RuleID, "internal.") { // internal.* are transient; never cache them
				e.cache.Add(key, d) // masked result is what gets cached
			}
			return d, nil
		})
		d = res.(Decision)
		if !evaled { // waiter on a shared flight, or leader whose re-check found the cache filled
			cacheHitsTotal.Inc()
			cacheHitsEpoch.WithLabelValues(epochStr).Inc()
			d.Cached = true
		}
	}

	d.LatencyUS = time.Since(start).Microseconds()
	decisionsTotal.WithLabelValues(metricStage(in.Stage), d.Decision, d.RuleID).Inc()
	e.sink.Emit(audit.Event{
		Time:      time.Now(),
		Stage:     in.Stage,
		KeyID:     in.KeyID,
		Subject:   subject(in),
		Decision:  d.Decision,
		RuleID:    d.RuleID,
		Reason:    d.Reason,
		Epoch:     d.Epoch,
		Cached:    d.Cached,
		LatencyUS: d.LatencyUS,
		Args:      d.MaskedArgs,
	})
	return d
}

// Explain evaluates input with full OPA query tracing enabled, bypassing cache.
// It returns the decision along with the ordered rule trace and pretty formatted trace.
func (e *Engine) Explain(ctx context.Context, in Input) Decision {
	start := time.Now()
	snap := e.store.Current()

	evalCtx, cancel := context.WithTimeout(ctx, e.opts.EvalTimeout)
	defer cancel()

	tracer := topdown.NewBufferTracer()

	rs, err := snap.Query.Eval(evalCtx, rego.EvalInput(regoInput(in)), rego.EvalQueryTracer(tracer))
	if err != nil || evalCtx.Err() != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(evalCtx.Err(), context.DeadlineExceeded) {
			d := denyInternal(snap, "internal.timeout", "policy eval exceeded timeout")
			d.LatencyUS = time.Since(start).Microseconds()
			return d
		}
		d := denyInternal(snap, "internal.eval_error", "policy evaluation failed")
		d.LatencyUS = time.Since(start).Microseconds()
		return d
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		d := denyInternal(snap, "internal.eval_error", "policy returned no decision")
		d.LatencyUS = time.Since(start).Microseconds()
		return d
	}
	val, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		d := denyInternal(snap, "internal.eval_error", "policy returned unexpected shape")
		d.LatencyUS = time.Since(start).Microseconds()
		return d
	}

	d := Decision{
		Decision: str(val["decision"]),
		RuleID:   str(val["rule_id"]),
		Reason:   str(val["reason"]),
		Epoch:    snap.Epoch,
		Cached:   false,
	}

	// Extract pretty trace
	var buf bytes.Buffer
	topdown.PrettyTrace(&buf, *tracer)
	d.PrettyTrace = buf.String()

	// Extract structured trace entries: rules evaluated in sequence + pass/fail
	var entries []TraceEntry
	for _, evt := range *tracer {
		ruleName := ""
		if r, ok := evt.Node.(*ast.Rule); ok && r != nil {
			ruleName = r.Path().String()
		} else if evt.Ref != nil {
			ruleName = evt.Ref.String()
		} else {
			func() {
				defer func() { _ = recover() }()
				if expr, ok := evt.Node.(*ast.Expr); ok && expr != nil {
					ruleName = expr.String()
				}
			}()
		}

		loc := ""
		if evt.Location != nil {
			loc = fmt.Sprintf("%s:%d", filepath.Base(evt.Location.File), evt.Location.Row)
		}

		result := ""
		switch evt.Op {
		case topdown.ExitOp:
			result = "pass"
		case topdown.FailOp:
			result = "fail"
		default:
			result = evt.Message
		}

		// Filter noise: keep Enter, Exit, Fail operations with meaningful node/rule
		if ruleName != "" && (evt.Op == topdown.EnterOp || evt.Op == topdown.ExitOp || evt.Op == topdown.FailOp) {
			entries = append(entries, TraceEntry{
				Op:       string(evt.Op),
				Rule:     ruleName,
				Location: loc,
				Result:   result,
			})
		}
	}
	d.Trace = entries
	d.MaskedArgs = applyMasking(snap, in.KeyID, in.Args)
	d.LatencyUS = time.Since(start).Microseconds()
	return d
}

// eval runs the prepared query under the eval timeout, maps the Rego decision
// object to a Decision, and applies the key's masking rules to args.
func (e *Engine) eval(ctx context.Context, snap *policy.Snapshot, in Input) Decision {
	evalCtx, cancel := context.WithTimeout(ctx, e.opts.EvalTimeout)
	defer cancel()

	if e.evalHook != nil {
		e.evalHook()
	}
	t0 := time.Now()
	rs, err := snap.Query.Eval(evalCtx, rego.EvalInput(regoInput(in)))
	dur := time.Since(t0).Seconds()
	evalDuration.Observe(dur)
	evalDurationStage.WithLabelValues(metricStage(in.Stage)).Observe(dur)

	if err != nil || evalCtx.Err() != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(evalCtx.Err(), context.DeadlineExceeded) {
			evalTimeoutsTotal.Inc()
			return denyInternal(snap, "internal.timeout", "policy eval exceeded timeout")
		}
		slog.Error("engine: eval", "error", err, "key_id", in.KeyID, "stage", in.Stage)
		return denyInternal(snap, "internal.eval_error", "policy evaluation failed")
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return denyInternal(snap, "internal.eval_error", "policy returned no decision")
	}
	val, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return denyInternal(snap, "internal.eval_error", "policy returned unexpected shape")
	}

	d := Decision{
		Decision:   str(val["decision"]),
		RuleID:     str(val["rule_id"]),
		Reason:     str(val["reason"]),
		Epoch:      snap.Epoch,
		MaskedArgs: applyMasking(snap, in.KeyID, in.Args),
	}
	return d
}

// applyMasking applies per-key masking rules to args map.
func applyMasking(snap *policy.Snapshot, keyID string, args map[string]any) map[string]any {
	if masked, changed := masking.Apply(snap.Maskers[keyID], "args", args); changed {
		if m, ok := masked.(map[string]any); ok {
			return m
		}
	}
	return nil
}

// denyInternal is the fail-closed answer for every internal failure mode.
func denyInternal(snap *policy.Snapshot, ruleID, reason string) Decision {
	return Decision{Decision: "deny", RuleID: ruleID, Reason: reason, Epoch: snap.Epoch}
}

// metricStage collapses the client-supplied stage onto a bounded label set so
// an unauthenticated caller can never mint a new cerberus_decisions_total
// time series (label cardinality = memory on an unauthenticated endpoint).
func metricStage(stage string) string {
	switch stage {
	case "llm", "tool", "http", "docker":
		return stage
	default:
		return "other"
	}
}

// subject picks the audit subject: model for llm, tool_call for tool,
// otherwise the generic action.
func subject(in Input) string {
	switch in.Stage {
	case "llm":
		return in.Model
	case "tool":
		return in.ToolCall
	default:
		return in.Action
	}
}

// cacheKey is sha256(epoch ‖ json.Marshal(in)) — the epoch invalidates the
// whole cache on reload, and json.Marshal sorts map keys so equal inputs hash
// equally.
// ponytail: json.Marshal for cache key — hand-rolled hasher only if bench shows it dominating.
func cacheKey(epoch uint64, in Input) [32]byte {
	b, err := json.Marshal(in)
	if err != nil {
		b = nil // unmarshalable args → stable (weaker) key; decision still fails closed on eval
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], epoch)
	h := sha256.New()
	h.Write(buf[:])
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// str extracts a string field from the Rego decision object.
func str(v any) string {
	return util.Str(v)
}

// Stats returns the cache hits and misses totals recorded by the engine.
func (e *Engine) Stats() (hits uint64, misses uint64) {
	return EngineStats()
}
