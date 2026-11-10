// Package engine evaluates decisions against the live policy snapshot with a
// bounded LRU cache, singleflight, and an eval timeout. Decide never returns
// an error: every failure mode maps to a deny with an internal.* rule_id
// (fail-closed, ADR-0001 §7).
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/masking"
	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/hashicorp/golang-lru/v2"
	"github.com/open-policy-agent/opa/v1/rego"
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
	defaultCacheSize   = 10000
	defaultEvalTimeout = 10 * time.Millisecond
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
	policyEpoch.Set(float64(store.Current().Epoch))
	return &Engine{store: store, sink: sink, opts: opts, cache: cache}, nil
}

// Decision is the public decision contract (golden-tested in Task 7).
type Decision struct {
	Decision   string         `json:"decision"`
	RuleID     string         `json:"rule_id"`
	Reason     string         `json:"reason"`
	MaskedArgs map[string]any `json:"masked_args"` // null when no rule changed a string
	Epoch      uint64         `json:"epoch"`
	Cached     bool           `json:"cached"`
	LatencyUS  int64          `json:"-"`
}

// Decide answers one request. It never returns an error and never blocks on a
// mutex: cache hit ~100ns, miss goes through singleflight so N identical
// concurrent requests share one eval.
func (e *Engine) Decide(ctx context.Context, in Input) Decision {
	start := time.Now()
	snap := e.store.Current()
	sum := cacheKey(snap.Epoch, in)
	key := hex.EncodeToString(sum[:])

	var d Decision
	if hit, ok := e.cache.Get(key); ok {
		cacheHitsTotal.Inc()
		hit.Cached = true
		d = hit
	} else {
		res, _, shared := e.sf.Do(key, func() (any, error) {
			// Re-check: a flight may have filled the cache between our Get
			// miss and this fn running, which would double-count the miss.
			if hit, ok := e.cache.Get(key); ok {
				return hit, nil
			}
			cacheMissesTotal.Inc()
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
		d.Cached = shared // waiters on a shared flight also skipped a fresh eval
	}

	d.LatencyUS = time.Since(start).Microseconds()
	decisionsTotal.WithLabelValues(metricStage(in.Stage), d.Decision, d.RuleID).Inc()
	policyEpoch.Set(float64(snap.Epoch))
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

// eval runs the prepared query under the eval timeout, maps the Rego decision
// object to a Decision, and applies the key's masking rules to args.
func (e *Engine) eval(ctx context.Context, snap *policy.Snapshot, in Input) Decision {
	evalCtx, cancel := context.WithTimeout(ctx, e.opts.EvalTimeout)
	defer cancel()

	t0 := time.Now()
	rs, err := snap.Query.Eval(evalCtx, rego.EvalInput(regoInput(in)))
	evalDuration.Observe(time.Since(t0).Seconds())

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
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
		Decision: str(val["decision"]),
		RuleID:   str(val["rule_id"]),
		Reason:   str(val["reason"]),
		Epoch:    snap.Epoch,
	}
	if masked, changed := masking.Apply(snap.Maskers[in.KeyID], "args", in.Args); changed {
		if m, ok := masked.(map[string]any); ok {
			d.MaskedArgs = m
		}
	}
	return d
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
	case "llm", "tool":
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
	s, _ := v.(string)
	return s
}
