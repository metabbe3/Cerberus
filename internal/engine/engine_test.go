package engine

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	policyDir = "../../policies"
	testData  = "../../policies/testdata/data.json"
)

// recSink records every emitted event for assertions.
type recSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (s *recSink) Emit(ev audit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *recSink) got() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Event(nil), s.events...)
}

func newTestEngine(t *testing.T, sink Sink, opts Options) *Engine {
	t.Helper()
	store, err := policy.NewStore(context.Background(), policyDir, testData)
	if err != nil {
		t.Fatalf("policy.NewStore: %v", err)
	}
	e, err := New(store, sink, opts)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return e
}

func toolInput(keyID, toolCall string, args map[string]any) Input {
	return Input{Stage: "tool", KeyID: keyID, ToolCall: toolCall, Args: args}
}

func TestDecide_AllowFromRego(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{})
	d := e.Decide(context.Background(), toolInput("k-glob", "kubernetes_get_pods", nil))
	if d.Decision != "allow" || d.RuleID != "ai.tool.allow" {
		t.Fatalf("decision = %s/%s, want allow/ai.tool.allow", d.Decision, d.RuleID)
	}
	if d.Epoch != 1 {
		t.Fatalf("Epoch = %d, want 1", d.Epoch)
	}
}

func TestDecide_DenyRestricted(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{})
	d := e.Decide(context.Background(), toolInput("k-glob", "kubernetes_delete_pod", nil))
	if d.Decision != "deny" || d.RuleID != "ai.tool.restricted" {
		t.Fatalf("decision = %s/%s, want deny/ai.tool.restricted", d.Decision, d.RuleID)
	}
}

func TestDecide_MasksArgs(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{})
	d := e.Decide(context.Background(), toolInput("k-glob", "kubernetes_exec",
		map[string]any{"cmd": "use sk-abc and nick@example.com"}))
	want := "use [REDACTED] and ni************om"
	if got, ok := d.MaskedArgs["cmd"].(string); !ok || got != want {
		t.Fatalf("MaskedArgs[cmd] = %q (%T), want %q", d.MaskedArgs["cmd"], d.MaskedArgs["cmd"], want)
	}
}

func TestDecide_NoMaskingYieldsNil(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{})
	d := e.Decide(context.Background(), toolInput("k-open", "bash", map[string]any{"cmd": "sk-abc"}))
	if d.MaskedArgs != nil {
		t.Fatalf("MaskedArgs = %v, want nil (k-open has no masking rules)", d.MaskedArgs)
	}
	if d.RuleID != "ai.tool.allow" {
		t.Fatalf("rule_id = %s, want ai.tool.allow", d.RuleID)
	}
}

func TestDecide_SecondCallCached(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{})
	in := toolInput("k-glob", "kubernetes_get_pods", nil)
	if d := e.Decide(context.Background(), in); d.Cached {
		t.Fatal("first call reported Cached=true, want false")
	}
	if d := e.Decide(context.Background(), in); !d.Cached {
		t.Fatal("second call reported Cached=false, want true")
	}
}

func TestDecide_EpochInvalidatesCache(t *testing.T) {
	ctx := context.Background()
	e := newTestEngine(t, &recSink{}, Options{})
	in := toolInput("k-glob", "kubernetes_get_pods", nil)
	if d := e.Decide(ctx, in); d.Cached {
		t.Fatal("first call cached")
	}
	snap, err := e.store.Reload(ctx)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if snap.Epoch != 2 {
		t.Fatalf("reload Epoch = %d, want 2", snap.Epoch)
	}
	d := e.Decide(ctx, in)
	if d.Cached {
		t.Fatal("call after reload reported Cached=true, want false (epoch invalidates cache)")
	}
	if d.Epoch != 2 {
		t.Fatalf("Epoch = %d, want 2", d.Epoch)
	}
}

func TestDecide_Singleflight(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{})
	in := toolInput("k-glob", "kubernetes_get_pods", nil)

	// Park the leader inside its eval. While parked the LRU is still empty, so
	// any caller that runs its own eval during the park provably missed the
	// cache mid-flight — a delta of 1 is then impossible without singleflight,
	// no matter how the scheduler interleaves the goroutines.
	var evals atomic.Int64
	parked := make(chan struct{})
	release := make(chan struct{})
	e.evalHook = func() {
		if evals.Add(1) == 1 {
			close(parked)
			<-release
		}
	}

	before := testutil.ToFloat64(cacheMissesTotal)
	const n = 100
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			e.Decide(context.Background(), in)
		}()
	}
	close(start)
	<-parked // leader inside eval, cache still empty

	// Release as soon as a second eval is observed (proof a caller missed
	// while the leader was parked), or — only reachable with singleflight,
	// where the other callers sit parked in the flight and nothing observable
	// happens — after a grace period. Fails safe either way.
	deadline := time.After(100 * time.Millisecond)
releaseFlight:
	for evals.Load() < 2 {
		select {
		case <-deadline:
			break releaseFlight
		default:
			time.Sleep(50 * time.Microsecond)
		}
	}
	close(release)
	wg.Wait()

	if delta := testutil.ToFloat64(cacheMissesTotal) - before; delta != 1 {
		t.Fatalf("cache misses delta = %v, want 1 (singleflight collapses concurrent identical calls)", delta)
	}
}

// The singleflight leader that actually ran the eval must report Cached=false
// even when others joined its flight, every waiter that skipped the eval must
// report Cached=true and count as a cache hit, and the one real eval must be
// the only miss — so hits+misses equals decisions.
func TestDecide_SingleflightCachedFlags(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{})
	in := toolInput("k-glob", "kubernetes_get_pods", nil)

	// Park the leader inside its eval so a second identical caller provably
	// joins the flight instead of racing past it.
	parked := make(chan struct{})
	release := make(chan struct{})
	e.evalHook = func() {
		close(parked)
		<-release
	}

	hitBefore := testutil.ToFloat64(cacheHitsTotal)
	missBefore := testutil.ToFloat64(cacheMissesTotal)

	leaderRes := make(chan Decision, 1)
	waiterRes := make(chan Decision, 1)
	go func() { leaderRes <- e.Decide(context.Background(), in) }()
	<-parked // leader inside eval, cache still empty
	go func() { waiterRes <- e.Decide(context.Background(), in) }()
	time.Sleep(20 * time.Millisecond) // let the waiter park inside the flight
	close(release)

	leader := <-leaderRes
	waiter := <-waiterRes
	if leader.Cached {
		t.Errorf("leader that ran the eval reported Cached=true, want false (it did the fresh eval)")
	}
	if !waiter.Cached {
		t.Errorf("flight waiter reported Cached=false, want true (it skipped the eval)")
	}
	if got := testutil.ToFloat64(cacheMissesTotal) - missBefore; got != 1 {
		t.Errorf("cache misses delta = %v, want 1 (only the leader's eval)", got)
	}
	if got := testutil.ToFloat64(cacheHitsTotal) - hitBefore; got != 1 {
		t.Errorf("cache hits delta = %v, want 1 (the waiter skipped the eval)", got)
	}
}

func TestDecide_TimeoutDenies(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{EvalTimeout: 1 * time.Nanosecond})
	d := e.Decide(context.Background(), toolInput("k-glob", "kubernetes_get_pods", nil))
	if d.Decision != "deny" || d.RuleID != "internal.timeout" {
		t.Fatalf("decision = %s/%s, want deny/internal.timeout", d.Decision, d.RuleID)
	}
}

func TestDecide_UnknownStageDenied(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{})
	d := e.Decide(context.Background(), Input{Stage: "unknown_stage", KeyID: "k-glob"})
	if d.Decision != "deny" || d.RuleID != "internal.unknown_stage" {
		t.Fatalf("decision = %s/%s, want deny/internal.unknown_stage", d.Decision, d.RuleID)
	}
}

func TestDecide_CancelledLeaderNotShared(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{})
	in := toolInput("k-glob", "kubernetes_get_pods", nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // leader's client dropped mid-eval
	d := e.Decide(ctx, in)
	if d.Decision != "allow" {
		t.Fatalf("decision = %s/%s, want allow (one client's disconnect must not fail-closed the flight)", d.Decision, d.RuleID)
	}
}

// Deterministic: the eval hook sleeps past the eval budget on the first call
// only, so the first decision is guaranteed internal.timeout and the second is
// guaranteed a fresh, successful eval — a 1ns budget is not deterministic
// (a fast eval can occasionally finish before the deadline check).
func TestDecide_InternalFailureNotCached(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{EvalTimeout: 20 * time.Millisecond})
	var calls atomic.Int32
	e.evalHook = func() {
		if calls.Add(1) == 1 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	in := toolInput("k-glob", "kubernetes_get_pods", nil)
	if d := e.Decide(context.Background(), in); d.RuleID != "internal.timeout" {
		t.Fatalf("first rule_id = %s, want internal.timeout", d.RuleID)
	}
	d := e.Decide(context.Background(), in)
	if d.Cached {
		t.Fatal("second call Cached=true: transient internal.timeout deny was cached for the epoch")
	}
	if d.RuleID != "ai.tool.allow" {
		t.Fatalf("second rule_id = %s, want ai.tool.allow (fresh eval)", d.RuleID)
	}
}

func TestDecide_UnknownStageBoundedMetricLabel(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{})
	e.Decide(context.Background(), Input{Stage: "6ba7b810-9dad-11d1-80b4-00c04fd430c8", KeyID: "k-glob"})

	reg := prometheus.NewRegistry()
	reg.MustRegister(decisionsTotal)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "stage" {
					switch lp.GetValue() {
					case "llm", "tool", "other":
					default:
						t.Fatalf("cerberus_decisions_total has unbounded stage label %q; want llm|tool|other", lp.GetValue())
					}
				}
			}
		}
	}
}

func TestPolicyEpoch_TracksReloadWithoutTraffic(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{})
	if got := testutil.ToFloat64(policyEpoch); got != 1 {
		t.Fatalf("policy epoch = %v, want 1", got)
	}
	snap, err := e.store.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := testutil.ToFloat64(policyEpoch); got != float64(snap.Epoch) {
		t.Fatalf("policy epoch = %v after reload to epoch %d; gauge went stale with no decide traffic", got, snap.Epoch)
	}
}

func TestPolicyEpoch_NeverMovesBackwards(t *testing.T) {
	ctx := context.Background()
	e := newTestEngine(t, &recSink{}, Options{})
	in1 := toolInput("k-glob", "kubernetes_get_pods", nil)
	in2 := toolInput("k-glob", "kubernetes_get_pods", map[string]any{"park": "probe"})

	// Park request A inside its epoch-1 eval, reload to epoch 2, let a full
	// epoch-2 request B finish, then release A: if the gauge is set from a
	// request's own snapshot, A's epilogue drags it back to 1.
	parked := make(chan struct{})
	release := make(chan struct{})
	var evals atomic.Int64
	e.evalHook = func() {
		if evals.Add(1) == 1 {
			close(parked)
			<-release
		}
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); e.Decide(ctx, in1) }()
	<-parked

	snap, err := e.store.Reload(ctx)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	e.Decide(ctx, in2) // epoch-2 traffic: the gauge must land on 2 and stay there
	close(release)
	wg.Wait()

	if got := testutil.ToFloat64(policyEpoch); got != float64(snap.Epoch) {
		t.Fatalf("policy epoch = %v, want %d (gauge moved backwards to a finished request's old snapshot)", got, snap.Epoch)
	}
}

func TestDecide_EmitsAudit(t *testing.T) {
	sink := &recSink{}
	e := newTestEngine(t, sink, Options{})
	e.Decide(context.Background(), Input{Stage: "llm", KeyID: "k-glob", Model: "m1", Prompt: "hello"})
	evs := sink.got()
	if len(evs) != 1 {
		t.Fatalf("sink got %d events, want 1", len(evs))
	}
	if evs[0].RuleID != "ai.llm.allow" {
		t.Fatalf("event rule_id = %s, want ai.llm.allow", evs[0].RuleID)
	}
	if evs[0].Subject != "m1" {
		t.Fatalf("event subject = %q, want %q (Model for llm stage)", evs[0].Subject, "m1")
	}
}

// Mask before persist: the audit event (→ SQLite and the SSE stream) must carry
// the masked args, never the raw secret.
func TestDecide_AuditCarriesMaskedArgsOnly(t *testing.T) {
	sink := &recSink{}
	e := newTestEngine(t, sink, Options{})
	e.Decide(context.Background(), toolInput("k-glob", "kubernetes_exec", map[string]any{"cmd": "use sk-abc123"}))
	evs := sink.got()
	if len(evs) != 1 {
		t.Fatalf("sink got %d events, want 1", len(evs))
	}
	raw, err := json.Marshal(evs[0])
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if strings.Contains(string(raw), "sk-abc123") {
		t.Fatalf("audit event leaks the raw secret: %s", raw)
	}
	if got := evs[0].Args["cmd"]; got != "use [REDACTED]" {
		t.Fatalf("event args.cmd = %v, want %q", got, "use [REDACTED]")
	}
}
