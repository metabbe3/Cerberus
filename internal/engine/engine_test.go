package engine

import (
	"context"
	"sync"
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
	wg.Wait()

	if delta := testutil.ToFloat64(cacheMissesTotal) - before; delta != 1 {
		t.Fatalf("cache misses delta = %v, want 1 (singleflight collapses concurrent identical calls)", delta)
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
	d := e.Decide(context.Background(), Input{Stage: "docker", KeyID: "k-glob"})
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

func TestDecide_InternalFailureNotCached(t *testing.T) {
	e := newTestEngine(t, &recSink{}, Options{EvalTimeout: 1 * time.Nanosecond})
	in := toolInput("k-glob", "kubernetes_get_pods", nil)
	if d := e.Decide(context.Background(), in); d.RuleID != "internal.timeout" {
		t.Fatalf("rule_id = %s, want internal.timeout", d.RuleID)
	}
	if d := e.Decide(context.Background(), in); d.Cached {
		t.Fatal("second call Cached=true: transient internal.timeout deny was cached for the epoch")
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
