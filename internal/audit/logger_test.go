package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The hot path constraint (ADR-0001) says Engine.Decide must take no mutex.
// Emit sits on that path, so it must not acquire Logger.mu: with the lock held
// here, Emit must still return. Before the lock-free fix it serialized on mu
// behind the ring write and subscriber fan-out.
func TestLogger_EmitTakesNoMutex(t *testing.T) {
	t.Parallel()
	l, err := Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"), Options{})
	if err != nil {
		t.Fatalf("audit: Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	l.mu.Lock() // simulate a slow Recent/Subscribe holding the lock
	defer l.mu.Unlock() // LIFO: releases before the deferred Close on failure
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.Emit(Event{Stage: "llm", Decision: "allow"})
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("audit: Emit blocked on Logger.mu; hot path must not take the mutex")
	}
}

func TestLogger_EmitFlushQuery(t *testing.T) {
	t.Parallel()
	db := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()

	l, err := Open(ctx, db, Options{})
	if err != nil {
		t.Fatalf("audit: Open: %v", err)
	}
	for i := range 1000 {
		l.Emit(Event{
			Stage:     "llm",
			KeyID:     fmt.Sprintf("k%d", i%10),
			Subject:   "model",
			Decision:  "allow",
			RuleID:    "ai.model.allow",
			Reason:    "ok",
			Epoch:     3,
			Cached:    i%2 == 0,
			LatencyUS: int64(i),
		})
	}
	if err := l.Close(); err != nil {
		t.Fatalf("audit: Close: %v", err)
	}

	l2, err := Open(ctx, db, Options{})
	if err != nil {
		t.Fatalf("audit: reopen: %v", err)
	}
	defer func() { _ = l2.Close() }()

	evs, err := l2.Query(ctx, Filter{Limit: 1000})
	if err != nil {
		t.Fatalf("audit: Query: %v", err)
	}
	if len(evs) != 1000 {
		t.Fatalf("audit: Query len = %d, want 1000", len(evs))
	}
	// Newest first: the last emitted event has LatencyUS 999.
	if evs[0].LatencyUS != 999 {
		t.Errorf("audit: newest-first violated: evs[0].LatencyUS = %d, want 999", evs[0].LatencyUS)
	}
	if evs[0].Epoch != 3 || evs[0].RuleID != "ai.model.allow" {
		t.Errorf("audit: round-trip mismatch: %+v", evs[0])
	}
}

func TestLogger_FullChannelDrops(t *testing.T) {
	t.Parallel()
	db := filepath.Join(t.TempDir(), "audit.db")

	before := testutil.ToFloat64(Dropped)
	l, err := Open(context.Background(), db, Options{
		ChanSize:   1,
		BatchSize:  1000,
		FlushEvery: time.Hour,
	})
	if err != nil {
		t.Fatalf("audit: Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	start := time.Now()
	for range 100 {
		l.Emit(Event{Stage: "llm", Decision: "deny", RuleID: "ai.model.deny"})
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("audit: Emit blocked for %v, want <= 100ms", elapsed)
	}
	if d := testutil.ToFloat64(Dropped) - before; d <= 0 {
		t.Fatalf("audit: Dropped delta = %v, want > 0", d)
	}
}

func TestLogger_RingRecent(t *testing.T) {
	t.Parallel()
	l, err := Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"), Options{
		RingSize:   3,
		BatchSize:  1000,
		FlushEvery: time.Hour,
	})
	if err != nil {
		t.Fatalf("audit: Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	for i := range 5 {
		l.Emit(Event{Reason: fmt.Sprintf("r%d", i)})
	}
	want := []string{"r4", "r3", "r2"}
	// The writer goroutine fills the ring, so Recent catches up asynchronously.
	var got []Event
	for deadline := time.Now().Add(time.Second); ; {
		got = l.Recent(10)
		if len(got) == len(want) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit: Recent(10) len = %d, want %d", len(got), len(want))
		}
		time.Sleep(time.Millisecond)
	}
	if len(got) != len(want) {
		t.Fatalf("audit: Recent(10) len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i, ev := range got {
		if ev.Reason != want[i] {
			t.Errorf("audit: Recent(10)[%d] = %q, want %q", i, ev.Reason, want[i])
		}
	}
}

func TestLogger_SubscribeReceives(t *testing.T) {
	t.Parallel()
	l, err := Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"), Options{})
	if err != nil {
		t.Fatalf("audit: Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	ch, cancel := l.Subscribe()
	l.Emit(Event{RuleID: "ai.model.deny"})

	select {
	case ev := <-ch:
		if ev.RuleID != "ai.model.deny" {
			t.Errorf("audit: subscribed event RuleID = %q, want ai.model.deny", ev.RuleID)
		}
	case <-time.After(time.Second):
		t.Fatal("audit: no event on subscribed channel within 1s")
	}

	cancel()
	if _, ok := <-ch; ok {
		t.Error("audit: subscribed channel not closed after cancel")
	}
}

// A cancelled context (SIGTERM) must not lose audit events: the writer stops
// only via Close and flushes with a live context.
func TestLogger_CancelledContextKeepsEvents(t *testing.T) {
	t.Parallel()
	db := filepath.Join(t.TempDir(), "audit.db")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before Open, like a ctx already hit by SIGTERM

	l, err := Open(ctx, db, Options{})
	if err != nil {
		t.Fatalf("audit: Open: %v", err)
	}
	const n = 300
	for i := range n {
		l.Emit(Event{Stage: "llm", KeyID: fmt.Sprintf("k%d", i), Decision: "allow"})
	}
	if err := l.Close(); err != nil {
		t.Fatalf("audit: Close: %v", err)
	}

	l2, err := Open(context.Background(), db, Options{})
	if err != nil {
		t.Fatalf("audit: reopen: %v", err)
	}
	defer func() { _ = l2.Close() }()

	evs, err := l2.Query(context.Background(), Filter{Limit: n})
	if err != nil {
		t.Fatalf("audit: Query: %v", err)
	}
	if len(evs) != n {
		t.Fatalf("audit: Query len = %d, want %d; cancelled ctx lost events", len(evs), n)
	}
}

func TestLogger_QueryFilters(t *testing.T) {
	t.Parallel()
	db := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()

	l, err := Open(ctx, db, Options{})
	if err != nil {
		t.Fatalf("audit: Open: %v", err)
	}
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	mid := now.Add(-time.Hour)
	l.Emit(Event{Time: old, KeyID: "k1", Stage: "llm", Decision: "allow", RuleID: "ai.model.allow"})
	l.Emit(Event{Time: mid, KeyID: "k2", Stage: "tool", Decision: "deny", RuleID: "ai.tool.deny"})
	l.Emit(Event{Time: now, KeyID: "k2", Stage: "tool", Decision: "deny", RuleID: "ai.tool.deny"})
	if err := l.Close(); err != nil {
		t.Fatalf("audit: Close: %v", err)
	}

	l2, err := Open(ctx, db, Options{})
	if err != nil {
		t.Fatalf("audit: reopen: %v", err)
	}
	defer func() { _ = l2.Close() }()

	// By RuleID.
	evs, err := l2.Query(ctx, Filter{RuleID: "ai.tool.deny"})
	if err != nil {
		t.Fatalf("audit: Query(RuleID): %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("audit: Query(RuleID) len = %d, want 2", len(evs))
	}
	if evs[0].Time.Before(evs[1].Time) {
		t.Errorf("audit: Query(RuleID) not newest first: %v then %v", evs[0].Time, evs[1].Time)
	}

	// By Since.
	evs, err = l2.Query(ctx, Filter{Since: now.Add(-90 * time.Minute)})
	if err != nil {
		t.Fatalf("audit: Query(Since): %v", err)
	}
	if len(evs) != 2 {
		t.Fatalf("audit: Query(Since) len = %d, want 2", len(evs))
	}
	if evs[0].Time != now.Truncate(time.Second) && evs[0].Time.Sub(now) > time.Second {
		t.Logf("audit: Query(Since) newest event time = %v, emitted at %v", evs[0].Time, now)
	}

	// Default limit applies when unset.
	evs, err = l2.Query(ctx, Filter{})
	if err != nil {
		t.Fatalf("audit: Query(): %v", err)
	}
	if len(evs) != 3 {
		t.Errorf("audit: Query() len = %d, want 3", len(evs))
	}
}
