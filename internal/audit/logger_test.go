package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	l.mu.Lock()         // simulate a slow Recent/Subscribe holding the lock
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

func TestLogger_EraseAndSince(t *testing.T) {
	t.Parallel()
	db := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()

	l, err := Open(ctx, db, Options{BatchSize: 1, FlushEvery: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("audit: Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	l.Emit(Event{Stage: "llm", Decision: "allow", Args: map[string]any{"secret": "sensitive1"}})
	l.Emit(Event{Stage: "llm", Decision: "deny", Args: map[string]any{"secret": "sensitive2"}})

	var recent []Event
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		recent = l.Recent(2)
		if len(recent) == 2 {
			break
		}
	}
	if len(recent) != 2 {
		t.Fatalf("Recent len = %d, want 2", len(recent))
	}
	idToErase := recent[0].ID
	if idToErase <= 0 {
		t.Fatalf("Event ID = %d, want > 0", idToErase)
	}

	// Erase requires the event to be flushed to SQLite; the ring may show it
	// before the async flush lands, so poll until the erase takes effect.
	var ok bool
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		ok, err = l.Erase(ctx, idToErase)
		if err != nil {
			t.Fatalf("Erase(%d) err=%v", idToErase, err)
		}
		if ok {
			break
		}
	}
	if !ok {
		t.Fatalf("Erase(%d) not persisted after 5s (async flush lag)", idToErase)
	}

	// Verify erased in ring
	ringEvs := l.Recent(2)
	var foundErased bool
	for _, e := range ringEvs {
		if e.ID == idToErase {
			if e.Args["_erased"] != true {
				t.Fatalf("ring event not erased: %+v", e.Args)
			}
			foundErased = true
		}
	}
	if !foundErased {
		t.Fatalf("erased event %d not found in ring", idToErase)
	}

	// Verify Since
	sinceEvs := l.Since(recent[1].ID)
	if len(sinceEvs) != 1 || sinceEvs[0].ID != idToErase {
		t.Fatalf("Since(%d) = %+v, want 1 event with ID %d", recent[1].ID, sinceEvs, idToErase)
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
		if len(got) == len(want) && got[0].Reason == want[0] {
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
	// Exactly the mid and now events, newest first, times round-tripped
	// (stored at the DB's precision — compare within a millisecond).
	for i, want := range []time.Time{now, mid} {
		if d := evs[i].Time.Sub(want); d > time.Millisecond || d < -time.Millisecond {
			t.Fatalf("audit: Query(Since)[%d].Time = %v, want %v", i, evs[i].Time, want)
		}
		if evs[i].KeyID != "k2" {
			t.Fatalf("audit: Query(Since)[%d].KeyID = %q, want k2 (the old k1 event is before Since)", i, evs[i].KeyID)
		}
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

// Sprint 2B - 1. Masking at-rest: secrets never land on disk
func TestLogger_MaskingAtRest(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	ctx := context.Background()

	l, err := Open(ctx, dbPath, Options{
		BatchSize:  1,
		FlushEvery: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	secretKey := "sk-abc1234567890def"
	l.Emit(Event{
		Stage:    "tool",
		KeyID:    "k-open",
		Subject:  "bash",
		Decision: "allow",
		RuleID:   "ai.tool.allow",
		Reason:   "ok",
		Args: map[string]any{
			"cmd":        fmt.Sprintf("use %s to authenticate", secretKey),
			"auth_token": secretKey,
		},
	})

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 1. Verify secrets never landed in SQLite files on disk
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(tmpDir, e.Name())) //nolint:gosec // G304 test temp dir
		if err != nil {
			continue
		}
		if bytes.Contains(raw, []byte(secretKey)) {
			t.Fatalf("secret leaked at-rest in %s: found raw secret %s", e.Name(), secretKey)
		}
	}

	// 2. Query audit and verify returned value is [REDACTED]
	l2, err := Open(ctx, dbPath, Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = l2.Close() }()

	evs, err := l2.Query(ctx, Filter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("len(evs) = %d, want 1", len(evs))
	}
	cmdVal, _ := evs[0].Args["cmd"].(string)
	if cmdVal != "use [REDACTED] to authenticate" {
		t.Fatalf("args.cmd = %q, want %q", cmdVal, "use [REDACTED] to authenticate")
	}
	tokenVal, _ := evs[0].Args["auth_token"].(string)
	if tokenVal != "[REDACTED]" {
		t.Fatalf("args.auth_token = %q, want [REDACTED]", tokenVal)
	}
}

// Sprint 2B - 2. Rotation & disk cap: daily partition audit-YYYYMMDD.db + prune >N days
func TestLogger_DailyPartitionAndPruning(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	ctx := context.Background()

	l, err := Open(ctx, dbPath, Options{
		BatchSize:     1,
		FlushEvery:    10 * time.Millisecond,
		RetentionDays: 7, // 7 days retention
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	now := time.Now().UTC()
	oldTime := now.AddDate(0, 0, -10) // 10 days ago (past retention limit)

	// Emit one event today
	l.Emit(Event{
		Time:     now,
		Stage:    "llm",
		Decision: "allow",
		RuleID:   "rule.today",
	})

	// Emit one event 10 days ago
	l.Emit(Event{
		Time:     oldTime,
		Stage:    "llm",
		Decision: "allow",
		RuleID:   "rule.old",
	})

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	todayFileName := fmt.Sprintf("audit-%s.db", now.Format("20060102"))
	oldFileName := fmt.Sprintf("audit-%s.db", oldTime.Format("20060102"))

	// Check both files exist before pruning
	if _, err := os.Stat(filepath.Join(tmpDir, todayFileName)); err != nil {
		t.Fatalf("expected today's file %s to exist: %v", todayFileName, err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, oldFileName)); err != nil {
		t.Fatalf("expected old file %s to exist: %v", oldFileName, err)
	}

	// Trigger prune
	l2, err := Open(ctx, dbPath, Options{RetentionDays: 7})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := l2.Prune(now); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	defer func() { _ = l2.Close() }()

	// Old file should be pruned, today's file should remain
	if _, err := os.Stat(filepath.Join(tmpDir, oldFileName)); !os.IsNotExist(err) {
		t.Fatalf("expected old file %s to be pruned", oldFileName)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, todayFileName)); err != nil {
		t.Fatalf("expected today's file %s to remain: %v", todayFileName, err)
	}
}

// Sprint 2B - 3. Ship-out: POST batch JSON lines (fire-and-forget, drop when full)
func TestLogger_ShipOut(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	ctx := context.Background()

	var receivedLines []string
	var mu sync.Mutex

	// Mock server receiving ship-out JSON lines
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		mu.Lock()
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				receivedLines = append(receivedLines, line)
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	l, err := Open(ctx, dbPath, Options{
		BatchSize:  5,
		FlushEvery: 50 * time.Millisecond,
		ShipURL:    ts.URL,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	for i := range 10 {
		l.Emit(Event{
			Stage:    "tool",
			KeyID:    fmt.Sprintf("k-%d", i),
			Decision: "allow",
			RuleID:   "ai.tool.allow",
		})
	}

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Give a moment for asynchronous post to finish
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(receivedLines)
		mu.Unlock()
		if count >= 10 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	count := len(receivedLines)
	mu.Unlock()
	if count < 10 {
		t.Fatalf("received %d shipped events, want at least 10", count)
	}

	// Verify each line is valid JSON
	mu.Lock()
	firstLine := receivedLines[0]
	mu.Unlock()
	var ev Event
	if err := json.Unmarshal([]byte(firstLine), &ev); err != nil {
		t.Fatalf("line is not valid JSON: %v", err)
	}
}

func TestLogger_TopDenies24h(t *testing.T) {
	ctx := context.Background()
	dbDir := t.TempDir()
	dbPath := filepath.Join(dbDir, "audit.db")

	l, err := Open(ctx, dbPath, Options{
		BatchSize:  2,
		FlushEvery: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	now := time.Now()

	// Layer 1: Happy path - emit deny events across multiple rule_ids
	// rule-a: 5 denies
	// rule-b: 3 denies
	// rule-c: 1 deny
	// rule-d: 1 allow (must NOT be counted)
	for range 5 {
		l.Emit(Event{Time: now, Stage: "tool", KeyID: "k1", Decision: "deny", RuleID: "shield.cmd.dangerous"})
	}
	for range 3 {
		l.Emit(Event{Time: now, Stage: "tool", KeyID: "k1", Decision: "deny", RuleID: "ai.tool.deny"})
	}
	l.Emit(Event{Time: now, Stage: "docker", KeyID: "k1", Decision: "deny", RuleID: "docker.privileged"})
	l.Emit(Event{Time: now, Stage: "tool", KeyID: "k1", Decision: "allow", RuleID: "ai.tool.allow"})

	// Give writer a moment to flush to SQLite
	var top []RuleDenyCount
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		top, _ = l.TopDenies24h(ctx, 10)
		// Poll until fully settled: length alone can reach 3 while async
		// flush is still writing (counts off-by-one). Wait for exact counts.
		if len(top) == 3 && top[0].Count == 5 && top[1].Count == 3 && top[2].Count == 1 {
			break
		}
	}
	if len(top) != 3 {
		t.Fatalf("TopDenies24h len = %d, want 3: %+v", len(top), top)
	}
	if top[0].RuleID != "shield.cmd.dangerous" || top[0].Count != 5 {
		t.Errorf("top[0] = %+v, want shield.cmd.dangerous with count 5", top[0])
	}
	if top[1].RuleID != "ai.tool.deny" || top[1].Count != 3 {
		t.Errorf("top[1] = %+v, want ai.tool.deny with count 3", top[1])
	}
	if top[2].RuleID != "docker.privileged" || top[2].Count != 1 {
		t.Errorf("top[2] = %+v, want docker.privileged with count 1", top[2])
	}

	// Layer 2: Tamper / boundary - events older than 24h must be excluded
	oldTime := now.Add(-25 * time.Hour)
	l.Emit(Event{Time: oldTime, Stage: "tool", KeyID: "k1", Decision: "deny", RuleID: "old.rule"})
	time.Sleep(50 * time.Millisecond)

	topAfterOld, err := l.TopDenies24h(ctx, 10)
	if err != nil {
		t.Fatalf("TopDenies24h after old: %v", err)
	}
	for _, item := range topAfterOld {
		if item.RuleID == "old.rule" {
			t.Fatalf("found old.rule in TopDenies24h: %+v", item)
		}
	}

	// Layer 3: Limit enforcement (e.g. top 2)
	top2, err := l.TopDenies24h(ctx, 2)
	if err != nil {
		t.Fatalf("TopDenies24h(limit 2): %v", err)
	}
	if len(top2) != 2 {
		t.Fatalf("TopDenies24h(limit 2) len = %d, want 2", len(top2))
	}
}

func TestLogger_Revisions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l, err := Open(ctx, filepath.Join(t.TempDir(), "audit.db"), Options{})
	if err != nil {
		t.Fatalf("audit: Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	// 1. Record revision with secret in data_json -> must be masked
	dataWithSecret := []byte(`{"agents":{"k1":{"secret":"sk-1234567890abcdef"}}}`)
	id1, err := l.RecordRevision(ctx, "admin-1", "added k1", dataWithSecret)
	if err != nil {
		t.Fatalf("RecordRevision 1: %v", err)
	}
	if id1 <= 0 {
		t.Fatalf("id1 = %d, want > 0", id1)
	}

	id2, err := l.RecordRevision(ctx, "admin-2", "updated k1", []byte(`{"agents":{"k1":{"active":true}}}`))
	if err != nil {
		t.Fatalf("RecordRevision 2: %v", err)
	}

	// 2. List revisions: newest first
	revs, err := l.ListRevisions(ctx, 10)
	if err != nil {
		t.Fatalf("ListRevisions: %v", err)
	}
	if len(revs) != 2 {
		t.Fatalf("ListRevisions len = %d, want 2", len(revs))
	}
	if revs[0].ID != id2 || revs[1].ID != id1 {
		t.Fatalf("unexpected order: revs[0].ID=%d, revs[1].ID=%d", revs[0].ID, revs[1].ID)
	}
	if revs[0].Author != "admin-2" || revs[1].Author != "admin-1" {
		t.Fatalf("unexpected authors: %+v", revs)
	}

	// 3. Get single revision & check secret masking at-rest
	r1, err := l.GetRevision(ctx, id1)
	if err != nil {
		t.Fatalf("GetRevision 1: %v", err)
	}
	if strings.Contains(r1.DataJSON, "sk-1234567890abcdef") {
		t.Fatalf("secret leaked in revision data_json: %s", r1.DataJSON)
	}
	if !strings.Contains(r1.DataJSON, "[REDACTED]") {
		t.Fatalf("secret not redacted in revision data_json: %s", r1.DataJSON)
	}
}

func TestLogger_FilePermissions(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")

	l, err := Open(ctx, dbPath, Options{
		BatchSize:  1,
		FlushEvery: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	l.Emit(Event{
		Stage:    "tool",
		KeyID:    "k-test",
		Decision: "allow",
		RuleID:   "ai.tool.allow",
	})
	_ = l.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected db files created in %s", dir)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatalf("Info: %v", err)
		}
		perm := info.Mode().Perm()
		// Permissions must not grant other (world) read/write/execute
		if perm&0o007 != 0 {
			t.Fatalf("file %s has insecure permissions %04o (expected 0640/0600)", e.Name(), perm)
		}
	}
}
