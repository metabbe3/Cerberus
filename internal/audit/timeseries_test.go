package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestTimeseriesBuckets seeds a temp audit DB with events at known times and
// verifies bucket math: alignment, allow/deny split, and windowing (Until
// exclusive).
func TestTimeseriesBuckets(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(context.Background(), filepath.Join(dir, "audit.db"), Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer l.Close()

	base := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	// 4 allows at t+0h, 2 denies at t+1h, 1 allow at t+2h
	for i := 0; i < 4; i++ {
		l.Emit(Event{Time: base, Stage: "llm", KeyID: "k", Decision: "allow", RuleID: "ai.llm.allow"})
	}
	for i := 0; i < 2; i++ {
		l.Emit(Event{Time: base.Add(time.Hour), Stage: "tool", KeyID: "k", Decision: "deny", RuleID: "shield.cmd.dangerous"})
	}
	l.Emit(Event{Time: base.Add(2 * time.Hour), Stage: "llm", KeyID: "k", Decision: "allow", RuleID: "ai.llm.allow"})

	// The writer is async (channel -> batch -> FlushEvery); poll until the
	// aggregate sees all 7 events so the test never races the flusher.
	var got []Bucket
	for attempt := 0; attempt < 100; attempt++ {
		var err error
		got, err = l.Timeseries(context.Background(), Filter{
			Since: base,
			Until: base.Add(3 * time.Hour),
		}, 3)
		if err != nil {
			t.Fatalf("timeseries: %v", err)
		}
		var total int64
		for _, b := range got {
			total += b.Total
		}
		if total == 7 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 buckets, got %d: %+v", len(got), got)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 buckets, got %d: %+v", len(got), got)
	}
	if got[0].Allow != 4 || got[0].Deny != 0 {
		t.Fatalf("bucket0 = %+v", got[0])
	}
	if got[1].Allow != 0 || got[1].Deny != 2 {
		t.Fatalf("bucket1 = %+v", got[1])
	}
	if got[2].Allow != 1 || got[2].Deny != 0 {
		t.Fatalf("bucket2 = %+v", got[2])
	}

	// Until exclusive: window [0h, 2h) must exclude the t+2h event.
	got2, err := l.Timeseries(context.Background(), Filter{Since: base, Until: base.Add(2 * time.Hour)}, 2)
	if err != nil {
		t.Fatalf("timeseries2: %v", err)
	}
	var total int64
	for _, b := range got2 {
		total += b.Total
	}
	if total != 6 {
		t.Fatalf("until-exclusive: want 6 events, got %d", total)
	}

	// Guard rails.
	if _, err := l.Timeseries(context.Background(), Filter{}, 10); err == nil {
		t.Fatalf("since-required not enforced")
	}
	if _, err := l.Timeseries(context.Background(), Filter{Since: base, Until: base.Add(time.Hour)}, 501); err == nil {
		t.Fatalf("bucket cap not enforced")
	}
}
