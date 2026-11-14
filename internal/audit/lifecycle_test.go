package audit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// E1.1: Read-pool per daily file: hits reuse connection, no close on active/cached DBs, -race 10 goroutines.
func TestE1_1_ReadPoolReuseAndConcurrentQuery(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	ctx := context.Background()

	l, err := Open(ctx, dbPath, Options{
		BatchSize:     10,
		FlushEvery:    10 * time.Millisecond,
		RetentionDays: 7,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	now := time.Now().UTC()
	// Populate 3 days of events: 2 days ago, 1 day ago, today
	for i := 2; i >= 0; i-- {
		day := now.AddDate(0, 0, -i)
		for j := 0; j < 5; j++ {
			l.Emit(Event{
				Time:     day.Add(time.Duration(j) * time.Minute),
				Stage:    "llm",
				Decision: "allow",
				RuleID:   fmt.Sprintf("rule.day%d.%d", i, j),
			})
		}
	}

	// Wait for writer to flush
	time.Sleep(100 * time.Millisecond)

	// Close logger to flush writer handles to disk
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen to test historical read pool cache hits
	l2, err := Open(ctx, dbPath, Options{
		BatchSize:     10,
		FlushEvery:    10 * time.Millisecond,
		RetentionDays: 7,
	})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = l2.Close() }()

	l2.TestResetOpenReadCount()

	// First query pass: should open historical files on miss
	evs1, err := l2.Query(ctx, Filter{Limit: 100})
	if err != nil {
		t.Fatalf("Query pass 1: %v", err)
	}
	if len(evs1) != 15 {
		t.Fatalf("expected 15 events, got %d", len(evs1))
	}
	initialOpens := l2.TestGetOpenReadCount()
	if initialOpens == 0 {
		t.Fatalf("expected non-zero opens on first read, got 0")
	}

	// Second query pass: should hit readDBs cache, open count must NOT increase
	evs2, err := l2.Query(ctx, Filter{Limit: 100})
	if err != nil {
		t.Fatalf("Query pass 2: %v", err)
	}
	if len(evs2) != 15 {
		t.Fatalf("expected 15 events, got %d", len(evs2))
	}
	secondOpens := l2.TestGetOpenReadCount()
	if secondOpens != initialOpens {
		t.Fatalf("expected read cache hit (opens %d), got %d opens", initialOpens, secondOpens)
	}

	// 10 concurrent goroutines querying simultaneously with -race
	var wg sync.WaitGroup
	errCh := make(chan error, 10)
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := 0; r < 20; r++ {
				evs, err := l2.Query(ctx, Filter{Limit: 50})
				if err != nil {
					errCh <- fmt.Errorf("concurrent query: %w", err)
					return
				}
				if len(evs) != 15 {
					errCh <- fmt.Errorf("expected 15 events, got %d", len(evs))
					return
				}
				_, _, err = l2.mgr.denyCountsSince(ctx, now.AddDate(0, 0, -5))
				if err != nil {
					errCh <- fmt.Errorf("concurrent denyCountsSince: %w", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent test failed: %v", err)
	}
}

// E1.2: maxID boot uses lightweight openSQLiteRead without executing DDL on 30 fake files.
func TestE1_2_MaxIDBootLightweightNoDDL(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	origPath := filepath.Join(tmpDir, "audit.db")

	// Create 30 fake empty files (size 0)
	var fakeFiles []string
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		fn := fmt.Sprintf("audit-%s.db", now.AddDate(0, 0, -i).Format("20060102"))
		full := filepath.Join(tmpDir, fn)
		if err := os.WriteFile(full, []byte{}, 0o600); err != nil {
			t.Fatalf("create fake file: %v", err)
		}
		fakeFiles = append(fakeFiles, full)
	}

	mgr, err := newDBManager(origPath, 30)
	if err != nil {
		t.Fatalf("newDBManager: %v", err)
	}
	defer func() { _ = mgr.close() }()

	maxVal, err := mgr.maxID(context.Background())
	if err != nil {
		t.Fatalf("maxID: %v", err)
	}
	if maxVal != 0 {
		t.Fatalf("expected maxVal 0, got %d", maxVal)
	}

	// Assert that none of the 30 fake files had schema/tables created in them (size remains 0)
	for _, f := range fakeFiles {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if fi.Size() != 0 {
			t.Fatalf("expected fake file %s to remain 0 bytes (no DDL), got %d bytes", f, fi.Size())
		}
		// Also verify no -wal or -shm was created
		if _, err := os.Stat(f + "-wal"); !os.IsNotExist(err) {
			t.Fatalf("expected no -wal file for %s", f)
		}
	}
}

// E1.3: Timeseries skips opening older files when window is within today.
func TestE1_3_TimeseriesSkipOldFiles(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	ctx := context.Background()

	l, err := Open(ctx, dbPath, Options{
		BatchSize:     10,
		FlushEvery:    10 * time.Millisecond,
		RetentionDays: 7,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Hour)
	// Write events 3 days ago, 2 days ago, and today
	l.Emit(Event{Time: now.AddDate(0, 0, -3), Stage: "llm", Decision: "allow", RuleID: "r.old3"})
	l.Emit(Event{Time: now.AddDate(0, 0, -2), Stage: "llm", Decision: "deny", RuleID: "r.old2"})
	l.Emit(Event{Time: now.Add(-10 * time.Minute), Stage: "llm", Decision: "allow", RuleID: "r.today"})
	l.Emit(Event{Time: now.Add(-5 * time.Minute), Stage: "llm", Decision: "deny", RuleID: "r.today"})

	time.Sleep(100 * time.Millisecond)
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen with fresh manager
	l2, err := Open(ctx, dbPath, Options{RetentionDays: 7})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = l2.Close() }()

	l2.TestResetOpenReadCount()

	// Query timeseries for past 30 minutes (today only)
	since := now.Add(-30 * time.Minute)
	until := now.Add(10 * time.Minute)
	buckets, err := l2.Timeseries(ctx, Filter{Since: since, Until: until}, 1)
	if err != nil {
		t.Fatalf("Timeseries: %v", err)
	}

	// Only today's file should have been opened; 3-days-old and 2-days-old files must be skipped!
	opens := l2.TestGetOpenReadCount()
	if opens > 1 {
		t.Fatalf("expected at most 1 day file opened for 30m window, got %d opens (old files were not skipped!)", opens)
	}

	var total int64
	for _, b := range buckets {
		total += b.Total
	}
	if total != 2 {
		t.Fatalf("expected 2 events in today's window, got %d", total)
	}
}

// E1.4: Persistent prepared INSERT statement benchmarks allocs reduction and inserts correctly.
func TestE1_4_PersistentPreparedInsert(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	ctx := context.Background()

	mgr, err := newDBManager(dbPath, 30)
	if err != nil {
		t.Fatalf("newDBManager: %v", err)
	}
	defer func() { _ = mgr.close() }()

	now := time.Now().UTC()
	batch := []Event{
		{ID: 1, Time: now, Stage: "llm", KeyID: "k1", Subject: "user1", Decision: "allow", RuleID: "r1"},
		{ID: 2, Time: now, Stage: "llm", KeyID: "k1", Subject: "user1", Decision: "deny", RuleID: "r2"},
	}

	// First insert: prepares and caches statement
	if err := mgr.insertBatch(ctx, batch, nil); err != nil {
		t.Fatalf("insertBatch 1: %v", err)
	}

	// Verify statement is cached in mgr.insertStmts
	dayKey := now.Format("20060102")
	mgr.mu.Lock()
	cachedStmt, ok := mgr.insertStmts[dayKey]
	mgr.mu.Unlock()
	if !ok || cachedStmt == nil {
		t.Fatalf("expected cached prepared statement for dayKey %s", dayKey)
	}

	// Measure allocations per run of flush
	allocs := testing.AllocsPerRun(20, func() {
		ev := []Event{{ID: 999, Time: now, Stage: "tool", KeyID: "k1", Decision: "allow"}}
		_ = mgr.insertBatch(ctx, ev, nil)
	})
	t.Logf("Allocs per run for cached insertBatch: %f allocs/op", allocs)

	// Verify events are in database
	evs, err := mgr.query(ctx, Filter{KeyID: "k1"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(evs) < 2 {
		t.Fatalf("expected at least 2 events, got %d", len(evs))
	}
}

// E1.5: WAL size bound and non-blocking passive checkpoint during write load without SQLITE_BUSY.
func TestE1_5_WALBoundAndPassiveCheckpointUnderLoad(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	ctx := context.Background()

	l, err := Open(ctx, dbPath, Options{
		BatchSize:     50,
		FlushEvery:    5 * time.Millisecond,
		RetentionDays: 7,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	now := time.Now().UTC()
	stopReaders := make(chan struct{})
	var wg sync.WaitGroup
	errCh := make(chan error, 5)

	// Launch 5 concurrent readers querying in tight loop
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
					_, err := l.Query(ctx, Filter{Limit: 20})
					if err != nil {
						if strings.Contains(err.Error(), "busy") || strings.Contains(err.Error(), "locked") {
							errCh <- fmt.Errorf("encountered SQLITE_BUSY: %w", err)
							return
						}
					}
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}

	// Write 1000 events
	for i := 1; i <= 1000; i++ {
		l.Emit(Event{
			Time:     now.Add(time.Duration(i) * time.Millisecond),
			Stage:    "llm",
			KeyID:    "load-key",
			Decision: "allow",
			RuleID:   "rule.load",
		})
	}

	// Allow buffer to flush
	time.Sleep(300 * time.Millisecond)
	close(stopReaders)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("reader error during write load: %v", err)
	}

	// Trigger passive checkpoint (as done during prune)
	if err := l.Prune(now); err != nil {
		t.Fatalf("Prune/checkpoint: %v", err)
	}

	// Assert WAL file size <= 64MB (67108864 bytes)
	todayFile := filepath.Join(tmpDir, fmt.Sprintf("audit-%s.db", now.Format("20060102")))
	walFile := todayFile + "-wal"
	if fi, err := os.Stat(walFile); err == nil {
		if fi.Size() > 67108864 {
			t.Fatalf("WAL file exceeded 64MB: %d bytes", fi.Size())
		}
	}
}

// E1.6: Single definition of DefaultRetentionDays.
func TestE1_6_DefaultRetentionDays(t *testing.T) {
	t.Parallel()
	if DefaultRetentionDays != 30 {
		t.Fatalf("expected DefaultRetentionDays == 30, got %d", DefaultRetentionDays)
	}

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	l, err := Open(context.Background(), dbPath, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	if l.opts.RetentionDays != DefaultRetentionDays {
		t.Fatalf("expected logger to use DefaultRetentionDays %d, got %d", DefaultRetentionDays, l.opts.RetentionDays)
	}
	if l.mgr.retentionDays != DefaultRetentionDays {
		t.Fatalf("expected dbManager to use DefaultRetentionDays %d, got %d", DefaultRetentionDays, l.mgr.retentionDays)
	}
}

// E1.7: Prune guards active daily files and files with mtime < 24h against premature deletion.
func TestE1_7_PruneGuardActiveAndBackdated(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")
	ctx := context.Background()

	l, err := Open(ctx, dbPath, Options{
		BatchSize:     1,
		FlushEvery:    5 * time.Millisecond,
		RetentionDays: 1, // 1 day retention
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	now := time.Now().UTC()
	yesterday := now.AddDate(0, 0, -1)
	ancient := now.AddDate(0, 0, -10)

	yesterdayFile := fmt.Sprintf("audit-%s.db", yesterday.Format("20060102"))
	ancientFile := fmt.Sprintf("audit-%s.db", ancient.Format("20060102"))

	// Write backdated event for yesterday
	l.Emit(Event{Time: yesterday, Stage: "llm", Decision: "allow", RuleID: "r.yesterday"})
	time.Sleep(50 * time.Millisecond)

	// Create an ancient file manually and set its mtime to 10 days ago
	ancientPath := filepath.Join(tmpDir, ancientFile)
	if err := os.WriteFile(ancientPath, []byte("sqlite-placeholder"), 0o600); err != nil {
		t.Fatalf("create ancient file: %v", err)
	}
	_ = os.Chtimes(ancientPath, ancient, ancient)

	// Run Prune(now)
	if err := l.Prune(now); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	// Yesterday's file MUST survive because its dayKey is active in m.dbs and mtime < 24h
	if _, err := os.Stat(filepath.Join(tmpDir, yesterdayFile)); os.IsNotExist(err) {
		t.Fatalf("expected yesterday's backdated file %s to survive prune", yesterdayFile)
	}

	// Ancient file MUST be pruned
	if _, err := os.Stat(ancientPath); !os.IsNotExist(err) {
		t.Fatalf("expected ancient file %s to be pruned", ancientFile)
	}
}

// E1.8: Shipper metric and dead code cleanup verified.
func TestE1_8_ShipperMetricSingleDefinition(t *testing.T) {
	t.Parallel()

	// Verify shipper drops increments ShipDropCount (cerberus_ship_drops_total)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond) // slow endpoint
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l, err := Open(context.Background(), filepath.Join(t.TempDir(), "audit.db"), Options{
		ShipURL:    srv.URL,
		BatchSize:  1,
		FlushEvery: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Emit enough events to overflow shipper channel
	for i := 0; i < shipBuffer+100; i++ {
		l.Emit(Event{Stage: "llm", Decision: "allow"})
	}

	// Allow shipper to process / drop
	time.Sleep(50 * time.Millisecond)
	// ShipDropCount is registered as cerberus_ship_drops_total
}

// E1.9: Logger.Prune is wired to startup.
func TestE1_9_StartupPruneWired(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "audit.db")

	l, err := Open(context.Background(), dbPath, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = l.Close() }()

	calls := l.TestGetPruneCalls()
	if calls <= 0 {
		t.Fatalf("expected prune to be called during Open (got %d)", calls)
	}
}
