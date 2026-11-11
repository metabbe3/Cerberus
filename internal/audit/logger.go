package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metabbe3/cerberus/internal/masking"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Dropped counts events discarded because the audit channel was full.
var Dropped = promauto.NewCounter(prometheus.CounterOpts{
	Name: "cerberus_audit_dropped_total",
	Help: "Audit events dropped because the channel buffer was full.",
})

// ShipDropCount counts events discarded by the shipper because the shipper queue was full.
var ShipDropCount = promauto.NewCounter(prometheus.CounterOpts{
	Name: "cerberus_ship_drops_total",
	Help: "Audit events dropped by the shipper because the ship queue was full.",
})

// AuditShipDroppedTotal is an alias counter matching Prometheus naming convention.
var AuditShipDroppedTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "cerberus_audit_ship_dropped_total",
	Help: "Audit events dropped by the shipper because the ship queue was full.",
})

var (
	activeLogger atomic.Pointer[Logger]

	auditQueueDepth = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "cerberus_audit_queue_depth",
		Help: "Current number of pending events waiting in the audit channel buffer.",
	}, func() float64 {
		if l := activeLogger.Load(); l != nil {
			return float64(l.QueueDepth())
		}
		return 0
	})
)

// Options configures a Logger.
type Options struct {
	ChanSize      int
	BatchSize     int
	FlushEvery    time.Duration
	RingSize      int
	RetentionDays int                               // SQLite daily log retention in days (default 30)
	ShipURL       string                            // Remote JSON-lines endpoint for decision logs (optional)
	MaskRules     []masking.Rule                    // Extra masking rules applied before persist
	MaskRulesFunc func(keyID string) []masking.Rule // Dynamic per-key masking rules lookup
}

const (
	subBuffer  = 64   // per-subscriber buffer; slow subscriber drops events
	shipBuffer = 1024 // shipper buffer; drops events when remote is slow
)

// Logger batches Events to SQLite on one background goroutine; that writer
// also maintains the in-memory ring and subscriber fan-out, so Emit stays
// lock-free (hot-path constraint, ADR-0001).
type Logger struct {
	mgr       *dbManager
	opts      Options
	ch        chan Event
	shipCh    chan Event
	seq       atomic.Int64
	mu        sync.Mutex
	ring      *ring
	subs      map[int]chan Event
	nextID    int
	maskFn    func(string) []masking.Rule
	stop      chan struct{}
	closeOnce sync.Once
	done      chan struct{}
	shipDone  chan struct{}
}

// Open creates (or reopens) the partitioned SQLite logs at dbPath and starts
// the background writer and shipper goroutines.
func Open(ctx context.Context, dbPath string, opts Options) (*Logger, error) {
	if opts.ChanSize <= 0 {
		opts.ChanSize = 4096
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 256
	}
	if opts.FlushEvery <= 0 {
		opts.FlushEvery = 200 * time.Millisecond
	}
	if opts.RingSize <= 0 {
		opts.RingSize = 1000
	}
	if opts.RetentionDays <= 0 {
		opts.RetentionDays = 30
	}

	mgr, err := newDBManager(dbPath, opts.RetentionDays)
	if err != nil {
		return nil, err
	}
	if dbPath != ":memory:" {
		_ = os.Chmod(dbPath, 0o640)
	}

	maxID, err := mgr.maxID(context.Background())
	if err != nil {
		_ = mgr.close()
		return nil, err
	}

	l := &Logger{
		mgr:    mgr,
		opts:   opts,
		ch:     make(chan Event, opts.ChanSize),
		ring:   newRing(opts.RingSize),
		subs:   make(map[int]chan Event),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		maskFn: opts.MaskRulesFunc,
	}
	l.seq.Store(maxID)

	if opts.ShipURL != "" {
		l.shipCh = make(chan Event, shipBuffer)
		l.shipDone = make(chan struct{})
		go l.runShipper()
	}

	go l.run(ctx)
	activeLogger.Store(l)
	return l, nil
}

// SetMaskRulesFunc updates the dynamic per-key masking rules function.
func (l *Logger) SetMaskRulesFunc(fn func(keyID string) []masking.Rule) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maskFn = fn
}

// Prune triggers pruning of daily partitions older than RetentionDays.
func (l *Logger) Prune(now time.Time) error {
	return l.mgr.prune(now)
}

// Emit hands ev to the writer without blocking and without taking Logger.mu.
func (l *Logger) Emit(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	if ev.ID <= 0 {
		ev.ID = l.seq.Add(1)
	}

	select {
	case l.ch <- ev:
	default:
		Dropped.Inc()
	}

	// Ship-out: fire-and-forget, non-blocking, drop when full
	if l.shipCh != nil {
		select {
		case l.shipCh <- ev:
		default:
			ShipDropCount.Inc()
			AuditShipDroppedTotal.Inc()
		}
	}
}

func (l *Logger) publish(ev Event) {
	l.mu.Lock()
	l.ring.add(ev)
	for _, ch := range l.subs {
		select {
		case ch <- ev:
		default:
		}
	}
	l.mu.Unlock()
}

// Recent returns up to n events from the ring buffer, newest first.
func (l *Logger) Recent(n int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ring.recent(n)
}

// Subscribe registers a buffered-64 channel for every emitted event.
func (l *Logger) Subscribe() (ch <-chan Event, cancel func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := make(chan Event, subBuffer)
	id := l.nextID
	l.nextID++
	l.subs[id] = c
	return c, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if _, ok := l.subs[id]; ok {
			close(l.subs[id])
			delete(l.subs, id)
		}
	}
}

// Filter narrows a Query.
type Filter struct {
	KeyID    string
	Stage    string
	Decision string
	RuleID   string
	Since    time.Time
	Limit    int
}

// Query runs a filtered read against SQLite daily files, newest first.
func (l *Logger) Query(ctx context.Context, f Filter) ([]Event, error) {
	return l.mgr.query(ctx, f)
}

// Erase masks out args for the given decision event ID in SQLite and the ring buffer.
func (l *Logger) Erase(ctx context.Context, id int64) (bool, error) {
	ok, err := l.mgr.erase(ctx, id)
	if err != nil {
		return false, err
	}
	l.mu.Lock()
	l.ring.erase(id)
	l.mu.Unlock()
	return ok, nil
}

// Since returns all events in the ring buffer with ID > lastID in chronological order.
func (l *Logger) Since(lastID int64) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ring.since(lastID)
}

// QueueDepth returns the number of pending events waiting in the audit channel.
func (l *Logger) QueueDepth() int {
	return len(l.ch)
}

// RuleDenyCount records the count of denies attributed to a rule_id.
type RuleDenyCount struct {
	RuleID string `json:"rule_id"`
	Count  int64  `json:"count"`
}

// TopDenies returns the top-N rule_ids by deny count since the given time.
func (l *Logger) TopDenies(ctx context.Context, since time.Time, limit int) ([]RuleDenyCount, error) {
	if limit <= 0 {
		limit = 10
	}
	maxID, counts, err := l.mgr.denyCountsSince(ctx, since)
	if err != nil {
		return nil, err
	}
	if counts == nil {
		counts = make(map[string]int64)
	}

	// Also inspect ring buffer for events emitted after SQLite's maxID
	l.mu.Lock()
	for _, ev := range l.ring.recent(l.opts.RingSize) {
		if ev.ID > maxID && ev.Decision == "deny" && !ev.Time.Before(since) {
			counts[ev.RuleID]++
		}
	}
	l.mu.Unlock()

	result := make([]RuleDenyCount, 0, len(counts))
	for ruleID, count := range counts {
		result = append(result, RuleDenyCount{RuleID: ruleID, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].RuleID < result[j].RuleID
	})
	if len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

// TopDenies24h returns the top-10 rule_ids by deny count in the past 24 hours.
func (l *Logger) TopDenies24h(ctx context.Context, limit int) ([]RuleDenyCount, error) {
	if limit <= 0 {
		limit = 10
	}
	return l.TopDenies(ctx, time.Now().Add(-24*time.Hour), limit)
}

// DailyToolCallsCount returns the number of tool stage events logged today for keyID.
func (l *Logger) DailyToolCallsCount(ctx context.Context, keyID string, today time.Time) (int64, error) {
	if l == nil || l.mgr == nil {
		return 0, nil
	}
	return l.mgr.countToolCallsToday(ctx, keyID, today)
}

// Close flushes pending batches, stops writer & shipper, and closes SQLite.
func (l *Logger) Close() error {
	activeLogger.CompareAndSwap(l, nil)
	l.closeOnce.Do(func() { close(l.stop) })
	<-l.done
	if l.shipDone != nil {
		<-l.shipDone
	}

	l.mu.Lock()
	for id, ch := range l.subs {
		close(ch)
		delete(l.subs, id)
	}
	l.mu.Unlock()

	return l.mgr.close()
}

func (l *Logger) run(context.Context) {
	defer close(l.done)
	batch := make([]Event, 0, l.opts.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		l.mu.Lock()
		maskFn := l.maskFn
		l.mu.Unlock()

		if err := l.mgr.insertBatch(context.Background(), batch, maskFn, l.opts.MaskRules); err != nil {
			slog.Error("audit: batch insert", "error", err)
		}
		batch = batch[:0]
	}
	ticker := time.NewTicker(l.opts.FlushEvery)
	defer ticker.Stop()

	// Hourly ticker for daily prune
	pruneTicker := time.NewTicker(time.Hour)
	defer pruneTicker.Stop()

	for {
		select {
		case <-l.stop:
			for {
				select {
				case ev := <-l.ch:
					l.publish(ev)
					batch = append(batch, ev)
				default:
					flush()
					return
				}
			}
		case <-ticker.C:
			flush()
		case now := <-pruneTicker.C:
			_ = l.mgr.prune(now)
		case ev := <-l.ch:
			l.publish(ev)
			batch = append(batch, ev)
			if len(batch) >= l.opts.BatchSize {
				flush()
			}
		}
	}
}

// runShipper runs the background worker that POSTs batch JSON lines to ship_url with backoff.
func (l *Logger) runShipper() {
	defer close(l.shipDone)
	client := &http.Client{Timeout: 3 * time.Second}
	batch := make([]Event, 0, l.opts.BatchSize)

	sendBatch := func() {
		if len(batch) == 0 {
			return
		}

		var buf bytes.Buffer
		for _, ev := range batch {
			b, err := json.Marshal(ev)
			if err == nil {
				buf.Write(b)
				buf.WriteByte('\n')
			}
		}
		data := buf.Bytes()
		batch = batch[:0]

		// Post with exponential backoff (up to 3 retries, capped delay)
		go func(body []byte) {
			backoff := 50 * time.Millisecond
			for attempt := 0; attempt < 3; attempt++ {
				req, err := http.NewRequest(http.MethodPost, l.opts.ShipURL, bytes.NewReader(body))
				if err != nil {
					return
				}
				req.Header.Set("Content-Type", "application/x-ndjson")
				resp, err := client.Do(req)
				if err == nil {
					_ = resp.Body.Close()
					if resp.StatusCode < 300 {
						return
					}
				}
				time.Sleep(backoff)
				backoff *= 2
			}
			slog.Warn("audit: ship-out failed after retries", "url", l.opts.ShipURL)
		}(data)
	}

	ticker := time.NewTicker(l.opts.FlushEvery)
	defer ticker.Stop()

	for {
		select {
		case <-l.stop:
			for {
				select {
				case ev := <-l.shipCh:
					batch = append(batch, ev)
				default:
					sendBatch()
					return
				}
			}
		case <-ticker.C:
			sendBatch()
		case ev := <-l.shipCh:
			batch = append(batch, ev)
			if len(batch) >= l.opts.BatchSize {
				sendBatch()
			}
		}
	}
}

// RecordRevision stores a historical policy snapshot into SQLite revisions.
func (l *Logger) RecordRevision(ctx context.Context, author, summary string, dataJSON []byte) (int64, error) {
	if l == nil || l.mgr == nil {
		return 0, nil
	}
	return l.mgr.recordRevision(ctx, author, summary, dataJSON)
}

// ListRevisions returns the latest configuration revisions in reverse chronological order.
func (l *Logger) ListRevisions(ctx context.Context, limit int) ([]Revision, error) {
	if l == nil || l.mgr == nil {
		return nil, nil
	}
	return l.mgr.listRevisions(ctx, limit)
}

// GetRevision returns a specific configuration revision by ID.
func (l *Logger) GetRevision(ctx context.Context, id int64) (*Revision, error) {
	if l == nil || l.mgr == nil {
		return nil, nil
	}
	return l.mgr.getRevision(ctx, id)
}
