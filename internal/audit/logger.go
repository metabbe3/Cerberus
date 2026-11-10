package audit

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Dropped counts events discarded because the audit channel was full.
var Dropped = promauto.NewCounter(prometheus.CounterOpts{
	Name: "cerberus_audit_dropped_total",
	Help: "Audit events dropped because the channel buffer was full.",
})

// Options configures a Logger. Zero values take the defaults 4096, 256,
// 200ms, 1000.
type Options struct {
	ChanSize   int
	BatchSize  int
	FlushEvery time.Duration
	RingSize   int
}

const subBuffer = 64 // per-subscriber buffer; slow subscriber drops events

// Logger batches Events to SQLite on one background goroutine; that writer
// also maintains the in-memory ring and subscriber fan-out, so Emit stays
// lock-free (hot-path constraint, ADR-0001).
type Logger struct {
	db   *sql.DB
	opts Options
	ch   chan Event

	mu     sync.Mutex
	ring   *ring
	subs   map[int]chan Event
	nextID int

	stop      chan struct{}
	closeOnce sync.Once
	done      chan struct{}
}

// Open creates (or reopens) the SQLite database at dbPath, enables WAL, and
// starts the single writer goroutine. The goroutine stops only via Close: ctx
// (a signal context) is accepted for signature compatibility but ignored, so
// SIGTERM shutdown still flushes pending events.
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

	db, err := openDB(dbPath)
	if err != nil {
		return nil, err
	}
	l := &Logger{
		db:   db,
		opts: opts,
		ch:   make(chan Event, opts.ChanSize),
		ring: newRing(opts.RingSize),
		subs: make(map[int]chan Event),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	go l.run(ctx)
	return l, nil
}

// Emit hands ev to the writer without blocking and without taking Logger.mu:
// only a non-blocking channel send happens here. The writer goroutine updates
// the ring and fans out to subscribers, so decisions on the Engine.Decide hot
// path never serialize behind Recent, Subscribe or a slow SSE fan-out. When
// the channel is full the event is dropped and Dropped increments.
func (l *Logger) Emit(ev Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}

	select {
	case l.ch <- ev:
	default:
		Dropped.Inc()
	}
}

// publish records ev in the ring and delivers it to every subscriber. Called
// only from the writer goroutine. The mu round-trip is fine here: this is the
// single writer, off the request path.
func (l *Logger) publish(ev Event) {
	l.mu.Lock()
	l.ring.add(ev)
	for _, ch := range l.subs {
		select {
		case ch <- ev: // buffered 64; slow subscriber drops
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

// Subscribe registers a buffered-64 channel for every emitted event. A slow
// subscriber drops events rather than blocking Emit. cancel closes the channel.
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

// Filter narrows a Query. Zero fields are ignored; Limit defaults to 100 and
// caps at 1000.
type Filter struct {
	KeyID    string
	Stage    string
	Decision string
	RuleID   string
	Since    time.Time
	Limit    int
}

// Query runs a filtered, newest-first read against SQLite.
func (l *Logger) Query(ctx context.Context, f Filter) ([]Event, error) {
	return queryEvents(ctx, l.db, f)
}

// Close flushes the pending batch, stops the writer goroutine, closes any
// remaining subscriber channels, and closes the DB. Safe to call once.
func (l *Logger) Close() error {
	l.closeOnce.Do(func() { close(l.stop) })
	<-l.done

	l.mu.Lock()
	for id, ch := range l.subs {
		close(ch)
		delete(l.subs, id)
	}
	l.mu.Unlock()

	return l.db.Close()
}

// run is the single writer: it publishes each event to the ring and
// subscribers, accumulates a batch, flushing on size or on the FlushEvery
// tick, and drains-and-flushes on stop. It deliberately ignores the caller's
// ctx: a cancelled ctx would fail the final insert and lose the pending batch
// on every graceful shutdown.
func (l *Logger) run(context.Context) {
	defer close(l.done)
	batch := make([]Event, 0, l.opts.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Background, not the caller's ctx: shutdown must still persist.
		if err := insertBatch(context.Background(), l.db, batch); err != nil {
			slog.Error("audit: batch insert", "error", err)
		}
		batch = batch[:0]
	}
	ticker := time.NewTicker(l.opts.FlushEvery)
	defer ticker.Stop()

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
		case ev := <-l.ch:
			l.publish(ev)
			batch = append(batch, ev)
			if len(batch) >= l.opts.BatchSize {
				flush()
			}
		}
	}
}
