package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metabbe3/cerberus/internal/masking"
	// pure-Go SQLite driver; registers as "sqlite"
	_ "modernc.org/sqlite"
)

var defaultMaskRules, _ = masking.Compile([]masking.Spec{
	{Pattern: `sk-[A-Za-z0-9_\-]+`, Transform: "redact", Scope: ""},
})

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id         INTEGER PRIMARY KEY,
	time       INTEGER,
	stage      TEXT,
	key_id     TEXT,
	subject    TEXT,
	decision   TEXT,
	rule_id    TEXT,
	reason     TEXT,
	epoch      INTEGER,
	cached     INTEGER,
	latency_us INTEGER,
	args       TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events (time);
CREATE INDEX IF NOT EXISTS idx_events_key_id_time ON events (key_id, time);
CREATE INDEX IF NOT EXISTS idx_events_decision_time ON events (decision, time);
`

const eventCols = "id, time, stage, key_id, subject, decision, rule_id, reason, epoch, cached, latency_us, args"

type dbManager struct {
	mu            sync.Mutex
	baseDir       string
	origPath      string
	isMemory      bool
	retentionDays int
	dbs           map[string]*sql.DB // dayKey "YYYYMMDD" -> *sql.DB
}

func newDBManager(dbPath string, retentionDays int) (*dbManager, error) {
	if retentionDays <= 0 {
		retentionDays = 30
	}
	m := &dbManager{
		origPath:      dbPath,
		retentionDays: retentionDays,
		dbs:           make(map[string]*sql.DB),
	}

	if dbPath == ":memory:" {
		m.isMemory = true
		db, err := openSQLite(":memory:")
		if err != nil {
			return nil, err
		}
		m.dbs["memory"] = db
		return m, nil
	}

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o750); err != nil && dir != "." {
		return nil, fmt.Errorf("audit: mkdir %s: %w", dir, err)
	}
	m.baseDir = dir

	// Prune old databases on startup
	_ = m.prune(time.Now().UTC())

	return m, nil
}

func openSQLite(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil && path != ":memory:" {
		_ = db.Close()
		return nil, fmt.Errorf("audit: journal_mode: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: schema: %w", err)
	}
	return db, nil
}

func (m *dbManager) getDBForTime(t time.Time) (*sql.DB, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isMemory {
		return m.dbs["memory"], nil
	}

	dayKey := t.UTC().Format("20060102")
	if db, ok := m.dbs[dayKey]; ok {
		return db, nil
	}

	fileName := fmt.Sprintf("audit-%s.db", dayKey)
	dbPath := filepath.Join(m.baseDir, fileName)
	db, err := openSQLite(dbPath)
	if err != nil {
		return nil, err
	}
	m.dbs[dayKey] = db
	return db, nil
}

func (m *dbManager) maxID(ctx context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isMemory {
		return maxEventID(ctx, m.dbs["memory"])
	}

	var maxVal int64
	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		return 0, nil
	}

	for _, e := range entries {
		name := e.Name()
		if (strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".db")) || name == filepath.Base(m.origPath) {
			p := filepath.Join(m.baseDir, name)
			db, err := openSQLite(p)
			if err != nil {
				continue
			}
			id, err := maxEventID(ctx, db)
			_ = db.Close()
			if err == nil && id > maxVal {
				maxVal = id
			}
		}
	}
	return maxVal, nil
}

func (m *dbManager) insertBatch(ctx context.Context, batch []Event, maskFn func(string) []masking.Rule, extraRules []masking.Rule) error {
	// Masking at-rest: secrets are masked before ever reaching disk
	for i := range batch {
		ev := &batch[i]
		var rules []masking.Rule
		rules = append(rules, defaultMaskRules...)
		rules = append(rules, extraRules...)
		if maskFn != nil {
			rules = append(rules, maskFn(ev.KeyID)...)
		}
		if len(rules) > 0 {
			if masked, changed := masking.Apply(rules, "args", ev.Args); changed {
				if m, ok := masked.(map[string]any); ok {
					ev.Args = m
				}
			}
		}
	}

	// Group events by day
	groups := make(map[string][]Event)
	for _, ev := range batch {
		dayKey := ev.Time.UTC().Format("20060102")
		groups[dayKey] = append(groups[dayKey], ev)
	}

	for _, group := range groups {
		db, err := m.getDBForTime(group[0].Time)
		if err != nil {
			return err
		}
		if err := insertBatch(ctx, db, group); err != nil {
			return err
		}
	}
	return nil
}

func insertBatch(ctx context.Context, db *sql.DB, batch []Event) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: begin: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO events
		(id, time, stage, key_id, subject, decision, rule_id, reason, epoch, cached, latency_us, args)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("audit: prepare: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, ev := range batch {
		args, err := json.Marshal(ev.Args)
		if err != nil {
			args = nil
		}
		if _, err := stmt.ExecContext(ctx, ev.ID, ev.Time.UnixNano(), ev.Stage, ev.KeyID, ev.Subject,
			ev.Decision, ev.RuleID, ev.Reason, int64(ev.Epoch),
			boolInt(ev.Cached), ev.LatencyUS,
			nullableJSON(args)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("audit: insert: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit: %w", err)
	}
	return nil
}

func (m *dbManager) query(ctx context.Context, f Filter) ([]Event, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	if m.isMemory {
		return queryEvents(ctx, m.dbs["memory"], f)
	}

	// Collect daily database files sorted descending (newest first)
	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		return nil, fmt.Errorf("audit: read dir: %w", err)
	}

	var files []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".db") {
			files = append(files, name)
		} else if name == filepath.Base(m.origPath) && !strings.HasPrefix(name, "audit-") {
			files = append(files, name)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(files)))

	var allEvents []Event
	for _, fn := range files {
		// If filtering by Since, check if file is before Since
		if strings.HasPrefix(fn, "audit-") && !f.Since.IsZero() {
			dayStr := strings.TrimPrefix(fn, "audit-")
			dayStr = strings.TrimSuffix(dayStr, ".db")
			if t, err := time.Parse("20060102", dayStr); err == nil {
				// End of day is t + 24 hours
				if t.Add(24 * time.Hour).Before(f.Since) {
					continue
				}
			}
		}

		db, err := openSQLite(filepath.Join(m.baseDir, fn))
		if err != nil {
			continue
		}
		subFilter := f
		subFilter.Limit = limit - len(allEvents)
		evs, err := queryEvents(ctx, db, subFilter)
		_ = db.Close()
		if err != nil {
			continue
		}
		allEvents = append(allEvents, evs...)
		if len(allEvents) >= limit {
			break
		}
	}

	return allEvents, nil
}

func (m *dbManager) erase(ctx context.Context, id int64) (bool, error) {
	if m.isMemory {
		return eraseEvent(ctx, m.dbs["memory"], id)
	}

	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		return false, err
	}

	erased := false
	for _, e := range entries {
		name := e.Name()
		if (strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".db")) || name == filepath.Base(m.origPath) {
			db, err := openSQLite(filepath.Join(m.baseDir, name))
			if err != nil {
				continue
			}
			ok, err := eraseEvent(ctx, db, id)
			_ = db.Close()
			if err == nil && ok {
				erased = true
			}
		}
	}
	return erased, nil
}

func (m *dbManager) prune(now time.Time) error {
	if m.isMemory || m.retentionDays <= 0 || m.baseDir == "" {
		return nil
	}

	cutoff := now.UTC().AddDate(0, 0, -m.retentionDays)
	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "audit-") || !strings.HasSuffix(name, ".db") {
			continue
		}
		dateStr := strings.TrimPrefix(name, "audit-")
		dateStr = strings.TrimSuffix(dateStr, ".db")
		fileDate, err := time.Parse("20060102", dateStr)
		if err != nil {
			continue
		}

		if fileDate.Before(cutoff) {
			if db, ok := m.dbs[dateStr]; ok {
				_ = db.Close()
				delete(m.dbs, dateStr)
			}
			fullPath := filepath.Join(m.baseDir, name)
			_ = os.Remove(fullPath)
			_ = os.Remove(fullPath + "-wal")
			_ = os.Remove(fullPath + "-shm")
			slog.Info("audit: pruned old daily database", "file", name)
		}
	}
	return nil
}

func (m *dbManager) close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	for k, db := range m.dbs {
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(m.dbs, k)
	}
	return firstErr
}

func maxEventID(ctx context.Context, db *sql.DB) (int64, error) {
	var maxID sql.NullInt64
	err := db.QueryRowContext(ctx, "SELECT MAX(id) FROM events").Scan(&maxID)
	if err != nil && !strings.Contains(err.Error(), "no such table") {
		return 0, err
	}
	return maxID.Int64, nil
}

func eraseEvent(ctx context.Context, db *sql.DB, id int64) (bool, error) {
	res, err := db.ExecContext(ctx, `UPDATE events SET args = '{"_erased":true}' WHERE id = ?`, id)
	if err != nil {
		return false, fmt.Errorf("audit: erase: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func queryDenyCounts(ctx context.Context, db *sql.DB, since time.Time, counts map[string]int64) error {
	rows, err := db.QueryContext(ctx, "SELECT rule_id, COUNT(*) FROM events WHERE decision = 'deny' AND time >= ? GROUP BY rule_id", since.UnixNano())
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil
		}
		return fmt.Errorf("audit: query denies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var ruleID string
		var cnt int64
		if err := rows.Scan(&ruleID, &cnt); err != nil {
			return err
		}
		counts[ruleID] += cnt
	}
	return rows.Err()
}

func (m *dbManager) denyCountsSince(ctx context.Context, since time.Time) (int64, map[string]int64, error) {
	counts := make(map[string]int64)
	if m.isMemory {
		db := m.dbs["memory"]
		maxID, err := maxEventID(ctx, db)
		if err != nil {
			return 0, nil, err
		}
		if err := queryDenyCounts(ctx, db, since, counts); err != nil {
			return 0, nil, err
		}
		return maxID, counts, nil
	}

	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		return 0, nil, err
	}

	var files []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".db") {
			files = append(files, name)
		} else if name == filepath.Base(m.origPath) && !strings.HasPrefix(name, "audit-") {
			files = append(files, name)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(files)))

	var globalMaxID int64
	for _, fn := range files {
		if strings.HasPrefix(fn, "audit-") {
			dayStr := strings.TrimPrefix(fn, "audit-")
			dayStr = strings.TrimSuffix(dayStr, ".db")
			if t, err := time.Parse("20060102", dayStr); err == nil {
				if t.Add(24 * time.Hour).Before(since) {
					break
				}
			}
		}

		db, err := openSQLite(filepath.Join(m.baseDir, fn))
		if err != nil {
			continue
		}
		mID, _ := maxEventID(ctx, db)
		if mID > globalMaxID {
			globalMaxID = mID
		}
		_ = queryDenyCounts(ctx, db, since, counts)
		_ = db.Close()
	}
	return globalMaxID, counts, nil
}

func (m *dbManager) countToolCallsToday(ctx context.Context, keyID string, today time.Time) (int64, error) {
	if m.isMemory {
		db := m.dbs["memory"]
		if db == nil {
			return 0, nil
		}
		var count int64
		err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE key_id = ? AND stage = 'tool'", keyID).Scan(&count)
		return count, err
	}

	db, err := m.getDBForTime(today)
	if err != nil {
		return 0, err
	}
	var count int64
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE key_id = ? AND stage = 'tool'", keyID).Scan(&count)
	return count, err
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func nullableJSON(b []byte) any {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return string(b)
}

func scanEvent(scan func(...any) error) (Event, error) {
	var ev Event
	var ts, epoch, cached, latency sql.NullInt64
	var args sql.NullString
	if err := scan(&ev.ID, &ts, &ev.Stage, &ev.KeyID, &ev.Subject, &ev.Decision,
		&ev.RuleID, &ev.Reason, &epoch, &cached, &latency, &args); err != nil {
		return Event{}, err
	}
	ev.Time = time.Unix(0, ts.Int64)
	ev.Epoch = uint64(epoch.Int64)
	ev.Cached = cached.Int64 == 1
	ev.LatencyUS = latency.Int64
	if args.Valid && args.String != "" {
		if err := json.Unmarshal([]byte(args.String), &ev.Args); err != nil {
			return Event{}, fmt.Errorf("audit: args json: %w", err)
		}
	}
	return ev, nil
}

func queryEvents(ctx context.Context, db *sql.DB, f Filter) ([]Event, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	where := []string{"1=1"}
	qargs := []any{}
	add := func(col, val string) {
		if val != "" {
			where = append(where, col+" = ?")
			qargs = append(qargs, val)
		}
	}
	add("key_id", f.KeyID)
	add("stage", f.Stage)
	add("decision", f.Decision)
	add("rule_id", f.RuleID)
	if !f.Since.IsZero() {
		where = append(where, "time >= ?")
		qargs = append(qargs, f.Since.UnixNano())
	}
	qargs = append(qargs, limit)

	rows, err := db.QueryContext(ctx,
		"SELECT "+eventCols+" FROM events WHERE "+strings.Join(where, " AND ")+
			" ORDER BY time DESC, id DESC LIMIT ?", qargs...)
	if err != nil {
		return nil, fmt.Errorf("audit: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []Event{}
	for rows.Next() {
		ev, err := scanEvent(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}
