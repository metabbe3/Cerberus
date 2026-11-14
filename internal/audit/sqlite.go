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
	"sync/atomic"
	"time"

	"github.com/metabbe3/cerberus/internal/masking"
	// pure-Go SQLite driver; registers as "sqlite"
	_ "modernc.org/sqlite"
)

// DefaultRetentionDays is the default retention period in days for SQLite audit daily logs.
const DefaultRetentionDays = 30

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

CREATE TABLE IF NOT EXISTS revisions (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	time       INTEGER,
	author     TEXT,
	summary    TEXT,
	data_json  TEXT
);
CREATE INDEX IF NOT EXISTS idx_revisions_time ON revisions (time);
`

const eventCols = "id, time, stage, key_id, subject, decision, rule_id, reason, epoch, cached, latency_us, args"

const insertStmtSQL = `INSERT INTO events
	(id, time, stage, key_id, subject, decision, rule_id, reason, epoch, cached, latency_us, args)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

type dbManager struct {
	mu                sync.Mutex
	baseDir           string
	origPath          string
	isMemory          bool
	retentionDays     int
	dbs               map[string]*sql.DB   // dayKey "YYYYMMDD" (or "memory") -> *sql.DB (writers)
	readDBs           map[string]*sql.DB   // fileName -> *sql.DB (readers, SetMaxOpenConns=2)
	insertStmts       map[string]*sql.Stmt // dayKey -> *sql.Stmt (cached prepared insert)
	testOpenReadCount atomic.Int64
	testPruneCalls    atomic.Int64
}

func newDBManager(dbPath string, retentionDays int) (*dbManager, error) {
	if retentionDays <= 0 {
		retentionDays = DefaultRetentionDays
	}
	m := &dbManager{
		origPath:      dbPath,
		retentionDays: retentionDays,
		dbs:           make(map[string]*sql.DB),
		readDBs:       make(map[string]*sql.DB),
		insertStmts:   make(map[string]*sql.Stmt),
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

// Test methods for lifecycle verification (scoped per dbManager / Logger instance)

func (m *dbManager) TestResetOpenReadCount() int64 {
	return m.testOpenReadCount.Swap(0)
}

func (m *dbManager) TestGetOpenReadCount() int64 {
	return m.testOpenReadCount.Load()
}

func (m *dbManager) TestGetPruneCalls() int64 {
	return m.testPruneCalls.Load()
}

// TestResetOpenReadCount resets and returns the count of opened read handles for this Logger.
func (l *Logger) TestResetOpenReadCount() int64 {
	if l == nil || l.mgr == nil {
		return 0
	}
	return l.mgr.TestResetOpenReadCount()
}

// TestGetOpenReadCount returns the current count of opened read handles for this Logger.
func (l *Logger) TestGetOpenReadCount() int64 {
	if l == nil || l.mgr == nil {
		return 0
	}
	return l.mgr.TestGetOpenReadCount()
}

// TestGetPruneCalls returns the number of prune calls executed for this Logger.
func (l *Logger) TestGetPruneCalls() int64 {
	if l == nil || l.mgr == nil {
		return 0
	}
	return l.mgr.TestGetPruneCalls()
}

// sqliteDSN appends a busy_timeout pragma to the DSN so readers block up to 2s
// instead of failing instantly with SQLITE_BUSY while a batch writer holds the
// write lock (observed as intermittent empty audit query results).
func sqliteDSN(path string) string {
	if path == ":memory:" {
		return path
	}
	return "file:" + path + "?_pragma=busy_timeout(2000)"
}

// sqliteDSNWriter appends busy_timeout and journal_size_limit (64MB) to writer DSN (E1.5).
func sqliteDSNWriter(path string) string {
	if path == ":memory:" {
		return path
	}
	return "file:" + path + "?_pragma=busy_timeout(2000)&_pragma=journal_size_limit(67108864)"
}

// openSQLiteRead opens an existing daily DB for querying WITHOUT running the
// WAL/schema DDL of openSQLite — those Exec calls take the write lock and can
// themselves trip SQLITE_BUSY against the live writer.
func openSQLiteRead(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return db, nil
}

func openSQLite(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", sqliteDSNWriter(path))
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	if path != ":memory:" {
		_ = os.Chmod(path, 0o640) //nolint:gosec // G302 group-readable for audit ship-out
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil && path != ":memory:" {
		_ = db.Close()
		return nil, fmt.Errorf("audit: journal_mode: %w", err)
	}
	if path != ":memory:" {
		_ = os.Chmod(path, 0o640)        //nolint:gosec // G302 group-readable for audit ship-out
		_ = os.Chmod(path+"-wal", 0o640) //nolint:gosec // G302
		_ = os.Chmod(path+"-shm", 0o640) //nolint:gosec // G302
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: schema: %w", err)
	}
	return db, nil
}

// getDBForFileRead returns an open *sql.DB for the given file name in m.baseDir.
// It checks m.dbs first (for active day writer handles), then m.readDBs cache.
// On cache miss, it opens via openSQLiteRead, sets max open conns to 2, and caches it.
// Callers MUST NOT close the returned *sql.DB.
func (m *dbManager) getDBForFileRead(fn string) (*sql.DB, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Active writer reuse (Guardrail 3)
	if strings.HasPrefix(fn, "audit-") && strings.HasSuffix(fn, ".db") {
		dayKey := strings.TrimSuffix(strings.TrimPrefix(fn, "audit-"), ".db")
		if db, ok := m.dbs[dayKey]; ok {
			return db, nil
		}
	}

	// Historical file read-cache (Guardrail 4)
	if db, ok := m.readDBs[fn]; ok {
		return db, nil
	}

	fullPath := filepath.Join(m.baseDir, fn)
	db, err := openSQLiteRead(fullPath)
	if err != nil {
		return nil, err
	}
	m.testOpenReadCount.Add(1)
	db.SetMaxOpenConns(2)
	m.readDBs[fn] = db
	return db, nil
}

func (m *dbManager) passiveCheckpointOlderDaysLocked(newDayKey string) {
	for k, db := range m.dbs {
		if k != "memory" && k < newDayKey {
			_, _ = db.Exec("PRAGMA wal_checkpoint(PASSIVE)")
		}
	}
}

func (m *dbManager) getDBAndStmtForTime(t time.Time) (*sql.DB, *sql.Stmt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isMemory {
		db := m.dbs["memory"]
		stmt, ok := m.insertStmts["memory"]
		if !ok || stmt == nil {
			var err error
			stmt, err = db.Prepare(insertStmtSQL)
			if err != nil {
				return nil, nil, fmt.Errorf("audit: prepare insert: %w", err)
			}
			m.insertStmts["memory"] = stmt
		}
		return db, stmt, nil
	}

	dayKey := t.UTC().Format("20060102")
	db, ok := m.dbs[dayKey]
	if !ok {
		m.passiveCheckpointOlderDaysLocked(dayKey)

		fileName := fmt.Sprintf("audit-%s.db", dayKey)
		dbPath := filepath.Join(m.baseDir, fileName)
		var err error
		db, err = openSQLite(dbPath)
		if err != nil {
			return nil, nil, err
		}
		m.dbs[dayKey] = db
	}

	stmt, ok := m.insertStmts[dayKey]
	if !ok || stmt == nil {
		var err error
		stmt, err = db.Prepare(insertStmtSQL)
		if err != nil {
			return nil, nil, fmt.Errorf("audit: prepare insert: %w", err)
		}
		m.insertStmts[dayKey] = stmt
	}

	return db, stmt, nil
}

func (m *dbManager) getDBForTime(t time.Time) (*sql.DB, error) {
	db, _, err := m.getDBAndStmtForTime(t)
	return db, err
}

func (m *dbManager) invalidateStmt(dayKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if stmt, ok := m.insertStmts[dayKey]; ok {
		_ = stmt.Close()
		delete(m.insertStmts, dayKey)
	}
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
			db, err := openSQLiteRead(p)
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

func (m *dbManager) insertBatch(ctx context.Context, batch []Event, maskFn func(string) []masking.Rule) error {
	// Masking at-rest: secrets are masked before ever reaching disk
	for i := range batch {
		ev := &batch[i]
		var rules []masking.Rule
		rules = append(rules, defaultMaskRules...)
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
		dayKey := "memory"
		if !m.isMemory {
			dayKey = ev.Time.UTC().Format("20060102")
		}
		groups[dayKey] = append(groups[dayKey], ev)
	}

	for dayKey, group := range groups {
		db, stmt, err := m.getDBAndStmtForTime(group[0].Time)
		if err != nil {
			return err
		}
		if err := insertBatchWithStmt(ctx, db, stmt, group); err != nil {
			m.invalidateStmt(dayKey)
			return err
		}
	}
	return nil
}

func insertBatchWithStmt(ctx context.Context, db *sql.DB, stmt *sql.Stmt, batch []Event) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: begin: %w", err)
	}
	txStmt := tx.StmtContext(ctx, stmt)
	defer func() { _ = txStmt.Close() }()

	for _, ev := range batch {
		args, err := json.Marshal(ev.Args)
		if err != nil {
			args = nil
		}
		//nolint:gosec // G115 nanosecond epoch
		if _, err := txStmt.ExecContext(ctx, ev.ID, ev.Time.UnixNano(), ev.Stage, ev.KeyID, ev.Subject,
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

	var dailyFiles []string
	var hasLegacy bool
	legacyName := filepath.Base(m.origPath)
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".db") {
			dailyFiles = append(dailyFiles, name)
		} else if name == legacyName && !strings.HasPrefix(name, "audit-") {
			hasLegacy = true
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dailyFiles)))
	files := dailyFiles
	if hasLegacy {
		files = append(files, legacyName)
	}

	// Non-nil even when empty so JSON encoding yields [] (not null) —
	// clients (Owl Zod array schemas) fail on null.
	allEvents := []Event{}
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

		db, err := m.getDBForFileRead(fn)
		if err != nil {
			continue
		}
		subFilter := f
		subFilter.Limit = limit - len(allEvents)
		evs, err := queryEvents(ctx, db, subFilter)
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

	m.testPruneCalls.Add(1)

	// Guardrail 1 & E1.5: Passive checkpoint on active writer databases
	for _, db := range m.dbs {
		_, _ = db.Exec("PRAGMA wal_checkpoint(PASSIVE)")
	}

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
			// E1.7 Guard: skip file if dayKey is active in m.dbs OR file mtime < 24h
			if _, active := m.dbs[dateStr]; active {
				continue
			}
			fullPath := filepath.Join(m.baseDir, name)
			if info, err := os.Stat(fullPath); err == nil {
				if time.Since(info.ModTime()) < 24*time.Hour {
					continue
				}
			}

			if stmt, ok := m.insertStmts[dateStr]; ok {
				_ = stmt.Close()
				delete(m.insertStmts, dateStr)
			}
			if db, ok := m.readDBs[name]; ok {
				_ = db.Close()
				delete(m.readDBs, name)
			}
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
	for k, stmt := range m.insertStmts {
		if err := stmt.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(m.insertStmts, k)
	}
	for k, db := range m.dbs {
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(m.dbs, k)
	}
	for k, db := range m.readDBs {
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(m.readDBs, k)
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

	var dailyFiles []string
	var hasLegacy bool
	legacyName := filepath.Base(m.origPath)
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".db") {
			dailyFiles = append(dailyFiles, name)
		} else if name == legacyName && !strings.HasPrefix(name, "audit-") {
			hasLegacy = true
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dailyFiles)))
	files := dailyFiles
	if hasLegacy {
		files = append(files, legacyName)
	}

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

		db, err := m.getDBForFileRead(fn)
		if err != nil {
			continue
		}
		mID, _ := maxEventID(ctx, db)
		if mID > globalMaxID {
			globalMaxID = mID
		}
		_ = queryDenyCounts(ctx, db, since, counts)
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
		err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE key_id = ? AND stage = 'tool' AND decision = 'allow'", keyID).Scan(&count)
		return count, err
	}

	db, err := m.getDBForTime(today)
	if err != nil {
		return 0, err
	}
	var count int64
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE key_id = ? AND stage = 'tool' AND decision = 'allow'", keyID).Scan(&count)
	return count, err
}

func (m *dbManager) countTeamCallsToday(ctx context.Context, teamKeys []string, today time.Time) (int64, error) {
	if len(teamKeys) == 0 {
		return 0, nil
	}
	placeholders := make([]string, len(teamKeys))
	args := make([]any, len(teamKeys))
	for i, k := range teamKeys {
		placeholders[i] = "?"
		args[i] = k
	}
	query := "SELECT COUNT(*) FROM events WHERE key_id IN (" + strings.Join(placeholders, ",") + ") AND stage = 'tool' AND decision = 'allow'"

	if m.isMemory {
		db := m.dbs["memory"]
		if db == nil {
			return 0, nil
		}
		var count int64
		err := db.QueryRowContext(ctx, query, args...).Scan(&count)
		return count, err
	}

	db, err := m.getDBForTime(today)
	if err != nil {
		return 0, err
	}
	var count int64
	err = db.QueryRowContext(ctx, query, args...).Scan(&count)
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
	ev.Epoch = uint64(epoch.Int64) //nolint:gosec // G115 epoch counter
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
	if !f.Until.IsZero() {
		where = append(where, "time < ?")
		qargs = append(qargs, f.Until.UnixNano())
	}
	qargs = append(qargs, limit)

	rows, err := db.QueryContext(ctx,
		"SELECT "+eventCols+" FROM events WHERE "+strings.Join(where, " AND ")+ //nolint:gosec // G202 whitelisted filter cols
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

// Revision represents a historical snapshot of Cerberus policy/data configuration.
type Revision struct {
	ID       int64     `json:"id"`
	Time     time.Time `json:"time"`
	Author   string    `json:"author"`
	Summary  string    `json:"summary"`
	DataJSON string    `json:"data_json,omitempty"`
}

func (m *dbManager) getRevisionsDB() (*sql.DB, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isMemory {
		return m.dbs["memory"], nil
	}

	if db, ok := m.dbs["revisions"]; ok {
		return db, nil
	}

	dbPath := filepath.Join(m.baseDir, "revisions.db")
	db, err := openSQLite(dbPath)
	if err != nil {
		return nil, err
	}
	m.dbs["revisions"] = db
	return db, nil
}

func (m *dbManager) recordRevision(ctx context.Context, author, summary string, dataJSON []byte) (int64, error) {
	db, err := m.getRevisionsDB()
	if err != nil {
		return 0, err
	}
	if author == "" {
		author = "admin"
	}
	now := time.Now().UTC().UnixNano()
	res, err := db.ExecContext(ctx, `INSERT INTO revisions (time, author, summary, data_json) VALUES (?, ?, ?, ?)`, now, author, summary, string(dataJSON))
	if err != nil {
		return 0, fmt.Errorf("audit: insert revision: %w", err)
	}
	return res.LastInsertId()
}

func (m *dbManager) listRevisions(ctx context.Context, limit int) ([]Revision, error) {
	db, err := m.getRevisionsDB()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `SELECT id, time, author, summary, data_json FROM revisions ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list revisions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var revs []Revision
	for rows.Next() {
		var r Revision
		var t int64
		if err := rows.Scan(&r.ID, &t, &r.Author, &r.Summary, &r.DataJSON); err != nil {
			return nil, err
		}
		r.Time = time.Unix(0, t).UTC()
		revs = append(revs, r)
	}
	return revs, rows.Err()
}

func (m *dbManager) getRevision(ctx context.Context, id int64) (*Revision, error) {
	db, err := m.getRevisionsDB()
	if err != nil {
		return nil, err
	}
	row := db.QueryRowContext(ctx, `SELECT id, time, author, summary, data_json FROM revisions WHERE id = ?`, id)
	var r Revision
	var t int64
	if err := row.Scan(&r.ID, &t, &r.Author, &r.Summary, &r.DataJSON); err != nil {
		return nil, err
	}
	r.Time = time.Unix(0, t).UTC()
	return &r, nil
}

// Bucket is one time-slice of a Timeseries result.
type Bucket struct {
	BucketNS int64 `json:"bucket_ns"`
	Allow    int64 `json:"allow"`
	Deny     int64 `json:"deny"`
	Total    int64 `json:"total"`
}

// Timeseries aggregates decision counts into fixed buckets between since and
// until (until exclusive; zero until = now). Buckets are aligned to the
// Unix epoch so consecutive queries stitch seamlessly, and the bucket count
// is capped at 500 so a wide range cannot mint thousands of rows.
func (l *Logger) Timeseries(ctx context.Context, f Filter, buckets int) ([]Bucket, error) {
	if buckets <= 0 || buckets > 500 {
		return nil, fmt.Errorf("audit: buckets must be 1..500")
	}
	since := f.Since
	if since.IsZero() {
		return nil, fmt.Errorf("audit: timeseries requires since")
	}
	until := f.Until
	if until.IsZero() {
		until = time.Now()
	}
	if !until.After(since) {
		return nil, fmt.Errorf("audit: until must be after since")
	}
	width := until.Sub(since).Nanoseconds() / int64(buckets)
	if width < 1 {
		width = 1
	}
	rows, err := l.mgr.queryAggregate(ctx, since, until, width, f)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// queryAggregate runs the grouped COUNT query across the daily files.
func (m *dbManager) queryAggregate(ctx context.Context, since, until time.Time, widthNS int64, f Filter) ([]Bucket, error) {
	where := []string{"time >= ?", "time < ?"}
	qargs := []any{since.UnixNano(), until.UnixNano()}
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

	out := []Bucket{}
	runOne := func(db *sql.DB) error {
		if db == nil {
			return nil
		}
		q := "SELECT ((time - ?) / ?) * ? AS b, " + //nolint:gosec // G202 whitelisted bucket cols
			"SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END), COUNT(*) " +
			"FROM events WHERE " + strings.Join(where, " AND ") + //nolint:gosec // G202 whitelisted filter cols
			" GROUP BY b ORDER BY b"
		rows, err := db.QueryContext(ctx, q, append([]any{since.UnixNano(), widthNS, widthNS}, qargs...)...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var b, allows, total int64
			if err := rows.Scan(&b, &allows, &total); err != nil {
				return err
			}
			out = append(out, Bucket{BucketNS: b, Allow: allows, Deny: total - allows, Total: total})
		}
		return rows.Err()
	}
	if m.isMemory {
		if err := runOne(m.dbs["memory"]); err != nil {
			return nil, fmt.Errorf("audit: timeseries: %w", err)
		}
	} else {
		entries, err := os.ReadDir(m.baseDir)
		if err != nil {
			return nil, fmt.Errorf("audit: read dir: %w", err)
		}
		var dailyFiles []string
		var hasLegacy bool
		legacyName := filepath.Base(m.origPath)
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "audit-") && strings.HasSuffix(name, ".db") {
				dailyFiles = append(dailyFiles, name)
			} else if name == legacyName && !strings.HasPrefix(name, "audit-") {
				hasLegacy = true
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(dailyFiles)))
		files := dailyFiles
		if hasLegacy {
			files = append(files, legacyName)
		}
		for _, fn := range files {
			if strings.HasPrefix(fn, "audit-") && !since.IsZero() {
				dayStr := strings.TrimPrefix(fn, "audit-")
				dayStr = strings.TrimSuffix(dayStr, ".db")
				if t, err := time.Parse("20060102", dayStr); err == nil {
					if t.Add(24 * time.Hour).Before(since) {
						break
					}
				}
			}

			db, err := m.getDBForFileRead(fn)
			if err != nil {
				continue // unreadable day file: skip, don't kill the aggregate
			}
			if err := runOne(db); err != nil {
				// A day-file that exists on disk but whose schema/tables have not
				// been created yet (writer hasn't flushed its first batch) must
				// not abort the aggregate — it is semantically empty.
				continue //nolint:revive // keep scanning remaining day files
			}
		}
	}
	// merge buckets across daily files (same bucket id can appear in 2 files)
	merged := map[int64]Bucket{}
	for _, b := range out {
		if cur, ok := merged[b.BucketNS]; ok {
			cur.Allow += b.Allow
			cur.Deny += b.Deny
			cur.Total += b.Total
			merged[b.BucketNS] = cur
		} else {
			merged[b.BucketNS] = b
		}
	}
	sorted := make([]Bucket, 0, len(merged))
	for _, b := range merged {
		sorted = append(sorted, b)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].BucketNS < sorted[j].BucketNS })
	return sorted, nil
}
