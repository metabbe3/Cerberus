package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	// pure-Go SQLite driver; registers as "sqlite"
	_ "modernc.org/sqlite"
)

// ponytail: no retention/vacuum — daily DELETE older than N days when the DB grows past concern
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
`

const eventCols = "id, time, stage, key_id, subject, decision, rule_id, reason, epoch, cached, latency_us, args"

func openDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", dbPath, err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: journal_mode: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: schema: %w", err)
	}
	return db, nil
}

// insertBatch writes one batch inside a single transaction. It is called only
// from the run() goroutine — modernc sqlite serializes writes on one conn.
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
			ev.Decision, ev.RuleID, ev.Reason, int64(ev.Epoch), // #nosec G115 -- epoch is a reload counter, never near MaxInt64
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

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// nullableJSON turns a "null" marshal (nil Args) into SQL NULL.
func nullableJSON(b []byte) any {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return string(b)
}

// scanEvent reads one row. Exported field mapping mirrors the Event struct.
func scanEvent(scan func(...any) error) (Event, error) {
	var ev Event
	var ts, epoch, cached, latency sql.NullInt64
	var args sql.NullString
	if err := scan(&ev.ID, &ts, &ev.Stage, &ev.KeyID, &ev.Subject, &ev.Decision,
		&ev.RuleID, &ev.Reason, &epoch, &cached, &latency, &args); err != nil {
		return Event{}, err
	}
	ev.Time = time.Unix(0, ts.Int64)
	ev.Epoch = uint64(epoch.Int64) // #nosec G115 -- epoch is a reload counter, never negative
	ev.Cached = cached.Int64 == 1
	ev.LatencyUS = latency.Int64
	if args.Valid && args.String != "" {
		if err := json.Unmarshal([]byte(args.String), &ev.Args); err != nil {
			return Event{}, fmt.Errorf("audit: args json: %w", err)
		}
	}
	return ev, nil
}

// queryEvents selects events matching f, newest first. Single reader query —
// WAL keeps it concurrent with the writer.
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
		"SELECT "+eventCols+" FROM events WHERE "+strings.Join(where, " AND ")+ // #nosec G202 -- clause strings are fixed constants; all values bound as parameters
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
