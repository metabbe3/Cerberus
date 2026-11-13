// Package store mirrors gateway data between the flat data.json file and
// PostgreSQL. The engine keeps its in-memory Snapshot (hot path is eval);
// PG is the system of record when CERBERUS_PG_DSN is set — boot loads from
// PG, and every admin PUT persists to PG (file write stays as backup).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // pgx driver for database/sql
)

// PG is a PostgreSQL mirror of the gateway data document. Every operation is
// logged with its duration so gateway-data changes are traceable end to end.
type PG struct {
	db  *sql.DB
	log *slog.Logger
}

// Open connects using a DSN (postgres://... or pgx://...). Callers must Close.
func Open(ctx context.Context, dsn string) (*PG, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open pg: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetConnMaxIdleTime(2 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping pg: %w", err)
	}
	return &PG{db: db, log: slog.Default().With("component", "pg_store")}, nil
}

// Close releases the connection pool.
func (p *PG) Close() error { return p.db.Close() }

// Ping verifies the connection is alive (used by /v1/health/components).
func (p *PG) Ping(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

// LoadData rebuilds the gateway data document {config, teams, agents,
// blocked_patterns, domains, prod_shield, ssh} from PG tables.
// Missing optional tables degrade to empty values; agents/config are required
// non-empty (same fail-closed contract as decodeData).
func (p *PG) LoadData(ctx context.Context) (map[string]any, error) {
	start := time.Now()
	out, err := p.loadData(ctx)
	if err != nil {
		p.log.Error("pg load_data failed", "err", err, "dur_ms", time.Since(start).Milliseconds())
		return nil, err
	}
	p.log.Info("pg load_data", "agents", len(out["agents"].(map[string]any)), "dur_ms", time.Since(start).Milliseconds())
	return out, nil
}

func (p *PG) loadData(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}

	var cfgJSON string
	err := p.db.QueryRowContext(ctx, `SELECT config FROM gateway_config WHERE id = 1`).Scan(&cfgJSON)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("store: gateway_config row missing")
	} else if err != nil {
		return nil, fmt.Errorf("store: load config: %w", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return nil, fmt.Errorf("store: parse config: %w", err)
	}
	out["config"] = cfg

	agents := map[string]any{}
	rows, err := p.db.QueryContext(ctx, `SELECT key_id, policy FROM agents WHERE enabled`)
	if err != nil {
		return nil, fmt.Errorf("store: load agents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var key, pol string
		if err := rows.Scan(&key, &pol); err != nil {
			return nil, fmt.Errorf("store: scan agent: %w", err)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(pol), &doc); err != nil {
			return nil, fmt.Errorf("store: parse agent %s: %w", key, err)
		}
		agents[key] = doc
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: agents rows: %w", err)
	}
	if len(agents) == 0 {
		return nil, fmt.Errorf("store: no enabled agents in pg")
	}
	out["agents"] = agents

	teams := map[string]any{}
	trows, err := p.db.QueryContext(ctx, `SELECT team_id, policy FROM teams`)
	if err == nil {
		defer func() { _ = trows.Close() }()
		for trows.Next() {
			var id, pol string
			if trows.Scan(&id, &pol) == nil {
				var doc map[string]any
				if json.Unmarshal([]byte(pol), &doc) == nil {
					teams[id] = doc
				}
			}
		}
	}
	out["teams"] = teams

	patterns := []string{}
	prows, err := p.db.QueryContext(ctx, `SELECT pattern FROM blocked_patterns ORDER BY created_at`)
	if err == nil {
		defer func() { _ = prows.Close() }()
		for prows.Next() {
			var pat string
			if prows.Scan(&pat) == nil {
				patterns = append(patterns, pat)
			}
		}
	}
	out["blocked_patterns"] = patterns

	domains := map[string]any{}
	drows, err := p.db.QueryContext(ctx, `SELECT domain, policy FROM domains`)
	if err == nil {
		defer func() { _ = drows.Close() }()
		for drows.Next() {
			var id, pol string
			if drows.Scan(&id, &pol) == nil {
				var doc map[string]any
				if json.Unmarshal([]byte(pol), &doc) == nil {
					domains[id] = doc
				}
			}
		}
	}
	out["domains"] = domains

	var shieldJSON string
	if err := p.db.QueryRowContext(ctx, `SELECT policy FROM prod_shield WHERE id = 1`).Scan(&shieldJSON); err == nil {
		var doc map[string]any
		if json.Unmarshal([]byte(shieldJSON), &doc) == nil {
			out["prod_shield"] = doc
		}
	}
	var sshJSON string
	if err := p.db.QueryRowContext(ctx, `SELECT policy FROM ssh_policy WHERE id = 1`).Scan(&sshJSON); err == nil {
		var doc map[string]any
		if json.Unmarshal([]byte(sshJSON), &doc) == nil {
			out["ssh"] = doc
		}
	}
	return out, nil
}

// SaveData persists a full gateway data document to PG in one transaction
// (delete+insert tables it owns; upsert singletons). Agents absent from the
// document are disabled, not deleted — audit history keeps key_ids stable.
func (p *PG) SaveData(ctx context.Context, data map[string]any) error {
	start := time.Now()
	err := p.saveData(ctx, data)
	if err != nil {
		p.log.Error("pg save_data failed", "err", err, "dur_ms", time.Since(start).Milliseconds())
		return err
	}
	agents, _ := data["agents"].(map[string]any)
	p.log.Info("pg save_data", "agents", len(agents), "dur_ms", time.Since(start).Milliseconds())
	return nil
}

func (p *PG) saveData(ctx context.Context, data map[string]any) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	cfg, _ := json.Marshal(data["config"])
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO gateway_config (id, config, updated_at) VALUES (1, $1, now())
		ON CONFLICT (id) DO UPDATE SET config = EXCLUDED.config, updated_at = now()`, string(cfg)); err != nil {
		return fmt.Errorf("store: save config: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `UPDATE agents SET enabled = false`); err != nil {
		return fmt.Errorf("store: disable agents: %w", err)
	}
	agents, _ := data["agents"].(map[string]any)
	for key, raw := range agents {
		doc, _ := raw.(map[string]any)
		if doc == nil {
			continue
		}
		name := key
		if n, ok := doc["name"].(string); ok && n != "" {
			name = n
		}
		pol := map[string]any{}
		for k, v := range doc {
			if k != "name" && k != "team_id" && k != "team" && k != "enabled" {
				pol[k] = v
			}
		}
		polJSON, _ := json.Marshal(pol)
		team, _ := doc["team_id"].(string)
		if team == "" {
			team, _ = doc["team"].(string)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO agents (key_id, name, team_id, policy, enabled, updated_at)
			VALUES ($1, $2, NULLIF($3,''), $4, true, now())
			ON CONFLICT (key_id) DO UPDATE SET name = EXCLUDED.name, team_id = EXCLUDED.team_id, policy = EXCLUDED.policy, enabled = true, updated_at = now()`,
			key, name, team, string(polJSON)); err != nil {
			return fmt.Errorf("store: save agent %s: %w", key, err)
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM teams`); err != nil {
		return fmt.Errorf("store: clear teams: %w", err)
	}
	teams, _ := data["teams"].(map[string]any)
	for id, raw := range teams {
		doc, _ := raw.(map[string]any)
		polJSON, _ := json.Marshal(doc)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO teams (team_id, name, policy) VALUES ($1, $1, $2)
			ON CONFLICT (team_id) DO UPDATE SET policy = EXCLUDED.policy, updated_at = now()`, id, string(polJSON)); err != nil {
			return fmt.Errorf("store: save team %s: %w", id, err)
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM blocked_patterns`); err != nil {
		return fmt.Errorf("store: clear patterns: %w", err)
	}
	if pats, ok := data["blocked_patterns"].([]any); ok {
		for _, raw := range pats {
			pat, _ := raw.(string)
			if pat == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO blocked_patterns (pattern) VALUES ($1) ON CONFLICT DO NOTHING`, pat); err != nil {
				return fmt.Errorf("store: save pattern: %w", err)
			}
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM domains`); err != nil {
		return fmt.Errorf("store: clear domains: %w", err)
	}
	if doms, ok := data["domains"].(map[string]any); ok {
		for id, raw := range doms {
			polJSON, _ := json.Marshal(raw)
			if _, err := tx.ExecContext(ctx, `INSERT INTO domains (domain, policy) VALUES ($1, $2) ON CONFLICT (domain) DO UPDATE SET policy = EXCLUDED.policy`, id, string(polJSON)); err != nil {
				return fmt.Errorf("store: save domain %s: %w", id, err)
			}
		}
	}

	if shield, ok := data["prod_shield"].(map[string]any); ok {
		polJSON, _ := json.Marshal(shield)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO prod_shield (id, policy, updated_at) VALUES (1, $1, now())
			ON CONFLICT (id) DO UPDATE SET policy = EXCLUDED.policy, updated_at = now()`, string(polJSON)); err != nil {
			return fmt.Errorf("store: save prod_shield: %w", err)
		}
	}
	if ssh, ok := data["ssh"].(map[string]any); ok {
		polJSON, _ := json.Marshal(ssh)
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ssh_policy (id, policy, updated_at) VALUES (1, $1, now())
			ON CONFLICT (id) DO UPDATE SET policy = EXCLUDED.policy, updated_at = now()`, string(polJSON)); err != nil {
			return fmt.Errorf("store: save ssh_policy: %w", err)
		}
	}

	return tx.Commit()
}

// ListTemplates returns wizard templates (builtin first, then custom).
func (p *PG) ListTemplates(ctx context.Context) ([]map[string]any, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT template_id, name, description, stage, policy, builtin FROM templates ORDER BY builtin DESC, created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: list templates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []map[string]any
	for rows.Next() {
		var id, name, desc, stage, pol string
		var builtin bool
		if err := rows.Scan(&id, &name, &desc, &stage, &pol, &builtin); err != nil {
			return nil, err
		}
		var polDoc map[string]any
		_ = json.Unmarshal([]byte(pol), &polDoc)
		out = append(out, map[string]any{
			"id": id, "name": name, "description": desc, "stage": stage,
			"policy": polDoc, "builtin": builtin,
		})
	}
	return out, rows.Err()
}

// UpsertTemplate inserts or updates a custom wizard template.
func (p *PG) UpsertTemplate(ctx context.Context, id, name, desc, stage string, policy map[string]any) error {
	start := time.Now()
	polJSON, _ := json.Marshal(policy)
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO templates (template_id, name, description, stage, policy, builtin, updated_at)
		VALUES ($1, $2, $3, $4, $5, false, now())
		ON CONFLICT (template_id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, stage = EXCLUDED.stage, policy = EXCLUDED.policy, updated_at = now()`,
		id, name, desc, stage, string(polJSON))
	if err != nil {
		p.log.Error("pg upsert_template failed", "id", id, "err", err)
		return fmt.Errorf("store: upsert template: %w", err)
	}
	p.log.Info("pg upsert_template", "id", id, "stage", stage, "dur_ms", time.Since(start).Milliseconds())
	return nil
}

// DeleteTemplate removes a custom template (builtins are protected).
func (p *PG) DeleteTemplate(ctx context.Context, id string) error {
	start := time.Now()
	res, err := p.db.ExecContext(ctx, `DELETE FROM templates WHERE template_id = $1 AND NOT builtin`, id)
	if err != nil {
		p.log.Error("pg delete_template failed", "id", id, "err", err)
		return fmt.Errorf("store: delete template: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("store: template %s not found or builtin", id)
	}
	p.log.Info("pg delete_template", "id", id, "dur_ms", time.Since(start).Milliseconds())
	return nil
}
