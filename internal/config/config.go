// Package config resolves Cerberus runtime configuration once at startup:
// env vars CERBERUS_* provide values, lower-kebab flags (-addr, -policy-dir,
// …) of the same name override them.
package config

import (
	"errors"
	"flag"
	"fmt"
	"strconv"
	"time"
)

// Default limits, ceilings, and timeouts across Cerberus.
const (
	DefaultCacheSize      = 10000
	DefaultEvalTimeout    = 10 * time.Millisecond
	DefaultRetentionDays  = 30
	DefaultMaxBodyBytes   = 1 << 20
	MaxBreakGlassDuration = 15 * time.Minute
)

// Config is the resolved runtime configuration. AdminToken must be non-empty
// or Load returns an error (required secret fails startup, CONVENTIONS.md).
type Config struct {
	Addr               string
	PolicyDir          string
	DataFile           string
	AuditDB            string
	AuditRetentionDays int
	ShipURL            string
	AdminToken         string
	PGDSN              string
	LogLevel           string
	CacheSize          int
	EvalTimeout        time.Duration
}

// Load resolves env (via getenv) then flags (args, os.Args[1:] style). Flag >
// env > default. args may be nil.
func Load(args []string, getenv func(string) string) (Config, error) {
	cacheSize, err := envInt(getenv, "CERBERUS_CACHE_SIZE", DefaultCacheSize)
	if err != nil {
		return Config{}, err
	}
	evalTimeout, err := envDuration(getenv, "CERBERUS_EVAL_TIMEOUT", DefaultEvalTimeout)
	if err != nil {
		return Config{}, err
	}
	retentionDays, err := envInt(getenv, "CERBERUS_AUDIT_RETENTION_DAYS", DefaultRetentionDays)
	if err != nil {
		return Config{}, err
	}
	c := Config{
		Addr:               firstNonEmpty(getenv("CERBERUS_ADDR"), ":8089"),
		PolicyDir:          firstNonEmpty(getenv("CERBERUS_POLICY_DIR"), "policies"),
		DataFile:           firstNonEmpty(getenv("CERBERUS_DATA_FILE"), "data/prod.json"),
		AuditDB:            firstNonEmpty(getenv("CERBERUS_AUDIT_DB"), "cerberus.db"),
		PGDSN:              getenv("CERBERUS_PG_DSN"),
		AuditRetentionDays: retentionDays,
		ShipURL:            firstNonEmpty(getenv("CERBERUS_DECISION_LOG_SHIP_URL"), getenv("CERBERUS_SHIP_URL")),
		AdminToken:         getenv("CERBERUS_ADMIN_TOKEN"),
		LogLevel:           firstNonEmpty(getenv("CERBERUS_LOG_LEVEL"), "info"),
		CacheSize:          cacheSize,
		EvalTimeout:        evalTimeout,
	}

	fs := flag.NewFlagSet("cerberus", flag.ContinueOnError)
	fs.StringVar(&c.Addr, "addr", c.Addr, "listen address ($CERBERUS_ADDR)")
	fs.StringVar(&c.PolicyDir, "policy-dir", c.PolicyDir, "Rego bundle directory ($CERBERUS_POLICY_DIR)")
	fs.StringVar(&c.DataFile, "data-file", c.DataFile, "policy data JSON ($CERBERUS_DATA_FILE)")
	fs.StringVar(&c.AuditDB, "audit-db", c.AuditDB, "audit SQLite path ($CERBERUS_AUDIT_DB)")
	fs.StringVar(&c.PGDSN, "pg-dsn", c.PGDSN, "PostgreSQL DSN — system of record for gateway data ($CERBERUS_PG_DSN); empty = flat file only")
	fs.IntVar(&c.AuditRetentionDays, "audit-retention-days", c.AuditRetentionDays, "days to retain daily audit SQLite logs ($CERBERUS_AUDIT_RETENTION_DAYS)")
	fs.StringVar(&c.ShipURL, "ship-url", c.ShipURL, "endpoint for shipping decision logs ($CERBERUS_DECISION_LOG_SHIP_URL)")
	// No -admin-token flag: a secret on argv is readable by any local user via
	// ps or /proc/<pid>/cmdline. The token comes from the environment only.
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "debug|info|warn|error ($CERBERUS_LOG_LEVEL)")
	fs.IntVar(&c.CacheSize, "cache-size", c.CacheSize, "LRU decision cache entries ($CERBERUS_CACHE_SIZE)")
	fs.Func("eval-timeout", "per-eval budget, e.g. 10ms ($CERBERUS_EVAL_TIMEOUT)", func(s string) error {
		d, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		c.EvalTimeout = d
		return nil
	})
	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("config: flags: %w", err)
	}

	if c.AdminToken == "" {
		return Config{}, errors.New("config: CERBERUS_ADMIN_TOKEN is required (env only; never a flag)")
	}
	return c, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func envInt(getenv func(string) string, key string, def int) (int, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	return n, nil
}

func envDuration(getenv func(string) string, key string, def time.Duration) (time.Duration, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	return d, nil
}
