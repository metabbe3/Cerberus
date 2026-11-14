package upstream

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // driver sqlite murni-Go untuk store upstream
)

var (
	// ErrInvalidURL dikembalikan bila endpoint bukan http/https yang valid.
	ErrInvalidURL = errors.New("endpoint URL tidak valid (harus dimulai dengan http:// atau https://)")
	// ErrAPIKeyTooShort dikembalikan bila api key kurang dari 8 karakter.
	ErrAPIKeyTooShort = errors.New("api key minimal 8 karakter")
	// ErrAPIKeyRequired dikembalikan bila api key kosong saat konfigurasi baru.
	ErrAPIKeyRequired = errors.New("api key wajib diisi untuk konfigurasi upstream baru")
	// ErrNoUpstreamConfig dikembalikan bila belum ada konfigurasi upstream tersimpan.
	ErrNoUpstreamConfig = errors.New("konfigurasi upstream belum diatur")
)

// Config represents public metadata of the active LLM upstream.
// The plaintext API key is NEVER exposed in this struct.
type Config struct {
	EndpointURL string    `json:"endpoint"`
	KeyHint     string    `json:"key_hint"`
	UpdatedBy   string    `json:"updated_by"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ActiveTarget contains the decrypted credentials used by cerberus-tap or internal proxies.
type ActiveTarget struct {
	EndpointURL string `json:"endpoint"`
	APIKey      string `json:"api_key"`
}

// Store manages persistence and secure encryption of upstream configuration.
type Store struct {
	mu        sync.RWMutex
	db        *sql.DB
	masterKey []byte
}

// NewStore initializes the upstream config table in SQLite.
func NewStore(db *sql.DB, masterKey []byte) (*Store, error) {
	if len(masterKey) != 32 {
		return nil, ErrInvalidMasterKey
	}
	schema := `
	CREATE TABLE IF NOT EXISTS upstream_config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		endpoint_url TEXT NOT NULL,
		api_key_encrypted TEXT NOT NULL,
		key_hint TEXT NOT NULL,
		updated_by TEXT NOT NULL DEFAULT 'system',
		updated_at TEXT NOT NULL
	);`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("create upstream_config table: %w", err)
	}
	return &Store{
		db:        db,
		masterKey: masterKey,
	}, nil
}

// NewMemoryStore initializes an in-memory upstream store for testing.
func NewMemoryStore(masterKey []byte) (*Store, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	return NewStore(db, masterKey)
}

// GetConfig returns the public metadata of the upstream target. Plaintext key is omitted.
func (s *Store) GetConfig(ctx context.Context) (*Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		endpointURL string
		keyHint     string
		updatedBy   string
		updatedAt   string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT endpoint_url, key_hint, updated_by, updated_at
		FROM upstream_config WHERE id = 1
	`).Scan(&endpointURL, &keyHint, &updatedBy, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query upstream_config: %w", err)
	}

	t, _ := time.Parse(time.RFC3339Nano, updatedAt)
	return &Config{
		EndpointURL: endpointURL,
		KeyHint:     keyHint,
		UpdatedBy:   updatedBy,
		UpdatedAt:   t,
	}, nil
}

// GetActiveTarget returns the decrypted endpoint and api_key for upstream proxying.
func (s *Store) GetActiveTarget(ctx context.Context) (*ActiveTarget, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		endpointURL string
		encrypted   string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT endpoint_url, api_key_encrypted
		FROM upstream_config WHERE id = 1
	`).Scan(&endpointURL, &encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query upstream_config: %w", err)
	}

	rawKey, err := Decrypt(encrypted, s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt upstream api key: %w", err)
	}

	return &ActiveTarget{
		EndpointURL: endpointURL,
		APIKey:      string(rawKey),
	}, nil
}

// SaveConfig validates, encrypts and upserts the upstream config profile.
// If apiKey is empty and an existing config exists, the previous encrypted key and hint are retained.
func (s *Store) SaveConfig(ctx context.Context, endpointURL, apiKey, updatedBy string) (*Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	endpointURL = strings.TrimSpace(endpointURL)
	endpointURL = strings.TrimRight(endpointURL, "/")
	if endpointURL == "" {
		return nil, ErrInvalidURL
	}

	u, err := url.Parse(endpointURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, ErrInvalidURL
	}

	apiKey = strings.TrimSpace(apiKey)
	var (
		encryptedKey string
		keyHint      string
	)

	// Check existing record
	var (
		existingEncrypted string
		existingHint      string
	)
	hasExisting := false
	err = s.db.QueryRowContext(ctx, `
		SELECT api_key_encrypted, key_hint FROM upstream_config WHERE id = 1
	`).Scan(&existingEncrypted, &existingHint)
	if err == nil {
		hasExisting = true
	}

	if apiKey == "" {
		if !hasExisting {
			return nil, ErrAPIKeyRequired
		}
		encryptedKey = existingEncrypted
		keyHint = existingHint
	} else {
		if len(apiKey) < 8 {
			return nil, ErrAPIKeyTooShort
		}
		enc, err := Encrypt([]byte(apiKey), s.masterKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt api key: %w", err)
		}
		encryptedKey = enc
		// Generate hint: last 4 chars
		if len(apiKey) >= 4 {
			keyHint = "sk-..." + apiKey[len(apiKey)-4:]
		} else {
			keyHint = "sk-..."
		}
	}

	if updatedBy == "" {
		updatedBy = "admin"
	}
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339Nano)

	query := `
	INSERT INTO upstream_config (id, endpoint_url, api_key_encrypted, key_hint, updated_by, updated_at)
	VALUES (1, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		endpoint_url = excluded.endpoint_url,
		api_key_encrypted = excluded.api_key_encrypted,
		key_hint = excluded.key_hint,
		updated_by = excluded.updated_by,
		updated_at = excluded.updated_at;
	`
	if _, err := s.db.ExecContext(ctx, query, endpointURL, encryptedKey, keyHint, updatedBy, nowStr); err != nil {
		return nil, fmt.Errorf("upsert upstream_config: %w", err)
	}

	return &Config{
		EndpointURL: endpointURL,
		KeyHint:     keyHint,
		UpdatedBy:   updatedBy,
		UpdatedAt:   now,
	}, nil
}
