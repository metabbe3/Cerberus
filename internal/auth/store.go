package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // driver sqlite murni-Go untuk store auth
)

var (
	// ErrInvalidCredentials dikembalikan bila username/password tidak cocok.
	ErrInvalidCredentials = errors.New("kredensial login tidak valid")
	// ErrUserDisabled dikembalikan bila akun dinonaktifkan admin.
	ErrUserDisabled = errors.New("pengguna dinonaktifkan")
	// ErrUserNotFound dikembalikan bila username tidak terdaftar.
	ErrUserNotFound = errors.New("pengguna tidak ditemukan")
	// ErrUsernameTaken dikembalikan bila username sudah dipakai user lain.
	ErrUsernameTaken = errors.New("username sudah digunakan")
	// ErrSessionExpired dikembalikan bila sesi lewat masa berlaku.
	ErrSessionExpired = errors.New("sesi telah kedaluwarsa")
	// ErrSessionRevoked dikembalikan bila sesi dicabut (logout/admin).
	ErrSessionRevoked = errors.New("sesi telah dicabut")
	// ErrAccountLocked dikembalikan bila lockout aktif setelah kegagalan berulang.
	ErrAccountLocked = errors.New("terlalu banyak percobaan gagal, akun terkunci selama 15 menit")
)

// SessionDuration adalah masa berlaku sesi login Owl.
const SessionDuration = 12 * time.Hour

// Store manages database persistence for users and login sessions.
type Store struct {
	db      *sql.DB
	lockout *LockoutManager
	log     *slog.Logger
}

// Open creates or connects to a SQLite database at the given file path.
func Open(dbPath string) (*Store, error) {
	if dbPath != ":memory:" && !strings.Contains(dbPath, "mode=memory") {
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("auth: create dir %s: %w", dir, err)
		}
	}

	dsn := dbPath
	if dbPath != ":memory:" && !strings.Contains(dbPath, "?") {
		dsn = dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("auth: open db: %w", err)
	}

	return NewStore(db)
}

// NewMemoryStore creates an isolated in-memory auth store for tests.
func NewMemoryStore() (*Store, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("auth: open memory db: %w", err)
	}
	return NewStore(db)
}

// NewStore initializes tables and admin bootstrap on an existing database connection.
func NewStore(db *sql.DB) (*Store, error) {
	s := &Store{
		db:      db,
		lockout: NewLockoutManager(),
		log:     slog.Default().With("component", "auth_store"),
	}

	if err := s.initSchema(context.Background()); err != nil {
		return nil, err
	}

	if err := s.bootstrapAdmin(context.Background()); err != nil {
		s.log.Warn("auth: bootstrap admin check error", "error", err)
	}

	return s, nil
}

func (s *Store) initSchema(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'viewer',
		disabled INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMP NOT NULL,
		last_login_at TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		token_hash TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		expires_at TIMESTAMP NOT NULL,
		revoked_at TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	`
	_, err := s.db.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("auth: init schema: %w", err)
	}
	return nil
}

func (s *Store) bootstrapAdmin(ctx context.Context) error {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil // Users already exist, no seeding needed
	}

	bootstrapPwd := os.Getenv("CERBERUS_ADMIN_BOOTSTRAP_PASSWORD")
	if bootstrapPwd == "" {
		bootstrapPwd = os.Getenv("OWL_PASSWORD")
	}

	if bootstrapPwd == "" {
		// Generate random 16-character password and log once
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		bootstrapPwd = hex.EncodeToString(b) + "A1!"
		s.log.Warn("auth: seeded admin user with bootstrap password", "username", "admin", "bootstrap_password", bootstrapPwd)
	}

	hash, err := HashPasswordWithCost(bootstrapPwd)
	if err != nil {
		return fmt.Errorf("auth: hash bootstrap password: %w", err)
	}

	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?)",
		"admin", hash, RoleAdmin, 0, now,
	)
	if err != nil {
		return fmt.Errorf("auth: insert admin bootstrap user: %w", err)
	}

	s.log.Info("auth: initial admin user successfully bootstrapped", "username", "admin")
	return nil
}

// HashToken computes the SHA-256 digest of a session token for secure lookup.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Authenticate verifies user credentials and issues a new session token.
func (s *Store) Authenticate(ctx context.Context, username, password, remoteIP string) (*User, string, time.Time, error) {
	lockKey := s.lockout.Key(username, remoteIP)
	if s.lockout.IsLocked(lockKey) {
		return nil, "", time.Time{}, ErrAccountLocked
	}

	var u User
	var pwdHash string
	var disabledInt int
	var lastLogin sql.NullTime

	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash, role, disabled, created_at, last_login_at FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &pwdHash, &u.Role, &disabledInt, &u.CreatedAt, &lastLogin)

	if err != nil {
		s.lockout.RecordFailure(lockKey)
		return nil, "", time.Time{}, ErrInvalidCredentials
	}

	u.Disabled = disabledInt == 1
	if u.Disabled {
		return nil, "", time.Time{}, ErrUserDisabled
	}

	if !CheckPassword(password, pwdHash) {
		s.lockout.RecordFailure(lockKey)
		return nil, "", time.Time{}, ErrInvalidCredentials
	}

	// Login succeeded - clear failure counter
	s.lockout.Clear(lockKey)

	// Generate 256-bit random session token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", time.Time{}, fmt.Errorf("generate session token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	tokenHash := HashToken(token)

	now := time.Now().UTC()
	expiresAt := now.Add(SessionDuration)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx,
		"INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
		tokenHash, u.ID, expiresAt,
	)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("save session: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		"UPDATE users SET last_login_at = ? WHERE id = ?",
		now, u.ID,
	)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("update last login: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, "", time.Time{}, err
	}

	u.LastLoginAt = &now
	return &u, token, expiresAt, nil
}

// ValidateSession retrieves the user associated with a valid, non-expired session token.
func (s *Store) ValidateSession(ctx context.Context, token string) (*User, error) {
	tokenHash := HashToken(token)
	now := time.Now().UTC()

	var u User
	var disabledInt int
	var lastLogin sql.NullTime
	var expiresAt time.Time
	var revokedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.role, u.disabled, u.created_at, u.last_login_at, s.expires_at, s.revoked_at
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.token_hash = ?
	`, tokenHash).Scan(
		&u.ID, &u.Username, &u.Role, &disabledInt, &u.CreatedAt, &lastLogin, &expiresAt, &revokedAt,
	)

	if err != nil {
		return nil, ErrSessionExpired
	}

	if revokedAt.Valid {
		return nil, ErrSessionRevoked
	}

	if now.After(expiresAt) {
		return nil, ErrSessionExpired
	}

	u.Disabled = disabledInt == 1
	if u.Disabled {
		return nil, ErrUserDisabled
	}

	if lastLogin.Valid {
		u.LastLoginAt = &lastLogin.Time
	}

	return &u, nil
}

// RevokeSession terminates a session token immediately.
func (s *Store) RevokeSession(ctx context.Context, token string) error {
	tokenHash := HashToken(token)
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		"UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
		now, tokenHash,
	)
	return err
}

// ListUsers returns all users in the system.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, username, role, disabled, created_at, last_login_at FROM users ORDER BY id ASC",
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var users []User
	for rows.Next() {
		var u User
		var disabledInt int
		var lastLogin sql.NullTime
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &disabledInt, &u.CreatedAt, &lastLogin); err != nil {
			return nil, err
		}
		u.Disabled = disabledInt == 1
		if lastLogin.Valid {
			u.LastLoginAt = &lastLogin.Time
		}
		users = append(users, u)
	}

	if users == nil {
		users = []User{}
	}
	return users, rows.Err()
}

// CreateUser registers a new user with a hashed password.
func (s *Store) CreateUser(ctx context.Context, username, password, role string) (*User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("username tidak boleh kosong")
	}

	if role != RoleAdmin && role != RoleViewer {
		return nil, fmt.Errorf("role '%s' tidak valid; harus admin atau viewer", role)
	}

	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, role, disabled, created_at) VALUES (?, ?, ?, ?, ?)",
		username, hash, role, 0, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, ErrUsernameTaken
		}
		return nil, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &User{
		ID:        id,
		Username:  username,
		Role:      role,
		Disabled:  false,
		CreatedAt: now,
	}, nil
}

// SetUserDisabled enables or disables a user account.
func (s *Store) SetUserDisabled(ctx context.Context, id int64, disabled bool) error {
	disabledInt := 0
	if disabled {
		disabledInt = 1
	}

	res, err := s.db.ExecContext(ctx,
		"UPDATE users SET disabled = ? WHERE id = ?",
		disabledInt, id,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUserNotFound
	}

	if disabled {
		// Revoke all sessions for this user
		now := time.Now().UTC()
		_, _ = s.db.ExecContext(ctx, "UPDATE sessions SET revoked_at = ? WHERE user_id = ?", now, id)
	}

	return nil
}

// ResetUserPassword updates a user's password and revokes their existing sessions.
func (s *Store) ResetUserPassword(ctx context.Context, id int64, newPassword string) error {
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		"UPDATE users SET password_hash = ? WHERE id = ?",
		hash, id,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUserNotFound
	}

	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, "UPDATE sessions SET revoked_at = ? WHERE user_id = ?", now, id)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// ChangeOwnPassword memverifikasi password lama lalu mengganti hash user.
// Semua session user DICABUT kecuali token yang sedang dipakai (keepToken).
func (s *Store) ChangeOwnPassword(ctx context.Context, userID int64, currentPassword, newPassword, keepToken string) error {
	if len(newPassword) < 12 {
		return ErrPasswordTooShort
	}
	var hash string
	err := s.db.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE id = ?", userID).Scan(&hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return err
	}
	if !CheckPassword(currentPassword, hash) {
		return ErrInvalidCredentials
	}
	newHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "UPDATE users SET password_hash = ? WHERE id = ?", newHash, userID); err != nil {
		return err
	}
	now := time.Now().UTC()
	keepHash := HashToken(keepToken)
	if _, err := tx.ExecContext(ctx,
		"UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND token_hash != ? AND revoked_at IS NULL",
		now, userID, keepHash); err != nil {
		return err
	}
	return tx.Commit()
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}
