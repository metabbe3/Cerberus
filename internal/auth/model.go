package auth

import "time"

// Role defines user permissions.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// User represents an authenticated identity in the gateway engine.
type User struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	Role        string     `json:"role"`
	Disabled    bool       `json:"disabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// Session represents an active login token session.
type Session struct {
	TokenHash string     `json:"token_hash"`
	UserID    int64      `json:"user_id"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}
