// Tests untuk paket auth: hashing Argon2id, sesi, lockout.
package auth

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashAndCheckPassword(t *testing.T) {
	password := "SecretPassword123!"

	// Too short
	_, err := HashPassword("short")
	if err == nil {
		t.Fatalf("expected error for short password")
	}

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !CheckPassword(password, hash) {
		t.Errorf("CheckPassword returned false for valid password")
	}

	if CheckPassword("WrongPassword123!", hash) {
		t.Errorf("CheckPassword returned true for incorrect password")
	}

	// Test bcrypt fallback
	bcHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt generate: %v", err)
	}
	if !CheckPassword(password, string(bcHash)) {
		t.Errorf("CheckPassword failed with bcrypt hash")
	}
}

func TestLockoutManager(t *testing.T) {
	lm := NewLockoutManager()
	key := lm.Key("alice", "10.0.0.1")

	for i := 1; i <= 4; i++ {
		locked := lm.RecordFailure(key)
		if locked {
			t.Fatalf("attempt %d should not lock", i)
		}
		if lm.IsLocked(key) {
			t.Fatalf("IsLocked should be false at attempt %d", i)
		}
	}

	// 5th attempt locks
	locked := lm.RecordFailure(key)
	if !locked {
		t.Fatalf("5th attempt should lock")
	}
	if !lm.IsLocked(key) {
		t.Fatalf("IsLocked should be true after 5 attempts")
	}

	// Clear resets
	lm.Clear(key)
	if lm.IsLocked(key) {
		t.Fatalf("IsLocked should be false after Clear()")
	}
}

func TestStoreUserLifecycle(t *testing.T) {
	ctx := context.Background()
	store, err := NewMemoryStore()
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	defer func() { _ = store.Close() }()

	// 1. Initial admin was bootstrapped
	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Username != "admin" {
		t.Fatalf("expected initial admin user, got %+v", users)
	}

	// 2. Create viewer user
	viewer, err := store.CreateUser(ctx, "bob", "BobPassword1234!", RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if viewer.Role != RoleViewer {
		t.Errorf("viewer.Role = %s, want %s", viewer.Role, RoleViewer)
	}

	// 3. Duplicate username fails
	_, err = store.CreateUser(ctx, "bob", "OtherPassword123!", RoleAdmin)
	if err == nil {
		t.Errorf("expected duplicate username error")
	}

	// 4. Authenticate viewer
	u, token, _, err := store.Authenticate(ctx, "bob", "BobPassword1234!", "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if u.Username != "bob" || token == "" {
		t.Fatalf("invalid auth result: u=%+v, token=%s", u, token)
	}

	// 5. Validate session
	valUser, err := store.ValidateSession(ctx, token)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if valUser.Username != "bob" {
		t.Errorf("valUser.Username = %s, want bob", valUser.Username)
	}

	// 6. Disable user -> session invalidated
	err = store.SetUserDisabled(ctx, viewer.ID, true)
	if err != nil {
		t.Fatalf("SetUserDisabled: %v", err)
	}

	_, err = store.ValidateSession(ctx, token)
	if err == nil {
		t.Errorf("expected error validating session of disabled user")
	}

	_, _, _, err = store.Authenticate(ctx, "bob", "BobPassword1234!", "127.0.0.1")
	if err != ErrUserDisabled {
		t.Errorf("Authenticate disabled user err = %v, want ErrUserDisabled", err)
	}

	// Re-enable
	err = store.SetUserDisabled(ctx, viewer.ID, false)
	if err != nil {
		t.Fatalf("re-enable: %v", err)
	}

	// 7. Reset password
	err = store.ResetUserPassword(ctx, viewer.ID, "NewPasswordBob5678!")
	if err != nil {
		t.Fatalf("ResetUserPassword: %v", err)
	}

	// Old password fails
	_, _, _, err = store.Authenticate(ctx, "bob", "BobPassword1234!", "127.0.0.1")
	if err != ErrInvalidCredentials {
		t.Errorf("old password should fail, got %v", err)
	}

	// New password succeeds
	_, newToken, _, err := store.Authenticate(ctx, "bob", "NewPasswordBob5678!", "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate with new password failed: %v", err)
	}

	// 8. Revoke session (logout)
	err = store.RevokeSession(ctx, newToken)
	if err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	_, err = store.ValidateSession(ctx, newToken)
	if err != ErrSessionRevoked {
		t.Errorf("ValidateSession revoked err = %v, want ErrSessionRevoked", err)
	}
}
