package auth

import (
	"sync"
	"time"
)

const (
	// MaxFailedAttempts adalah batas kegagalan login sebelum lockout sementara.
	MaxFailedAttempts = 5
	// LockoutWindow adalah durasi lockout setelah MaxFailedAttempts tercapai.
	LockoutWindow = 15 * time.Minute
)

type attemptRecord struct {
	count     int
	firstFail time.Time
	lockedAt  time.Time
}

// LockoutManager tracks failed authentication attempts to prevent brute force.
type LockoutManager struct {
	mu       sync.Mutex
	attempts map[string]*attemptRecord
}

// NewLockoutManager creates a new in-memory lockout tracker.
func NewLockoutManager() *LockoutManager {
	return &LockoutManager{
		attempts: make(map[string]*attemptRecord),
	}
}

// Key builds the composite lockout identifier from username and remote IP.
func (lm *LockoutManager) Key(username, ip string) string {
	if ip == "" {
		ip = "127.0.0.1"
	}
	return username + "@" + ip
}

// IsLocked checks if the given key is currently locked out.
func (lm *LockoutManager) IsLocked(key string) bool {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	rec, ok := lm.attempts[key]
	if !ok {
		return false
	}

	if !rec.lockedAt.IsZero() {
		if time.Since(rec.lockedAt) < LockoutWindow {
			return true
		}
		// Lockout expired, clean up
		delete(lm.attempts, key)
		return false
	}

	// Check if window expired for attempts
	if time.Since(rec.firstFail) > LockoutWindow {
		delete(lm.attempts, key)
		return false
	}

	return false
}

// RecordFailure registers a failed login attempt and locks if threshold is reached.
// Returns whether the key is now locked out.
func (lm *LockoutManager) RecordFailure(key string) bool {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	now := time.Now()
	rec, ok := lm.attempts[key]
	if !ok || now.Sub(rec.firstFail) > LockoutWindow {
		lm.attempts[key] = &attemptRecord{
			count:     1,
			firstFail: now,
		}
		return false
	}

	rec.count++
	if rec.count >= MaxFailedAttempts {
		rec.lockedAt = now
		return true
	}

	return false
}

// Clear removes all failed attempts for a key upon successful login.
func (lm *LockoutManager) Clear(key string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	delete(lm.attempts, key)
}
