package upstream

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	plaintext := "sk-ant-api03-abcdef1234567890"
	enc, err := Encrypt([]byte(plaintext), key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	dec, err := Decrypt(enc, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(dec) != plaintext {
		t.Fatalf("expected %q, got %q", plaintext, string(dec))
	}

	// Wrong key fails
	wrongKey := make([]byte, 32)
	wrongKey[0] = 0xFF
	if _, err := Decrypt(enc, wrongKey); err == nil {
		t.Fatalf("expected decrypt error with wrong key, got nil")
	}

	// Tampered ciphertext fails
	if _, err := Decrypt("invalid-base64", key); err == nil {
		t.Fatalf("expected decrypt error with invalid base64")
	}
}

func TestUpstreamStore(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 42)
	}

	store, err := NewMemoryStore(key)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}

	// Initially empty
	cfg, err := store.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig on empty store: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config, got %+v", cfg)
	}

	// First save requires key
	_, err = store.SaveConfig(ctx, "https://api.openai.com/v1", "", "admin")
	if err != ErrAPIKeyRequired {
		t.Fatalf("expected ErrAPIKeyRequired, got %v", err)
	}

	// Invalid URL rejected
	_, err = store.SaveConfig(ctx, "ftp://invalid-url.com", "sk-12345678", "admin")
	if err != ErrInvalidURL {
		t.Fatalf("expected ErrInvalidURL, got %v", err)
	}

	// Key < 8 chars rejected
	_, err = store.SaveConfig(ctx, "https://api.openai.com/v1", "short", "admin")
	if err != ErrAPIKeyTooShort {
		t.Fatalf("expected ErrAPIKeyTooShort, got %v", err)
	}

	// Valid save
	saved, err := store.SaveConfig(ctx, "https://api.z.ai/api/anthropic", "sk-live-secret-key-1234", "admin@cerberus")
	if err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	if saved.EndpointURL != "https://api.z.ai/api/anthropic" {
		t.Errorf("expected endpoint %q, got %q", "https://api.z.ai/api/anthropic", saved.EndpointURL)
	}
	if saved.KeyHint != "sk-...1234" {
		t.Errorf("expected hint sk-...1234, got %q", saved.KeyHint)
	}
	if saved.UpdatedBy != "admin@cerberus" {
		t.Errorf("expected updated_by admin@cerberus, got %q", saved.UpdatedBy)
	}

	// GetConfig NEVER returns raw key
	cfg, err = store.GetConfig(ctx)
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}
	if cfg.KeyHint != "sk-...1234" {
		t.Errorf("expected hint sk-...1234, got %q", cfg.KeyHint)
	}

	// GetActiveTarget returns decrypted key
	target, err := store.GetActiveTarget(ctx)
	if err != nil {
		t.Fatalf("GetActiveTarget failed: %v", err)
	}
	if target.APIKey != "sk-live-secret-key-1234" {
		t.Errorf("expected decrypted key sk-live-secret-key-1234, got %q", target.APIKey)
	}

	// Update with empty key retains previous key
	updated, err := store.SaveConfig(ctx, "http://localhost:4000", "", "operator")
	if err != nil {
		t.Fatalf("SaveConfig with empty key failed: %v", err)
	}
	if updated.EndpointURL != "http://localhost:4000" {
		t.Errorf("expected updated endpoint, got %q", updated.EndpointURL)
	}
	if updated.KeyHint != "sk-...1234" {
		t.Errorf("expected preserved hint, got %q", updated.KeyHint)
	}

	// Target key still preserved
	target, err = store.GetActiveTarget(ctx)
	if err != nil {
		t.Fatalf("GetActiveTarget after update failed: %v", err)
	}
	if target.APIKey != "sk-live-secret-key-1234" {
		t.Errorf("expected preserved key, got %q", target.APIKey)
	}
}

func TestResolveMasterKey(t *testing.T) {
	// 1. Env hex
	raw := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Setenv("CERBERUS_UPSTREAM_MASTER_KEY", raw)
	k, err := ResolveMasterKey()
	if err != nil {
		t.Fatalf("ResolveMasterKey from hex: %v", err)
	}
	if hex.EncodeToString(k) != raw {
		t.Fatalf("mismatch hex master key")
	}

	// 2. File fallback
	t.Setenv("CERBERUS_UPSTREAM_MASTER_KEY", "")
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origWd) }()

	k1, err := ResolveMasterKey()
	if err != nil {
		t.Fatalf("ResolveMasterKey generate file: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(k1))
	}

	fi, err := os.Stat(filepath.Join(tmpDir, ".upstream.key"))
	if err != nil {
		t.Fatalf("stat .upstream.key: %v", err)
	}
	// Check file permission 0600
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %o", fi.Mode().Perm())
	}

	// Load existing file
	k2, err := ResolveMasterKey()
	if err != nil {
		t.Fatalf("ResolveMasterKey reload file: %v", err)
	}
	if string(k1) != string(k2) {
		t.Fatalf("key mismatch between generate and reload")
	}
}
