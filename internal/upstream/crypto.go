// Package upstream menyimpan konfigurasi LLM upstream (endpoint+key) terenkripsi AES-256-GCM.
package upstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
)

var (
	// ErrInvalidMasterKey dikembalikan bila master key tidak 32 byte.
	ErrInvalidMasterKey = errors.New("master key harus 32 byte (AES-256)")
	// ErrInvalidCiphertext dikembalikan bila ciphertext AES-GCM korup atau tidak valid.
	ErrInvalidCiphertext = errors.New("format ciphertext tidak valid")
	// ErrDecryptFailed dikembalikan bila dekripsi gagal (master key salah/data rusak).
	ErrDecryptFailed = errors.New("gagal mendekripsi api key (kunci master tidak sesuai atau data rusak)")
)

// Encrypt encrypts plaintext using AES-256-GCM with a random 12-byte nonce.
// Returns a base64-encoded string: nonce (12 bytes) + ciphertext + tag (16 bytes).
func Encrypt(plaintext, key []byte) (string, error) {
	if len(key) != 32 {
		return "", ErrInvalidMasterKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt decrypts an AES-256-GCM base64-encoded ciphertext using the 32-byte master key.
func Decrypt(ciphertextB64 string, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidMasterKey
	}

	raw, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return plaintext, nil
}

// ResolveMasterKey retrieves or initializes the AES-256 master key.
// Checks env CERBERUS_UPSTREAM_MASTER_KEY; if unset, loads from or generates .upstream.key (0600).
func ResolveMasterKey() ([]byte, error) {
	if envKey := os.Getenv("CERBERUS_UPSTREAM_MASTER_KEY"); envKey != "" {
		// Try hex decode first (64 hex characters = 32 bytes)
		if len(envKey) == 64 {
			if b, err := hex.DecodeString(envKey); err == nil && len(b) == 32 {
				return b, nil
			}
		}
		// Try base64 decode
		if b, err := base64.StdEncoding.DecodeString(envKey); err == nil && len(b) == 32 {
			return b, nil
		}
		// Fallback raw bytes if exactly 32 bytes
		if len(envKey) == 32 {
			return []byte(envKey), nil
		}
		return nil, fmt.Errorf("CERBERUS_UPSTREAM_MASTER_KEY must decode to 32 bytes (got %d chars)", len(envKey))
	}

	keyFile := ".upstream.key"
	if b, err := os.ReadFile(keyFile); err == nil && len(b) == 32 {
		return b, nil
	}

	// Generate once and persist with 0600 permissions
	newKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}

	if err := os.WriteFile(keyFile, newKey, 0600); err != nil {
		return nil, fmt.Errorf("persist master key to %s: %w", keyFile, err)
	}

	slog.Warn("upstream: generated new master key, persisted to .upstream.key (0600)")
	return newKey, nil
}
