package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrPasswordTooShort dikembalikan bila password tidak memenuhi kebijakan minimum 12 karakter.
	ErrPasswordTooShort = errors.New("kata sandi minimal 12 karakter")
	// ErrInvalidHash dikembalikan bila format hash tersimpan tidak valid.
	ErrInvalidHash = errors.New("format hash password tidak valid")
)

// Standard Argon2id parameters (RFC 9106 recommended minimum for interactive logins)
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPasswordWithCost hashes a plaintext password without length check (for bootstrap seeds).
func HashPasswordWithCost(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Standard Argon2id format: $argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64Salt, b64Hash)

	return encoded, nil
}

// HashPassword hashes a plaintext password using Argon2id with minimum 12-char validation.
func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", ErrPasswordTooShort
	}
	return HashPasswordWithCost(password)
}

// CheckPassword verifies a plaintext password against an Argon2id or bcrypt hash.
func CheckPassword(password, encodedHash string) bool {
	if strings.HasPrefix(encodedHash, "$2a$") || strings.HasPrefix(encodedHash, "$2b$") || strings.HasPrefix(encodedHash, "$2y$") {
		// Bcrypt fallback compatibility
		return bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password)) == nil
	}

	if !strings.HasPrefix(encodedHash, "$argon2id$") {
		return false
	}

	parts := strings.Split(encodedHash, "$")
	// Expected parts: ["", "argon2id", "v=19", "m=65536,t=1,p=4", "<salt>", "<hash>"]
	if len(parts) != 6 {
		return false
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}

	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	expectedLen := uint32(0)
	if len(expectedHash) > 0 && len(expectedHash) <= int(^uint32(0)>>1) {
		expectedLen = uint32(len(expectedHash)) // #nosec G115 -- panjang di-clamp: 0 < len <= MaxInt32
	}
	hash := argon2.IDKey([]byte(password), salt, time, memory, threads, expectedLen) // #nosec G115 -- expectedLen di-clamp eksplisit di atas

	return subtle.ConstantTimeCompare(hash, expectedHash) == 1
}
