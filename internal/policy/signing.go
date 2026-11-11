package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	// ErrInvalidSignature is returned when bundle signature verification fails.
	ErrInvalidSignature = errors.New("bundle: invalid signature")
	// ErrMissingSignature is returned when a signed bundle is required but signatures.json is missing.
	ErrMissingSignature = errors.New("bundle: missing signatures.json")
)

// FileDigest represents an entry in the signatures manifest.
type FileDigest struct {
	Name      string `json:"name"`
	Hash      string `json:"hash"`
	Algorithm string `json:"algorithm"`
}

// SignHeader is the JWT header for bundle signatures.
type SignHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// SignPayload is the JWT payload containing file hashes.
type SignPayload struct {
	Files []FileDigest `json:"files"`
}

// SignaturesFile is the structure of signatures.json.
type SignaturesFile struct {
	Signatures []string     `json:"signatures"`
	Files      []FileDigest `json:"files,omitempty"`
	Signature  string       `json:"signature,omitempty"`
}

// ParsePrivateKey loads an Ed25519 private key from PEM, hex, base64, or raw bytes.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	trimmed := strings.TrimSpace(string(data))
	// Try PEM decode first
	if block, _ := pem.Decode(data); block != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
		}
		if priv, ok := key.(ed25519.PrivateKey); ok {
			return priv, nil
		}
		return nil, errors.New("PEM key is not ed25519.PrivateKey")
	}

	// Try hex decode
	if h, err := hex.DecodeString(trimmed); err == nil {
		if len(h) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(h), nil
		}
		if len(h) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(h), nil
		}
	}

	// Try base64 decode
	if b, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		if len(b) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(b), nil
		}
		if len(b) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(b), nil
		}
	}

	// Try raw bytes
	if len(data) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(data), nil
	}
	if len(data) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(data), nil
	}

	return nil, errors.New("unrecognized ed25519 private key format")
}

// ParsePublicKey loads an Ed25519 public key from PEM, hex, base64, or raw bytes.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(string(data))
	// Try PEM decode first
	if block, _ := pem.Decode(data); block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}
		if p, ok := pub.(ed25519.PublicKey); ok {
			return p, nil
		}
		return nil, errors.New("PEM key is not ed25519.PublicKey")
	}

	// Try hex decode
	if h, err := hex.DecodeString(trimmed); err == nil && len(h) == ed25519.PublicKeySize {
		return ed25519.PublicKey(h), nil
	}

	// Try base64 decode
	if b, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}

	// Try raw bytes
	if len(data) == ed25519.PublicKeySize {
		return ed25519.PublicKey(data), nil
	}

	return nil, errors.New("unrecognized ed25519 public key format")
}

// ComputeFileDigests computes sha256 digests for files, skipping signature files.
func ComputeFileDigests(files map[string][]byte) []FileDigest {
	names := make([]string, 0, len(files))
	for name := range files {
		clean := strings.TrimPrefix(name, "/")
		clean = strings.TrimPrefix(clean, "./")
		if clean == "signatures.json" || clean == ".signatures.json" ||
			strings.HasSuffix(clean, "/signatures.json") || strings.HasSuffix(clean, "/.signatures.json") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	digests := make([]FileDigest, 0, len(names))
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		digests = append(digests, FileDigest{
			Name:      name,
			Hash:      hex.EncodeToString(sum[:]),
			Algorithm: "SHA-256",
		})
	}
	return digests
}

// SignBundle generates signatures.json content for files signed with privKey.
func SignBundle(files map[string][]byte, privKey ed25519.PrivateKey) ([]byte, error) {
	digests := ComputeFileDigests(files)

	header := SignHeader{Alg: "EdDSA", Typ: "JWT"}
	payload := SignPayload{Files: digests}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	encHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := encHeader + "." + encPayload

	sig := ed25519.Sign(privKey, []byte(signingInput))
	jwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	sf := SignaturesFile{
		Signatures: []string{jwt},
		Files:      digests,
		Signature:  base64.RawURLEncoding.EncodeToString(sig),
	}

	return json.MarshalIndent(sf, "", "  ")
}

// VerifyBundle verifies that sigsJSON contains a valid signature from pubKey over files.
func VerifyBundle(files map[string][]byte, sigsJSON []byte, pubKey ed25519.PublicKey) error {
	if len(sigsJSON) == 0 {
		return ErrMissingSignature
	}

	var sf SignaturesFile
	if err := json.Unmarshal(sigsJSON, &sf); err != nil {
		return fmt.Errorf("%w: parse signatures.json: %v", ErrInvalidSignature, err)
	}

	var payload SignPayload
	verified := false

	// Try JWT signature from Signatures slice first
	for _, jwt := range sf.Signatures {
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			continue
		}
		sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			sigBytes, err = base64.URLEncoding.DecodeString(parts[2])
			if err != nil {
				continue
			}
		}

		signedData := []byte(parts[0] + "." + parts[1])
		if !ed25519.Verify(pubKey, signedData, sigBytes) {
			continue
		}

		payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			payloadBytes, err = base64.URLEncoding.DecodeString(parts[1])
			if err != nil {
				continue
			}
		}

		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			continue
		}
		verified = true
		break
	}

	// Fallback to detached signature field if present
	if !verified && sf.Signature != "" && len(sf.Files) > 0 {
		sigBytes, err := base64.RawURLEncoding.DecodeString(sf.Signature)
		if err != nil {
			sigBytes, _ = base64.URLEncoding.DecodeString(sf.Signature)
		}
		if len(sigBytes) == ed25519.SignatureSize {
			headerJSON, _ := json.Marshal(SignHeader{Alg: "EdDSA", Typ: "JWT"})
			payloadJSON, _ := json.Marshal(SignPayload{Files: sf.Files})
			signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
			if ed25519.Verify(pubKey, []byte(signingInput), sigBytes) {
				payload = SignPayload{Files: sf.Files}
				verified = true
			}
		}
	}

	if !verified {
		return fmt.Errorf("%w: verification failed", ErrInvalidSignature)
	}

	// Verify all signed files match bundle content and hashes
	signedSet := make(map[string]bool)
	for _, entry := range payload.Files {
		content, ok := files[entry.Name]
		if !ok {
			return fmt.Errorf("%w: signed file missing from bundle: %s", ErrInvalidSignature, entry.Name)
		}
		sum := sha256.Sum256(content)
		actualHash := hex.EncodeToString(sum[:])
		if !strings.EqualFold(actualHash, entry.Hash) {
			return fmt.Errorf("%w: hash mismatch for file %s (want %s, got %s)", ErrInvalidSignature, entry.Name, entry.Hash, actualHash)
		}
		signedSet[entry.Name] = true
	}

	// Verify no untracked files are present (fail-closed integrity)
	for name := range files {
		clean := strings.TrimPrefix(name, "/")
		clean = strings.TrimPrefix(clean, "./")
		if clean == "signatures.json" || clean == ".signatures.json" ||
			strings.HasSuffix(clean, "/signatures.json") || strings.HasSuffix(clean, "/.signatures.json") {
			continue
		}
		if !signedSet[name] {
			return fmt.Errorf("%w: untracked file present in bundle: %s", ErrInvalidSignature, name)
		}
	}

	return nil
}
