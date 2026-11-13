package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCerberusBundle_BuildAndVerify(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyFile, privPEM, 0o600); err != nil {
		t.Fatalf("write key.pem: %v", err)
	}

	pubBytes, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	pubFile := filepath.Join(tmpDir, "pub.pem")
	//nolint:gosec // G306 test
	if err := os.WriteFile(pubFile, pubPEM, 0o600); err != nil {
		t.Fatalf("write pub.pem: %v", err)
	}

	// Create bundle directory
	bundleDir := filepath.Join(tmpDir, "bundle_src")
	if err := os.MkdirAll(filepath.Join(bundleDir, "policies/stages"), 0o750); err != nil {
		t.Fatalf("mkdir bundle_src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, ".manifest"), []byte(`{"roots":["stages"],"revision":"v1.0.0"}`), 0o600); err != nil {
		t.Fatalf("write .manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "data.json"), []byte(`{"agents":{}}`), 0o600); err != nil {
		t.Fatalf("write data.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "policies/stages/foo.rego"), []byte("package stages.foo\nallow := true"), 0o600); err != nil {
		t.Fatalf("write foo.rego: %v", err)
	}

	outTarGz := filepath.Join(tmpDir, "out.tar.gz")

	// 1. Build signed bundle
	err = runBuild([]string{"-k", keyFile, "-d", bundleDir, outTarGz})
	if err != nil {
		t.Fatalf("runBuild: %v", err)
	}
	if _, err := os.Stat(outTarGz); err != nil {
		t.Fatalf("bundle tar.gz not created: %v", err)
	}

	// 2. Verify valid bundle
	err = runVerify([]string{"-k", pubFile, outTarGz})
	if err != nil {
		t.Fatalf("runVerify valid: %v", err)
	}

	// 3. Verify with wrong public key
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub := wrongPriv.Public().(ed25519.PublicKey)
	wrongPubBytes, _ := x509.MarshalPKIXPublicKey(wrongPub)
	wrongPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wrongPubBytes})
	wrongPubFile := filepath.Join(tmpDir, "wrong_pub.pem")
	//nolint:gosec // G306 test
	if err := os.WriteFile(wrongPubFile, wrongPubPEM, 0o600); err != nil {
		t.Fatalf("write wrong_pub.pem: %v", err)
	}

	err = runVerify([]string{"-k", wrongPubFile, outTarGz})
	if err == nil {
		t.Fatal("expected verify failure with wrong public key, got nil")
	}
}

func TestCerberusBundle_Coverage(t *testing.T) {
	// Test human-readable coverage command on actual policies
	err := runCoverage([]string{"-d", "../../policies"})
	if err != nil {
		t.Fatalf("runCoverage policies: %v", err)
	}

	// Test json output coverage command
	err = runCoverage([]string{"-d", "../../policies", "--json"})
	if err != nil {
		t.Fatalf("runCoverage policies --json: %v", err)
	}
}
