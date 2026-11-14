package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func createCustomBundle(t *testing.T, roots []string, revision string, dataJSON []byte, regoFiles map[string]string, privKey ed25519.PrivateKey) []byte {
	t.Helper()
	files := make(map[string][]byte)

	// .manifest
	if roots != nil || revision != "" {
		if roots == nil {
			roots = []string{"stages"}
		}
		manifest := fmt.Sprintf(`{"roots":["%s"],"revision":"%s"}`, strings.Join(roots, `","`), revision)
		files[".manifest"] = []byte(manifest)
	}

	// data.json
	if dataJSON != nil {
		files["data.json"] = dataJSON
	}

	// rego files
	for name, content := range regoFiles {
		files[name] = []byte(content)
	}

	// signatures.json if privKey is provided
	if privKey != nil {
		sigJSON, err := SignBundle(files, privKey)
		if err != nil {
			t.Fatalf("SignBundle: %v", err)
		}
		files["signatures.json"] = sigJSON
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Size: int64(len(content)),
			Mode: 0o600,
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestStore_LoadBundleAndReload(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir policyDir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")

	repoPolicies := "../../policies"
	if err := os.CopyFS(policyDir, os.DirFS(repoPolicies)); err != nil {
		t.Fatalf("copy repo policies: %v", err)
	}
	initialData := loadTestData(t)
	if err := os.WriteFile(dataPath, initialData, 0o600); err != nil {
		t.Fatalf("write data.json: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if store.Current().Epoch != 1 {
		t.Fatalf("epoch = %d, want 1", store.Current().Epoch)
	}

	aiRego, err := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego")) //nolint:gosec // G304 test fixture
	if err != nil {
		t.Fatalf("read ai: %v", err)
	}

	// Change agent k-open's budget_limit in data
	newData := []byte(`{
		"config": {"bypass_unknown_keys": true, "bypass_unknown_teams": true},
		"teams": {},
		"agents": {
			"k-open": {"name": "open-agent", "budget_limit": 10}
		},
		"blocked_patterns": ["jailbreak"],
		"domains": {},
		"prod_shield": {
			"dangerous_cmd_patterns": [
				{"id": "rm_rf", "regex": "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)"},
				{"id": "grep_wildcard_dump", "regex": "grep\\s+[^|]*(\\*|wildcard)[^|]*(/passwd|/etc|\\.env|id_rsa)"}
			],
			"protected_containers": ["teknikalidnew-db-1"]
		}
	}`)

	bundleGz := createCustomBundle(t, []string{"stages"}, "v1.0.1", newData, map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}, nil)

	bundleFile := filepath.Join(tmpDir, "bundle.tar.gz")
	if err := os.WriteFile(bundleFile, bundleGz, 0o600); err != nil {
		t.Fatalf("write bundle file: %v", err)
	}

	snap, err := store.LoadBundleFile(ctx, bundleFile)
	if err != nil {
		t.Fatalf("LoadBundleFile: %v", err)
	}
	if snap.Epoch != 2 {
		t.Fatalf("snap.Epoch = %d, want 2", snap.Epoch)
	}
	if snap.Revision != "v1.0.1" {
		t.Fatalf("snap.Revision = %q, want v1.0.1", snap.Revision)
	}
	if store.Current().Epoch != 2 {
		t.Fatalf("store.Current().Epoch = %d, want 2", store.Current().Epoch)
	}

	snap3, err := store.Reload(ctx)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if snap3.Epoch != 3 {
		t.Fatalf("snap3.Epoch = %d, want 3", snap3.Epoch)
	}
}

// Layer 2: Tamper-deny - Refuse bundle whose roots overlap with local core modules (gateway/shield)
func TestStore_BundleRootsOverlapRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")
	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy repo policies: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write data.json: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	cases := []struct {
		name  string
		roots []string
	}{
		{"root gateway", []string{"gateway"}},
		{"root gateway subpath", []string{"gateway/authz"}},
		{"root shield", []string{"shield"}},
		{"root shield prod", []string{"shield/prod"}},
		{"mixed roots with shield", []string{"stages", "shield"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := createCustomBundle(t, tc.roots, "rev-evil", loadTestData(t), map[string]string{
				"stages/custom.rego": "package stages.custom\nallow := true",
			}, nil)

			_, err := store.LoadBundle(ctx, b)
			if err == nil {
				t.Fatalf("expected error for overlapping root %v, got nil", tc.roots)
			}
			if !errors.Is(err, ErrData) {
				t.Fatalf("expected ErrData, got %v", err)
			}
			if store.Current().Epoch != 1 {
				t.Fatalf("epoch changed on failed bundle load: got %d, want 1", store.Current().Epoch)
			}
		})
	}
}

// Layer 2: Tamper-deny - Refuse bundle attempting to overwrite local core rego files
func TestStore_BundleCoreFileOverwriteRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")
	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy repo policies: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write data.json: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Bundle tries to overwrite shield/prod.rego
	b := createCustomBundle(t, []string{"stages"}, "rev-hack", loadTestData(t), map[string]string{
		"shield/prod.rego": "package shield.prod\n# backdoor",
	}, nil)

	_, err = store.LoadBundle(ctx, b)
	if err == nil {
		t.Fatal("expected error when bundle tries to overwrite shield/prod.rego, got nil")
	}
	if store.Current().Epoch != 1 {
		t.Fatalf("epoch changed on refused bundle: %d, want 1", store.Current().Epoch)
	}
}

// TestStore_BundleCorePackageDeclRefused verifies R3:
// 1. A bundle file in stages/helper.rego declaring package gateway.authz is rejected.
// 2. A bundle file with repeated prefix policies/policies/gateway/authz.rego is rejected.
func TestStore_BundleCorePackageDeclRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")
	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy repo policies: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write data.json: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// 1. Bundle with stages/helper.rego but declaring package gateway.authz -> must be rejected
	bEvilHelper := createCustomBundle(t, []string{"stages"}, "rev-evil-helper", loadTestData(t), map[string]string{
		"stages/helper.rego": "package gateway.authz\n\ndefault decision := {\"decision\": \"allow\"}\n",
	}, nil)

	_, err = store.LoadBundle(ctx, bEvilHelper)
	if err == nil {
		t.Fatal("expected error when bundle contains helper.rego declaring package gateway.authz, got nil")
	}

	// 2. Bundle with repeated prefix policies/policies/gateway/authz.rego -> must be rejected
	bNestedCore := createCustomBundle(t, []string{"stages"}, "rev-nested-core", loadTestData(t), map[string]string{
		"policies/policies/gateway/authz.rego": "package gateway.authz\n\ndefault decision := {\"decision\": \"allow\"}\n",
	}, nil)

	_, err = store.LoadBundle(ctx, bNestedCore)
	if err == nil {
		t.Fatal("expected error when bundle contains policies/policies/gateway/authz.rego, got nil")
	}
}

// 3-Layer: Signing & verification tests (Happy path, Tampered signature, Tampered content)
func TestStore_BundleSigningAndVerification(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")
	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	store.SetVerificationKey(pub)

	aiRego, err := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego")) //nolint:gosec // G304 test fixture
	if err != nil {
		t.Fatalf("read ai: %v", err)
	}

	// 1. Happy path: validly signed bundle loads successfully
	validBundle := createCustomBundle(t, []string{"stages"}, "rev-sig-1", loadTestData(t), map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}, priv)

	snap, err := store.LoadBundle(ctx, validBundle)
	if err != nil {
		t.Fatalf("LoadBundle validly signed: %v", err)
	}
	if snap.Epoch != 2 {
		t.Fatalf("snap.Epoch = %d, want 2", snap.Epoch)
	}

	// 2. Tampered content: bundle signed by priv, but file content altered
	files := map[string][]byte{
		".manifest":               []byte(`{"roots":["stages"],"revision":"rev-tampered"}`),
		"data.json":               loadTestData(t),
		"policies/stages/ai.rego": aiRego,
	}
	sigJSON, err := SignBundle(files, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	// Tamper data.json content AFTER signing
	files["data.json"] = []byte(`{"tampered":true}`)
	files["signatures.json"] = sigJSON

	var tamperedBuf bytes.Buffer
	gw := gzip.NewWriter(&tamperedBuf)
	tw := tar.NewWriter(gw)
	for n, c := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Size: int64(len(c)), Mode: 0o600})
		_, _ = tw.Write(c)
	}
	_ = tw.Close()
	_ = gw.Close()

	_, err = store.LoadBundle(ctx, tamperedBuf.Bytes())
	if err == nil {
		t.Fatal("expected signature verification failure for tampered content, got nil")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
	if store.Current().Epoch != 2 {
		t.Fatalf("epoch changed on tampered bundle: got %d, want 2", store.Current().Epoch)
	}

	// 3. Invalid signature: wrong key signed the bundle
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrongKeyBundle := createCustomBundle(t, []string{"stages"}, "rev-wrong-key", loadTestData(t), map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}, otherPriv)

	_, err = store.LoadBundle(ctx, wrongKeyBundle)
	if err == nil {
		t.Fatal("expected failure when signed by wrong key, got nil")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
	if store.Current().Epoch != 2 {
		t.Fatalf("epoch changed on wrong key bundle: got %d, want 2", store.Current().Epoch)
	}

	// 4. Missing signature when verification key is set
	unsignedBundle := createCustomBundle(t, []string{"stages"}, "rev-unsigned", loadTestData(t), map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}, nil)

	_, err = store.LoadBundle(ctx, unsignedBundle)
	if err == nil {
		t.Fatal("expected failure when unsigned bundle provided to verified store, got nil")
	}
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
	if store.Current().Epoch != 2 {
		t.Fatalf("epoch changed on unsigned bundle: got %d, want 2", store.Current().Epoch)
	}
}

// Layer 3: Fail-closed - Dry-run eval smoke fails (e.g. broken shield or policy)
func TestStore_BundleDryRunSmokeFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")
	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Data without prod_shield rules so rm -rf / does not deny
	brokenData := []byte(`{
		"config": {"bypass_unknown_keys": true, "bypass_unknown_teams": true},
		"teams": {},
		"agents": {},
		"blocked_patterns": [],
		"domains": {},
		"prod_shield": {
			"dangerous_cmd_patterns": []
		}
	}`)

	aiRego, _ := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego")) //nolint:gosec // G304 test fixture
	b := createCustomBundle(t, []string{"stages"}, "rev-smoke-fail", brokenData, map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}, nil)

	_, err = store.LoadBundle(ctx, b)
	if err == nil {
		t.Fatal("expected smoke dry-run failure, got nil")
	}
	if !strings.Contains(err.Error(), "smoke test failed") {
		t.Fatalf("expected smoke test error, got: %v", err)
	}
	if store.Current().Epoch != 1 {
		t.Fatalf("epoch changed on smoke failure: got %d, want 1", store.Current().Epoch)
	}
}

// Activation & Rollback test
func TestStore_BundleRollback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")
	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Layer 3: Rollback with no previous bundle fails closed
	if _, err := store.Rollback(ctx); !errors.Is(err, ErrNoRollback) {
		t.Fatalf("expected ErrNoRollback, got %v", err)
	}

	aiRego, _ := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego")) //nolint:gosec // G304 test fixture

	// Load Bundle 1
	b1 := createCustomBundle(t, []string{"stages"}, "rev-1.0", loadTestData(t), map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}, nil)
	snap1, err := store.LoadBundle(ctx, b1)
	if err != nil {
		t.Fatalf("LoadBundle b1: %v", err)
	}
	if snap1.Revision != "rev-1.0" || snap1.Epoch != 2 {
		t.Fatalf("snap1 = %s/%d, want rev-1.0/2", snap1.Revision, snap1.Epoch)
	}

	// Load Bundle 2
	b2 := createCustomBundle(t, []string{"stages"}, "rev-2.0", loadTestData(t), map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}, nil)
	snap2, err := store.LoadBundle(ctx, b2)
	if err != nil {
		t.Fatalf("LoadBundle b2: %v", err)
	}
	if snap2.Revision != "rev-2.0" || snap2.Epoch != 3 {
		t.Fatalf("snap2 = %s/%d, want rev-2.0/3", snap2.Revision, snap2.Epoch)
	}

	// Rollback to Bundle 1
	rolledSnap, err := store.Rollback(ctx)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rolledSnap.Revision != "rev-1.0" {
		t.Fatalf("rolledSnap.Revision = %q, want rev-1.0", rolledSnap.Revision)
	}
	if rolledSnap.Epoch != 4 {
		t.Fatalf("rolledSnap.Epoch = %d, want 4 (incremented on rollback)", rolledSnap.Epoch)
	}

	// Second rollback without an intermediate bundle fails closed
	if _, err := store.Rollback(ctx); !errors.Is(err, ErrNoRollback) {
		t.Fatalf("expected ErrNoRollback on second rollback, got %v", err)
	}
}

// B1 audit fix: bundle rollback cleans up added files and executes smoke test
func TestStore_BundleRollback_RestoresFilesAndRunsSmoke(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")
	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	aiRego, err := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego")) //nolint:gosec // G304 test fixture
	if err != nil {
		t.Fatalf("read ai.rego: %v", err)
	}
	toolRego, err := os.ReadFile(filepath.Join(policyDir, "stages/tool.rego")) //nolint:gosec // G304 test fixture
	if err != nil {
		t.Fatalf("read tool.rego: %v", err)
	}

	// Bundle A: 2 files
	bA := createCustomBundle(t, []string{"stages"}, "rev-A", loadTestData(t), map[string]string{
		"policies/stages/ai.rego":   string(aiRego),
		"policies/stages/tool.rego": string(toolRego),
	}, nil)
	snapA, err := store.LoadBundle(ctx, bA)
	if err != nil {
		t.Fatalf("LoadBundle A: %v", err)
	}
	if snapA.Revision != "rev-A" {
		t.Fatalf("snapA.Revision = %q, want rev-A", snapA.Revision)
	}

	// Bundle B: Bundle A + 1 new file
	newFileContent := "package stages\n\ndefault extra_audit_allowed := true\n"
	bB := createCustomBundle(t, []string{"stages"}, "rev-B", loadTestData(t), map[string]string{
		"policies/stages/ai.rego":                  string(aiRego),
		"policies/stages/tool.rego":                string(toolRego),
		"policies/stages/extra_audit_feature.rego": newFileContent,
	}, nil)
	snapB, err := store.LoadBundle(ctx, bB)
	if err != nil {
		t.Fatalf("LoadBundle B: %v", err)
	}
	if snapB.Revision != "rev-B" {
		t.Fatalf("snapB.Revision = %q, want rev-B", snapB.Revision)
	}

	newFilePath := filepath.Join(policyDir, "stages/extra_audit_feature.rego")
	if _, err := os.Stat(newFilePath); err != nil {
		t.Fatalf("expected new file from bundle B on disk, got err: %v", err)
	}

	// Rollback to Bundle A
	rolledSnap, err := store.Rollback(ctx)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rolledSnap.Revision != "rev-A" {
		t.Fatalf("rolledSnap.Revision = %q, want rev-A", rolledSnap.Revision)
	}

	// Verify the newly added file was deleted upon rollback
	if _, err := os.Stat(newFilePath); !os.IsNotExist(err) {
		t.Fatalf("expected new file %s to be deleted on rollback, stat err: %v", newFilePath, err)
	}

	// Verify smoke test passes on rolled back policy
	if err := DryRunSmoke(ctx, rolledSnap); err != nil {
		t.Fatalf("smoke test failed on rolled back snapshot: %v", err)
	}
}

// Data subtree /data/* support
func TestStore_BundleDataSubtree(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")
	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Create bundle without root data.json, but with /data/agents.json and /data/config.json etc.
	files := map[string][]byte{
		".manifest": []byte(`{"roots":["stages"],"revision":"rev-subtree"}`),
		"data/agents.json": []byte(`{
			"k-open": {"name": "open-agent", "budget_limit": 25}
		}`),
		"data/config.json": []byte(`{
			"bypass_unknown_keys": true,
			"bypass_unknown_teams": true
		}`),
		"data/prod_shield.json": []byte(`{
			"dangerous_cmd_patterns": [
				{"id": "rm_rf", "regex": "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)"},
				{"id": "grep_wildcard_dump", "regex": "grep\\s+[^|]*(\\*|wildcard)[^|]*(/passwd|/etc|\\.env|id_rsa)"}
			],
			"protected_containers": ["teknikalidnew-db-1"]
		}`),
		"policies/stages/ai.rego": []byte(readFile(t, filepath.Join(policyDir, "stages/ai.rego"))),
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for n, c := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Size: int64(len(c)), Mode: 0o600})
		_, _ = tw.Write(c)
	}
	_ = tw.Close()
	_ = gw.Close()

	snap, err := store.LoadBundle(ctx, buf.Bytes())
	if err != nil {
		t.Fatalf("LoadBundle with data subtree: %v", err)
	}
	if snap.Revision != "rev-subtree" {
		t.Fatalf("snap.Revision = %q, want rev-subtree", snap.Revision)
	}
	if snap.Data["agents"] == nil || snap.Data["prod_shield"] == nil {
		t.Fatalf("merged data missing keys: %v", snap.Data)
	}
}

func TestStore_BundleCoverageDropGate(t *testing.T) {
	ctx := context.Background()

	// Coverage-drop gate requires the suite to actually run: force it ON even
	// when the matrix runs with CERBERUS_SKIP_POLICY_SUITE=1. (Not parallel: t.Setenv.)
	t.Setenv("CERBERUS_SKIP_POLICY_SUITE", "0")

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")
	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// 1. Compute active coverage
	rep, err := store.Coverage(ctx)
	if err != nil || rep == nil {
		t.Fatalf("store.Coverage: %v", err)
	}
	_ = rep.Coverage

	// 2. Create bundle with a large set of completely untested Rego rules
	// to drop coverage by >5 percentage points.
	var untestedRules strings.Builder
	untestedRules.WriteString("package stages.untested\nimport rego.v1\n")
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&untestedRules, "rule_%d if input.val == %d\n", i, i)
	}

	aiRego, _ := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego")) //nolint:gosec // G304 test fixture
	bDrop := createCustomBundle(t, []string{"stages"}, "rev-drop-cov", loadTestData(t), map[string]string{
		"policies/stages/ai.rego":       string(aiRego),
		"policies/stages/untested.rego": untestedRules.String(),
	}, nil)

	_, err = store.LoadBundle(ctx, bDrop)
	if err == nil {
		t.Fatal("expected bundle activation to be rejected due to coverage drop >5 points, got nil")
	}
	if !strings.Contains(err.Error(), "coverage dropped by") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// 3. Normal bundle that keeps coverage intact should succeed
	bNormal := createCustomBundle(t, []string{"stages"}, "rev-good-cov", loadTestData(t), map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}, nil)

	snap, err := store.LoadBundle(ctx, bNormal)
	if err != nil {
		t.Fatalf("LoadBundle with normal coverage should succeed: %v", err)
	}
	if snap.Revision != "rev-good-cov" {
		t.Fatalf("snap.Revision = %q, want rev-good-cov", snap.Revision)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304 test fixture
	if err != nil {
		t.Fatalf("readFile %s: %v", path, err)
	}
	return string(b)
}

func TestReadBundle_AppleDoubleRegoSkipped(t *testing.T) {
	regoFiles := map[string]string{
		"policies/stages/foo.rego":    "package stages.foo\n\ndefault decision = {\"decision\": \"allow\"}\n",
		"policies/stages/._evil.rego": "broken syntax (((\n",
		"._root_evil.rego":            "broken syntax (((\n",
	}
	raw := createCustomBundle(t, []string{"stages"}, "rev-appledouble", []byte(`{}`), regoFiles, nil)
	b, err := ReadBundle(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadBundle: %v", err)
	}
	if _, ok := b.RegoFiles["policies/stages/._evil.rego"]; ok {
		t.Error("policies/stages/._evil.rego should be skipped from RegoFiles")
	}
	if _, ok := b.RegoFiles["._root_evil.rego"]; ok {
		t.Error("._root_evil.rego should be skipped from RegoFiles")
	}
	if _, ok := b.RegoFiles["policies/stages/foo.rego"]; !ok {
		t.Error("policies/stages/foo.rego should be present in RegoFiles")
	}
}

func TestSafeRel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"normal rego", "policies/stages/ai.rego", "stages/ai.rego", false},
		{"direct rego", "stages/ai.rego", "stages/ai.rego", false},
		{"repeated policies prefix", "policies/policies/gateway/authz.rego", "gateway/authz.rego", false},
		{"data json", "data.json", "data.json", false},
		{"manifest", ".manifest", ".manifest", false},
		{"policies dot dot evil", "policies/../../evil.rego", "", true},
		{"dot dot escape", "../escape", "", true},
		{"a dot dot b", "a/../../b", "", true},
		{"root absolute", "/etc/passwd", "", true},
		{"empty", "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rel, err := safeRel(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("safeRel(%q): expected error, got %q", tc.input, rel)
				}
				return
			}
			if err != nil {
				t.Fatalf("safeRel(%q): unexpected error: %v", tc.input, err)
			}
			if rel != tc.want {
				t.Fatalf("safeRel(%q) = %q, want %q", tc.input, rel, tc.want)
			}
		})
	}
}

func TestReadBundle_PathTraversalRejected(t *testing.T) {
	t.Parallel()

	traversalEntries := []string{
		"policies/../../evil.rego",
		"../escape",
		"a/../../b",
	}

	for _, entryName := range traversalEntries {
		t.Run("reject_"+entryName, func(t *testing.T) {
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gw)

			content := []byte("package malicious\ndefault allow = true\n")
			if err := tw.WriteHeader(&tar.Header{
				Name: entryName,
				Size: int64(len(content)),
				Mode: 0o600,
			}); err != nil {
				t.Fatalf("WriteHeader: %v", err)
			}
			if _, err := tw.Write(content); err != nil {
				t.Fatalf("Write: %v", err)
			}
			_ = tw.Close()
			_ = gw.Close()

			_, err := ReadBundle(bytes.NewReader(buf.Bytes()))
			if err == nil {
				t.Fatalf("expected ReadBundle to reject path traversal entry %q, got nil", entryName)
			}
		})
	}

	t.Run("normal_entry_allowed", func(t *testing.T) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)

		dataJSON := []byte(`{}`)
		if err := tw.WriteHeader(&tar.Header{
			Name: "data.json",
			Size: int64(len(dataJSON)),
			Mode: 0o600,
		}); err != nil {
			t.Fatalf("WriteHeader data.json: %v", err)
		}
		if _, err := tw.Write(dataJSON); err != nil {
			t.Fatalf("Write data.json: %v", err)
		}

		content := []byte("package stages.test\ndefault allow = true\n")
		if err := tw.WriteHeader(&tar.Header{
			Name: "policies/stages/test.rego",
			Size: int64(len(content)),
			Mode: 0o600,
		}); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("Write: %v", err)
		}
		_ = tw.Close()
		_ = gw.Close()

		b, err := ReadBundle(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("expected normal entry to pass, got error: %v", err)
		}
		if _, ok := b.RegoFiles["policies/stages/test.rego"]; !ok {
			t.Fatal("expected policies/stages/test.rego in RegoFiles")
		}
	})
}

func TestReadBundle_ZipBombRejected(t *testing.T) {
	t.Parallel()

	// Create a tar archive with a 100MB zero-filled entry.
	// With gzip compression, 100MB of zeros compresses to a tiny file (<100KB).
	const bombSize = 100 << 20 // 100MB
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Name: "policies/stages/huge.rego",
		Size: bombSize,
		Mode: 0o600,
	}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}

	chunk := make([]byte, 1<<20) // 1MB buffer
	for i := 0; i < 100; i++ {
		if _, err := tw.Write(chunk); err != nil {
			t.Fatalf("Write chunk: %v", err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()

	t.Logf("compressed 100MB zeros size: %d bytes", buf.Len())

	_, err := ReadBundle(bytes.NewReader(buf.Bytes()))
	if err == nil {
		t.Fatal("expected ReadBundle to reject 100MB entry exceeding maxPerEntry, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// TestStore_BundleRollback_RestoresOverwrittenFileAndFailsOnDataWriteError verifies D8:
// 1. Loading bundle B overwrites an existing file -> rollback restores original pre-B content.
// 2. When data.json restore fails (via read-only dir), rollback returns error and does NOT swap snapshot.
func TestStore_BundleRollback_RestoresOverwrittenFileAndFailsOnDataWriteError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataDir := filepath.Join(tmpDir, "datadir")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatalf("mkdir datadir: %v", err)
	}
	dataPath := filepath.Join(dataDir, "data.json")

	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write data: %v", err)
	}

	// Create custom pre-B file on disk
	preBContent := "package stages\n\ndefault pra_b_custom := true\n"
	customFilePath := filepath.Join(policyDir, "stages/custom_target.rego")
	if err := os.WriteFile(customFilePath, []byte(preBContent), 0o600); err != nil {
		t.Fatalf("write custom_target.rego: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	aiRego, _ := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego"))     //nolint:gosec // G304 test fixture
	toolRego, _ := os.ReadFile(filepath.Join(policyDir, "stages/tool.rego")) //nolint:gosec // G304 test fixture

	// Bundle A (baseline active bundle)
	bA := createCustomBundle(t, []string{"stages"}, "rev-A", loadTestData(t), map[string]string{
		"policies/stages/ai.rego":            string(aiRego),
		"policies/stages/tool.rego":          string(toolRego),
		"policies/stages/custom_target.rego": preBContent,
	}, nil)
	if _, err := store.LoadBundle(ctx, bA); err != nil {
		t.Fatalf("LoadBundle A: %v", err)
	}

	// Bundle B overwrites custom_target.rego with new content
	postBContent := "package stages\n\ndefault pra_b_custom := false\ndefault post_b := true\n"
	bB := createCustomBundle(t, []string{"stages"}, "rev-B", loadTestData(t), map[string]string{
		"policies/stages/ai.rego":            string(aiRego),
		"policies/stages/tool.rego":          string(toolRego),
		"policies/stages/custom_target.rego": postBContent,
	}, nil)
	snapB, err := store.LoadBundle(ctx, bB)
	if err != nil {
		t.Fatalf("LoadBundle B: %v", err)
	}
	if snapB.Revision != "rev-B" {
		t.Fatalf("snapB.Revision = %q, want rev-B", snapB.Revision)
	}

	// Verify disk file was overwritten
	diskPostB, err := os.ReadFile(customFilePath) //nolint:gosec // G304 test fixture
	if err != nil {
		t.Fatalf("read custom_target.rego: %v", err)
	}
	if string(diskPostB) != postBContent {
		t.Fatalf("expected overwritten content on disk, got: %s", string(diskPostB))
	}

	// Rollback to Bundle A
	snapRolled, err := store.Rollback(ctx)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if snapRolled.Revision != "rev-A" {
		t.Fatalf("snapRolled.Revision = %q, want rev-A", snapRolled.Revision)
	}

	// Verify disk file is restored to pre-B content
	diskRestored, err := os.ReadFile(customFilePath) //nolint:gosec // G304 test fixture
	if err != nil {
		t.Fatalf("read custom_target.rego after rollback: %v", err)
	}
	if string(diskRestored) != preBContent {
		t.Fatalf("expected pre-B content restored after rollback, got: %s", string(diskRestored))
	}

	// Part 2: Load bundle B again, then make dataDir read-only so writeAtomic(dataPath) fails on Rollback
	if _, err := store.LoadBundle(ctx, bB); err != nil {
		t.Fatalf("LoadBundle B second time: %v", err)
	}
	if store.Current().Revision != "rev-B" {
		t.Fatalf("current revision = %q, want rev-B", store.Current().Revision)
	}

	// Make dataDir read-only
	if err := os.Chmod(dataDir, 0o500); err != nil { //nolint:gosec // G302 read-only test directory
		t.Fatalf("chmod dataDir: %v", err)
	}
	defer func() { _ = os.Chmod(dataDir, 0o750) }() //nolint:gosec // G302 restore test directory

	// Rollback must fail on data.json write
	_, rollbackErr := store.Rollback(ctx)
	if rollbackErr == nil {
		t.Fatal("expected rollback to fail when data.json directory is read-only, got nil")
	}

	// Snapshot must NOT be swapped on failure (must remain rev-B)
	if store.Current().Revision != "rev-B" {
		t.Fatalf("snapshot was swapped despite restore error: got %q, want rev-B", store.Current().Revision)
	}
}

// TestStore_LoadBundle_CleansUpOnPartialFailure verifies D11:
// when writeAtomic fails midway through installing bundle files,
// any previously written files from that bundle are removed from policyDir.
func TestStore_LoadBundle_CleansUpOnPartialFailure(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")

	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write data: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Create a read-only subdirectory to force write failure
	roDir := filepath.Join(policyDir, "stages/readonly_dir")
	if err := os.MkdirAll(roDir, 0o500); err != nil {
		t.Fatalf("mkdir roDir: %v", err)
	}
	defer func() {
		_ = os.Chmod(roDir, 0o750) //nolint:gosec // G302 restore test directory
	}()

	aiRego, _ := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego"))     //nolint:gosec // G304 test fixture
	toolRego, _ := os.ReadFile(filepath.Join(policyDir, "stages/tool.rego")) //nolint:gosec // G304 test fixture

	// Bundle contains:
	// 1. newly added file 1
	// 2. file destined for readonly_dir (fails to write)
	file1Name := "policies/stages/new_feature_file1.rego"
	file2Name := "policies/stages/readonly_dir/new_feature_file2.rego"

	b := createCustomBundle(t, []string{"stages"}, "rev-fail", loadTestData(t), map[string]string{
		"policies/stages/ai.rego":   string(aiRego),
		"policies/stages/tool.rego": string(toolRego),
		file1Name:                   "package stages\ndefault f1 := true\n",
		file2Name:                   "package stages\ndefault f2 := true\n",
	}, nil)

	_, err = store.LoadBundle(ctx, b)
	if err == nil {
		t.Fatal("expected LoadBundle to fail due to read-only directory, got nil")
	}

	// Verify file 1 does NOT exist on disk in policyDir
	dest1 := filepath.Join(policyDir, "stages/new_feature_file1.rego")
	if _, err := os.Stat(dest1); !os.IsNotExist(err) {
		t.Fatalf("expected file 1 (%s) to be cleaned up after partial failure, but it exists", dest1)
	}
}

// TestStore_LoadBundle_RedSuiteRejected verifies E2.2:
// when the OPA test-suite inside a bundle fails (red), LoadBundle rejects the bundle.
func TestStore_LoadBundle_RedSuiteRejected(t *testing.T) {
	ctx := context.Background()

	// This test verifies the red-suite gate itself: force the suite ON even when
	// the matrix runs with CERBERUS_SKIP_POLICY_SUITE=1. (Not parallel: t.Setenv.)
	t.Setenv("CERBERUS_SKIP_POLICY_SUITE", "0")

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")

	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write data: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	aiRego, _ := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego")) //nolint:gosec // G304 test fixture

	// Create a bundle that contains valid policy plus a failing test
	b := createCustomBundle(t, []string{"stages"}, "rev-red", loadTestData(t), map[string]string{
		"policies/stages/ai.rego": string(aiRego),
		"policies/stages/failing_test.rego": `package stages.ai_test
import rego.v1

test_will_fail if {
	1 == 2
}
`,
	}, nil)

	_, err = store.LoadBundle(ctx, b)
	if err == nil {
		t.Fatal("expected LoadBundle to fail when bundle has red test suite, but got nil")
	}
	if !strings.Contains(err.Error(), "test suite failed") {
		t.Fatalf("expected error mentioning test suite failure, got: %v", err)
	}
}

// TestStore_LoadBundle_PrestagingDoesNotBlockConcurrentReload verifies E2.2:
// Coverage calculation runs before s.mu is acquired, so concurrent Reload or ReplaceData
// is not blocked during bundle test/coverage staging.
func TestStore_LoadBundle_PrestagingDoesNotBlockConcurrentReload(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")

	if err := os.CopyFS(policyDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("write data: %v", err)
	}

	store, err := NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	b := createCustomBundle(t, []string{"stages"}, "rev-valid", loadTestData(t), map[string]string{
		"policies/stages/valid_feature.rego": "package stages.tool\n\nvalid_feat := true\n",
	}, nil)

	loadStarted := make(chan struct{})
	loadDone := make(chan error, 1)

	go func() {
		close(loadStarted)
		_, lerr := store.LoadBundle(ctx, b)
		loadDone <- lerr
	}()

	<-loadStarted
	// Concurrent ReplaceData or Reload should execute smoothly
	_, rerr := store.ReplaceData(ctx, loadTestData(t))
	if rerr != nil {
		t.Fatalf("ReplaceData failed concurrently: %v", rerr)
	}

	if err := <-loadDone; err != nil {
		t.Fatalf("LoadBundle failed: %v", err)
	}
}
