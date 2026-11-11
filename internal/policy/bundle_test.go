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

	aiRego, err := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego"))
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

	aiRego, err := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego"))
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

	aiRego, _ := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego"))
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

	aiRego, _ := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego"))

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

	// 1. Compute active coverage
	rep, err := store.Coverage(ctx)
	if err != nil || rep == nil {
		t.Fatalf("store.Coverage: %v", err)
	}
	activeCov := rep.Coverage
	store.Current().Coverage = activeCov

	// 2. Create bundle with a large set of completely untested Rego rules
	// to drop coverage by >5 percentage points.
	var untestedRules strings.Builder
	untestedRules.WriteString("package stages.untested\nimport rego.v1\n")
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&untestedRules, "rule_%d if input.val == %d\n", i, i)
	}

	aiRego, _ := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego"))
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
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readFile %s: %v", path, err)
	}
	return string(b)
}
