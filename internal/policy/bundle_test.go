package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func createTestBundle(t *testing.T, dataJSON []byte, regoFiles map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// .manifest
	manifest := []byte(`{"roots":["gateway","stages"]}`)
	if err := tw.WriteHeader(&tar.Header{
		Name: ".manifest",
		Size: int64(len(manifest)),
		Mode: 0o600,
	}); err != nil {
		t.Fatalf("tar manifest header: %v", err)
	}
	if _, err := tw.Write(manifest); err != nil {
		t.Fatalf("tar manifest write: %v", err)
	}

	// data.json
	if err := tw.WriteHeader(&tar.Header{
		Name: "data.json",
		Size: int64(len(dataJSON)),
		Mode: 0o600,
	}); err != nil {
		t.Fatalf("tar data header: %v", err)
	}
	if _, err := tw.Write(dataJSON); err != nil {
		t.Fatalf("tar data write: %v", err)
	}

	// rego files
	for name, content := range regoFiles {
		b := []byte(content)
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Size: int64(len(b)),
			Mode: 0o600,
		}); err != nil {
			t.Fatalf("tar rego header %s: %v", name, err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatalf("tar rego write %s: %v", name, err)
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

	// Create temp policyDir and dataPath
	tmpDir := t.TempDir()
	policyDir := filepath.Join(tmpDir, "policies")
	if err := os.MkdirAll(policyDir, 0o750); err != nil {
		t.Fatalf("mkdir policyDir: %v", err)
	}
	dataPath := filepath.Join(tmpDir, "data.json")

	// Read existing repo policies into the temp policyDir
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

	// Read current policies to bundle them with a modified data.json
	authzRego, err := os.ReadFile(filepath.Join(policyDir, "gateway/authz.rego"))
	if err != nil {
		t.Fatalf("read authz: %v", err)
	}
	aiRego, err := os.ReadFile(filepath.Join(policyDir, "stages/ai.rego"))
	if err != nil {
		t.Fatalf("read ai: %v", err)
	}
	llmRego, err := os.ReadFile(filepath.Join(policyDir, "stages/llm.rego"))
	if err != nil {
		t.Fatalf("read llm: %v", err)
	}
	toolRego, err := os.ReadFile(filepath.Join(policyDir, "stages/tool.rego"))
	if err != nil {
		t.Fatalf("read tool: %v", err)
	}

	// Change agent k-open's budget_limit in data
	newData := []byte(`{
		"config": {"bypass_unknown_keys": true, "bypass_unknown_teams": true},
		"teams": {},
		"agents": {
			"k-open": {"name": "open-agent", "budget_limit": 10}
		},
		"blocked_patterns": ["jailbreak"],
		"domains": {}
	}`)

	bundleGz := createTestBundle(t, newData, map[string]string{
		"policies/gateway/authz.rego": string(authzRego),
		"policies/stages/ai.rego":     string(aiRego),
		"policies/stages/llm.rego":    string(llmRego),
		"policies/stages/tool.rego":   string(toolRego),
	})

	bundleFile := filepath.Join(tmpDir, "bundle.tar.gz")
	if err := os.WriteFile(bundleFile, bundleGz, 0o600); err != nil {
		t.Fatalf("write bundle file: %v", err)
	}

	// Load bundle from file
	snap, err := store.LoadBundleFile(ctx, bundleFile)
	if err != nil {
		t.Fatalf("LoadBundleFile: %v", err)
	}
	if snap.Epoch != 2 {
		t.Fatalf("snap.Epoch = %d, want 2", snap.Epoch)
	}
	if store.Current().Epoch != 2 {
		t.Fatalf("store.Current().Epoch = %d, want 2", store.Current().Epoch)
	}

	// Verify reload retains the bundle contents
	snap3, err := store.Reload(ctx)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if snap3.Epoch != 3 {
		t.Fatalf("snap3.Epoch = %d, want 3", snap3.Epoch)
	}
}
