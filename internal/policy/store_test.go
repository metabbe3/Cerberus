package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestStore builds a Store over the repo policies with the fixture data
// copied into a temp file, so tests never rewrite repo data.
func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dataPath := filepath.Join(t.TempDir(), "data.json")
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("stage fixture data: %v", err)
	}
	s, err := NewStore(context.Background(), policyDir, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s, dataPath
}

func TestStore_ReloadIncrementsEpoch(t *testing.T) {
	s, _ := newTestStore(t)
	if got := s.Current().Epoch; got != 1 {
		t.Fatalf("initial epoch = %d, want 1", got)
	}
	snap, err := s.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if snap.Epoch != 2 {
		t.Fatalf("reloaded epoch = %d, want 2", snap.Epoch)
	}
	if got := s.Current().Epoch; got != 2 {
		t.Fatalf("current epoch = %d, want 2", got)
	}
}

func TestStore_ReloadKeepsOldOnError(t *testing.T) {
	s, dataPath := newTestStore(t)
	if err := os.WriteFile(dataPath, []byte(`{"bogus":1}`), 0o600); err != nil {
		t.Fatalf("write broken data: %v", err)
	}
	if _, err := s.Reload(context.Background()); err == nil {
		t.Fatal("Reload with broken data: want error, got nil")
	}
	if got := s.Current().Epoch; got != 1 {
		t.Fatalf("epoch after failed reload = %d, want 1 (old snapshot stays live)", got)
	}
}

func TestStore_ReloadDoesNotBlockCurrent(t *testing.T) {
	s, _ := newTestStore(t)
	var stop atomic.Bool
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if snap := s.Current(); snap == nil {
					t.Error("Current() returned nil during reload")
					return
				}
			}
		}()
	}
	for range 10 {
		if _, err := s.Reload(context.Background()); err != nil {
			t.Fatalf("Reload: %v", err)
		}
	}
	stop.Store(true)
	wg.Wait()
	if got := s.Current().Epoch; got != 11 {
		t.Fatalf("final epoch = %d, want 11", got)
	}

	// Non-blocking proof: with the reload lock held (a reload parked
	// mid-compile), Current must still return promptly. A Current that took
	// s.mu would deadlock here until the lock is released.
	s.mu.Lock()
	got := make(chan *Snapshot, 1)
	go func() { got <- s.Current() }()
	select {
	case snap := <-got:
		if snap == nil {
			t.Error("Current() = nil while reload lock held")
		}
	case <-time.After(time.Second):
		t.Error("Current() blocked while the reload lock was held")
	}
	s.mu.Unlock()
}

func TestStore_ReplaceData_FsyncsDataAndDir(t *testing.T) {
	// Power loss within the dirty-writeback window after ReplaceData must not
	// leave dataPath empty/truncated: the temp file is fsynced before close and
	// the parent directory after rename. In-process we can only assert the
	// durability calls happen on the right paths.
	s, dataPath := newTestStore(t)
	var fileSyncs, dirSyncs int
	var syncedFile, syncedDir string
	origFile, origDir := syncFile, syncDir
	syncFile = func(f *os.File) error {
		fileSyncs++
		syncedFile = f.Name()
		return origFile(f)
	}
	syncDir = func(dir string) error {
		dirSyncs++
		syncedDir = dir
		return origDir(dir)
	}
	t.Cleanup(func() { syncFile, syncDir = origFile, origDir })

	if _, err := s.ReplaceData(context.Background(), loadTestData(t)); err != nil {
		t.Fatalf("ReplaceData: %v", err)
	}
	if fileSyncs != 1 {
		t.Fatalf("data file fsyncs = %d, want 1 (crash would leave it dirty)", fileSyncs)
	}
	if !strings.HasPrefix(filepath.Base(syncedFile), "."+filepath.Base(dataPath)) {
		t.Fatalf("fsynced wrong file: %q", syncedFile)
	}
	if dirSyncs != 1 {
		t.Fatalf("parent dir fsyncs = %d, want 1 (crash would lose the rename)", dirSyncs)
	}
	if syncedDir != filepath.Dir(dataPath) {
		t.Fatalf("fsynced dir = %q, want %q", syncedDir, filepath.Dir(dataPath))
	}
}

func TestStore_ReplaceData_WritesFileAtomically(t *testing.T) {
	s, dataPath := newTestStore(t)
	newData := bytes.Replace(loadTestData(t), []byte(`"glob-agent"`), []byte(`"glob-agent-2"`), 1)

	snap, err := s.ReplaceData(context.Background(), newData)
	if err != nil {
		t.Fatalf("ReplaceData: %v", err)
	}
	if snap.Epoch != 2 {
		t.Fatalf("epoch = %d, want 2", snap.Epoch)
	}
	if s.Current() != snap {
		t.Fatal("Current() not swapped to new snapshot")
	}

	got, err := os.ReadFile(dataPath) // #nosec G304 -- path from t.TempDir
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, newData) {
		t.Fatalf("file content mismatch: got %s", got)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(dataPath), "*.tmp")); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
	if name, _ := snap.Data["agents"].(map[string]any)["k-glob"].(map[string]any)["name"].(string); name != "glob-agent-2" {
		t.Fatalf("new snapshot Data not in effect: agent name = %q", name)
	}
}

func TestStore_ReplaceData_KeepsOldOnError(t *testing.T) {
	s, dataPath := newTestStore(t)
	before, err := os.ReadFile(dataPath) // #nosec G304 -- path from t.TempDir
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := s.ReplaceData(context.Background(), []byte(`{"bogus":1}`)); err == nil {
		t.Fatal("ReplaceData with invalid data: want error, got nil")
	}
	after, err := os.ReadFile(dataPath) // #nosec G304 -- path from t.TempDir
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dataPath changed on failed ReplaceData")
	}
	if got := s.Current().Epoch; got != 1 {
		t.Fatalf("epoch = %d, want 1", got)
	}
	if !strings.Contains(s.PolicyDir(), "policies") {
		t.Fatalf("PolicyDir = %q", s.PolicyDir())
	}
}

func TestStore_ReplaceData_GlobalKillSwitchAllowed(t *testing.T) {
	s, _ := newTestStore(t)
	raw := loadTestData(t)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cfg := doc["config"].(map[string]any)
	ks := cfg["kill_switch"].(map[string]any)
	ks["global"] = true
	killData, _ := json.Marshal(doc)

	snap, err := s.ReplaceData(context.Background(), killData)
	if err != nil {
		t.Fatalf("ReplaceData with global kill switch: %v", err)
	}
	if snap.Epoch != 2 {
		t.Fatalf("epoch = %d, want 2", snap.Epoch)
	}
}

func TestStore_OnSwap_MultipleCallbacks(t *testing.T) {
	s, _ := newTestStore(t)

	var cb1Calls, cb2Calls atomic.Int32
	var cb1Epoch, cb2Epoch atomic.Uint64

	s.OnSwap(func(snap *Snapshot) {
		cb1Calls.Add(1)
		cb1Epoch.Store(snap.Epoch)
	})
	s.OnSwap(func(snap *Snapshot) {
		cb2Calls.Add(1)
		cb2Epoch.Store(snap.Epoch)
	})

	snap, err := s.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if cb1Calls.Load() != 1 {
		t.Fatalf("cb1 called %d times, want 1", cb1Calls.Load())
	}
	if cb2Calls.Load() != 1 {
		t.Fatalf("cb2 called %d times, want 1", cb2Calls.Load())
	}
	if cb1Epoch.Load() != snap.Epoch {
		t.Fatalf("cb1 received epoch %d, want %d", cb1Epoch.Load(), snap.Epoch)
	}
	if cb2Epoch.Load() != snap.Epoch {
		t.Fatalf("cb2 received epoch %d, want %d", cb2Epoch.Load(), snap.Epoch)
	}
}

func TestStore_OnSwap_Unsubscribe(t *testing.T) {
	s, _ := newTestStore(t)

	var calls atomic.Int32
	cancel := s.OnSwap(func(_ *Snapshot) {
		calls.Add(1)
	})

	if s.SwapCallbacksLen() != 1 {
		t.Fatalf("expected 1 callback, got %d", s.SwapCallbacksLen())
	}

	_, err := s.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", calls.Load())
	}

	// Cancel / unsubscribe
	cancel()
	if s.SwapCallbacksLen() != 0 {
		t.Fatalf("expected 0 callbacks after cancel, got %d", s.SwapCallbacksLen())
	}

	_, err = s.Reload(context.Background())
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected no new calls after unsubscribe, got %d", calls.Load())
	}
}

func TestStore_Reload_RejectsCorruptDataWithoutAgents(t *testing.T) {
	s, dataPath := newTestStore(t)
	oldSnap := s.Current()

	// Data without required "agents" key
	brokenData := []byte(`{"config":{}}`)
	if err := os.WriteFile(dataPath, brokenData, 0o600); err != nil {
		t.Fatalf("write broken data: %v", err)
	}

	_, err := s.Reload(context.Background())
	if err == nil {
		t.Fatal("expected Reload to fail with corrupted data missing agents, got nil")
	}

	// Snapshot must not change
	if s.Current() != oldSnap {
		t.Fatal("Current() snapshot changed despite failed Reload")
	}
	if s.Current().Epoch != 1 {
		t.Fatalf("epoch changed to %d, want 1", s.Current().Epoch)
	}
}

func TestStore_Reload_FailsSmokeTest(t *testing.T) {
	tmpPolicy := t.TempDir()
	if err := os.CopyFS(tmpPolicy, os.DirFS(policyDir)); err != nil {
		t.Fatalf("copy policyDir: %v", err)
	}
	dataPath := filepath.Join(t.TempDir(), "data.json")
	if err := os.WriteFile(dataPath, loadTestData(t), 0o600); err != nil {
		t.Fatalf("stage fixture data: %v", err)
	}
	s, err := NewStore(context.Background(), tmpPolicy, dataPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	oldSnap := s.Current()

	// Write a rego file into tmpPolicy that forces all decisions to deny,
	// causing DryRunSmoke ("ls allow") to fail.
	brokenRego := []byte("package gateway.authz\n\ndecision := {\"decision\": \"deny\", \"rule_id\": \"override_all\"}\n")
	if err := os.WriteFile(filepath.Join(tmpPolicy, "override.rego"), brokenRego, 0o600); err != nil {
		t.Fatalf("write override.rego: %v", err)
	}

	_, err = s.Reload(context.Background())
	if err == nil {
		t.Fatal("expected Reload to fail when smoke test fails, got nil")
	}
	if !strings.Contains(err.Error(), "smoke test failed") {
		t.Fatalf("unexpected error message: %v", err)
	}

	if s.Current() != oldSnap {
		t.Fatal("Current() snapshot changed despite failed Reload smoke check")
	}
	if s.Current().Epoch != 1 {
		t.Fatalf("epoch changed to %d, want 1", s.Current().Epoch)
	}
}

// B9 audit fix: verify smoke test handles missing bypass_unknown_keys flag gracefully by defaulting to closedMode=true
func TestDryRunSmoke_ClosedModeDefault(t *testing.T) {
	ctx := context.Background()

	raw := loadTestData(t)

	// 1. Data without bypass_unknown_keys flag (closed mode default)
	var dataWithoutFlag map[string]any
	if err := json.Unmarshal(raw, &dataWithoutFlag); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cfg := dataWithoutFlag["config"].(map[string]any)
	delete(cfg, "bypass_unknown_keys")
	dataWithoutFlagBytes, _ := json.Marshal(dataWithoutFlag)

	snapWithoutFlag, err := Load(ctx, policyDir, dataWithoutFlagBytes, 1)
	if err != nil {
		t.Fatalf("Load without flag: %v", err)
	}

	// Smoke test must PASS on data without bypass_unknown_keys flag
	if err := DryRunSmoke(ctx, snapWithoutFlag); err != nil {
		t.Fatalf("DryRunSmoke failed with closedMode default (missing flag): %v", err)
	}

	// 2. Data with bypass_unknown_keys == true (onboarding mode)
	snapWithFlagTrue, err := Load(ctx, policyDir, raw, 2)
	if err != nil {
		t.Fatalf("Load with flag true: %v", err)
	}

	// Smoke test must PASS on data with bypass_unknown_keys == true
	if err := DryRunSmoke(ctx, snapWithFlagTrue); err != nil {
		t.Fatalf("DryRunSmoke failed with bypass_unknown_keys=true: %v", err)
	}
}

// TestDryRunSmoke_ClosedModeBrokenPolicyFails verifies R6:
// In closed mode (bypass_unknown_keys=false), if policy is broken (e.g. rm -rf allowed),
// DryRunSmoke must FAIL instead of silently passing via config.unknown_key_closed.
func TestDryRunSmoke_ClosedModeBrokenPolicyFails(t *testing.T) {
	ctx := context.Background()

	// Create temp policy dir with a broken policy that allows rm -rf
	tmpDir := t.TempDir()
	if err := os.CopyFS(tmpDir, os.DirFS("../../policies")); err != nil {
		t.Fatalf("copy policies: %v", err)
	}

	// Corrupt ai.rego: make tool decision unconditionally allow
	brokenAIRego := `package stages.ai
import rego.v1
default tool_decision := {"decision": "allow", "rule_id": "ai.tool.allow", "reason": "broken"}
default llm_decision := {"decision": "allow", "rule_id": "ai.llm.allow", "reason": "broken"}
decision := tool_decision if input.stage == "tool"
decision := llm_decision if input.stage == "llm"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "stages", "ai.rego"), []byte(brokenAIRego), 0o600); err != nil {
		t.Fatalf("write broken ai.rego: %v", err)
	}

	raw := loadTestData(t)
	var dataWithoutFlag map[string]any
	if err := json.Unmarshal(raw, &dataWithoutFlag); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cfg := dataWithoutFlag["config"].(map[string]any)
	cfg["bypass_unknown_keys"] = false
	dataClosedBytes, _ := json.Marshal(dataWithoutFlag)

	snapBroken, err := Load(ctx, tmpDir, dataClosedBytes, 1)
	if err != nil {
		t.Fatalf("Load broken policy: %v", err)
	}

	// In closed mode, DryRunSmoke MUST FAIL on the broken policy (e.g. on rm -rf wanting deny)
	if err := DryRunSmoke(ctx, snapBroken); err == nil {
		t.Fatal("expected DryRunSmoke to fail in closed mode with broken policy allowing rm -rf, but got nil")
	}
}
