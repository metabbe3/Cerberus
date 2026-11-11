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
