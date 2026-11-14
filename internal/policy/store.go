package policy

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

type swapSub struct {
	id uint64
	fn func(*Snapshot)
}

// Store holds the current Snapshot behind an atomic pointer. Current is
// lock-free on the hot path; mu only serializes Reload/ReplaceData against
// each other so epochs increase monotonically.
type Store struct {
	ptr             atomic.Pointer[Snapshot]
	policyDir       string
	dataPath        string
	verificationKey ed25519.PublicKey
	mu              sync.Mutex
	// onSwaps holds callbacks invoked after each successful swap.
	// Protected by mu.
	onSwaps         []swapSub
	nextSwapID      uint64
	prevSnapshot    *Snapshot
	prevBundle      []byte
	prevAddedFiles  []string
	prevOverwritten map[string][]byte
	prevDataJSON    []byte
	currentBundle   []byte
}

// SetVerificationKey sets the public key used to verify incoming bundles.
func (s *Store) SetVerificationKey(k ed25519.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verificationKey = k
}

// VerificationKey returns the currently configured bundle verification public key.
func (s *Store) VerificationKey() ed25519.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verificationKey
}

// CurrentBundle returns the active bundle tar.gz bytes, or nil if none loaded.
func (s *Store) CurrentBundle() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentBundle
}

// SetCurrentBundle updates the stored active bundle tar.gz bytes.
func (s *Store) SetCurrentBundle(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentBundle = b
}

// OnSwap registers f to run after each successful snapshot swap (Reload,
// ReplaceData, LoadBundle, Rollback). Callbacks are executed under mu in registration order.
// It returns a cancel function that unsubscribes the callback.
func (s *Store) OnSwap(f func(*Snapshot)) func() {
	if f == nil {
		return func() {}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextSwapID++
	id := s.nextSwapID
	s.onSwaps = append(s.onSwaps, swapSub{id: id, fn: f})
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for i, sub := range s.onSwaps {
			if sub.id == id {
				s.onSwaps = append(s.onSwaps[:i], s.onSwaps[i+1:]...)
				break
			}
		}
	}
}

func (s *Store) notifySwaps(snap *Snapshot) {
	for _, sub := range s.onSwaps {
		if sub.fn != nil {
			sub.fn(snap)
		}
	}
}

// SwapCallbacksLen returns the number of active OnSwap callbacks (used for testing).
func (s *Store) SwapCallbacksLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.onSwaps)
}

// NewStore builds the first Snapshot (epoch 1) from policyDir and dataPath.
func NewStore(ctx context.Context, policyDir, dataPath string) (*Store, error) {
	s := &Store{policyDir: policyDir, dataPath: dataPath}
	snap, err := LoadFiles(ctx, policyDir, dataPath, 1)
	if err != nil {
		return nil, err
	}
	s.ptr.Store(snap)
	return s, nil
}

// NewStoreWithSnapshot wraps an existing Snapshot into a Store (primarily for tests).
func NewStoreWithSnapshot(snap *Snapshot) *Store {
	s := &Store{}
	s.ptr.Store(snap)
	return s
}

// Current returns the live snapshot, lock-free; never nil after NewStore.
func (s *Store) Current() *Snapshot { return s.ptr.Load() }

// PolicyDir returns the directory the Rego bundle is compiled from.
func (s *Store) PolicyDir() string { return s.policyDir }

// Coverage computes the current test coverage across policies.
func (s *Store) Coverage(ctx context.Context) (*CoverageReport, error) {
	if s.policyDir == "" {
		return &CoverageReport{}, nil
	}
	rep, err := ComputeCoverage(ctx, s.policyDir)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if snap := s.ptr.Load(); snap != nil && rep != nil {
		next := *snap
		next.Coverage = rep.Coverage
		s.ptr.Store(&next)
	}
	s.mu.Unlock()
	return rep, nil
}

// Reload recompiles the snapshot from the policy and data files on disk. On
// error the old snapshot stays live and the epoch is unchanged.
func (s *Store) Reload(ctx context.Context) (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.ptr.Load()
	snap, err := LoadFiles(ctx, s.policyDir, s.dataPath, old.Epoch+1)
	if err != nil {
		return nil, err
	}
	if err := DryRunSmoke(ctx, snap); err != nil {
		return nil, fmt.Errorf("smoke test failed: %w", err)
	}
	s.ptr.Store(snap)
	s.notifySwaps(snap)
	return snap, nil
}

// ReplaceData validates dataJSON against the policy, writes it to dataPath
// atomically (temp file + rename), then swaps the snapshot in. On error the
// old snapshot stays live and dataPath is untouched.
func (s *Store) ReplaceData(ctx context.Context, dataJSON []byte) (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.ptr.Load()
	snap, err := Load(ctx, s.policyDir, dataJSON, old.Epoch+1)
	if err != nil {
		return nil, err
	}
	if err := DryRunSmoke(ctx, snap); err != nil {
		return nil, fmt.Errorf("smoke test failed: %w", err)
	}
	if err := writeAtomic(s.dataPath, dataJSON); err != nil {
		return nil, err
	}
	s.ptr.Store(snap)
	s.notifySwaps(snap)
	return snap, nil
}

// syncFile and syncDir are vars for test injection; the real ones fsync.
var syncFile = func(f *os.File) error { return f.Sync() }

// syncDir fsyncs dir so a rename into it survives a crash (on XFS, or ext4
// without auto_da_alloc, rename is not durable until the directory is synced).
var syncDir = func(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- dir comes from the configured data path
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// writeAtomic writes b to path via a temp file in the same directory plus
// rename, so concurrent readers never observe a partial file. The temp file is
// fsynced before close and the directory after rename, so the write survives
// power loss: without the file fsync the file can land empty/truncated, and
// without the dir fsync the rename itself can be lost.
func writeAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("policy: write data %s: %w", path, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op once renamed
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("policy: write data %s: %w", path, err)
	}
	if err := syncFile(tmp); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("policy: write data %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("policy: write data %s: %w", path, err)
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return fmt.Errorf("policy: write data %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("policy: write data %s: %w", path, err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("policy: sync dir %s: %w", dir, err)
	}
	return nil
}
