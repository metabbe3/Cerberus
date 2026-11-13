package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/metabbe3/cerberus/internal/util"
)

// ErrNoRollback is returned when rollback is requested but no previous snapshot is available.
var ErrNoRollback = errors.New("bundle: no previous snapshot available for rollback")

// ErrFutureRevision is returned when bundle revision or timestamp is from the future (clock skew).
var ErrFutureRevision = errors.New("bundle: revision timestamp is from the future (clock skew detected)")

// Manifest represents an OPA bundle manifest.
type Manifest struct {
	Revision string   `json:"revision"`
	Roots    []string `json:"roots"`
}

// Bundle represents an unpacked OPA-style bundle in memory.
type Bundle struct {
	Manifest       []byte
	ManifestObj    *Manifest
	Revision       string
	Roots          []string
	DataJSON       []byte
	SignaturesJSON []byte
	RegoFiles      map[string][]byte
	DataFiles      map[string][]byte
	RawFiles       map[string][]byte
}

// ReadBundle extracts an OPA bundle (.tar.gz) from r.
func ReadBundle(r io.Reader) (*Bundle, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("bundle: gzip open: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	b := &Bundle{
		RegoFiles: make(map[string][]byte),
		DataFiles: make(map[string][]byte),
		RawFiles:  make(map[string][]byte),
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: read tar: %w", err)
		}
		if hdr.FileInfo().IsDir() {
			continue
		}

		name := strings.TrimPrefix(hdr.Name, "/")
		name = strings.TrimPrefix(name, "./")

		var buf bytes.Buffer
		if _, err := io.Copy(&buf, tr); err != nil { //nolint:gosec // G110 signed bundle, size-capped
			return nil, fmt.Errorf("bundle: read entry %s: %w", name, err)
		}
		content := buf.Bytes()
		b.RawFiles[name] = content

		switch {
		case name == ".manifest" || strings.HasSuffix(name, "/.manifest"):
			b.Manifest = content
		case name == "signatures.json" || name == ".signatures.json" ||
			strings.HasSuffix(name, "/signatures.json") || strings.HasSuffix(name, "/.signatures.json"):
			b.SignaturesJSON = content
		case name == "data.json" || strings.HasSuffix(name, "/data.json"):
			b.DataJSON = content
		case strings.HasSuffix(name, ".json") && (strings.HasPrefix(name, "data/") || strings.Contains(name, "/data/")):
			b.DataFiles[name] = content
		case strings.HasSuffix(name, ".rego") && !strings.HasSuffix(name, "_test.rego"):
			b.RegoFiles[name] = content
		}
	}

	// Parse .manifest if present
	if len(b.Manifest) > 0 {
		var m Manifest
		if err := json.Unmarshal(b.Manifest, &m); err != nil {
			return nil, fmt.Errorf("bundle: %w: parse .manifest: %v", ErrData, err)
		}
		b.ManifestObj = &m
		b.Revision = m.Revision
		b.Roots = m.Roots

		// Refuse bundle if roots overlap with local core modules (gateway/shield)
		if err := checkRootsOverlap(m.Roots); err != nil {
			slog.Warn("bundle refused: roots overlap with local core", "err", err)
			return nil, fmt.Errorf("bundle: %w: %w", ErrData, err)
		}
	}

	// Also verify that no rego file attempts to overwrite local core modules
	for name := range b.RegoFiles {
		rel := filepath.Clean(name)
		rel = strings.TrimPrefix(rel, "policies/")
		if strings.HasPrefix(rel, "gateway/") || strings.HasPrefix(rel, "shield/") || rel == "gateway.rego" || rel == "shield.rego" {
			slog.Warn("bundle refused: rego file overlaps with local core", "file", name)
			return nil, fmt.Errorf("bundle: %w: file %s overwrites local core module (gateway/shield)", ErrData, name)
		}
	}

	// Handle data merging: root data.json + /data/* subtree
	dataMap := make(map[string]any)
	if len(b.DataJSON) > 0 {
		if err := json.Unmarshal(b.DataJSON, &dataMap); err != nil {
			return nil, fmt.Errorf("bundle: %w: decode data.json: %v", ErrData, err)
		}
	}

	for path, content := range b.DataFiles {
		if err := mergeDataSubtree(dataMap, path, content); err != nil {
			return nil, fmt.Errorf("bundle: %w: merge data subtree %s: %v", ErrData, path, err)
		}
	}

	if len(dataMap) > 0 {
		merged, err := json.Marshal(dataMap)
		if err != nil {
			return nil, fmt.Errorf("bundle: %w: marshal merged data: %v", ErrData, err)
		}
		b.DataJSON = merged
	}

	if len(b.DataJSON) == 0 {
		return nil, fmt.Errorf("bundle: %w: missing data.json or /data/* subtree", ErrData)
	}
	if len(b.RegoFiles) == 0 {
		return nil, fmt.Errorf("bundle: %w: no rego policy files found", ErrCompile)
	}

	return b, nil
}

// checkRootsOverlap verifies no root overlaps with local core modules (gateway, shield).
func checkRootsOverlap(roots []string) error {
	for _, r := range roots {
		clean := strings.TrimPrefix(r, "/")
		clean = strings.TrimPrefix(clean, "data.")
		parts := strings.FieldsFunc(clean, func(c rune) bool {
			return c == '/' || c == '.'
		})
		if len(parts) > 0 {
			top := parts[0]
			if top == "gateway" || top == "shield" {
				return fmt.Errorf("root %q overlaps with local core module %s", r, top)
			}
		}
	}
	return nil
}

// mergeDataSubtree parses content and merges into dataMap based on path under data/.
func mergeDataSubtree(dataMap map[string]any, path string, content []byte) error {
	var val any
	if err := json.Unmarshal(content, &val); err != nil {
		return err
	}

	// Clean path, remove leading "data/" or anything up to "/data/"
	clean := strings.TrimPrefix(path, "/")
	clean = strings.TrimPrefix(clean, "./")
	if idx := strings.Index(clean, "data/"); idx >= 0 {
		clean = clean[idx+len("data/"):]
	}
	clean = strings.TrimSuffix(clean, ".json")
	if clean == "" || clean == "data" {
		if vm, ok := val.(map[string]any); ok {
			for k, v := range vm {
				dataMap[k] = v
			}
			return nil
		}
		return errors.New("root data file must contain a JSON object")
	}

	keys := strings.Split(clean, "/")
	curr := dataMap
	for i, k := range keys {
		if i == len(keys)-1 {
			// If both existing and new are maps, merge
			if existing, ok := curr[k].(map[string]any); ok {
				if vm, ok := val.(map[string]any); ok {
					for ek, ev := range vm {
						existing[ek] = ev
					}
					break
				}
			}
			curr[k] = val
			break
		}
		nxt, ok := curr[k].(map[string]any)
		if !ok {
			nxt = make(map[string]any)
			curr[k] = nxt
		}
		curr = nxt
	}
	return nil
}

func isFutureRevision(rev string, manifestRaw []byte) bool {
	maxAllowed := time.Now().Add(2 * time.Minute)

	if len(manifestRaw) > 0 {
		var mf map[string]any
		if json.Unmarshal(manifestRaw, &mf) == nil {
			for _, k := range []string{"timestamp", "created_at", "created", "time"} {
				if v, ok := mf[k]; ok {
					switch val := v.(type) {
					case string:
						if t, err := time.Parse(time.RFC3339, val); err == nil && t.After(maxAllowed) {
							return true
						}
					case float64:
						t := time.Unix(int64(val), 0)
						if t.After(maxAllowed) {
							return true
						}
					}
				}
			}
		}
	}

	trimmed := strings.TrimPrefix(rev, "rev-")
	trimmed = strings.TrimPrefix(trimmed, "bundle-")
	if t, err := time.Parse(time.RFC3339, trimmed); err == nil && t.After(maxAllowed) {
		return true
	}
	if len(trimmed) >= 10 {
		if t, err := time.Parse("2006-01-02", trimmed[:10]); err == nil && t.After(maxAllowed) {
			return true
		}
	}
	if len(trimmed) >= 8 {
		if t, err := time.Parse("20060102", trimmed[:8]); err == nil && t.After(maxAllowed) {
			return true
		}
	}
	return false
}

// copyDir copies all files from src to dst.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return nil
		}
		destPath := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
			return err
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304 operator-supplied path
		if err != nil {
			return err
		}
		return os.WriteFile(destPath, data, 0o600) //nolint:gosec // G703 sanitized member path
	})
}

func strVal(v any) string {
	return util.Str(v)
}

// LoadBundle validates and installs an in-memory bundle.tar.gz.
// On success, it writes the unpacked policies and data to disk, atomically
// swaps the live Snapshot to epoch+1, and runs registered swap callbacks.
func (s *Store) LoadBundle(ctx context.Context, bundleGz []byte) (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := ReadBundle(bytes.NewReader(bundleGz))
	if err != nil {
		return nil, err
	}

	// Clock skew validation: reject revisions from the future
	if isFutureRevision(b.Revision, b.Manifest) {
		slog.Warn("bundle rejected: revision timestamp is from the future (clock skew)", "revision", b.Revision)
		return nil, ErrFutureRevision
	}

	// Signature verification: if a verification key is configured on the store,
	// the bundle MUST have a valid Ed25519 signature over all files.
	if s.verificationKey != nil {
		if err := VerifyBundle(b.RawFiles, b.SignaturesJSON, s.verificationKey); err != nil {
			slog.Warn("bundle signature verification failed", "err", err)
			return nil, fmt.Errorf("bundle: %w: %w", ErrInvalidSignature, err)
		}
	}

	// Unpack to a temporary directory for staging & validation
	tmpDir, err := os.MkdirTemp("", "cerberus-bundle-*")
	if err != nil {
		return nil, fmt.Errorf("bundle: temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Copy base policies (local core gateway/shield) into tmpDir so they are preserved
	if s.policyDir != "" {
		if err := copyDir(s.policyDir, tmpDir); err != nil {
			return nil, fmt.Errorf("bundle: copy local core policies: %w", err)
		}
	}

	// Unpack bundle's rego files into tmpDir
	for name, content := range b.RegoFiles {
		rel := filepath.Clean(name)
		rel = strings.TrimPrefix(rel, "policies/")
		dest := filepath.Join(tmpDir, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return nil, fmt.Errorf("bundle: mkdir: %w", err)
		}
		if err := os.WriteFile(dest, content, 0o600); err != nil {
			return nil, fmt.Errorf("bundle: write rego: %w", err)
		}
	}

	old := s.ptr.Load()
	snap, err := Load(ctx, tmpDir, b.DataJSON, old.Epoch+1)
	if err != nil {
		return nil, err
	}
	snap.Revision = b.Revision

	// Dry-run eval smoke: subset test fixtures must pass before activation
	if err := DryRunSmoke(ctx, snap); err != nil {
		slog.Warn("bundle rejected: dry-run smoke test failed", "err", err)
		return nil, fmt.Errorf("bundle: smoke test failed: %w", err)
	}

	// Coverage gate: bundle activation rejects if coverage drops >5 points vs active revision
	oldCov := old.Coverage
	if oldCov <= 0 && s.policyDir != "" {
		if curCov, _ := ComputeCoverage(s.policyDir); curCov != nil && curCov.TotalLines > 0 {
			oldCov = curCov.Coverage
			old.Coverage = oldCov
		}
	}
	if oldCov > 0 {
		if newCov, _ := ComputeCoverage(tmpDir); newCov != nil && newCov.TotalLines > 0 {
			if (oldCov - newCov.Coverage) > 5.0 {
				slog.Warn("bundle rejected: coverage drop exceeds threshold", "old_coverage", oldCov, "new_coverage", newCov.Coverage)
				return nil, fmt.Errorf("bundle activation rejected: coverage dropped by %.2f points (active: %.2f%%, bundle: %.2f%%, max allowed drop: 5.0%%)",
					oldCov-newCov.Coverage, oldCov, newCov.Coverage)
			}
			snap.Coverage = newCov.Coverage
		}
	}

	// If store has paths configured on disk, persist the bundle contents so
	// reload or disk readers also observe them.
	if s.policyDir != "" {
		for name, content := range b.RegoFiles {
			rel := filepath.Clean(name)
			rel = strings.TrimPrefix(rel, "policies/")
			dest := filepath.Join(s.policyDir, rel)
			if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
				return nil, fmt.Errorf("bundle: install mkdir: %w", err)
			}
			if err := writeAtomic(dest, content); err != nil {
				return nil, fmt.Errorf("bundle: install rego: %w", err)
			}
		}
	}
	if s.dataPath != "" {
		if err := writeAtomic(s.dataPath, b.DataJSON); err != nil {
			return nil, fmt.Errorf("bundle: install data: %w", err)
		}
	}

	// Save previous state for instant rollback
	s.prevSnapshot = old
	s.prevBundle = s.currentBundle
	s.currentBundle = bundleGz

	// Atomic swap
	s.ptr.Store(snap)
	if s.onSwap != nil {
		s.onSwap(snap)
	}
	return snap, nil
}

// LoadBundleFile reads a bundle.tar.gz from path and calls LoadBundle.
func (s *Store) LoadBundleFile(ctx context.Context, path string) (*Snapshot, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304 operator-supplied path // #nosec G304 -- operator configured path
	if err != nil {
		return nil, fmt.Errorf("bundle: read file %s: %w", path, err)
	}
	return s.LoadBundle(ctx, raw)
}

// Rollback restores the previous bundle snapshot atomically with epoch+1.
func (s *Store) Rollback(ctx context.Context) (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.prevSnapshot == nil && len(s.prevBundle) == 0 {
		return nil, ErrNoRollback
	}

	old := s.ptr.Load()
	var rolledBack *Snapshot

	if len(s.prevBundle) > 0 {
		b, err := ReadBundle(bytes.NewReader(s.prevBundle))
		if err != nil {
			return nil, fmt.Errorf("rollback: read prev bundle: %w", err)
		}

		tmpDir, err := os.MkdirTemp("", "cerberus-rollback-*")
		if err != nil {
			return nil, fmt.Errorf("rollback: temp dir: %w", err)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		if s.policyDir != "" {
			_ = copyDir(s.policyDir, tmpDir)
		}
		for name, content := range b.RegoFiles {
			rel := filepath.Clean(name)
			rel = strings.TrimPrefix(rel, "policies/")
			dest := filepath.Join(tmpDir, rel)
			_ = os.MkdirAll(filepath.Dir(dest), 0o750)
			_ = os.WriteFile(dest, content, 0o600)
		}

		snap, err := Load(ctx, tmpDir, b.DataJSON, old.Epoch+1)
		if err != nil {
			return nil, fmt.Errorf("rollback: load prev bundle: %w", err)
		}
		snap.Revision = b.Revision

		if s.policyDir != "" {
			for name, content := range b.RegoFiles {
				rel := filepath.Clean(name)
				rel = strings.TrimPrefix(rel, "policies/")
				dest := filepath.Join(s.policyDir, rel)
				_ = os.MkdirAll(filepath.Dir(dest), 0o750)
				_ = writeAtomic(dest, content)
			}
		}
		if s.dataPath != "" {
			_ = writeAtomic(s.dataPath, b.DataJSON)
		}

		rolledBack = snap
	} else if s.prevSnapshot != nil {
		rolledBack = &Snapshot{
			Epoch:    old.Epoch + 1,
			EpochStr: strconv.FormatUint(old.Epoch+1, 10),
			Revision: s.prevSnapshot.Revision,
			Query:    s.prevSnapshot.Query,
			Data:     s.prevSnapshot.Data,
			Maskers:  s.prevSnapshot.Maskers,
			Loaded:   time.Now(),
		}
	}

	s.currentBundle = s.prevBundle
	s.prevBundle = nil
	s.prevSnapshot = nil

	s.ptr.Store(rolledBack)
	if s.onSwap != nil {
		s.onSwap(rolledBack)
	}
	return rolledBack, nil
}
