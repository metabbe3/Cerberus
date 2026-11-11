package policy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Bundle represents an unpacked OPA-style bundle in memory.
type Bundle struct {
	Manifest  []byte
	DataJSON  []byte
	RegoFiles map[string][]byte
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
		if _, err := io.Copy(&buf, tr); err != nil {
			return nil, fmt.Errorf("bundle: read entry %s: %w", name, err)
		}
		content := buf.Bytes()

		switch {
		case name == ".manifest" || strings.HasSuffix(name, "/.manifest"):
			b.Manifest = content
		case name == "data.json" || strings.HasSuffix(name, "/data.json"):
			b.DataJSON = content
		case strings.HasSuffix(name, ".rego") && !strings.HasSuffix(name, "_test.rego"):
			b.RegoFiles[name] = content
		}
	}

	if len(b.DataJSON) == 0 {
		return nil, fmt.Errorf("bundle: %w: missing data.json", ErrData)
	}
	if len(b.RegoFiles) == 0 {
		return nil, fmt.Errorf("bundle: %w: no rego policy files found", ErrCompile)
	}

	return b, nil
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

	// Unpack to a temporary directory for validation
	tmpDir, err := os.MkdirTemp("", "cerberus-bundle-*")
	if err != nil {
		return nil, fmt.Errorf("bundle: temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	for name, content := range b.RegoFiles {
		// Clean and flatten or recreate relative paths
		rel := filepath.Clean(name)
		if strings.HasPrefix(rel, "policies/") {
			rel = strings.TrimPrefix(rel, "policies/")
		}
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

	// If store has paths configured on disk, persist the bundle contents so
	// reload or disk readers also observe them.
	if s.policyDir != "" {
		for name, content := range b.RegoFiles {
			rel := filepath.Clean(name)
			if strings.HasPrefix(rel, "policies/") {
				rel = strings.TrimPrefix(rel, "policies/")
			}
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

	s.ptr.Store(snap)
	if s.onSwap != nil {
		s.onSwap(snap)
	}
	return snap, nil
}

// LoadBundleFile reads a bundle.tar.gz from path and calls LoadBundle.
func (s *Store) LoadBundleFile(ctx context.Context, path string) (*Snapshot, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator configured path
	if err != nil {
		return nil, fmt.Errorf("bundle: read file %s: %w", path, err)
	}
	return s.LoadBundle(ctx, raw)
}
