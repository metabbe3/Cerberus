// Command cerberus-bundle builds and verifies signed OPA-compatible bundles for Cerberus.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/metabbe3/cerberus/internal/policy"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "build":
		if err := runBuild(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "build error: %v\n", err)
			os.Exit(1)
		}
	case "verify":
		if err := runVerify(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "verify error: %v\n", err)
			os.Exit(1)
		}
	case "coverage":
		if err := runCoverage(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "coverage error: %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  cerberus-bundle build [-k <keyfile>] -d <dir> <out.tar.gz>
  cerberus-bundle verify -k <pubkey> <bundle.tar.gz>
  cerberus-bundle coverage [-d <dir>] [--json]
`)
}

func runBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	var keyFile, dir string
	fs.StringVar(&keyFile, "k", "", "path to ed25519 private key (optional)")
	fs.StringVar(&dir, "d", "", "directory containing bundle contents (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if dir == "" {
		return fmt.Errorf("-d <dir> is required")
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("missing output bundle path")
	}
	outFile := fs.Arg(0)

	files := make(map[string][]byte)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.rego") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[rel] = data
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk directory %s: %w", dir, err)
	}

	if keyFile != "" {
		keyBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("read private key: %w", err)
		}
		privKey, err := policy.ParsePrivateKey(keyBytes)
		if err != nil {
			return fmt.Errorf("parse private key: %w", err)
		}
		sigBytes, err := policy.SignBundle(files, privKey)
		if err != nil {
			return fmt.Errorf("sign bundle: %w", err)
		}
		files["signatures.json"] = sigBytes
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, data := range files {
		hdr := &tar.Header{
			Name: name,
			Size: int64(len(data)),
			Mode: 0o644,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write tar header %s: %w", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("write tar data %s: %w", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("close gzip: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil && filepath.Dir(outFile) != "." {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := os.WriteFile(outFile, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write out file %s: %w", outFile, err)
	}

	fmt.Printf("Bundle built successfully: %s (%d files)\n", outFile, len(files))
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var pubKeyFile string
	fs.StringVar(&pubKeyFile, "k", "", "path to ed25519 public key (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if pubKeyFile == "" {
		return fmt.Errorf("-k <pubkey> is required")
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("missing bundle file path")
	}
	bundlePath := fs.Arg(0)

	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}

	pubBytes, err := os.ReadFile(pubKeyFile)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	pubKey, err := policy.ParsePublicKey(pubBytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	b, err := policy.ReadBundle(bytes.NewReader(bundleBytes))
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}

	if err := policy.VerifyBundle(b.RawFiles, b.SignaturesJSON, pubKey); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Printf("bundle signature valid (verified %d files)\n", len(b.RawFiles)-1)
	return nil
}

func runCoverage(args []string) error {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	var dir string
	var jsonOutput bool
	fs.StringVar(&dir, "d", "policies", "directory containing policies to test")
	fs.BoolVar(&jsonOutput, "json", false, "output report as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 && dir == "policies" {
		dir = fs.Arg(0)
	}

	rep, err := policy.ComputeCoverage(dir)
	if err != nil {
		return err
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}

	fmt.Printf("Policy Test Coverage: %.2f%% (%d covered, %d uncovered lines across %d files)\n",
		rep.Coverage, rep.CoveredLines, rep.NotCoveredLines, len(rep.Files))
	fmt.Println("Files:")
	for _, f := range rep.SortedFiles() {
		fr := rep.Files[f]
		fmt.Printf("  %-35s %.2f%% (%d/%d lines)\n",
			f, fr.Coverage, fr.CoveredLines, fr.CoveredLines+fr.NotCoveredLines)
	}
	return nil
}

