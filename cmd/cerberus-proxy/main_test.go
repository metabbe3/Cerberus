package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestCerberusProxy_Version(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run . --version failed: %v, out: %s", err, out)
	}
	if !strings.HasPrefix(string(out), "cerberus-proxy dev") {
		t.Fatalf("unexpected version output: %s", out)
	}
}
