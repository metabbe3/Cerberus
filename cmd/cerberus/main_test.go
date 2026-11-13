package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/metabbe3/cerberus/internal/server"
)

// TestServerCutsOffSlowBody reproduces the code-review finding: a client that
// declares a 1MiB body and trickles it one byte at a time must have its
// connection cut off by the server instead of parking a goroutine in
// readBody's io.ReadAll forever.
func TestServerCutsOffSlowBody(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer(l.Addr().String(), server.New(server.Deps{})) // readBody runs before any engine use
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	req := "POST /v1/decide HTTP/1.1\r\nHost: cerberus\r\nContent-Type: application/json\r\nContent-Length: 1048576\r\n\r\n{"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	go func() { // trickle the rest, one byte every 50ms, forever
		for {
			if _, err := conn.Write([]byte("x")); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	done := make(chan string, 1)
	go func() {
		raw, _ := io.ReadAll(conn) // returns once the server cuts the connection
		done <- string(raw)
	}()
	select {
	case resp := <-done:
		if !strings.Contains(resp, "400 Bad Request") {
			t.Fatalf("expected the cut-off to surface as 400 Bad Request, got %q", resp)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("slow-body trickle was not cut off; a goroutine is parked in readBody forever")
	}
}

func TestSetupVerificationKey_ValidBase64(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64Key := base64.StdEncoding.EncodeToString(pub)
	store := policy.NewStoreWithSnapshot(nil)

	if err := setupVerificationKey(store, b64Key); err != nil {
		t.Fatalf("setupVerificationKey failed: %v", err)
	}
	if !bytes.Equal(store.VerificationKey(), pub) {
		t.Fatalf("stored verification key = %x, want %x", store.VerificationKey(), pub)
	}
}

func TestSetupVerificationKey_CorruptedKeyReturnsError(t *testing.T) {
	store := policy.NewStoreWithSnapshot(nil)
	if err := setupVerificationKey(store, "not-a-valid-base64-or-key!"); err == nil {
		t.Fatal("expected error for corrupted key string, got nil")
	}
	if store.VerificationKey() != nil {
		t.Fatalf("expected nil verification key on error, got %x", store.VerificationKey())
	}
}

func TestSetupVerificationKey_EmptyKeyOmitted(t *testing.T) {
	store := policy.NewStoreWithSnapshot(nil)
	if err := setupVerificationKey(store, ""); err != nil {
		t.Fatalf("expected nil error for empty key, got %v", err)
	}
	if store.VerificationKey() != nil {
		t.Fatalf("expected nil verification key when empty, got %x", store.VerificationKey())
	}
}
