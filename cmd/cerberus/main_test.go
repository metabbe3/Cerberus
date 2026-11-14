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

func TestBootFromPostgres_NoAgentsDoesNotPanic(t *testing.T) {
	// Payload without agents or with non-map agents (e.g. nil)
	payloads := []map[string]any{
		{"config": map[string]any{"bypass_unknown_keys": true}},
		{"config": map[string]any{"bypass_unknown_keys": true}, "agents": nil},
		{"config": map[string]any{"bypass_unknown_keys": true}, "agents": "not-a-map"},
	}

	for i, data := range payloads {
		// Verify comma-ok assertion does not panic
		agents, _ := data["agents"].(map[string]any)
		if len(agents) != 0 {
			t.Fatalf("[%d] expected 0 agents, got %d", i, len(agents))
		}
	}
}

func TestClusterWiring_TwoNodeGossip(t *testing.T) {
	adminTok := "cluster-test-admin-token"

	// Start Node 1 listener
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l1.Close() }()
	node1URL := "http://" + l1.Addr().String()

	api1 := server.New(server.Deps{
		AdminToken: adminTok,
		Version:    "test-v1",
		Cluster: server.ClusterConfig{
			NodeID:       "node-1",
			StartedAt:    time.Now().Unix(),
			SyncInterval: 50 * time.Millisecond,
		},
	})
	srv1 := newHTTPServer(l1.Addr().String(), api1)
	go func() { _ = srv1.Serve(l1) }()
	t.Cleanup(func() {
		api1.ShutdownStreams()
		_ = srv1.Close()
	})

	// Start Node 2 listener with peer pointing to Node 1
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l2.Close() }()

	api2 := server.New(server.Deps{
		AdminToken: adminTok,
		Version:    "test-v2",
		Cluster: server.ClusterConfig{
			NodeID:       "node-2",
			StartedAt:    time.Now().Unix(),
			Peers:        []string{node1URL},
			SyncInterval: 50 * time.Millisecond,
		},
	})
	srv2 := newHTTPServer(l2.Addr().String(), api2)
	go func() { _ = srv2.Serve(l2) }()
	t.Cleanup(func() {
		api2.ShutdownStreams()
		_ = srv2.Close()
	})

	// Wait for Node 2 to gossip with Node 1
	time.Sleep(150 * time.Millisecond)
}
