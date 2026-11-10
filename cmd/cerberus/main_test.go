package main

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

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
