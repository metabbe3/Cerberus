package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBreakGlass_NoDeadlock(t *testing.T) {
	bg := newBreakGlassManager()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: Status loop (reader)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_ = bg.Status("key-1")
			}
		}
	}()

	// Goroutine 2: Activate loop (writer)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				bg.Activate("key-1", 10*time.Millisecond, "test reason")
				time.Sleep(100 * time.Microsecond)
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Succeeded without deadlock
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: goroutines did not finish within timeout")
	}
}

// TestBreakGlassKeyIDValidation verifies D3:
// 1. X-Break-Glass header with body missing key_id returns 400 Bad Request.
// 2. X-Break-Glass header with valid key_id arms break-glass for that key only (per-key).
// 3. X-Break-Glass header with key_id="*" explicitly arms global bypass.
func TestBreakGlassKeyIDValidation(t *testing.T) {
	h := newHarness(t)

	// 1. Header without key_id -> 400 Bad Request
	bodyNoKey := `{"action":"write","resource":"/prod/db"}`
	req1, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/decide", strings.NewReader(bodyNoKey))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Authorization", "Bearer "+adminToken)
	req1.Header.Set("X-Break-Glass", "emergency test")
	resp1, err := h.ts.Client().Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp1.Body.Close() }()
	if resp1.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 when key_id missing with break-glass, got %d", resp1.StatusCode)
	}

	// 2. Header with valid key_id -> armed per-key
	bodyKeyA := `{"key_id":"key-a","action":"write","resource":"/prod/db"}`
	req2, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/decide", strings.NewReader(bodyKeyA))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+adminToken)
	req2.Header.Set("X-Break-Glass", "emergency for key-a")
	resp2, err := h.ts.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for valid key break-glass, got %d", resp2.StatusCode)
	}
	// Verify key-a is armed and key-b is NOT armed
	activeA, _ := h.api.breakGlass.IsActive("key-a")
	activeB, _ := h.api.breakGlass.IsActive("key-b")
	if !activeA {
		t.Fatal("expected key-a break-glass to be active")
	}
	if activeB {
		t.Fatal("expected key-b break-glass to NOT be active (should be per-key, not global)")
	}

	// 3. Header with key_id="*" -> armed global
	bodyGlobal := `{"key_id":"*","action":"write","resource":"/prod/db"}`
	req3, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/decide", strings.NewReader(bodyGlobal))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Authorization", "Bearer "+adminToken)
	req3.Header.Set("X-Break-Glass", "global emergency")
	resp3, err := h.ts.Client().Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp3.Body.Close() }()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for '*' break-glass, got %d", resp3.StatusCode)
	}
	// Now any key should be active due to global bypass
	activeAny, _ := h.api.breakGlass.IsActive("any-other-key")
	if !activeAny {
		t.Fatal("expected global break-glass to be active for all keys when key_id='*'")
	}
}

// TestPrivilegedAdmin_UnixSocketTrust verifies R5:
// 1. Caller with RemoteAddr="" without admin token is NOT admin (returns 401 when claiming privileged key).
// 2. Caller with RemoteAddr="@" without CERBERUS_TRUST_UNIX_SOCKET is NOT admin (returns 401).
// 3. Caller with RemoteAddr="@" with CERBERUS_TRUST_UNIX_SOCKET=true IS privileged admin (allowed).
func TestPrivilegedAdmin_UnixSocketTrust(t *testing.T) {
	h := newHarness(t)

	// 1. RemoteAddr="" without token claiming k-owner -> 401 Unauthorized
	body := `{"key_id":"k-owner","stage":"tool","tool_call":"bash","args":{"cmd":"ls"}}`
	req1 := httptest.NewRequest(http.MethodPost, "/v1/decide", strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.RemoteAddr = ""
	w1 := httptest.NewRecorder()
	h.api.ServeHTTP(w1, req1)
	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for RemoteAddr='' claiming k-owner, got %d: %s", w1.Code, w1.Body.String())
	}

	// 2. RemoteAddr="@" without env CERBERUS_TRUST_UNIX_SOCKET -> 401 Unauthorized
	t.Setenv("CERBERUS_TRUST_UNIX_SOCKET", "")
	req2 := httptest.NewRequest(http.MethodPost, "/v1/decide", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.RemoteAddr = "@"
	w2 := httptest.NewRecorder()
	h.api.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for RemoteAddr='@' without trust env, got %d: %s", w2.Code, w2.Body.String())
	}

	// 3. RemoteAddr="@" with CERBERUS_TRUST_UNIX_SOCKET=true -> 200 OK (treated as privileged admin)
	t.Setenv("CERBERUS_TRUST_UNIX_SOCKET", "true")
	req3 := httptest.NewRequest(http.MethodPost, "/v1/decide", strings.NewReader(body))
	req3.Header.Set("Content-Type", "application/json")
	req3.RemoteAddr = "@"
	w3 := httptest.NewRecorder()
	h.api.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 for RemoteAddr='@' with CERBERUS_TRUST_UNIX_SOCKET=true, got %d: %s", w3.Code, w3.Body.String())
	}
}
