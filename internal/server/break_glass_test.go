package server

import (
	"context"
	"net/http"
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
