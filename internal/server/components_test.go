package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestComponentsHandler verifies the one-endpoint estate report: every
// component row present, status vocabulary bounded, admin-gated.
func TestComponentsHandler(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/health/components", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	h.ts.Config.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		CheckedAt  string           `json:"checked_at"`
		Components []map[string]any `json:"components"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	names := map[string]bool{}
	for _, c := range body.Components {
		names[c["component"].(string)] = true
		st := c["status"].(string)
		if st != "ok" && st != "degraded" && st != "down" {
			t.Fatalf("component %s: bad status %q", c["component"], st)
		}
	}
	for _, want := range []string{"engine", "agents", "kill_switch", "postgres", "audit"} {
		if !names[want] {
			t.Fatalf("missing component %q in %v", want, names)
		}
	}
	// Unauthenticated must be rejected.
	rec2 := httptest.NewRecorder()
	h.ts.Config.Handler.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/v1/health/components", nil))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status %d, want 401", rec2.Code)
	}
}

// TestCoverageComponentsConcurrent verifies D2:
// concurrent calls to Coverage() and Components() do not trigger data races.
func TestCoverageComponentsConcurrent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	const iterations = 10

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if h.store != nil {
				_, _ = h.store.Coverage(ctx)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest(http.MethodGet, "/v1/health/components", nil)
			req.Header.Set("Authorization", "Bearer "+adminToken)
			rec := httptest.NewRecorder()
			h.ts.Config.Handler.ServeHTTP(rec, req)
		}
	}()

	wg.Wait()
}
