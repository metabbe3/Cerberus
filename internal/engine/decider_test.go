package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPDecider_Allow(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decide" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var in Input
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Decision{
			Decision: "allow",
			RuleID:   "test.allow",
			Reason:   "allowed",
			Epoch:    42,
		})
	}))
	defer ts.Close()

	dec := NewHTTPDecider(ts.URL, "test-tok")
	d := dec.Decide(context.Background(), Input{
		Stage:    "docker",
		KeyID:    "k-test",
		Action:   "GET",
		Resource: "/containers/json",
	})
	if d.Decision != "allow" {
		t.Fatalf("expected allow, got %s (rule: %s, reason: %s)", d.Decision, d.RuleID, d.Reason)
	}
	if d.RuleID != "test.allow" || d.Epoch != 42 {
		t.Fatalf("unexpected decision payload: %+v", d)
	}
}

func TestHTTPDecider_Deny(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Decision{
			Decision: "deny",
			RuleID:   "shield.container.protected",
			Reason:   "protected container",
		})
	}))
	defer ts.Close()

	dec := NewHTTPDecider(ts.URL, "test-tok")
	d := dec.Decide(context.Background(), Input{
		Stage:    "docker",
		KeyID:    "k-test",
		Action:   "DELETE",
		Resource: "/containers/prod-db",
	})
	if d.Decision != "deny" || d.RuleID != "shield.container.protected" {
		t.Fatalf("expected deny shield.container.protected, got %+v", d)
	}
}

func TestHTTPDecider_FailClosedOnUnreachable(t *testing.T) {
	// Point to dead server port
	dec := NewHTTPDecider("http://127.0.0.1:54321", "test-tok")
	d := dec.Decide(context.Background(), Input{Stage: "http", Action: "CONNECT"})
	if d.Decision != "deny" {
		t.Fatalf("expected fail-closed deny, got %s", d.Decision)
	}
	if d.RuleID != "proxy.engine_unreachable" {
		t.Fatalf("expected rule_id proxy.engine_unreachable, got %s", d.RuleID)
	}
}

func TestHTTPDecider_FailClosedOnServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	dec := NewHTTPDecider(ts.URL, "test-tok")
	d := dec.Decide(context.Background(), Input{Stage: "http", Action: "CONNECT"})
	if d.Decision != "deny" {
		t.Fatalf("expected fail-closed deny, got %s", d.Decision)
	}
	if d.RuleID != "proxy.engine_unreachable" {
		t.Fatalf("expected rule_id proxy.engine_unreachable, got %s", d.RuleID)
	}
}

func TestHTTPDecider_FailClosedOnTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	dec := NewHTTPDecider(ts.URL, "test-tok")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	d := dec.Decide(ctx, Input{Stage: "http", Action: "CONNECT"})
	if d.Decision != "deny" {
		t.Fatalf("expected fail-closed deny on timeout, got %s", d.Decision)
	}
	if d.RuleID != "proxy.engine_unreachable" {
		t.Fatalf("expected rule_id proxy.engine_unreachable, got %s", d.RuleID)
	}
}
