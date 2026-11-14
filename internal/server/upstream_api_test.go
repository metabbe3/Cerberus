package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/auth"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/metabbe3/cerberus/internal/upstream"
)

func newUpstreamTestServer(t *testing.T) (*Server, *audit.Logger, *auth.Store, *upstream.Store) {
	t.Helper()
	ctx := context.Background()

	al, err := audit.Open(ctx, ":memory:", audit.Options{
		FlushEvery: 5 * time.Millisecond,
		BatchSize:  1,
	})
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = al.Close() })

	authStore, err := auth.NewMemoryStore()
	if err != nil {
		t.Fatalf("auth.NewMemoryStore: %v", err)
	}

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	upStore, err := upstream.NewMemoryStore(masterKey)
	if err != nil {
		t.Fatalf("upstream.NewMemoryStore: %v", err)
	}

	dataPath := filepath.Join(t.TempDir(), "data.json")
	raw, err := os.ReadFile(testData)
	if err != nil {
		t.Fatalf("read testData: %v", err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("unmarshal testData: %v", err)
	}
	agents, _ := fixture["agents"].(map[string]any)
	if agents == nil {
		agents = make(map[string]any)
	}
	agents["k-test"] = map[string]any{"name": "test-agent", "allowed_tools": []string{"bash"}}
	agents["k-private"] = map[string]any{"name": "private-agent", "allowed_tools": []string{"bash"}, "capture": false}
	fixture["agents"] = agents

	modifiedRaw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(dataPath, modifiedRaw, 0o600); err != nil {
		t.Fatalf("write data.json: %v", err)
	}

	store, err := policy.NewStore(ctx, "../../policies", dataPath)
	if err != nil {
		t.Fatalf("policy.NewStore: %v", err)
	}

	eng, err := engine.New(store, al, engine.Options{EvalTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	srv := New(Deps{
		Engine:     eng,
		Store:      store,
		Audit:      al,
		Auth:       authStore,
		Upstream:   upStore,
		AdminToken: "admin-secret-token",
	})

	return srv, al, authStore, upStore
}

func TestUpstreamAPI_CRUDAndViewerRBAC(t *testing.T) {
	srv, al, authStore, _ := newUpstreamTestServer(t)

	// Create a viewer user and session
	_, err := authStore.CreateUser(context.Background(), "viewer1", "ViewerPassword123!", auth.RoleViewer)
	if err != nil {
		t.Fatalf("CreateUser viewer: %v", err)
	}
	_, viewerToken, _, err := authStore.Authenticate(context.Background(), "viewer1", "ViewerPassword123!", "127.0.0.1")
	if err != nil {
		t.Fatalf("Authenticate viewer: %v", err)
	}

	// 1. Initial GET on empty upstream
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/upstream", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var emptyResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &emptyResp)
	if emptyResp["endpoint"] != "" {
		t.Errorf("expected empty endpoint, got %v", emptyResp["endpoint"])
	}

	// 2. Viewer cannot mutate via PUT (403 Forbidden)
	putPayload := []byte(`{"endpoint":"https://api.openai.com/v1","api_key":"sk-secretkey1234"}`)
	req = httptest.NewRequest(http.MethodPut, "/v1/admin/upstream", bytes.NewReader(putPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for viewer on PUT /v1/admin/upstream, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Admin PUT with invalid URL rejected (400)
	invalidPayload := []byte(`{"endpoint":"invalid-url","api_key":"sk-secretkey1234"}`)
	req = httptest.NewRequest(http.MethodPut, "/v1/admin/upstream", bytes.NewReader(invalidPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on invalid URL, got %d: %s", w.Code, w.Body.String())
	}

	// 4. Admin PUT with valid config succeeds (200)
	req = httptest.NewRequest(http.MethodPut, "/v1/admin/upstream", bytes.NewReader(putPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on valid PUT, got %d: %s", w.Code, w.Body.String())
	}

	var putResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &putResp)
	if putResp["endpoint"] != "https://api.openai.com/v1" {
		t.Errorf("expected endpoint https://api.openai.com/v1, got %v", putResp["endpoint"])
	}
	if putResp["key_hint"] != "sk-...1234" {
		t.Errorf("expected hint sk-...1234, got %v", putResp["key_hint"])
	}
	// Plaintext key is NEVER returned
	if _, exists := putResp["api_key"]; exists {
		t.Fatalf("raw api_key leaked in response!")
	}

	// 5. GET by viewer succeeds (read-only allowed)
	req = httptest.NewRequest(http.MethodGet, "/v1/admin/upstream", nil)
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for viewer on GET /v1/admin/upstream, got %d: %s", w.Code, w.Body.String())
	}
	var getResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &getResp)
	if getResp["key_hint"] != "sk-...1234" {
		t.Errorf("expected hint sk-...1234, got %v", getResp["key_hint"])
	}
	if _, exists := getResp["api_key"]; exists {
		t.Fatalf("raw api_key leaked in GET response!")
	}

	// 6. Internal endpoint returns decrypted target
	req = httptest.NewRequest(http.MethodGet, "/v1/internal/upstream", nil)
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on internal upstream, got %d: %s", w.Code, w.Body.String())
	}
	var intResp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &intResp)
	if intResp["api_key"] != "sk-secretkey1234" {
		t.Errorf("expected decrypted key sk-secretkey1234, got %q", intResp["api_key"])
	}

	// 7. Test connection endpoint (allowed for viewer and admin)
	testPayload := []byte(`{"endpoint":"https://api.openai.com/v1"}`)
	req = httptest.NewRequest(http.MethodPost, "/v1/admin/upstream/test", bytes.NewReader(testPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on test endpoint for viewer, got %d: %s", w.Code, w.Body.String())
	}
	var testResp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &testResp)
	if _, exists := testResp["ok"]; !exists {
		t.Fatalf("missing ok field in test response")
	}

	// 8. Verify audit event upstream.update was emitted
	time.Sleep(50 * time.Millisecond)
	events := al.Recent(10)
	foundUpstreamEvent := false
	for _, ev := range events {
		if ev.RuleID == "upstream.update" {
			foundUpstreamEvent = true
			if ev.Subject != "https://api.openai.com/v1" {
				t.Errorf("expected subject https://api.openai.com/v1, got %q", ev.Subject)
			}
			break
		}
	}
	if !foundUpstreamEvent {
		t.Fatalf("expected upstream.update audit event, found none")
	}
}

func TestDownstreamControls_CaptureFlagAndToggle(t *testing.T) {
	srv, al, _, _ := newUpstreamTestServer(t)

	// 1. Agent with capture: false gets X-Cerberus-Capture: false header in decide
	decidePayload := []byte(`{"key_id":"k-private","stage":"llm","action":"chat","model":"claude-3-opus","prompt":"test"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/decide/llm", bytes.NewReader(decidePayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Header().Get("X-Cerberus-Capture") != "false" {
		t.Errorf("expected X-Cerberus-Capture: false for k-private, got %q", w.Header().Get("X-Cerberus-Capture"))
	}

	// 2. Normal agent without capture: false does NOT have X-Cerberus-Capture: false
	decidePayloadNormal := []byte(`{"key_id":"k-test","stage":"llm","action":"chat","model":"claude-3-opus","prompt":"test"}`)
	req = httptest.NewRequest(http.MethodPost, "/v1/decide/llm", bytes.NewReader(decidePayloadNormal))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Header().Get("X-Cerberus-Capture") == "false" {
		t.Errorf("did not expect X-Cerberus-Capture: false for k-test")
	}

	// 3. Toggle capture flag on k-test via POST /v1/admin/agents/{keyId}/capture
	togglePayload := []byte(`{"capture":false}`)
	req = httptest.NewRequest(http.MethodPost, "/v1/admin/agents/k-test/capture", bytes.NewReader(togglePayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer admin-secret-token")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on capture toggle, got %d: %s", w.Code, w.Body.String())
	}

	// Now k-test should return X-Cerberus-Capture: false
	req = httptest.NewRequest(http.MethodPost, "/v1/decide/llm", bytes.NewReader(decidePayloadNormal))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Header().Get("X-Cerberus-Capture") != "false" {
		t.Errorf("expected X-Cerberus-Capture: false for k-test after toggle")
	}

	// 4. Verify audit event agent.capture_toggle was emitted
	time.Sleep(50 * time.Millisecond)
	events := al.Recent(10)
	foundToggleEvent := false
	for _, ev := range events {
		if ev.RuleID == "agent.capture_toggle" {
			foundToggleEvent = true
			if ev.KeyID != "k-test" {
				t.Errorf("expected key_id k-test, got %q", ev.KeyID)
			}
			break
		}
	}
	if !foundToggleEvent {
		t.Fatalf("expected agent.capture_toggle audit event, found none")
	}
}
