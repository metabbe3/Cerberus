package server

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/policy"
)

const (
	policyDir  = "../../policies"
	testData   = "../../policies/testdata/data.json"
	adminToken = "test-admin-token"
)

// harness wires a server over the repo policies, a temp data file, and a fast
// flushing audit DB, and exposes an httptest server.
type harness struct {
	ts       *httptest.Server
	store    *policy.Store
	auditLog *audit.Logger
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()

	dataPath := filepath.Join(t.TempDir(), "data.json")
	raw, err := os.ReadFile(testData)
	if err != nil {
		t.Fatalf("read fixture data: %v", err)
	}
	if err := os.WriteFile(dataPath, raw, 0o600); err != nil { // #nosec G703 -- path built from t.TempDir()
		t.Fatalf("write data: %v", err)
	}
	store, err := policy.NewStore(ctx, policyDir, dataPath)
	if err != nil {
		t.Fatalf("policy.NewStore: %v", err)
	}

	al, err := audit.Open(ctx, filepath.Join(t.TempDir(), "audit.db"),
		audit.Options{BatchSize: 1, FlushEvery: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	// ponytail: 2s eval timeout — under -race + full-suite load a 10ms default
	// budget flakes the golden tests (observed once); timeout behavior itself is
	// covered by engine TestDecide_TimeoutDenies, so outcome tests don't need it.
	eng, err := engine.New(store, al, engine.Options{EvalTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	h := &harness{store: store, auditLog: al}
	h.ts = httptest.NewServer(New(Deps{
		Engine: eng, Store: store, Audit: al,
		AdminToken: adminToken, Version: "test",
	}))
	t.Cleanup(func() { h.ts.Close(); _ = al.Close() }) // server first, then logger
	return h
}

// do issues one request and returns the response (body closed on cleanup).
func (h *harness) do(t *testing.T, method, path, contentType, body string, auth bool) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, h.ts.URL+path, rd)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func decodeJSON[T any](t *testing.T, r io.Reader) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return v
}

func writeJSONBody(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return string(b)
}

// compareGolden decodes both bodies as generic JSON and deep-compares them
// ignoring "epoch", which varies with reload history.
func compareGolden(t *testing.T, goldenPath string, got io.Reader) {
	t.Helper()
	wantRaw, err := os.ReadFile(goldenPath) // #nosec G304 -- testdata fixture path
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var want, have map[string]any
	if err := json.Unmarshal(wantRaw, &want); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	if err := json.NewDecoder(got).Decode(&have); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	delete(want, "epoch")
	delete(have, "epoch")
	if !reflect.DeepEqual(have, want) {
		t.Fatalf("response ≠ golden\n got: %v\nwant: %v", have, want)
	}
}

const decideAllowBody = `{"stage":"tool","key_id":"k-glob","tool_call":"kubernetes_get_pods","args":{"cmd":"k get pods --token sk-abc123"}}`
const decideDenyBody = `{"stage":"tool","key_id":"k-glob","tool_call":"kubernetes_delete_pod"}`

func TestDecide_AllowGolden(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", decideAllowBody, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	compareGolden(t, "testdata/decide_allow.golden.json", resp.Body)
}

func TestDecide_DenyGolden(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", decideDenyBody, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	compareGolden(t, "testdata/decide_deny.golden.json", resp.Body)
}

func TestDecide_LLMAliasForcesStage(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	// No "stage" in the body; the route must force llm and reach ai.llm rules.
	resp := h.do(t, http.MethodPost, "/v1/decide/llm", "application/json",
		`{"key_id":"k-glob","model":"m1"}`, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	d := decodeJSON[engine.Decision](t, resp.Body)
	if d.Decision != "allow" || d.RuleID != "ai.llm.allow" {
		t.Fatalf("decision = %s/%s, want allow/ai.llm.allow", d.Decision, d.RuleID)
	}
}

func TestDecide_InvalidJSON400(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", "{nope", false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	body := decodeJSON[map[string]string](t, resp.Body)
	if body["error"] != "invalid json" {
		t.Fatalf("error = %q, want %q", body["error"], "invalid json")
	}
}

func TestDecide_BodyTooLarge413(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	big := `{"prompt":"` + strings.Repeat("x", 2<<20) + `"}`
	resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", big, false)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestDecide_WrongContentType415(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do(t, http.MethodPost, "/v1/decide", "text/plain", decideAllowBody, false)
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", resp.StatusCode)
	}
}

func TestAdmin_NoToken401(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/data"},
		{http.MethodPut, "/v1/admin/data"},
		{http.MethodPost, "/v1/admin/reload"},
		{http.MethodGet, "/v1/audit"},
		{http.MethodGet, "/v1/events"},
	} {
		resp := h.do(t, tc.method, tc.path, "", "", false)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s: status = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
	// A wrong token is equally rejected.
	req, err := http.NewRequest(http.MethodGet, h.ts.URL+"/v1/admin/data", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer wrong")
	wrong, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("wrong-token request: %v", err)
	}
	_ = wrong.Body.Close()
	if wrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", wrong.StatusCode)
	}
}

func TestAdmin_PutData_ReloadsEpoch(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	resp := h.do(t, http.MethodGet, "/v1/admin/data", "", "", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET data: status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Cerberus-Epoch"); got != "1" {
		t.Fatalf("initial epoch header = %q, want 1", got)
	}

	// Modify the data: restrict the very tool the allow golden uses.
	raw, err := os.ReadFile(testData)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	agents := data["agents"].(map[string]any)
	kglob := agents["k-glob"].(map[string]any)
	kglob["restricted_tool_calls"] = []string{"kubernetes_get_pods"}

	resp = h.do(t, http.MethodPut, "/v1/admin/data", "application/json", writeJSONBody(t, data), true)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT data: status = %d, want 200 (body %s)", resp.StatusCode, body)
	}
	epoch := decodeJSON[map[string]any](t, resp.Body)
	if epoch["epoch"].(float64) != 2 {
		t.Fatalf("PUT epoch = %v, want 2", epoch["epoch"])
	}

	resp = h.do(t, http.MethodGet, "/v1/admin/data", "", "", true)
	if got := resp.Header.Get("X-Cerberus-Epoch"); got != "2" {
		t.Fatalf("epoch header after PUT = %q, want 2", got)
	}

	// The next decide reflects the reloaded data.
	resp = h.do(t, http.MethodPost, "/v1/decide", "application/json", decideAllowBody, false)
	d := decodeJSON[engine.Decision](t, resp.Body)
	if d.Decision != "deny" || d.RuleID != "ai.tool.restricted" {
		t.Fatalf("decide after PUT = %s/%s, want deny/ai.tool.restricted", d.Decision, d.RuleID)
	}
}

func TestAdmin_PutData_InvalidKeeps422(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do(t, http.MethodPut, "/v1/admin/data", "application/json", `{"bogus":1}`, true)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	body := decodeJSON[map[string]any](t, resp.Body)
	if _, ok := body["error"]; !ok {
		t.Fatalf("422 body missing \"error\": %v", body)
	}
	resp = h.do(t, http.MethodGet, "/v1/admin/data", "", "", true)
	if got := resp.Header.Get("X-Cerberus-Epoch"); got != "1" {
		t.Fatalf("epoch after failed PUT = %q, want 1 (old snapshot stays live)", got)
	}
}

func TestAdmin_PolicyValidate_BadRego422(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do(t, http.MethodPost, "/v1/admin/policy/validate", "application/json",
		`{"rego":"package gateway.broken("}`, true)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	body := decodeJSON[map[string]any](t, resp.Body)
	if body["ok"] != false {
		t.Fatalf("ok = %v, want false", body["ok"])
	}
	errs, ok := body["errors"].([]any)
	if !ok || len(errs) == 0 {
		t.Fatalf("errors missing or empty: %v", body)
	}
}

func TestAdmin_PolicyValidate_GoodRego200(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	rego := "package gateway.extra\n\nallow if {\n\tinput.stage == \"llm\"\n}\n"
	resp := h.do(t, http.MethodPost, "/v1/admin/policy/validate", "application/json",
		`{"rego":`+strconv.Quote(rego)+`}`, true)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, body)
	}
	body := decodeJSON[map[string]any](t, resp.Body)
	if body["ok"] != true {
		t.Fatalf("ok = %v, want true", body["ok"])
	}
}

func TestAudit_QueryReturnsDecision(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", decideAllowBody, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decide status = %d, want 200", resp.StatusCode)
	}

	// The batcher is async; poll the query route until the event lands.
	var events []audit.Event
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp := h.do(t, http.MethodGet, "/v1/audit?key_id=k-glob", "", "", true)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("audit status = %d, want 200", resp.StatusCode)
		}
		events = decodeJSON[[]audit.Event](t, resp.Body)
		if len(events) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit query returned %d events, want 1", len(events))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if events[0].Decision != "allow" || events[0].RuleID != "ai.tool.allow" {
		t.Fatalf("event = %s/%s, want allow/ai.tool.allow", events[0].Decision, events[0].RuleID)
	}
}

func TestEvents_SSEStreamsDecision(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.ts.URL+"/v1/events", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}

	// Parse SSE frames in the background; the test selects on them.
	type sseFrame struct{ event, data string }
	frames := make(chan sseFrame, 16)
	go func() {
		defer close(frames)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		var ev, data string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				ev = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				data = strings.TrimPrefix(line, "data: ")
			case line == "":
				if ev != "" || data != "" {
					frames <- sseFrame{event: ev, data: data}
					ev, data = "", ""
				}
			}
		}
	}()

	// The handler subscribes before returning its headers; a short delay then
	// one decide call must surface as exactly one live decision frame.
	time.Sleep(100 * time.Millisecond)
	h.do(t, http.MethodPost, "/v1/decide", "application/json", decideAllowBody, false)

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatal("stream ended before a decision frame")
			}
			if f.event != "decision" {
				continue
			}
			var e audit.Event
			if err := json.Unmarshal([]byte(f.data), &e); err != nil {
				t.Fatalf("frame data: %v (%s)", err, f.data)
			}
			if e.RuleID != "ai.tool.allow" || e.Decision != "allow" {
				t.Fatalf("streamed event = %s/%s, want allow/ai.tool.allow", e.Decision, e.RuleID)
			}
			return
		case <-timer.C:
			t.Fatal("no decision frame within 2s")
		}
	}
}

func TestReadyz(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do(t, http.MethodGet, "/readyz", "", "", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz with snapshot: status = %d, want 200", resp.StatusCode)
	}

	// A store whose snapshot was never loaded (zero-value Store) reads 503.
	notReady := httptest.NewServer(New(Deps{Store: &policy.Store{}}))
	defer notReady.Close()
	r, err := http.Get(notReady.URL + "/readyz") // #nosec G107 -- httptest URL
	if err != nil {
		t.Fatalf("readyz empty store: %v", err)
	}
	_ = r.Body.Close()
	if r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz empty store: status = %d, want 503", r.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do(t, http.MethodGet, "/healthz", "", "", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if strings.TrimSpace(string(b)) != "ok" {
		t.Fatalf("body = %q, want %q", string(b), "ok")
	}
}

func TestMetrics(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.do(t, http.MethodPost, "/v1/decide", "application/json", decideAllowBody, false)
	resp := h.do(t, http.MethodGet, "/metrics", "", "", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(b), "cerberus_decisions_total") {
		t.Fatalf("/metrics missing cerberus_decisions_total:\n%s", b)
	}
}

func TestAudit_InvalidSince400(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	resp := h.do(t, http.MethodGet, "/v1/audit?since=not-a-time", "", "", true)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRecover_PanicBecomes500(t *testing.T) {
	t.Parallel()
	// A Deps set that makes a handler panic: nil Engine on the decide route.
	srv := httptest.NewServer(New(Deps{AdminToken: adminToken}))
	defer srv.Close()
	resp, err := srv.Client().Post(srv.URL+"/v1/decide", "application/json",
		strings.NewReader(decideAllowBody))
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}
