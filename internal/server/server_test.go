package server

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	api      *Server
	store    *policy.Store
	auditLog *audit.Logger
	policies string // policy dir the store compiles from (may be a scratch copy)
	dataPath string // data file the store writes on PUT
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessIn(t, policyDir)
}

// newHarnessCopy wires the server over a scratch copy of the repo policy tree,
// so a test can corrupt the Rego on disk without touching the checkout.
func newHarnessCopy(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(policyDir)); err != nil {
		t.Fatalf("copy policy tree: %v", err)
	}
	return newHarnessIn(t, dir)
}

func newHarnessIn(t *testing.T, dir string) *harness {
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
	store, err := policy.NewStore(ctx, dir, dataPath)
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
	eng, err := engine.New(store, al, engine.Options{EvalTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	h := &harness{store: store, auditLog: al, policies: dir, dataPath: dataPath}
	h.api = New(Deps{
		Engine: eng, Store: store, Audit: al,
		AdminToken: adminToken, Version: "test",
	})
	h.ts = httptest.NewServer(h.api)
	t.Cleanup(func() { h.ts.CloseClientConnections(); h.ts.Close(); _ = al.Close() }) // server first, then logger
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

// Review Focus 1: empty bodies and the JSON literal null (which json.Unmarshal
// accepts, leaving Input zero-valued) are malformed requests, not decisions.
func TestDecide_EmptyAndNullBody400(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	for _, body := range []string{"", "null", "  ", "[]", `"x"`} {
		resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", body, false)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("body %q: status = %d, want 400", body, resp.StatusCode)
		}
	}
}

func TestDecide_KeySpoof401(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// 1. Unauthenticated request claiming exempt key (k-owner) -> 401
	bodyOwner := `{"stage":"tool","key_id":"k-owner","tool_call":"bash","args":{"cmd":"whoami"}}`
	resp1 := h.do(t, http.MethodPost, "/v1/decide", "application/json", bodyOwner, false)
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated k-owner decide status = %d, want 401", resp1.StatusCode)
	}

	// 2. Authenticated request claiming exempt key (k-owner) with admin token -> 200
	resp2 := h.do(t, http.MethodPost, "/v1/decide", "application/json", bodyOwner, true)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("admin k-owner decide status = %d, want 200", resp2.StatusCode)
	}

	// 3. Caller header key differs from body key without admin token -> 401
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/decide", strings.NewReader(`{"stage":"tool","key_id":"k-exact"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cerberus-Key", "k-open")
	resp3, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do req: %v", err)
	}
	defer func() { _ = resp3.Body.Close() }()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Fatalf("mismatched key decide status = %d, want 401", resp3.StatusCode)
	}
}

// A server-side write failure (here: read-only data dir) is a 500, not a 422,
// and must not leak absolute filesystem paths to the client.
func TestAdmin_PutData_IOFailure500NoPath(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("read-only-dir IO-failure test invalid as root (root bypasses mode bits)")
	}
	h := newHarness(t)
	dir := filepath.Dir(h.dataPath)
	if err := os.Chmod(dir, 0o500); err != nil { // #nosec G302 -- test-only read-only dir
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restore for TempDir cleanup
	raw, err := os.ReadFile(testData)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	before := h.store.Current().Epoch
	resp := h.do(t, http.MethodPut, "/v1/admin/data", "application/json", string(raw), true)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	body := decodeJSON[map[string]string](t, resp.Body)
	if strings.Contains(body["error"], dir) || strings.Contains(body["error"], "/") {
		t.Fatalf("error leaks a path: %q", body["error"])
	}
	if got := h.store.Current().Epoch; got != before {
		t.Fatalf("epoch = %d after failed write, want %d", got, before)
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
		{http.MethodPost, "/v1/admin/policy/validate"},
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
	// Two rejection shapes: a well-formed document with an unknown top-level
	// key, and a syntactically broken one. Both must 422 with an error body.
	for _, body := range []string{`{"bogus":1}`, `{"agents":`} {
		resp := h.do(t, http.MethodPut, "/v1/admin/data", "application/json", body, true)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("PUT %s: status = %d, want 422", body, resp.StatusCode)
		}
		got := decodeJSON[map[string]any](t, resp.Body)
		if _, ok := got["error"]; !ok {
			t.Fatalf("PUT %s: 422 body missing \"error\": %v", body, got)
		}
	}
	resp := h.do(t, http.MethodGet, "/v1/admin/data", "", "", true)
	if got := resp.Header.Get("X-Cerberus-Epoch"); got != "1" {
		t.Fatalf("epoch after failed PUT = %q, want 1 (old snapshot stays live)", got)
	}
	// The failed PUTs must not have disturbed the live document: a decide
	// still evaluates against the old data.
	resp = h.do(t, http.MethodPost, "/v1/decide", "application/json", decideAllowBody, false)
	d := decodeJSON[engine.Decision](t, resp.Body)
	if d.Decision != "allow" || d.RuleID != "ai.tool.allow" {
		t.Fatalf("decide after failed PUT = %s/%s, want allow/ai.tool.allow (old data live)", d.Decision, d.RuleID)
	}
}

func TestAdmin_Reload_BrokenRegoKeeps422(t *testing.T) {
	t.Parallel()
	h := newHarnessCopy(t)

	// An unterminated rule body fails to compile; reload must 422 and keep
	// the old snapshot live.
	broken := filepath.Join(h.policies, "gateway", "broken.rego")
	if err := os.WriteFile(broken, []byte("package gateway.broken\n\nallow if {\n"), 0o600); err != nil {
		t.Fatalf("write broken rego: %v", err)
	}
	resp := h.do(t, http.MethodPost, "/v1/admin/reload", "", "", true)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("reload status = %d, want 422", resp.StatusCode)
	}
	body := decodeJSON[map[string]any](t, resp.Body)
	if _, ok := body["error"]; !ok {
		t.Fatalf("422 body missing \"error\": %v", body)
	}

	resp = h.do(t, http.MethodGet, "/v1/admin/data", "", "", true)
	if got := resp.Header.Get("X-Cerberus-Epoch"); got != "1" {
		t.Fatalf("epoch after failed reload = %q, want 1", got)
	}
	// The pre-reload snapshot still answers decisions.
	resp = h.do(t, http.MethodPost, "/v1/decide", "application/json", decideAllowBody, false)
	d := decodeJSON[engine.Decision](t, resp.Body)
	if d.Decision != "allow" || d.RuleID != "ai.tool.allow" {
		t.Fatalf("decide after failed reload = %s/%s, want allow/ai.tool.allow (old snapshot live)", d.Decision, d.RuleID)
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
	deadline := time.Now().Add(10 * time.Second)
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

// TestEvents_ShutdownEndsStream: a parked /v1/events client must not hold
// http.Server.Shutdown out to its drain deadline (one dashboard = a 10s stall
// per rolling-deploy pod). Wiring mirrors main: RegisterOnShutdown(ShutdownStreams).
func TestEvents_ShutdownEndsStream(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	srv := &http.Server{Handler: h.api, ReadHeaderTimeout: 5 * time.Second}
	srv.RegisterOnShutdown(h.api.ShutdownStreams)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// One dashboard client parked on /v1/events, never disconnecting.
	req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/v1/events", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Let the handler reach its subscribe, then shut down: it must finish
	// clean and fast, not wait on the stream.
	time.Sleep(200 * time.Millisecond)
	shutdownErr := make(chan error, 1)
	go func() { shutdownErr <- srv.Shutdown(context.Background()) }()
	select {
	case err := <-shutdownErr:
		if err != nil {
			t.Fatalf("Shutdown with an open SSE stream: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown still draining after 3s; the SSE stream blocks graceful shutdown")
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

	// Layer 1: Happy path - verify /metrics and /v1/metrics both return 200 and all observability metrics
	for _, path := range []string{"/metrics", "/v1/metrics"} {
		resp := h.do(t, http.MethodGet, path, "", "", false)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", path, resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		bodyStr := string(b)
		for _, want := range []string{
			"cerberus_decisions_total",
			"cerberus_eval_duration_stage_seconds",
			"cerberus_cache_misses_epoch_total",
			"cerberus_bundle_revision",
			"cerberus_audit_queue_depth",
			"cerberus_ship_drops_total",
		} {
			if !strings.Contains(bodyStr, want) {
				t.Fatalf("%s missing metric %q:\n%s", path, want, bodyStr)
			}
		}
	}

	// Layer 2: Tamper / method not allowed
	badMethodResp := h.do(t, http.MethodPost, "/v1/metrics", "", "", false)
	if badMethodResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /v1/metrics status = %d, want 405", badMethodResp.StatusCode)
	}

	// Layer 3: Fail-closed / robustness - unauthenticated caller can scrape metrics without crashing
	unauthResp := h.do(t, http.MethodGet, "/v1/metrics", "", "", false)
	if unauthResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/metrics status = %d, want 200", unauthResp.StatusCode)
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

func TestAdmin_EraseDecision(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// Make a decision
	h.do(t, http.MethodPost, "/v1/decide", "application/json", decideAllowBody, false)
	time.Sleep(50 * time.Millisecond)

	// Query audit to get the event
	resp := h.do(t, http.MethodGet, "/v1/audit", "", "", true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit status = %d, want 200", resp.StatusCode)
	}
	var evs []audit.Event
	if err := json.NewDecoder(resp.Body).Decode(&evs); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	if len(evs) == 0 {
		t.Fatal("audit events empty")
	}
	targetID := evs[0].ID

	// Call erase endpoint
	eraseBody := fmt.Sprintf(`{"id": %d}`, targetID)
	eraseResp := h.do(t, http.MethodPost, "/v1/admin/decisions/erase", "application/json", eraseBody, true)
	if eraseResp.StatusCode != http.StatusOK {
		t.Fatalf("erase status = %d, want 200", eraseResp.StatusCode)
	}
	var res map[string]any
	if err := json.NewDecoder(eraseResp.Body).Decode(&res); err != nil {
		t.Fatalf("decode erase response: %v", err)
	}
	if res["ok"] != true || res["erased"] != float64(1) {
		t.Fatalf("erase response = %+v, want ok=true, erased=1", res)
	}

	// Verify in audit that args was erased
	resp2 := h.do(t, http.MethodGet, "/v1/audit", "", "", true)
	var evs2 []audit.Event
	if err := json.NewDecoder(resp2.Body).Decode(&evs2); err != nil {
		t.Fatalf("decode audit 2: %v", err)
	}
	var found bool
	for _, e := range evs2 {
		if e.ID == targetID {
			found = true
			if e.Args["_erased"] != true {
				t.Fatalf("event args not erased: %+v", e.Args)
			}
		}
	}
	if !found {
		t.Fatalf("event %d not found after erase", targetID)
	}

	// Erase non-existent ID -> 404
	erase404Resp := h.do(t, http.MethodPost, "/v1/admin/decisions/erase", "application/json", `{"id": 999999}`, true)
	if erase404Resp.StatusCode != http.StatusNotFound {
		t.Fatalf("erase non-existent status = %d, want 404", erase404Resp.StatusCode)
	}
}

func TestAdmin_Status(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// Make an allow decision and a deny decision so stats & top denies are populated
	h.do(t, http.MethodPost, "/v1/decide", "application/json", decideAllowBody, false)
	denyBody := `{"stage":"tool","key_id":"k-open","tool_call":"bash","args":{"cmd":"rm -rf /"}}`
	h.do(t, http.MethodPost, "/v1/decide", "application/json", denyBody, false)
	time.Sleep(50 * time.Millisecond)

	// Layer 1: Happy path - GET /v1/status returns 200 with all status metrics including Sprint 2D fields
	resp := h.do(t, http.MethodGet, "/v1/status", "", "", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var st map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	for _, key := range []string{
		"bundle_epoch", "revision", "active_revision",
		"policies_loaded_at", "snapshot_age", "snapshot_age_seconds",
		"last_reload", "eval_total/24h", "cache_hit_rate",
		"audit_queue_depth", "top_denies_24h",
	} {
		if _, ok := st[key]; !ok {
			t.Errorf("status missing key %q: %+v", key, st)
		}
	}
	if st["bundle_epoch"].(float64) < 1 {
		t.Errorf("bundle_epoch = %v, want >= 1", st["bundle_epoch"])
	}

	// Verify top_denies_24h contains the denied rule
	topDenies, ok := st["top_denies_24h"].([]any)
	if !ok {
		t.Fatalf("top_denies_24h is not a slice: %+v", st["top_denies_24h"])
	}
	var foundShieldDeny bool
	for _, item := range topDenies {
		m, ok := item.(map[string]any)
		if ok && m["rule_id"] == "shield.cmd.dangerous" && m["count"].(float64) >= 1 {
			foundShieldDeny = true
		}
	}
	if !foundShieldDeny {
		t.Errorf("top_denies_24h missing shield.cmd.dangerous: %+v", topDenies)
	}

	// Layer 2: Tamper / method not allowed
	badMethod := h.do(t, http.MethodPost, "/v1/status", "", "", false)
	if badMethod.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /v1/status = %d, want 405", badMethod.StatusCode)
	}

	// Layer 3: Fail-closed / robustness - GET /v1/admin/status with admin token also returns 200
	adminResp := h.do(t, http.MethodGet, "/v1/admin/status", "", "", true)
	if adminResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/admin/status = %d, want 200", adminResp.StatusCode)
	}
}

func TestEvents_LastEventIDReconnect(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// Make 2 decisions
	h.do(t, http.MethodPost, "/v1/decide", "application/json", decideAllowBody, false)
	h.do(t, http.MethodPost, "/v1/decide", "application/json", decideAllowBody, false)
	time.Sleep(50 * time.Millisecond)

	recent := h.auditLog.Recent(2)
	if len(recent) < 2 {
		t.Fatalf("recent len = %d, want >= 2", len(recent))
	}
	firstID := recent[1].ID
	lastID := recent[0].ID

	// Connect with Last-Event-ID header set to firstID
	req, err := http.NewRequest(http.MethodGet, h.ts.URL+"/v1/events", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Last-Event-ID", strconv.FormatInt(firstID, 10))

	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("get events: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	sc := bufio.NewScanner(resp.Body)
	var foundID, foundData bool
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "id: ") {
			idStr := strings.TrimPrefix(line, "id: ")
			id, _ := strconv.ParseInt(idStr, 10, 64)
			if id == lastID {
				foundID = true
			}
		}
		if strings.HasPrefix(line, "data: ") && foundID {
			foundData = true
			break
		}
	}
	if !foundID || !foundData {
		t.Fatalf("did not replay event %d: foundID=%v foundData=%v", lastID, foundID, foundData)
	}
}

func TestAdmin_UploadBundle(t *testing.T) {
	t.Parallel()
	h := newHarnessCopy(t)

	// Create a valid bundle.tar.gz with updated data.json
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	manifest := []byte(`{"roots":["stages"]}`)
	_ = tw.WriteHeader(&tar.Header{Name: ".manifest", Size: int64(len(manifest)), Mode: 0o600})
	_, _ = tw.Write(manifest)

	// Update agent k-open with budget_limit = 5
	updatedData := []byte(`{
		"config": {"bypass_unknown_keys": true, "bypass_unknown_teams": true},
		"teams": {},
		"agents": {
			"k-open": {"name": "open-agent", "budget_limit": 5}
		},
		"blocked_patterns": ["jailbreak"],
		"domains": {},
		"prod_shield": {
			"dangerous_cmd_patterns": [
				{"id": "rm_rf", "regex": "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)"},
				{"id": "grep_wildcard_dump", "regex": "grep\\s+[^|]*(\\*|wildcard)[^|]*(/passwd|/etc|\\.env|id_rsa)"}
			],
			"protected_containers": ["teknikalidnew-db-1"]
		}
	}`)
	_ = tw.WriteHeader(&tar.Header{Name: "data.json", Size: int64(len(updatedData)), Mode: 0o600})
	_, _ = tw.Write(updatedData)

	// Include stages rego files
	for _, rel := range []string{"stages/ai.rego", "stages/llm.rego", "stages/tool.rego"} {
		content, err := os.ReadFile(filepath.Join(h.policies, rel)) //nolint:gosec // G304 test fixture
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		_ = tw.WriteHeader(&tar.Header{Name: "policies/" + rel, Size: int64(len(content)), Mode: 0o600})
		_, _ = tw.Write(content)
	}
	_ = tw.Close()
	_ = gw.Close()

	// Upload bundle via POST /v1/admin/bundle
	req, err := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/admin/bundle", &buf)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/gzip")

	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("upload bundle: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("bundle upload status = %d (%s), want 200", resp.StatusCode, b)
	}

	var res epochResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("decode epoch response: %v", err)
	}
	if res.Epoch != 2 {
		t.Fatalf("epoch = %d, want 2", res.Epoch)
	}

	// Verify decision changed: k-open with spend_usd=10 exceeds new budget_limit=5
	spendBody := `{"stage": "llm", "key_id": "k-open", "model": "m1", "context": {"spend_usd": 10}}`
	decResp := h.do(t, http.MethodPost, "/v1/decide", "application/json", spendBody, false)
	if decResp.StatusCode != http.StatusOK {
		t.Fatalf("decide status = %d, want 200", decResp.StatusCode)
	}
	var dec engine.Decision
	if err := json.NewDecoder(decResp.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if dec.Decision != "deny" || dec.RuleID != "ai.llm.budget_exceeded" {
		t.Fatalf("decision = %s/%s, want deny/ai.llm.budget_exceeded", dec.Decision, dec.RuleID)
	}
}

func TestDecide_RateLimit(t *testing.T) {
	h := newHarness(t)

	// k-rate-limited has requests_per_minute: 60, bursts: 2
	body := `{"stage": "tool", "key_id": "k-rate-limited", "tool_name": "read", "tool_args": {}}`

	// 1st request -> allowed (200)
	resp1 := h.do(t, http.MethodPost, "/v1/decide", "application/json", body, false)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("req 1 status = %d, want 200", resp1.StatusCode)
	}

	// 2nd request -> allowed (200)
	resp2 := h.do(t, http.MethodPost, "/v1/decide", "application/json", body, false)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("req 2 status = %d, want 200", resp2.StatusCode)
	}

	// 3rd request -> rate limited (429)
	resp3 := h.do(t, http.MethodPost, "/v1/decide", "application/json", body, false)
	if resp3.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("req 3 status = %d, want 429", resp3.StatusCode)
	}
	retryAfter := resp3.Header.Get("Retry-After")
	if retryAfter == "" {
		t.Errorf("expected Retry-After header to be set")
	}

	var dec engine.Decision
	if err := json.NewDecoder(resp3.Body).Decode(&dec); err != nil {
		t.Fatalf("decode 429 body: %v", err)
	}
	if dec.Decision != "deny" || dec.RuleID != "ops.rate_limited" {
		t.Errorf("dec = %s/%s, want deny/ops.rate_limited", dec.Decision, dec.RuleID)
	}
}

func TestKillSwitch_EndToEnd(t *testing.T) {
	h := newHarness(t)

	// k-bad is configured in kill_switch.keys in policies/testdata/data.json
	body := `{"stage": "llm", "key_id": "k-bad", "model": "m1"}`
	resp := h.do(t, http.MethodPost, "/v1/decide", "application/json", body, false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decide status = %d, want 200", resp.StatusCode)
	}

	var dec engine.Decision
	if err := json.NewDecoder(resp.Body).Decode(&dec); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if dec.Decision != "deny" || dec.RuleID != "ops.kill_switch" {
		t.Fatalf("expected deny/ops.kill_switch, got %s/%s", dec.Decision, dec.RuleID)
	}
}

func TestBreakGlass_EndToEnd(t *testing.T) {
	h := newHarness(t)

	body := `{"stage": "llm", "key_id": "k-bad", "model": "m1"}`

	// 1. Without break-glass: denied by kill_switch
	resp1 := h.do(t, http.MethodPost, "/v1/decide", "application/json", body, false)
	var dec1 engine.Decision
	_ = json.NewDecoder(resp1.Body).Decode(&dec1)
	if dec1.Decision != "deny" {
		t.Fatalf("expected deny without break-glass, got %s", dec1.Decision)
	}

	// 2. Non-admin client sending X-Break-Glass: MUST NOT bypass (unauthorized)
	req2, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/decide", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Break-Glass", "true")
	resp2, err := h.ts.Client().Do(req2)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	var dec2 engine.Decision
	_ = json.NewDecoder(resp2.Body).Decode(&dec2)
	_ = resp2.Body.Close()
	if dec2.Decision != "deny" {
		t.Fatalf("unauthorized X-Break-Glass should NOT bypass: got %s", dec2.Decision)
	}

	// 3. Admin sending X-Break-Glass with valid admin token: MUST bypass
	req3, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/decide", strings.NewReader(body))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Authorization", "Bearer "+adminToken)
	req3.Header.Set("X-Break-Glass", "emergency production hotfix")
	resp3, err := h.ts.Client().Do(req3)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	var dec3 engine.Decision
	_ = json.NewDecoder(resp3.Body).Decode(&dec3)
	_ = resp3.Body.Close()
	if dec3.Decision != "allow" || dec3.RuleID != "ops.break_glass" {
		t.Fatalf("expected allow/ops.break_glass, got %s/%s (%s)", dec3.Decision, dec3.RuleID, dec3.Reason)
	}

	// 4. Test admin break-glass API window
	bgBody := `{"key_id": "k-bad", "duration_minutes": 15, "reason": "console hotfix"}`
	respBG := h.do(t, http.MethodPost, "/v1/admin/break-glass", "application/json", bgBody, true)
	if respBG.StatusCode != http.StatusOK {
		t.Fatalf("post /v1/admin/break-glass status = %d, want 200", respBG.StatusCode)
	}
	_ = respBG.Body.Close()

	// Subsequent request during window without headers should now bypass
	resp4 := h.do(t, http.MethodPost, "/v1/decide", "application/json", body, false)
	var dec4 engine.Decision
	_ = json.NewDecoder(resp4.Body).Decode(&dec4)
	if dec4.Decision != "allow" || dec4.RuleID != "ops.break_glass" {
		t.Fatalf("expected active window to bypass, got %s/%s", dec4.Decision, dec4.RuleID)
	}

	// Deactivate break-glass
	respDel := h.do(t, http.MethodDelete, "/v1/admin/break-glass?key_id=k-bad", "", "", true)
	if respDel.StatusCode != http.StatusOK {
		t.Fatalf("delete break glass status = %d", respDel.StatusCode)
	}
	_ = respDel.Body.Close()

	// Request is denied again
	resp5 := h.do(t, http.MethodPost, "/v1/decide", "application/json", body, false)
	var dec5 engine.Decision
	_ = json.NewDecoder(resp5.Body).Decode(&dec5)
	if dec5.Decision != "deny" {
		t.Fatalf("expected deny after deactivation, got %s", dec5.Decision)
	}
}

// 8A.5: Audit untuk cache-hit: dua panggilan decide identik -> keduanya tercatat di /v1/audit
func TestServer_Decide_AuditCacheHit(t *testing.T) {
	h := newHarness(t)

	body := `{"stage":"tool","key_id":"k-glob","tool_call":"kubernetes_get_pods","args":{"cmd":"k get pods"}}`

	// Call 1: Miss
	resp1 := h.do(t, http.MethodPost, "/v1/decide", "application/json", body, false)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("call 1 status = %d, want 200", resp1.StatusCode)
	}
	var dec1 engine.Decision
	_ = json.NewDecoder(resp1.Body).Decode(&dec1)
	_ = resp1.Body.Close()
	if dec1.Cached {
		t.Fatalf("call 1 should not be cached")
	}

	// Call 2: Hit
	resp2 := h.do(t, http.MethodPost, "/v1/decide", "application/json", body, false)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("call 2 status = %d, want 200", resp2.StatusCode)
	}
	var dec2 engine.Decision
	_ = json.NewDecoder(resp2.Body).Decode(&dec2)
	_ = resp2.Body.Close()
	if !dec2.Cached {
		t.Fatalf("call 2 should be cached")
	}

	time.Sleep(50 * time.Millisecond)

	// Query /v1/audit: both events must be recorded in /v1/audit
	auditResp := h.do(t, http.MethodGet, "/v1/audit?key_id=k-glob", "", "", true)
	if auditResp.StatusCode != http.StatusOK {
		t.Fatalf("audit status = %d, want 200", auditResp.StatusCode)
	}
	var evs []audit.Event
	if err := json.NewDecoder(auditResp.Body).Decode(&evs); err != nil {
		t.Fatalf("decode audit events: %v", err)
	}
	_ = auditResp.Body.Close()

	var matchCount int
	var cachedCount int
	for _, e := range evs {
		if e.KeyID == "k-glob" && e.Subject == "kubernetes_get_pods" {
			matchCount++
			if e.Cached {
				cachedCount++
			}
		}
	}
	if matchCount < 2 {
		t.Fatalf("expected at least 2 events for identical decide calls in /v1/audit, got %d", matchCount)
	}
	if cachedCount < 1 {
		t.Fatalf("expected at least 1 cache hit recorded in /v1/audit, got %d", cachedCount)
	}
}

// 8B finishing: unit test Go end-to-end stage ssh (decide stage=ssh connect host=git.teknikal.id -> allow; host unknown -> deny)
func TestDecide_SSHStageEndToEnd(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// 1. Host allowlisted by wildcard (*.teknikal.id) -> allow
	allowBody := `{"stage":"ssh","key_id":"k-open","action":"connect","host":"git.teknikal.id","user":"ubuntu","port":22}`
	respAllow := h.do(t, http.MethodPost, "/v1/decide", "application/json", allowBody, false)
	if respAllow.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", respAllow.StatusCode)
	}
	var decAllow engine.Decision
	if err := json.NewDecoder(respAllow.Body).Decode(&decAllow); err != nil {
		t.Fatalf("decode allow decision: %v", err)
	}
	_ = respAllow.Body.Close()
	if decAllow.Decision != "allow" {
		t.Fatalf("expected decision allow, got %q (rule_id: %s, reason: %s)", decAllow.Decision, decAllow.RuleID, decAllow.Reason)
	}
	if decAllow.RuleID != "ssh.allow" {
		t.Fatalf("expected rule_id ssh.allow, got %q", decAllow.RuleID)
	}

	// 2. Unknown host -> deny
	denyBody := `{"stage":"ssh","key_id":"k-open","action":"connect","host":"unknown-host.example.com","user":"ubuntu","port":22}`
	respDeny := h.do(t, http.MethodPost, "/v1/decide", "application/json", denyBody, false)
	if respDeny.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", respDeny.StatusCode)
	}
	var decDeny engine.Decision
	if err := json.NewDecoder(respDeny.Body).Decode(&decDeny); err != nil {
		t.Fatalf("decode deny decision: %v", err)
	}
	_ = respDeny.Body.Close()
	if decDeny.Decision != "deny" {
		t.Fatalf("expected decision deny, got %q", decDeny.Decision)
	}
	if decDeny.RuleID != "ssh.host_not_allowed" {
		t.Fatalf("expected rule_id ssh.host_not_allowed, got %q", decDeny.RuleID)
	}
}
