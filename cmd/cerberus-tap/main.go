// Package main: cerberus-tap — in-path LLM gateway interceptor + enforcement.
//
// Sits between agents and the LLM API. Every request/response (including SSE
// streams) is captured per turn into a rotating SQLite store. When wired to the
// Cerberus engine (-engine-url), a "deny" verdict BLOCKS the request before it
// reaches the upstream — the tap is a gate, not just a mirror.
package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const maxBody = 2 << 20 // 2MB capture cap per body

type turnRow struct {
	KeyID   string          `json:"key_id"`
	Model   string          `json:"model"`
	Kind    string          `json:"kind"` // request|response|sse_assembled
	Payload json.RawMessage `json:"payload"`
}

// store rotates tap-YYYYMMDD.db daily and prunes old files.
type store struct {
	dir           string
	retentionDays int

	mu   sync.Mutex
	day  string
	db   *sql.DB
	ins  *sql.Stmt
	insM sync.Mutex
}

func newStore(dir string, retentionDays int) *store {
	if dir == "" {
		dir = "."
	}
	return &store{dir: dir, retentionDays: retentionDays}
}

func (s *store) current(now time.Time) (*sql.DB, *sql.Stmt, error) {
	day := now.Format("20060102")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ins != nil && s.day == day {
		return s.db, s.ins, nil
	}
	if s.db != nil {
		s.ins.Close()
		s.db.Close()
	}
	path := filepath.Join(s.dir, "tap-"+day+".db")
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS turns (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts TEXT NOT NULL,
		key_id TEXT NOT NULL DEFAULT 'unknown',
		model TEXT NOT NULL DEFAULT '',
		kind TEXT NOT NULL,
		payload TEXT NOT NULL,
		latency_ms INTEGER NOT NULL DEFAULT 0,
		status INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS turns_ts ON turns(ts);
	CREATE INDEX IF NOT EXISTS turns_key ON turns(key_id, ts);`); err != nil {
		db.Close()
		return nil, nil, err
	}
	ins, err := db.Prepare(`INSERT INTO turns (ts, key_id, model, kind, payload, latency_ms, status) VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	s.db, s.ins, s.day = db, ins, day

	// prune (best effort, once per rotation)
	go s.prune(time.Now())
	return s.db, s.ins, nil
}

func (s *store) prune(now time.Time) {
	if s.retentionDays <= 0 {
		return
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	cutoff := now.AddDate(0, 0, -s.retentionDays).Format("20060102")
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "tap-") || !strings.HasSuffix(name, ".db") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, "tap-"), ".db")
		if len(day) == 8 && day < cutoff {
			os.Remove(filepath.Join(s.dir, name))
			os.Remove(filepath.Join(s.dir, name+"-wal"))
			os.Remove(filepath.Join(s.dir, name+"-shm"))
		}
	}
}

func (s *store) save(t turnRow, latencyMS int64, status int) {
	db, ins, err := s.current(time.Now())
	if err != nil {
		log.Printf("[tap] store open: %v", err)
		return
	}
	s.insM.Lock()
	_, err = ins.Exec(time.Now().UTC().Format(time.RFC3339Nano), t.KeyID, t.Model, t.Kind, string(t.Payload), latencyMS, status)
	s.insM.Unlock()
	if err != nil {
		log.Printf("[tap] store insert: %v", err)
	}
	_ = db
}

func (s *store) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ins != nil {
		s.ins.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
}

// decideResp mirrors the engine /v1/decide response (subset we care about).
type decideResp struct {
	Decision string `json:"decision"`
	RuleID   string `json:"rule_id"`
	Reason   string `json:"reason"`
}

// askEngine calls POST /v1/decide/llm. Returns verdict, allowed.
func askEngine(engineURL, token, keyID string, body []byte) (decideResp, bool) {
	if engineURL == "" {
		return decideResp{Decision: "allow"}, true
	}
	prompt := summarizePrompt(body)
	payload, _ := json.Marshal(map[string]any{
		"key_id": keyID,
		"stage":  "llm",
		"action": "chat",
		"input": map[string]any{
			"key_id": keyID,
			"model":  modelOf(body),
			"prompt": prompt,
		},
	})
	url := strings.TrimSuffix(engineURL, "/") + "/v1/decide/llm"
	req, _ := http.NewRequest("POST", url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Engine unreachable: fail-open for visibility mode, but log loudly.
		log.Printf("[tap] engine decide unreachable (allowing): %v", err)
		return decideResp{Decision: "allow", RuleID: "tap.engine_unreachable"}, true
	}
	defer resp.Body.Close()
	var dr decideResp
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil || dr.Decision == "" {
		log.Printf("[tap] engine decide decode error (allowing)")
		return decideResp{Decision: "allow", RuleID: "tap.engine_bad_response"}, true
	}
	return dr, dr.Decision == "allow"
}

func modelOf(body []byte) string {
	var p struct {
		Model string `json:"model"`
	}
	json.Unmarshal(body, &p)
	return p.Model
}

// summarizePrompt extracts last user text + tool names for policy eval.
func summarizePrompt(body []byte) string {
	var p struct {
		System   json.RawMessage   `json:"system"`
		Messages []json.RawMessage `json:"messages"`
		Tools    []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return ""
	}
	var last string
	for _, m := range p.Messages {
		var mm struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		if json.Unmarshal(m, &mm) != nil {
			continue
		}
		if mm.Role == "user" {
			if s := contentText(mm.Content); s != "" {
				last = s
			}
		}
	}
	var toolNames []string
	for _, t := range p.Tools {
		toolNames = append(toolNames, t.Name)
	}
	summary := last
	if len(p.Tools) > 0 {
		summary += "\n[tools: " + strings.Join(toolNames, ",") + "]"
	}
	if len(summary) > 4000 {
		summary = summary[:4000] + "…"
	}
	return summary
}

// contentText handles content as string or []blocks.
func contentText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) == nil {
		var out []string
		for _, b := range blocks {
			if b.Type == "text" {
				out = append(out, b.Text)
			}
		}
		return strings.Join(out, "\n")
	}
	return ""
}

type server struct {
	upstream  string
	engineURL string
	engineTok string
	client    *http.Client
	st        *store
}

func (s *server) handleTap(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/tap/healthz":
		w.Write([]byte("ok"))
	case "/tap/turns":
		limit := 50
		fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		db, _, err := s.st.current(time.Now())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		q := `SELECT ts, key_id, model, kind, payload, latency_ms, status FROM turns ORDER BY id DESC LIMIT ?`
		rows, err := db.Query(q, limit)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()
		type row struct {
			Ts        string          `json:"ts"`
			KeyID     string          `json:"key_id"`
			Model     string          `json:"model"`
			Kind      string          `json:"kind"`
			Payload   json.RawMessage `json:"payload"`
			LatencyMS int64           `json:"latency_ms"`
			Status    int             `json:"status"`
		}
		out := []row{}
		for rows.Next() {
			var x row
			var pl string
			if rows.Scan(&x.Ts, &x.KeyID, &x.Model, &x.Kind, &pl, &x.LatencyMS, &x.Status) == nil {
				x.Payload = json.RawMessage(pl)
				out = append(out, x)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	case "/tap/stats":
		db, _, err := s.st.current(time.Now())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		rows, err := db.Query(`SELECT key_id, model, kind, COUNT(*) FROM turns GROUP BY key_id, model, kind ORDER BY 4 DESC LIMIT 100`)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()
		type stat struct {
			KeyID string `json:"key_id"`
			Model string `json:"model"`
			Kind  string `json:"kind"`
			Count int    `json:"count"`
		}
		out := []stat{}
		for rows.Next() {
			var x stat
			if rows.Scan(&x.KeyID, &x.Model, &x.Kind, &x.Count) == nil {
				out = append(out, x)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	default:
		http.NotFound(w, r)
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/tap/") {
		s.handleTap(w, r)
		return
	}
	start := time.Now()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	r.Body.Close()
	if err != nil {
		http.Error(w, "read body: "+err.Error(), 400)
		return
	}
	truncated := len(body) > maxBody
	if truncated {
		body = body[:maxBody]
	}

	keyID := r.Header.Get("X-Tap-Key")
	if keyID == "" {
		keyID = "unknown"
	}

	// Enforcement: ask the engine BEFORE forwarding. deny = request dies here.
	verdict, allowed := askEngine(s.engineURL, s.engineTok, keyID, body)
	if !allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"type":"tap_blocked","message":"blocked by cerberus policy"}}`))
		s.st.save(turnRow{KeyID: keyID, Model: modelOf(body), Kind: "blocked", Payload: mustJSON(map[string]any{
			"verdict": verdict, "path": r.URL.Path,
		})}, time.Since(start).Milliseconds(), 403)
		return
	}

	// Capture request (auth headers never persisted — we only store parsed fields).
	s.st.save(turnRow{KeyID: keyID, Model: modelOf(body), Kind: "request", Payload: sanitizedBody(body, truncated)}, 0, 0)

	// Forward upstream.
	fwd, _ := http.NewRequestWithContext(r.Context(), r.Method, s.upstream+r.URL.Path, bytes.NewReader(body))
	fwd.Header = r.Header.Clone()
	fwd.Header.Del("X-Tap-Key")
	resp, err := s.client.Do(fwd)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), 502)
		return
	}
	defer resp.Body.Close()

	isSSE := strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream")
	if isSSE {
		s.proxySSE(w, resp, keyID, modelOf(body), start)
		return
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	lat := time.Since(start).Milliseconds()
	// copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	s.st.save(turnRow{KeyID: keyID, Model: modelOf(body), Kind: "response", Payload: respBody}, lat, resp.StatusCode)
}

// proxySSE tees the stream to the client while reassembling thinking/text/tool_use.
func (s *server) proxySSE(w http.ResponseWriter, resp *http.Response, keyID, model string, start time.Time) {
	flusher, _ := w.(http.Flusher)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	var thinking strings.Builder
	var text strings.Builder
	var toolName string
	var toolInput strings.Builder
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 2*maxBody)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) > 0 {
			w.Write(line)
			w.Write([]byte("\n"))
			if flusher != nil {
				flusher.Flush()
			}
		} else {
			w.Write([]byte("\n"))
			if flusher != nil {
				flusher.Flush()
			}
		}
		parseSSE(line, &thinking, &text, &toolName, &toolInput)
	}
	lat := time.Since(start).Milliseconds()
	assembled := map[string]any{}
	if t := strings.TrimSpace(thinking.String()); t != "" {
		assembled["thinking"] = t
	}
	if t := strings.TrimSpace(text.String()); t != "" {
		assembled["text"] = t
	}
	if toolName != "" {
		assembled["tool_use"] = map[string]any{"name": toolName, "input_raw": strings.TrimSpace(toolInput.String())}
	}
	if len(assembled) > 0 {
		s.st.save(turnRow{KeyID: keyID, Model: model, Kind: "sse_assembled", Payload: mustJSON(assembled)}, lat, resp.StatusCode)
	}
}

// parseSSE extracts delta text from anthropic-style SSE events.
func parseSSE(line []byte, thinking, text *strings.Builder, toolName *string, toolInput *strings.Builder) {
	if !bytes.HasPrefix(line, []byte("data:")) {
		return
	}
	data := bytes.TrimSpace(line[5:])
	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return
	}
	var ev struct {
		Type  string `json:"type"`
		Delta struct {
			Type         string `json:"type"`
			Thinking     string `json:"thinking"`
			Text         string `json:"text"`
			PartialJSON  string `json:"partial_json"`
			Name         string `json:"name"`
			ReasoningCon string `json:"reasoning_content"`
		} `json:"delta"`
		ContentBlock struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"content_block"`
	}
	if json.Unmarshal(data, &ev) != nil {
		return
	}
	switch {
	case ev.ContentBlock.Type == "tool_use" && ev.ContentBlock.Name != "":
		*toolName = ev.ContentBlock.Name
	case ev.Delta.Thinking != "":
		thinking.WriteString(ev.Delta.Thinking)
	case ev.Delta.ReasoningCon != "":
		thinking.WriteString(ev.Delta.ReasoningCon)
	case ev.Delta.Text != "":
		text.WriteString(ev.Delta.Text)
	case ev.Delta.PartialJSON != "":
		toolInput.WriteString(ev.Delta.PartialJSON)
	case ev.Delta.Name != "":
		*toolName = ev.Delta.Name
	}
}

// sanitizedBody returns a persisted copy of the request WITHOUT auth headers
// (they were never copied) and with a truncation marker if needed.
func sanitizedBody(body []byte, truncated bool) json.RawMessage {
	var cap int = 2000
	if len(body) < cap {
		cap = len(body)
	}
	var p map[string]any
	if json.Unmarshal(body, &p) != nil {
		return mustJSON(map[string]any{"raw_prefix": string(body[:cap]), "truncated": truncated})
	}
	if truncated {
		p["_truncated"] = true
	}
	return mustJSON(p)
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func main() {
	var (
		listen        = flag.String("listen", "127.0.0.1:8090", "listen address")
		upstream      = flag.String("upstream", "https://api.z.ai/api/anthropic", "upstream LLM API base URL")
		engineURL     = flag.String("engine-url", "", "cerberus engine URL for decide (empty = visibility only)")
		engineTok     = flag.String("engine-token", "", "cerberus engine admin token (or env CERBERUS_ADMIN_TOKEN)")
		dataDir       = flag.String("data-dir", ".", "directory for tap-YYYYMMDD.db")
		retentionDays = flag.Int("retention-days", 14, "days to keep tap DBs (0 = forever)")
	)
	flag.Parse()
	if *engineTok == "" {
		*engineTok = os.Getenv("CERBERUS_ADMIN_TOKEN")
	}

	st := newStore(*dataDir, *retentionDays)
	srv := &server{
		upstream:  strings.TrimSuffix(*upstream, "/"),
		engineURL: *engineURL,
		engineTok: *engineTok,
		client:    &http.Client{Timeout: 300 * time.Second},
		st:        st,
	}

	httpSrv := &http.Server{Addr: *listen, Handler: srv}
	go func() {
		log.Printf("[tap] listening on %s -> %s (engine: %s)", *listen, *upstream, orDefault(*engineURL, "off"))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpSrv.Shutdown(ctx)
	st.close()
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
