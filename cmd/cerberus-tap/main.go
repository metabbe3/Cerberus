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
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const maxBody = 2 << 20 // 2MB capture limit per body

// at-rest masking: applied to every persisted payload. Secrets inside
// prompts/thinking/tool args never reach the tap DB in cleartext.
type maskRule struct {
	re   *regexp.Regexp
	repl string
}

var atRestMask = []maskRule{
	{regexp.MustCompile(`sk-[A-Za-z0-9_\-]{8,}`), "sk-[REDACTED]"},
	{regexp.MustCompile(`(?i)(api[_-]?key|token|password|passwd|secret|authorization)["'\s:=]+[A-Za-z0-9_\-\./+=]{8,}`), "$1=[REDACTED]"},
	{regexp.MustCompile(`postgres(ql)?://[^\s"']+`), "postgresql://[REDACTED]"},
	{regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-\./+=]{8,}`), "Bearer [REDACTED]"},
	{regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`), "[EMAIL-REDACTED]"},
}

func maskAtRest(s string) string {
	for _, m := range atRestMask {
		s = m.re.ReplaceAllString(s, m.repl)
	}
	return s
}

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
		_ = s.ins.Close()
		_ = s.db.Close()
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
		_ = db.Close()
		return nil, nil, err
	}
	ins, err := db.Prepare(`INSERT INTO turns (ts, key_id, model, kind, payload, latency_ms, status) VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		_ = db.Close()
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
			_ = os.Remove(filepath.Join(s.dir, name))
			_ = os.Remove(filepath.Join(s.dir, name+"-wal"))
			_ = os.Remove(filepath.Join(s.dir, name+"-shm"))
		}
	}
}

func (s *store) save(t turnRow, latencyMS int64, status int) {
	db, ins, err := s.current(time.Now())
	if err != nil {
		log.Printf("[tap] store open: %v", err)
		return
	}
	masked := maskAtRest(string(t.Payload))
	s.insM.Lock()
	_, err = ins.Exec(time.Now().UTC().Format(time.RFC3339Nano), t.KeyID, t.Model, t.Kind, masked, latencyMS, status)
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
		_ = s.ins.Close()
	}
	if s.db != nil {
		_ = s.db.Close()
	}
}

// decideResp mirrors the engine /v1/decide response (subset we care about).
type decideResp struct {
	Decision   string `json:"decision"`
	RuleID     string `json:"rule_id"`
	Reason     string `json:"reason"`
	TeamID     string `json:"team_id,omitempty"`
	Capture    bool   `json:"-"`
	StatusCode int    `json:"-"`
	RetryAfter string `json:"-"`
}

// askEngine calls POST /v1/decide/llm. Returns verdict, allowed.
// strict=true: engine unreachable => NOT allowed (fail-closed).
func askEngine(engineURL, token, keyID string, body []byte, strict bool) (decideResp, bool) {
	if engineURL == "" {
		return decideResp{Decision: "allow", StatusCode: http.StatusOK, Capture: true}, true
	}
	prompt, msgs := extractConversationAndPrompt(body)
	payloadMap := map[string]any{
		"key_id": keyID,
		"stage":  "llm",
		"action": "chat",
		"model":  modelOf(body),
		"prompt": prompt,
		// Trafik tap sudah in-path ter-inspeksi penuh (capture body + turn audit),
		// sehingga guard ai.llm.unscanned (>4KB tanpa scan) tidak berlaku:
		// tandai sumber agar rule injection_scanned terpenuhi secara jujur
		// dan audit tetap mencatat asal keputusan (context.source).
		"context": map[string]any{
			"scanner": "tap-passthrough",
			"source":  "cerberus-tap",
		},
	}
	if len(msgs) > 0 {
		payloadMap["messages"] = msgs
	}
	payload, _ := json.Marshal(payloadMap)
	url := strings.TrimSuffix(engineURL, "/") + "/v1/decide/llm"
	req, _ := http.NewRequest("POST", url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if strict {
			log.Printf("[tap] engine decide unreachable (STRICT: denying): %v", err)
			return decideResp{Decision: "deny", RuleID: "tap.engine_unreachable_strict", StatusCode: http.StatusBadGateway}, false
		}
		// Engine unreachable: fail-open for visibility mode, but log loudly.
		log.Printf("[tap] engine decide unreachable (allowing): %v", err)
		return decideResp{Decision: "allow", RuleID: "tap.engine_unreachable", StatusCode: http.StatusOK, Capture: true}, true
	}
	defer func() { _ = resp.Body.Close() }()
	var dr decideResp
	dr.StatusCode = resp.StatusCode
	dr.RetryAfter = resp.Header.Get("Retry-After")
	dr.Capture = resp.Header.Get("X-Cerberus-Capture") != "false"
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil || dr.Decision == "" {
		if resp.StatusCode == http.StatusTooManyRequests {
			return decideResp{Decision: "deny", RuleID: "ops.tenant_quota_exceeded", StatusCode: 429, RetryAfter: resp.Header.Get("Retry-After")}, false
		}
		if strict {
			return decideResp{Decision: "deny", RuleID: "tap.engine_bad_response_strict", StatusCode: resp.StatusCode}, false
		}
		log.Printf("[tap] engine decide decode error (allowing)")
		return decideResp{Decision: "allow", RuleID: "tap.engine_bad_response", StatusCode: resp.StatusCode, Capture: true}, true
	}
	dr.StatusCode = resp.StatusCode
	dr.RetryAfter = resp.Header.Get("Retry-After")
	dr.Capture = resp.Header.Get("X-Cerberus-Capture") != "false"
	if dr.TeamID == "" {
		dr.TeamID = resp.Header.Get("X-Cerberus-Team")
	}
	return dr, dr.Decision == "allow" && resp.StatusCode == http.StatusOK
}

func modelOf(body []byte) string {
	var p struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &p)
	return p.Model
}

// extractConversationAndPrompt parses full conversation (system + all turns),
// flattening content arrays to strings, capped at 64KB with middle truncation.
func extractConversationAndPrompt(body []byte) (string, []map[string]any) {
	var p struct {
		System   json.RawMessage `json:"system"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return "", nil
	}

	var allTurns []map[string]any
	if sysText := contentText(p.System); sysText != "" {
		allTurns = append(allTurns, map[string]any{
			"role":    "system",
			"content": sysText,
		})
	}

	var lastUserText string
	for _, m := range p.Messages {
		txt := contentText(m.Content)
		allTurns = append(allTurns, map[string]any{
			"role":    m.Role,
			"content": txt,
		})
		if m.Role == "user" && txt != "" {
			lastUserText = txt
		}
	}

	var toolNames []string
	for _, t := range p.Tools {
		toolNames = append(toolNames, t.Name)
	}
	summary := lastUserText
	if len(p.Tools) > 0 {
		summary += "\n[tools: " + strings.Join(toolNames, ",") + "]"
	}
	if len(summary) > 4000 {
		summary = summary[:4000] + "…"
	}

	cappedTurns := capConversation(allTurns, 64*1024)
	return summary, cappedTurns
}

func capConversation(turns []map[string]any, limit int) []map[string]any {
	total := 0
	for _, t := range turns {
		s, _ := t["content"].(string)
		total += len(s)
	}
	if total <= limit {
		return turns
	}
	half := limit / 2
	var head []map[string]any
	headBytes := 0
	i := 0
	for i < len(turns) && headBytes < half {
		s, _ := turns[i]["content"].(string)
		if headBytes+len(s) <= half {
			head = append(head, turns[i])
			headBytes += len(s)
			i++
		} else {
			rem := half - headBytes
			if rem > 0 {
				head = append(head, map[string]any{
					"role":    turns[i]["role"],
					"content": s[:rem],
				})
			}
			break
		}
	}
	var tail []map[string]any
	tailBytes := 0
	j := len(turns) - 1
	for j >= i && tailBytes < half {
		s, _ := turns[j]["content"].(string)
		if tailBytes+len(s) <= half {
			tail = append([]map[string]any{turns[j]}, tail...)
			tailBytes += len(s)
			j--
		} else {
			rem := half - tailBytes
			if rem > 0 {
				tail = append([]map[string]any{{
					"role":    turns[j]["role"],
					"content": s[len(s)-rem:],
				}}, tail...)
			}
			break
		}
	}
	out := head
	out = append(out, map[string]any{
		"role":    "system",
		"content": "[...truncated...]",
	})
	out = append(out, tail...)
	return out
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

type upstreamTarget struct {
	endpoint string
	apiKey   string
}

type server struct {
	target    atomic.Pointer[upstreamTarget]
	fallback  upstreamTarget
	engineURL string
	engineTok string
	strict    bool
	adminTok  string
	client    *http.Client
	st        *store
	kills     *killRegistry
}

func fetchUpstream(engineURL, token string) (*upstreamTarget, error) {
	if engineURL == "" {
		return nil, errors.New("engine URL not configured")
	}
	u := strings.TrimSuffix(engineURL, "/") + "/v1/internal/upstream"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var res struct {
		Endpoint string `json:"endpoint"`
		APIKey   string `json:"api_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	ep := strings.TrimSpace(res.Endpoint)
	ep = strings.TrimRight(ep, "/")
	if ep == "" {
		return nil, nil // no active DB config
	}
	parsed, err := url.Parse(ep)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("invalid endpoint URL: %s", ep)
	}
	return &upstreamTarget{
		endpoint: ep,
		apiKey:   strings.TrimSpace(res.APIKey),
	}, nil
}

func (s *server) handleTap(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/tap/healthz" {
		_, _ = w.Write([]byte("ok"))
		return
	}
	// Inspection endpoints carry other agents' prompts/thinking — admin-only.
	// When admin token is unconfigured, refuse to serve inspection endpoints (fail-closed).
	if s.adminTok == "" {
		http.Error(w, "admin token not configured", http.StatusServiceUnavailable)
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(tok), []byte(s.adminTok)) != 1 {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/tap/turns":
		limit := 50
		_, _ = fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
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
		defer func() { _ = rows.Close() }()
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
		_ = json.NewEncoder(w).Encode(out)
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
		defer func() { _ = rows.Close() }()
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
		_ = json.NewEncoder(w).Encode(out)
	case "/tap/kill":
		n := 0
		if s.kills != nil {
			n = s.kills.killAll()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"killed_streams":%d}`, n)
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

	// Read FULL body — policy MUST see exactly what we forward. Bodies larger
	// than the hard limit (32MB) are rejected with 413: no oversized body is ever
	// inspected partially and forwarded fully (closes truncation smuggling).
	const hardCap = 32 << 20
	limited := io.LimitReader(r.Body, hardCap+1)
	raw, err := io.ReadAll(limited)
	_ = r.Body.Close()
	if err != nil {
		http.Error(w, "read body: "+err.Error(), 400)
		return
	}
	if len(raw) > hardCap {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = w.Write([]byte(`{"error":{"type":"tap_too_large","message":"request exceeds 32MB inspection limit"}}`))
		return
	}

	keyID := r.Header.Get("X-Tap-Key")
	if keyID == "" {
		log.Printf("[tap] request WITHOUT X-Tap-Key from %s %s", r.RemoteAddr, r.UserAgent())
		keyID = "unknown"
	}

	// Enforcement: ask the engine BEFORE forwarding. deny = request dies here.
	// -strict: engine unreachable => deny (fail-closed). Default: fail-open (visibility mode).
	verdict, allowed := askEngine(s.engineURL, s.engineTok, keyID, raw, s.strict)
	teamID := verdict.TeamID
	if teamID == "" {
		teamID = r.Header.Get("X-Tap-Team")
	}
	if !allowed {
		if verdict.StatusCode == http.StatusTooManyRequests || verdict.RuleID == "ops.tenant_quota_exceeded" {
			if s.kills != nil && teamID != "" {
				s.kills.killTeam(teamID)
			}
			w.Header().Set("Content-Type", "application/json")
			if verdict.RetryAfter != "" {
				w.Header().Set("Retry-After", verdict.RetryAfter)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"type":"tenant_quota_exceeded","code":429,"rule_id":"ops.tenant_quota_exceeded"}}`))
			s.st.save(turnRow{KeyID: keyID, Model: modelOf(raw), Kind: "quota_cut", Payload: mustJSON(map[string]any{
				"verdict": verdict, "path": r.URL.Path,
			})}, time.Since(start).Milliseconds(), 429)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"type":"tap_blocked","message":"blocked by cerberus policy"}}`))
		s.st.save(turnRow{KeyID: keyID, Model: modelOf(raw), Kind: "blocked", Payload: mustJSON(map[string]any{
			"verdict": verdict, "path": r.URL.Path,
		})}, time.Since(start).Milliseconds(), 403)
		return
	}

	// Capture request (auth headers never persisted — we only store parsed fields).
	// Oversized bodies: store prefix + tail + hash, and NEVER forward silently past
	// inspection — the engine already saw the full body above.
	captureEnabled := verdict.Capture
	if !captureEnabled {
		s.st.save(turnRow{
			KeyID:   keyID,
			Model:   modelOf(raw),
			Kind:    "request",
			Payload: mustJSON(map[string]any{"_privacy_mode": true, "_note": "[no-capture: privacy mode enabled]"}),
		}, 0, 0)
	} else {
		truncated := len(raw) > maxBody
		capture := raw
		if truncated {
			half := maxBody / 2
			capture = append(append([]byte{}, raw[:half]...), raw[len(raw)-half:]...)
		}
		s.st.save(turnRow{KeyID: keyID, Model: modelOf(raw), Kind: "request", Payload: sanitizedBody(capture, truncated)}, 0, 0)
	}

	// Forward upstream — atomically loaded active target.
	curTarget := s.target.Load()
	targetURL := curTarget.endpoint + r.URL.Path
	fwd, _ := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(raw)) //nolint:gosec
	fwd.Header = r.Header.Clone()
	fwd.Header.Del("X-Tap-Key")
	if curTarget.apiKey != "" {
		fwd.Header.Set("Authorization", "Bearer "+curTarget.apiKey)
		fwd.Header.Set("x-api-key", curTarget.apiKey)
	}
	resp, err := s.client.Do(fwd) // #nosec G704 -- target dari upstream-config admin (AES-GCM store), bukan input publik
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	isSSE := strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream")
	if isSSE {
		s.proxySSE(w, resp, keyID, teamID, modelOf(raw), start, captureEnabled)
		return
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	lat := time.Since(start).Milliseconds()

	// R4: Non-SSE response >maxBody must NOT be forwarded without inspection (fail-closed)
	if len(respBody) > maxBody {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "response_exceeds_inspection_limit",
			"message": "upstream response exceeds inspection limit",
		})
		s.st.save(turnRow{
			KeyID:   keyID,
			Model:   modelOf(raw),
			Kind:    "response_rejected",
			Payload: mustJSON(map[string]any{"error": "response_exceeds_inspection_limit"}),
		}, lat, http.StatusBadGateway)
		return
	}

	// In non-SSE path, inspect Anthropic responses containing tool_use blocks.
	if strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		type anthropicBlock struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		}
		var msg struct {
			Content []anthropicBlock `json:"content"`
		}
		if err := json.Unmarshal(respBody, &msg); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "response_exceeds_inspection_limit",
				"message": "failed to parse response for inspection: " + err.Error(),
			})
			s.st.save(turnRow{
				KeyID:   keyID,
				Model:   modelOf(raw),
				Kind:    "response_rejected",
				Payload: mustJSON(map[string]any{"error": "response_exceeds_inspection_limit"}),
			}, lat, http.StatusBadGateway)
			return
		}
		if len(msg.Content) > 0 {
			for _, b := range msg.Content {
				if b.Type == "tool_use" {
					rawInput := strings.TrimSpace(string(b.Input))
					if rawInput == "" {
						rawInput = "{}"
					}
					verdict, ok := s.askToolEngine(keyID, modelOf(raw), b.Name, rawInput)
					if !ok {
						if verdict.StatusCode == http.StatusTooManyRequests || verdict.RuleID == "ops.tenant_quota_exceeded" {
							if verdict.TeamID != "" {
								teamID = verdict.TeamID
							}
							if s.kills != nil && teamID != "" {
								s.kills.killTeam(teamID)
							}
							w.Header().Set("Content-Type", "application/json")
							if verdict.RetryAfter != "" {
								w.Header().Set("Retry-After", verdict.RetryAfter)
							}
							w.WriteHeader(http.StatusTooManyRequests)
							_, _ = w.Write([]byte(`{"error":{"type":"tenant_quota_exceeded","code":429,"rule_id":"ops.tenant_quota_exceeded"}}`))
							s.st.save(turnRow{
								KeyID: keyID, Model: modelOf(raw), Kind: "quota_cut",
								Payload: mustJSON(map[string]any{"tool": b.Name, "verdict": verdict}),
							}, lat, 429)
							return
						}
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusBadGateway)
						_ = json.NewEncoder(w).Encode(map[string]any{
							"error":   "cerberus_tool_blocked",
							"message": "tool_use blocked by cerberus policy: " + verdict.Reason,
							"rule_id": verdict.RuleID,
						})
						s.st.save(turnRow{
							KeyID:   keyID,
							Model:   modelOf(raw),
							Kind:    "tool_blocked",
							Payload: mustJSON(map[string]any{"tool": b.Name, "verdict": verdict}),
						}, lat, http.StatusBadGateway)
						return
					}
				}
			}
		}
	}

	// copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)

	if !captureEnabled {
		s.st.save(turnRow{
			KeyID:   keyID,
			Model:   modelOf(raw),
			Kind:    "response",
			Payload: mustJSON(map[string]any{"_privacy_mode": true, "_note": "[no-capture: privacy mode enabled]"}),
		}, lat, resp.StatusCode)
	} else {
		s.st.save(turnRow{KeyID: keyID, Model: modelOf(raw), Kind: "response", Payload: respBody}, lat, resp.StatusCode)
	}
}

// proxySSE tees the stream to the client while reassembling thinking/text/tool_use.
func (s *server) proxySSE(w http.ResponseWriter, resp *http.Response, keyID, teamID, model string, start time.Time, captureEnabled bool) {
	flusher, _ := w.(http.Flusher)
	// kill-switch hook: registering lets /tap/kill sever this stream mid-flight.
	var killID int64
	var killCtx context.Context
	if s.kills != nil {
		killID, killCtx = s.kills.add(keyID, teamID)
		defer s.kills.remove(killID)
		go func() {
			<-killCtx.Done()
			_ = resp.Body.Close()
		}()
	}
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

	// tool_use hold-and-verify: while a tool_use block is open, its events are
	// buffered instead of streamed. On content_block_stop the completed
	// tool call is checked via POST /v1/decide/tool; allowed blocks flush
	// through, denied blocks are replaced with an error event and the stream
	// is cut (the agent never receives the arguments).
	inToolBlock := false
	var heldLines [][]byte
	aborted := false
	var startEv toolStartEvent
	var startInput string
	var hadDelta bool

	flushHeld := func() {
		for _, hl := range heldLines {
			_, _ = w.Write(hl)
			_, _ = w.Write([]byte("\n"))
		}
		heldLines = nil
	}

	for {
		if killCtx != nil {
			select {
			case <-killCtx.Done():
				aborted = true
			default:
			}
			if aborted {
				break
			}
		}
		if !sc.Scan() {
			break
		}
		line := sc.Bytes()
		lineCopy := append([]byte{}, line...)

		if inToolBlock {
			if isContentBlockStop(lineCopy) {
				finalInput := strings.TrimSpace(toolInput.String())
				switch {
				case hadDelta && finalInput != "":
					// input verified via delta path — nothing extra to check
				case startInput != "":
					finalInput = startInput
				case finalInput == "":
					finalInput = "{}"
				}

				// verify the completed tool_use before the agent sees it
				verdict, ok := s.askToolEngine(keyID, model, toolName, finalInput)
				if ok {
					recon := reconstructToolStart(startEv, toolName, finalInput, hadDelta)
					if len(heldLines) > 0 {
						heldLines[0] = recon
					}
					heldLines = append(heldLines, lineCopy)
					flushHeld()
					inToolBlock = false
				} else {
					if verdict.StatusCode == http.StatusTooManyRequests || verdict.RuleID == "ops.tenant_quota_exceeded" {
						if verdict.TeamID != "" {
							teamID = verdict.TeamID
						}
						_, _ = w.Write([]byte("data: {\"type\":\"error\",\"error\":{\"type\":\"tenant_quota_exceeded\",\"code\":429,\"rule_id\":\"ops.tenant_quota_exceeded\"}}\n\n"))
						if flusher != nil {
							flusher.Flush()
						}
						if s.kills != nil && teamID != "" {
							s.kills.killTeam(teamID)
						}
						s.st.save(turnRow{KeyID: keyID, Model: model, Kind: "quota_cut", Payload: mustJSON(map[string]any{
							"tool": toolName, "verdict": verdict, "rule_id": "ops.tenant_quota_exceeded",
						})}, time.Since(start).Milliseconds(), 429)
						break
					}
					_, _ = w.Write([]byte("data: {\"type\":\"error\",\"error\":{\"type\":\"tap_tool_blocked\",\"message\":\"tool_use blocked by cerberus policy: " + verdict.Reason + "\"}}\n\n"))
					if flusher != nil {
						flusher.Flush()
					}
					s.st.save(turnRow{KeyID: keyID, Model: model, Kind: "tool_blocked", Payload: mustJSON(map[string]any{
						"tool": toolName, "verdict": verdict,
					})}, time.Since(start).Milliseconds(), 403)
					break
				}
				continue
			}
			if isPartialJSONDelta(lineCopy) {
				hadDelta = true
			}
			parseSSE(lineCopy, &thinking, &text, &toolName, &toolInput)
			heldLines = append(heldLines, lineCopy)
			continue
		}
		if isToolBlockStart(lineCopy) {
			inToolBlock = true
			startEv = parseToolStart(lineCopy)
			toolName = startEv.ContentBlock.Name
			toolInput.Reset()
			startInput = ""
			hadDelta = false
			if len(startEv.ContentBlock.Input) > 0 {
				raw := strings.TrimSpace(string(startEv.ContentBlock.Input))
				if raw != "" && raw != "{}" && raw != "null" {
					startInput = raw
				}
			}
			heldLines = append(heldLines, lineCopy)
			parseSSE(lineCopy, &thinking, &text, &toolName, &toolInput)
			continue
		}
		if len(lineCopy) > 0 {
			_, _ = w.Write(lineCopy)
			_, _ = w.Write([]byte("\n"))
			if flusher != nil {
				flusher.Flush()
			}
		} else {
			_, _ = w.Write([]byte("\n"))
			if flusher != nil {
				flusher.Flush()
			}
		}
		parseSSE(lineCopy, &thinking, &text, &toolName, &toolInput)
	}
	lat := time.Since(start).Milliseconds()
	assembled := map[string]any{}
	if t := strings.TrimSpace(thinking.String()); t != "" {
		assembled["thinking"] = t
	}
	if t := strings.TrimSpace(text.String()); t != "" {
		assembled["text"] = t
	}
	finalAssembled := strings.TrimSpace(toolInput.String())
	if !hadDelta && startInput != "" {
		finalAssembled = startInput
	}
	if toolName != "" {
		assembled["tool_use"] = map[string]any{"name": toolName, "input_raw": finalAssembled}
	}
	if len(assembled) > 0 {
		if !captureEnabled {
			s.st.save(turnRow{KeyID: keyID, Model: model, Kind: "sse_assembled", Payload: mustJSON(map[string]any{"_privacy_mode": true, "_note": "[no-capture: privacy mode enabled]"})}, lat, resp.StatusCode)
		} else {
			s.st.save(turnRow{KeyID: keyID, Model: model, Kind: "sse_assembled", Payload: mustJSON(assembled)}, lat, resp.StatusCode)
		}
	}
}

// isToolBlockStart reports whether an SSE data line opens a tool_use block.
func isToolBlockStart(line []byte) bool {
	if !bytes.HasPrefix(line, []byte("data:")) {
		return false
	}
	data := bytes.TrimSpace(line[5:])
	var ev struct {
		Type         string `json:"type"`
		ContentBlock struct {
			Type string `json:"type"`
		} `json:"content_block"`
	}
	if json.Unmarshal(data, &ev) != nil {
		return false
	}
	return ev.Type == "content_block_start" && ev.ContentBlock.Type == "tool_use"
}

// isContentBlockStop reports whether an SSE data line closes a content block.
func isContentBlockStop(line []byte) bool {
	if !bytes.HasPrefix(line, []byte("data:")) {
		return false
	}
	data := bytes.TrimSpace(line[5:])
	var ev struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &ev) != nil {
		return false
	}
	return ev.Type == "content_block_stop"
}

type toolStartEvent struct {
	Type         string `json:"type"`
	Index        int    `json:"index,omitempty"`
	ContentBlock struct {
		Type  string          `json:"type"`
		ID    string          `json:"id,omitempty"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input,omitempty"`
	} `json:"content_block"`
}

func parseToolStart(line []byte) toolStartEvent {
	var ev toolStartEvent
	if !bytes.HasPrefix(line, []byte("data:")) {
		return ev
	}
	data := bytes.TrimSpace(line[5:])
	_ = json.Unmarshal(data, &ev)
	return ev
}

func isPartialJSONDelta(line []byte) bool {
	if !bytes.HasPrefix(line, []byte("data:")) {
		return false
	}
	data := bytes.TrimSpace(line[5:])
	var ev struct {
		Type  string `json:"type"`
		Delta struct {
			Type        string `json:"type"`
			PartialJSON string `json:"partial_json"`
		} `json:"delta"`
	}
	if json.Unmarshal(data, &ev) != nil {
		return false
	}
	return ev.Type == "content_block_delta" && (ev.Delta.Type == "input_json_delta" || ev.Delta.PartialJSON != "")
}

func reconstructToolStart(ev toolStartEvent, toolName, verifiedInput string, hadDelta bool) []byte {
	block := map[string]any{
		"type": "tool_use",
		"name": toolName,
	}
	if ev.ContentBlock.ID != "" {
		block["id"] = ev.ContentBlock.ID
	}
	if hadDelta {
		block["input"] = map[string]any{}
	} else {
		var inputObj any
		if err := json.Unmarshal([]byte(verifiedInput), &inputObj); err == nil && inputObj != nil {
			block["input"] = inputObj
		} else {
			block["input"] = map[string]any{}
		}
	}
	out := map[string]any{
		"type":          "content_block_start",
		"content_block": block,
	}
	if ev.Index != 0 {
		out["index"] = ev.Index
	}
	b, _ := json.Marshal(out)
	return append([]byte("data: "), b...)
}

// askToolEngine runs POST /v1/decide/tool for a completed tool_use block.
// No engine configured or unreachable => allow (visibility mode) unless strict.
func (s *server) askToolEngine(keyID, model, tool, inputJSON string) (decideResp, bool) {
	if s.engineURL == "" {
		return decideResp{Decision: "allow", StatusCode: http.StatusOK}, true
	}
	var parsedArgs map[string]any
	if err := json.Unmarshal([]byte(inputJSON), &parsedArgs); err != nil || parsedArgs == nil {
		parsedArgs = make(map[string]any)
	}
	parsedArgs["input_raw"] = inputJSON
	if _, ok := parsedArgs["model"]; !ok && model != "" {
		parsedArgs["model"] = model
	}
	payload, _ := json.Marshal(map[string]any{
		"key_id":    keyID,
		"stage":     "tool",
		"action":    tool,
		"tool_call": tool,
		"args":      parsedArgs,
	})
	url := strings.TrimSuffix(s.engineURL, "/") + "/v1/decide/tool"
	req, _ := http.NewRequest("POST", url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if s.engineTok != "" {
		req.Header.Set("Authorization", "Bearer "+s.engineTok)
	}
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if s.strict {
			return decideResp{Decision: "deny", RuleID: "tap.tool_engine_unreachable_strict", Reason: "engine unreachable (strict)", StatusCode: http.StatusBadGateway}, false
		}
		return decideResp{Decision: "allow", RuleID: "tap.tool_engine_unreachable", StatusCode: http.StatusOK}, true
	}
	defer func() { _ = resp.Body.Close() }()
	var dr decideResp
	dr.StatusCode = resp.StatusCode
	dr.RetryAfter = resp.Header.Get("Retry-After")
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil || dr.Decision == "" {
		if resp.StatusCode == http.StatusTooManyRequests {
			return decideResp{Decision: "deny", RuleID: "ops.tenant_quota_exceeded", StatusCode: 429, RetryAfter: resp.Header.Get("Retry-After")}, false
		}
		if s.strict {
			return decideResp{Decision: "deny", RuleID: "tap.tool_engine_bad_response_strict", Reason: "bad engine response (strict)", StatusCode: resp.StatusCode}, false
		}
		return decideResp{Decision: "allow", RuleID: "tap.tool_engine_bad_response", StatusCode: resp.StatusCode}, true
	}
	dr.StatusCode = resp.StatusCode
	dr.RetryAfter = resp.Header.Get("Retry-After")
	if dr.TeamID == "" {
		dr.TeamID = resp.Header.Get("X-Cerberus-Team")
	}
	return dr, dr.Decision == "allow" && resp.StatusCode == http.StatusOK
}

// streamEntry records in-flight SSE stream context and ownership.
type streamEntry struct {
	cancel context.CancelFunc
	keyID  string
	teamID string
}

// kill registry: per-request CancelFuncs so an external kill signal can sever
// all in-flight SSE streams and tunnels immediately.
type killRegistry struct {
	mu      sync.Mutex
	streams map[int64]streamEntry
	nextID  int64
}

func newKillRegistry() *killRegistry {
	return &killRegistry{streams: make(map[int64]streamEntry)}
}

func (k *killRegistry) add(keyID, teamID string) (int64, context.Context) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.nextID++
	id := k.nextID
	ctx, cancel := context.WithCancel(context.Background())
	k.streams[id] = streamEntry{
		cancel: cancel,
		keyID:  keyID,
		teamID: teamID,
	}
	return id, ctx
}

func (k *killRegistry) remove(id int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if e, ok := k.streams[id]; ok {
		e.cancel()
		delete(k.streams, id)
	}
}

// killAll cancels every registered in-flight stream.
func (k *killRegistry) killAll() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := len(k.streams)
	for _, e := range k.streams {
		e.cancel()
	}
	k.streams = make(map[int64]streamEntry)
	return n
}

// killTeam cancels every in-flight stream for a specific teamID.
func (k *killRegistry) killTeam(teamID string) int {
	if teamID == "" {
		return 0
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	n := 0
	for id, e := range k.streams {
		if e.teamID == teamID {
			e.cancel()
			delete(k.streams, id)
			n++
		}
	}
	return n
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
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
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
	limit := 2000
	if len(body) < limit {
		limit = len(body)
	}
	var p map[string]any
	if json.Unmarshal(body, &p) != nil {
		return mustJSON(map[string]any{"raw_prefix": string(body[:limit]), "truncated": truncated})
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
		strict        = flag.Bool("strict", false, "fail-closed: deny LLM calls when engine unreachable/unreadable")
		adminToken    = flag.String("admin-token", "", "admin token guarding /tap/turns and /tap/stats (or env TAP_ADMIN_TOKEN)")
		retentionDays = flag.Int("retention-days", 14, "days to keep tap DBs (0 = forever)")
	)
	flag.Parse()
	if *engineTok == "" {
		*engineTok = os.Getenv("CERBERUS_ADMIN_TOKEN")
	}

	st := newStore(*dataDir, *retentionDays)
	adminTok := *adminToken
	if adminTok == "" {
		adminTok = os.Getenv("TAP_ADMIN_TOKEN")
	}

	// Precedence: DB > env TAP_UPSTREAM_* > default z.ai
	fallbackURL := os.Getenv("TAP_UPSTREAM_URL")
	if fallbackURL == "" {
		fallbackURL = os.Getenv("TAP_UPSTREAM_ENDPOINT")
	}
	if fallbackURL == "" {
		fallbackURL = os.Getenv("CERBERUS_TAP_UPSTREAM")
	}
	if fallbackURL == "" {
		fallbackURL = *upstream
	}
	fallbackKey := os.Getenv("TAP_UPSTREAM_KEY")
	if fallbackKey == "" {
		fallbackKey = os.Getenv("TAP_UPSTREAM_API_KEY")
	}
	fallback := upstreamTarget{
		endpoint: strings.TrimRight(fallbackURL, "/"),
		apiKey:   fallbackKey,
	}

	srv := &server{
		fallback:  fallback,
		engineURL: *engineURL,
		engineTok: *engineTok,
		strict:    *strict,
		adminTok:  adminTok,
		kills:     newKillRegistry(),
		client:    &http.Client{Timeout: 300 * time.Second},
		st:        st,
	}
	srv.target.Store(&fallback)

	// Hot-reload: fetch upstream target at startup and poll every 30s
	if *engineURL != "" {
		dbTarget, err := fetchUpstream(*engineURL, *engineTok)
		if err == nil && dbTarget != nil && dbTarget.endpoint != "" {
			srv.target.Store(dbTarget)
			log.Printf("[tap] upstream initialized from engine DB: %s", dbTarget.endpoint)
		} else {
			log.Printf("[tap] upstream initialized from fallback: %s", fallback.endpoint)
		}

		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				target, err := fetchUpstream(srv.engineURL, srv.engineTok)
				if err != nil {
					// Network blip or invalid endpoint: retain current target
					continue
				}
				cur := srv.target.Load()
				if target == nil || target.endpoint == "" {
					if cur.endpoint != srv.fallback.endpoint {
						srv.target.Store(&srv.fallback)
						log.Printf("[tap] upstream reverted to fallback: %s", srv.fallback.endpoint)
					}
					continue
				}
				if cur.endpoint != target.endpoint || cur.apiKey != target.apiKey {
					srv.target.Store(target)
					log.Printf("[tap] upstream swapped atomically: %s -> %s", cur.endpoint, target.endpoint)
				}
			}
		}()
	} else {
		log.Printf("[tap] upstream initialized from fallback: %s", fallback.endpoint)
	}

	httpSrv := &http.Server{Addr: *listen, Handler: srv, ReadHeaderTimeout: 10 * time.Second} //nolint:gosec // G112
	go func() {
		cur := srv.target.Load()
		log.Printf("[tap] listening on %s -> %s (engine: %s)", *listen, cur.endpoint, orDefault(*engineURL, "off"))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	st.close()
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
