package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/loader"
)

type epochResponse struct {
	Epoch uint64 `json:"epoch"`
}

type validationResponse struct {
	OK     bool     `json:"ok"`
	Errors []string `json:"errors,omitempty"`
}

// getData returns the live data document with its epoch in a header.
func (s *Server) getData(w http.ResponseWriter, _ *http.Request) {
	snap := s.deps.Store.Current()
	if snap == nil {
		writeErr(w, http.StatusServiceUnavailable, "not ready")
		return
	}
	w.Header().Set("X-Cerberus-Epoch", strconv.FormatUint(snap.Epoch, 10))
	writeJSON(w, http.StatusOK, snap.Data)
}

// putData validates and installs a new data document (epoch +1). Any
// validation or compile failure answers 422 and leaves the old snapshot live.
func (s *Server) putData(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	snap, err := s.deps.Store.ReplaceData(r.Context(), body)
	if err != nil {
		writeStoreErr(w, "put data", err)
		return
	}
	writeJSON(w, http.StatusOK, epochResponse{Epoch: snap.Epoch})
}

// reload recompiles from disk (epoch +1); same error contract as putData.
func (s *Server) reload(w http.ResponseWriter, r *http.Request) {
	snap, err := s.deps.Store.Reload(r.Context())
	if err != nil {
		writeStoreErr(w, "reload", err)
		return
	}
	writeJSON(w, http.StatusOK, epochResponse{Epoch: snap.Epoch})
}

// writeStoreErr maps a Store error: a rejected document or policy (ErrData,
// ErrCompile) is the client's to fix → 422 with the validation message; any
// other failure (disk full, permissions, missing file) is a server fault →
// 500 with a generic message, details only in the log. Absolute paths never
// reach the client.
func writeStoreErr(w http.ResponseWriter, op string, err error) {
	if errors.Is(err, policy.ErrData) || errors.Is(err, policy.ErrCompile) {
		writeErr(w, http.StatusUnprocessableEntity, stripPaths(err.Error()))
		return
	}
	slog.Error("admin: "+op+" failed", "err", err)
	writeErr(w, http.StatusInternalServerError, op+" failed; see server log")
}

// stripPaths replaces absolute-path tokens in a message with their base name.
func stripPaths(msg string) string {
	fields := strings.Fields(msg)
	for i, f := range fields {
		trimmed := strings.TrimRight(f, ":,")
		if strings.HasPrefix(trimmed, "/") {
			fields[i] = filepath.Base(trimmed) + f[len(trimmed):]
		}
	}
	return strings.Join(fields, " ")
}

// validatePolicy parses one submitted module and compiles it together with
// the modules currently on disk, without touching the live snapshot.
func (s *Server) validatePolicy(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req struct {
		Rego string `json:"rego"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	candidate, err := ast.ParseModule("candidate.rego", req.Rego)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, validationResponse{OK: false, Errors: []string{err.Error()}})
		return
	}
	mods, err := currentModules(s.deps.Store.PolicyDir())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	mods["candidate.rego"] = candidate

	c := ast.NewCompiler()
	c.Compile(mods)
	if c.Failed() {
		errs := make([]string, 0, len(c.Errors))
		for _, e := range c.Errors {
			errs = append(errs, e.Error())
		}
		writeJSON(w, http.StatusUnprocessableEntity, validationResponse{OK: false, Errors: errs})
		return
	}
	writeJSON(w, http.StatusOK, validationResponse{OK: true})
}

// currentModules parses the non-test Rego files under dir, mirroring the
// bundle the policy package compiles (data files and *_test.rego excluded).
func currentModules(dir string) (map[string]*ast.Module, error) {
	res, err := loader.NewFileLoader().WithFilter(regoFilter).All([]string{dir})
	if err != nil {
		return nil, fmt.Errorf("server: load policies: %w", err)
	}
	mods := make(map[string]*ast.Module, len(res.Modules))
	for _, m := range res.Modules {
		mods[m.Name] = m.Parsed
	}
	return mods, nil
}

// regoFilter keeps only non-test .rego files, same rule as policy.Load.
func regoFilter(_ string, info os.FileInfo, _ int) bool {
	if info == nil || info.IsDir() {
		return false
	}
	name := info.Name()
	return strings.HasSuffix(name, ".rego") && !strings.HasSuffix(name, "_test.rego")
}

// queryAudit runs Audit.Query with the filter params from the URL:
// key_id, stage, decision, rule_id, since (RFC3339), limit.
func (s *Server) queryAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := audit.Filter{
		KeyID:    q.Get("key_id"),
		Stage:    q.Get("stage"),
		Decision: q.Get("decision"),
		RuleID:   q.Get("rule_id"),
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid since (want RFC3339)")
			return
		}
		f.Since = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "invalid limit")
			return
		}
		f.Limit = n
	}
	events, err := s.deps.Audit.Query(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, events)
}

type eraseRequest struct {
	ID        any   `json:"id"`
	IDs       []any `json:"ids"`
	RequestID any   `json:"request_id"`
}

type eraseResponse struct {
	OK      bool   `json:"ok"`
	Erased  int    `json:"erased"`
	Message string `json:"message,omitempty"`
}

func (s *Server) eraseDecision(w http.ResponseWriter, r *http.Request) {
	if s.deps.Audit == nil {
		writeErr(w, http.StatusServiceUnavailable, "audit unavailable")
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req eraseRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	parseID := func(v any) (int64, bool) {
		switch n := v.(type) {
		case float64:
			return int64(n), true
		case int:
			return int64(n), true
		case int64:
			return n, true
		case string:
			parsed, err := strconv.ParseInt(n, 10, 64)
			return parsed, err == nil
		default:
			return 0, false
		}
	}

	var ids []int64
	if req.ID != nil {
		if id, ok := parseID(req.ID); ok {
			ids = append(ids, id)
		}
	}
	if req.RequestID != nil {
		if id, ok := parseID(req.RequestID); ok {
			ids = append(ids, id)
		}
	}
	for _, item := range req.IDs {
		if id, ok := parseID(item); ok {
			ids = append(ids, id)
		}
	}

	if len(ids) == 0 {
		writeErr(w, http.StatusBadRequest, "missing or invalid id")
		return
	}

	erasedCount := 0
	for _, id := range ids {
		ok, err := s.deps.Audit.Erase(r.Context(), id)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if ok {
			erasedCount++
		}
	}

	if erasedCount == 0 && len(ids) == 1 {
		writeJSON(w, http.StatusNotFound, eraseResponse{OK: false, Message: "decision not found"})
		return
	}

	writeJSON(w, http.StatusOK, eraseResponse{OK: true, Erased: erasedCount})
}

// uploadBundle handles POST/PUT /v1/admin/bundle for uploading a bundle.tar.gz.
func (s *Server) uploadBundle(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	snap, err := s.deps.Store.LoadBundle(r.Context(), body)
	if err != nil {
		writeStoreErr(w, "load bundle", err)
		return
	}
	writeJSON(w, http.StatusOK, epochResponse{Epoch: snap.Epoch})
}

type statusResponse struct {
	BundleEpoch       uint64  `json:"bundle_epoch"`
	PoliciesLoadedAt  string  `json:"policies_loaded_at"`
	LastReload        string  `json:"last_reload"`
	EvalTotal24hSlash uint64  `json:"eval_total/24h"`
	EvalTotal24h      uint64  `json:"eval_total_24h"`
	CacheHitRate      float64 `json:"cache_hit_rate"`
	AuditQueueDepth   int     `json:"audit_queue_depth"`
}

// getStatus returns runtime status metrics (bundle epoch, evals, cache hit rate, audit queue).
func (s *Server) getStatus(w http.ResponseWriter, _ *http.Request) {
	if s.deps.Store == nil || s.deps.Store.Current() == nil {
		writeErr(w, http.StatusServiceUnavailable, "not ready")
		return
	}
	snap := s.deps.Store.Current()
	var hits, misses uint64
	if s.deps.Engine != nil {
		hits, misses = s.deps.Engine.Stats()
	}
	total := hits + misses
	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}
	queueDepth := 0
	if s.deps.Audit != nil {
		queueDepth = s.deps.Audit.QueueDepth()
	}
	resp := statusResponse{
		BundleEpoch:       snap.Epoch,
		PoliciesLoadedAt:  snap.Loaded.UTC().Format(time.RFC3339),
		LastReload:        snap.Loaded.UTC().Format(time.RFC3339),
		EvalTotal24hSlash: total,
		EvalTotal24h:      total,
		CacheHitRate:      hitRate,
		AuditQueueDepth:   queueDepth,
	}
	writeJSON(w, http.StatusOK, resp)
}
