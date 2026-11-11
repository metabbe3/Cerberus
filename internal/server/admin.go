package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/masking"
	"github.com/metabbe3/cerberus/internal/policy"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
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
	if errors.Is(err, policy.ErrData) || errors.Is(err, policy.ErrCompile) ||
		errors.Is(err, policy.ErrInvalidSignature) || errors.Is(err, policy.ErrMissingSignature) ||
		strings.Contains(err.Error(), "smoke test failed") {
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
	if q.Get("cluster") == "true" {
		s.queryClusterAudit(w, r, f)
		return
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

// getBundle handles GET /v1/admin/bundle for exporting the active bundle.tar.gz.
func (s *Server) getBundle(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}
	b := s.deps.Store.CurrentBundle()
	if len(b) == 0 {
		writeErr(w, http.StatusNotFound, "no active bundle")
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	if snap := s.deps.Store.Current(); snap != nil {
		w.Header().Set("X-Cerberus-Revision", snap.Revision)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// rollbackBundle handles POST /v1/admin/bundle/rollback.
func (s *Server) rollbackBundle(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}
	snap, err := s.deps.Store.Rollback(r.Context())
	if err != nil {
		if errors.Is(err, policy.ErrNoRollback) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeStoreErr(w, "rollback bundle", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"epoch":    snap.Epoch,
		"revision": snap.Revision,
	})
}

type statusResponse struct {
	BundleEpoch        uint64                `json:"bundle_epoch"`
	Revision           string                `json:"revision"`
	ActiveRevision     string                `json:"active_revision"`
	PoliciesLoadedAt   string                `json:"policies_loaded_at"`
	SnapshotAge        string                `json:"snapshot_age"`
	SnapshotAgeSeconds float64               `json:"snapshot_age_seconds"`
	LastReload         string                `json:"last_reload"`
	EvalTotal24hSlash  uint64                `json:"eval_total/24h"`
	EvalTotal24h       uint64                `json:"eval_total_24h"`
	CacheHitRate       float64               `json:"cache_hit_rate"`
	AuditQueueDepth    int                   `json:"audit_queue_depth"`
	TopDenies24h       []audit.RuleDenyCount `json:"top_denies_24h"`
	Deny24hTop10       []audit.RuleDenyCount `json:"deny_24h_top10,omitempty"`
}

// getStatus returns runtime status metrics (bundle epoch, evals, cache hit rate, audit queue).
func (s *Server) getStatus(w http.ResponseWriter, r *http.Request) {
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
	var topDenies []audit.RuleDenyCount
	if s.deps.Audit != nil {
		queueDepth = s.deps.Audit.QueueDepth()
		var err error
		topDenies, err = s.deps.Audit.TopDenies24h(r.Context(), 10)
		if err != nil {
			slog.Warn("admin: top denies 24h", "error", err)
		}
	}
	if topDenies == nil {
		topDenies = []audit.RuleDenyCount{}
	}
	age := time.Since(snap.Loaded)
	resp := statusResponse{
		BundleEpoch:        snap.Epoch,
		Revision:           snap.Revision,
		ActiveRevision:     snap.Revision,
		PoliciesLoadedAt:   snap.Loaded.UTC().Format(time.RFC3339),
		SnapshotAge:        age.Round(time.Millisecond).String(),
		SnapshotAgeSeconds: age.Seconds(),
		LastReload:         snap.Loaded.UTC().Format(time.RFC3339),
		EvalTotal24hSlash:  total,
		EvalTotal24h:       total,
		CacheHitRate:       hitRate,
		AuditQueueDepth:    queueDepth,
		TopDenies24h:       topDenies,
		Deny24hTop10:       topDenies,
	}
	writeJSON(w, http.StatusOK, resp)
}

type policyModuleInfo struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Package string `json:"package"`
	Hash    string `json:"hash"`
	Raw     string `json:"raw"`
}

type listPoliciesResponse struct {
	Revision string             `json:"revision"`
	Result   []policyModuleInfo `json:"result"`
}

// listPolicies handles GET /v1/policies returning list of policy modules + revision + hash.
func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil || s.deps.Store.Current() == nil {
		writeErr(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}
	snap := s.deps.Store.Current()
	dir := s.deps.Store.PolicyDir()

	var modules []policyModuleInfo
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".rego") || strings.HasSuffix(info.Name(), "_test.rego") {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		sum := sha256.Sum256(content)
		hashStr := hex.EncodeToString(sum[:])

		parsed, err := ast.ParseModule(rel, string(content))
		pkg := ""
		if err == nil && parsed != nil && parsed.Package != nil {
			pkg = parsed.Package.Path.String()
			pkg = strings.TrimPrefix(pkg, "data.")
		}

		modules = append(modules, policyModuleInfo{
			ID:      rel,
			Path:    rel,
			Package: pkg,
			Hash:    hashStr,
			Raw:     string(content),
		})
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sort.Slice(modules, func(i, j int) bool {
		return modules[i].ID < modules[j].ID
	})

	writeJSON(w, http.StatusOK, listPoliciesResponse{
		Revision: snap.Revision,
		Result:   modules,
	})
}

var apiDataMaskRules, _ = masking.Compile([]masking.Spec{
	{Pattern: `sk-[A-Za-z0-9_\-]+`, Transform: "redact", Scope: ""},
	{Pattern: `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, Transform: "mask", Scope: ""},
})

// getV1Data handles GET /v1/data (and ?path=...) reading data document read-only with secrets/emails masked.
func (s *Server) getV1Data(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil || s.deps.Store.Current() == nil {
		writeErr(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}
	snap := s.deps.Store.Current()

	p := r.URL.Query().Get("path")
	if p == "" {
		trimmed := strings.TrimPrefix(r.URL.Path, "/v1/data")
		p = strings.TrimPrefix(trimmed, "/")
	}
	p = strings.Trim(p, "/")

	var curr any = snap.Data
	if p != "" {
		segments := strings.FieldsFunc(p, func(c rune) bool {
			return c == '/' || c == '.'
		})
		for _, seg := range segments {
			m, ok := curr.(map[string]any)
			if !ok {
				writeErrCode(w, http.StatusNotFound, "not_found", fmt.Sprintf("path %q not found", p))
				return
			}
			val, found := m[seg]
			if !found {
				writeErrCode(w, http.StatusNotFound, "not_found", fmt.Sprintf("path %q not found", p))
				return
			}
			curr = val
		}
	}

	// Masking: JANGAN expose data.agents mentah — masking email/token di response
	masked, _ := masking.Apply(apiDataMaskRules, "", curr)

	writeJSON(w, http.StatusOK, map[string]any{
		"result": masked,
	})
}

type queryRequest struct {
	Q     string         `json:"q"`
	Query string         `json:"query"`
	Input map[string]any `json:"input"`
}

// postQuery handles POST /v1/query evaluating ad-hoc Rego query (rate limited to 10/min, with email/token masked).
func (s *Server) postQuery(w http.ResponseWriter, r *http.Request) {
	// Rate limit: 10 per minute
	if s.queryLimiter != nil && !s.queryLimiter.Allow() {
		writeErrCode(w, http.StatusTooManyRequests, "rate_limit_exceeded", "query rate limit exceeded (10/min)")
		return
	}

	if s.deps.Store == nil || s.deps.Store.Current() == nil {
		writeErr(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req queryRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	q := req.Q
	if q == "" {
		q = req.Query
	}
	if q == "" {
		writeErr(w, http.StatusBadRequest, "query (q) is required")
		return
	}

	snap := s.deps.Store.Current()
	dir := s.deps.Store.PolicyDir()

	res, err := loader.NewFileLoader().WithFilter(regoFilter).All([]string{dir})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	opts := []func(*rego.Rego){
		rego.Query(q),
		rego.Store(inmem.NewFromObject(snap.Data)),
		rego.StrictBuiltinErrors(true),
	}
	for _, m := range res.Modules {
		opts = append(opts, rego.ParsedModule(m.Parsed))
	}

	prepared, err := rego.New(opts...).PrepareForEval(r.Context())
	if err != nil {
		writeErrCode(w, http.StatusUnprocessableEntity, "compile_error", err.Error())
		return
	}

	rs, err := prepared.Eval(r.Context(), rego.EvalInput(req.Input))
	if err != nil {
		writeErrCode(w, http.StatusInternalServerError, "eval_error", err.Error())
		return
	}

	rawJSON, err := json.Marshal(rs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "marshal eval result")
		return
	}
	var resData any
	_ = json.Unmarshal(rawJSON, &resData)

	masked, _ := masking.Apply(apiDataMaskRules, "", resData)

	writeJSON(w, http.StatusOK, map[string]any{
		"result": masked,
	})
}
