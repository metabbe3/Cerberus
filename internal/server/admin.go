package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/engine"
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
	oldSnap := s.deps.Store.Current()
	var oldBytes []byte
	var summary string
	if oldSnap != nil && oldSnap.Data != nil {
		oldBytes, _ = json.Marshal(oldSnap.Data)
		var newData map[string]any
		_ = json.Unmarshal(body, &newData)
		summary = diffDataSummary(oldSnap.Data, newData)
	} else {
		summary = "initial data"
	}

	snap, err := s.deps.Store.ReplaceData(r.Context(), body)
	if err != nil {
		writeStoreErr(w, "put data", err)
		return
	}
	if s.deps.PGMirror != nil {
		var doc map[string]any
		if jerr := json.Unmarshal(body, &doc); jerr == nil {
			if perr := s.deps.PGMirror.SaveData(r.Context(), doc); perr != nil {
				slog.Error("pg mirror persist failed", "err", perr)
			}
		}
	}

	author := r.Header.Get("X-Admin-User")
	if author == "" {
		author = "admin"
	}

	if s.deps.Audit != nil && len(oldBytes) > 0 {
		_, _ = s.deps.Audit.RecordRevision(r.Context(), author, summary, oldBytes)
		s.deps.Audit.Emit(audit.Event{
			Time:     time.Now().UTC(),
			Stage:    "admin",
			KeyID:    author,
			Subject:  "data",
			Decision: "allow",
			RuleID:   "admin.data.update",
			Reason:   summary,
			Epoch:    snap.Epoch,
		})
	}

	writeJSON(w, http.StatusOK, epochResponse{Epoch: snap.Epoch})
}

func diffDataSummary(oldData, newData map[string]any) string {
	var changes []string
	keys := make(map[string]bool)
	for k := range oldData {
		keys[k] = true
	}
	for k := range newData {
		keys[k] = true
	}
	sortedKeys := make([]string, 0, len(keys))
	for k := range keys {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)

	for _, k := range sortedKeys {
		oldV, hasOld := oldData[k]
		newV, hasNew := newData[k]
		if !hasOld {
			changes = append(changes, "+"+k)
			continue
		}
		if !hasNew {
			changes = append(changes, "-"+k)
			continue
		}
		oldJSON, _ := json.Marshal(oldV)
		newJSON, _ := json.Marshal(newV)
		if string(oldJSON) != string(newJSON) {
			if k == "prod_shield" {
				psChanges := diffSubMap(oldV, newV)
				if len(psChanges) > 0 {
					changes = append(changes, "prod_shield("+strings.Join(psChanges, ", ")+")")
				} else {
					changes = append(changes, "prod_shield")
				}
			} else {
				changes = append(changes, k)
			}
		}
	}
	if len(changes) == 0 {
		return "no changes"
	}
	return "updated " + strings.Join(changes, ", ")
}

func diffSubMap(oldV, newV any) []string {
	oldM, ok1 := oldV.(map[string]any)
	newM, ok2 := newV.(map[string]any)
	if !ok1 || !ok2 {
		return nil
	}
	var diffs []string
	allKeys := make(map[string]bool)
	for k := range oldM {
		allKeys[k] = true
	}
	for k := range newM {
		allKeys[k] = true
	}
	for k := range allKeys {
		oJ, _ := json.Marshal(oldM[k])
		nJ, _ := json.Marshal(newM[k])
		if string(oJ) != string(nJ) {
			diffs = append(diffs, k)
		}
	}
	sort.Strings(diffs)
	return diffs
}

type regexTestRequest struct {
	Regex      string `json:"regex"`
	TestString string `json:"test_string"`
}

type regexTestResponse struct {
	Valid   bool   `json:"valid"`
	Error   string `json:"error,omitempty"`
	Matches bool   `json:"matches"`
}

// testRegex compiles a candidate regex pattern and optionally tests it against an example input string.
func (s *Server) testRegex(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req regexTestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	re, err := regexp.Compile(req.Regex)
	if err != nil {
		writeJSON(w, http.StatusOK, regexTestResponse{
			Valid:   false,
			Error:   err.Error(),
			Matches: false,
		})
		return
	}
	matches := false
	if req.TestString != "" {
		matches = re.MatchString(req.TestString)
	}
	writeJSON(w, http.StatusOK, regexTestResponse{
		Valid:   true,
		Matches: matches,
	})
}

// listRevisions returns the configuration revision history stored in SQLite.
func (s *Server) listRevisions(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if s.deps.Audit == nil {
		writeJSON(w, http.StatusOK, []audit.Revision{})
		return
	}
	revs, err := s.deps.Audit.ListRevisions(r.Context(), limit)
	if err != nil {
		writeInternalErr(w, err)
		return
	}
	if revs == nil {
		revs = []audit.Revision{}
	}
	writeJSON(w, http.StatusOK, revs)
}

type rollbackRequest struct {
	RevisionID int64 `json:"revision_id"`
}

type rollbackResponse struct {
	OK         bool   `json:"ok"`
	Epoch      uint64 `json:"epoch"`
	RevisionID int64  `json:"revision_id"`
}

// rollbackData restores a previous data configuration snapshot from SQLite revisions.
func (s *Server) rollbackData(w http.ResponseWriter, r *http.Request) {
	var req rollbackRequest
	if r.Body != nil {
		body, _ := readBody(w, r)
		if len(body) > 0 {
			_ = json.Unmarshal(body, &req)
		}
	}
	if s.deps.Audit == nil {
		writeErr(w, http.StatusBadRequest, "audit logger not configured")
		return
	}

	var targetRev *audit.Revision
	if req.RevisionID > 0 {
		rev, err := s.deps.Audit.GetRevision(r.Context(), req.RevisionID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "revision not found")
			return
		}
		targetRev = rev
	} else {
		// Take the latest revision
		revs, err := s.deps.Audit.ListRevisions(r.Context(), 1)
		if err != nil || len(revs) == 0 {
			writeErr(w, http.StatusNotFound, "no revision available for rollback")
			return
		}
		targetRev = &revs[0]
	}

	if targetRev.DataJSON == "" {
		writeErr(w, http.StatusUnprocessableEntity, "target revision has empty data")
		return
	}

	snap, err := s.deps.Store.ReplaceData(r.Context(), []byte(targetRev.DataJSON))
	if err != nil {
		writeStoreErr(w, "rollback data", err)
		return
	}

	author := r.Header.Get("X-Admin-User")
	if author == "" {
		author = "admin"
	}

	s.deps.Audit.Emit(audit.Event{
		Time:     time.Now().UTC(),
		Stage:    "admin",
		KeyID:    author,
		Subject:  "data",
		Decision: "allow",
		RuleID:   "admin.data.rollback",
		Reason:   fmt.Sprintf("rollback to revision #%d (%s)", targetRev.ID, targetRev.Summary),
		Epoch:    snap.Epoch,
	})

	writeJSON(w, http.StatusOK, rollbackResponse{
		OK:         true,
		Epoch:      snap.Epoch,
		RevisionID: targetRev.ID,
	})
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
		errors.Is(err, policy.ErrFutureRevision) ||
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

// writeInternalErr logs the full error with slog.Error and responds with a sanitized 500 "internal error".
func writeInternalErr(w http.ResponseWriter, err error) {
	slog.Error("internal error", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
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
		writeInternalErr(w, err)
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
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid until (want RFC3339)")
			return
		}
		f.Until = t
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
		writeInternalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// timeseriesHandler aggregates decisions into fixed buckets between since and
// until (exclusive; until defaults to now) — the shape dashboards chart
// natively, instead of shipping raw events client-side. Buckets are capped at
// 500 and default to 48 (e.g. 24h → 30m slices).
func (s *Server) timeseriesHandler(w http.ResponseWriter, r *http.Request) {
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
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid until (want RFC3339)")
			return
		}
		f.Until = t
	}
	buckets := 48
	if v := q.Get("buckets"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeErr(w, http.StatusBadRequest, "buckets must be 1..500")
			return
		}
		buckets = n
	}
	ts, err := s.deps.Audit.Timeseries(r.Context(), f, buckets)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ts)
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
			writeInternalErr(w, err)
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
func (s *Server) getBundle(w http.ResponseWriter, _ *http.Request) {
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

	if s.deps.Audit != nil {
		author := r.Header.Get("X-Admin-User")
		if author == "" {
			author = "admin"
		}
		s.deps.Audit.Emit(audit.Event{
			Time:     time.Now().UTC(),
			RuleID:   "admin.bundle.rollback",
			KeyID:    author,
			Epoch:    snap.Epoch,
			Reason:   "rollback to revision " + snap.Revision,
			Decision: "allow",
			Stage:    "admin",
		})
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
func (s *Server) listPolicies(w http.ResponseWriter, _ *http.Request) {
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
		content, err := os.ReadFile(path) //nolint:gosec // G304 bundle member, sanitized
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
		writeInternalErr(w, err)
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

	forbiddenBuiltins := []string{"http.send", "opa.runtime", "net.", "crypto."}
	for _, forbidden := range forbiddenBuiltins {
		if strings.Contains(q, forbidden) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("query contains forbidden builtin or function: %s", forbidden))
			return
		}
	}

	snap := s.deps.Store.Current()
	dir := s.deps.Store.PolicyDir()

	res, err := loader.NewFileLoader().WithFilter(regoFilter).All([]string{dir})
	if err != nil {
		writeInternalErr(w, err)
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
		writeInternalErr(w, err)
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

// replayDiffItem describes a difference between an audited decision and its replayed evaluation.
type replayDiffItem struct {
	EventID     int64     `json:"event_id"`
	Time        time.Time `json:"time"`
	Stage       string    `json:"stage"`
	KeyID       string    `json:"key_id"`
	Subject     string    `json:"subject"`
	OldDecision string    `json:"old_decision"`
	NewDecision string    `json:"new_decision"`
	OldRuleID   string    `json:"old_rule_id"`
	NewRuleID   string    `json:"new_rule_id"`
	OldReason   string    `json:"old_reason"`
	NewReason   string    `json:"new_reason"`
	Shift       string    `json:"shift"` // "stricter" | "looser" | "rule_changed"
}

// replayResponse is the JSON report returned by POST /v1/admin/replay.
type replayResponse struct {
	TotalEvaluated   int              `json:"total_evaluated"`
	UnchangedCount   int              `json:"unchanged_count"`
	DiffCount        int              `json:"diff_count"`
	StricterCount    int              `json:"stricter_count"`
	LooserCount      int              `json:"looser_count"`
	RuleChangedCount int              `json:"rule_changed_count"`
	Diffs            []replayDiffItem `json:"diffs"`
}

type replayRequest struct {
	Limit int            `json:"limit"`
	Data  map[string]any `json:"data,omitempty"`
}

// replayAudit handles POST /v1/admin/replay.
// Re-evaluates recent audit events (default 500) against current or draft policy data,
// reporting verdict/rule differences and stricter/looser shifts.
func (s *Server) replayAudit(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil || s.deps.Engine == nil || s.deps.Audit == nil {
		writeErr(w, http.StatusServiceUnavailable, "dependencies unavailable")
		return
	}

	limit := 500
	var draftData map[string]any

	if r.Body != nil {
		body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20))
		if len(body) > 0 && isJSONObject(body) {
			var req replayRequest
			if err := json.Unmarshal(body, &req); err == nil {
				if req.Limit > 0 {
					limit = req.Limit
				}
				if len(req.Data) > 0 {
					draftData = req.Data
				}
			}
		}
	}
	if qLimit := r.URL.Query().Get("limit"); qLimit != "" {
		if n, err := strconv.Atoi(qLimit); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 1000 {
		limit = 1000
	}

	snap := s.deps.Store.Current()
	if draftData != nil {
		dataBytes, err := json.Marshal(draftData)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid draft data JSON")
			return
		}
		draftSnap, err := policy.Load(r.Context(), s.deps.Store.PolicyDir(), dataBytes, snap.Epoch)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("draft data compile error: %v", err))
			return
		}
		snap = draftSnap
	}

	events, err := s.deps.Audit.Query(r.Context(), audit.Filter{Limit: limit})
	if err != nil || len(events) == 0 {
		events = s.deps.Audit.Recent(limit)
	}

	resp := replayResponse{
		TotalEvaluated: len(events),
		Diffs:          make([]replayDiffItem, 0),
	}

	for _, ev := range events {
		in := engine.Input{
			Stage: ev.Stage,
			KeyID: ev.KeyID,
			Args:  ev.Args,
		}
		switch ev.Stage {
		case "llm":
			in.Model = ev.Subject
			if ev.Args != nil {
				if p, ok := ev.Args["prompt"].(string); ok {
					in.Prompt = p
				}
			}
		case "tool":
			in.ToolCall = ev.Subject
		case "http":
			in.Resource = ev.Subject
			if ev.Args != nil {
				if m, ok := ev.Args["method"].(string); ok {
					in.Action = m
				}
			}
		case "docker":
			if ev.Args != nil {
				if act, ok := ev.Args["action"].(string); ok {
					in.Action = act
					in.Resource = ev.Subject
				} else {
					in.Action = ev.Subject
					if res, ok := ev.Args["resource"].(string); ok {
						in.Resource = res
					}
				}
			} else {
				in.Action = ev.Subject
			}
		default:
			in.Action = ev.Subject
		}

		dec := s.deps.Engine.EvalSnapshot(r.Context(), snap, in)
		if ev.Decision == dec.Decision && ev.RuleID == dec.RuleID {
			resp.UnchangedCount++
		} else {
			resp.DiffCount++
			var shift string
			switch {
			case ev.Decision == "allow" && dec.Decision == "deny":
				shift = "stricter"
				resp.StricterCount++
			case ev.Decision == "deny" && dec.Decision == "allow":
				shift = "looser"
				resp.LooserCount++
			default:
				shift = "rule_changed"
				resp.RuleChangedCount++
			}

			resp.Diffs = append(resp.Diffs, replayDiffItem{
				EventID:     ev.ID,
				Time:        ev.Time,
				Stage:       ev.Stage,
				KeyID:       ev.KeyID,
				Subject:     ev.Subject,
				OldDecision: ev.Decision,
				NewDecision: dec.Decision,
				OldRuleID:   ev.RuleID,
				NewRuleID:   dec.RuleID,
				OldReason:   ev.Reason,
				NewReason:   dec.Reason,
				Shift:       shift,
			})
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// getCoverage handles GET /v1/admin/coverage.
func (s *Server) getCoverage(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}
	rep, err := s.deps.Store.Coverage(r.Context())
	if err != nil {
		writeInternalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
