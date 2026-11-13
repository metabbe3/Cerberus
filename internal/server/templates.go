package server

import (
	"encoding/json"
	"net/http"
	"regexp"
)

// templateIDPattern keeps template ids slugs: lowercase letters, digits,
// dashes — no paths, no unicode, nothing that could collide with another
// table or escape quoting.
var templateIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

type templateDoc struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Stage       string         `json:"stage,omitempty"`
	Policy      map[string]any `json:"policy"`
	Builtin     bool           `json:"builtin,omitempty"`
}

// listTemplates returns all wizard templates (builtin + custom) — PG only;
// without a PG mirror the client falls back to its compiled-in builtins.
func (s *Server) listTemplates(w http.ResponseWriter, r *http.Request) {
	if s.deps.PGMirror == nil {
		writeErr(w, http.StatusNotImplemented, "templates require CERBERUS_PG_DSN")
		return
	}
	tpls, err := s.deps.PGMirror.ListTemplates(r.Context())
	if err != nil {
		writeInternalErr(w, err)
		return
	}
	if tpls == nil {
		tpls = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": tpls})
}

// putTemplate upserts a custom template (builtin ids are rejected).
func (s *Server) putTemplate(w http.ResponseWriter, r *http.Request) {
	if s.deps.PGMirror == nil {
		writeErr(w, http.StatusNotImplemented, "templates require CERBERUS_PG_DSN")
		return
	}
	var doc templateDoc
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&doc); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if !templateIDPattern.MatchString(doc.ID) {
		writeErr(w, http.StatusBadRequest, "id must be a slug: [a-z0-9][a-z0-9-]{0,63}")
		return
	}
	if doc.Name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	if doc.Policy == nil {
		doc.Policy = map[string]any{}
	}
	if doc.Stage == "" {
		doc.Stage = "ai"
	}
	// Builtins live in code+seed; a client may never overwrite them.
	for _, b := range builtinTemplateIDs {
		if doc.ID == b {
			writeErr(w, http.StatusConflict, "builtin template id is immutable")
			return
		}
	}
	if err := s.deps.PGMirror.UpsertTemplate(r.Context(), doc.ID, doc.Name, doc.Description, doc.Stage, doc.Policy); err != nil {
		writeInternalErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": doc.ID})
}

// deleteTemplate removes a custom template (builtins protected).
func (s *Server) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	if s.deps.PGMirror == nil {
		writeErr(w, http.StatusNotImplemented, "templates require CERBERUS_PG_DSN")
		return
	}
	id := r.PathValue("id")
	if !templateIDPattern.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.deps.PGMirror.DeleteTemplate(r.Context(), id); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// builtinTemplateIDs mirrors the seed rows in migrations/001_postgres.sql.
var builtinTemplateIDs = []string{
	"research-readonly", "ops-ssh", "llm-cheap-only", "nightly-batch",
	"http-allowlist", "ssh-host-allow", "llm-glm-family", "full-access",
}
