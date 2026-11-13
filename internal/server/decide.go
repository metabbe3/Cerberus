package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/config"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/util"
)

// decide handles POST /v1/decide (stage = "") and the stage aliases
// /v1/decide/llm and /v1/decide/tool, which force the stage regardless of the
// body. The engine maps every failure mode to a deny, so the only client
// errors here are transport-level: 400 invalid json, 413, 415.
func (s *Server) decide(stage string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readBody(w, r)
		if !ok {
			return
		}
		// The body must be a JSON object: json.Unmarshal accepts the literal
		// null (and leaves Input zero-valued), which is a malformed request,
		// not a decision.
		var in engine.Input
		if !isJSONObject(body) || json.Unmarshal(body, &in) != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		if stage != "" {
			in.Stage = stage
		}

		// Security check: unauthenticated caller cannot claim privileged/exempt keys (e.g. k-owner)
		// or spoof a key differing from authentication header.
		callerKey := util.ResolveKey(r)
		isPrivAdmin := s.isPrivilegedAdmin(r)
		if !isPrivAdmin {
			if s.isExemptKey(in.KeyID) {
				writeErr(w, http.StatusUnauthorized, "unauthorized: privileged key requires admin token")
				return
			}
			if callerKey != "" && in.KeyID != "" && callerKey != in.KeyID {
				writeErr(w, http.StatusUnauthorized, "unauthorized: key_id mismatch with credential")
				return
			}
		}

		// Break-glass check: header X-Break-Glass + 15 min time-window
		// Security constraint: only from unix socket or with valid admin token.
		var breakGlassActive bool
		var breakGlassReason string
		if s.breakGlass != nil {
			breakGlassActive, breakGlassReason = s.breakGlass.IsActive(in.KeyID)
		}
		if h := r.Header.Get("X-Break-Glass"); h != "" {
			if in.KeyID == "" {
				writeErr(w, http.StatusBadRequest, "key_id is required for break-glass (use '*' for explicit global bypass)")
				return
			}
			if s.isPrivilegedAdmin(r) {
				breakGlassActive = true
				if breakGlassReason == "" {
					breakGlassReason = h
					if breakGlassReason == "true" || breakGlassReason == "1" {
						breakGlassReason = "privileged admin header bypass"
					}
				}
				if s.breakGlass != nil {
					s.breakGlass.Activate(in.KeyID, config.MaxBreakGlassDuration, breakGlassReason)
				}
			} else {
				s.log.Warn("http: unauthorized X-Break-Glass attempt ignored", "key_id", in.KeyID, "remote_addr", r.RemoteAddr)
			}
		}

		if breakGlassActive {
			var epoch uint64
			if s.deps.Store != nil && s.deps.Store.Current() != nil {
				epoch = s.deps.Store.Current().Epoch
			}
			d := engine.Decision{
				Decision: "allow",
				RuleID:   "ops.break_glass",
				Reason:   "BREAK-GLASS EMERGENCY BYPASS: " + breakGlassReason,
				Epoch:    epoch,
			}
			if s.deps.Audit != nil {
				s.deps.Audit.Emit(audit.Event{
					Time:     time.Now(),
					Stage:    in.Stage,
					KeyID:    in.KeyID,
					Subject:  in.ToolCall,
					Decision: "allow",
					RuleID:   "ops.break_glass",
					Reason:   "BREAK-GLASS EMERGENCY BYPASS: " + breakGlassReason,
					Epoch:    epoch,
				})
			}
			writeJSON(w, http.StatusOK, d)
			return
		}

		// Rate limiting and quota check per key
		if s.limiter != nil {
			verdict := s.limiter.Allow(r.Context(), in.KeyID, in.Stage)
			if !verdict.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(verdict.RetryAfter))
				var epoch uint64
				if s.deps.Store != nil && s.deps.Store.Current() != nil {
					epoch = s.deps.Store.Current().Epoch
				}
				d := engine.Decision{
					Decision: "deny",
					RuleID:   verdict.RuleID,
					Reason:   verdict.Reason,
					Epoch:    epoch,
				}
				if s.deps.Audit != nil {
					s.deps.Audit.Emit(audit.Event{
						Time:     time.Now(),
						Stage:    in.Stage,
						KeyID:    in.KeyID,
						Subject:  in.ToolCall,
						Decision: "deny",
						RuleID:   verdict.RuleID,
						Reason:   verdict.Reason,
						Epoch:    epoch,
					})
				}
				writeJSON(w, http.StatusTooManyRequests, d)
				return
			}
		}

		if r.URL.Query().Get("explain") == "true" {
			if !s.isPrivilegedAdmin(r) {
				writeErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			d := s.deps.Engine.Explain(r.Context(), in)
			if s.deps.Audit != nil {
				var epoch uint64
				if s.deps.Store != nil && s.deps.Store.Current() != nil {
					epoch = s.deps.Store.Current().Epoch
				}
				s.deps.Audit.Emit(audit.Event{
					Time:     time.Now(),
					Stage:    in.Stage,
					KeyID:    in.KeyID,
					Subject:  d.RuleID,
					Decision: d.Decision,
					RuleID:   "admin.explain",
					Reason:   d.Reason,
					Epoch:    epoch,
				})
			}
			writeJSON(w, http.StatusOK, d)
			return
		}

		d := s.deps.Engine.Decide(r.Context(), in)
		writeJSON(w, http.StatusOK, d)
	}
}

// explain handles POST /v1/admin/explain (dry-run evaluation with OPA rule trace).
func (s *Server) explain(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var in engine.Input
	if !isJSONObject(body) || json.Unmarshal(body, &in) != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	d := s.deps.Engine.Explain(r.Context(), in)
	writeJSON(w, http.StatusOK, d)
}

// isJSONObject reports whether b, ignoring leading whitespace, starts an object.
func isJSONObject(b []byte) bool {
	b = bytes.TrimLeft(b, " \t\r\n")
	return len(b) > 0 && b[0] == '{'
}

func (s *Server) isExemptKey(keyID string) bool {
	if keyID == "" {
		return false
	}
	if keyID == "k-owner" {
		return true
	}
	if s.deps.Store != nil {
		snap := s.deps.Store.Current()
		if snap != nil && snap.Data != nil {
			if ps, ok := snap.Data["prod_shield"].(map[string]any); ok {
				if exempts, ok := ps["exempt_keys"].([]any); ok {
					for _, ex := range exempts {
						if sEx, ok := ex.(string); ok && sEx == keyID {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
