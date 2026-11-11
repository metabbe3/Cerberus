package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/engine"
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

		d := s.deps.Engine.Decide(r.Context(), in)
		writeJSON(w, http.StatusOK, d)
	}
}

// isJSONObject reports whether b, ignoring leading whitespace, starts an object.
func isJSONObject(b []byte) bool {
	b = bytes.TrimLeft(b, " \t\r\n")
	return len(b) > 0 && b[0] == '{'
}
