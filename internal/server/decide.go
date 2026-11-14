package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
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

			// R1: Agent secret verification via X-Agent-Key header.
			// If agent has api_key_sha256 configured, X-Agent-Key is mandatory and must match.
			// If CERBERUS_REQUIRE_AGENT_KEYS=true, all non-admin requests must provide a valid agent key.
			requireKeys := os.Getenv("CERBERUS_REQUIRE_AGENT_KEYS") == "true" || os.Getenv("CERBERUS_REQUIRE_AGENT_KEYS") == "1"
			agentKeyHeader := r.Header.Get("X-Agent-Key")

			var expectedHash string
			if s.deps.Store != nil {
				if snap := s.deps.Store.Current(); snap != nil && snap.Data != nil {
					if agents, ok := snap.Data["agents"].(map[string]any); ok {
						if ag, ok := agents[in.KeyID].(map[string]any); ok {
							if h, ok := ag["api_key_sha256"].(string); ok {
								expectedHash = strings.ToLower(strings.TrimSpace(h))
							}
						}
					}
				}
			}

			if expectedHash != "" {
				if agentKeyHeader == "" {
					writeErrCode(w, http.StatusUnauthorized, "agent_key_required", "agent_key_required")
					return
				}
				hdrHashBytes := sha256.Sum256([]byte(agentKeyHeader))
				hdrHash := hex.EncodeToString(hdrHashBytes[:])
				if subtle.ConstantTimeCompare([]byte(hdrHash), []byte(expectedHash)) != 1 {
					writeErrCode(w, http.StatusUnauthorized, "agent_key_invalid", "agent_key_invalid")
					return
				}
			} else if requireKeys {
				if agentKeyHeader == "" {
					writeErrCode(w, http.StatusUnauthorized, "agent_key_required", "agent_key_required")
					return
				}
				writeErrCode(w, http.StatusUnauthorized, "agent_key_invalid", "agent_key_invalid")
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

		// Rate limiting and quota check per key and team
		var teamID string
		if s.deps.Store != nil && s.deps.Store.Current() != nil {
			teamID = extractTeamID(s.deps.Store.Current().Data, in.KeyID)
		}
		if teamID != "" {
			w.Header().Set("X-Cerberus-Team", teamID)
		}

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

			// Inject team budget spend into input.context.budget_spent_usd if not already set
			if in.KeyID != "" {
				teamSpend := s.limiter.GetTeamSpend(in.KeyID)
				if in.Context == nil {
					in.Context = make(map[string]any)
				}
				if _, exists := in.Context["budget_spent_usd"]; !exists {
					in.Context["budget_spent_usd"] = teamSpend
				}
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
		if d.Decision == "allow" && in.Context != nil && s.limiter != nil && in.KeyID != "" {
			for _, k := range []string{"spend_usd", "cost_usd"} {
				if val, ok := in.Context[k]; ok {
					var spend float64
					switch v := val.(type) {
					case float64:
						spend = v
					case int:
						spend = float64(v)
					case int64:
						spend = float64(v)
					}
					if spend > 0 {
						s.limiter.RecordSpend(in.KeyID, spend)
						break
					}
				}
			}
		}
		writeJSON(w, http.StatusOK, d)
	}
}

func extractTeamID(data map[string]any, keyID string) string {
	if data == nil || keyID == "" {
		return ""
	}
	agents, ok := data["agents"].(map[string]any)
	if !ok {
		return ""
	}
	agent, ok := agents[keyID].(map[string]any)
	if !ok {
		return ""
	}
	teamID, ok := agent["team_id"].(string)
	if !ok {
		return ""
	}
	return teamID
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
