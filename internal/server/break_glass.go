package server

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
)

type breakGlassManager struct {
	mu           sync.RWMutex
	globalUntil  time.Time
	globalReason string
	keysUntil    map[string]time.Time
	keysReason   map[string]string
}

func newBreakGlassManager() *breakGlassManager {
	return &breakGlassManager{
		keysUntil:  make(map[string]time.Time),
		keysReason: make(map[string]string),
	}
}

func (bg *breakGlassManager) Activate(keyID string, duration time.Duration, reason string) time.Time {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	if duration <= 0 || duration > 15*time.Minute {
		duration = 15 * time.Minute
	}
	until := time.Now().Add(duration)
	if keyID == "" || keyID == "*" {
		bg.globalUntil = until
		bg.globalReason = reason
	} else {
		bg.keysUntil[keyID] = until
		bg.keysReason[keyID] = reason
	}
	return until
}

func (bg *breakGlassManager) Deactivate(keyID string) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	if keyID == "" || keyID == "*" {
		bg.globalUntil = time.Time{}
		bg.globalReason = ""
	} else {
		delete(bg.keysUntil, keyID)
		delete(bg.keysReason, keyID)
	}
}

func (bg *breakGlassManager) IsActive(keyID string) (bool, string) {
	bg.mu.RLock()
	defer bg.mu.RUnlock()
	now := time.Now()
	if !bg.globalUntil.IsZero() && now.Before(bg.globalUntil) {
		return true, bg.globalReason
	}
	if keyID != "" {
		if until, ok := bg.keysUntil[keyID]; ok && now.Before(until) {
			return true, bg.keysReason[keyID]
		}
	}
	return false, ""
}

func (bg *breakGlassManager) Status(keyID string) map[string]any {
	bg.mu.RLock()
	defer bg.mu.RUnlock()
	now := time.Now()
	active, reason := bg.IsActive(keyID)
	res := map[string]any{
		"active": active,
		"reason": reason,
	}
	if !bg.globalUntil.IsZero() && now.Before(bg.globalUntil) {
		res["global_expires_at"] = bg.globalUntil.Format(time.RFC3339)
	}
	if keyID != "" {
		if until, ok := bg.keysUntil[keyID]; ok && now.Before(until) {
			res["key_expires_at"] = until.Format(time.RFC3339)
		}
	}
	return res
}

func (s *Server) isPrivilegedAdmin(r *http.Request) bool {
	// 1. Unix domain socket caller
	if r.RemoteAddr == "@" || strings.HasPrefix(r.RemoteAddr, "/") || r.RemoteAddr == "" {
		return true
	}
	// 2. Admin bearer token
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if ok && s.deps.AdminToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.deps.AdminToken)) == 1 {
		return true
	}
	return false
}

type breakGlassReq struct {
	KeyID           string `json:"key_id"`
	DurationMinutes int    `json:"duration_minutes"`
	Reason          string `json:"reason"`
}

func (s *Server) postBreakGlass(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var req breakGlassReq
	if len(body) > 0 && json.Unmarshal(body, &req) != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.Reason == "" {
		req.Reason = "admin manual activation"
	}
	dur := time.Duration(req.DurationMinutes) * time.Minute
	if dur <= 0 || dur > 15*time.Minute {
		dur = 15 * time.Minute
	}
	until := s.breakGlass.Activate(req.KeyID, dur, req.Reason)

	// Emit BIG RED audit event & SSE alert
	if s.deps.Audit != nil {
		var epoch uint64
		if s.deps.Store != nil && s.deps.Store.Current() != nil {
			epoch = s.deps.Store.Current().Epoch
		}
		s.deps.Audit.Emit(audit.Event{
			Time:     time.Now(),
			Stage:    "admin",
			KeyID:    req.KeyID,
			Subject:  "break-glass",
			Decision: "allow",
			RuleID:   "ops.break_glass",
			Reason:   "BREAK-GLASS EMERGENCY ARMED: " + req.Reason,
			Epoch:    epoch,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "activated",
		"key_id":     req.KeyID,
		"expires_at": until.Format(time.RFC3339),
		"reason":     req.Reason,
	})
}

func (s *Server) getBreakGlass(w http.ResponseWriter, r *http.Request) {
	keyID := r.URL.Query().Get("key_id")
	writeJSON(w, http.StatusOK, s.breakGlass.Status(keyID))
}

func (s *Server) deleteBreakGlass(w http.ResponseWriter, r *http.Request) {
	keyID := r.URL.Query().Get("key_id")
	s.breakGlass.Deactivate(keyID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deactivated", "key_id": keyID})
}
