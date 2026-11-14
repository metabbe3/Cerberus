package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/upstream"
)

// handleGetUpstream handles GET /v1/admin/upstream.
// Returns public metadata without exposing the plaintext API key.
func (s *Server) handleGetUpstream(w http.ResponseWriter, r *http.Request) {
	if s.upstream == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"endpoint":   "",
			"key_hint":   "",
			"updated_at": "",
		})
		return
	}

	cfg, err := s.upstream.GetConfig(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "gagal membaca konfigurasi upstream: "+err.Error())
		return
	}
	if cfg == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"endpoint":   "",
			"key_hint":   "",
			"updated_at": "",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint":   cfg.EndpointURL,
		"key_hint":   cfg.KeyHint,
		"updated_by": cfg.UpdatedBy,
		"updated_at": cfg.UpdatedAt.Format(time.RFC3339),
	})
}

// handlePutUpstream handles PUT /v1/admin/upstream.
// Saves upstream endpoint and encrypted API key (AES-256-GCM).
// Emits audit event upstream.update.
func (s *Server) handlePutUpstream(w http.ResponseWriter, r *http.Request) {
	if s.upstream == nil {
		writeErr(w, http.StatusInternalServerError, "upstream store belum diinisialisasi")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req struct {
		Endpoint string `json:"endpoint"`
		APIKey   string `json:"api_key"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "format json tidak valid")
		return
	}

	updatedBy := "admin"
	if u := UserFromContext(r.Context()); u != nil && u.Username != "" {
		updatedBy = u.Username
	}

	cfg, err := s.upstream.SaveConfig(r.Context(), req.Endpoint, req.APIKey, updatedBy)
	if err != nil {
		switch {
		case errors.Is(err, upstream.ErrInvalidURL):
			writeErr(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, upstream.ErrAPIKeyTooShort):
			writeErr(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, upstream.ErrAPIKeyRequired):
			writeErr(w, http.StatusBadRequest, err.Error())
		default:
			writeErr(w, http.StatusInternalServerError, "gagal menyimpan konfigurasi: "+err.Error())
		}
		return
	}

	// Emit audit event
	if s.deps.Audit != nil {
		var epoch uint64
		if s.deps.Store != nil && s.deps.Store.Current() != nil {
			epoch = s.deps.Store.Current().Epoch
		}
		s.deps.Audit.Emit(audit.Event{
			Time:     time.Now(),
			Stage:    "admin",
			KeyID:    updatedBy,
			Subject:  cfg.EndpointURL,
			Decision: "allow",
			RuleID:   "upstream.update",
			Reason:   fmt.Sprintf("upstream configuration updated to %s", cfg.EndpointURL),
			Epoch:    epoch,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint":   cfg.EndpointURL,
		"key_hint":   cfg.KeyHint,
		"updated_by": cfg.UpdatedBy,
		"updated_at": cfg.UpdatedAt.Format(time.RFC3339),
	})
}

// handleTestUpstream handles POST /v1/admin/upstream/test.
// Performs a lightweight connectivity check with a 10s timeout.
func (s *Server) handleTestUpstream(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req struct {
		Endpoint string `json:"endpoint"`
		APIKey   string `json:"api_key"`
	}
	_ = json.Unmarshal(body, &req)

	endpoint := strings.TrimSpace(req.Endpoint)
	apiKey := strings.TrimSpace(req.APIKey)

	// Fallback to active target if endpoint is empty
	if endpoint == "" && s.upstream != nil {
		active, err := s.upstream.GetActiveTarget(r.Context())
		if err == nil && active != nil {
			endpoint = active.EndpointURL
			if apiKey == "" {
				apiKey = active.APIKey
			}
		}
	} else if apiKey == "" && s.upstream != nil {
		// If endpoint is given but apiKey is empty, check if active target has a key
		active, err := s.upstream.GetActiveTarget(r.Context())
		if err == nil && active != nil && strings.TrimRight(endpoint, "/") == strings.TrimRight(active.EndpointURL, "/") {
			apiKey = active.APIKey
		}
	}

	if endpoint == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         false,
			"latency_ms": 0,
			"error":      "endpoint upstream belum ditentukan",
		})
		return
	}

	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         false,
			"latency_ms": 0,
			"error":      "skema endpoint harus http:// atau https://",
		})
		return
	}

	start := time.Now()
	client := &http.Client{Timeout: 10 * time.Second}

	// Try GET /models or /v1/models probe
	probeURL := strings.TrimRight(endpoint, "/") + "/models"
	probeReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, probeURL, nil)
	if err == nil && apiKey != "" {
		probeReq.Header.Set("Authorization", "Bearer "+apiKey)
		probeReq.Header.Set("x-api-key", apiKey)
	}

	resp, err := client.Do(probeReq)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		// Try root probe fallback
		startRoot := time.Now()
		rootReq, err2 := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
		if err2 == nil {
			if apiKey != "" {
				rootReq.Header.Set("Authorization", "Bearer "+apiKey)
			}
			resp2, errRoot := client.Do(rootReq)
			if errRoot == nil {
				_ = resp2.Body.Close()
				latRoot := time.Since(startRoot).Milliseconds()
				writeJSON(w, http.StatusOK, map[string]any{
					"ok":         resp2.StatusCode < 500,
					"latency_ms": latRoot,
					"error":      "",
				})
				return
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         false,
			"latency_ms": lat,
			"error":      fmt.Sprintf("koneksi gagal: %v", err),
		})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         false,
			"latency_ms": lat,
			"error":      fmt.Sprintf("autentikasi ditolak (HTTP %d)", resp.StatusCode),
		})
		return
	}

	// Any non-5xx response means the upstream server is up and responsive
	if resp.StatusCode < 500 {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         true,
			"latency_ms": lat,
			"error":      "",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         false,
		"latency_ms": lat,
		"error":      fmt.Sprintf("upstream mengembalikan HTTP %d", resp.StatusCode),
	})
}

// handleGetInternalUpstream handles GET /v1/internal/upstream.
// Used by cerberus-tap to retrieve active decrypted credentials for hot-reload.
func (s *Server) handleGetInternalUpstream(w http.ResponseWriter, r *http.Request) {
	if s.upstream == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"endpoint": "",
			"api_key":  "",
		})
		return
	}

	target, err := s.upstream.GetActiveTarget(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "gagal mendekripsi target upstream: "+err.Error())
		return
	}
	if target == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"endpoint": "",
			"api_key":  "",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint": target.EndpointURL,
		"api_key":  target.APIKey,
	})
}

// handleGetTapTurns handles GET /v1/tap/turns.
// Proxies to tap's /tap/turns endpoint or returns empty list if tap is not reachable.
func (s *Server) handleGetTapTurns(w http.ResponseWriter, r *http.Request) {
	tapURL := os.Getenv("CERBERUS_TAP_URL")
	if tapURL == "" {
		tapURL = "http://127.0.0.1:8090"
	}
	tapURL = strings.TrimRight(tapURL, "/") + "/tap/turns"
	if q := r.URL.RawQuery; q != "" {
		tapURL += "?" + q
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, tapURL, nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
		return
	}

	adminTok := os.Getenv("TAP_ADMIN_TOKEN")
	if adminTok != "" {
		req.Header.Set("Authorization", "Bearer "+adminTok)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}

// handleToggleAgentCapture handles POST /v1/admin/agents/{keyId}/capture.
// Updates agent's capture privacy flag and emits agent.capture_toggle audit event.
func (s *Server) handleToggleAgentCapture(w http.ResponseWriter, r *http.Request) {
	keyID := r.PathValue("keyId")
	if keyID == "" {
		writeErr(w, http.StatusBadRequest, "key_id wajib disertakan")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req struct {
		Capture bool `json:"capture"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "format json tidak valid")
		return
	}

	if s.deps.Store == nil {
		writeErr(w, http.StatusInternalServerError, "store belum siap")
		return
	}

	snap := s.deps.Store.Current()
	if snap == nil || snap.Data == nil {
		writeErr(w, http.StatusInternalServerError, "snapshot data tidak tersedia")
		return
	}

	// Deep clone data
	dataRaw, err := json.Marshal(snap.Data)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "clone data gagal")
		return
	}
	var nextData map[string]any
	if err := json.Unmarshal(dataRaw, &nextData); err != nil {
		writeErr(w, http.StatusInternalServerError, "clone data gagal")
		return
	}

	agents, ok := nextData["agents"].(map[string]any)
	if !ok {
		writeErr(w, http.StatusBadRequest, "tabel agents tidak ditemukan di data")
		return
	}

	agentRaw, exists := agents[keyID]
	if !exists {
		writeErr(w, http.StatusNotFound, "agen tidak ditemukan: "+keyID)
		return
	}

	agentMap, ok := agentRaw.(map[string]any)
	if !ok {
		agentMap = make(map[string]any)
	}

	agentMap["capture"] = req.Capture
	agents[keyID] = agentMap
	nextData["agents"] = agents

	nextBytes, _ := json.Marshal(nextData)
	newSnap, err := s.deps.Store.ReplaceData(r.Context(), nextBytes)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "gagal menyimpan konfigurasi agen: "+err.Error())
		return
	}

	s.mirrorSaveData(newSnap.Data)

	// Emit audit event agent.capture_toggle
	if s.deps.Audit != nil {
		s.deps.Audit.Emit(audit.Event{
			Time:     time.Now(),
			Stage:    "admin",
			KeyID:    keyID,
			Subject:  keyID,
			Decision: "allow",
			RuleID:   "agent.capture_toggle",
			Reason:   fmt.Sprintf("capture flag set to %v", req.Capture),
			Epoch:    newSnap.Epoch,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"key_id":  keyID,
		"capture": req.Capture,
		"epoch":   newSnap.Epoch,
	})
}
