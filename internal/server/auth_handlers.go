package server

import (
	"log/slog"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/auth"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      auth.User `json:"user"`
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeErr(w, http.StatusServiceUnavailable, "auth service not initialized")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req loginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		req.Username = "admin"
	}

	ip := clientIP(r)
	u, token, expiresAt, err := s.auth.Authenticate(r.Context(), req.Username, req.Password, ip)
	epoch := uint64(0)
	if s.deps.Store != nil && s.deps.Store.Current() != nil {
		epoch = s.deps.Store.Current().Epoch
	}

	if err != nil {
		reason := err.Error()
		if s.deps.Audit != nil {
			s.deps.Audit.Emit(audit.Event{
				Time:     time.Now().UTC(),
				Stage:    "auth",
				KeyID:    req.Username,
				Subject:  "auth",
				Decision: "deny",
				RuleID:   "auth.login_failed",
				Reason:   reason,
				Epoch:    epoch,
			})
		}
		if errors.Is(err, auth.ErrAccountLocked) {
			writeErr(w, http.StatusTooManyRequests, reason)
			return
		}
		writeErr(w, http.StatusUnauthorized, reason)
		return
	}

	// Login succeeded
	if s.deps.Audit != nil {
		s.deps.Audit.Emit(audit.Event{
			Time:     time.Now().UTC(),
			Stage:    "auth",
			KeyID:    u.Username,
			Subject:  "auth",
			Decision: "allow",
			RuleID:   "auth.login",
			Reason:   "login berhasil",
			Epoch:    epoch,
		})
	}

	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- atribut keamanan diatur lengkap di bawah; Secure mengikuti TLS terminator
		Name:     "owl_session",
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   int(auth.SessionDuration.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, loginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User:      *u,
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		if cookie, err := r.Cookie("owl_session"); err == nil {
			tok = cookie.Value
		}
	}

	author := "unknown"
	if s.auth != nil && tok != "" {
		if u, err := s.auth.ValidateSession(r.Context(), tok); err == nil && u != nil {
			author = u.Username
		}
		_ = s.auth.RevokeSession(r.Context(), tok)
	}

	epoch := uint64(0)
	if s.deps.Store != nil && s.deps.Store.Current() != nil {
		epoch = s.deps.Store.Current().Epoch
	}
	if s.deps.Audit != nil {
		s.deps.Audit.Emit(audit.Event{
			Time:     time.Now().UTC(),
			Stage:    "auth",
			KeyID:    author,
			Subject:  "auth",
			Decision: "allow",
			RuleID:   "auth.logout",
			Reason:   "logout berhasil",
			Epoch:    epoch,
		})
	}

	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- atribut keamanan diatur lengkap di bawah; Secure mengikuti TLS terminator
		Name:     "owl_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		if cookie, err := r.Cookie("owl_session"); err == nil {
			tok = cookie.Value
		}
	}

	if tok == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if s.deps.AdminToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.deps.AdminToken)) == 1 {
		writeJSON(w, http.StatusOK, map[string]any{
			"user": auth.User{
				ID:       0,
				Username: "admin",
				Role:     auth.RoleAdmin,
			},
		})
		return
	}

	if s.auth != nil {
		u, err := s.auth.ValidateSession(r.Context(), tok)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user": u,
		})
		return
	}

	writeErr(w, http.StatusUnauthorized, "unauthorized")
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	u := UserFromContext(r.Context())
	if u == nil || u.Role != auth.RoleAdmin {
		writeErr(w, http.StatusForbidden, "hanya admin yang dapat mengelola pengguna")
		return
	}

	if s.auth == nil {
		writeErr(w, http.StatusServiceUnavailable, "auth service not initialized")
		return
	}

	users, err := s.auth.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, users)
}

type createUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	cur := UserFromContext(r.Context())
	if cur == nil || cur.Role != auth.RoleAdmin {
		writeErr(w, http.StatusForbidden, "hanya admin yang dapat mengelola pengguna")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req createUserRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	newUser, err := s.auth.CreateUser(r.Context(), req.Username, req.Password, req.Role)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	epoch := uint64(0)
	if s.deps.Store != nil && s.deps.Store.Current() != nil {
		epoch = s.deps.Store.Current().Epoch
	}
	if s.deps.Audit != nil {
		s.deps.Audit.Emit(audit.Event{
			Time:     time.Now().UTC(),
			Stage:    "auth",
			KeyID:    cur.Username,
			Subject:  "user:" + newUser.Username,
			Decision: "allow",
			RuleID:   "auth.user_created",
			Reason:   fmt.Sprintf("pengguna %s dibuat dengan peran %s", newUser.Username, newUser.Role),
			Epoch:    epoch,
		})
	}

	writeJSON(w, http.StatusCreated, map[string]any{"user": newUser})
}

type setUserDisabledRequest struct {
	Disabled bool `json:"disabled"`
}

func (s *Server) handleSetUserDisabled(w http.ResponseWriter, r *http.Request) {
	cur := UserFromContext(r.Context())
	if cur == nil || cur.Role != auth.RoleAdmin {
		writeErr(w, http.StatusForbidden, "hanya admin yang dapat mengelola pengguna")
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid user id")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req setUserDisabledRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	if err := s.auth.SetUserDisabled(r.Context(), id, req.Disabled); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	ruleID := "auth.user_disabled"
	action := "dinonaktifkan"
	if !req.Disabled {
		ruleID = "auth.user_enabled"
		action = "diaktifkan kembali"
	}

	epoch := uint64(0)
	if s.deps.Store != nil && s.deps.Store.Current() != nil {
		epoch = s.deps.Store.Current().Epoch
	}
	if s.deps.Audit != nil {
		s.deps.Audit.Emit(audit.Event{
			Time:     time.Now().UTC(),
			Stage:    "auth",
			KeyID:    cur.Username,
			Subject:  fmt.Sprintf("user_id:%d", id),
			Decision: "allow",
			RuleID:   ruleID,
			Reason:   fmt.Sprintf("pengguna ID %d %s", id, action),
			Epoch:    epoch,
		})
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type resetPasswordRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	cur := UserFromContext(r.Context())
	if cur == nil || cur.Role != auth.RoleAdmin {
		writeErr(w, http.StatusForbidden, "hanya admin yang dapat mengelola pengguna")
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid user id")
		return
	}

	body, ok := readBody(w, r)
	if !ok {
		return
	}

	var req resetPasswordRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	if err := s.auth.ResetUserPassword(r.Context(), id, req.Password); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	epoch := uint64(0)
	if s.deps.Store != nil && s.deps.Store.Current() != nil {
		epoch = s.deps.Store.Current().Epoch
	}
	if s.deps.Audit != nil {
		s.deps.Audit.Emit(audit.Event{
			Time:     time.Now().UTC(),
			Stage:    "auth",
			KeyID:    cur.Username,
			Subject:  fmt.Sprintf("user_id:%d", id),
			Decision: "allow",
			RuleID:   "auth.password_reset",
			Reason:   fmt.Sprintf("kata sandi pengguna ID %d direset", id),
			Epoch:    epoch,
		})
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAuthChangePassword mengganti password sendiri (verifikasi password lama,
// session lain dicabut otomatis kecuali yang dipakai).
func (s *Server) handleAuthChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "body JSON tidak valid")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeErr(w, http.StatusBadRequest, "current_password dan new_password wajib diisi")
		return
	}
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		if cookie, err := r.Cookie("owl_session"); err == nil {
			tok = cookie.Value
		}
	}
	user, err := s.auth.ValidateSession(r.Context(), tok)
	if err != nil || user == nil {
		writeErr(w, http.StatusUnauthorized, "sesi tidak valid")
		return
	}
	if err := s.auth.ChangeOwnPassword(r.Context(), user.ID, req.CurrentPassword, req.NewPassword, tok); err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeErr(w, http.StatusUnauthorized, "password saat ini salah")
		case errors.Is(err, auth.ErrPasswordTooShort):
			writeErr(w, http.StatusBadRequest, "kata sandi baru minimal 12 karakter")
		default:
			slog.Error("auth: change password", "err", err)
			writeErr(w, http.StatusInternalServerError, "kesalahan internal")
		}
		return
	}
	if s.deps.Audit != nil {
		s.deps.Audit.Emit(audit.Event{
			Time:     time.Now().UTC(),
			Stage:    "auth",
			KeyID:    user.Username,
			Subject:  "auth",
			Decision: "allow",
			RuleID:   "auth.password_changed",
			Reason:   "password diganti sendiri",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "password diganti; session lain dicabut"})
}
