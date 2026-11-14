package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/metabbe3/cerberus/internal/auth"
	"github.com/metabbe3/cerberus/internal/config"
	"github.com/metabbe3/cerberus/internal/util"
)

// maxBodyBytes caps every request body (Global Constraints: 1 MiB).
const maxBodyBytes = config.DefaultMaxBodyBytes

// statusWriter records the status code for the access log; Unwrap lets
// http.NewResponseController reach the real Flusher (SSE needs it).
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

// Unwrap is required by http.NewResponseController to find Flusher behind
// this wrapper.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// withMiddleware wraps every request: panic recovery, request-id +
// X-Cerberus-Version headers, 1 MiB body limit, JSON content-type on
// body-carrying POST/PUT, and one structured access-log line.
func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		rid := r.Header.Get("X-Request-Id")
		if rid == "" {
			rid = newRequestID()
		}
		sw.Header().Set("X-Request-Id", rid)
		if s.deps.Version != "" {
			sw.Header().Set("X-Cerberus-Version", s.deps.Version)
		}

		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("http: panic", "panic", rec, "method", r.Method, "path", r.URL.Path)
				if !sw.wrote {
					writeErr(sw, http.StatusInternalServerError, "internal error")
				}
			}
			s.log.Info("http",
				"method", r.Method, "path", r.URL.Path, "status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(), "request_id", rid)
		}()

		maxBody := int64(maxBodyBytes)
		if strings.HasPrefix(r.URL.Path, "/v1/decide") || r.URL.Path == "/v1/admin/bundle" {
			maxBody = 10 << 20 // 10 MiB to allow LLM oversized inspection (OP04 2MB)
		}
		r.Body = http.MaxBytesReader(sw, r.Body, maxBody)
		if needsJSONBody(r) && !isJSONContentType(r.Header.Get("Content-Type")) {
			writeErr(sw, http.StatusUnsupportedMediaType, "content-type must be application/json")
			return
		}
		next.ServeHTTP(sw, r)
	})
}

// needsJSONBody reports whether the request carries a body that must be JSON:
// POST/PUT with a declared (or chunked) body. Bodyless POSTs — e.g. reload —
// and binary uploads like /v1/admin/bundle are exempt.
func needsJSONBody(r *http.Request) bool {
	if r.URL.Path == "/v1/admin/bundle" {
		return false
	}
	return (r.Method == http.MethodPost || r.Method == http.MethodPut) && r.ContentLength != 0
}

func isJSONContentType(h string) bool {
	mt, _, err := mime.ParseMediaType(h)
	return err == nil && mt == "application/json"
}

// APIError represents a structured error response with code and message.
type APIError = util.APIError

type userCtxKey struct{}

var userContextKey = userCtxKey{}

// UserFromContext retrieves the authenticated user from the request context, if any.
func UserFromContext(ctx context.Context) *auth.User {
	u, _ := ctx.Value(userContextKey).(*auth.User)
	return u
}

// isMutatingAdminRequest returns true if an admin route performs state mutations.
func isMutatingAdminRequest(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return false
	}
	path := r.URL.Path
	if r.Method == http.MethodPost {
		if path == "/v1/admin/policy/validate" ||
			path == "/v1/admin/regex/test" ||
			path == "/v1/admin/explain" ||
			path == "/v1/admin/replay" ||
			path == "/v1/policy/test-run" ||
			path == "/v1/query" ||
			path == "/v1/auth/logout" ||
			path == "/v1/admin/upstream/test" {
			return false
		}
	}
	return true
}

// admin guards the admin routes with the bearer token or DB session token, compared in constant
// time. An empty configured token rejects everything.
func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || tok == "" {
			if cookie, err := r.Cookie("owl_session"); err == nil && cookie.Value != "" {
				tok = cookie.Value
				ok = true
			}
		}

		if !ok || tok == "" {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var authedUser *auth.User
		isMasterAdmin := s.deps.AdminToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.deps.AdminToken)) == 1

		if isMasterAdmin {
			authedUser = &auth.User{
				ID:       0,
				Username: "admin",
				Role:     auth.RoleAdmin,
			}
		} else if s.auth != nil {
			u, err := s.auth.ValidateSession(r.Context(), tok)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if u.Disabled {
				writeErr(w, http.StatusUnauthorized, "pengguna dinonaktifkan")
				return
			}
			authedUser = u
		} else {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		// Role viewer = read-only:
		// "server-side: engine tolak mutasi admin endpoint dgn 403 untuk role viewer — enforcement di engine, bukan cuma UI"
		if authedUser.Role == auth.RoleViewer {
			if isMutatingAdminRequest(r) {
				writeErr(w, http.StatusForbidden, "akses ditolak: role viewer hanya memiliki izin baca")
				return
			}
		}

		if s.adminLimiter != nil && !s.adminLimiter.Allow() {
			writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, authedUser)
		next(w, r.WithContext(ctx))
	}
}

// readBody reads the (already size-capped) body, mapping the two failure
// modes: too large → 413, transport error → 400.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
		} else {
			writeErr(w, http.StatusBadRequest, "error reading body")
		}
		return nil, false
	}
	return b, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	util.WriteJSON(w, status, v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	util.WriteErr(w, status, msg)
}

func writeErrCode(w http.ResponseWriter, status int, code, msg string) {
	util.WriteErrCode(w, status, code, msg)
}

// newRequestID is 8 random bytes as hex; on RNG failure it is empty and the
// header is simply short.
func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
