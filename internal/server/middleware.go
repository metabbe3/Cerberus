package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

// maxBodyBytes caps every request body (Global Constraints: 1 MiB).
const maxBodyBytes = 1 << 20

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
func (s *server) withMiddleware(next http.Handler) http.Handler {
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

		r.Body = http.MaxBytesReader(sw, r.Body, maxBodyBytes)
		if needsJSONBody(r) && !isJSONContentType(r.Header.Get("Content-Type")) {
			writeErr(sw, http.StatusUnsupportedMediaType, "content-type must be application/json")
			return
		}
		next.ServeHTTP(sw, r)
	})
}

// needsJSONBody reports whether the request carries a body that must be JSON:
// POST/PUT with a declared (or chunked) body. Bodyless POSTs — e.g. reload —
// are exempt.
func needsJSONBody(r *http.Request) bool {
	return (r.Method == http.MethodPost || r.Method == http.MethodPut) && r.ContentLength != 0
}

func isJSONContentType(h string) bool {
	mt, _, err := mime.ParseMediaType(h)
	return err == nil && mt == "application/json"
}

// admin guards the admin routes with the bearer token, compared in constant
// time. An empty configured token rejects everything.
func (s *server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.deps.AdminToken == "" || !ok ||
			subtle.ConstantTimeCompare([]byte(tok), []byte(s.deps.AdminToken)) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
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
