package util

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// APIError is the standard JSON error structure for Cerberus API responses.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// StatusCodeToCode maps an HTTP status code to a machine-readable error code.
func StatusCodeToCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusUnsupportedMediaType:
		return "unsupported_media_type"
	case http.StatusRequestEntityTooLarge:
		return "request_entity_too_large"
	case http.StatusUnprocessableEntity:
		return "unprocessable_entity"
	case http.StatusTooManyRequests:
		return "rate_limit_exceeded"
	case http.StatusServiceUnavailable:
		return "service_unavailable"
	default:
		return "internal_error"
	}
}

// WriteJSON serializes v as JSON with Content-Type application/json; charset=utf-8.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteErr writes an APIError response using the status code's standard error code.
func WriteErr(w http.ResponseWriter, status int, msg string) {
	code := StatusCodeToCode(status)
	WriteJSON(w, status, APIError{Code: code, Message: msg, Error: msg})
}

// WriteErrCode writes an APIError response with an explicit code string.
func WriteErrCode(w http.ResponseWriter, status int, code, msg string) {
	WriteJSON(w, status, APIError{Code: code, Message: msg, Error: msg})
}

// WriteForbidden writes a standard policy denial response.
func WriteForbidden(w http.ResponseWriter, ruleID, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   "forbidden by policy",
		"rule_id": ruleID,
		"reason":  reason,
	})
}

// ResolveKey extracts the Cerberus key ID from request headers or query parameters.
// Priority:
// 1. Headers: X-Cerberus-Key, X-Policy-Key
// 2. Authorization: Proxy-Authorization Bearer, Authorization Bearer
// 3. Query params: policy_key, key_id
func ResolveKey(r *http.Request) string {
	if k := r.Header.Get("X-Cerberus-Key"); k != "" {
		return k
	}
	if k := r.Header.Get("X-Policy-Key"); k != "" {
		return k
	}
	if auth := r.Header.Get("Proxy-Authorization"); auth != "" {
		if k := bearerOrBasicToken(auth); k != "" {
			return k
		}
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		if k := bearerOrBasicToken(auth); k != "" {
			return k
		}
	}
	if k := r.URL.Query().Get("policy_key"); k != "" {
		return k
	}
	if k := r.URL.Query().Get("key_id"); k != "" {
		return k
	}
	return ""
}

func bearerOrBasicToken(auth string) string {
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) == 2 {
		if strings.EqualFold(parts[0], "bearer") {
			return parts[1]
		}
		if strings.EqualFold(parts[0], "basic") {
			if dec, err := base64.StdEncoding.DecodeString(parts[1]); err == nil {
				userPass := strings.SplitN(string(dec), ":", 2)
				return userPass[0]
			}
		}
	}
	return ""
}

// ExtractHost parses a destination host string (or URL) into host and port.
// Defaults port to 443 if missing or invalid.
func ExtractHost(raw string) (host string, port string) {
	host = raw
	if strings.Contains(host, "://") {
		parts := strings.SplitN(host, "://", 2)
		host = parts[1]
	}
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return host, "443"
	}
	return h, p
}

// ValidateRequest checks for malformed requests (e.g. HTTP smuggling vectors like
// Content-Length and Transfer-Encoding present together, duplicate Content-Length/Host headers).
func ValidateRequest(r *http.Request) error {
	if r == nil {
		return nil
	}
	// Check for Content-Length and Transfer-Encoding present simultaneously
	hasCL := r.ContentLength > 0 || r.Header.Get("Content-Length") != "" || len(r.Header.Values("Content-Length")) > 0
	hasTE := len(r.TransferEncoding) > 0 || r.Header.Get("Transfer-Encoding") != "" || len(r.Header.Values("Transfer-Encoding")) > 0
	if hasCL && hasTE {
		return fmt.Errorf("malformed request: Content-Length and Transfer-Encoding both present")
	}
	// Check duplicate Content-Length headers
	if len(r.Header.Values("Content-Length")) > 1 {
		return fmt.Errorf("malformed request: duplicate Content-Length header")
	}
	// Check duplicate Host headers
	if len(r.Header.Values("Host")) > 1 {
		return fmt.Errorf("malformed request: duplicate Host header")
	}
	// Check duplicate Transfer-Encoding headers
	if len(r.Header.Values("Transfer-Encoding")) > 1 {
		return fmt.Errorf("malformed request: duplicate Transfer-Encoding header")
	}
	return nil
}
