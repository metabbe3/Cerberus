package util

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractHost(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort string
	}{
		{"example.com", "example.com", "443"},
		{"example.com:8080", "example.com", "8080"},
		{"https://secure.example.com/api/v1", "secure.example.com", "443"},
		{"http://localhost:3000/test", "localhost", "3000"},
	}

	for _, tc := range tests {
		h, p := ExtractHost(tc.input)
		if h != tc.wantHost || p != tc.wantPort {
			t.Errorf("ExtractHost(%q) = (%q, %q), want (%q, %q)", tc.input, h, p, tc.wantHost, tc.wantPort)
		}
	}
}

func TestResolveKey(t *testing.T) {
	req1, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
	req1.Header.Set("X-Cerberus-Key", "k-cerb")
	if k := ResolveKey(req1); k != "k-cerb" {
		t.Errorf("ResolveKey(X-Cerberus-Key) = %q, want k-cerb", k)
	}

	req2, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
	req2.Header.Set("Proxy-Authorization", "Bearer k-bearer")
	if k := ResolveKey(req2); k != "k-bearer" {
		t.Errorf("ResolveKey(Proxy-Authorization) = %q, want k-bearer", k)
	}

	req3, _ := http.NewRequest(http.MethodGet, "http://localhost/?key_id=k-query", nil)
	if k := ResolveKey(req3); k != "k-query" {
		t.Errorf("ResolveKey(key_id query) = %q, want k-query", k)
	}
}

func TestWriteJSONAndErr(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteErr(rec, http.StatusNotFound, "not found")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want %d", rec.Code, http.StatusNotFound)
	}
	var errResp APIError
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode APIError: %v", err)
	}
	if errResp.Code != "not_found" || errResp.Message != "not found" {
		t.Errorf("unexpected APIError: %+v", errResp)
	}
}

func TestStr(t *testing.T) {
	if Str("hello") != "hello" {
		t.Errorf("Str(hello) != hello")
	}
	if Str(123) != "" {
		t.Errorf("Str(123) != empty string")
	}
	if Str(nil) != "" {
		t.Errorf("Str(nil) != empty string")
	}
}
