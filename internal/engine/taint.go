package engine

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2"
	"github.com/metabbe3/cerberus/internal/util"
)

// TaintMark records the origin and timestamp of a sensitive request that was allowed.
type TaintMark struct {
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

// TaintTracker manages in-memory TTL taint marks with LRU eviction and thread safety.
type TaintTracker struct {
	mu    sync.RWMutex
	cache *lru.Cache[string, TaintMark]
	ttl   time.Duration
}

const (
	defaultTaintCapacity = 10000
	defaultTaintTTL      = 60 * time.Second
)

// NewTaintTracker creates a new TaintTracker with bounded LRU cache and TTL.
func NewTaintTracker(capacity int, ttl time.Duration) (*TaintTracker, error) {
	if capacity <= 0 {
		capacity = defaultTaintCapacity
	}
	if ttl <= 0 {
		ttl = defaultTaintTTL
	}
	cache, err := lru.New[string, TaintMark](capacity)
	if err != nil {
		return nil, fmt.Errorf("taint tracker lru: %w", err)
	}
	return &TaintTracker{
		cache: cache,
		ttl:   ttl,
	}, nil
}

// GetActiveTaint checks if key has an active, unexpired taint mark.
func (tt *TaintTracker) GetActiveTaint(key string) (*TaintMark, bool) {
	if key == "" || tt == nil {
		return nil, false
	}
	tt.mu.Lock()
	defer tt.mu.Unlock()

	mark, ok := tt.cache.Get(key)
	if !ok {
		return nil, false
	}
	if time.Since(mark.CreatedAt) > tt.ttl {
		tt.cache.Remove(key)
		return nil, false
	}
	return &mark, true
}

// RecordTaint stores or updates a taint mark for the given key.
func (tt *TaintTracker) RecordTaint(key, source string) {
	if key == "" || tt == nil {
		return
	}
	tt.mu.Lock()
	defer tt.mu.Unlock()

	tt.cache.Add(key, TaintMark{
		Source:    source,
		CreatedAt: time.Now(),
	})
}

// Clear flushes all taint marks from the tracker.
func (tt *TaintTracker) Clear() {
	if tt == nil {
		return
	}
	tt.mu.Lock()
	defer tt.mu.Unlock()
	tt.cache.Purge()
}

// SessionKey derives the tracking key for taint marks.
// Format: key_id:session_id if session_id is present (or trace_id in context); fallback key_id.
func SessionKey(in Input) string {
	sid := in.SessionID
	if sid == "" && in.Context != nil {
		if v, ok := in.Context["session_id"].(string); ok && v != "" {
			sid = v
		} else if v, ok := in.Context["trace_id"].(string); ok && v != "" {
			sid = v
		}
	}
	if sid != "" {
		if in.KeyID != "" {
			return in.KeyID + ":" + sid
		}
		return sid
	}
	if in.KeyID != "" {
		return in.KeyID
	}
	return "anonymous"
}

// isNonPublicHost checks if a host or resource URL targets non-public/internal IP ranges or hosts.
func isNonPublicHost(host, resource string) bool {
	h := host
	if h == "" && resource != "" {
		if u, err := url.Parse(resource); err == nil && u.Hostname() != "" {
			h = u.Hostname()
		}
	}
	if h == "" {
		return false
	}
	// Strip port if present
	if sh, _, err := net.SplitHostPort(h); err == nil {
		h = sh
	}
	h = util.NormalizeIPString(h)
	ip := net.ParseIP(h)
	if ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
		return false
	}
	lh := strings.ToLower(h)
	if lh == "localhost" || strings.HasSuffix(lh, ".internal") || strings.HasSuffix(lh, ".internal.corp") || strings.HasSuffix(lh, ".local") {
		return true
	}
	return false
}

var (
	writeSQLRegex       = regexp.MustCompile(`(?i)^\s*(insert|update|delete|create|replace|alter|drop|truncate|upsert|merge|copy)\b`)
	egressCmdRegex      = regexp.MustCompile(`(?i)(>\s*|>>\s*|\b(curl|wget|nc|netcat|ncat|socat|ssh|scp|rsync|ftp|telnet)\b)`)
	credPatternRegex    = regexp.MustCompile(`(?i)(\.ssh|id_rsa|id_ed25519|\.env|/etc/shadow|/etc/passwd|credentials|prod_secret)`)
	sensitiveTableRegex = regexp.MustCompile(`(?i)\b(credential|secret|password|token|user|api_key|payment|personal)\w*`)
)

// DetectSensitiveSource inspects an allowed request to determine if it accessed sensitive resources.
// secretMarkers: penanda kredensial nyata yang tidak wajar muncul di prompt agent.
var secretMarkers = []string{
	"BEGIN RSA PRIVATE KEY",
	"BEGIN OPENSSH PRIVATE KEY",
	"BEGIN EC PRIVATE KEY",
	"BEGIN PRIVATE KEY",
	"-----BEGIN PGP PRIVATE KEY",
}

// llmPromptContainsSecret melaporkan apakah teks prompt memuat material kredensial
// nyata (private key block dsb.) — bukan sekadar panjang.
func llmPromptContainsSecret(s string) bool {
	for _, m := range secretMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func DetectSensitiveSource(in Input) (string, bool) {
	switch in.Stage {
	case "http":
		if isNonPublicHost(in.Host, in.Resource) {
			return "http:non_public_ip", true
		}
	case "db":
		var sql string
		if in.Args != nil {
			if s, ok := in.Args["sql"].(string); ok {
				sql = s
			} else if s, ok := in.Args["query"].(string); ok {
				sql = s
			}
		}
		if sql == "" {
			sql = in.Resource
		}
		if sensitiveTableRegex.MatchString(sql) {
			return "db:sensitive_table", true
		}
		if strings.Contains(strings.ToLower(sql), "copy") && strings.Contains(strings.ToLower(sql), "to") {
			return "db:file_drop", true
		}
		if in.Args != nil {
			if db, ok := in.Args["database"].(string); ok {
				ldb := strings.ToLower(db)
				if strings.Contains(ldb, "prod") || strings.Contains(ldb, "secret") {
					return "db:sensitive_database", true
				}
			}
		}
	case "k8s":
		res := strings.ToLower(in.Resource)
		if in.Args != nil {
			if r, ok := in.Args["resource"].(string); ok && r != "" {
				res = strings.ToLower(r)
			}
		}
		if strings.Contains(res, "secret") {
			return "k8s:secret_read", true
		}
	case "docker":
		target := strings.ToLower(in.Resource)
		if target == "" && in.Args != nil {
			if c, ok := in.Args["container"].(string); ok {
				target = strings.ToLower(c)
			}
		}
		if strings.Contains(target, "teknikalidnew-db-1") || strings.Contains(target, "prod") || strings.Contains(target, "db-1") {
			return "docker:protected_container", true
		}
		if in.Args != nil {
			for _, v := range in.Args {
				if s, ok := v.(string); ok {
					ls := strings.ToLower(s)
					if strings.Contains(ls, "teknikalidnew-db-1") || strings.Contains(ls, "prod") {
						return "docker:protected_container", true
					}
				}
			}
		}
	case "llm":
		// Prompt besar TIDAK otomatis sensitif: agent mengirim system prompt puluhan KB
		// secara rutin; ukuran sendiri bukan indikasi exfiltration. Sesi hanya ditandai
		// bila konten memuat penanda rahasia nyata (kredensial/kunci privat).
		if llmPromptContainsSecret(in.Prompt) {
			return "llm:secret_in_prompt", true
		}
		for _, m := range in.Messages {
			if content, ok := m["content"].(string); ok && llmPromptContainsSecret(content) {
				return "llm:secret_in_prompt", true
			}
		}
	case "tool":
		if in.Args != nil {
			for _, v := range in.Args {
				if s, ok := v.(string); ok {
					if credPatternRegex.MatchString(s) {
						return "tool:credential_harvest", true
					}
					if strings.Contains(s, ">") || strings.Contains(s, "/tmp/") || strings.Contains(s, "/var/tmp/") || strings.Contains(s, "/dev/shm/") {
						return "tool:staged_script_write", true
					}
				}
			}
		}
	}
	return "", false
}

// IsEgressAttempt determines if a request is attempting to exfiltrate data or write externally.
func IsEgressAttempt(in Input) bool {
	switch in.Stage {
	case "http":
		method := strings.ToUpper(in.Action)
		if method == "" && in.Args != nil {
			if m, ok := in.Args["method"].(string); ok {
				method = strings.ToUpper(m)
			}
		}
		if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" {
			if !isNonPublicHost(in.Host, in.Resource) {
				return true
			}
		}
	case "tool":
		tc := strings.ToLower(in.ToolCall)
		if strings.Contains(tc, "write") || strings.Contains(tc, "save") || strings.Contains(tc, "upload") || strings.Contains(tc, "send") {
			return true
		}
		if in.Args != nil {
			for _, k := range []string{"cmd", "command", "script", "exec", "argv"} {
				if v, ok := in.Args[k]; ok {
					if s, ok := v.(string); ok && egressCmdRegex.MatchString(s) {
						return true
					}
				}
			}
		}
	case "ssh":
		return true
	case "db":
		act := strings.ToLower(in.Action)
		if act == "write" || act == "insert" || act == "update" || act == "delete" || act == "copy" {
			return true
		}
		var sql string
		if in.Args != nil {
			if s, ok := in.Args["sql"].(string); ok {
				sql = s
			} else if s, ok := in.Args["query"].(string); ok {
				sql = s
			}
		}
		if sql == "" {
			sql = in.Resource
		}
		if writeSQLRegex.MatchString(sql) || (strings.Contains(strings.ToLower(sql), "copy") && strings.Contains(strings.ToLower(sql), "to")) {
			return true
		}
	case "k8s":
		verb := strings.ToLower(in.Action)
		if in.Args != nil {
			if v, ok := in.Args["verb"].(string); ok && v != "" {
				verb = strings.ToLower(v)
			}
		}
		if verb == "exec" || verb == "attach" || verb == "port-forward" || verb == "run" {
			return true
		}
	case "llm":
		return true
	}
	return false
}
