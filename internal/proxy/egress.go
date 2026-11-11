package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/ratelimit"
)

// EgressConfig holds options for the HTTP/HTTPS egress proxy.
type EgressConfig struct {
	FallbackKeyID string
	DialTimeout   time.Duration
	// LookupIP overrides DNS lookup; defaults to net.LookupIP.
	LookupIP func(host string) ([]net.IP, error)
	Limiter  *ratelimit.Limiter
	Audit    *audit.Logger
}

// EgressProxy inspects all outbound HTTP and HTTPS (via CONNECT) traffic,
// evaluating destination hosts against stage http and PROD SHIELD CIDRs.
type EgressProxy struct {
	engine    *engine.Engine
	cfg       EgressConfig
	transport *http.Transport
}

// NewEgressProxy constructs an EgressProxy handler.
func NewEgressProxy(eng *engine.Engine, cfg EgressConfig) (*EgressProxy, error) {
	if eng == nil {
		return nil, fmt.Errorf("proxy: nil engine")
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	if cfg.LookupIP == nil {
		cfg.LookupIP = net.LookupIP
	}

	tr := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression: false,
	}

	return &EgressProxy{
		engine:    eng,
		cfg:       cfg,
		transport: tr,
	}, nil
}

// ServeHTTP handles both forward HTTP requests and HTTPS CONNECT tunnels.
func (p *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	keyID := p.resolveKey(r)
	if p.cfg.Limiter != nil {
		v := p.cfg.Limiter.Allow(r.Context(), keyID, "http")
		if !v.Allowed {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", v.RetryAfter))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"decision":    "deny",
				"error":       "rate limit exceeded",
				"rule_id":     v.RuleID,
				"reason":      v.Reason,
				"retry_after": v.RetryAfter,
			})
			if p.cfg.Audit != nil {
				p.cfg.Audit.Emit(audit.Event{
					Time:     time.Now(),
					Stage:    "http",
					KeyID:    keyID,
					Subject:  r.Host,
					Decision: "deny",
					RuleID:   v.RuleID,
					Reason:   v.Reason,
				})
			}
			return
		}
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *EgressProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	hostOnly, port, err := net.SplitHostPort(host)
	if err != nil {
		hostOnly = host
		port = "443"
	}

	keyID := p.resolveKey(r)

	// 1. Evaluate stage http on destination host
	in := engine.Input{
		Stage:    "http",
		KeyID:    keyID,
		Action:   "CONNECT",
		Resource: host,
		Args: map[string]any{
			"method": "CONNECT",
			"host":   hostOnly,
			"port":   port,
		},
	}
	dec := p.engine.Decide(r.Context(), in)
	if !dec.Allowed() {
		p.writeForbidden(w, dec)
		return
	}

	// 2. DNS check: if host is not a raw IP, resolve and check each IP against prod shield
	if net.ParseIP(hostOnly) == nil && p.cfg.LookupIP != nil {
		if ips, err := p.cfg.LookupIP(hostOnly); err == nil {
			for _, ip := range ips {
				ipIn := engine.Input{
					Stage:    "http",
					KeyID:    keyID,
					Action:   "CONNECT",
					Resource: ip.String(),
					Args: map[string]any{
						"method": "CONNECT",
						"host":   ip.String(),
						"port":   port,
					},
				}
				ipDec := p.engine.Decide(r.Context(), ipIn)
				if !ipDec.Allowed() {
					p.writeForbidden(w, ipDec)
					return
				}
			}
		}
	}

	// 3. Dial target host
	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(hostOnly, port), p.cfg.DialTimeout)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "egress dial failed",
			"rule_id": "proxy.egress.dial_failed",
			"reason":  err.Error(),
		})
		return
	}
	defer func() { _ = targetConn.Close() }()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, bufrw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func() { _ = clientConn.Close() }()

	// Send 200 Connection Established
	_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = bufrw.Flush()

	// Bidirectional full-duplex tunnel
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, bufrw)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, targetConn)
		if cc, ok := clientConn.(*net.TCPConn); ok {
			_ = cc.CloseWrite()
		}
	}()

	wg.Wait()
}

func (p *EgressProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	destURL := r.URL.String()
	if !strings.HasPrefix(destURL, "http://") && !strings.HasPrefix(destURL, "https://") {
		destURL = "http://" + r.Host + r.URL.RequestURI()
	}

	keyID := p.resolveKey(r)

	in := engine.Input{
		Stage:    "http",
		KeyID:    keyID,
		Action:   r.Method,
		Resource: destURL,
		Args: map[string]any{
			"method": r.Method,
			"host":   r.Host,
			"path":   r.URL.Path,
		},
	}
	dec := p.engine.Decide(r.Context(), in)
	if !dec.Allowed() {
		p.writeForbidden(w, dec)
		return
	}

	// Forward plain HTTP
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, destURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	copyHeaders(outReq.Header, r.Header)
	// Strip hop-by-hop headers
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Del("Proxy-Connection")

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "egress roundtrip failed",
			"rule_id": "proxy.egress.bad_gateway",
			"reason":  err.Error(),
		})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *EgressProxy) writeForbidden(w http.ResponseWriter, dec engine.Decision) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   "forbidden by policy",
		"rule_id": dec.RuleID,
		"reason":  dec.Reason,
	})
}

func (p *EgressProxy) resolveKey(r *http.Request) string {
	if k := r.Header.Get("X-Cerberus-Key"); k != "" {
		return k
	}
	if k := r.Header.Get("X-Policy-Key"); k != "" {
		return k
	}
	if auth := r.Header.Get("Proxy-Authorization"); auth != "" {
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
	}
	return p.cfg.FallbackKeyID
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
