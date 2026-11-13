package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/ratelimit"
	"github.com/metabbe3/cerberus/internal/util"
)

// EgressConfig holds options for the HTTP/HTTPS egress proxy.
type EgressConfig struct {
	// DenyLocalIPs blocks loopback/private/link-local/multicast/unspecified
	// destination IPs at the dial Control hook (OS-level). Default TRUE when
	// nil — tests that dial 127.0.0.1 backends must set it to false.
	DenyLocalIPs  *bool
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
	engine      *engine.Engine
	cfg         EgressConfig
	transport   *http.Transport
	dialControl func(network, address string, c syscall.RawConn) error
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
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: false,
	}

	// DNS-rebinding (TOCTOU) guard: the pre-check resolves the host and
	// evaluates policy, but a second resolver run at dial time could return a
	// different IP (TTL=0 rebind to 127.0.0.1 / 169.254.169.254 / prod CIDR).
	// The Control hook sees the ACTUAL connection IP — validate it there,
	// post-resolution, pre-handshake. Both the forward transport and the
	// CONNECT tunnel dialer share this guard.
	denyLocal := true
	if cfg.DenyLocalIPs != nil {
		denyLocal = *cfg.DenyLocalIPs
	}
	control := func(_, address string, _ syscall.RawConn) error { //nolint:revive
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		ipStr := NormalizeIPString(host)
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("egress: unparseable dial address %q", address)
		}
		if denyLocal && IsLocalIP(ip) {
			return fmt.Errorf("egress blocked: connection to private/internal IP disallowed (%s)", ipStr)
		}
		return DenyHostIP(context.Background(), eng, ipStr)
	}
	tr.DialContext = (&net.Dialer{
		Timeout: cfg.DialTimeout,
		Control: control,
	}).DialContext

	return &EgressProxy{
		engine:      eng,
		cfg:         cfg,
		transport:   tr,
		dialControl: control,
	}, nil
}

// DenyHostIP evaluates shield policy against a concrete post-resolution IP.
// Used by the dial Control hook — any deny verdict aborts the connection
// before the TCP handshake completes.
func DenyHostIP(ctx context.Context, eng *engine.Engine, ipStr string) error {
	ipStr = NormalizeIPString(ipStr)
	ipIn := engine.Input{
		Stage:    "http",
		KeyID:    "egress-dial-guard",
		Action:   "DIAL",
		Resource: ipStr,
		Args: map[string]any{
			"method": "DIAL",
			"host":   ipStr,
		},
	}
	dec := eng.Decide(ctx, ipIn)
	if !dec.Allowed() {
		return fmt.Errorf("egress: %s blocked: %s", ipStr, dec.RuleID)
	}
	return nil
}

// IsLocalIP reports whether an IP is loopback, private, link-local,
// multicast, or unspecified (0.0.0.0/::) — never valid egress targets.
func IsLocalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// NormalizeIPString unwraps IPv4-mapped IPv6 ("::ffff:10.0.0.1" → "10.0.0.1")
// so CIDR checks always see the embedded v4 address.
func NormalizeIPString(host string) string {
	h := strings.Trim(host, "[]")
	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return h
}

// ServeHTTP handles both forward HTTP requests and HTTPS CONNECT tunnels.
func (p *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := util.ValidateRequest(r); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "bad request",
			"rule_id": "proxy.egress.malformed_request",
			"reason":  err.Error(),
		})
		return
	}

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
	keyID := p.resolveKey(r)

	// Collect targets from both RequestURI/URL.Host and Host header
	urlHost := r.URL.Host
	if (urlHost == "http:" || urlHost == "https:") && strings.HasPrefix(r.URL.Path, "//") {
		urlHost = strings.TrimPrefix(r.URL.Path, "//")
	}
	targets := make([]string, 0, 2)
	if urlHost != "" {
		targets = append(targets, urlHost)
	}
	if r.Host != "" && r.Host != urlHost {
		targets = append(targets, r.Host)
	}
	if len(targets) == 0 {
		http.Error(w, "missing host in CONNECT request", http.StatusBadRequest)
		return
	}

	for _, target := range targets {
		hostOnly, port, err := util.ExtractHost(target)
		if err != nil || hostOnly == "" {
			http.Error(w, "invalid host or port in CONNECT request", http.StatusBadRequest)
			return
		}

		// 1. Evaluate stage http on destination host
		in := engine.Input{
			Stage:    "http",
			KeyID:    keyID,
			Action:   "CONNECT",
			Resource: target,
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
						Resource: net.JoinHostPort(ip.String(), port),
						Args: map[string]any{
							"method": "CONNECT",
							"host":   ip.String(),
							"port":   port,
						},
					}
					ipDec := p.engine.Decide(r.Context(), ipIn)
					if strings.HasPrefix(ipDec.RuleID, "shield.prod.") {
						p.writeForbidden(w, ipDec)
						return
					}
				}
			}
		}
	}

	// 3. Dial target host (prefer explicit URL.Host if set, otherwise r.Host)
	dialTarget := urlHost
	if dialTarget == "" {
		dialTarget = r.Host
	}
	dialHost, dialPort, err := util.ExtractHost(dialTarget)
	if err != nil || dialHost == "" {
		http.Error(w, "invalid host or port in CONNECT request", http.StatusBadRequest)
		return
	}

	dialer := &net.Dialer{Timeout: p.cfg.DialTimeout}
	if p.dialControl != nil {
		dialer.Control = p.dialControl
	}
	targetConn, err := dialer.Dial("tcp", net.JoinHostPort(dialHost, dialPort))
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
	hostOnly, port, err := util.ExtractHost(r.Host)
	if err != nil || hostOnly == "" {
		http.Error(w, "invalid host or port", http.StatusBadRequest)
		return
	}
	if port == "443" && !strings.Contains(r.Host, ":") {
		if r.URL.Scheme == "http" || strings.HasPrefix(destURL, "http://") {
			port = "80"
		}
	}

	in := engine.Input{
		Stage:    "http",
		KeyID:    keyID,
		Action:   r.Method,
		Resource: destURL,
		Args: map[string]any{
			"method": r.Method,
			"host":   hostOnly,
			"port":   port,
			"path":   r.URL.Path,
		},
	}
	dec := p.engine.Decide(r.Context(), in)
	if !dec.Allowed() {
		p.writeForbidden(w, dec)
		return
	}

	// DNS check: if host is not a raw IP, resolve and check each IP against prod shield
	if net.ParseIP(hostOnly) == nil && p.cfg.LookupIP != nil {
		if ips, err := p.cfg.LookupIP(hostOnly); err == nil {
			for _, ip := range ips {
				ipIn := engine.Input{
					Stage:    "http",
					KeyID:    keyID,
					Action:   r.Method,
					Resource: net.JoinHostPort(ip.String(), port),
					Args: map[string]any{
						"method": r.Method,
						"host":   ip.String(),
						"port":   port,
						"path":   r.URL.Path,
					},
				}
				ipDec := p.engine.Decide(r.Context(), ipIn)
				if strings.HasPrefix(ipDec.RuleID, "shield.prod.") {
					p.writeForbidden(w, ipDec)
					return
				}
			}
		}
	}

	// Forward plain HTTP
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, destURL, r.Body) //nolint:gosec // G704 dial guarded by SecureDialer allowlist
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
	util.WriteForbidden(w, dec.RuleID, dec.Reason)
}

func (p *EgressProxy) resolveKey(r *http.Request) string {
	if k := util.ResolveKey(r); k != "" {
		return k
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
