package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/ratelimit"
	"github.com/metabbe3/cerberus/internal/util"
)

// DefaultTunnelIdleTimeout is the watchdog timeout for hijacked CONNECT tunnels.
const DefaultTunnelIdleTimeout = 5 * time.Minute

// EgressConfig holds options for the HTTP/HTTPS egress proxy.
type EgressConfig struct {
	// DenyLocalIPs blocks loopback/private/link-local/multicast/unspecified
	// destination IPs at the dial Control hook (OS-level). Default TRUE when
	// nil — tests that dial 127.0.0.1 backends must set it to false.
	DenyLocalIPs      *bool
	FallbackKeyID     string
	DialTimeout       time.Duration
	TunnelIdleTimeout time.Duration
	// LookupIP overrides DNS lookup; defaults to net.LookupIP.
	LookupIP func(host string) ([]net.IP, error)
	Limiter  *ratelimit.Limiter
	Audit    *audit.Logger
}

// EgressProxy inspects all outbound HTTP and HTTPS (via CONNECT) traffic,
// evaluating destination hosts against stage http and PROD SHIELD CIDRs.
type EgressProxy struct {
	engine      engine.Decider
	cfg         EgressConfig
	transport   *http.Transport
	dialControl func(network, address string, c syscall.RawConn) error
}

// NewEgressProxy constructs an EgressProxy handler.
func NewEgressProxy(eng engine.Decider, cfg EgressConfig) (*EgressProxy, error) {
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
func DenyHostIP(ctx context.Context, eng engine.Decider, ipStr string) error {
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

	idleTimeout := p.cfg.TunnelIdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = DefaultTunnelIdleTimeout
	}

	ctx := r.Context()
	stopWatcher := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = clientConn.Close()
			_ = targetConn.Close()
		case <-stopWatcher:
		}
	}()
	defer close(stopWatcher)

	// Bidirectional full-duplex tunnel with activity watchdog
	var wg sync.WaitGroup
	wg.Add(2)

	copyHalf := func(dst io.Writer, src io.Reader, readConn, writeConn net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			_ = readConn.SetDeadline(time.Now().Add(idleTimeout))
			n, err := src.Read(buf)
			if n > 0 {
				_ = readConn.SetDeadline(time.Now().Add(idleTimeout))
				_ = writeConn.SetDeadline(time.Now().Add(idleTimeout))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else if tc, ok := writeConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		_ = readConn.Close()
		_ = writeConn.Close()
	}

	go copyHalf(targetConn, bufrw, clientConn, targetConn)
	go copyHalf(clientConn, targetConn, targetConn, clientConn)

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

	// Buffer body if present for potential redirect replay
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, err = io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	const maxRedirects = 5

	client := &http.Client{
		Transport: p.transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	currentURL := destURL
	currentMethod := r.Method
	currentBody := bodyBytes

	currentHeaders := r.Header.Clone()
	currentHeaders.Del("Proxy-Authorization")
	currentHeaders.Del("Proxy-Connection")

	for redirectCount := 0; redirectCount <= maxRedirects; redirectCount++ {
		var bodyReader io.Reader
		if currentBody != nil {
			bodyReader = bytes.NewReader(currentBody)
		}

		outReq, err := http.NewRequestWithContext(r.Context(), currentMethod, currentURL, bodyReader) //nolint:gosec // G704: currentURL re-validated via engine decide each redirect hop
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		copyHeaders(outReq.Header, currentHeaders)

		parsedCurURL, parseErr := url.Parse(currentURL)
		if parseErr == nil && parsedCurURL.Host != "" {
			outReq.Host = parsedCurURL.Host
		}

		resp, err := client.Do(outReq) //nolint:gosec // G704: currentURL re-validated via engine decide each redirect hop
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

		// Check if redirect
		isRedirect := (resp.StatusCode == http.StatusMovedPermanently ||
			resp.StatusCode == http.StatusFound ||
			resp.StatusCode == http.StatusSeeOther ||
			resp.StatusCode == http.StatusTemporaryRedirect ||
			resp.StatusCode == http.StatusPermanentRedirect)

		loc := resp.Header.Get("Location")
		if !isRedirect || loc == "" {
			defer func() { _ = resp.Body.Close() }()
			copyHeaders(w.Header(), resp.Header)
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
			return
		}

		// Response is a redirect: clean up body before proceeding
		_ = resp.Body.Close()

		if redirectCount == maxRedirects {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "too many redirects",
				"rule_id": "proxy.egress.too_many_redirects",
				"reason":  "maximum redirect limit (5) exceeded",
			})
			return
		}

		locURL, err := url.Parse(loc)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "invalid redirect location",
				"rule_id": "proxy.egress.invalid_redirect",
				"reason":  err.Error(),
			})
			return
		}
		nextURL := parsedCurURL.ResolveReference(locURL)

		if nextURL.Scheme != "http" && nextURL.Scheme != "https" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "unsupported redirect scheme",
				"rule_id": "proxy.egress.unsupported_scheme",
				"reason":  fmt.Sprintf("scheme %q is not supported", nextURL.Scheme),
			})
			return
		}

		// RFC 7231 / RFC 9110 method semantics
		if resp.StatusCode == http.StatusSeeOther {
			if currentMethod != http.MethodHead {
				currentMethod = http.MethodGet
			}
			currentBody = nil
		} else if (resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound) && currentMethod == http.MethodPost {
			currentMethod = http.MethodGet
			currentBody = nil
		}

		// Strip Authorization header if redirecting across different hosts
		if !strings.EqualFold(parsedCurURL.Host, nextURL.Host) {
			currentHeaders.Del("Authorization")
		}

		// Evaluate redirect destination hop
		nextHostOnly, nextPort, err := util.ExtractHost(nextURL.Host)
		if err != nil || nextHostOnly == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "invalid redirect host",
				"rule_id": "proxy.egress.invalid_redirect_host",
				"reason":  fmt.Sprintf("cannot extract host from redirect URL %q", nextURL.String()),
			})
			return
		}
		if nextPort == "443" && !strings.Contains(nextURL.Host, ":") {
			if nextURL.Scheme == "http" {
				nextPort = "80"
			}
		}

		hopIn := engine.Input{
			Stage:    "http",
			KeyID:    keyID,
			Action:   currentMethod,
			Resource: nextURL.String(),
			Args: map[string]any{
				"method": currentMethod,
				"host":   nextHostOnly,
				"port":   nextPort,
				"path":   nextURL.Path,
			},
		}
		hopDec := p.engine.Decide(r.Context(), hopIn)
		if !hopDec.Allowed() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"decision": "deny",
				"error":    "egress redirect denied",
				"rule_id":  hopDec.RuleID,
				"reason":   hopDec.Reason,
			})
			if p.cfg.Audit != nil {
				p.cfg.Audit.Emit(audit.Event{
					Time:     time.Now(),
					Stage:    "http",
					KeyID:    keyID,
					Subject:  nextHostOnly,
					Decision: "deny",
					RuleID:   hopDec.RuleID,
					Reason:   hopDec.Reason,
				})
			}
			return
		}

		// Pre-check IP: if host is not a raw IP, resolve and check each IP against prod shield
		if net.ParseIP(nextHostOnly) == nil && p.cfg.LookupIP != nil {
			if ips, err := p.cfg.LookupIP(nextHostOnly); err == nil {
				for _, ip := range ips {
					ipIn := engine.Input{
						Stage:    "http",
						KeyID:    keyID,
						Action:   currentMethod,
						Resource: net.JoinHostPort(ip.String(), nextPort),
						Args: map[string]any{
							"method": currentMethod,
							"host":   ip.String(),
							"port":   nextPort,
							"path":   nextURL.Path,
						},
					}
					ipDec := p.engine.Decide(r.Context(), ipIn)
					if strings.HasPrefix(ipDec.RuleID, "shield.prod.") {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusBadGateway)
						_ = json.NewEncoder(w).Encode(map[string]any{
							"decision": "deny",
							"error":    "egress redirect denied",
							"rule_id":  ipDec.RuleID,
							"reason":   ipDec.Reason,
						})
						if p.cfg.Audit != nil {
							p.cfg.Audit.Emit(audit.Event{
								Time:     time.Now(),
								Stage:    "http",
								KeyID:    keyID,
								Subject:  ip.String(),
								Decision: "deny",
								RuleID:   ipDec.RuleID,
								Reason:   ipDec.Reason,
							})
						}
						return
					}
				}
			}
		}

		currentURL = nextURL.String()
	}
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
