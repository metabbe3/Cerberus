// Package proxy implements enforcer proxies for Cerberus: a Docker socket-proxy
// gating Docker Engine API requests before forwarding to the real Docker daemon,
// and an HTTP egress proxy gating outgoing traffic.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/ratelimit"
	"github.com/metabbe3/cerberus/internal/util"
)

var (
	apiVersionRegex  = regexp.MustCompile(`^/v\d+\.\d+`)
	containerSubpath = regexp.MustCompile(`^/containers/([^/]+)(?:/(.+))?$`)
	imageSubpath     = regexp.MustCompile(`^/images/([^/]+)(?:/(.+))?$`)
	execSubpath      = regexp.MustCompile(`^/exec/([^/]+)(?:/(.+))?$`)
)

func stripAPIVersion(path string) string {
	if strings.HasPrefix(path, "/v") {
		if loc := apiVersionRegex.FindStringIndex(path); loc != nil && loc[0] == 0 {
			return path[loc[1]:]
		}
	}
	return path
}

// ContainerLabelResolver resolves the cerberus.policy-key label for a container.
type ContainerLabelResolver func(ctx context.Context, containerID string) (string, error)

// DockerConfig holds configuration for the Docker socket-proxy.
type DockerConfig struct {
	// TargetURL is the Docker daemon address, e.g. unix:///var/run/docker.sock or http://127.0.0.1:2375.
	TargetURL *url.URL
	// FallbackKeyID is used when no key is specified via header, query, or container label.
	FallbackKeyID string
	// LabelResolver resolves container labels. If nil, defaultResolver is used when TargetURL is set.
	LabelResolver ContainerLabelResolver
	Limiter       *ratelimit.Limiter
	Audit         *audit.Logger
}

// DockerProxy intercepts Docker Engine API calls and evaluates them against the
// Cerberus engine's docker stage.
type DockerProxy struct {
	engine       *engine.Engine
	cfg          DockerConfig
	reverseProxy *httputil.ReverseProxy
	labelCache   sync.Map // containerID -> cachedLabel
	client       *http.Client
}

type cachedLabel struct {
	keyID     string
	expiresAt time.Time
}

// NewDockerProxy constructs a Docker socket-proxy handler.
func NewDockerProxy(eng *engine.Engine, cfg DockerConfig) (*DockerProxy, error) {
	if eng == nil {
		return nil, fmt.Errorf("proxy: nil engine")
	}
	if cfg.TargetURL == nil {
		var err error
		cfg.TargetURL, err = url.Parse("unix:///var/run/docker.sock")
		if err != nil {
			return nil, fmt.Errorf("proxy: parse default target url: %w", err)
		}
	}

	transport := &http.Transport{
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: true,
	}

	isUnix := cfg.TargetURL.Scheme == "unix"
	socketPath := cfg.TargetURL.Path
	if isUnix {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		}
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			if isUnix {
				req.URL.Scheme = "http"
				req.URL.Host = "docker"
			} else {
				req.URL.Scheme = cfg.TargetURL.Scheme
				req.URL.Host = cfg.TargetURL.Host
			}
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "docker daemon unreachable",
				"rule_id": "proxy.docker.bad_gateway",
				"reason":  err.Error(),
			})
		},
	}

	dp := &DockerProxy{
		engine:       eng,
		cfg:          cfg,
		reverseProxy: rp,
		client: &http.Client{
			Transport: transport,
			Timeout:   2 * time.Second,
		},
	}
	return dp, nil
}

// ServeHTTP implements http.Handler.
func (p *DockerProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	input, err := p.parseRequest(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "bad request",
			"rule_id": "proxy.docker.bad_request",
			"reason":  err.Error(),
		})
		return
	}

	if p.cfg.Limiter != nil {
		v := p.cfg.Limiter.Allow(r.Context(), input.KeyID, "docker")
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
					Stage:    "docker",
					KeyID:    input.KeyID,
					Subject:  input.Resource,
					Decision: "deny",
					RuleID:   v.RuleID,
					Reason:   v.Reason,
				})
			}
			return
		}
	}

	decision := p.engine.Decide(r.Context(), input)
	if !decision.Allowed() {
		util.WriteForbidden(w, decision.RuleID, decision.Reason)
		return
	}

	p.reverseProxy.ServeHTTP(w, r)
}

func (p *DockerProxy) parseRequest(r *http.Request) (engine.Input, error) {
	cleanPath := stripAPIVersion(r.URL.Path)
	if cleanPath == "" {
		cleanPath = "/"
	}

	var bodyBytes []byte
	var bodyMap map[string]any
	if r.Body != nil && r.ContentLength != 0 {
		var err error
		bodyBytes, err = io.ReadAll(http.MaxBytesReader(nil, r.Body, 1<<20))
		if err != nil && err != io.EOF {
			return engine.Input{}, fmt.Errorf("read body: %w", err)
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		if len(bodyBytes) > 0 {
			_ = json.Unmarshal(bodyBytes, &bodyMap)
		}
	}

	action := strings.ToLower(r.Method)
	resource := ""
	args := make(map[string]any, 4)

	// Container endpoints: /containers/{id}/start, /containers/{id}/stop, etc.
	if m := containerSubpath.FindStringSubmatch(cleanPath); len(m) > 1 {
		id := m[1]
		sub := ""
		if len(m) > 2 {
			sub = m[2]
		}
		if id == "create" {
			action = "create"
			if bodyMap != nil {
				if img, ok := bodyMap["Image"].(string); ok {
					resource = img
				}
				p.extractHostConfig(bodyMap, args)
			}
			if resource == "" {
				resource = r.URL.Query().Get("name")
			}
		} else {
			resource = id
			switch sub {
			case "start":
				action = "start"
			case "stop":
				action = "stop"
			case "restart":
				action = "restart"
			case "kill":
				action = "kill"
			case "rm":
				action = "rm"
			case "exec":
				action = "exec_create"
				p.extractExecArgs(bodyMap, args)
			case "attach":
				action = "attach"
			default:
				if r.Method == http.MethodDelete && sub == "" {
					action = "rm"
				} else if sub != "" {
					action = sub
				}
			}
		}
	} else if m := imageSubpath.FindStringSubmatch(cleanPath); len(m) > 1 {
		id := m[1]
		resource = id
		if r.Method == http.MethodDelete {
			action = "image_delete"
		} else if id == "create" {
			action = "pull"
			resource = r.URL.Query().Get("fromImage")
		}
	} else if cleanPath == "/exec" && r.Method == http.MethodPost {
		action = "exec_create"
		if bodyMap != nil {
			if c, ok := bodyMap["Container"].(string); ok {
				resource = c
			}
			p.extractExecArgs(bodyMap, args)
		}
	} else if m := execSubpath.FindStringSubmatch(cleanPath); len(m) > 1 {
		resource = m[1]
		sub := ""
		if len(m) > 2 {
			sub = m[2]
		}
		if sub == "start" {
			action = "exec_start"
		} else {
			action = "exec"
		}
	}

	keyID := p.resolveKey(r, resource)

	return engine.Input{
		Stage:    "docker",
		KeyID:    keyID,
		Action:   action,
		Resource: resource,
		Args:     args,
	}, nil
}

func (p *DockerProxy) extractHostConfig(body map[string]any, args map[string]any) {
	if body == nil {
		return
	}
	var mounts []any
	var binds []any
	var capAdd []any
	var privileged any

	if hc, ok := body["HostConfig"].(map[string]any); ok {
		if b, ok := hc["Binds"].([]any); ok {
			binds = append(binds, b...)
			mounts = append(mounts, b...)
		}
		if m, ok := hc["Mounts"].([]any); ok {
			mounts = append(mounts, m...)
		}
		if ca, ok := hc["CapAdd"].([]any); ok {
			capAdd = append(capAdd, ca...)
		}
		if priv, ok := hc["Privileged"]; ok {
			privileged = priv
		}
	}

	if b, ok := body["Binds"].([]any); ok {
		binds = append(binds, b...)
		mounts = append(mounts, b...)
	}
	if v, ok := body["Volumes"].([]any); ok {
		mounts = append(mounts, v...)
	}
	if ca, ok := body["CapAdd"].([]any); ok {
		capAdd = append(capAdd, ca...)
	}
	if priv, ok := body["Privileged"]; ok {
		privileged = priv
	}

	if len(mounts) > 0 {
		args["mounts"] = mounts
	}
	if len(binds) > 0 {
		args["binds"] = binds
	}
	if len(capAdd) > 0 {
		args["cap_add"] = capAdd
	}
	if privileged != nil {
		args["privileged"] = privileged
	}
}

func (p *DockerProxy) extractExecArgs(body map[string]any, args map[string]any) {
	if body == nil {
		return
	}
	p.extractHostConfig(body, args)
	if cmd, ok := body["Cmd"]; ok {
		args["cmd"] = cmd
	}
	if priv, ok := body["Privileged"]; ok {
		args["privileged"] = priv
	}
	if mounts, ok := body["Mounts"].([]any); ok {
		args["mounts"] = mounts
	}
}

func (p *DockerProxy) resolveKey(r *http.Request, containerID string) string {
	if k := util.ResolveKey(r); k != "" {
		return k
	}

	// Container label lookup
	if containerID != "" && containerID != "create" {
		if val, ok := p.labelCache.Load(containerID); ok {
			cl := val.(cachedLabel)
			if time.Now().Before(cl.expiresAt) && cl.keyID != "" {
				return cl.keyID
			}
		}
		if p.cfg.LabelResolver != nil {
			if k, err := p.cfg.LabelResolver(r.Context(), containerID); err == nil && k != "" {
				p.labelCache.Store(containerID, cachedLabel{keyID: k, expiresAt: time.Now().Add(60 * time.Second)})
				return k
			}
		} else if p.client != nil {
			if k, err := p.fetchContainerLabel(r.Context(), containerID); err == nil && k != "" {
				p.labelCache.Store(containerID, cachedLabel{keyID: k, expiresAt: time.Now().Add(60 * time.Second)})
				return k
			}
		}
	}

	// 4. Fallback key ID
	return p.cfg.FallbackKeyID
}

func (p *DockerProxy) fetchContainerLabel(ctx context.Context, containerID string) (string, error) {
	reqURL := fmt.Sprintf("http://docker/containers/%s/json", containerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status: %d", resp.StatusCode)
	}

	var data struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Config.Labels["cerberus.policy-key"], nil
}
