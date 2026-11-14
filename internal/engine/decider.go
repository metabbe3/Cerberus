package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Decider evaluates policy decisions for gateway requests.
// Implemented in-process by *Engine and remotely by *HTTPDecider.
type Decider interface {
	Decide(ctx context.Context, in Input) Decision
}

// HTTPDecider delegates decision-making to a remote Cerberus engine HTTP server (POST /v1/decide).
type HTTPDecider struct {
	client   *http.Client
	url      string
	adminTok string
}

// NewHTTPDecider constructs an HTTPDecider with persistent connection pooling and fail-closed timeout.
func NewHTTPDecider(engineURL, adminToken string) *HTTPDecider {
	tr := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	return &HTTPDecider{
		client: &http.Client{
			Transport: tr,
			Timeout:   2 * time.Second,
		},
		url:      strings.TrimRight(engineURL, "/"),
		adminTok: adminToken,
	}
}

// Decide calls POST /v1/decide on the remote engine and returns the decision.
// Any connection failure, timeout, non-200 HTTP code, or invalid response returns
// a fail-closed deny decision with rule_id "proxy.engine_unreachable".
func (h *HTTPDecider) Decide(ctx context.Context, in Input) Decision {
	body, err := json.Marshal(in)
	if err != nil {
		return Decision{
			Decision: "deny",
			RuleID:   "proxy.marshal_error",
			Reason:   err.Error(),
		}
	}

	endpoint := h.url + "/v1/decide"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Decision{
			Decision: "deny",
			RuleID:   "proxy.engine_unreachable",
			Reason:   err.Error(),
		}
	}
	req.Header.Set("Content-Type", "application/json")
	if h.adminTok != "" {
		req.Header.Set("Authorization", "Bearer "+h.adminTok)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return Decision{
			Decision: "deny",
			RuleID:   "proxy.engine_unreachable",
			Reason:   fmt.Sprintf("engine unreachable: %v", err),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Decision{
			Decision: "deny",
			RuleID:   "proxy.engine_unreachable",
			Reason:   fmt.Sprintf("engine returned status %d", resp.StatusCode),
		}
	}

	var d Decision
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return Decision{
			Decision: "deny",
			RuleID:   "proxy.engine_unreachable",
			Reason:   fmt.Sprintf("decode engine response: %v", err),
		}
	}
	if d.Decision == "" {
		d.Decision = "deny"
		d.RuleID = "proxy.engine_unreachable"
		d.Reason = "empty decision from engine"
	}
	return d
}
