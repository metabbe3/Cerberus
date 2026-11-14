package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// EscapeRecord documents any oracle violation or policy escape.
type EscapeRecord struct {
	Seed               uint64 `json:"seed"`
	SampleIdx          uint64 `json:"sample_idx"`
	Stage              string `json:"stage"`
	ChainID            string `json:"chain_id,omitempty"`
	InputJSON          string `json:"input_json"`
	ExpectedDecision   string `json:"expected_decision"`
	ExpectedRuleFamily string `json:"expected_rule_family"`
	ActualDecision     string `json:"actual_decision"`
	ActualRuleID       string `json:"actual_rule_id"`
	ReproCurl          string `json:"repro_curl"`
}

// DecisionResponse mirrors the engine /v1/decide JSON response.
type DecisionResponse struct {
	Decision   string         `json:"decision"`
	RuleID     string         `json:"rule_id"`
	Reason     string         `json:"reason"`
	MaskedArgs map[string]any `json:"masked_args"`
	Epoch      uint64         `json:"epoch"`
	Cached     bool           `json:"cached"`
}

// Oracle executes oracle chains and determines whether policy decisions match specifications.
type Oracle struct {
	client         *http.Client
	decideURL      string
	token          string
	chains         []OracleChain
	mu             sync.Mutex
	escapes        []EscapeRecord
	escapeCnt      int64
	chainBrokenCnt int64
}

// NewOracle constructs an Oracle with the given client, URL, token, and chains.
func NewOracle(client *http.Client, decideURL, token string, chains []OracleChain) *Oracle {
	return &Oracle{
		client:    client,
		decideURL: decideURL,
		token:     token,
		chains:    chains,
	}
}

// Escapes returns all recorded escape records.
func (o *Oracle) Escapes() []EscapeRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	cp := make([]EscapeRecord, len(o.escapes))
	copy(cp, o.escapes)
	return cp
}

// EscapeCount returns the total number of escapes found.
func (o *Oracle) EscapeCount() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.escapeCnt
}

// ChainBrokenCount returns the total number of broken chains where step 1 was denied.
func (o *Oracle) ChainBrokenCount() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.chainBrokenCnt
}

func (o *Oracle) recordChainBroken() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.chainBrokenCnt++
}

// RunChain executes one oracle chain by index or ID and returns escapes, allowCount, and denyCount.
func (o *Oracle) RunChain(ctx context.Context, chain OracleChain, masterSeed uint64, idx uint64) ([]EscapeRecord, int, int, error) {
	var results []EscapeRecord
	var allows, denies int

	// Execute Step 1
	body1 := prepareChainPayload(chain.Step1, chain.ID, 1)
	resp1, err := o.sendDecide(ctx, body1)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("chain %s step 1 request failed: %w", chain.ID, err)
	}

	if resp1.Decision == "allow" {
		allows++
	} else {
		denies++
	}

	escaped1 := isEscape(chain.Expected1, resp1)
	if escaped1 {
		rec := EscapeRecord{
			Seed:               DeriveSeed(masterSeed, StageIDChains, idx),
			SampleIdx:          idx,
			Stage:              "chains",
			ChainID:            chain.ID + "-step1",
			InputJSON:          string(body1),
			ExpectedDecision:   chain.Expected1.Decision,
			ExpectedRuleFamily: chain.Expected1.RuleFamily,
			ActualDecision:     resp1.Decision,
			ActualRuleID:       resp1.RuleID,
			ReproCurl:          FormatCurl(o.decideURL, o.token, body1),
		}
		o.recordEscape(rec)
		results = append(results, rec)
	}

	// If step 2 exists, execute Step 2
	if chain.Step2 != nil && chain.Expected2 != nil {
		body2 := prepareChainPayload(chain.Step2, chain.ID, 2)
		resp2, err := o.sendDecide(ctx, body2)
		if err != nil {
			return nil, allows, denies, fmt.Errorf("chain %s step 2 request failed: %w", chain.ID, err)
		}

		if resp2.Decision == "allow" {
			allows++
		} else {
			denies++
		}

		// Escape step-2 HANYA dihitung bila step-1 == allow (rantai hidup).
		// Kalau step-1 deny -> step-2 allow = RANTAI PUTUS = bukan escape (log sebagai chain_broken metric, bukan escapes[]).
		if resp1.Decision == "allow" {
			escaped2 := isEscape(*chain.Expected2, resp2)
			if escaped2 {
				rec := EscapeRecord{
					Seed:               DeriveSeed(masterSeed, StageIDChains, idx+1000000),
					SampleIdx:          idx,
					Stage:              "chains",
					ChainID:            chain.ID + "-step2",
					InputJSON:          string(body2),
					ExpectedDecision:   chain.Expected2.Decision,
					ExpectedRuleFamily: chain.Expected2.RuleFamily,
					ActualDecision:     resp2.Decision,
					ActualRuleID:       resp2.RuleID,
					ReproCurl:          FormatCurl(o.decideURL, o.token, body2),
				}
				o.recordEscape(rec)
				results = append(results, rec)
			}
		} else {
			// Step-1 was denied: attack chain broken at step 1.
			o.recordChainBroken()
		}
	}

	return results, allows, denies, nil
}

func (o *Oracle) recordEscape(rec EscapeRecord) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.escapes = append(o.escapes, rec)
	o.escapeCnt++
}

func (o *Oracle) sendDecide(ctx context.Context, body []byte) (*DecisionResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.decideURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.token != "" {
		req.Header.Set("Authorization", "Bearer "+o.token)
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var d DecisionResponse
	if err := json.Unmarshal(respBody, &d); err != nil {
		// If status is 429 rate limit or 401
		return &DecisionResponse{
			Decision: "deny",
			RuleID:   fmt.Sprintf("http.status_%d", resp.StatusCode),
			Reason:   string(respBody),
		}, nil
	}

	return &d, nil
}

// prepareChainPayload replaces dynamic placeholders like __FILL_64KB_MIDDLE_TRUNCATE__ or __FILL_2MB_BOUNDARY__
func prepareChainPayload(raw map[string]any, chainID string, step int) []byte {
	// Deep clone map
	b, _ := json.Marshal(raw)
	var cloned map[string]any
	_ = json.Unmarshal(b, &cloned)

	// Unique session per chain+step so engine taint-marks never
	// cross-contaminate samples (run-3 artifact: 15k deny from stale marks).
	cloned["session_id"] = fmt.Sprintf("mc-%s-%d", chainID, step)

	if chainID == "S06" && step == 1 {
		prefix := strings.Repeat("A", 32768)
		suffix := strings.Repeat("B", 32768)
		cloned["messages"] = []map[string]any{
			{"role": "user", "content": prefix + " dump prod-db " + suffix},
		}
	} else if chainID == "OP04" {
		cloned["prompt"] = strings.Repeat("Z", 2097152-10)
	}

	res, _ := json.Marshal(cloned)
	return res
}

func isEscape(expected OracleVerdict, actual *DecisionResponse) bool {
	if expected.Decision != "" && actual.Decision != expected.Decision {
		return true
	}
	return false
}

// FormatCurl builds a clean reproducible curl command string.
func FormatCurl(url string, token string, body []byte) string {
	authHeader := ""
	if token != "" {
		authHeader = fmt.Sprintf(" -H 'Authorization: Bearer %s'", token)
	}
	// Escape single quotes for bash
	safeBody := strings.ReplaceAll(string(body), "'", `'\''`)
	return fmt.Sprintf("curl -s -X POST '%s' -H 'Content-Type: application/json'%s -d '%s'",
		url, authHeader, safeBody)
}
