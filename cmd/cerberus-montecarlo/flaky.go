package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sort"
	"sync"
)

// FlakyType defines the detection layer that caught the divergence.
type FlakyType string

const (
	FlakyTypeIdempotencyBurst FlakyType = "FLAKY_IDEMPOTENCY_BURST"
	FlakyTypeCanonicalJSON    FlakyType = "FLAKY_CANONICAL_JSON"
	FlakyTypeExplainDiff      FlakyType = "FLAKY_EXPLAIN_DIFF"
)

// FlakyRecord documents non-deterministic or inconsistent verdicts.
type FlakyRecord struct {
	Type      FlakyType `json:"type"`
	Stage     string    `json:"stage"`
	SampleIdx uint64    `json:"sample_idx"`
	Detail    string    `json:"detail"`
	PayloadA  string    `json:"payload_a"`
	PayloadB  string    `json:"payload_b,omitempty"`
	VerdictA  string    `json:"verdict_a"`
	VerdictB  string    `json:"verdict_b,omitempty"`
}

// VerdictTuple captures the essential identity of an engine decision.
type VerdictTuple struct {
	Decision       string
	RuleID         string
	Reason         string
	MaskedArgsHash string
}

// FlakyDetector orchestrates the 3-layer flaky detection checks.
type FlakyDetector struct {
	client        *http.Client
	decideURL     string
	token         string
	explainSample float64
	mu            sync.Mutex
	records       []FlakyRecord
}

// NewFlakyDetector creates a new FlakyDetector.
func NewFlakyDetector(client *http.Client, decideURL, token string, explainSample float64) *FlakyDetector {
	return &FlakyDetector{
		client:        client,
		decideURL:     decideURL,
		token:         token,
		explainSample: explainSample,
	}
}

// Records returns all detected flaky records.
func (f *FlakyDetector) Records() []FlakyRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]FlakyRecord, len(f.records))
	copy(cp, f.records)
	return cp
}

// CheckIdempotencyBurst runs 5 parallel and 5 sequential requests for sample idx % 50 == 0.
func (f *FlakyDetector) CheckIdempotencyBurst(ctx context.Context, stage string, idx uint64, rawBody []byte) error {
	tuples := make([]VerdictTuple, 10)
	var errOnce error

	// 5 Parallel requests
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			vt, err := f.executeAndTuple(ctx, rawBody, false)
			if err != nil {
				errOnce = err
				return
			}
			tuples[slot] = vt
		}(i)
	}
	wg.Wait()

	if errOnce != nil {
		return errOnce
	}

	// 5 Sequential requests
	for i := 5; i < 10; i++ {
		vt, err := f.executeAndTuple(ctx, rawBody, false)
		if err != nil {
			return err
		}
		tuples[i] = vt
	}

	// Verify all 10 tuples match
	baseline := tuples[0]
	for i := 1; i < 10; i++ {
		cur := tuples[i]
		if cur != baseline {
			f.mu.Lock()
			f.records = append(f.records, FlakyRecord{
				Type:      FlakyTypeIdempotencyBurst,
				Stage:     stage,
				SampleIdx: idx,
				Detail: fmt.Sprintf("burst run #%d differed: base=(%s,%s,%s) vs got=(%s,%s,%s)",
					i, baseline.Decision, baseline.RuleID, baseline.Reason,
					cur.Decision, cur.RuleID, cur.Reason),
				PayloadA: string(rawBody),
				VerdictA: fmt.Sprintf("%s:%s", baseline.Decision, baseline.RuleID),
				VerdictB: fmt.Sprintf("%s:%s", cur.Decision, cur.RuleID),
			})
			f.mu.Unlock()
			break
		}
	}

	return nil
}

// CheckCanonicalJSONPermutation tests verdict consistency across randomized key ordering & formatting.
func (f *FlakyDetector) CheckCanonicalJSONPermutation(ctx context.Context, stage string, idx uint64, in map[string]any) error {
	b1, err := json.Marshal(in)
	if err != nil {
		return err
	}

	// Permute key order in serialized JSON
	b2 := permuteJSONKeys(in)

	vt1, err1 := f.executeAndTuple(ctx, b1, false)
	if err1 != nil {
		return err1
	}

	vt2, err2 := f.executeAndTuple(ctx, b2, false)
	if err2 != nil {
		return err2
	}

	if vt1.Decision != vt2.Decision || vt1.RuleID != vt2.RuleID {
		f.mu.Lock()
		f.records = append(f.records, FlakyRecord{
			Type:      FlakyTypeCanonicalJSON,
			Stage:     stage,
			SampleIdx: idx,
			Detail:    fmt.Sprintf("canonical json key permutation gave divergent verdict: %s vs %s", vt1.Decision, vt2.Decision),
			PayloadA:  string(b1),
			PayloadB:  string(b2),
			VerdictA:  fmt.Sprintf("%s:%s", vt1.Decision, vt1.RuleID),
			VerdictB:  fmt.Sprintf("%s:%s", vt2.Decision, vt2.RuleID),
		})
		f.mu.Unlock()
	}

	return nil
}

// CheckExplainDiff samples 5% of requests to compare /v1/decide vs /v1/decide?explain=true.
func (f *FlakyDetector) CheckExplainDiff(ctx context.Context, stage string, idx uint64, rawBody []byte, r *rand.Rand) error {
	if r.Float64() > f.explainSample {
		return nil
	}

	vtDecide, err := f.executeAndTuple(ctx, rawBody, false)
	if err != nil {
		return err
	}

	vtExplain, err := f.executeAndTuple(ctx, rawBody, true)
	if err != nil {
		return err
	}

	if vtDecide.Decision != vtExplain.Decision || vtDecide.RuleID != vtExplain.RuleID {
		f.mu.Lock()
		f.records = append(f.records, FlakyRecord{
			Type:      FlakyTypeExplainDiff,
			Stage:     stage,
			SampleIdx: idx,
			Detail: fmt.Sprintf("explain diff: cached decide=(%s,%s) vs uncached explain=(%s,%s)",
				vtDecide.Decision, vtDecide.RuleID, vtExplain.Decision, vtExplain.RuleID),
			PayloadA: string(rawBody),
			VerdictA: fmt.Sprintf("%s:%s", vtDecide.Decision, vtDecide.RuleID),
			VerdictB: fmt.Sprintf("%s:%s", vtExplain.Decision, vtExplain.RuleID),
		})
		f.mu.Unlock()
	}

	return nil
}

func (f *FlakyDetector) executeAndTuple(ctx context.Context, body []byte, explain bool) (VerdictTuple, error) {
	targetURL := f.decideURL
	if explain {
		if bytes.ContainsRune([]byte(targetURL), '?') {
			targetURL += "&explain=true"
		} else {
			targetURL += "?explain=true"
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return VerdictTuple{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return VerdictTuple{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return VerdictTuple{}, err
	}

	var d DecisionResponse
	if err := json.Unmarshal(respBody, &d); err != nil {
		return VerdictTuple{
			Decision: "deny",
			RuleID:   fmt.Sprintf("http_%d", resp.StatusCode),
			Reason:   string(respBody),
		}, nil
	}

	// Compute hash of MaskedArgs
	var maskedHash string
	if d.MaskedArgs != nil {
		mb, _ := json.Marshal(d.MaskedArgs)
		h := sha256.Sum256(mb)
		maskedHash = hex.EncodeToString(h[:])
	}

	return VerdictTuple{
		Decision:       d.Decision,
		RuleID:         d.RuleID,
		Reason:         d.Reason,
		MaskedArgsHash: maskedHash,
	}, nil
}

// permuteJSONKeys serializes a map with reverse sorted keys to test key-ordering invariance.
func permuteJSONKeys(m map[string]any) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')

		val := m[k]
		if subMap, ok := val.(map[string]any); ok {
			buf.Write(permuteJSONKeys(subMap))
		} else {
			vb, _ := json.Marshal(val)
			buf.Write(vb)
		}
	}
	buf.WriteByte('}')
	return buf.Bytes()
}
