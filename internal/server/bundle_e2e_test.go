package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/policy"
)

func buildE2EBundle(t *testing.T, roots []string, revision string, dataJSON []byte, regoFiles map[string]string, privKey ed25519.PrivateKey) []byte {
	t.Helper()
	files := make(map[string][]byte)

	if roots == nil {
		roots = []string{"stages"}
	}
	manifest := fmt.Sprintf(`{"roots":["%s"],"revision":"%s"}`, strings.Join(roots, `","`), revision)
	files[".manifest"] = []byte(manifest)
	files["data.json"] = dataJSON
	for name, content := range regoFiles {
		files[name] = []byte(content)
	}

	if privKey != nil {
		sig, err := policy.SignBundle(files, privKey)
		if err != nil {
			t.Fatalf("SignBundle: %v", err)
		}
		files["signatures.json"] = sig
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for n, c := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Size: int64(len(c)), Mode: 0o644})
		_, _ = tw.Write(c)
	}
	_ = tw.Close()
	_ = gw.Close()

	return buf.Bytes()
}

func TestBundle_E2E_BuildSignUploadSmokeRollback(t *testing.T) {
	h := newHarnessCopy(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	h.store.SetVerificationKey(pub)

	// Step 0: Base check - initial decision for k-open bash echo hello is allow
	dec0 := decideDirect(t, h, engine.Input{
		Stage:    "tool",
		KeyID:    "k-open",
		ToolCall: "bash",
		Args:     map[string]any{"cmd": "echo initial"},
	})
	if dec0.Decision != "allow" {
		t.Fatalf("initial dec = %s, want allow", dec0.Decision)
	}

	// Read existing ai.rego
	aiRego, err := os.ReadFile(filepath.Join(h.policies, "stages/ai.rego"))
	if err != nil {
		t.Fatalf("read ai: %v", err)
	}

	// Data for Bundle 1: updates k-open to allow bash
	data1, err := os.ReadFile(testData)
	if err != nil {
		t.Fatalf("read testData: %v", err)
	}
	var dataObj map[string]any
	if err := json.Unmarshal(data1, &dataObj); err != nil {
		t.Fatalf("unmarshal testData: %v", err)
	}
	agents := dataObj["agents"].(map[string]any)
	agents["k-open"] = map[string]any{
		"name":          "open-agent",
		"allowed_tools": []any{"bash"},
	}
	data1Bytes, _ := json.Marshal(dataObj)

	// Step 1: Build & sign Bundle 1
	bundle1 := buildE2EBundle(t, []string{"stages"}, "bundle-rev-1", data1Bytes, map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}, priv)

	// Step 2: Upload Bundle 1 -> smoke passes, activation succeeds
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+"/v1/admin/bundle", bytes.NewReader(bundle1))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/admin/bundle: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload bundle status = %d, want 200", resp.StatusCode)
	}
	var epochResp epochResponse
	_ = json.NewDecoder(resp.Body).Decode(&epochResp)
	_ = resp.Body.Close()
	if epochResp.Epoch != 2 {
		t.Fatalf("epoch after bundle1 upload = %d, want 2", epochResp.Epoch)
	}
	if h.store.Current().Revision != "bundle-rev-1" {
		t.Fatalf("revision = %q, want bundle-rev-1", h.store.Current().Revision)
	}

	// Step 3: Bundle signature salah -> ditolak -> decision TIDAK berubah
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	tamperedBundle := buildE2EBundle(t, []string{"stages"}, "bundle-rev-evil", data1Bytes, map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}, otherPriv) // signed with wrong key

	req, _ = http.NewRequest(http.MethodPost, h.ts.URL+"/v1/admin/bundle", bytes.NewReader(tamperedBundle))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST tampered bundle: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("tampered bundle status = %d, want 422", resp.StatusCode)
	}
	// Verify epoch and decision unchanged
	if h.store.Current().Epoch != 2 {
		t.Fatalf("epoch changed on failed bundle load: got %d, want 2", h.store.Current().Epoch)
	}
	dec1 := decideDirect(t, h, engine.Input{
		Stage:    "tool",
		KeyID:    "k-open",
		ToolCall: "bash",
		Args:     map[string]any{"cmd": "echo initial"},
	})
	if dec1.Decision != "allow" {
		t.Fatalf("dec after failed upload = %s, want allow", dec1.Decision)
	}

	// Step 4: Smoke failure bundle -> ditolak -> decision TIDAK berubah
	brokenDataObj := map[string]any{
		"config": map[string]any{"bypass_unknown_keys": true, "bypass_unknown_teams": true},
		"teams":  map[string]any{},
		"agents": map[string]any{},
		"prod_shield": map[string]any{
			"dangerous_cmd_patterns": []any{},
		},
	}
	brokenDataBytes, _ := json.Marshal(brokenDataObj)
	smokeFailBundle := buildE2EBundle(t, []string{"stages"}, "bundle-broken-smoke", brokenDataBytes, map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}, priv)

	req, _ = http.NewRequest(http.MethodPost, h.ts.URL+"/v1/admin/bundle", bytes.NewReader(smokeFailBundle))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST broken smoke bundle: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("smoke fail bundle status = %d, want 422", resp.StatusCode)
	}
	if h.store.Current().Epoch != 2 {
		t.Fatalf("epoch changed after broken smoke: got %d, want 2", h.store.Current().Epoch)
	}

	// Step 5: Upload Bundle 2 -> valid, becomes active
	agents["k-open"] = map[string]any{
		"name":          "open-agent",
		"allowed_tools": []any{"bash"},
		"budget_limit":  999,
	}
	data2Bytes, _ := json.Marshal(dataObj)
	bundle2 := buildE2EBundle(t, []string{"stages"}, "bundle-rev-2", data2Bytes, map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}, priv)

	req, _ = http.NewRequest(http.MethodPost, h.ts.URL+"/v1/admin/bundle", bytes.NewReader(bundle2))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST bundle 2: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bundle 2 upload status = %d, want 200", resp.StatusCode)
	}
	if h.store.Current().Revision != "bundle-rev-2" || h.store.Current().Epoch != 3 {
		t.Fatalf("current snap = %s/%d, want bundle-rev-2/3", h.store.Current().Revision, h.store.Current().Epoch)
	}

	// Step 6: Rollback -> revision returns to bundle-rev-1
	req, _ = http.NewRequest(http.MethodPost, h.ts.URL+"/v1/admin/bundle/rollback", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-Admin-User", "test-admin")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST rollback: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rollback status = %d, want 200", resp.StatusCode)
	}
	var rollResp struct {
		OK       bool   `json:"ok"`
		Epoch    uint64 `json:"epoch"`
		Revision string `json:"revision"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&rollResp)
	_ = resp.Body.Close()

	if !rollResp.OK {
		t.Fatal("rollback response ok = false")
	}
	if rollResp.Revision != "bundle-rev-1" {
		t.Fatalf("rolled back revision = %q, want bundle-rev-1", rollResp.Revision)
	}
	if rollResp.Epoch != 4 {
		t.Fatalf("rolled back epoch = %d, want 4", rollResp.Epoch)
	}

	// Verify audit event emitted for bundle rollback (B4)
	var foundRollback bool
	var matchedEvent audit.Event
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		evs, err := h.auditLog.Query(context.Background(), audit.Filter{Limit: 10})
		if err == nil {
			for _, ev := range evs {
				if ev.RuleID == "admin.bundle.rollback" {
					foundRollback = true
					matchedEvent = ev
					break
				}
			}
		}
		if foundRollback {
			break
		}
	}
	if !foundRollback {
		t.Fatal("expected admin.bundle.rollback audit event, none found within 5s")
	}
	if matchedEvent.KeyID != "test-admin" {
		t.Errorf("matchedEvent.KeyID = %q, want test-admin", matchedEvent.KeyID)
	}
	if matchedEvent.Epoch != 4 {
		t.Errorf("matchedEvent.Epoch = %d, want 4", matchedEvent.Epoch)
	}
	if matchedEvent.Reason != "rollback to revision bundle-rev-1" {
		t.Errorf("matchedEvent.Reason = %q, want rollback to revision bundle-rev-1", matchedEvent.Reason)
	}

	// Step 7: Verify decision still works as expected
	decRolled := decideDirect(t, h, engine.Input{
		Stage:    "tool",
		KeyID:    "k-open",
		ToolCall: "bash",
		Args:     map[string]any{"cmd": "echo after-rollback"},
	})
	if decRolled.Decision != "allow" {
		t.Fatalf("decRolled = %s, want allow", decRolled.Decision)
	}
}

func decideDirect(t *testing.T, h *harness, in engine.Input) engine.Decision {
	t.Helper()
	body, _ := json.Marshal(in)
	resp, err := http.Post(h.ts.URL+"/v1/decide", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /v1/decide: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var d engine.Decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	return d
}
