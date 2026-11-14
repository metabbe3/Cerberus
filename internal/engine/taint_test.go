package engine

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTaintTracker_RecordAndExpire(t *testing.T) {
	tracker, err := NewTaintTracker(100, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("NewTaintTracker: %v", err)
	}

	tracker.RecordTaint("key1", "test_source")
	mark, ok := tracker.GetActiveTaint("key1")
	if !ok {
		t.Fatal("expected active taint for key1")
	}
	if mark.Source != "test_source" {
		t.Fatalf("expected source 'test_source', got %q", mark.Source)
	}

	time.Sleep(70 * time.Millisecond)
	_, ok = tracker.GetActiveTaint("key1")
	if ok {
		t.Fatal("expected taint to be expired after TTL")
	}
}

func TestTaintTracker_LRUEviction(t *testing.T) {
	tracker, err := NewTaintTracker(2, time.Minute)
	if err != nil {
		t.Fatalf("NewTaintTracker: %v", err)
	}

	tracker.RecordTaint("k1", "s1")
	tracker.RecordTaint("k2", "s2")
	tracker.RecordTaint("k3", "s3") // k1 should be evicted

	if _, ok := tracker.GetActiveTaint("k1"); ok {
		t.Fatal("expected k1 to be evicted by LRU")
	}
	if _, ok := tracker.GetActiveTaint("k2"); !ok {
		t.Fatal("expected k2 to remain")
	}
	if _, ok := tracker.GetActiveTaint("k3"); !ok {
		t.Fatal("expected k3 to remain")
	}
}

func TestSessionKey(t *testing.T) {
	// 1. SessionID provided
	in1 := Input{KeyID: "k-open", SessionID: "sess-123"}
	if k := SessionKey(in1); k != "k-open:sess-123" {
		t.Fatalf("got %q, want 'k-open:sess-123'", k)
	}

	// 2. Context session_id fallback
	in2 := Input{KeyID: "k-open", Context: map[string]any{"session_id": "sess-456"}}
	if k := SessionKey(in2); k != "k-open:sess-456" {
		t.Fatalf("got %q, want 'k-open:sess-456'", k)
	}

	// 3. Context trace_id fallback
	in3 := Input{KeyID: "k-open", Context: map[string]any{"trace_id": "tr-789"}}
	if k := SessionKey(in3); k != "k-open:tr-789" {
		t.Fatalf("got %q, want 'k-open:tr-789'", k)
	}

	// 4. Fallback to key_id only
	in4 := Input{KeyID: "k-open"}
	if k := SessionKey(in4); k != "k-open" {
		t.Fatalf("got %q, want 'k-open'", k)
	}
}

func TestDetectSensitiveSource(t *testing.T) {
	tests := []struct {
		name       string
		in         Input
		wantSource string
		wantOk     bool
	}{
		{
			name: "http private ip",
			in: Input{
				Stage: "http",
				Host:  "10.0.0.1",
			},
			wantSource: "http:non_public_ip",
			wantOk:     true,
		},
		{
			name: "http link-local",
			in: Input{
				Stage:    "http",
				Resource: "http://169.254.169.254/latest/meta-data/",
			},
			wantSource: "http:non_public_ip",
			wantOk:     true,
		},
		{
			name: "http public host",
			in: Input{
				Stage:    "http",
				Resource: "https://api.github.com/repos",
			},
			wantOk: false,
		},
		{
			name: "db sensitive table",
			in: Input{
				Stage: "db",
				Args: map[string]any{
					"sql": "SELECT * FROM credentials",
				},
			},
			wantSource: "db:sensitive_table",
			wantOk:     true,
		},
		{
			name: "k8s secret read",
			in: Input{
				Stage: "k8s",
				Args: map[string]any{
					"verb":     "get",
					"resource": "secret",
				},
			},
			wantSource: "k8s:secret_read",
			wantOk:     true,
		},
		{
			name: "docker protected container",
			in: Input{
				Stage:    "docker",
				Action:   "inspect",
				Resource: "teknikalidnew-db-1",
			},
			wantSource: "docker:protected_container",
			wantOk:     true,
		},
		{
			name: "tool cred harvest",
			in: Input{
				Stage:    "tool",
				ToolCall: "runner",
				Args: map[string]any{
					"exec": "cat ~/.ssh/id_rsa",
				},
			},
			wantSource: "tool:credential_harvest",
			wantOk:     true,
		},
		{
			name: "llm oversized",
			in: Input{
				Stage:  "llm",
				Prompt: strings.Repeat("A", 5000),
			},
			wantSource: "llm:oversized",
			wantOk:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src, ok := DetectSensitiveSource(tc.in)
			if ok != tc.wantOk {
				t.Fatalf("DetectSensitiveSource ok=%v, want %v", ok, tc.wantOk)
			}
			if ok && src != tc.wantSource {
				t.Fatalf("DetectSensitiveSource src=%q, want %q", src, tc.wantSource)
			}
		})
	}
}

func TestIsEgressAttempt(t *testing.T) {
	tests := []struct {
		name   string
		in     Input
		wantOk bool
	}{
		{
			name: "http post external",
			in: Input{
				Stage:    "http",
				Action:   "POST",
				Resource: "https://api.github.com/gists",
			},
			wantOk: true,
		},
		{
			name: "http get external",
			in: Input{
				Stage:    "http",
				Action:   "GET",
				Resource: "https://api.github.com/gists",
			},
			wantOk: false,
		},
		{
			name: "ssh connect",
			in: Input{
				Stage:  "ssh",
				Action: "connect",
				Host:   "bastion.corp",
			},
			wantOk: true,
		},
		{
			name: "k8s exec",
			in: Input{
				Stage: "k8s",
				Args: map[string]any{
					"verb": "exec",
				},
			},
			wantOk: true,
		},
		{
			name: "db write",
			in: Input{
				Stage: "db",
				Args: map[string]any{
					"sql": "INSERT INTO logs VALUES ('exfil')",
				},
			},
			wantOk: true,
		},
		{
			name: "tool file redirect",
			in: Input{
				Stage:    "tool",
				ToolCall: "bash",
				Args: map[string]any{
					"cmd": "echo test > /tmp/p.sh",
				},
			},
			wantOk: true,
		},
		{
			name: "llm prompt",
			in: Input{
				Stage:  "llm",
				Prompt: "Hello",
			},
			wantOk: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsEgressAttempt(tc.in)
			if got != tc.wantOk {
				t.Fatalf("IsEgressAttempt got %v, want %v", got, tc.wantOk)
			}
		})
	}
}

func TestEngine_TaintTrackingFlow(t *testing.T) {
	eng := newTestEngine(t, nil, Options{})
	defer eng.Close()

	ctx := context.Background()

	// Step 1: Docker inspect protected container with session_id "sess-A"
	step1 := Input{
		Stage:     "docker",
		KeyID:     "k-open",
		SessionID: "sess-A",
		Action:    "inspect",
		Resource:  "teknikalidnew-db-1",
	}
	d1 := eng.Decide(ctx, step1)
	if !d1.Allowed() {
		t.Fatalf("step 1 expected allow, got %v (%s)", d1.Decision, d1.RuleID)
	}

	// Verify taint is active for sess-A
	mark, ok := eng.TaintTracker().GetActiveTaint("k-open:sess-A")
	if !ok {
		t.Fatal("expected active taint mark for k-open:sess-A")
	}
	if mark.Source != "docker:protected_container" {
		t.Fatalf("expected source docker:protected_container, got %s", mark.Source)
	}

	// Step 2: session "sess-B" on same key tries to egress (POST to github) -> should NOT be blocked
	step2OtherSession := Input{
		Stage:     "http",
		KeyID:     "k-open",
		SessionID: "sess-B",
		Action:    "POST",
		Resource:  "https://api.github.com/gists",
	}
	d2Other := eng.Decide(ctx, step2OtherSession)
	if !d2Other.Allowed() {
		t.Fatalf("session B expected allow, got deny: %s", d2Other.RuleID)
	}

	// Step 3: session "sess-A" tries to egress (POST to github) -> MUST be blocked by chain.tainted_exfil
	step2TaintedSession := Input{
		Stage:     "http",
		KeyID:     "k-open",
		SessionID: "sess-A",
		Action:    "POST",
		Resource:  "https://api.github.com/gists",
	}
	d2Tainted := eng.Decide(ctx, step2TaintedSession)
	if d2Tainted.Decision != "deny" {
		t.Fatalf("session A expected deny, got %v", d2Tainted.Decision)
	}
	if d2Tainted.RuleID != "chain.tainted_exfil" {
		t.Fatalf("expected rule_id chain.tainted_exfil, got %q", d2Tainted.RuleID)
	}
	if !strings.Contains(d2Tainted.Reason, "docker:protected_container") {
		t.Fatalf("reason should mention source docker:protected_container, got %q", d2Tainted.Reason)
	}
	if !strings.Contains(d2Tainted.Reason, "age=") {
		t.Fatalf("reason should mention age, got %q", d2Tainted.Reason)
	}
}
