package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/policy"
)

// blockingOrKilledSink simulates a dead, blocked, or slow audit sink.
type blockingOrKilledSink struct {
	closed bool
}

func (s *blockingOrKilledSink) Emit(_ audit.Event) {
	// Drops instantly; must NEVER block the engine caller
}

func TestChaos_KillAuditSink_DecisionPathSubMillisecond(t *testing.T) {
	store, err := policy.NewStore(context.Background(), policyDir, testData)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	deadSink := &blockingOrKilledSink{closed: true}
	eng, err := New(store, deadSink, Options{
		CacheSize:   1000,
		EvalTimeout: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	ctx := context.Background()
	in := Input{
		Stage:    "llm",
		KeyID:    "k-open",
		Model:    "m1",
		Prompt:   "hello world",
		ToolCall: "",
	}

	// Warmup
	eng.Decide(ctx, in)

	// Measure 1000 decisions under dead audit sink
	start := time.Now()
	const iterations = 1000
	for i := 0; i < iterations; i++ {
		d := eng.Decide(ctx, in)
		if !d.Allowed() {
			t.Fatalf("decision dropped or denied unexpectedly: %v", d)
		}
	}
	elapsed := time.Since(start)
	avgPerDecision := elapsed / iterations

	if avgPerDecision > time.Millisecond {
		t.Errorf("average decision latency %v exceeds 1ms limit under dead audit sink", avgPerDecision)
	}
}

func TestChaos_BundleCorruptUpload_PreservesSnapshot(t *testing.T) {
	store, err := policy.NewStore(context.Background(), policyDir, testData)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	origSnap := store.Current()
	origEpoch := origSnap.Epoch
	origRev := origSnap.Revision

	corruptPayloads := [][]byte{
		[]byte("not a gzip file at all"),
		[]byte("\x1f\x8b\x08\x00\x00\x00\x00\x00corrupt truncated data"),
		bytes.Repeat([]byte{0xFF}, 1024),
		[]byte(""),
	}

	ctx := context.Background()
	for i, payload := range corruptPayloads {
		_, err := store.LoadBundle(ctx, payload)
		if err == nil {
			t.Errorf("corrupt payload %d should be refused", i)
		}

		// Snapshot must remain intact, epoch unchanged
		cur := store.Current()
		if cur.Epoch != origEpoch || cur.Revision != origRev {
			t.Fatalf("snapshot mutated after corrupt upload %d: epoch=%d rev=%s", i, cur.Epoch, cur.Revision)
		}
	}
}

func TestChaos_ClockSkew_FutureBundleRevisionRejected(t *testing.T) {
	store, err := policy.NewStore(context.Background(), policyDir, testData)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	origSnap := store.Current()
	origEpoch := origSnap.Epoch

	// Bundle with revision timestamp set far in the future (year 2099)
	dataRaw, _ := os.ReadFile(testData)
	futureBundle := buildTestBundle(t, []string{"stages"}, "rev-2099-12-31T23:59:59Z", dataRaw, map[string]string{
		"policies/stages/ai.rego": `package stages.ai
import rego.v1
default decision := {"decision": "allow", "rule_id": "future.ai", "reason": "ok"}
`,
	})

	ctx := context.Background()
	_, err = store.LoadBundle(ctx, futureBundle)
	if err == nil {
		t.Fatal("bundle with future revision timestamp MUST be rejected")
	}
	if !errors.Is(err, policy.ErrFutureRevision) {
		t.Fatalf("expected ErrFutureRevision, got %v", err)
	}

	// Verify original snapshot unchanged
	if store.Current().Epoch != origEpoch {
		t.Fatalf("epoch changed after rejected future bundle: %d != %d", store.Current().Epoch, origEpoch)
	}
}

func buildTestBundle(t *testing.T, roots []string, revision string, dataJSON []byte, regoFiles map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	manifest := fmt.Sprintf(`{"roots":["%s"],"revision":"%s"}`, strings.Join(roots, `","`), revision)
	files := map[string][]byte{
		".manifest": []byte(manifest),
		"data.json": dataJSON,
	}
	for n, c := range regoFiles {
		files[n] = []byte(c)
	}

	for n, c := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Size: int64(len(c)), Mode: 0o644})
		_, _ = tw.Write(c)
	}
	_ = tw.Close()
	_ = gw.Close()

	return buf.Bytes()
}
