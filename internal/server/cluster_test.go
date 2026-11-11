package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/engine"
	"github.com/metabbe3/cerberus/internal/policy"
)

func TestCluster_GossipSync_PullFromAuthoritativePeer(t *testing.T) {
	ctx := context.Background()

	// 1. Create Node 1 (older node, authoritative)
	dir1 := t.TempDir()
	store1, err := policy.NewStore(ctx, policyDir, testData)
	if err != nil {
		t.Fatalf("store1: %v", err)
	}
	al1, err := audit.Open(ctx, filepath.Join(dir1, "audit.db"), audit.Options{BatchSize: 1})
	if err != nil {
		t.Fatalf("audit1: %v", err)
	}
	t.Cleanup(func() { _ = al1.Close() })

	eng1, _ := engine.New(store1, al1, engine.Options{EvalTimeout: time.Second})
	srv1 := New(Deps{
		Engine:     eng1,
		Store:      store1,
		Audit:      al1,
		AdminToken: adminToken,
		Version:    "test-1",
		Cluster: ClusterConfig{
			NodeID:       "node-1",
			SyncInterval: time.Hour, // manual sync in test
		},
	})
	srv1.cluster.startedAt = 1000 // earlier timestamp (older node)
	ts1 := httptest.NewServer(srv1)
	defer ts1.Close()

	// Install bundle-rev-alpha on Node 1
	dataRaw, err := os.ReadFile(testData)
	if err != nil {
		t.Fatalf("read testData: %v", err)
	}
	var dataObj map[string]any
	if err := json.Unmarshal(dataRaw, &dataObj); err != nil {
		t.Fatalf("unmarshal testData: %v", err)
	}
	aiRego, err := os.ReadFile(filepath.Join(policyDir, "stages", "ai.rego"))
	if err != nil {
		t.Fatalf("read ai.rego: %v", err)
	}
	data1Bytes, _ := json.Marshal(dataObj)
	regoFiles := map[string]string{
		"policies/stages/ai.rego": string(aiRego),
	}
	bundleAlpha := buildE2EBundle(t, []string{"stages"}, "bundle-rev-alpha", data1Bytes, regoFiles, nil)
	snap1, err := store1.LoadBundle(ctx, bundleAlpha)
	if err != nil {
		t.Fatalf("load bundle on node 1: %v", err)
	}
	if snap1.Revision != "bundle-rev-alpha" {
		t.Fatalf("snap1 revision = %s", snap1.Revision)
	}

	// 2. Create Node 2 (younger node, peer of Node 1)
	dir2 := t.TempDir()
	store2, err := policy.NewStore(ctx, policyDir, testData)
	if err != nil {
		t.Fatalf("store2: %v", err)
	}
	al2, err := audit.Open(ctx, filepath.Join(dir2, "audit.db"), audit.Options{BatchSize: 1})
	if err != nil {
		t.Fatalf("audit2: %v", err)
	}
	t.Cleanup(func() { _ = al2.Close() })

	eng2, _ := engine.New(store2, al2, engine.Options{EvalTimeout: time.Second})
	srv2 := New(Deps{
		Engine:     eng2,
		Store:      store2,
		Audit:      al2,
		AdminToken: adminToken,
		Version:    "test-2",
		Cluster: ClusterConfig{
			NodeID:       "node-2",
			Peers:        []string{ts1.URL},
			SyncInterval: time.Hour,
		},
	})
	srv2.cluster.startedAt = 2000 // later timestamp (younger node)
	ts2 := httptest.NewServer(srv2)
	defer ts2.Close()

	// Initial check: Node 2 should NOT have bundle-rev-alpha
	if store2.Current().Revision == "bundle-rev-alpha" {
		t.Fatalf("node 2 should not have bundle-rev-alpha before sync")
	}

	// 3. Trigger gossip sync on Node 2
	srv2.cluster.SyncAll(ctx)

	// 4. Verify Node 2 successfully pulled and installed bundle from Node 1
	snap2 := store2.Current()
	if snap2.Revision != "bundle-rev-alpha" {
		t.Fatalf("node 2 revision after sync = %q, want bundle-rev-alpha", snap2.Revision)
	}
}

func TestCluster_AuditMergeSort(t *testing.T) {
	ctx := context.Background()

	// Node 1
	dir1 := t.TempDir()
	store1, _ := policy.NewStore(ctx, policyDir, testData)
	al1, _ := audit.Open(ctx, filepath.Join(dir1, "audit.db"), audit.Options{BatchSize: 1, FlushEvery: 10 * time.Millisecond})
	t.Cleanup(func() { _ = al1.Close() })
	eng1, _ := engine.New(store1, al1, engine.Options{EvalTimeout: time.Second})

	// Node 2
	dir2 := t.TempDir()
	store2, _ := policy.NewStore(ctx, policyDir, testData)
	al2, _ := audit.Open(ctx, filepath.Join(dir2, "audit.db"), audit.Options{BatchSize: 1, FlushEvery: 10 * time.Millisecond})
	t.Cleanup(func() { _ = al2.Close() })
	eng2, _ := engine.New(store2, al2, engine.Options{EvalTimeout: time.Second})

	srv2 := New(Deps{
		Engine:     eng2,
		Store:      store2,
		Audit:      al2,
		AdminToken: adminToken,
	})
	ts2 := httptest.NewServer(srv2)
	defer ts2.Close()

	srv1 := New(Deps{
		Engine:     eng1,
		Store:      store1,
		Audit:      al1,
		AdminToken: adminToken,
		Cluster: ClusterConfig{
			Peers: []string{ts2.URL},
		},
	})
	ts1 := httptest.NewServer(srv1)
	defer ts1.Close()

	// Emit interleaved events into both nodes
	t0 := time.Now().Add(-10 * time.Minute)
	t1 := t0.Add(1 * time.Minute) // Node 1: Event A
	t2 := t0.Add(2 * time.Minute) // Node 2: Event B
	t3 := t0.Add(3 * time.Minute) // Node 1: Event C
	t4 := t0.Add(4 * time.Minute) // Node 2: Event D

	al1.Emit(audit.Event{Time: t1, Stage: "llm", KeyID: "k-open", Subject: "evA", Decision: "allow", RuleID: "test.a"})
	al2.Emit(audit.Event{Time: t2, Stage: "llm", KeyID: "k-open", Subject: "evB", Decision: "allow", RuleID: "test.b"})
	al1.Emit(audit.Event{Time: t3, Stage: "llm", KeyID: "k-open", Subject: "evC", Decision: "allow", RuleID: "test.c"})
	al2.Emit(audit.Event{Time: t4, Stage: "llm", KeyID: "k-open", Subject: "evD", Decision: "allow", RuleID: "test.d"})

	time.Sleep(50 * time.Millisecond) // wait for SQLite flushes

	// Query Node 1 with cluster=true
	req, _ := http.NewRequest(http.MethodGet, ts1.URL+"/v1/audit?cluster=true", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := ts1.Client().Do(req)
	if err != nil {
		t.Fatalf("query cluster audit: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var events []audit.Event
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		t.Fatalf("decode events: %v", err)
	}

	if len(events) < 4 {
		t.Fatalf("got %d events, want at least 4", len(events))
	}

	// Verify order is strictly newest-first (t4 > t3 > t2 > t1)
	for i := 0; i < len(events)-1; i++ {
		if events[i].Time.Before(events[i+1].Time) {
			t.Errorf("events out of order: event[%d] (%s) is before event[%d] (%s)",
				i, events[i].Subject, i+1, events[i+1].Subject)
		}
	}

	// Check subjects order: evD -> evC -> evB -> evA
	expectedSubjects := []string{"evD", "evC", "evB", "evA"}
	for i, want := range expectedSubjects {
		if events[i].Subject != want {
			t.Errorf("event[%d].Subject = %q, want %q", i, events[i].Subject, want)
		}
	}
}
