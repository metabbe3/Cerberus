package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
)

// SyncPayload is exchanged between Cerberus nodes during gossip sync.
type SyncPayload struct {
	NodeID         string `json:"node_id"`
	StartedAt      int64  `json:"started_at"` // Unix timestamp in seconds; older node is authoritative leader
	BundleRevision string `json:"bundle_revision"`
	DataHash       string `json:"data_hash"`
	Epoch          uint64 `json:"epoch"`
}

// ClusterConfig configures multi-node peering and sync.
type ClusterConfig struct {
	NodeID       string
	StartedAt    int64
	Peers        []string
	SyncInterval time.Duration
}

// ClusterManager coordinates peer gossip sync and distributed cluster audit queries.
type ClusterManager struct {
	nodeID       string
	startedAt    int64
	peers        []string
	syncInterval time.Duration
	srv          *Server
	client       *http.Client
	stop         chan struct{}
	closeOnce    sync.Once
}

func newClusterManager(srv *Server, cfg ClusterConfig) *ClusterManager {
	if cfg.NodeID == "" {
		cfg.NodeID = fmt.Sprintf("node-%s", newRequestID())
	}
	startedAt := cfg.StartedAt
	if startedAt == 0 {
		startedAt = time.Now().Unix()
	}
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 60 * time.Second
	}
	cm := &ClusterManager{
		nodeID:       cfg.NodeID,
		startedAt:    startedAt,
		peers:        cleanPeers(cfg.Peers),
		syncInterval: cfg.SyncInterval,
		srv:          srv,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		stop: make(chan struct{}),
	}
	if len(cm.peers) > 0 {
		go cm.run()
	}
	return cm
}

func cleanPeers(peers []string) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		p = strings.TrimRight(strings.TrimSpace(p), "/")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (cm *ClusterManager) Close() {
	cm.closeOnce.Do(func() {
		close(cm.stop)
	})
}

func (cm *ClusterManager) currentPayload() SyncPayload {
	var rev string
	var epoch uint64
	var dataHash string
	if cm.srv.deps.Store != nil && cm.srv.deps.Store.Current() != nil {
		snap := cm.srv.deps.Store.Current()
		rev = snap.Revision
		epoch = snap.Epoch
		if snap.Data != nil {
			if b, err := json.Marshal(snap.Data); err == nil {
				h := sha256.Sum256(b)
				dataHash = hex.EncodeToString(h[:])
			}
		}
	}
	return SyncPayload{
		NodeID:         cm.nodeID,
		StartedAt:      cm.startedAt,
		BundleRevision: rev,
		DataHash:       dataHash,
		Epoch:          epoch,
	}
}

func (cm *ClusterManager) run() {
	ticker := time.NewTicker(cm.syncInterval)
	defer ticker.Stop()

	// Initial sync on startup
	cm.SyncAll(context.Background())

	for {
		select {
		case <-cm.stop:
			return
		case <-ticker.C:
			cm.SyncAll(context.Background())
		}
	}
}

// SyncAll contacts all configured peers to exchange sync payloads and pull bundle if needed.
func (cm *ClusterManager) SyncAll(ctx context.Context) {
	myPayload := cm.currentPayload()
	for _, peer := range cm.peers {
		if err := cm.syncWithPeer(ctx, peer, myPayload); err != nil {
			slog.Debug("cluster: sync with peer failed", "peer", peer, "err", err)
		}
	}
}

func (cm *ClusterManager) syncWithPeer(ctx context.Context, peer string, myPayload SyncPayload) error {
	body, err := json.Marshal(myPayload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, peer+"/v1/internal/sync", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if cm.srv.deps.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+cm.srv.deps.AdminToken)
	}

	resp, err := cm.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer returned status %d", resp.StatusCode)
	}

	var peerPayload SyncPayload
	if err := json.NewDecoder(resp.Body).Decode(&peerPayload); err != nil {
		return fmt.Errorf("decode peer payload: %w", err)
	}

	// HA rule: The eldest peer (lower startedAt) or peer with higher epoch/different revision
	// is authoritative. If peer is older and has different revision/hash, pull bundle from it.
	shouldPull := false
	if peerPayload.BundleRevision != "" && peerPayload.BundleRevision != myPayload.BundleRevision {
		if peerPayload.StartedAt < myPayload.StartedAt || peerPayload.Epoch > myPayload.Epoch {
			shouldPull = true
		}
	} else if peerPayload.DataHash != "" && peerPayload.DataHash != myPayload.DataHash {
		if peerPayload.StartedAt < myPayload.StartedAt || peerPayload.Epoch > myPayload.Epoch {
			shouldPull = true
		}
	}

	if shouldPull {
		slog.Info("cluster: pulling bundle from authoritative peer", "peer", peer, "peer_rev", peerPayload.BundleRevision, "peer_epoch", peerPayload.Epoch)
		return cm.pullBundle(ctx, peer)
	}
	return nil
}

func (cm *ClusterManager) pullBundle(ctx context.Context, peer string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, peer+"/v1/admin/bundle", nil)
	if err != nil {
		return err
	}
	if cm.srv.deps.AdminToken != "" {
		req.Header.Set("Authorization", "Bearer "+cm.srv.deps.AdminToken)
	}

	resp, err := cm.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pull bundle failed with status %d", resp.StatusCode)
	}

	bundleBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read pulled bundle: %w", err)
	}

	if cm.srv.deps.Store == nil {
		return fmt.Errorf("store unavailable")
	}

	snap, err := cm.srv.deps.Store.LoadBundle(ctx, bundleBytes)
	if err != nil {
		return fmt.Errorf("install pulled bundle: %w", err)
	}

	slog.Info("cluster: successfully installed bundle from peer", "epoch", snap.Epoch, "revision", snap.Revision)
	return nil
}

// handleInternalSync handles POST /v1/internal/sync.
func (s *Server) handleInternalSync(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil {
		writeErr(w, http.StatusServiceUnavailable, "cluster disabled")
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var incoming SyncPayload
	if len(body) > 0 && json.Unmarshal(body, &incoming) != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}

	current := s.cluster.currentPayload()
	writeJSON(w, http.StatusOK, current)
}

// queryClusterAudit queries local SQLite audit logs and all peers, merging by timestamp descending.
func (s *Server) queryClusterAudit(w http.ResponseWriter, r *http.Request, f audit.Filter) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	// 1. Query local events
	var allEvents []audit.Event
	if s.deps.Audit != nil {
		local, err := s.deps.Audit.Query(r.Context(), f)
		if err == nil {
			allEvents = append(allEvents, local...)
		}
	}

	// 2. Query peers concurrently
	if s.cluster != nil && len(s.cluster.peers) > 0 {
		q := r.URL.Query()
		q.Del("cluster") // prevent infinite recursion across peers

		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, peer := range s.cluster.peers {
			wg.Add(1)
			go func(peerURL string) {
				defer wg.Done()
				peerReqURL := fmt.Sprintf("%s/v1/audit?%s", peerURL, q.Encode())
				ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
				defer cancel()

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, peerReqURL, nil)
				if err != nil {
					return
				}
				if s.deps.AdminToken != "" {
					req.Header.Set("Authorization", "Bearer "+s.deps.AdminToken)
				}
				resp, err := s.cluster.client.Do(req)
				if err != nil {
					return
				}
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode != http.StatusOK {
					return
				}
				var peerEvs []audit.Event
				if err := json.NewDecoder(resp.Body).Decode(&peerEvs); err == nil {
					mu.Lock()
					allEvents = append(allEvents, peerEvs...)
					mu.Unlock()
				}
			}(peer)
		}
		wg.Wait()
	}

	// 3. Merge sort by timestamp descending (newest first), tie-breaker event ID
	sort.Slice(allEvents, func(i, j int) bool {
		if allEvents[i].Time.Equal(allEvents[j].Time) {
			return allEvents[i].ID > allEvents[j].ID
		}
		return allEvents[i].Time.After(allEvents[j].Time)
	})

	if len(allEvents) > limit {
		allEvents = allEvents[:limit]
	}

	writeJSON(w, http.StatusOK, allEvents)
}
