# ADR-0003: Lightweight Multi-Node HA & Distributed Peering

## Status
Accepted

## Context
Cerberus operates as an authoritative runtime decision engine and gateway proxy. In production environments requiring high availability (HA) and rolling upgrades, running multiple Cerberus instances is necessary. Introducing heavy distributed consensus engines (such as etcd, Consul, or Raft clusters) increases operational burden, maintenance overhead, and failure surface area.

Sprint 4C designs a lightweight multi-node architecture that preserves Cerberus's sub-millisecond evaluation latency and local-first execution model without external consensus dependencies.

## Decision

### 1. Peer Gossip & Authoritative Sync (`/v1/internal/sync`)
- Nodes are configured with a list of peer endpoints (`peers`).
- Nodes exchange status payloads (`node_id`, `started_at`, `bundle_revision`, `data_hash`, `epoch`) via `POST /v1/internal/sync` on a 60-second polling cycle and on startup.
- **Eldest Node Authoritative Rule**: The peer with the earliest `started_at` timestamp (or higher epoch / differing bundle revision) is treated as the authoritative peer. Younger nodes automatically pull the active signed bundle via `GET /v1/admin/bundle` from the eldest peer and install it via `Store.LoadBundle`.
- No distributed consensus (etcd/Raft) is required.

### 2. Local-First SQLite Audit with On-Demand Cluster Merge
- Every Cerberus node writes audit events strictly to its own local SQLite daily database (`audit-YYYYMMDD.db`).
- This guarantees that the hot decision path remains 100% lock-free and never blocks on cross-network I/O or distributed transactions.
- When operators or dashboards query cluster-wide audit history via `GET /v1/audit?cluster=true`, the querying node fetches local audit records, queries all configured peers concurrently, and performs an in-memory **merge-sort by timestamp descending** (newest first).

### 3. Deployment Guidance: Single-Node vs Multi-Node

| Scenario | Recommendation | Rationale |
| :--- | :--- | :--- |
| **Edge / Local Sidecar** | Single-Node | Minimal footprint, sub-100µs LRU hits, local SQLite storage. |
| **Small-to-Medium Cluster (<50k req/min)** | Single-Node with auto-restart | Simplest operational posture; bundle reloading and data swaps are instantaneous in-memory atomic operations. |
| **High-Availability (HA) Production** | Multi-Node (2-3 instances) | Redundant nodes behind L4/L7 load balancer (e.g. AWS ALB, NGINX, Envoy). Zero-downtime rolling deploys. |
| **Multi-Datacenter / Disaster Recovery** | Multi-Node with peer sync | Active-active nodes syncing policy bundles asynchronously. |

### 4. Consistency Model & Limitations
- **Consistency**: **Eventual consistency** across nodes. Policy and data updates propagate across peers within the 60-second gossip cycle (or instantly via direct webhook/bundle upload to each node).
- **Conflict Resolution**: **Last-Writer-Wins (LWW)** on `data.json` updates; higher epoch and eldest node tie-breaker for bundle revisions.
- **Rate Limiting**: Token buckets are in-memory per-node. For multi-node setups behind round-robin load balancers, per-node rate limit thresholds can be calibrated proportionally (`limit / num_nodes`), or used as local burst dampeners.

### 5. Upgrade Path to Centralized Bundle Service
For enterprise scale deployments requiring instantaneous synchronized fleet deployments:
1. **Current (Phase 1)**: Peer-to-peer gossip pull from eldest node via `/v1/internal/sync`.
2. **Phase 2 (Centralized S3/GCS Object Store)**: Nodes poll signed bundles (`bundle.tar.gz`) directly from an S3 bucket or OCI registry on SQS/SNS notification.
3. **Phase 3 (Enterprise Control Plane)**: Owl console pushes validated and signed bundles directly into an enterprise bundle distribution network, while nodes continue executing evaluations purely in-memory.
