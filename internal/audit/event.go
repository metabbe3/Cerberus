// Package audit persists decision events to SQLite in bounded batches and
// fans them out to in-memory ring, subscribers, and queries. Emit never
// blocks the decision hot path; the channel send is the whole cost.
package audit

import "time"

// Event is one audited decision. Args carries masked args only — the engine
// masks before emitting, never after.
type Event struct {
	ID        int64          `json:"id"` // set by DB
	Time      time.Time      `json:"time"`
	Stage     string         `json:"stage"`
	KeyID     string         `json:"key_id"`
	Subject   string         `json:"subject"` // model | tool_call | action
	Decision  string         `json:"decision"`
	RuleID    string         `json:"rule_id"`
	Reason    string         `json:"reason"`
	Epoch     uint64         `json:"epoch"`
	Cached    bool           `json:"cached"`
	LatencyUS int64          `json:"latency_us"`
	Args      map[string]any `json:"args,omitempty"`
}
