// Package policy compiles the Rego bundle and gateway data into an immutable
// Snapshot and swaps it atomically on reload.
package policy

import (
	"time"

	"github.com/metabbe3/cerberus/internal/masking"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Snapshot is an immutable compiled policy: a prepared eval query over
// data.gateway.authz.decision, the parsed data document, and per-key masking
// rules. Readers get it from Store.Current and must treat it as read-only;
// updates are made by building a new Snapshot and swapping it in.
type Snapshot struct {
	Epoch    uint64
	EpochStr string
	Revision string                 // bundle/policy revision (from .manifest or empty)
	Query    rego.PreparedEvalQuery // query: data.gateway.authz.decision
	Data     map[string]any         // parsed data JSON (read-only after build)
	Maskers  map[string][]masking.Rule
	Loaded   time.Time
}
