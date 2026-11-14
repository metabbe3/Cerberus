// Package policy compiles the Rego bundle and gateway data into an immutable
// Snapshot and swaps it atomically on reload.
package policy

import (
	"time"

	"github.com/metabbe3/cerberus/internal/masking"
	"github.com/open-policy-agent/opa/v1/ast"
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
	Coverage float64                // active test coverage percentage (0.0 to 100.0)
	Query    rego.PreparedEvalQuery // query: data.gateway.authz.decision
	Data     map[string]any         // parsed data JSON (read-only after build)
	Maskers  map[string][]masking.Rule
	Modules  map[string]*ast.Module // parsed rego modules (reused from loader compile)
	Stages   map[string]bool        // registered stages derived from modules & data
	RuleIDs  map[string]bool        // registered rule IDs for bounded metric labels
	Loaded   time.Time
}
