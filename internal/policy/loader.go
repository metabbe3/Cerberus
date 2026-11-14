package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/metabbe3/cerberus/internal/masking"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

var (
	// ErrCompile is returned when the Rego under policyDir fails to parse or compile.
	ErrCompile = errors.New("policy: compile failed")
	// ErrData is returned when a data document is not valid JSON, carries an
	// unknown top-level key, or holds a masking spec that fails to compile.
	ErrData = errors.New("policy: invalid data")
)

// allowedTopKeys are the only top-level keys a data document may contain
// (CONVENTIONS.md "Data JSON": unknown top-level fields are rejected).
var allowedTopKeys = map[string]bool{
	"config": true, "teams": true, "agents": true,
	"blocked_patterns": true, "domains": true, "_comment": true,
	"prod_shield": true, "ssh": true,
}

// Load compiles the Rego files under policyDir together with dataJSON into a
// Snapshot at the given epoch. Only non-test .rego files enter the bundle;
// data comes exclusively from dataJSON. (rego.Load cannot be combined with a
// user-provided store in OPA v1 — it would need a write transaction on it —
// so modules are loaded first and handed to rego individually.)
func Load(ctx context.Context, policyDir string, dataJSON []byte, epoch uint64) (*Snapshot, error) {
	data, err := decodeData(dataJSON)
	if err != nil {
		return nil, err
	}
	ensureSmokeFixture(data)

	maskers, err := compileMaskers(data)
	if err != nil {
		return nil, err
	}

	result, err := loader.NewFileLoader().Filtered([]string{policyDir}, bundleFilter)
	if err != nil {
		return nil, fmt.Errorf("policy: %w: %w", ErrCompile, err)
	}

	opts := []func(*rego.Rego){
		rego.Query("data.gateway.authz.decision"),
		rego.Store(inmem.NewFromObject(data)),
		rego.StrictBuiltinErrors(true),
	}
	for _, m := range result.Modules {
		opts = append(opts, rego.ParsedModule(m.Parsed))
	}

	query, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: %w: %w", ErrCompile, err)
	}

	parsedMods := result.ParsedModules()
	ruleIDs := extractRuleIDs(parsedMods)
	stages := extractStages(parsedMods, data)

	return &Snapshot{
		Epoch:    epoch,
		EpochStr: strconv.FormatUint(epoch, 10),
		Query:    query,
		Data:     data,
		Maskers:  maskers,
		Modules:  parsedMods,
		Stages:   stages,
		RuleIDs:  ruleIDs,
		Loaded:   time.Now(),
	}, nil
}

// LoadFiles reads dataPath and calls Load.
func LoadFiles(ctx context.Context, policyDir, dataPath string, epoch uint64) (*Snapshot, error) {
	dataJSON, err := os.ReadFile(dataPath) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, fmt.Errorf("policy: read data %s: %w", dataPath, err)
	}
	return Load(ctx, policyDir, dataJSON, epoch)
}

// bundleFilter keeps only non-test .rego files: *_test.rego never ships in a
// snapshot, and data files under policyDir are ignored in favor of dataJSON.
// Hidden files and AppleDouble (._*) metadata files are skipped.
func bundleFilter(_ string, info os.FileInfo, _ int) bool {
	if info == nil || info.IsDir() {
		return false
	}
	name := info.Name()
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "._") {
		return true
	}
	return !strings.HasSuffix(name, ".rego") || strings.HasSuffix(name, "_test.rego")
}

// decodeData strictly decodes the data document, rejecting non-objects (JSON
// null included), unknown top-level keys so a typo can never silently disable
// part of the policy, and documents missing config or agents — an empty or
// partial document would wipe the policy and disable every registered agent.
func decodeData(dataJSON []byte) (map[string]any, error) {
	var data map[string]any
	if err := json.Unmarshal(dataJSON, &data); err != nil {
		return nil, fmt.Errorf("policy: %w: %w", ErrData, err)
	}
	if data == nil { // JSON null (or an otherwise non-object document)
		return nil, fmt.Errorf("policy: %w: document is not a JSON object", ErrData)
	}
	for k := range data {
		if !allowedTopKeys[k] {
			return nil, fmt.Errorf("policy: %w: unknown top-level key %q", ErrData, k)
		}
	}
	for _, k := range []string{"config", "agents"} {
		if _, ok := data[k]; !ok {
			return nil, fmt.Errorf("policy: %w: missing required top-level key %q", ErrData, k)
		}
	}
	return data, nil
}

// ensureSmokeFixture adds minimal allow fixture agent k-smoke-fixture for dry-run smoke testing.
func ensureSmokeFixture(data map[string]any) {
	if data == nil {
		return
	}
	agents, ok := data["agents"].(map[string]any)
	if !ok || agents == nil {
		agents = make(map[string]any)
		data["agents"] = agents
	}
	if _, ok := agents["k-smoke-fixture"]; !ok {
		agents["k-smoke-fixture"] = map[string]any{
			"name":           "smoke-fixture",
			"allowed_tools":  []any{"bash", "docker rm"},
			"allowed_models": []any{"gpt-4"},
		}
	}
}

// extractRuleIDs extracts all registered rule_id strings from parsed rego AST modules,
// plus internal rule IDs produced by the evaluation engine.
func extractRuleIDs(modules map[string]*ast.Module) map[string]bool {
	ruleIDs := map[string]bool{
		"internal.default":       true,
		"internal.unknown_stage": true,
		"internal.eval_error":    true,
		"internal.timeout":       true,
	}
	vis := ast.NewGenericVisitor(func(x any) bool {
		obj, ok := x.(ast.Object)
		if !ok {
			return false
		}
		obj.Foreach(func(k, v *ast.Term) {
			if s, ok := k.Value.(ast.String); ok && string(s) == "rule_id" {
				if vs, ok := v.Value.(ast.String); ok {
					ruleIDs[string(vs)] = true
				}
			}
		})
		return false
	})
	for _, m := range modules {
		vis.Walk(m)
	}
	return ruleIDs
}

// extractStages extracts registered stages from module package names (stages.<stage>)
// and data document stages.
func extractStages(modules map[string]*ast.Module, data map[string]any) map[string]bool {
	stages := map[string]bool{
		"llm":    true,
		"tool":   true,
		"http":   true,
		"docker": true,
		"ssh":    true,
		"db":     true,
	}
	for _, m := range modules {
		if m.Package != nil && len(m.Package.Path) >= 3 {
			if m.Package.Path[0].Value.String() == "data" && m.Package.Path[1].Value.String() == "stages" {
				stg := strings.Trim(m.Package.Path[2].Value.String(), `"`)
				if stg != "ai" && stg != "" {
					stages[stg] = true
				}
			}
		}
	}
	if rawStages, ok := data["stages"].(map[string]any); ok {
		for s := range rawStages {
			if s != "ai" && s != "" {
				stages[s] = true
			}
		}
	}
	return stages
}

// compileMaskers builds per-key masking rules from agents[*].masking.
func compileMaskers(data map[string]any) (map[string][]masking.Rule, error) {
	agents, _ := data["agents"].(map[string]any)
	maskers := make(map[string][]masking.Rule, len(agents))
	for keyID, a := range agents {
		agent, ok := a.(map[string]any)
		if !ok {
			continue
		}
		raw, ok := agent["masking"].([]any)
		if !ok || len(raw) == 0 {
			continue
		}
		specs, err := decodeMaskingSpecs(raw)
		if err != nil {
			return nil, fmt.Errorf("policy: %w: agent %q masking: %w", ErrData, keyID, err)
		}
		rules, err := masking.Compile(specs)
		if err != nil {
			return nil, fmt.Errorf("policy: %w: agent %q: %w", ErrData, keyID, err)
		}
		maskers[keyID] = rules
	}
	return maskers, nil
}

// decodeMaskingSpecs re-round-trips the generic JSON slice into masking.Specs.
func decodeMaskingSpecs(raw []any) ([]masking.Spec, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var specs []masking.Spec
	if err := json.Unmarshal(b, &specs); err != nil {
		return nil, err
	}
	return specs, nil
}
