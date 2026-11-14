package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ScenarioSpace models the statistical sampling space described in montecarlo-argon §1.
type ScenarioSpace struct {
	Version       string          `json:"version"`
	Distribution  DistributionCfg `json:"distribution"`
	StagesWeights StagesCfg       `json:"stages_weights"`
	ToolCalls     ToolCallsCfg    `json:"tool_calls"`
	Generators    GeneratorsCfg   `json:"generators"`
	Mutators      MutatorsCfg     `json:"mutators"`
	ChainsMatrix  ChainsMatrixCfg `json:"chains_matrix"`
	OracleChains  []OracleChain   `json:"oracle_chains"`
}

type DistributionCfg struct {
	RiilRatio        float64 `json:"riil_ratio"`
	AdversarialRatio float64 `json:"adversarial_ratio"`
}

type StagesCfg struct {
	Riil              map[string]float64 `json:"riil"`
	AdversarialStages []string           `json:"adversarial_stages"`
}

type ToolCallsCfg struct {
	RiilWeight        float64  `json:"riil_weight"`
	AdversarialWeight float64  `json:"adversarial_weight"`
	Riil              []string `json:"riil"`
	Adversarial       []string `json:"adversarial"`
}

type GeneratorsCfg struct {
	ArgsCmd   ArgsCmdCfg  `json:"args_cmd"`
	ArgsSQL   ArgsSQLCfg  `json:"args_sql"`
	ArgsHost  ArgsHostCfg `json:"args_host"`
	K8s       K8sCfg      `json:"k8s"`
	Databases []string    `json:"databases"`
	Docker    DockerCfg   `json:"docker"`
	SSH       SSHCfg      `json:"ssh"`
}

type ArgsCmdCfg struct {
	Riil           []string       `json:"riil"`
	AdversarialAST AdversarialAST `json:"adversarial_ast"`
}

type AdversarialAST struct {
	Pipes       []string `json:"pipes"`
	Semicolons  []string `json:"semicolons"`
	Redirects   []string `json:"redirects"`
	Heredocs    []string `json:"heredocs"`
	Subshells   []string `json:"subshells"`
	RandomFlags []string `json:"random_flags"`
	BinaryPaths []string `json:"binary_paths"`
}

type ArgsSQLCfg struct {
	Riil              []string          `json:"riil"`
	AdversarialBypass AdversarialSQLCfg `json:"adversarial_bypass"`
}

type AdversarialSQLCfg struct {
	CTEs               []string `json:"ctes"`
	Subqueries         []string `json:"subqueries"`
	MultiStmt          []string `json:"multi_stmt"`
	Comments           []string `json:"comments"`
	CopyTo             []string `json:"copy_to"`
	DangerousFunctions []string `json:"dangerous_functions"`
}

type ArgsHostCfg struct {
	Riil          []string         `json:"riil"`
	AdversarialIP AdversarialIPCfg `json:"adversarial_ip"`
}

type AdversarialIPCfg struct {
	DecimalOctal []string `json:"decimal_octal"`
	IPv6Mapped   []string `json:"ipv6_mapped"`
	Metadata     []string `json:"metadata"`
}

type K8sCfg struct {
	Verbs      []string   `json:"verbs"`
	Namespaces []string   `json:"namespaces"`
	Flags      [][]string `json:"flags"`
}

type DockerCfg struct {
	Containers []string `json:"containers"`
	Actions    []string `json:"actions"`
}

type SSHCfg struct {
	Users []string `json:"users"`
	Hosts []string `json:"hosts"`
}

type MutatorsCfg struct {
	Encodings     []string `json:"encodings"`
	Unicodes      []string `json:"unicodes"`
	Lengths       []int    `json:"lengths"`
	NestingDepths []int    `json:"nesting_depths"`
}

type ChainsMatrixCfg struct {
	Sources []string `json:"sources"`
	Sinks   []string `json:"sinks"`
}

type OracleChain struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Step1       map[string]any `json:"step1"`
	Expected1   OracleVerdict  `json:"expected1"`
	Step2       map[string]any `json:"step2,omitempty"`
	Expected2   *OracleVerdict `json:"expected2,omitempty"`
}

type OracleVerdict struct {
	Decision   string `json:"decision"`
	RuleFamily string `json:"rule_family"`
}

// LoadScenarioSpace reads and parses scenario-space.json.
func LoadScenarioSpace(path string) (*ScenarioSpace, error) {
	cleanPath := filepath.Clean(path)
	b, err := os.ReadFile(cleanPath) //nolint:gosec // user specified scenario space
	if err != nil {
		return nil, fmt.Errorf("read scenario space %q: %w", path, err)
	}
	var space ScenarioSpace
	if err := json.Unmarshal(b, &space); err != nil {
		return nil, fmt.Errorf("unmarshal scenario space %q: %w", path, err)
	}
	return &space, nil
}
