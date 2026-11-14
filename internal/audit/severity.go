package audit

import "strings"

// Severity represents the security classification of a rule or decision.
type Severity string

// Severity levels for audit events and rule classification.
const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityPolicy   Severity = "POLICY"
)

var criticalRules = map[string]bool{
	"shield.cmd.dangerous":        true,
	"shield.container.protected":  true,
	"shield.prod.ip_blocked":      true,
	"k8s.privilege_escalation":    true,
	"k8s.exec_into_pod":           true,
	"db.destructive_statement":    true,
	"docker.privileged_forbidden": true,
	"docker.host_root_forbidden":  true,
	"shellguard.unparseable":      true,
}

var highExactRules = map[string]bool{
	"db.sensitive_table":        true,
	"db.write_without_approval": true,
	"k8s.secret_read":           true,
	"k8s.destructive_verb":      true,
	"ssh.command_denied":        true,
}

// GetSeverity determines the severity of a rule_id according to BRIEF U2.
func GetSeverity(ruleID string) Severity {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return SeverityPolicy
	}

	// 1. CRITICAL exact match
	if criticalRules[ruleID] {
		return SeverityCritical
	}

	// 2. HIGH matches
	if strings.HasPrefix(ruleID, "shield.prod.") {
		return SeverityHigh
	}
	if highExactRules[ruleID] {
		return SeverityHigh
	}
	if strings.HasPrefix(ruleID, "ai.") && strings.Contains(ruleID, "blocked_pattern") {
		return SeverityHigh
	}

	// 3. POLICY matches (bukan breach)
	if strings.Contains(ruleID, ".not_allowed") || ruleID == "ops.rate_limited" || strings.HasPrefix(ruleID, "ai.llm.budget_") {
		return SeverityPolicy
	}

	// 4. MEDIUM matches
	if strings.Contains(ruleID, ".restricted") ||
		strings.Contains(ruleID, ".arg_violation") ||
		strings.Contains(ruleID, ".host_denied") ||
		ruleID == "ops.kill_switch" {
		return SeverityMedium
	}

	// Known security prefixes default to MEDIUM if not matched above
	if strings.HasPrefix(ruleID, "shield.") ||
		strings.HasPrefix(ruleID, "k8s.") ||
		strings.HasPrefix(ruleID, "db.") ||
		strings.HasPrefix(ruleID, "docker.") ||
		strings.HasPrefix(ruleID, "ssh.") ||
		strings.HasPrefix(ruleID, "shellguard.") {
		return SeverityMedium
	}

	return SeverityPolicy
}

// IsSecurityRule returns true if ruleID is considered a security rule
// (prefixes: shield., k8s., db., docker., ssh., shellguard., or ai.*blocked_pattern*).
func IsSecurityRule(ruleID string) bool {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return false
	}
	// Policy rules are NOT security rules
	if strings.Contains(ruleID, ".not_allowed") || ruleID == "ops.rate_limited" || strings.HasPrefix(ruleID, "ai.llm.budget_") {
		return false
	}
	if strings.HasPrefix(ruleID, "shield.") ||
		strings.HasPrefix(ruleID, "k8s.") ||
		strings.HasPrefix(ruleID, "db.") ||
		strings.HasPrefix(ruleID, "docker.") ||
		strings.HasPrefix(ruleID, "ssh.") ||
		strings.HasPrefix(ruleID, "shellguard.") {
		return true
	}
	if strings.HasPrefix(ruleID, "ai.") && strings.Contains(ruleID, "blocked_pattern") {
		return true
	}
	return false
}

// IsBreach returns true if the event constitutes a security breach:
// decision is "deny" and severity is CRITICAL or HIGH.
func IsBreach(decision, ruleID string) bool {
	if !strings.EqualFold(decision, "deny") {
		return false
	}
	sev := GetSeverity(ruleID)
	return sev == SeverityCritical || sev == SeverityHigh
}
