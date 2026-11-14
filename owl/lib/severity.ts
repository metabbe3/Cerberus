/**
 * Severity mapping and breach definition for Cerberus Owl.
 * Source: BRIEF U (Arbitrase final Hermes / Argon / Opus)
 *
 * CRITICAL:
 *   - shield.cmd.dangerous
 *   - shield.container.protected
 *   - shield.prod.ip_blocked
 *   - k8s.privilege_escalation
 *   - k8s.exec_into_pod
 *   - db.destructive_statement
 *   - docker.privileged_forbidden
 *   - docker.host_root_forbidden
 *   - shellguard.unparseable
 *
 * HIGH:
 *   - shield.prod.*
 *   - db.sensitive_table
 *   - db.write_without_approval
 *   - k8s.secret_read
 *   - k8s.destructive_verb
 *   - ssh.command_denied
 *   - ai.*.blocked_pattern(s)
 *
 * MEDIUM:
 *   - *.restricted*
 *   - *.arg_violation*
 *   - *.host_denied*
 *   - ops.kill_switch
 *
 * POLICY (bukan breach):
 *   - *.not_allowed
 *   - ops.rate_limited
 *   - ai.llm.budget_*
 *
 * BREACH definition: HANYA deny security-rule (CRITICAL + HIGH).
 * Rate/quota/not_allowed = warning/info, DILUAR breach center.
 */

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "POLICY" | "LOW";

export const SUPPORTED_STAGES = [
  "llm",
  "tool",
  "http",
  "docker",
  "ssh",
  "db",
  "k8s",
] as const;

export type SupportedStage = (typeof SUPPORTED_STAGES)[number];

const CRITICAL_RULES = new Set([
  "shield.cmd.dangerous",
  "shield.container.protected",
  "shield.prod.ip_blocked",
  "k8s.privilege_escalation",
  "k8s.exec_into_pod",
  "db.destructive_statement",
  "docker.privileged_forbidden",
  "docker.host_root_forbidden",
  "shellguard.unparseable",
]);

const HIGH_EXACT_RULES = new Set([
  "db.sensitive_table",
  "db.write_without_approval",
  "k8s.secret_read",
  "k8s.destructive_verb",
  "ssh.command_denied",
]);

/**
 * Determine severity level of a given rule_id.
 */
export function getSeverity(ruleId: string): Severity {
  if (!ruleId) return "POLICY";
  const r = ruleId.trim();

  // 1. CRITICAL exact match
  if (CRITICAL_RULES.has(r)) {
    return "CRITICAL";
  }

  // 2. HIGH match
  if (r.startsWith("shield.prod.")) {
    return "HIGH";
  }
  if (HIGH_EXACT_RULES.has(r)) {
    return "HIGH";
  }
  if (r.startsWith("ai.") && r.includes("blocked_pattern")) {
    return "HIGH";
  }

  // 3. POLICY (check before medium pattern match to avoid false flags)
  if (r.includes(".not_allowed") || r === "ops.rate_limited" || r.startsWith("ai.llm.budget_")) {
    return "POLICY";
  }

  // 4. MEDIUM match
  if (
    r.includes(".restricted") ||
    r.includes(".arg_violation") ||
    r.includes(".host_denied") ||
    r === "ops.kill_switch"
  ) {
    return "MEDIUM";
  }

  // Security prefixes that default to MEDIUM if not matched above
  if (
    r.startsWith("shield.") ||
    r.startsWith("k8s.") ||
    r.startsWith("db.") ||
    r.startsWith("docker.") ||
    r.startsWith("ssh.") ||
    r.startsWith("shellguard.")
  ) {
    return "MEDIUM";
  }

  return "POLICY";
}

/**
 * Return true if the event constitutes a security breach:
 * Deny on a security rule (CRITICAL or HIGH).
 */
export function isBreach(ruleId: string, decision?: string): boolean {
  if (decision && decision.toLowerCase() !== "deny") {
    return false;
  }
  const sev = getSeverity(ruleId);
  return sev === "CRITICAL" || sev === "HIGH";
}

export interface SeverityBadgeConfig {
  label: string;
  badgeClass: string;
}

export function getSeverityBadge(severity: Severity): SeverityBadgeConfig {
  switch (severity) {
    case "CRITICAL":
      return {
        label: "CRITICAL",
        badgeClass: "bg-red-500/15 text-red-700 dark:text-red-400 border-red-500/30 font-semibold",
      };
    case "HIGH":
      return {
        label: "HIGH",
        badgeClass: "bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30 font-semibold",
      };
    case "MEDIUM":
      return {
        label: "MEDIUM",
        badgeClass: "bg-yellow-500/15 text-yellow-700 dark:text-yellow-400 border-yellow-500/30 font-medium",
      };
    case "POLICY":
      return {
        label: "POLICY",
        badgeClass: "bg-muted text-muted-foreground border-border font-normal",
      };
    default:
      return {
        label: severity,
        badgeClass: "bg-muted text-muted-foreground border-border font-normal",
      };
  }
}

export interface Incident<T = unknown> {
  id: string;
  key_id: string;
  rule_id: string;
  date: string; // YYYY-MM-DD
  severity: Severity;
  count: number;
  first_seen: string;
  last_seen: string;
  sample_event: T;
  stages: string[];
}

/**
 * Dedup raw audit events into incidents grouped by (key_id, rule_id, day).
 */
export function dedupIncidents<T extends { key_id: string; rule_id: string; time: string; stage?: string }>(
  events: T[],
): Incident<T>[] {
  const map = new Map<string, Incident<T>>();

  for (const ev of events) {
    const day = ev.time ? ev.time.slice(0, 10) : new Date().toISOString().slice(0, 10);
    const key = `${ev.key_id}::${ev.rule_id}::${day}`;
    const sev = getSeverity(ev.rule_id);

    const existing = map.get(key);
    if (!existing) {
      map.set(key, {
        id: key,
        key_id: ev.key_id,
        rule_id: ev.rule_id,
        date: day,
        severity: sev,
        count: 1,
        first_seen: ev.time,
        last_seen: ev.time,
        sample_event: ev,
        stages: ev.stage ? [ev.stage] : [],
      });
    } else {
      existing.count += 1;
      if (new Date(ev.time) > new Date(existing.last_seen)) {
        existing.last_seen = ev.time;
        existing.sample_event = ev;
      }
      if (new Date(ev.time) < new Date(existing.first_seen)) {
        existing.first_seen = ev.time;
      }
      if (ev.stage && !existing.stages.includes(ev.stage)) {
        existing.stages.push(ev.stage);
      }
    }
  }

  // Sort incidents by last_seen descending
  return Array.from(map.values()).sort(
    (a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime(),
  );
}

export interface SecuritySignal<T = unknown> {
  id: string; // fingerprint hash
  key_id: string;
  rule_id: string;
  normalized_reason: string;
  severity: Severity;
  count: number;
  first_seen: string;
  last_seen: string;
  is_new: boolean;
  sample_event: T;
  events: T[];
  stages: string[];
}

/**
 * Group events into security signals using fingerprint hash(rule_id+key_id+normalized_reason) in a 15m window.
 */
export function groupSecuritySignals<T extends { key_id: string; rule_id: string; reason?: string; time: string; stage?: string; first_seen?: boolean }>(
  events: T[],
  windowMinutes = 15,
): SecuritySignal<T>[] {
  const windowMs = windowMinutes * 60 * 1000;
  const groups = new Map<string, SecuritySignal<T>>();

  for (const ev of events) {
    const timeMs = new Date(ev.time).getTime();
    const windowStart = Math.floor(timeMs / windowMs) * windowMs;
    const normReason = (ev.reason ?? "").toLowerCase().trim().replace(/\s+/g, " ");
    const fingerprint = `${ev.rule_id}::${ev.key_id}::${normReason}::${windowStart}`;
    const sev = getSeverity(ev.rule_id);

    const existing = groups.get(fingerprint);
    if (!existing) {
      groups.set(fingerprint, {
        id: fingerprint,
        key_id: ev.key_id,
        rule_id: ev.rule_id,
        normalized_reason: normReason,
        severity: sev,
        count: 1,
        first_seen: ev.time,
        last_seen: ev.time,
        is_new: Boolean(ev.first_seen),
        sample_event: ev,
        events: [ev],
        stages: ev.stage ? [ev.stage] : [],
      });
    } else {
      existing.count += 1;
      existing.events.push(ev);
      if (ev.first_seen) existing.is_new = true;
      if (new Date(ev.time) > new Date(existing.last_seen)) {
        existing.last_seen = ev.time;
        existing.sample_event = ev;
      }
      if (new Date(ev.time) < new Date(existing.first_seen)) {
        existing.first_seen = ev.time;
      }
      if (ev.stage && !existing.stages.includes(ev.stage)) {
        existing.stages.push(ev.stage);
      }
    }
  }

  return Array.from(groups.values()).sort(
    (a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime(),
  );
}
