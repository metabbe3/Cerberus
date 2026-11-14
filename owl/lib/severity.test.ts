import { describe, expect, it } from "vitest";
import { getSeverity, isBreach, dedupIncidents } from "./severity";

describe("severity mapping", () => {
  it("classifies CRITICAL rules correctly", () => {
    const criticals = [
      "shield.cmd.dangerous",
      "shield.container.protected",
      "shield.prod.ip_blocked",
      "k8s.privilege_escalation",
      "k8s.exec_into_pod",
      "db.destructive_statement",
      "docker.privileged_forbidden",
      "docker.host_root_forbidden",
      "shellguard.unparseable",
    ];

    for (const r of criticals) {
      expect(getSeverity(r)).toBe("CRITICAL");
      expect(isBreach(r, "deny")).toBe(true);
      expect(isBreach(r, "allow")).toBe(false);
    }
  });

  it("classifies HIGH rules correctly", () => {
    const highs = [
      "shield.prod.something",
      "shield.prod.network_isolated",
      "db.sensitive_table",
      "db.write_without_approval",
      "k8s.secret_read",
      "k8s.destructive_verb",
      "ssh.command_denied",
      "ai.prompt.blocked_patterns",
      "ai.tool.blocked_pattern",
    ];

    for (const r of highs) {
      expect(getSeverity(r)).toBe("HIGH");
      expect(isBreach(r, "deny")).toBe(true);
      expect(isBreach(r, "allow")).toBe(false);
    }
  });

  it("classifies MEDIUM rules correctly", () => {
    const mediums = [
      "tool.restricted_access",
      "custom.arg_violation_check",
      "http.host_denied",
      "ops.kill_switch",
    ];

    for (const r of mediums) {
      expect(getSeverity(r)).toBe("MEDIUM");
      expect(isBreach(r, "deny")).toBe(false); // Only CRITICAL and HIGH are breaches
    }
  });

  it("classifies POLICY (non-breach) rules correctly", () => {
    const policies = [
      "tool.not_allowed",
      "ops.rate_limited",
      "ai.llm.budget_exceeded",
      "ai.llm.budget_daily",
    ];

    for (const r of policies) {
      expect(getSeverity(r)).toBe("POLICY");
      expect(isBreach(r, "deny")).toBe(false);
    }
  });

  it("deduplicates incidents per key_id, rule_id, day", () => {
    const events = [
      { key_id: "agent-1", rule_id: "shield.cmd.dangerous", time: "2026-11-14T10:00:00Z", stage: "tool" },
      { key_id: "agent-1", rule_id: "shield.cmd.dangerous", time: "2026-11-14T10:05:00Z", stage: "tool" },
      { key_id: "agent-1", rule_id: "db.destructive_statement", time: "2026-11-14T10:06:00Z", stage: "db" },
      { key_id: "agent-2", rule_id: "shield.cmd.dangerous", time: "2026-11-14T10:07:00Z", stage: "tool" },
      { key_id: "agent-1", rule_id: "shield.cmd.dangerous", time: "2026-11-13T10:00:00Z", stage: "tool" }, // different day
    ];

    const incidents = dedupIncidents(events);
    expect(incidents).toHaveLength(4);

    const ag1Today = incidents.find(
      (i) => i.key_id === "agent-1" && i.rule_id === "shield.cmd.dangerous" && i.date === "2026-11-14"
    );
    expect(ag1Today).toBeDefined();
    expect(ag1Today?.count).toBe(2);
    expect(ag1Today?.last_seen).toBe("2026-11-14T10:05:00Z");
    expect(ag1Today?.severity).toBe("CRITICAL");
  });
});
