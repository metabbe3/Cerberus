import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CerberusDataSchema, parseData } from "./schema";

const template = JSON.parse(
  readFileSync(new URL("../../data.template.json", import.meta.url), "utf8"),
);

describe("CerberusDataSchema", () => {
  it("parses the engine's data.template.json", () => {
    const data = parseData(template);
    expect(Object.keys(data.agents)).toHaveLength(4);
    expect(data.config.bypass_unknown_keys).toBe(true);
  });

  it("rejects an unknown top-level key", () => {
    expect(() =>
      CerberusDataSchema.parse({ ...template, evil: true }),
    ).toThrow();
  });

  it("rejects an invalid masking transform", () => {
    const bad = structuredClone(template);
    bad.agents.EXAMPLE_key_id_allowlist_agent.masking = [
      { pattern: "sk-", transform: "shout", scope: "args" },
    ];
    expect(() => CerberusDataSchema.parse(bad)).toThrow();
  });

  it("accepts all four tool_argument_constraints forms", () => {
    const constraint =
      template.agents.EXAMPLE_key_id_tool_argument_constraints_agent.tool_argument_constraints.bash;
    const parsed = CerberusDataSchema.parse(template);
    expect(parsed.agents.EXAMPLE_key_id_tool_argument_constraints_agent.tool_argument_constraints?.bash).toEqual(constraint);
  });

  it("requires config and agents", () => {
    expect(() => CerberusDataSchema.parse({ config: template.config })).toThrow();
  });

  it("preserves unknown nested fields the engine passes through", () => {
    const withExtra = structuredClone(template);
    withExtra.agents.EXAMPLE_key_id_allowlist_agent.future_field = { x: 1 };
    const parsed = parseData(withExtra);
    expect(
      (parsed.agents.EXAMPLE_key_id_allowlist_agent as Record<string, unknown>).future_field,
    ).toEqual({ x: 1 });
  });
});
