import { z } from "zod";

/**
 * Zod mirror of the engine's data JSON (internal/policy/loader.go decodeData).
 * The engine strictly validates only the top-level keys and masking rules;
 * nested fields pass through untouched, so nested objects stay loose here —
 * unknown fields survive the editor round-trip instead of being dropped.
 */

// One masking rule as compiled by internal/masking.Compile: a valid regex
// (engine also rejects patterns matching ""), transform redact|mask|hash,
// scope args|response|"" ("" = both).
export const MaskingRuleSchema = z
  .object({
    pattern: z
      .string()
      .refine((p) => {
        try {
          new RegExp(p);
          return true;
        } catch {
          return false;
        }
      }, "pattern is not a valid regex"),
    transform: z.enum(["redact", "mask", "hash"]),
    scope: z.enum(["args", "response", ""]).optional(),
  })
  .loose();

export type MaskingRule = z.infer<typeof MaskingRuleSchema>;

// One tool argument constraint, in any of the four forms authz.rego reads
// (data.template.json "tool_argument_constraints"): a bare string array, or
// an object tagged allowlist | regex_allow | range. Anything else the engine
// tolerates (the tool stays unconstrained) — the loose catch-all keeps it.
export const ToolConstraintSchema = z.union([
  z.array(z.string()),
  z.object({ type: z.literal("allowlist"), values: z.array(z.string()) }).loose(),
  z.object({ type: z.literal("regex_allow"), patterns: z.array(z.string()) }).loose(),
  z.object({ type: z.literal("range"), min: z.number(), max: z.number() }).loose(),
  z.record(z.string(), z.unknown()),
]);

export type ToolConstraint = z.infer<typeof ToolConstraintSchema>;

// log_level / risk_tier are display-only metadata (authz.rego never reads
// them), so they stay plain strings here rather than an enum that would
// reject documents the engine accepts.
export const AgentSchema = z
  .object({
    name: z.string().optional(),
    description: z.string().optional(),
    team_id: z.string().optional(),
    allowed_models: z.array(z.string()).optional(),
    allowed_tools: z.array(z.string()).optional(),
    restricted_tools: z.array(z.string()).optional(),
    allowed_tool_calls: z.array(z.string()).optional(),
    restricted_tool_calls: z.array(z.string()).optional(),
    tool_argument_constraints: z
      .record(z.string(), z.record(z.string(), ToolConstraintSchema))
      .optional(),
    budget_limit: z.number().optional(),
    risk_tier: z.string().optional(),
    log_level: z.string().optional(),
    prod_access: z.boolean().optional(),
    masking: z.array(MaskingRuleSchema).optional(),
  })
  .loose();

export type Agent = z.infer<typeof AgentSchema>;

export const TeamSchema = z
  .object({
    name: z.string().optional(),
    allowed_models: z.array(z.string()).optional(),
    allowed_tools: z.array(z.string()).optional(),
    budget_limit: z.number().optional(),
  })
  .loose();

export type Team = z.infer<typeof TeamSchema>;

// authz.rego treats an absent flag as false (fail-closed); the template sets
// both true while onboarding.
export const ConfigSchema = z
  .object({
    bypass_unknown_teams: z.boolean().optional(),
    bypass_unknown_keys: z.boolean().optional(),
  })
  .loose();

export type Config = z.infer<typeof ConfigSchema>;

// AuditEvent mirrors internal/audit.Event, the SSE frame and /v1/audit row.
export const AuditEventSchema = z.object({
  id: z.number(),
  time: z.string(),
  stage: z.string(),
  key_id: z.string(),
  subject: z.string(),
  decision: z.string(),
  rule_id: z.string(),
  reason: z.string(),
  epoch: z.number(),
  cached: z.boolean(),
  latency_us: z.number(),
  args: z.record(z.string(), z.unknown()).optional(),
});

export type AuditEvent = z.infer<typeof AuditEventSchema>;

// Top level: exactly the engine's allowedTopKeys, with config and agents
// required (decodeData refuses documents missing either).
export const CerberusDataSchema = z
  .strictObject({
    _comment: z.string().optional(),
    config: ConfigSchema,
    teams: z.record(z.string(), TeamSchema).optional(),
    agents: z.record(z.string(), AgentSchema),
    blocked_patterns: z.array(z.string()).optional(),
    domains: z.record(z.string(), z.unknown()).optional(),
    prod_shield: z.record(z.string(), z.unknown()).optional(),
  });

export type CerberusData = z.infer<typeof CerberusDataSchema>;

export function parseData(data: unknown): CerberusData {
  return CerberusDataSchema.parse(data);
}
