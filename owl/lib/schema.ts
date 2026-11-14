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

export const RateLimitSchema = z
  .object({
    requests_per_minute: z.number().optional(),
    bursts: z.number().optional(),
    tool_calls_per_hour: z.number().optional(),
    daily_tool_calls: z.number().optional(),
  })
  .loose();

export type RateLimit = z.infer<typeof RateLimitSchema>;

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
    capture: z.boolean().optional(),
    hold_and_verify: z.boolean().optional(),
    masking: z.array(MaskingRuleSchema).optional(),
    rate_limit: RateLimitSchema.optional(),
  })
  .loose();

export type Agent = z.infer<typeof AgentSchema>;

export const UpstreamConfigSchema = z
  .object({
    endpoint: z.string(),
    key_hint: z.string(),
    updated_by: z.string().optional(),
    updated_at: z.string().optional(),
  })
  .loose();

export type UpstreamConfig = z.infer<typeof UpstreamConfigSchema>;

export const TurnRowSchema = z
  .object({
    ts: z.string(),
    key_id: z.string(),
    model: z.string(),
    kind: z.string(),
    payload: z.unknown(),
    latency_ms: z.number().optional(),
    status: z.number().optional(),
  })
  .loose();

export type TurnRow = z.infer<typeof TurnRowSchema>;

export const TeamSchema = z
  .object({
    name: z.string().optional(),
    allowed_models: z.array(z.string()).optional(),
    allowed_tools: z.array(z.string()).optional(),
    budget_limit: z.number().optional(),
  })
  .loose();

export type Team = z.infer<typeof TeamSchema>;

export const KillSwitchSchema = z
  .object({
    global: z.boolean().optional(),
    keys: z.record(z.string(), z.boolean()).optional(),
  })
  .loose();

export type KillSwitch = z.infer<typeof KillSwitchSchema>;

// authz.rego treats an absent flag as false (fail-closed); the template sets
// both true while onboarding.
export const ConfigSchema = z
  .object({
    bypass_unknown_teams: z.boolean().optional(),
    bypass_unknown_keys: z.boolean().optional(),
    kill_switch: KillSwitchSchema.optional(),
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
  first_seen: z.boolean().optional(),
});

export type AuditEvent = z.infer<typeof AuditEventSchema>;

export const DangerousCmdPatternSchema = z
  .object({
    id: z.string(),
    regex: z.string(),
    description: z.string().optional(),
    enabled: z.boolean().optional(),
  })
  .loose();

export type DangerousCmdPattern = z.infer<typeof DangerousCmdPatternSchema>;

export const ProdShieldSchema = z
  .object({
    dangerous_cmd_patterns: z.array(DangerousCmdPatternSchema).optional(),
    protected_containers: z.array(z.string()).optional(),
    cidrs: z.array(z.string()).optional(),
    host_keywords: z.array(z.string()).optional(),
    db_keywords: z.array(z.string()).optional(),
    exempt_keys: z.array(z.string()).optional(),
    protected_paths: z.array(z.string()).optional(),
  })
  .loose();

export type ProdShield = z.infer<typeof ProdShieldSchema>;

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
    prod_shield: ProdShieldSchema.optional(),
    // New stages (e.g. ssh from sprint 8) may add top-level data sections;
    // accept-and-passthrough so dashboards on newer engines keep working.
    ssh: z.record(z.string(), z.unknown()).optional(),
  });

export type CerberusData = z.infer<typeof CerberusDataSchema>;

export function parseData(data: unknown): CerberusData {
  return CerberusDataSchema.parse(data);
}

export interface BreachSummary {
  critical: number;
  high: number;
  medium: number;
  total: number;
}

export interface BreachBucket {
  bucket_ns: number;
  critical: number;
  high: number;
  medium: number;
}

export interface TopOffender {
  key_id: string;
  count: number;
  critical_count: number;
  last_time: string;
  top_rule_id: string;
}

export interface BreachResult {
  summary: BreachSummary;
  buckets: BreachBucket[];
  top_offenders: TopOffender[];
  events: AuditEvent[];
}

export interface AgentSummary {
  key_id: string;
  total: number;
  deny: number;
  breach_count: number;
  last_active: string;
  daily_tool_calls: number;
  rate_limit_hits?: number;
}

export interface RotateKeyResult {
  ok: boolean;
  old_key_id: string;
  new_key_id: string;
  revoked_old: boolean;
  epoch: number;
}

export interface PolicyModuleItem {
  file: string;
  package: string;
  sha256: string;
  size: number;
  mtime: string;
}

export interface TestCaseResult {
  name: string;
  package: string;
  pass: boolean;
  duration_ms: number;
  msg?: string;
}

export interface TestRunResponse {
  passed: number;
  failed: number;
  total: number;
  duration_ms: number;
  tests: TestCaseResult[];
}

