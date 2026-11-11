-- Cerberus PostgreSQL schema (migration 001).
-- Moves agent/team/policy data from data.json (flat file) and Owl templates
-- from browser localStorage to server-side durable storage.
-- Design: engine keeps its in-memory Snapshot (hot path is eval, not I/O);
-- Postgres is the SYSTEM OF RECORD — engine loads from PG at boot and after
-- every admin PUT, mirroring today's JSON flow 1:1.

CREATE TABLE IF NOT EXISTS agents (
    key_id          TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    team_id         TEXT,
    policy          JSONB NOT NULL,          -- full agent policy doc (allowed_tool_calls, allowed_models, budget_limit, rate_limit, ...)
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS teams (
    team_id         TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    policy          JSONB NOT NULL,          -- team-level policy (allowed_tools, budget, ssh hosts, ...)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS gateway_config (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),  -- singleton row
    config          JSONB NOT NULL,          -- {bypass_unknown_keys, kill_switch, ...}
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- List-valued global policies (injection blocklist etc.)
CREATE TABLE IF NOT EXISTS blocked_patterns (
    pattern         TEXT PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS domains (
    domain          TEXT PRIMARY KEY,
    policy          JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS prod_shield (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    policy          JSONB NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ssh_policy (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    policy          JSONB NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Owl wizard templates (were: browser localStorage owl-templates-v1)
CREATE TABLE IF NOT EXISTS templates (
    template_id     TEXT PRIMARY KEY,        -- slug
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    stage           TEXT NOT NULL DEFAULT 'ai',
    policy          JSONB NOT NULL,          -- wizard policy payload
    builtin         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agents_team ON agents(team_id);
CREATE INDEX IF NOT EXISTS idx_templates_builtin ON templates(builtin);

-- Seed templates from the wizard's 8 built-ins (idempotent ON CONFLICT).
INSERT INTO templates (template_id, name, description, stage, policy, builtin) VALUES
  ('research-readonly',  'Research (Read-Only)',   'http/fetch/search/read; no exec, no write',            'ai', '{"allowed_tool_calls":["http_get","fetch*","search*","read*"],"restricted_tool_calls":["*exec*","*write*","ssh*"]}', true),
  ('ops-ssh',            'Ops (SSH/Docker)',       'ssh/docker/shell ke host tepercaya',                   'ai', '{"allowed_tool_calls":["ssh*","docker*","shell*"]}', true),
  ('llm-cheap-only',     'LLM Cheap-Only',         'hanya model murah (flash/mini/haiku)',                 'ai', '{"allowed_models":["*flash*","*mini*","*haiku*"]}', true),
  ('nightly-batch',      'Nightly Batch',          'http + budget kecil untuk job malam',                  'ai', '{"allowed_tool_calls":["http_get"],"budget_limit":1,"rate_limit":{"requests_per_minute":30}}', true),
  ('http-allowlist',     'HTTP Allowlist',         'hanya domain terdaftar',                              'http', '{"allowed_domains":["api.teknikal.id"]}', true),
  ('ssh-host-allow',     'SSH Host Allowlist',     'hanya host *.teknikal.id',                             'ssh', '{"allow_hosts":["*.teknikal.id"]}', true),
  ('llm-glm-family',     'LLM GLM Family',         'hanya keluarga model glm',                             'ai', '{"allowed_models":["glm-*"]}', true),
  ('full-access',        'Full Access (Trust)',    'tanpa pembatasan tool — hanya untuk owner',            'ai', '{}', true)
ON CONFLICT (template_id) DO NOTHING;
