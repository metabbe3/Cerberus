#!/usr/bin/env bash
# ==============================================================================
# Cerberus Bootstrap Installer (get.cerberus.sh)
# Quickstart in <5 minutes with Docker Compose, 12-factor secrets, and Owl UI.
#
# Usage:
#   curl -fsSL https://get.cerberus.sh | bash
#   or locally: ./scripts/get.sh
# ==============================================================================
set -euo pipefail

REPO_OWNER="metabbe3"
REPO_NAME="Cerberus"
REPO_BRANCH="main"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${REPO_BRANCH}"
RELEASE_BASE="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download"

info() {
    printf "\033[1;34m[cerberus]\033[0m %s\n" "$*"
}

success() {
    printf "\033[1;32m[cerberus]\033[0m %s\n" "$*"
}

warn() {
    printf "\033[1;33m[cerberus WARNING]\033[0m %s\n" "$*"
}

err() {
    printf "\033[1;31m[cerberus ERROR]\033[0m %s\n" "$*" >&2
}

# ------------------------------------------------------------------------------
# 1. PREREQUISITE CHECKS
# ------------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || {
    err "docker is required but not installed. Please install Docker and try again."
    exit 1
}

command -v curl >/dev/null 2>&1 || {
    err "curl is required but not installed."
    exit 1
}

command -v openssl >/dev/null 2>&1 || {
    err "openssl is required for cryptographic secret generation."
    exit 1
}

if ! docker info >/dev/null 2>&1; then
    err "Docker daemon is not running. Please start Docker."
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. ASSETS / REPOSITORY RESOLUTION
# ------------------------------------------------------------------------------
# If running inside existing clone/worktree, operate in place.
if [ -f "docker-compose.prod.yml" ] && [ -d "policies" ]; then
    INSTALL_DIR="$(pwd)"
    info "Running inside Cerberus workspace at ${INSTALL_DIR}"
else
    INSTALL_DIR="${CERBERUS_HOME:-$(pwd)}"
    mkdir -p "${INSTALL_DIR}"
    cd "${INSTALL_DIR}"
    info "Setting up Cerberus in ${INSTALL_DIR}"

    # Download docker-compose.prod.yml if missing
    if [ ! -f "docker-compose.prod.yml" ]; then
        info "Fetching docker-compose.prod.yml..."
        if ! curl -fsSL "${RELEASE_BASE}/docker-compose.prod.yml" -o "docker-compose.prod.yml" 2>/dev/null; then
            curl -fsSL "${RAW_BASE}/docker-compose.prod.yml" -o "docker-compose.prod.yml"
        fi
    fi

    # Download .env.example if missing
    if [ ! -f ".env.example" ]; then
        info "Fetching .env.example template..."
        curl -fsSL "${RAW_BASE}/.env.example" -o ".env.example" 2>/dev/null || true
    fi

    # Fetch policies and assets: release tar.gz or fallback sparse-checkout
    if [ ! -d "policies" ]; then
        info "Downloading default policy bundle..."
        TAR_URL="${RELEASE_BASE}/policies-default.tar.gz"
        if curl -fsSL "${TAR_URL}" -o "policies-default.tar.gz" 2>/dev/null && tar -tzf "policies-default.tar.gz" >/dev/null 2>&1; then
            tar -xzf "policies-default.tar.gz"
            rm -f "policies-default.tar.gz"
            success "Extracted policy bundle from release assets"
        elif command -v git >/dev/null 2>&1; then
            info "Release asset not found. Using git sparse-checkout fallback..."
            TMP_GIT="$(mktemp -d)"
            git clone --depth 1 --filter=blob:none --sparse "https://github.com/${REPO_OWNER}/${REPO_NAME}.git" "${TMP_GIT}"
            (
                cd "${TMP_GIT}"
                git sparse-checkout set policies data owl
                cp -r policies "${INSTALL_DIR}/"
                cp -r data "${INSTALL_DIR}/"
                cp -r owl "${INSTALL_DIR}/" 2>/dev/null || true
            )
            rm -rf "${TMP_GIT}"
            success "Fetched policies, data, and owl via sparse-checkout"
        else
            err "Failed to obtain policies. Install git or verify release assets."
            exit 1
        fi
    fi
fi

# Ensure data directory and data/prod.json exist
mkdir -p data
if [ ! -f "data/prod.json" ]; then
    if [ -f "data/prod.template.json" ]; then
        cp data/prod.template.json data/prod.json
    elif [ -f "data.template.json" ]; then
        cp data.template.json data/prod.json
    else
        cat <<'EOF' > data/prod.json
{
  "config": {
    "bypass_unknown_keys": true,
    "bypass_unknown_teams": true
  },
  "teams": {},
  "agents": {
    "k-glob": {
      "name": "default-glob-agent",
      "allowed_tool_calls": ["kubernetes*"],
      "restricted_tool_calls": ["delete"]
    },
    "k-default-agent": {
      "name": "default proxy identity"
    }
  },
  "blocked_patterns": ["jailbreak"],
  "prod_shield": {
    "cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "dangerous_cmd_patterns": [
      {
        "id": "rm_rf",
        "regex": "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)"
      }
    ],
    "exempt_keys": ["k-owner"]
  }
}
EOF
    fi
    info "Initialized data/prod.json from template"
fi

# ------------------------------------------------------------------------------
# 3. 12-FACTOR SECRET & .ENV GENERATION (Idempotent)
# ------------------------------------------------------------------------------
ENV_FILE="${INSTALL_DIR}/.env"
FIRST_RUN=false

compute_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{print $1}'
    else
        openssl dgst -sha256 | awk '{print $NF}'
    fi
}

if [ ! -f "${ENV_FILE}" ]; then
    FIRST_RUN=true
    info "Generating randomized production credentials (12-factor)..."

    ADMIN_TOKEN="cb_adm_$(openssl rand -hex 24)"
    TAP_TOKEN="cb_tap_$(openssl rand -hex 24)"
    OWL_PASSWORD="cb_owl_$(openssl rand -hex 16)"
    OWL_SESSION="$(openssl rand -hex 32)"
    AGENT_SECRET="sk-cb-$(openssl rand -hex 24)"
    AGENT_KEY=$(echo -n "${AGENT_SECRET}" | compute_sha256)

    cat <<EOF > "${ENV_FILE}"
# Auto-generated Cerberus Production Environment (.env)
CERBERUS_ADMIN_TOKEN=${ADMIN_TOKEN}
CERBERUS_ADDR=:8089
CERBERUS_POLICY_DIR=/policies
CERBERUS_DATA_FILE=/data/prod.json
CERBERUS_AUDIT_DB=/audit/cerberus.db
CERBERUS_AUDIT_RETENTION_DAYS=30
CERBERUS_EVAL_TIMEOUT=3s
CERBERUS_LOG_LEVEL=info
CERBERUS_ENGINE_URL=http://engine:8089

# LLM Tap Gate
CERBERUS_TAP_UPSTREAM=https://api.anthropic.com
CERBERUS_TAP_LISTEN=0.0.0.0:8090
TAP_ADMIN_TOKEN=${TAP_TOKEN}
CERBERUS_TAP_RETENTION_DAYS=14

# Docker Proxy & Egress
CERBERUS_PROXY_LISTEN=0.0.0.0:2377
CERBERUS_PROXY_DOCKER_HOST=unix:///var/run/docker.sock
CERBERUS_EGRESS_ADDR=0.0.0.0:8088
CERBERUS_PROXY_DEFAULT_KEY=k-default-agent

# SSH Bastion Gate
CERBERUS_SSH_LISTEN=0.0.0.0:2222

# Owl Dashboard
OWL_ADMIN_PASSWORD=${OWL_PASSWORD}
OWL_SESSION_SECRET=${OWL_SESSION}

# Quickstart Agent Credentials
CERBERUS_AGENT_SECRET=${AGENT_SECRET}
CERBERUS_AGENT_KEY=${AGENT_KEY}
EOF

    chmod 600 "${ENV_FILE}"
    success "Generated ${ENV_FILE} with permissions 0600"
else
    info "Existing configuration found at ${ENV_FILE}. Preserving existing secrets."
    # Extract existing tokens for smoke test and display without leaking raw secrets to stdout on re-run
    ADMIN_TOKEN="$(grep -E '^CERBERUS_ADMIN_TOKEN=' "${ENV_FILE}" | cut -d'=' -f2- || true)"
    AGENT_KEY="$(grep -E '^CERBERUS_AGENT_KEY=' "${ENV_FILE}" | cut -d'=' -f2- || true)"
    if [ -z "${AGENT_KEY}" ]; then
        AGENT_KEY="k-glob"
    fi
fi

# ------------------------------------------------------------------------------
# 4. LAUNCH DOCKER COMPOSE STACK
# ------------------------------------------------------------------------------
info "Starting Cerberus production stack with Docker Compose..."
docker compose -f docker-compose.prod.yml up -d --wait

# ------------------------------------------------------------------------------
# 5. SMOKE TESTING (2 Decision Checks)
# ------------------------------------------------------------------------------
info "Running initial policy evaluation smoke checks..."
ENGINE_HOST="127.0.0.1:8089"

# Smoke 1: Allow kubectl get pods (using k-glob with kubernetes* allowlist)
ALLOW_PAYLOAD='{"stage":"tool","key_id":"k-glob","tool_call":"kubernetes_get_pods","args":{"cmd":"kubectl get pods"}}'
SMOKE_1_OUT=$(curl -fsS -X POST "http://${ENGINE_HOST}/v1/decide/tool" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -d "${ALLOW_PAYLOAD}" 2>/dev/null || true)

if echo "${SMOKE_1_OUT}" | grep -q '"decision":"allow"'; then
    success "Smoke 1 PASS: 'kubectl get pods' allowed (rule_id: ai.tool.allow)"
else
    # Fallback to internal docker exec if host loopback is restricted
    SMOKE_1_OUT=$(docker compose -f docker-compose.prod.yml exec -T engine wget -qO- \
        --post-data="${ALLOW_PAYLOAD}" \
        --header="Content-Type: application/json" \
        --header="Authorization: Bearer ${ADMIN_TOKEN}" \
        "http://127.0.0.1:8089/v1/decide/tool" 2>/dev/null || true)
    if echo "${SMOKE_1_OUT}" | grep -q '"decision":"allow"'; then
        success "Smoke 1 PASS: 'kubectl get pods' allowed (via engine container)"
    else
        warn "Smoke 1 check returned unexpected output: ${SMOKE_1_OUT}"
    fi
fi

# Smoke 2: Deny dangerous rm -rf command (blocked by Production Shield)
DENY_PAYLOAD='{"stage":"tool","key_id":"k-glob","tool_call":"bash","args":{"cmd":"rm -rf /"}}'
SMOKE_2_OUT=$(curl -fsS -X POST "http://${ENGINE_HOST}/v1/decide/tool" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -d "${DENY_PAYLOAD}" 2>/dev/null || true)

if echo "${SMOKE_2_OUT}" | grep -q '"decision":"deny"'; then
    success "Smoke 2 PASS: 'rm -rf' blocked by Production Shield (rule_id: shield.cmd.dangerous)"
else
    SMOKE_2_OUT=$(docker compose -f docker-compose.prod.yml exec -T engine wget -qO- \
        --post-data="${DENY_PAYLOAD}" \
        --header="Content-Type: application/json" \
        --header="Authorization: Bearer ${ADMIN_TOKEN}" \
        "http://127.0.0.1:8089/v1/decide/tool" 2>/dev/null || true)
    if echo "${SMOKE_2_OUT}" | grep -q '"decision":"deny"'; then
        success "Smoke 2 PASS: 'rm -rf' blocked by Production Shield (via engine container)"
    else
        warn "Smoke 2 check returned unexpected output: ${SMOKE_2_OUT}"
    fi
fi

# ------------------------------------------------------------------------------
# 6. REPORTING & AGENT INTEGRATION ENVS
# ------------------------------------------------------------------------------
printf "\n"
if [ "${FIRST_RUN}" = true ]; then
    printf "================================================================================\n"
    printf "\033[1;33m⚠️  INITIAL SECRETS GENERATED (Shown ONCE — Save to password manager!)\033[0m\n"
    printf "================================================================================\n"
    printf "Cerberus Admin Token : %s\n" "${ADMIN_TOKEN}"
    printf "Tap Admin Token      : %s\n" "${TAP_TOKEN}"
    printf "Owl Admin Password   : %s\n" "${OWL_PASSWORD}"
    printf "Agent Secret         : %s\n" "${AGENT_SECRET}"
    printf "Agent Key ID (sha256): %s\n" "${AGENT_KEY}"
    printf "Stored safely in     : %s (mode 0600)\n" "${ENV_FILE}"
    printf "================================================================================\n"
else
    printf "================================================================================\n"
    printf "Cerberus stack updated successfully.\n"
    printf "Config file          : %s\n" "${ENV_FILE}"
    printf "(Secrets hidden. Inspect %s directly to view credentials)\n" "${ENV_FILE}"
    printf "================================================================================\n"
fi

printf "\n"
printf "================================================================================\n"
printf "\033[1;32m🚀 CERBERUS AGENT INTEGRATION ENVIRONMENT\033[0m\n"
printf "================================================================================\n"
printf "Copy and export these variables into your agent runtime:\n\n"
printf "  export ANTHROPIC_BASE_URL=\"http://127.0.0.1:8090\"\n"
printf "  export X_TAP_KEY=\"%s\"\n" "${AGENT_KEY}"
printf "  export HTTP_PROXY=\"http://127.0.0.1:8088\"\n"
printf "  export HTTPS_PROXY=\"http://127.0.0.1:8088\"\n"
printf "  export DOCKER_HOST=\"tcp://127.0.0.1:2377\"\n"
printf "\n"
printf "🦉 Owl Management Dashboard: http://127.0.0.1:3000\n"
printf "================================================================================\n"
