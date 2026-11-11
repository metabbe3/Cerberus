#!/usr/bin/env bash
# deploy/harden-macmini.sh
# Hardening script for Cerberus on Mac Mini (idempotent, dry-run by default)
# Usage:
#   ./deploy/harden-macmini.sh         # Dry-run
#   ./deploy/harden-macmini.sh --apply # Apply changes

set -euo pipefail

APPLY=false
if [[ "${1:-}" == "--apply" ]]; then
  APPLY=true
fi

echo "=========================================================="
echo "   CERBERUS MAC MINI HARDENING AUDIT & REMEDIATION"
echo "   Mode: $(if [[ "$APPLY" == true ]]; then echo "APPLY (live changes)"; else echo "DRY-RUN (pass --apply to execute)"; fi)"
echo "=========================================================="

# 1. Audit databases permission hardening (/tmp/cerberus*.db, /tmp/audit-*.db)
echo -e "\n[1] Checking SQLite Audit DB permissions in /tmp..."
FOUND_DBS=$(find -L /tmp -maxdepth 1 -type f \( -name "cerberus*.db*" -o -name "audit-*.db*" \) 2>/dev/null || find /private/tmp -maxdepth 1 -type f \( -name "cerberus*.db*" -o -name "audit-*.db*" \))

if [[ -z "$FOUND_DBS" ]]; then
  echo "  No audit DB files found in /tmp."
else
  while IFS= read -r dbfile; do
    [[ -z "$dbfile" ]] && continue
    CUR_PERM=$(stat -f "%Lp" "$dbfile" 2>/dev/null || stat -c "%a" "$dbfile" 2>/dev/null)
    if [[ "$CUR_PERM" != "640" && "$CUR_PERM" != "600" ]]; then
      echo "  Insecure permissions on $dbfile: $CUR_PERM (target: 0640)"
      if [[ "$APPLY" == true ]]; then
        chmod 0640 "$dbfile"
        echo "    -> Applied chmod 0640 $dbfile"
      else
        echo "    -> [DRY-RUN] would run: chmod 0640 $dbfile"
      fi
    else
      echo "  OK: $dbfile has safe permissions ($CUR_PERM)"
    fi
  done <<< "$FOUND_DBS"
fi

# 2. Duplicate proxy instances cleanup (port 2376)
echo -e "\n[2] Checking duplicate proxy instances on port 2376..."
PID_2376=$(lsof -ti :2376 2>/dev/null || true)

if [[ -n "$PID_2376" ]]; then
  CMD_2376=$(ps -p "$PID_2376" -o command= 2>/dev/null || echo "unknown")
  echo "  Found duplicate proxy on port 2376 (PID $PID_2376): $CMD_2376"
  if [[ "$APPLY" == true ]]; then
    kill "$PID_2376"
    echo "    -> Killed duplicate proxy PID $PID_2376"
  else
    echo "    -> [DRY-RUN] would kill PID $PID_2376 (port 2376)"
  fi
else
  echo "  OK: No duplicate proxy running on port 2376."
fi

# 3. /tmp/owl_deploy.env permissions check
echo -e "\n[3] Checking /tmp/owl_deploy.env permissions..."
ENV_FILE="/tmp/owl_deploy.env"
if [[ -f "$ENV_FILE" ]]; then
  CUR_ENV_PERM=$(stat -f "%Lp" "$ENV_FILE" 2>/dev/null || stat -c "%a" "$ENV_FILE" 2>/dev/null)
  if [[ "$CUR_ENV_PERM" != "600" ]]; then
    echo "  Insecure permissions on $ENV_FILE: $CUR_ENV_PERM (target: 0600)"
    if [[ "$APPLY" == true ]]; then
      chmod 0600 "$ENV_FILE"
      echo "    -> Applied chmod 0600 $ENV_FILE"
    else
      echo "    -> [DRY-RUN] would run: chmod 0600 $ENV_FILE"
    fi
  else
    echo "  OK: $ENV_FILE has secure permissions ($CUR_ENV_PERM)"
  fi
else
  echo "  Note: $ENV_FILE not found."
fi

# 4. Final summary and residual risk documentation
echo -e "\n[4] Active Cerberus Gateways & Residual Risk Report:"
echo "----------------------------------------------------------"
echo "  Active Listening Ports:"
lsof -i :2377 -i :8088 -i :8089 2>/dev/null | grep -v COMMAND | awk '{printf "    - %-12s PID %-6s listening on %s\n", $1, $2, $9}' || echo "    None detected"

DOCKER_SOCK="/Users/nicholasandriansurjadi/.docker/run/docker.sock"
[[ ! -e "$DOCKER_SOCK" ]] && DOCKER_SOCK="/var/run/docker.sock"
if [[ -e "$DOCKER_SOCK" ]]; then
  SOCK_PERM=$(ls -l "$DOCKER_SOCK" | awk '{print $1, $3":"$4}')
  echo -e "\n  Original Docker Socket:"
  echo "    Path:        $DOCKER_SOCK"
  echo "    Permissions: $SOCK_PERM"
  echo "    Accessibility: REACHABLE by current user nicholasandriansurjadi"
  echo "    RESIDUAL RISK NOTICE: In macOS/OrbStack user-owned Docker environments,"
  echo "    the local user account owns the unix socket. Full kernel-level sandboxing"
  echo "    is not enforced against the host user. Docker enforcer proxy is advisory"
  echo "    for host processes unless DOCKER_HOST points to 127.0.0.1:2377."
  echo "    Recommendation: Keep DOCKER_HOST=tcp://127.0.0.1:2377 in agent environments"
  echo "    and route egress through HTTP_PROXY=http://127.0.0.1:8088."
fi
echo "=========================================================="
