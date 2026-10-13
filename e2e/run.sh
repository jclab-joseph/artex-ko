#!/usr/bin/env bash
#
# End-to-end test for the Management ↔ sandboxed-Agent split.
#
# It builds the two binaries, brings up postgres + management + a sandboxed agent via
# docker-compose, then drives a Bash tool call from the Management Server THROUGH the
# agent over mTLS — proving dangerous execution happens only in the sandbox, that the
# bidirectional mTLS channel works, and that output flows back. No LLM key required.
#
# Usage:  e2e/run.sh            (build, run, assert, tear down)
#         KEEP=1 e2e/run.sh     (leave the stack up for inspection on exit)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

COMPOSE="docker compose -f e2e/docker-compose.yml -p artex-e2e"
MGMT_URL="http://127.0.0.1:8787"
ADMIN_PW="e2e-admin-password"
AGENT_ID="e2e-agent"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
fail() { printf '\n\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; dump_logs; exit 1; }
ok()   { printf '\033[1;32m%s\033[0m\n' "$*"; }

dump_logs() {
  echo "----- management logs (tail) -----" >&2
  $COMPOSE logs --tail=40 management 2>&1 >&2 || true
  echo "----- agent logs (tail) -----" >&2
  $COMPOSE logs --tail=40 agent 2>&1 >&2 || true
  echo "----- provision logs -----" >&2
  $COMPOSE logs provision 2>&1 >&2 || true
}

cleanup() {
  if [[ "${KEEP:-0}" == "1" ]]; then
    say "KEEP=1 set — leaving stack up ($COMPOSE down -v to clean)"
    return
  fi
  say "Tearing down"
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Build the binaries on the host (pure Go, CGO off) into e2e/dist.
say "Building artex and artex-agent (linux/amd64)"
mkdir -p e2e/dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o e2e/dist/artex ./cmd/artex
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o e2e/dist/artex-agent ./cmd/artex-agent
ok "binaries built"

# 2. Bring the stack up. compose orders it: postgres → management(healthy) →
#    provision(one-shot, mints the bundle) → agent(dials in over mTLS).
say "Starting stack (postgres, management, provision, agent)"
$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up -d --build

# 3. Wait for the management API.
say "Waiting for management API"
for i in $(seq 1 40); do
  if curl -fsS "$MGMT_URL/api/health" >/dev/null 2>&1; then ok "management healthy"; break; fi
  [[ $i == 40 ]] && fail "management API never became healthy"
  sleep 2
done

# 4. Log in (ARTEX_ADMIN_PASSWORD auto-initialised the admin account).
say "Authenticating"
TOKEN="$(curl -fsS -X POST "$MGMT_URL/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"ARTEX\",\"password\":\"$ADMIN_PW\"}" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')"
[[ -n "$TOKEN" ]] || fail "could not obtain auth token"
ok "authenticated"
AUTH=(-H "Authorization: Bearer $TOKEN")

# 5. Wait for the sandboxed agent to dial in and register.
say "Waiting for agent '$AGENT_ID' to connect over mTLS"
for i in $(seq 1 40); do
  AGENTS="$(curl -fsS "${AUTH[@]}" "$MGMT_URL/api/exec-agents" 2>/dev/null || echo '{}')"
  if echo "$AGENTS" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if any(a.get('id')=='$AGENT_ID' for a in d.get('agents',[])) else 1)" 2>/dev/null; then
    ok "agent connected"
    echo "$AGENTS" | python3 -m json.tool
    break
  fi
  [[ $i == 40 ]] && fail "agent never connected"
  sleep 2
done

# 6. Drive a Bash tool call from Management THROUGH the agent over mTLS.
say "Executing Bash on the agent via the control plane"
MARKER="ARTEX_E2E_OK_$RANDOM"
RESP="$(curl -fsS "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/exec" \
  -H 'Content-Type: application/json' \
  -d "{\"tool\":\"Bash\",\"input\":{\"command\":\"echo $MARKER; uname -n; id -un\"}}")"
echo "$RESP" | python3 -m json.tool

# 7. Assert the marker came back and the call did not error.
echo "$RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('is_error') is not True, 'tool reported error: %r' % d
assert '$MARKER' in d.get('output',''), 'marker not in output: %r' % d
print('assertion passed: output contains $MARKER, is_error=%s' % d.get('is_error'))
" || fail "execution assertion failed"

# 8. Negative check: an unknown tool must be rejected by the agent.
say "Negative check: unknown tool is rejected"
BADCODE="$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/exec" \
  -H 'Content-Type: application/json' -d '{"tool":"NotARealTool","input":{}}')"
[[ "$BADCODE" == "502" || "$BADCODE" == "400" ]] || fail "unknown tool should be rejected (got HTTP $BADCODE)"
ok "unknown tool rejected (HTTP $BADCODE)"

say "E2E PASSED — Management drove Bash in the sandboxed Agent over mTLS and got the result back"
