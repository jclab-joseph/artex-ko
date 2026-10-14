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
  echo "----- agent-md logs (tail) -----" >&2
  $COMPOSE logs --tail=40 agent-md 2>&1 >&2 || true
  echo "----- provision logs -----" >&2
  $COMPOSE logs provision 2>&1 >&2 || true
  echo "----- provision-md logs -----" >&2
  $COMPOSE logs provision-md 2>&1 >&2 || true
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
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o e2e/dist/mcpstub ./e2e/mcpstub
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

# 5b. REVERSE direction (mgmt-dials-agent): the 'agent-md' container LISTENS on :8791
#     and Management dials OUT to it via POST /api/exec-agents/dial. Proves the
#     Management→Agent connection path + mTLS pin, then runs Bash through it.
AGENT_MD_ID="e2e-agent-md"
say "Dialing the listening agent '$AGENT_MD_ID' (mgmt-dials-agent) at agent-md:8791"
for i in $(seq 1 30); do
  DIALCODE="$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/dial" \
    -H 'Content-Type: application/json' -d "{\"agent_id\":\"$AGENT_MD_ID\",\"address\":\"agent-md:8791\"}")"
  [[ "$DIALCODE" == "200" ]] && { ok "dialed agent-md (HTTP 200)"; break; }
  [[ $i == 30 ]] && fail "could not dial agent-md (last HTTP $DIALCODE)"
  sleep 2
done
# It must now appear in the registry alongside the agent-dials one.
curl -fsS "${AUTH[@]}" "$MGMT_URL/api/exec-agents" | python3 -c "
import sys, json
ids = [a.get('id') for a in json.load(sys.stdin).get('agents', [])]
assert '$AGENT_MD_ID' in ids, 'dialed agent not registered: %r' % ids
print('assertion passed: mgmt-dials agent registered (%r)' % ids)
" || fail "mgmt-dials agent not registered"
# Drive Bash through the mgmt-dials agent (the reverse-direction channel works too).
MDMARK="ARTEX_MD_OK_$RANDOM"
MDRESP="$(curl -fsS "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_MD_ID/exec" \
  -H 'Content-Type: application/json' \
  -d "{\"tool\":\"Bash\",\"input\":{\"command\":\"echo $MDMARK; uname -n\"}}")"
echo "$MDRESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('is_error') is not True, 'mgmt-dials exec errored: %r' % d
assert '$MDMARK' in d.get('output',''), 'marker missing: %r' % d
print('assertion passed: Bash ran via the mgmt-dials (Management→Agent) channel')
" || fail "mgmt-dials Bash execution failed"

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

# 7b. Exercise an execution SERVICE (the enrich DNS prober) in the sandbox. Asserts the
#     service ran and returned a well-formed result (not that any record resolved, so the
#     check does not depend on outbound DNS being reachable).
say "Executing the DNS service (__artex_dns) in the sandbox"
DNSRESP="$(curl -fsS "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/exec" \
  -H 'Content-Type: application/json' \
  -d '{"tool":"__artex_dns","input":{"host":"example.com"}}')"
echo "$DNSRESP" | python3 -m json.tool
echo "$DNSRESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('is_error') is not True, 'dns service errored: %r' % d
json.loads(d.get('output','') or '{}')  # output must be valid JSON {a,aaaa,cname}
print('assertion passed: __artex_dns ran in the sandbox and returned JSON')
" || fail "dns service assertion failed"

# 7b-exec-hosting. Interactive shell + background tasks now run IN THE SANDBOX (보안 리뷰
#   F1/F5): the Agent hosts the shell session tools (shell_*) and the background-task
#   Manager (Monitor/Task*). Previously the SDK injected these on the control plane. Drive
#   shell_list (reads the Agent's Manager) and Monitor (spawns a background process in the
#   sandbox) over the channel and assert both ran there without error.
say "Exercising Agent-hosted interactive shell + background tasks (shell_list, Monitor)"
SHRESP="$(curl -fsS "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/exec" \
  -H 'Content-Type: application/json' -d '{"tool":"shell_list","input":{}}')"
echo "$SHRESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('is_error') is not True, 'shell_list errored (shell tools not hosted on agent?): %r' % d
print('assertion passed: shell_list ran on the Agent (interactive shell hosted in sandbox)')
" || fail "agent-hosted shell_list failed"
MONRESP="$(curl -fsS "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/exec" \
  -H 'Content-Type: application/json' -d '{"tool":"Monitor","input":{"command":"echo e2e-monitor; sleep 1","description":"e2e"}}')"
echo "$MONRESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('is_error') is not True, 'Monitor errored (background manager not hosted on agent?): %r' % d
out = d.get('output','')
assert ('Output file' in out) or ('monitor' in out.lower()), 'Monitor did not start a background task: %r' % d
print('assertion passed: Monitor spawned a background task IN the sandbox')
" || fail "agent-hosted Monitor failed"

# 7b-exec-isolation. Per-execution-session isolation (보안 리뷰 F2/F3): each /exec call
#   runs under its OWN execution session that is torn down when the call ends, so a
#   background task started in one call is invisible to — and already reclaimed for —
#   the next. Start a long Monitor, then TaskList in a SEPARATE call and assert it sees
#   no tasks: one session cannot enumerate (hence cannot TaskStop) another's processes,
#   and state does not leak or linger across sessions.
say "Asserting per-session isolation + teardown (Monitor in one session, TaskList in another)"
curl -fsS "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/exec" \
  -H 'Content-Type: application/json' \
  -d '{"tool":"Monitor","input":{"command":"sleep 30","description":"iso-probe"}}' >/dev/null
ISO="$(curl -fsS "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/exec" \
  -H 'Content-Type: application/json' -d '{"tool":"TaskList","input":{}}')"
echo "$ISO" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('is_error') is not True, 'TaskList errored: %r' % d
out = d.get('output','')
assert 'No background tasks' in out, 'another session saw/retained tasks (isolation/teardown broken): %r' % out
print('assertion passed: a background task in one execution session is isolated + reclaimed (invisible to another)')
" || fail "per-session isolation/teardown assertion failed"

# 7b-traffic. Prove the recording store is HOSTED IN THE SANDBOX: make the Agent fetch
#   a target through its own hosted recorder (Bash+curl egress → recorder → target),
#   then drive traffic_search from Management THROUGH the Agent and assert the captured
#   exchange comes back. Both the capture and the query happen only in the sandbox.
say "Capturing a target exchange in the sandbox, then querying it via traffic_search"
CAP="$(curl -fsS "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/exec" \
  -H 'Content-Type: application/json' \
  -d '{"tool":"Bash","input":{"command":"curl -s -o /dev/null -w %{http_code} http://target/"}}')"
echo "$CAP" | python3 -m json.tool
echo "$CAP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('is_error') is not True, 'capture curl errored: %r' % d
assert '200' in d.get('output',''), 'target fetch did not return 200: %r' % d
print('assertion passed: Agent fetched http://target/ through its hosted recorder')
" || fail "sandbox capture fetch failed"

# Give the recorder a moment to flush the exchange to its index, then query it.
for i in $(seq 1 15); do
  TS="$(curl -fsS "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/exec" \
    -H 'Content-Type: application/json' \
    -d '{"tool":"traffic_search","input":{"host":"target"}}')"
  if echo "$TS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
sys.exit(0 if (d.get('is_error') is not True and 'target' in d.get('output','') and d.get('output','').strip() not in ('', '无匹配流量。')) else 1)
" 2>/dev/null; then
    echo "$TS" | python3 -m json.tool
    ok "traffic_search returned the sandbox-captured exchange"
    break
  fi
  [[ $i == 15 ]] && { echo "$TS" | python3 -m json.tool; fail "traffic_search never returned the captured exchange"; }
  sleep 1
done
# (Monitor egress-through-proxy — 보안 리뷰 F4 — is covered deterministically by the
#  remoteexec unit test TestMonitorInheritsEgressEnv: the diagnostic /exec path gives each
#  call its own execution session and tears it down the instant the call returns, which
#  kills a Monitor-spawned background request before it completes, so a captured exchange
#  from it cannot be observed over this endpoint. Bash egress-through-proxy is asserted
#  above; the unit test asserts Monitor inherits the same egress env.)

# 7b-evidence. Prove finding-bind evidence SYNC: the control plane pulls the cited
#   exchange bytes out of the sandbox via the Agent's __artex_traffic_evidence service
#   (the exact call evidence.Store makes when a finding is bound in split mode). Assert
#   a well-formed exchange with non-empty, decodable base64 bodies comes back.
say "Syncing captured evidence out of the sandbox (__artex_traffic_evidence)"
EXID="$(echo "$TS" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.loads(d['output'])[0]['id'])")"
[[ -n "$EXID" ]] || fail "could not extract exchange id from traffic_search"
EV="$(curl -fsS "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/exec" \
  -H 'Content-Type: application/json' \
  -d "{\"tool\":\"__artex_traffic_evidence\",\"input\":{\"ids\":[\"$EXID\"]}}")"
echo "$EV" | python3 -m json.tool
echo "$EV" | python3 -c "
import sys, json, base64
d = json.load(sys.stdin)
assert d.get('is_error') is not True, 'evidence service errored: %r' % d
payload = json.loads(d.get('output','') or '{}')
exs = payload.get('exchanges') or []
assert len(exs) == 1, 'expected 1 exchange, got %r' % payload
e = exs[0]
assert e.get('id') == '$EXID', 'id mismatch: %r' % e
assert not e.get('req_oversize') and not e.get('resp_oversize'), 'small bodies flagged oversize: %r' % e
resp = base64.b64decode(e.get('resp_b64',''))  # must decode
assert e.get('resp_head'), 'missing response head: %r' % e
print('assertion passed: evidence synced from sandbox (resp %d bytes, head present)' % len(resp))
" || fail "evidence sync assertion failed"

# 7b-mcp. Agent-hosted MCP: the bundle told the Agent to host the mcpstub MCP server
#   (a stdio child process in the sandbox); it announced mcp__e2estub__echo with its
#   schema. Drive that tool from Management THROUGH the Agent and assert the echo —
#   proving a real MCP server runs in the sandbox and the control plane routes to it.
say "Driving an Agent-hosted MCP tool (mcp__e2estub__echo) over the channel"
echo "$AGENTS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
tools = (d.get('agents') or [{}])[0].get('tools', [])
assert 'mcp__e2estub__echo' in tools, 'agent did not announce the hosted MCP tool: %r' % tools
print('assertion passed: agent announced mcp__e2estub__echo')
" || fail "agent did not announce the hosted MCP tool"
MCPRESP="$(curl -fsS "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/exec" \
  -H 'Content-Type: application/json' \
  -d '{"tool":"mcp__e2estub__echo","input":{"text":"hello-mcp"}}')"
echo "$MCPRESP" | python3 -m json.tool
echo "$MCPRESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('is_error') is not True, 'MCP tool errored: %r' % d
assert 'mcp-echo:hello-mcp' in d.get('output',''), 'unexpected MCP output: %r' % d
print('assertion passed: Management drove the sandbox-hosted MCP tool and got the echo back')
" || fail "agent-hosted MCP assertion failed"

# 7c. Per-task Agent pinning (multi-agent routing). Pin validates that the task and
#     the agent actually exist, and the pin shows up in GET /api/exec-agents.
say "Pinning a task to the agent, then unpinning"
# Create a real (idle) task to pin to — no LLM needed; the engine just stays idle.
TASK_ID="$(curl -fsS "${AUTH[@]}" -X POST "$MGMT_URL/api/tasks" \
  -H 'Content-Type: application/json' -d '{"description":"e2e pin target"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')"
[[ -n "$TASK_ID" ]] || fail "could not create a task to pin"

# Negative: pinning a non-existent task must be REJECTED (not silently succeed).
BADPIN="$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/pin" \
  -H 'Content-Type: application/json' -d '{"task_id":"no-such-task-999"}')"
[[ "$BADPIN" == "404" ]] || fail "pinning a bogus task should 404 (got HTTP $BADPIN)"

# Positive: pin the real task, and assert it appears in the exec-agents pin map.
PINCODE="$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/pin" \
  -H 'Content-Type: application/json' -d "{\"task_id\":\"$TASK_ID\"}")"
[[ "$PINCODE" == "200" ]] || fail "pin should succeed (got HTTP $PINCODE)"
curl -fsS "${AUTH[@]}" "$MGMT_URL/api/exec-agents" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('pins', {}).get('$TASK_ID') == '$AGENT_ID', 'pin not reflected in list: %r' % d.get('pins')
print('assertion passed: pin for task $TASK_ID → $AGENT_ID visible in exec-agents list')
" || fail "pin not reflected in exec-agents list"

# Unpin and assert it is gone.
UNPINCODE="$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/unpin" \
  -H 'Content-Type: application/json' -d "{\"task_id\":\"$TASK_ID\"}")"
[[ "$UNPINCODE" == "200" ]] || fail "unpin should succeed (got HTTP $UNPINCODE)"
curl -fsS "${AUTH[@]}" "$MGMT_URL/api/exec-agents" | python3 -c "
import sys, json
assert '$TASK_ID' not in json.load(sys.stdin).get('pins', {}), 'pin still present after unpin'
print('assertion passed: pin cleared after unpin')
" || fail "pin still present after unpin"
ok "pin/unpin ok (validated + reflected in list)"

# 8. Negative check: an unknown tool must be rejected by the agent.
say "Negative check: unknown tool is rejected"
BADCODE="$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" -X POST "$MGMT_URL/api/exec-agents/$AGENT_ID/exec" \
  -H 'Content-Type: application/json' -d '{"tool":"NotARealTool","input":{}}')"
[[ "$BADCODE" == "502" || "$BADCODE" == "400" ]] || fail "unknown tool should be rejected (got HTTP $BADCODE)"
ok "unknown tool rejected (HTTP $BADCODE)"

say "E2E PASSED — Management drove Bash in the sandboxed Agent over mTLS and got the result back"
