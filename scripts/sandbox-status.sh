#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_root/dev/sandbox/compose.yaml"
client_key="$repo_root/dev/sandbox/state/ssh/client_key"
# Keep these defaults in sync with dev/sandbox/compose.yaml, which reads the
# same SANDBOX_*_PORT variables. Export an override for both commands, e.g.
#   SANDBOX_HTTP_PORT=28080 npm run sandbox:up
http_port="${SANDBOX_HTTP_PORT:-18080}"
ws_port="${SANDBOX_WS_PORT:-18081}"
pg_port="${SANDBOX_PG_PORT:-15432}"
ssh_port="${SANDBOX_SSH_PORT:-12222}"
wait_for_services=false

if [[ "${1:-}" == "--wait" ]]; then
  wait_for_services=true
elif [[ $# -gt 0 ]]; then
  echo "usage: $0 [--wait]" >&2
  exit 2
fi

for command in docker curl ssh-keyscan ssh-keygen; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "sandbox: $command is required" >&2
    exit 1
  fi
done

if [[ ! -f "$client_key" ]]; then
  echo "sandbox: SSH client key is missing; run npm run sandbox:up" >&2
  exit 1
fi

check_http() {
  curl --fail --silent --max-time 2 "http://127.0.0.1:$http_port/health" >/dev/null 2>&1
}

check_websocket_server() {
  local response
  response="$(
    curl --silent --include --no-buffer --max-time 2 --http1.1 \
      --header 'Connection: Upgrade' \
      --header 'Upgrade: websocket' \
      --header 'Sec-WebSocket-Version: 13' \
      --header 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
      --header 'Authorization: Bearer agentmfa-ws-test-token' \
      "http://127.0.0.1:$ws_port/ws" 2>/dev/null || true
  )"
  [[ "$response" == "HTTP/1.1 101 "* ]]
}

check_postgres() {
  # TCP, not the Unix socket: initdb's temporary first-boot server answers
  # on the socket while the real server is not accepting connections yet.
  docker compose -f "$compose_file" exec -T postgres \
    pg_isready -h 127.0.0.1 -U agentmfa -d agentmfa_sandbox >/dev/null 2>&1
}

scan_ssh_host_key() {
  ssh-keyscan -T 2 -t ed25519 -p "$ssh_port" 127.0.0.1 2>/dev/null
}

check_ssh() {
  scan_ssh_host_key >/dev/null
}

wait_for() {
  local label="$1"
  shift
  local attempt
  for attempt in {1..30}; do
    if "$@"; then
      echo "  ready: $label"
      return 0
    fi
    sleep 1
  done
  echo "sandbox: timed out waiting for $label" >&2
  return 1
}

if $wait_for_services; then
  echo "Waiting for sandbox services..."
  wait_for HTTP check_http
  wait_for WebSocket check_websocket_server
  wait_for Postgres check_postgres
  wait_for SSH check_ssh
else
  docker compose -f "$compose_file" ps
  echo
fi

host_keys="$(scan_ssh_host_key)"
if [[ -z "$host_keys" ]]; then
  echo "sandbox: SSH is not ready; run npm run sandbox:up" >&2
  exit 1
fi
fingerprint_line="$(printf '%s\n' "$host_keys" | ssh-keygen -lf -)"
read -r _ ssh_fingerprint _ <<<"$fingerprint_line"

cat <<EOF

AgentMFA sandbox services

In AgentMFA, open Services → “Add a service for your agent”, pick the
type, paste the Quick setup line, and press Continue. It pre-fills the
form; the values below cover the remaining fields (and manual entry).
Press Test on each service after saving it.

HTTP API
  Quick setup:      http://127.0.0.1:$http_port
  Name:             sandbox-http
  API root:         http://127.0.0.1:$http_port
  Authentication:   Bearer token
  Credential name:  SANDBOX_HTTP_TOKEN
  Credential value: agentmfa-test-token

WebSocket
  Quick setup:      ws://127.0.0.1:$ws_port/ws
  Name:             sandbox-websocket
  URL:              ws://127.0.0.1:$ws_port/ws
  Authentication:   Bearer token
  Credential name:  SANDBOX_WEBSOCKET_TOKEN
  Credential value: agentmfa-ws-test-token

Postgres
  Quick setup:      postgres://agentmfa:agentmfa-test-password@127.0.0.1:$pg_port/agentmfa_sandbox?sslmode=disable
  Name:             sandbox-postgres
  Host / Port:      127.0.0.1 / $pg_port
  Database / User:  agentmfa_sandbox / agentmfa
  TLS mode:         Disable (the container has no TLS)
  Database password: agentmfa-test-password

SSH
  Quick setup:      ssh -i $client_key -p $ssh_port sandbox@127.0.0.1
  Name:             sandbox-ssh
  User / Host / Port: sandbox / 127.0.0.1 / $ssh_port
  Identity file:    $client_key
                    (pre-selected by the Quick setup line; AgentMFA reads
                    the key file itself — no need to paste key contents)
  Host key fingerprint (optional): $ssh_fingerprint
                    Leave blank to confirm and pin it at the first connection.

Details and agent-driven checks: dev/sandbox/README.md
EOF
