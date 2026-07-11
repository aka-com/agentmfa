#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_root/dev/sandbox/compose.yaml"
client_key="$repo_root/dev/sandbox/state/ssh/client_key"
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
  curl --fail --silent --show-error --max-time 2 http://127.0.0.1:18080/status/200 >/dev/null
}

check_websocket_server() {
  curl --fail --silent --show-error --max-time 2 http://127.0.0.1:18081/ >/dev/null
}

check_postgres() {
  docker compose -f "$compose_file" exec -T postgres \
    pg_isready -U agentmfa -d agentmfa_sandbox >/dev/null
}

scan_ssh_host_key() {
  ssh-keyscan -T 2 -t ed25519 -p 12222 127.0.0.1 2>/dev/null
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

HTTP API
  Origin:     http://127.0.0.1:18080
  Secret:     agentmfa-test-token
  Template:   Authorization: Bearer {{HTTPBIN_TOKEN}}

WebSocket
  URL:        ws://127.0.0.1:18081
  Secret:     agentmfa-ws-test-token
  Template:   Authorization: Bearer {{WEBSOCKET_TOKEN}}

Postgres
  Host:       127.0.0.1
  Port:       15432
  Database:   agentmfa_sandbox
  User:       agentmfa
  Password:   agentmfa-test-password
  SSL mode:   disable

SSH
  Host:       127.0.0.1
  Port:       12222
  User:       sandbox
  Private key: $client_key
  Host key:   $ssh_fingerprint
EOF
