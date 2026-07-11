#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_root/dev/sandbox/compose.yaml"
state_dir="$repo_root/dev/sandbox/state/ssh"
client_key="$state_dir/client_key"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "sandbox: $1 is required" >&2
    exit 1
  fi
}

require_command docker
require_command ssh-keygen

if ! docker compose version >/dev/null 2>&1; then
  echo "sandbox: Docker Compose v2 is required (docker compose)" >&2
  exit 1
fi

mkdir -p "$state_dir/config"
if [[ ! -f "$client_key" ]]; then
  echo "Generating a dedicated SSH key for the AgentMFA sandbox..."
  ssh-keygen -q -t ed25519 -N "" -C agentmfa-sandbox -f "$client_key"
elif [[ ! -f "$client_key.pub" ]]; then
  ssh-keygen -y -f "$client_key" >"$client_key.pub"
fi

docker compose -f "$compose_file" up -d
"$repo_root/scripts/sandbox-status.sh" --wait
