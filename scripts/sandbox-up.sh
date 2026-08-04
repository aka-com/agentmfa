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

if ! docker info >/dev/null 2>&1; then
  echo "sandbox: cannot reach the Docker daemon — start Docker Desktop (or the docker service) and retry" >&2
  exit 1
fi

mkdir -p "$state_dir"
# A `docker compose up` that ran before the key existed leaves empty
# directories where the key files belong; clear them so keygen can run.
for path in "$client_key" "$client_key.pub"; do
  if [[ -d "$path" ]]; then rmdir "$path"; fi
done
if [[ ! -f "$client_key" ]]; then
  echo "Generating a dedicated SSH key for the Multitool sandbox..."
  ssh-keygen -q -t ed25519 -N "" -C aka-sandbox -f "$client_key"
elif [[ ! -f "$client_key.pub" ]]; then
  ssh-keygen -y -f "$client_key" >"$client_key.pub"
fi

if ! docker image inspect aka-sandbox-fixture >/dev/null 2>&1; then
  echo "First start: building the sandbox fixture image — this compiles a small"
  echo "Rust service and can take several minutes. Later starts take seconds."
fi

docker compose -f "$compose_file" up -d --build --remove-orphans
"$repo_root/scripts/sandbox-status.sh" --wait
