#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_root/dev/sandbox/compose.yaml"

docker compose -f "$compose_file" down

echo "Sandbox stopped. Generated SSH state was preserved in dev/sandbox/state/."
