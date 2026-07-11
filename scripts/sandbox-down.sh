#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_root/dev/sandbox/compose.yaml"

docker compose -f "$compose_file" down --remove-orphans

echo "Sandbox stopped. Generated SSH client and server identities were preserved."
