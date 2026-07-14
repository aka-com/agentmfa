#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="$repo_root/dev/sandbox/compose.yaml"
state_dir="$repo_root/dev/sandbox/state"

if [[ "${1:-}" == "--yes" ]]; then
  confirmed=true
elif [[ $# -gt 0 ]]; then
  echo "usage: $0 [--yes]" >&2
  exit 2
else
  confirmed=false
  read -r -p "Delete all AKA sandbox containers, volumes, and generated SSH keys? [y/N] " answer
  case "$answer" in
    y|Y|yes|YES) confirmed=true ;;
  esac
fi

if ! $confirmed; then
  echo "Sandbox reset cancelled."
  exit 0
fi

docker compose -f "$compose_file" down --volumes --remove-orphans
rm -rf "$state_dir"

echo "Sandbox reset. The next npm run sandbox:up will create new SSH identities."
