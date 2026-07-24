#!/usr/bin/env bash
set -euo pipefail

# Verify every npm artifact before publishing anything, then publish the four
# platform packages before the launcher. Extra arguments are passed to every
# `npm publish` invocation, e.g. `npm run npm:publish -- --dry-run`.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
repo_root="$(cd "$script_dir/.." >/dev/null && pwd)"
cd "$repo_root"

node scripts/npm/sync-versions.mjs --check
node scripts/npm/verify-package.mjs --all

packages=(
  agentmfa-darwin-arm64
  agentmfa-darwin-x64
  agentmfa-linux-arm64
  agentmfa-linux-x64
  agentmfa
)

for package in "${packages[@]}"; do
  echo "publishing $package"
  (cd "npm/$package" && npm publish "$@")
done
