#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
repo_root="$(cd "$script_dir/.." >/dev/null && pwd)"
cd "$repo_root"

cargo build "$@"
"$repo_root/node_modules/.bin/tsx" "$script_dir/print-cargo-build-output.ts" "$@"
