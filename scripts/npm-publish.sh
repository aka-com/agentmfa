#!/usr/bin/env bash
set -euo pipefail

# Verify every npm artifact before publishing anything, then publish the four
# platform packages before the launcher. Extra arguments are passed to every
# `npm publish` invocation, e.g. `npm run npm:publish -- --dry-run`.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
repo_root="$(cd "$script_dir/.." >/dev/null && pwd)"
cd "$repo_root"

packages=(
  multitool-darwin-arm64
  multitool-darwin-x64
  multitool-linux-arm64
  multitool-linux-x64
  multitool
)

# `npm publish --dry-run` never authenticates with the registry, so it can
# give false confidence when the configured token is expired or belongs to an
# account that cannot publish these packages. Check both before spending time
# verifying artifacts or uploading the first package.
if ! npm_user="$(npm whoami 2>/dev/null)"; then
  echo "npm authentication failed; refusing to publish." >&2
  echo "Run: npm login --registry=https://registry.npmjs.org/ --auth-type=web" >&2
  exit 1
fi

for package in "${packages[@]}"; do
  published="@aka-com/$package"
  if ! view_output="$(npm view "$published" maintainers --json 2>&1)"; then
    if [[ "$view_output" == *"E404"* ]]; then
      echo "$published is not published yet; npm will verify scope access on first publish."
      continue
    fi
    echo "Could not inspect maintainers for $published; refusing to publish." >&2
    echo "$view_output" >&2
    exit 1
  fi
  maintainers="$view_output"
  if ! node -e '
    const entries = JSON.parse(process.argv[1]);
    const user = process.argv[2];
    const maintainers = Array.isArray(entries) ? entries : [entries];
    const names = maintainers.map((entry) =>
      typeof entry === "string" ? entry.replace(/[ <].*$/, "") : entry.name
    );
    process.exit(names.includes(user) ? 0 : 1);
  ' "$maintainers" "$npm_user"; then
    echo "npm user $npm_user is not a maintainer of $published; refusing to publish." >&2
    exit 1
  fi
done
echo "npm publish preflight passed: authenticated as $npm_user"

node scripts/npm/sync-versions.mjs --check
node scripts/npm/verify-package.mjs --all

for package in "${packages[@]}"; do
  echo "publishing @aka-com/$package"
  (cd "npm/$package" && npm publish "$@")
done
