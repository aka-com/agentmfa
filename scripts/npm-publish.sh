#!/usr/bin/env bash
set -euo pipefail

# Verify every npm artifact before publishing anything, then publish the four
# platform packages before the launcher. Extra arguments are passed to every
# `npm publish` invocation, e.g. `npm run npm:publish -- --dry-run`.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
repo_root="$(cd "$script_dir/.." >/dev/null && pwd)"
cd "$repo_root"

packages=(
  agentmfa-darwin-arm64
  agentmfa-darwin-x64
  agentmfa-linux-arm64
  agentmfa-linux-x64
  agentmfa
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
  if ! maintainers="$(npm view "$package" maintainers --json 2>/dev/null)"; then
    echo "Could not read npm ownership for $package; refusing to publish." >&2
    exit 1
  fi
  if ! node -e '
    const entries = JSON.parse(process.argv[1]);
    const user = process.argv[2];
    const maintainers = Array.isArray(entries) ? entries : [entries];
    const names = maintainers.map((entry) =>
      typeof entry === "string" ? entry.replace(/[ <].*$/, "") : entry.name
    );
    process.exit(names.includes(user) ? 0 : 1);
  ' "$maintainers" "$npm_user"; then
    echo "npm user $npm_user is not a maintainer of $package; refusing to publish." >&2
    exit 1
  fi
done
echo "npm publish preflight passed: authenticated as $npm_user"

node scripts/npm/sync-versions.mjs --check
node scripts/npm/verify-package.mjs --all

for package in "${packages[@]}"; do
  echo "publishing $package"
  (cd "npm/$package" && npm publish "$@")
done
