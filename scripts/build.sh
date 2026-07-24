#!/usr/bin/env bash
set -euo pipefail

# Build the signed macOS bundle (.app + .dmg), by reading the
# APPLE_SIGNING_IDENTITY environment variable, or auto-detecting
# the machine's single Developer ID Application identity as a fallback.
# Notarization is not included. Use scripts/release.sh to also notarize.
#
# The signature is also what decides whether the app can read its own secrets
# without an OS dialog: the entitlements this signs with carry a
# keychain-access-groups entry, and only a build carrying it can use the
# macOS data-protection keychain (see crates/aka-core/src/keychain). That
# entry needs the signing team's ID, so entitlements.signed.plist is generated
# here from the checked-in entitlements.plist rather than committed.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
repo_root="$(cd "$script_dir/.." >/dev/null && pwd)"
cd "$repo_root"

# The sidecar bundle rides along as a Tauri resource, and the pinned Node it
# runs on is an externalBin. Both must exist before the bundler looks for
# them, or the build fails late with a missing-file error.
#
# The externalBin declaration lives in a separate config merged in here,
# not in tauri.conf.json: Tauri validates external binaries on *every*
# build of the shell crate, so declaring it in the base config would make
# `cargo test` require the vendored Node download.
npm run sidecar:build
npm run sidecar:vendor

target_args=()
if [[ "$(uname)" == "Darwin" ]]; then
  if [[ -z "${APPLE_SIGNING_IDENTITY:-}" ]]; then
    identities="$(security find-identity -v -p codesigning | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p')"
    if [[ "$(printf '%s\n' "$identities" | grep -c .)" -ne 1 ]]; then
      echo "Set APPLE_SIGNING_IDENTITY (found identities: ${identities:-none})." >&2
      exit 1
    fi
    export APPLE_SIGNING_IDENTITY="$identities"
    echo "Signing as: $APPLE_SIGNING_IDENTITY"
  fi

  # The team ID prefixes the keychain access group. Signing identities are
  # named "Developer ID Application: Name (TEAMID)", so it can be read off the
  # identity when APPLE_TEAM_ID is not set outright.
  team_id="${APPLE_TEAM_ID:-}"
  if [[ -z "$team_id" ]]; then
    team_id="$(printf '%s' "$APPLE_SIGNING_IDENTITY" | sed -n 's/.*(\([A-Z0-9]\{10\}\))[[:space:]]*$/\1/p')"
  fi

  bundle_id="$(node -p "require('$repo_root/src-tauri/tauri.conf.json').identifier")"
  entitlements="$repo_root/src-tauri/entitlements.signed.plist"
  cp "$repo_root/src-tauri/entitlements.plist" "$entitlements"

  if [[ -n "$team_id" ]]; then
    /usr/libexec/PlistBuddy \
      -c "Add :keychain-access-groups array" \
      -c "Add :keychain-access-groups:0 string ${team_id}.${bundle_id}" \
      "$entitlements" >/dev/null
    echo "Keychain access group: ${team_id}.${bundle_id}"
  elif [[ -n "${AGENTMFA_NO_KEYCHAIN_ENTITLEMENT:-}" ]]; then
    # Deliberate opt-out, for signing setups with no usable team ID. The app
    # still runs; it falls back to the login keychain, which means an OS
    # approval dialog per secret per build.
    echo "WARNING: building without a keychain access group — this app will" >&2
    echo "         prompt for Keychain access on every secret it reads." >&2
  else
    echo "Could not determine the signing team ID from APPLE_SIGNING_IDENTITY." >&2
    echo "Set APPLE_TEAM_ID, or set AGENTMFA_NO_KEYCHAIN_ENTITLEMENT=1 to build" >&2
    echo "without the entitlement and accept a Keychain prompt per secret." >&2
    exit 1
  fi

  # Universal binary: one DMG runs on Apple silicon and Intel. The fat build
  # needs both std targets installed; `rustup target add` is a no-op when
  # they already are.
  rustup target add aarch64-apple-darwin x86_64-apple-darwin
  target_args=(--target universal-apple-darwin)
fi

# CI=true makes the DMG bundler skip the Finder/AppleScript window-layout
# step, which needs Apple-Events automation access and can hang a headless
# or unattended build.
exec env CI=true "$repo_root/node_modules/.bin/tauri" build --config src-tauri/tauri.bundle.conf.json --bundles app,dmg "${target_args[@]}" "$@"
