#!/usr/bin/env bash
set -euo pipefail

# Build the signed macOS bundle (.app + .dmg), by reading the
# APPLE_SIGNING_IDENTITY environment variable, or auto-detecting
# the machine's single Developer ID Application identity as a fallback.
# This allows "Always Allow" keychain selections to persist across builds.
# Notarization is not included. Use scripts/release.sh to also notarize.

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
