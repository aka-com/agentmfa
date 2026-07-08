#!/usr/bin/env bash
set -euo pipefail

# Notarized macOS release: the universal signed .app + .dmg from
# scripts/build.sh, submitted to Apple's notary service, stapled, and
# validated. Release artifacts must go through this flow (README: Developer
# ID signed, notarized, and stapled before distribution); local dev builds
# only need build.sh.
#
# Notary credentials, either form:
#   NOTARYTOOL_KEYCHAIN_PROFILE   profile stored once via
#                                 `xcrun notarytool store-credentials`
#   APPLE_ID + APPLE_PASSWORD + APPLE_TEAM_ID
#                                 Apple ID with an app-specific password
#
# APPLE_SIGNING_IDENTITY is auto-detected by build.sh when unset.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
repo_root="$(cd "$script_dir/.." >/dev/null && pwd)"
cd "$repo_root"

if [[ "$(uname)" != "Darwin" ]]; then
  echo "release.sh builds and notarizes macOS bundles; run it on macOS." >&2
  exit 1
fi

notary_args=()
if [[ -n "${NOTARYTOOL_KEYCHAIN_PROFILE:-}" ]]; then
  notary_args=(--keychain-profile "$NOTARYTOOL_KEYCHAIN_PROFILE")
elif [[ -n "${APPLE_ID:-}" && -n "${APPLE_PASSWORD:-}" && -n "${APPLE_TEAM_ID:-}" ]]; then
  notary_args=(--apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID")
else
  echo "Set NOTARYTOOL_KEYCHAIN_PROFILE, or APPLE_ID + APPLE_PASSWORD + APPLE_TEAM_ID." >&2
  exit 1
fi

# Build with the Tauri bundler's own notarization disabled (it activates on
# the same APPLE_ID/APPLE_API_* variables): one notarization path, this one.
env -u APPLE_ID -u APPLE_PASSWORD -u APPLE_TEAM_ID \
    -u APPLE_API_ISSUER -u APPLE_API_KEY -u APPLE_API_KEY_PATH \
    bash "$script_dir/build.sh"

bundle_dir="$repo_root/src-tauri/target/universal-apple-darwin/release/bundle"
app="$bundle_dir/macos/AgentMFA.app"
dmg="$(ls "$bundle_dir"/dmg/AgentMFA_*.dmg)"

# Notarizing the DMG covers the nested .app; staple both so each artifact
# passes Gatekeeper offline whether distributed as a DMG or a bare .app.
xcrun notarytool submit "$dmg" --wait "${notary_args[@]}"
xcrun stapler staple "$dmg"
xcrun stapler staple "$app"

xcrun stapler validate "$dmg"
xcrun stapler validate "$app"
spctl --assess --type open --context context:primary-signature -v "$dmg"

echo "Release artifacts ready:"
echo "  $dmg"
echo "  $app"
