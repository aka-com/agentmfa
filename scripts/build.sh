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
#
# Two ways to carry that entitlement, because Apple's rules for restricted
# entitlements under Developer ID are not something to bet a release on:
#
#   default                       keychain-access-groups alone, no
#                                 provisioning profile.
#   APPLE_PROVISIONING_PROFILE=…  also adds com.apple.application-identifier
#                                 and embeds the named .provisionprofile,
#                                 which authorizes both.
#
# The default is the lighter setup and, as far as we can tell, sufficient. If
# a build from it will not launch ("The application cannot be opened"), that
# is macOS rejecting an unauthorized restricted entitlement: get a Developer
# ID provisioning profile for this app id that includes the Keychain Sharing
# capability and point APPLE_PROVISIONING_PROFILE at it. Runtime behaviour is
# identical either way — the app probes what it can actually reach and falls
# back to the login keychain — so the only thing at stake here is whether the
# entitlement is honoured at all. DEVELOPING.md has the whole story.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
repo_root="$(cd "$script_dir/.." >/dev/null && pwd)"
cd "$repo_root"

# Load ignored, machine-local build settings when present. Preserve variables
# the caller explicitly exported so CI and one-off command-line overrides take
# precedence over .env. `set -a` makes ordinary NAME=value entries available
# to the programs this script launches.
if [[ -f "$repo_root/.env" ]]; then
  inherited_names=()
  inherited_values=()
  while IFS= read -r name; do
    inherited_names+=("$name")
    inherited_values+=("${!name}")
  done < <(compgen -e)

  set -a
  # shellcheck disable=SC1091
  source "$repo_root/.env"
  set +a

  for ((i = 0; i < ${#inherited_names[@]}; i++)); do
    export "${inherited_names[$i]}=${inherited_values[$i]}"
  done
  unset inherited_names inherited_values name i
fi

# build.sh deliberately signs but does not notarize. Do not let credentials
# loaded from .env activate Tauri's separate automatic notarization path;
# release.sh owns submission and stapling.
unset APPLE_ID APPLE_PASSWORD APPLE_API_ISSUER APPLE_API_KEY APPLE_API_KEY_PATH

target_args=()
bundle_config="src-tauri/tauri.bundle.conf.json"
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

  profile=""
  if [[ -n "${APPLE_PROVISIONING_PROFILE:-}" ]]; then
    if [[ -n "${MULTITOOL_NO_KEYCHAIN_ENTITLEMENT:-${AGENTMFA_NO_KEYCHAIN_ENTITLEMENT:-}}" ]]; then
      echo "APPLE_PROVISIONING_PROFILE and MULTITOOL_NO_KEYCHAIN_ENTITLEMENT ask for" >&2
      echo "opposite things. Unset one." >&2
      exit 1
    fi
    if [[ ! -f "$APPLE_PROVISIONING_PROFILE" ]]; then
      echo "APPLE_PROVISIONING_PROFILE is not a file: $APPLE_PROVISIONING_PROFILE" >&2
      exit 1
    fi
    # Absolute: it goes into a Tauri config that the bundler resolves from
    # its own directory, not this one.
    profile="$(cd "$(dirname "$APPLE_PROVISIONING_PROFILE")" >/dev/null && pwd)/$(basename "$APPLE_PROVISIONING_PROFILE")"
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
  elif [[ -n "${MULTITOOL_NO_KEYCHAIN_ENTITLEMENT:-${AGENTMFA_NO_KEYCHAIN_ENTITLEMENT:-}}" ]]; then
    # Deliberate opt-out, for signing setups with no usable team ID. The app
    # still runs; it falls back to the login keychain, which means an OS
    # approval dialog per secret per build.
    echo "WARNING: building without a keychain access group — this app will" >&2
    echo "         prompt for Keychain access on every secret it reads." >&2
  else
    echo "Could not determine the signing team ID from APPLE_SIGNING_IDENTITY." >&2
    echo "Set APPLE_TEAM_ID, or set MULTITOOL_NO_KEYCHAIN_ENTITLEMENT=1 to build" >&2
    echo "without the entitlement and accept a Keychain prompt per secret." >&2
    exit 1
  fi

  if [[ -n "$profile" ]]; then
    # application-identifier is unambiguously restricted, so it only goes on
    # when there is a profile to authorize it. It is what a provisioned build
    # uses to name its default keychain access group, and it must agree with
    # the group above.
    /usr/libexec/PlistBuddy \
      -c "Add :com.apple.application-identifier string ${team_id}.${bundle_id}" \
      "$entitlements" >/dev/null
    # Tauri's macOS `files` map copies into Contents/, which is where macOS
    # looks for the embedded profile. Merged over the checked-in bundle
    # config rather than passed as a second --config, so there is exactly one
    # config file either way.
    bundle_config="src-tauri/tauri.build.conf.json"
    node -e '
      const fs = require("fs");
      const [base, profile, out] = process.argv.slice(1);
      const config = JSON.parse(fs.readFileSync(base, "utf8"));
      config.bundle ??= {};
      config.bundle.macOS ??= {};
      config.bundle.macOS.files = {
        ...(config.bundle.macOS.files ?? {}),
        "embedded.provisionprofile": profile,
      };
      fs.writeFileSync(out, JSON.stringify(config, null, 2) + "\n");
    ' "$repo_root/src-tauri/tauri.bundle.conf.json" "$profile" "$repo_root/$bundle_config"
    echo "Embedding provisioning profile: $profile"
  fi

  # Universal binary: one DMG runs on Apple silicon and Intel. The fat build
  # needs both std targets installed; `rustup target add` is a no-op when
  # they already are.
  rustup target add aarch64-apple-darwin x86_64-apple-darwin
  sidecar_dir="$repo_root/src-tauri/binaries"
  mkdir -p "$sidecar_dir"
  bash "$script_dir/build-onepassword-sidecar.sh" \
    --target aarch64-apple-darwin \
    --output "$sidecar_dir/multitool-onepassword-aarch64-apple-darwin"
  bash "$script_dir/build-onepassword-sidecar.sh" \
    --target x86_64-apple-darwin \
    --output "$sidecar_dir/multitool-onepassword-x86_64-apple-darwin"
  lipo -create \
    "$sidecar_dir/multitool-onepassword-aarch64-apple-darwin" \
    "$sidecar_dir/multitool-onepassword-x86_64-apple-darwin" \
    -output "$sidecar_dir/multitool-onepassword-universal-apple-darwin"
  chmod 0755 "$sidecar_dir/multitool-onepassword-universal-apple-darwin"
  target_args=(--target universal-apple-darwin)
fi

# The DMG bundler's Finder/AppleScript pass styles the image's window (icon
# view, positioned app + Applications alias). It needs Apple-Events
# automation access — Finder running, a one-time "control Finder" consent —
# and hangs a headless or unattended build waiting for either, which is what
# CI=true skips. Style only from an interactive terminal; a caller-set CI
# always wins.
if [[ -z "${CI:-}" && -t 1 ]]; then
  exec "$repo_root/node_modules/.bin/tauri" build --config "$bundle_config" --bundles app,dmg "${target_args[@]}" "$@"
fi
exec env CI=true "$repo_root/node_modules/.bin/tauri" build --config "$bundle_config" --bundles app,dmg "${target_args[@]}" "$@"
