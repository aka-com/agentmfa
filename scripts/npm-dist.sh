#!/usr/bin/env bash
set -euo pipefail

# Build the `aka` CLI in release mode and stage it into the npm distribution
# under npm/ (the main `agentmfa` launcher package plus per-platform binary
# packages). One invocation stages one target, or all supported targets when
# the required Rust targets and cross-linkers are available.
#
#   scripts/npm-dist.sh                  build and stage for this machine
#   scripts/npm-dist.sh --target TRIPLE  build for a specific Rust target
#   scripts/npm-dist.sh --all            build and stage every supported target
#   scripts/npm-dist.sh --pack           also `npm pack` the staged platform
#                                        package(s) and the main package into
#                                        dist/npm/
#
# Publish order matters: every agentmfa-<os>-<arch> package must be
# published before the main agentmfa package of the same version (npm/README.md has the
# full runbook).

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
repo_root="$(cd "$script_dir/.." >/dev/null && pwd)"
cd "$repo_root"

# Keep build caches inside the repository so release builds work in clean or
# sandboxed environments whose home-directory caches are read-only. npm sets
# npm_config_cache before invoking scripts, so use our own override variable.
export npm_config_cache="${AGENTMFA_NPM_CACHE:-$repo_root/target/npm-cache}"
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$repo_root/target/zig-cache}"

set_if_unset() {
  local name="$1"
  local value="$2"
  if [[ -z "${!name:-}" ]]; then
    export "$name=$value"
  fi
}

configure_linux_toolchain() {
  local target="$1"
  local cargo_linker_var cc_var cxx_var ar_var ranlib_var
  local gnu_prefix zig_target

  case "$target" in
    aarch64-unknown-linux-gnu)
      cargo_linker_var=CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER
      cc_var=CC_aarch64_unknown_linux_gnu
      cxx_var=CXX_aarch64_unknown_linux_gnu
      ar_var=AR_aarch64_unknown_linux_gnu
      ranlib_var=RANLIB_aarch64_unknown_linux_gnu
      gnu_prefix=aarch64-linux-gnu
      zig_target=aarch64-linux-gnu
      ;;
    x86_64-unknown-linux-gnu)
      cargo_linker_var=CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER
      cc_var=CC_x86_64_unknown_linux_gnu
      cxx_var=CXX_x86_64_unknown_linux_gnu
      ar_var=AR_x86_64_unknown_linux_gnu
      ranlib_var=RANLIB_x86_64_unknown_linux_gnu
      gnu_prefix=x86_64-linux-gnu
      zig_target=x86_64-linux-gnu
      ;;
    *) return ;;
  esac

  if command -v "$gnu_prefix-gcc" >/dev/null 2>&1 &&
     command -v "$gnu_prefix-g++" >/dev/null 2>&1 &&
     command -v "$gnu_prefix-ar" >/dev/null 2>&1; then
    set_if_unset "$cargo_linker_var" "$gnu_prefix-gcc"
    set_if_unset "$cc_var" "$gnu_prefix-gcc"
    set_if_unset "$cxx_var" "$gnu_prefix-g++"
    set_if_unset "$ar_var" "$gnu_prefix-ar"
    if command -v "$gnu_prefix-ranlib" >/dev/null 2>&1; then
      set_if_unset "$ranlib_var" "$gnu_prefix-ranlib"
    fi
    echo "using GNU cross-toolchain for $target"
  elif command -v zig >/dev/null 2>&1; then
    local toolchain_dir="$repo_root/scripts/npm/toolchains"
    set_if_unset "$cargo_linker_var" "$toolchain_dir/zig-$zig_target-cc"
    set_if_unset "$cc_var" "$toolchain_dir/zig-$zig_target-cc"
    set_if_unset "$cxx_var" "$toolchain_dir/zig-$zig_target-cxx"
    set_if_unset "$ar_var" "$toolchain_dir/zig-ar"
    set_if_unset "$ranlib_var" "$toolchain_dir/zig-ranlib"
    echo "using Zig cross-toolchain for $target"
  else
    echo "no cross-toolchain found for $target" >&2
    echo "install $gnu_prefix-gcc/$gnu_prefix-g++ or Zig, or set $cargo_linker_var and the matching CC/CXX/AR variables" >&2
    exit 2
  fi
}

target=""
all=0
pack=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      if [[ $# -lt 2 ]]; then
        echo "--target requires a Rust target triple" >&2
        exit 2
      fi
      target="$2"
      shift 2
      ;;
    --all) all=1; shift ;;
    --pack) pack=1; shift ;;
    *) echo "unknown argument: $1 (expected --all, --target TRIPLE, and/or --pack)" >&2; exit 2 ;;
  esac
done

if [[ "$all" -eq 1 && -n "$target" ]]; then
  echo "--all and --target cannot be used together" >&2
  exit 2
fi

node scripts/npm/sync-versions.mjs --check

# The npm launcher reuses its own Node 22 runtime, but it still needs the
# self-contained MCP host script. Build and stage that one-file bundle beside
# the launcher so `aka serve` can host MCP from any working directory.
npm run sidecar:build
install -d "npm/agentmfa/sidecar"
install -m 0644 "dist/sidecar/main.mjs" "npm/agentmfa/sidecar/main.mjs"
echo "staged dist/sidecar/main.mjs -> npm/agentmfa/sidecar/main.mjs"

host="$(rustc -vV | sed -n 's/^host: //p')"
if [[ "$all" -eq 1 ]]; then
  targets=(
    aarch64-apple-darwin
    x86_64-apple-darwin
    aarch64-unknown-linux-gnu
    x86_64-unknown-linux-gnu
  )
elif [[ -z "$target" ]]; then
  target="$host"
  targets=("$target")
else
  targets=("$target")
fi

for target in "${targets[@]}"; do
  case "$target" in
    aarch64-apple-darwin)      platform_pkg="agentmfa-darwin-arm64" ;;
    x86_64-apple-darwin)       platform_pkg="agentmfa-darwin-x64" ;;
    aarch64-unknown-linux-gnu) platform_pkg="agentmfa-linux-arm64" ;;
    x86_64-unknown-linux-gnu)  platform_pkg="agentmfa-linux-x64" ;;
    *)
      echo "no npm platform package maps to Rust target '$target'." >&2
      echo "supported: aarch64-apple-darwin x86_64-apple-darwin" >&2
      echo "           aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu" >&2
      exit 2
      ;;
  esac

  configure_linux_toolchain "$target"

  build_args=(--release --package aka)
  bin_dir="target/release"
  if [[ "$target" != "$host" ]]; then
    rustup target add "$target"
    build_args+=(--target "$target")
    bin_dir="target/$target/release"
  fi

  cargo build "${build_args[@]}"

  install -d "npm/$platform_pkg/bin"
  install -m 0755 "$bin_dir/aka" "npm/$platform_pkg/bin/aka"
  echo "staged $bin_dir/aka -> npm/$platform_pkg/bin/aka"
  node scripts/npm/verify-package.mjs "npm/$platform_pkg"

  if [[ "$pack" -eq 1 ]]; then
    mkdir -p dist/npm
    (cd "npm/$platform_pkg" && npm pack --pack-destination "$repo_root/dist/npm")
  fi
done

if [[ "$pack" -eq 1 ]]; then
  node scripts/npm/verify-package.mjs "npm/agentmfa"
  (cd npm/agentmfa && npm pack --pack-destination "$repo_root/dist/npm")
  echo "tarballs written to dist/npm/"
fi
