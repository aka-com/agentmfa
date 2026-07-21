#!/usr/bin/env bash
set -euo pipefail

# Vendor the pinned Node runtime the sidecar runs on.
#
# The sidecar hosts the executor engine, which we do not want to depend on
# whatever Node the user happens to have — or on them having one at all. So
# a known-good build ships inside the .app. Tauri's `externalBin` expects
# one file per target triple, named `node-<triple>`, and signs each as part
# of the bundle.
#
# Both macOS arches are fetched because scripts/build.sh produces a
# universal binary; a lipo'd Node covers both from one externalBin entry.

NODE_VERSION="${NODE_VERSION:-22.14.0}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
repo_root="$(cd "$script_dir/.." >/dev/null && pwd)"
out_dir="$repo_root/src-tauri/binaries"
work_dir="$repo_root/target/node-vendor"

mkdir -p "$out_dir" "$work_dir"

fetch() {
  local arch="$1" triple="$2"
  local name="node-v${NODE_VERSION}-darwin-${arch}"
  local dest="$work_dir/$name/bin/node"

  if [[ ! -x "$dest" ]]; then
    echo "Fetching Node ${NODE_VERSION} (${arch})…"
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/${name}.tar.gz" \
      | tar -xz -C "$work_dir"
  fi
  echo "$dest"
}

if [[ "$(uname)" != "Darwin" ]]; then
  echo "vendor-node.sh currently only supports macOS." >&2
  exit 1
fi

arm="$(fetch arm64 aarch64-apple-darwin)"
intel="$(fetch x64 x86_64-apple-darwin)"

# Every triple the build might ask for gets the same universal binary, so a
# single-arch and a universal build both find their file.
universal="$work_dir/node-universal"
lipo -create -output "$universal" "$arm" "$intel"

for triple in aarch64-apple-darwin x86_64-apple-darwin universal-apple-darwin; do
  cp "$universal" "$out_dir/node-$triple"
  chmod +x "$out_dir/node-$triple"
done

echo "Vendored Node ${NODE_VERSION} into src-tauri/binaries/"
