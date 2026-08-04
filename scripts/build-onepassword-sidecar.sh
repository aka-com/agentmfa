#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
repo_root="$(cd "$script_dir/.." >/dev/null && pwd)"

target="$(rustc -vV | sed -n 's/^host: //p')"
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) target="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$target" in
  aarch64-apple-darwin) goos=darwin; goarch=arm64; cgo=1 ;;
  x86_64-apple-darwin) goos=darwin; goarch=amd64; cgo=1 ;;
  aarch64-unknown-linux-gnu) goos=linux; goarch=arm64; cgo=1; cc_var=CC_aarch64_unknown_linux_gnu ;;
  x86_64-unknown-linux-gnu) goos=linux; goarch=amd64; cgo=1; cc_var=CC_x86_64_unknown_linux_gnu ;;
  *) echo "unsupported sidecar target: $target" >&2; exit 2 ;;
esac

if [[ "$goos" == "linux" ]]; then
  go_host_os="$(go env GOOS)"
  go_host_arch="$(go env GOARCH)"
  configured_cc="${!cc_var:-}"
  if [[ -n "$configured_cc" ]]; then
    export CC="$configured_cc"
  elif [[ "$go_host_os/$go_host_arch" != "$goos/$goarch" ]]; then
    echo "CGO cross-compiler $cc_var is required for $target" >&2
    exit 2
  fi
fi

if [[ -z "$output" ]]; then
  output="$repo_root/target/$target/multitool-onepassword"
fi
mkdir -p "$(dirname "$output")"

if [[ -n "${MULTITOOL_GO_BUILD_CACHE:-}" ]]; then
  export GOCACHE="$MULTITOOL_GO_BUILD_CACHE"
fi
if [[ -n "${MULTITOOL_GO_MODULE_CACHE:-}" ]]; then
  export GOMODCACHE="$MULTITOOL_GO_MODULE_CACHE"
fi

(
  cd "$repo_root/sidecars/onepassword"
  CGO_ENABLED="$cgo" GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags='-s -w' -o "$output" .
)
chmod 0755 "$output"
echo "built 1Password SDK sidecar: $output"
