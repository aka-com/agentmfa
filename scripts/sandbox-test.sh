#!/usr/bin/env bash
# Run the broker test suite against the local Docker sandbox.
#
# The suite drives real brokers (`mfa serve` on throwaway roots) against the
# sandbox's four upstreams, so this script checks that the sandbox is up,
# makes sure the binaries the tests spawn exist, and then hands over to the
# Node test runner. Every argument is passed through to it, so a single file
# can be run directly:
#
#   npm run sandbox:test -- dev/sandbox/tests/postgres.test.ts
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Keep these defaults in sync with dev/sandbox/compose.yaml and
# scripts/sandbox-status.sh; the tests read the same variables.
http_port="${SANDBOX_HTTP_PORT:-18080}"
pg_port="${SANDBOX_PG_PORT:-15432}"
ssh_port="${SANDBOX_SSH_PORT:-12222}"
client_key="$repo_root/dev/sandbox/state/ssh/client_key"

for command in curl node psql; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "sandbox: $command is required" >&2
    exit 1
  fi
done

not_up() {
  echo "sandbox: $1" >&2
  echo "         run \`npm run sandbox:up\` first (see dev/sandbox/README.md)" >&2
  exit 1
}

check_tcp() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

curl --fail --silent --max-time 5 "http://127.0.0.1:$http_port/health" >/dev/null 2>&1 ||
  not_up "the HTTP/MCP fixture is not answering on 127.0.0.1:$http_port"

curl --fail --silent --max-time 5 \
  --header 'Authorization: Bearer aka-mcp-test-token' \
  --header 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  "http://127.0.0.1:$http_port/mcp" 2>/dev/null | grep -q 'aka-sandbox-mcp' ||
  not_up "the MCP fixture did not answer an initialize on 127.0.0.1:$http_port/mcp"

check_tcp "$pg_port" || not_up "Postgres is not listening on 127.0.0.1:$pg_port"
check_tcp "$ssh_port" || not_up "SSH is not listening on 127.0.0.1:$ssh_port"
[[ -f "$client_key" ]] || not_up "the sandbox SSH key is missing ($client_key)"

# The tests spawn this binary; build it unless the caller pinned one.
if [[ -z "${AKA_MFA_BIN:-}" ]]; then
  echo "Building the mfa binary..."
  cargo build -p mfa
  AKA_MFA_BIN="$repo_root/target/debug/mfa"
  export AKA_MFA_BIN
fi
[[ -x "$AKA_MFA_BIN" ]] || {
  echo "sandbox: AKA_MFA_BIN=$AKA_MFA_BIN is not executable" >&2
  exit 1
}

# The MCP host is a Node sidecar built from source. Without it the MCP-host
# tests skip themselves, so build it here rather than leaving a hole.
sidecar="${AKA_SIDECAR_SCRIPT:-$repo_root/dist/sidecar/main.mjs}"
if [[ ! -f "$sidecar" ]]; then
  echo "Building the MCP sidecar..."
  npm run --silent sidecar:build
fi
export AKA_SIDECAR_SCRIPT="$sidecar"

# One broker per test file, so files are independent; keep the number that
# run at once modest, since each is a process with its own listeners.
concurrency="${AKA_SANDBOX_CONCURRENCY:-4}"

if [[ $# -gt 0 ]]; then
  targets=("$@")
else
  targets=("$repo_root"/dev/sandbox/tests/*.test.ts)
fi

echo "Running the broker suite against the sandbox on ports \
$http_port (http/mcp), $pg_port (pg), $ssh_port (ssh)..."
[[ -n "${AKA_SANDBOX_SLOW:-}" ]] ||
  echo "  (set AKA_SANDBOX_SLOW=1 to include the minute-scale timeout and expiry cases)"

exec npx tsx --test --test-concurrency="$concurrency" "${targets[@]}"
