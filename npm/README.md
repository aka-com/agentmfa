# AgentMFA CLI

This directory is the npm distribution of the `aka` CLI, published as
[`agentmfa`](https://www.npmjs.com/package/agentmfa).

This is an open-source package (MIT License) that follows an esbuild-style layout:

- `agentmfa/` — the package users install. It contains a Node launcher
  (`bin/agentmfa.js`, exposed as both `agentmfa` and `aka`) plus the bundled
  JavaScript MCP host. The launcher executes the prebuilt binary and gives its
  own Node executable to the broker for supervising that MCP host. It declares
  one exact-pinned `optionalDependency` per platform; npm installs the single
  matching one.
- `agentmfa-{darwin,linux}-{arm64,x64}/` — per-platform packages whose only
  payload is `bin/aka`, the release binary for that `os`/`cpu` pair. The
  binaries are staged by `scripts/npm-dist.sh` and are gitignored; only the
  manifests are checked in.

There are no postinstall scripts and no install-time downloads. Node
22 or newer is required, as the MCP host runtime.

## Versioning

The Cargo workspace version in the root `Cargo.toml` is the single source of
truth (it is what `aka --version` reports). All five `package.json` files must
carry the same version, with the launcher's `optionalDependencies` pinned
exactly. After bumping the workspace version, run:

```sh
node scripts/npm/sync-versions.mjs          # stamp the npm manifests
node scripts/npm/sync-versions.mjs --check  # verify only (CI/test mode)
```

`npm test` (via `npm run npm:check`) and `scripts/npm-dist.sh` both run the
check, so drift fails fast. The launcher also refuses at runtime to execute a
platform package whose version differs from its own.

## Building and local testing

```sh
npm run npm:dist    # build, verify, stage, and pack every supported target
```

This runs `scripts/npm-dist.sh --all --pack`, producing all four platform
packages plus the launcher and its single-file MCP host in `dist/npm/`. For
Linux cross-builds it prefers matching GNU tools when installed and otherwise
uses the repo's wrappers with Zig. Explicit Cargo/CC/CXX/AR target variables
are preserved. Use `scripts/npm-dist.sh --target TRIPLE --pack` on native
CI runners when a single cross-build host is not available, then aggregate
the staged `bin/aka` files.

The command keeps its npm cache under `target/npm-cache`; set
`AGENTMFA_NPM_CACHE` to override that location.

Smoke-test a native pair from the result in a scratch prefix:

```sh
npm install --global --prefix /tmp/agentmfa-test \
    dist/npm/agentmfa-linux-x64-*.tgz \
    dist/npm/agentmfa-[0-9]*.tgz
/tmp/agentmfa-test/bin/agentmfa --version
/tmp/agentmfa-test/bin/aka skill | head
```

## Platform support

Supported today: `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`
(glibc). Not covered yet:

- **musl/Alpine**: either add `agentmfa-linux-{x64,arm64}-musl` packages, or
  build the linux binaries as static musl artifacts so one package covers
  both libcs.
- **Windows**: unsupported by the broker itself (Unix-domain-socket
  rendezvous, termios, `std::os::unix`); the launcher and the main package's
  `os` field both say so explicitly.
