# Multitool CLI

This directory is the npm distribution of the `aka` CLI, published as
[`@aka-labs/multitool`](https://www.npmjs.com/package/@aka-labs/multitool). This is an open-source
package published under the MIT License that follows an esbuild-style layout:

- `multitool/` — the package users install. It contains a Node launcher
  (`bin/multitool.js`, exposed as both `multitool` and `aka`) plus the bundled
  JavaScript MCP host. The launcher executes the prebuilt binary and gives its
  own Node executable to the broker for supervising that MCP host. It declares
  one exact-pinned `optionalDependency` per platform; npm installs the single
  matching one.
- `multitool-{darwin,linux}-{arm64,x64}/` — per-platform packages published
  under the `@aka-labs` scope, whose only
  payload is `bin/aka`, the release binary for that `os`/`cpu` pair. The
  binaries are staged by `scripts/npm-dist.sh` and are gitignored; only the
  manifests are checked in.

There are deliberately **no postinstall scripts and no install-time
downloads**: a credential broker should have an inert, auditable install.
Node 22 or newer is required and is reused as the MCP host runtime; npm does
not carry a second Node executable.

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
packages plus the launcher and its single-file MCP host in `dist/npm/`. For Linux cross-builds it prefers
matching GNU tools when installed and otherwise uses the repo's wrappers with
Zig. Explicit Cargo/CC/CXX/AR target variables are preserved. Use
`scripts/npm-dist.sh --target TRIPLE --pack` on native CI runners when a single
cross-build host is not available, then aggregate the staged `bin/aka` files.
The command keeps its npm cache under `target/npm-cache`; set
`MULTITOOL_NPM_CACHE` to override that location.
Smoke-test a native pair from the result in a scratch prefix:

```sh
npm install --global --prefix /tmp/multitool-test \
    dist/npm/aka-labs-multitool-linux-x64-*.tgz \
    dist/npm/aka-labs-multitool-[0-9]*.tgz
/tmp/multitool-test/bin/multitool --version
/tmp/multitool-test/bin/aka skill | head
```

## Release runbook

1. Bump the workspace version in `Cargo.toml`; run
   `node scripts/npm/sync-versions.mjs`; commit.
2. Run `npm run npm:dist` on a host configured to cross-build every target.
   Alternatively, run `scripts/npm-dist.sh --target TRIPLE --pack` in native
   matrix jobs for `aarch64-apple-darwin`, `x86_64-apple-darwin`,
   `aarch64-unknown-linux-gnu`, and `x86_64-unknown-linux-gnu`, then aggregate
   the four staged binaries into one release workspace.
3. Verify each staged `npm/multitool-*/bin/aka` runs `--version` on its
   platform and reports the workspace version.
   The package verifier also rejects missing, non-executable, or incorrectly
   targeted binaries before packing or publishing.
4. Publish from the workspace root. The command verifies all five packages
   before publishing anything, then publishes the four platform packages
   first and the main package last, so no install can ever resolve a launcher
   whose binary package is missing:

   ```sh
   npm run npm:publish
   ```

   Extra npm arguments are forwarded to every publish, so use
   `npm run npm:publish -- --dry-run` to exercise the complete release without
   changing the registry. Each package also runs the verifier through its own
   `prepublishOnly` hook when published directly.

5. Sanity-check from a clean machine:
   `npx @aka-labs/multitool@latest --version`.

## Platform matrix and future work

Supported today: `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`
(glibc). Not covered yet:

- **musl/Alpine**: either add `multitool-linux-{x64,arm64}-musl` packages, or
  build the linux binaries as static musl artifacts so one package covers
  both libcs.
- **Windows**: unsupported by the broker itself (Unix-domain-socket
  rendezvous, termios, `std::os::unix`); the launcher and the main package's
  `os` field both say so explicitly.
