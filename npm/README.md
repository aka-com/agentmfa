# npm distribution

This directory is the npm distribution of the `aka` CLI, published as
[`agentmfa`](https://www.npmjs.com/package/agentmfa).

It follows the esbuild-style layout:

- `agentmfa/` — the package users install. It contains only a Node launcher
  (`bin/agentmfa.js`, exposed as both `agentmfa` and `aka`) that resolves and
  executes the prebuilt binary. It declares one exact-pinned
  `optionalDependency` per platform; npm installs the single matching one.
- `agentmfa-{darwin,linux}-{arm64,x64}/` — per-platform packages whose only
  payload is `bin/aka`, the release binary for that `os`/`cpu` pair. The
  binaries are staged by `scripts/npm-dist.sh` and are gitignored; only the
  manifests are checked in.

There are deliberately **no postinstall scripts and no install-time
downloads**: a credential broker should have an inert, auditable install.

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
packages plus the launcher in `dist/npm/`. For Linux cross-builds it prefers
matching GNU tools when installed and otherwise uses the repo's wrappers with
Zig. Explicit Cargo/CC/CXX/AR target variables are preserved. Use
`scripts/npm-dist.sh --target TRIPLE --pack` on native CI runners when a single
cross-build host is not available, then aggregate the staged `bin/aka` files.
The command keeps its npm cache under `target/npm-cache`; set
`AGENTMFA_NPM_CACHE` to override that location.
Smoke-test a native pair from the result in a scratch prefix:

```sh
npm install --global --prefix /tmp/agentmfa-test \
    dist/npm/agentmfa-linux-x64-*.tgz dist/npm/agentmfa-*[0-9].tgz
/tmp/agentmfa-test/bin/agentmfa --version
/tmp/agentmfa-test/bin/aka skill | head
```

## Release runbook

1. Bump the workspace version in `Cargo.toml`; run
   `node scripts/npm/sync-versions.mjs`; commit.
2. Run `npm run npm:dist` on a host configured to cross-build every target.
   Alternatively, run `scripts/npm-dist.sh --target TRIPLE --pack` in native
   matrix jobs for `aarch64-apple-darwin`, `x86_64-apple-darwin`,
   `aarch64-unknown-linux-gnu`, and `x86_64-unknown-linux-gnu`, then aggregate
   the four staged binaries into one release workspace.
3. Verify each staged `npm/agentmfa-*/bin/aka` runs `--version` on its
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

5. Sanity-check from a clean machine: `npx agentmfa@latest --version`.

## Platform matrix and future work

Supported today: `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`
(glibc). Not covered yet:

- **musl/Alpine**: either add `agentmfa-linux-{x64,arm64}-musl` packages, or
  build the linux binaries as static musl artifacts so one package covers
  both libcs.
- **Windows**: unsupported by the broker itself (Unix-domain-socket
  rendezvous, termios, `std::os::unix`); the launcher and the main package's
  `os` field both say so explicitly.
- **Scoped packages**: if an `@agentmfa` npm org is ever claimed, the
  platform packages could move to `@agentmfa/<platform>`; do that before the
  first publish or not at all, since the launcher's optionalDependencies pin
  the names.
