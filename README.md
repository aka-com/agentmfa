# AKA Multitool

Multitool lets agents make API calls, open database connections,
access SSH servers, and (soon) interface with MCP servers. In many
cases it allows agents to use unmodified tools like `curl`, `psql`,
and `git` without raw credentials. This is done through a connection
broker — keys are kept in a local secret store, encrypted on-disk, and
injected into requests on the upstream leg only.

The tool supports most common workflows:

- **HTTP**: the agent supplies method/path/headers/body to a pinned host
- **Postgres**: the agent gets a password-less DSN + short-lived ticket
- **SSH**: the agent gets an `SSH_AUTH_SOCK` path, which supports
  `ssh`/`git`/`rsync` while the broker signs only for the connection's
  pinned user and server host key (pinned up front, or automatically at
  the first connection)
- **WebSocket**: the agent gets a short-lived `ws://127.0.0.1:…` bridge
  URL usable by any stock WS client
- **MCP**: coming soon, via https://executor.sh

## Tools and wiring

Tools (connections) are added in the app, globally — they belong to
Multitool, not to any particular agent. Agents register themselves with
one `POST /v1/pair` call (no approval step) and appear in the app; you
then **wire** an agent to the tools it may use. A wired call executes
immediately with no prompt; an unwired call is refused. The very first
agent to register is wired to everything that exists at that moment, so
a fresh setup works end-to-end.

Wirings bind to a stable client ID and to the connection's pinned
destination: deleting a connection or changing its target drops its
wirings, and disconnecting an agent drops that agent's wirings.

Locally, we use the `keyring` crate's apple-native backend, which
targets the login keychain. Reading a secret from the app (reveal or
copy) can require native reauthentication (Touch ID); agent executions
are authorized by their wiring instead.

## MCP Support

MCP support is not yet implemented.

## Developing

```sh
npm install        # Install the pinned Tauri and TypeScript toolchain
npm test           # Type-check, then test the core, CLI, desktop commands, and UI helpers
npm run test:ui    # Run only the TypeScript UI helper tests
npm run lint       # Lint the workspace and the separate Tauri app crate
npm run typecheck  # Type-check the frontend without emitting files

npm start          # start Vite and launch the desktop app
npm run build      # build .app and .dmg bundles
```

## Publishing the CLI

```sh
brew install zig # one-time macOS cross-linker setup
npm run npm:dist
npm run npm:publish -- --dry-run
```

The distribution script also uses GNU cross-toolchains when they are already
available or explicitly configured through Cargo's target linker variables.

## Signing and notarization

For a distributable `.app`/`.dmg`, build with the Tauri CLI and a
Developer ID Application certificate.

```sh
npm run build      # signed universal .app + .dmg (auto-detects the identity)
npm run release    # will also notarize, staple, and validate
```
