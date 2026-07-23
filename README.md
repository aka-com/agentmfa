# Multitool

Multitool lets agents make API calls, open database connections,
access SSH servers, and interface with MCP servers. In many
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
- **MCP**: the enabled connections appear as MCP tools, and any
  remote (HTTP) MCP server can itself be added as a connection and
  re-exposed — served by a bundled Node sidecar built on
  [executor](https://executor.sh)

The Postgres and SSH sessions have shell one-liners: `aka dsn` and
`aka ssh` open a session on the running broker and print the one value a
stock client needs. The printed DSN embeds the short-lived session
ticket — an accepted argv exposure for its window; supply the ticket via
PGPASSWORD (`POST /v1/pg/open`) when that matters:

```sh
psql "$(aka dsn analytics)"
export SSH_AUTH_SOCK="$(aka ssh production)"
git push production main
```

## Tools, the shared key, and agent access

Tools (connections) are added in the app, globally — they belong to
Multitool, not to any particular agent. Every local agent authenticates
with **one shared key** ("this computer's key"), minted by the broker and
kept in plaintext at `~/.aka/token` (mode 0600) where agents read it
themselves; the broker stores only its hash. This is deliberate: on a
single-user machine the real boundary is the OS user plus the 0600
socket — per-agent tokens were self-issued and never distinguished
same-user processes — so the key is defense against *accidental* secret
use and the audit handle, not inter-agent isolation. `POST /v1/pair`
remains as a compat shim that hands the same key back; agents may also
send `X-Multitool-Client: <name>` to label themselves in the activity
log (attribution only, never authorization).

Authorization is per **tool**: a connection is enabled for agents when it
is added (adding it was the deliberate act) and can be switched off from
its row on the Tools tab. An enabled call executes immediately with no
prompt; a disabled call is refused with `403 denied_by_policy` — for
every agent at once. Access binds to the connection's pinned destination:
retargeting a tool resets its MCP tool selection and revokes its direct
endpoints (a disabled tool stays disabled). Rotating the key from the
Connect page disconnects everything at once; agents that read the token
file recover on their own.

Locally, we use the `keyring` crate's apple-native backend, which
targets the login keychain. Copying a secret's full value from the app
can require native reauthentication (Touch ID); revealing its short
prefix never does. Agent executions, connection tests, and MCP status
checks are authorized by per-tool agent access instead.

## MCP Support

Agents reach Multitool over MCP through a supervised Node sidecar that
embeds the [executor](https://executor.sh) engine; see `EXECUTOR.md` for
the design and the phase plan. The sidecar serves streamable HTTP on
loopback and authorizes nothing itself: each request carries the shared
broker key, and the broker re-checks per-tool agent access on every
call. Secrets stay in the broker — MCP traffic rides the existing broker
planes, so the sidecar never sees a credential.

The easiest way to connect an MCP client is the stdio bridge:

```sh
aka mcp --client claude-code   # stdio ⇄ streamable-HTTP, self-configuring
```

It reads the shared key from `~/.aka/token` and finds the MCP host
through the discovery manifest (the sidecar's loopback port is dynamic
and advertised as `mcp_url` in `/.well-known/agent-broker.json`), so
Claude Code, Claude Desktop, and Codex configs are two static words:
`command: aka, args: [mcp]`. The app's Connect tab has copy-paste setup
for each.

```sh
npm run sidecar:build    # bundle sidecar/ to dist/sidecar/main.mjs
npm run sidecar:vendor   # fetch the pinned Node the .app ships (macOS)
npm run test:sidecar     # the sidecar's own tests
```

Enabled connections appear over MCP: an API connection becomes
`multitool_<name>_request`, and Postgres/SSH/WebSocket connections become
`multitool_<name>_open`, which hand back the same password-less DSN,
agent socket, or bridge URL the CLI path returns. Disabled connections
are never registered. `multitool_status` is always present and reports
the caller's label and what it may use.

**Remote MCP servers are connections too.** An API connection may carry an
`mcp_path` (e.g. `/mcp`); when it does, that upstream speaks MCP and the
sidecar re-exposes its tools as `multitool_<namespace>_<tool>`. This is
not a new connection kind — an HTTP MCP server is a pinned-host API
connection whose JSON-RPC rides the existing `/v1/http` plane, which is
exactly what keeps its credential out of the sidecar. Stdio MCP servers
are not supported. In the app, GitHub, Gmail, Notion and 1Password are
branded shortcuts for adding one (you supply the server URL your provider
gave you — no endpoints are hard-coded), and a generic **MCP server** row
adds any other by URL.

When an MCP server is connected with OAuth, the provider issues an access
token after browser approval and Multitool stores it directly in the vault
under an internal generated credential name. The broker refreshes that token
when the provider permits it and injects it only on requests to the pinned MCP
server. The ordinary edit sheet therefore treats the server and authentication
as managed: rename the tool there, use **Reconnect** to authorize another
account, or add a separate MCP server for a different destination.

Manually authenticated APIs and MCP servers may instead use a custom
authentication template such as `Authorization: Bearer {{GITHUB_TOKEN}}`.
`{{GITHUB_TOKEN}}` is a reference to a saved credential, not executable
template code; the broker resolves it only when making the pinned upstream
request.

The app starts the sidecar when `dist/sidecar/main.mjs` exists and runs
without it otherwise, so a checkout that skips `sidecar:build` still
works. `AKA_SIDECAR_NODE` and `AKA_SIDECAR_SCRIPT` override what gets
run. `npm run build` performs both sidecar steps for you.

## Remote management (hosted broker)

The desktop app can manage a broker running on another Mac instead of its
own: the broker serves a **manage API** (`/v1/manage/*`, mirroring the
app's whole management surface, plus an SSE change feed) on an optional
TCP listener, authorized by a dedicated **management token** —
`akamgr_…`, issued with `aka manage token`, fully distinct from the agent
key. In the app, the broker switcher at the right of the title bar flips
between **This Mac** and a remote broker; an unreachable remote takes
over the content pane with a retry/error state. Gated configuration
actions on a hosted broker are authorized by token possession and the
activity log records them as such (`via manage token`).

```sh
aka manage token                  # on the broker host, broker stopped
aka serve --listen 127.0.0.1:4780 --public-url https://broker.example.dev
```

`aka serve` also supervises the MCP sidecar itself now (checkout builds
or `AKA_SIDECAR_SCRIPT`), and the daemon reverse-proxies `/mcp`, so
remote agents reach MCP at `<public-url>/mcp` with the shared agent key.
`/v1/pair` is never served over TCP. TLS is the operator's proxy or
tunnel. Browser OAuth sign-ins (BYO-app and MCP) are relayed to your
machine, and direct endpoints issue remotely. WS/PG data-plane opens can
advertise a reachable host via `--data-plane-listen`/`--advertise-host`
(plaintext legs — trusted network only); SSH stays same-machine.
`aka manage token --ttl-days N` bounds a leaked token, and the manage
event stream resumes on reconnect (`Last-Event-ID`) instead of refetching.

The broker runs on **macOS** (Keychain vault) or **Linux** (an
XChaCha20-Poly1305 encrypted vault under a host-provided master key,
`AKA_VAULT_KEY`). Runbooks plus a Dockerfile, systemd unit, and
LaunchAgent live under `dev/hosted-mac/` and `dev/hosted-linux/`.

## Developing

```sh
npm install        # Install the pinned Tauri and TypeScript toolchain
npm test           # Type-check, then test the core, CLI, desktop commands, UI helpers, and sidecar
npm run test:ui    # Run only the TypeScript UI helper tests
npm run lint       # Lint the workspace and the separate Tauri app crate
npm run typecheck  # Type-check the frontend without emitting files

npm start          # start Vite and launch the desktop app
npm run build      # build .app and .dmg bundles
```

### Frontend-only mode (browser, no broker)

The UI runs standalone in a plain browser against a self-contained dev
mock (`ui/src/bridge.ts`): outside Tauri, every command is served from an
in-memory fixture store — seeded secrets, connections, an agent, a wiring,
a live session, and activity — so screens are reviewable and adjustable
without the Rust core. Nothing is enforced (no Keychain, no daemon, no
native authentication).

```sh
npm run frontend:dev   # vite dev server with hot reload
```

Then open:

- <http://127.0.0.1:1420/> — the main window (Tools catalog, Connect,
  Secrets, Activity)
- <http://127.0.0.1:1420/#dropdown> — the compact menu-bar dropdown

The window chrome is chosen from the URL hash; edits to `ui/` hot-reload
in place.

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
