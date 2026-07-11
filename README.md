# AgentMFA

AgentMFA allows agents to make API calls, open database connections,
and access SSH servers, using unmodified tools like `curl`, `psql`,
and `git` without exposing raw credentials.

Agents make calls through a connection broker, which keeps API keys in
macOS keychain and injects them into request following user approval.

The default approval creates a fixed 15-minute session. Try a GET/HEAD
request for read access, or a POST or pg/SSH connection for full access.

AgentMFA supports most everyday workflows:

- **HTTP**: the agent supplies method/path/headers/body to a pinned host
- **Postgres**: the agent gets a password-less DSN + short-lived ticket
- **SSH**: the agent gets an `SSH_AUTH_SOCK` path, which supports
  `ssh`/`git`/`rsync` while the broker signs only for the connection's
  pinned user and server host key (pinned up front, or confirmed with you
  and pinned at the first connection)
- **WebSocket**: the agent gets a short-lived `ws://127.0.0.1:…` bridge
  URL usable by any stock WS client

Pair tokens are checked against the code-signing identity observed
during pairing, or a best-effort local executable fingerprint for
unsigned/ad-hoc peers. The app distinguishes the agent's self-reported
name from that program identity. Permissions bind to a stable
paired-client ID; a different program requesting the same name
inherits nothing.

We uses the `keyring` crate's apple-native backend, which targets the
login keychain and does not expose the Data Protection keychain's
`SecAccessControl` policies.  Native reauthentication on read is
enforced by the broker before app-initiated vault reads; true
Keychain-enforced per-item ACL semantics require direct
Security.framework calls and corresponding signing entitlements.

## Developing

```sh
npm install        # Install the pinned Tauri and TypeScript toolchain
npm test           # Type-check, then test the core, CLI, desktop commands, and UI helpers
npm run test:ui    # Run only the TypeScript UI helper tests
npm run clippy     # Lint the workspace and the separate Tauri app crate
npm run typecheck  # Type-check the frontend without emitting files

npm start          # start Vite and launch the desktop app
npm run build      # build .app and .dmg bundles
```

## Signing and notarization

For a distributable `.app`/`.dmg`, build with the Tauri CLI and a
Developer ID Application certificate.

```sh
npm run build      # signed universal .app + .dmg (auto-detects the identity)
npm run release    # will also notarize, staple, and validate
```

For code signing, configure `bundle.macOS.signingIdentity`, and give
`scripts/release.sh` notary credentials via
`NOTARYTOOL_KEYCHAIN_PROFILE` (`xcrun notarytool store-credentials`)
or `APPLE_ID`, `APPLE_PASSWORD`, and `APPLE_TEAM_ID`.

## Test builds

To drive the system without the desktop app, `agentmfa serve` runs the
whole broker headless with a terminal approver, so you can drive it
exactly as an agent would over the Unix socket:

```sh
cargo run -p agentmfa-cli -- serve
curl --unix-socket ~/.agentmfa/broker.sock http://localhost/instructions
```

For disposable local HTTP, WebSocket, Postgres, and SSH upstreams, see the
[developer service sandbox](dev/sandbox/README.md). The sandbox runs the
upstreams in Docker while AgentMFA continues to run natively.

To seed secrets and connections from the terminal, with the broker stopped:

```sh
printf '%s' "$GITHUB_TOKEN" | cargo run -p agentmfa-cli -- secret add GITHUB_API_KEY
cargo run -p agentmfa-cli -- conn add github --kind api --host api.github.com \
    --template 'Authorization: Bearer {{GITHUB_API_KEY}}'
cargo run -p agentmfa-cli -- conn list
```

To generate the checked-in skill file served at /instructions:

```sh
cargo run -p agentmfa-cli -- skill --write    # → .claude/skills/agentmfa/SKILL.md
```

## Agent workflow

1. Reuse the token stored at `~/.agentmfa/tokens/<name>` if `GET /v1/whoami`
   accepts it, or use `POST /v1/pair {"agent_name": "claude-code"}` to pair
   a new agent and get a 30-day bearer token.
2. `GET /v1/connections` — discover the named connections it may use (targets
   only; never secret names or values) and whether each one `will_prompt`,
   is `read_auto_allowed` (read-scoped permission), or is already
   `auto_allowed` (full permission).
3. Call a capability, naming a connection:
   - `POST /v1/http` — `{status, headers, body}`; the broker injects the
     credential, validates the path, and follows redirects only within the
     connection's pinned host.
   - `POST /v1/ws/open` — a `ws://127.0.0.1:<port>/…/<ticket>` bridge URL for
     any stock WebSocket client.
   - `POST /v1/pg/open` — a password-less DSN + a ticket to pass via
     `PGPASSWORD`; unmodified `psql` runs against the local proxy.
   - `POST /v1/ssh/open` — an `auth_sock` path to point `SSH_AUTH_SOCK` at;
     `ssh`/`git`/`rsync` authenticate through the broker's ssh-agent using
     host-bound authentication, pinned to the configured user and server
     host-key fingerprint. A service saved without a fingerprint is trusted
     on first use: the first connection shows the observed host key in a
     trust prompt (with known_hosts provenance) and pins it on approval,
     while the ssh client waits on the agent socket. OpenSSH normally
     negotiates the host-bound mode automatically; forcing it with
     `PubkeyAuthentication=host-bound` is optional.

## Architecture

- The core owns Keychain access, connection configuration, policy,
  approvals, agent pairing, upstream clients, and activity events.
- The webview receives metadata and, after an explicit reveal, a short
  secret prefix. High-consequence approvals and configuration changes go through
  a core-owned macOS authentication sheet that the webview cannot forge.
- Agents use HTTP over a per-user Unix socket for discovery and capability
  requests. WebSocket and Postgres data sessions use short-lived tickets on
  OS-assigned loopback ports; SSH uses a scoped per-open ssh-agent socket.

```
                        ┌────────────────────────────────────────────┐
                        │                AgentMFA.app                │
                        │                                            │
 ┌──────────────┐ Tauri │  ┌──────────────┐        ┌──────────────┐  │
 │ Webview UI   │ cmds  │  │  UI commands │        │   Keychain   │  │
 │ (tray drop-  ├───────┼──►  (masked     ├───┐    │  (Security.  │  │
 │ down/window) │ events│  │   metadata)  │   │    │  framework)  │  │
 └──────────────┘       │  └──────────────┘   │    └──────▲───────┘  │
                        │                     │           │          │
                        │                ┌────▼───────────┴─────┐    │
                        │                │      Core (Rust)     │    │
                        │                │  store · policy ·    │    │
                        │                │  audit · approvals   │    │
                        │                └────┬────────────┬────┘    │
                        │                     │            │         │
                        │  ┌──────────────────▼───┐   ┌────▼──────┐  │
 ┌──────────────┐  UDS  │  │  Broker listeners    │   │ Upstream  │  │
 │ Coding agent ├───────┼──►  broker.sock (ctrl)  ├───►  clients  ├──┼──► api.github.com
 │ (claude-code,│       │  │  /.well-known/…      │   │ (reqwest, │  │    wss://…
 │  codex, …)   │       │  │  /instructions       │   │ tungsten- ├──┼──► pg host:5432
 └──────┬───────┘  TCP  │  │  /v1/pair /v1/http   │   │ ite, pg   │  │
        │               │  │  /v1/{ws,pg,ssh}/open│   │  proxy)   │  │
        └───────────────┼──►  data: tcp + ssh sock│   └───────────┘  │
                        │  └──────────────────────┘                  │
                        └────────────────────────────────────────────┘
```

Other features:

- **Native authentication / clipboard.** `auth.rs` uses macOS
  LocalAuthentication, which permits Touch ID with account-password fallback,
  and `clipboard.rs` uses `NSPasteboard`. A successful user-initiated copy
  authorizes other clipboard copies for five minutes in memory; this window
  does not authorize agent reads or other protected actions. On other
  platforms the confirmation gate fails closed and the concealed-clipboard
  write is skipped (both are macOS product features).
- **SSH host binding.** The AgentMFA implementation requires OpenSSH
  `session-bind@openssh.com` and signs only
  `publickey-hostbound-v00@openssh.com` authentication for the configured user,
  key, session, and server host-key fingerprint. Unbound or mismatched signing
  requests fail closed. Compatible OpenSSH clients negotiate these extensions
  without requiring an explicit `PubkeyAuthentication=host-bound` option.
  The fingerprint is optional at setup: an unpinned service pins the key
  trust-on-first-use — the first `session-bind` raises a dedicated approval
  showing the observed fingerprint alongside what the user's own known_hosts
  says about it, and only that one-time decision (never an access session or
  standing rule) writes the pin.
- **HTTP consequence classification.** For access-session scope, idempotency,
  and the extra confirmation on *Allow once*, AgentMFA classifies `GET` and
  `HEAD` as read-like and every other accepted method as potentially mutating.
  In the desktop app, starting an access session always requires native
  confirmation, including for a read. The method classification is a
  heuristic, not a guarantee about upstream behavior: an action performed
  through `GET` can fit in read access, while a harmless `POST` requires full
  access.
- **On-disk integrity and identity strength.** `index.json`, `rules.json`, and
  `agents.json` are sealed with HMAC-SHA256 under a vault-held key and refuse
  to load on a verification failure (bare pre-seal files migrate
  trust-on-first-use). Identity pinning remains intentionally limited:
  interpreted runtimes may present a coarse shared identity, and unsigned or
  ad-hoc peers use a weaker best-effort local executable fingerprint.

## Security considerations

- [ ] HTTP connections pin an origin, not an allowed set of paths or
  operations. Full access and standing rules allow any accepted method
  and path on that origin; read access allows GET/HEAD on any path.
- [ ] Postgres statements, WebSocket frames, and SSH operations are
  not individually inspected or approved, and that a multi-connect
  ticket may establish several sessions under one decision.
- [ ] Standing-rule scope: an agent name plus an entire stable
  connection, with no path, method, query, read-only, expiry, or
  deny-rule constraints. Distinguish it from a token-generation- and
  connection-revision-bound, scoped 15-minute access session. Agent
  names are also self-asserted. Runtimes may share `node` or `python`.
- [ ] State that a paired agent can list every configured connection target,
  including internal hostnames and database users, but not secret names, IDs,
  or injection templates.
- [ ] SSH trust on first use pins whatever key the server presents at the
  first approved connection. It authenticates continuity, not initial
  identity: a machine-in-the-middle present at that first connection would
  be pinned. Enter the fingerprint manually (or verify the prompt's value
  out-of-band) when first-connection integrity matters.

## License

MIT (C) 2026
