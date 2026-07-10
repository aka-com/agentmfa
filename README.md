# AgentMFA

AgentMFA is a secrets manager for agents. Make API calls, open database and
WebSocket connections, and authenticate SSH sessions — with unmodified tools
like `curl`, `psql`, and `git` — without directly exposing stored secret values
from the vault to Claude, Codex, or other local agents.

```
                        ┌────────────────────────────────────────────┐
                        │                AgentMFA.app                │
                        │                                            │
 ┌──────────────┐ Tauri │  ┌──────────────┐        ┌──────────────┐  │
 │  Webview UI  │ cmds  │  │  UI commands │        │   Keychain   │  │
 │  (tray drop- ├───────┼──►  (masked     ├───┐    │  (Security.  │  │
 │  down/window)│ events│  │   metadata)  │   │    │  framework)  │  │
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

## Features

- **Secrets manager for agents.** Raw values live in macOS Keychain items. For
  brokered use, they are fetched only for a request authorized by an exact
  approval, an active access session, or a standing rule. Explicit user copy
  is a separate, user-directed clipboard operation.
- **Authorization-gated access.** Every capability call must match an active
  access session or pass policy. The default prompted approval creates a fixed
  15-minute, in-memory access session: GET/HEAD starts read access, while a
  mutating HTTP request or WebSocket/Postgres/SSH open starts full access.
  *Allow once* and *Always allow…* remain available. Session traffic is
  authorized when the session is opened, not per frame, query, or SSH
  operation.
- **Supports most agent workflows:** Injects credentials for HTTP, WebSocket, Postgres, and SSH.
  - **HTTP** — the agent supplies method/path/headers/body; the connection pins the host; redirects are only followed within that host.
  - **WebSocket** — the agent gets a short-lived `ws://127.0.0.1:…` bridge URL usable by any stock WS client.
  - **Postgres** — the agent gets a password-less DSN + short-lived ticket; unmodified `psql` works, while the broker opens the upstream leg itself. The default `sslmode=require` encrypts without certificate verification; use `verify-full` for CA and hostname verification.
  - **SSH** — the agent gets an `SSH_AUTH_SOCK` path; `ssh`/`git`/`rsync` work
    with OpenSSH host-bound authentication, while the broker signs only for the
    connection's pinned user and server host key. Compatible OpenSSH clients
    negotiate this automatically; explicitly setting
    `PubkeyAuthentication=host-bound` is not normally required.
- **Identity-pinned pairing.** Pair tokens are checked against the code-signing
  identity observed during pairing, or a best-effort local executable
  fingerprint for unsigned/ad-hoc peers. The app distinguishes the agent's
  self-reported name from that program identity and, on re-pairing, asks
  whether previously saved no-prompt access should carry over.
- **Local activity log.** Pairing, approval, denial, and upstream events are
  emitted to the app's Activity view and appended to disk on a best-effort
  basis. Persistence failures do not block broker operations, so history may
  be incomplete; it is not a tamper-evident audit ledger.
- **Free and open source.** MIT-licensed local desktop application; contact us for enterprise support.

## How it works

AgentMFA separates **secrets** from **connections**. A secret is an opaque
named value. A connection binds one or more secrets to a fixed destination and
transport, such as an API origin, Postgres database, WebSocket URL, or SSH
host. The agent supplies the *what* — method, path, body, or session-open
request — while the connection supplies the *where* and the credential.

After authorization and any required human approval, the Rust core reads the
required secret from the Keychain as late as possible and uses it on the
configured upstream connection. Broker-produced agent API fields never contain
the full stored value, and the webview never renders it in full. Relayed HTTP
responses are scrubbed for exact rendered credential material and common
components, but an upstream service can transform or independently return
sensitive data in a form the broker cannot recognize; response redaction is not
an absolute non-disclosure boundary. Explicit user copy is the separate,
user-directed exception: the core writes the value to the macOS pasteboard as a
concealed item and conditionally clears it after 30 seconds.

- The **core** owns Keychain access, connection configuration, policy,
  approvals, agent pairing, upstream clients, and activity events.
- The **webview** receives metadata and, after an explicit reveal, a short
  secret prefix. High-consequence approvals and configuration changes require
  a core-owned macOS authentication sheet that the webview cannot forge.
- Agents use HTTP over a per-user Unix socket for discovery and capability
  requests. WebSocket and Postgres data sessions use short-lived tickets on
  OS-assigned loopback ports; SSH uses a scoped per-open ssh-agent socket.

## Adoption and compatibility

- AgentMFA v1 is a single-user, local macOS 13+ application. It has no remote
  broker surface, shared team vault, or centrally managed policy backend.
- Secret values remain local to the Mac where they are created; AgentMFA does
  not provide iCloud or application-level cloud synchronization.
- The current `keyring` backend uses the login Keychain. It does not provide
  Data Protection Keychain per-item ACLs; broker-side LocalAuthentication is a
  separate confirmation and reauthentication control.
- HTTP connections support bearer and custom-header credentials, Basic auth
  through `base64(...)`, query injection through `url(...)`, and composition
  of multiple secrets in a fixed injection template.
- Postgres `sslmode=require`, the default, encrypts the upstream connection but
  does not verify its certificate. Use `verify-full` for CA and hostname
  verification.
- SSH supports ed25519 and RSA keys and requires OpenSSH-compatible session
  binding and host-bound authentication. Encrypted or unsupported private keys
  fail when the SSH capability is opened.
- AgentMFA does not export durable secrets into an agent or child-process
  environment; doing so would give the agent the value and bypass broker
  mediation.
- AgentMFA does not ship a built-in MCP server. The Unix-socket protocol is the
  enforcement surface; `/instructions` and the generated skill are the
  agent-agnostic discovery and ergonomics layers.

## Developing

Everything runs from the repo root. `npm install` once to get the pinned
Tauri CLI, then:

```
npm test           # cargo test --workspace (core + CLI crates)
npm run clippy     # cargo clippy --workspace --all-targets

# macOS desktop app (src-tauri is outside the cargo workspace; the scripts
# reach it via --manifest-path / the Tauri CLI)
npm start          # build and launch the app
npm run build      # build .app and .dmg bundles

# Linux (not supported)
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libsoup-3.0-dev libayatana-appindicator3-dev
cd src-tauri && cargo check
```

## macOS run, signing, and notarization

For local development, run the desktop app from the repo root:

```sh
npm start    # cargo run --manifest-path src-tauri/Cargo.toml --bin agentmfa-app
```

Use a stable signing identity even for dev builds when testing Keychain behavior. Unsigned/ad-hoc builds run, but macOS treats each changed signature as a different app for Keychain ACLs, so rebuilds can re-trigger access prompts and notification behavior may differ from a bundled app.

For a distributable `.app`/`.dmg`, build with the Tauri CLI and a Developer ID Application certificate (a universal binary — Apple silicon and Intel, macOS 13+ — built headlessly, so no Finder automation prompts):

```sh
npm run build      # signed universal .app + .dmg (auto-detects the identity)
npm run release    # the above, then notarize, staple, and validate
```

Configure `bundle.macOS.signingIdentity` (or let `scripts/build.sh` auto-detect the machine's one Developer ID identity), keep `hardenedRuntime` enabled, and give `scripts/release.sh` notary credentials via `NOTARYTOOL_KEYCHAIN_PROFILE` (from `xcrun notarytool store-credentials`) or `APPLE_ID`/`APPLE_PASSWORD`/`APPLE_TEAM_ID`. Release artifacts must be Developer ID signed, notarized, and stapled before distribution — `npm run release` is that flow.

Keep the bundle identifier (`com.aka.desktop`) stable so release builds retain a
consistent Keychain identity. The current `keyring` backend targets the login
keychain. Keychain-enforced per-item access control would require a future
Security.framework backend and corresponding signing entitlements.

## Try it without the desktop app

`agentmfa serve` runs the whole broker headless with a terminal approver, so
you can drive it exactly as an agent would over the Unix socket:

```sh
cargo run -p agentmfa-cli -- serve            # prompts you to approve in the terminal
# in another shell:
curl --unix-socket ~/.agentmfa/broker.sock http://localhost/instructions
```

Seed secrets and connections from the terminal (with the broker stopped —
the commands refuse to race a live broker; values are read from stdin or
`--value-env`, never argv):

```sh
printf '%s' "$GITHUB_TOKEN" | cargo run -p agentmfa-cli -- secret add GITHUB_API_KEY
cargo run -p agentmfa-cli -- conn add github --kind api --host api.github.com \
    --template 'Authorization: Bearer {{GITHUB_API_KEY}}'
cargo run -p agentmfa-cli -- conn list
```

Generate the checked-in skill file (the same content the daemon serves at
`/instructions`, so it can't drift):

```sh
cargo run -p agentmfa-cli -- skill --write    # → .claude/skills/agentmfa/SKILL.md
```

## What an agent does

1. Reuse the token stored at `~/.agentmfa/tokens/<name>` if `GET /v1/whoami`
   accepts it; otherwise `POST /v1/pair {"agent_name": "claude-code"}` — the
   user approves; the response is a 30-day bearer token, pinned to the
   agent's peer identity, plus the `store_at` path to keep it in.
2. `GET /v1/connections` — discover the named connections it may use (targets
   only; never secret names or values) and whether each one `will_prompt`,
   is `read_auto_allowed`, or is already `auto_allowed`.
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
     host-key fingerprint. OpenSSH normally negotiates the host-bound mode
     automatically; forcing it with `PubkeyAuthentication=host-bound` is
     optional.

Every capability call is authorization-checked. A call that requires a prompt
is surfaced as a **held-open request** and blocks until the user decides or the
120 s timeout auto-denies. The primary decision creates a non-sliding,
15-minute access session bound to the current pair-token generation, stable
connection, and exact connection revision. Read access covers GET/HEAD; full
access covers every HTTP method and new session opens. A later full-access
approval replaces a read session and starts a new fixed 15-minute window;
ordinary use never extends either window. *Allow once* and a standing "always
allow" rule remain available. Compatible requests that were already waiting
are covered by the newly approved session rather than prompting again. Natural
expiry is recorded in the activity log and removes the access indicator at
the grant's deadline. For WebSocket, Postgres, and SSH, authorization applies
to the session-open call. Traffic inside an authorized live session is not
approved individually. A transport issued under a grant is capped by the
grant's remaining lifetime, and grant expiry or revocation closes it.

Disconnecting or re-pairing an agent invalidates all of that agent's
outstanding data-plane capabilities and closes its open WebSocket, Postgres,
and SSH connections, including connections opened through one-time or saved
access. Saved "use without asking" permissions remain dormant for a
disconnected name unless the user removes them or chooses **Require approval
again** while reconnecting it.

## Conformance

- The **core** owns the Keychain, the daemon, the policy engine, and the audit log.
- The **webview** gets metadata and explicitly requested short prefixes, never
  full stored values, and cannot complete a high-consequence *Allow once*
  decision, start an access session, save a standing rule, or make protected
  configuration changes without a core-owned native OS authentication sheet.

Implementation notes:

- **Keychain backend.** `vault.rs` uses the `keyring` crate's apple-native
  backend, which targets the login keychain and does not expose the Data
  Protection keychain's `SecAccessControl` policies.
  Native reauthentication on read is enforced by the broker before
  app-initiated vault reads; true Keychain-enforced per-item ACL semantics
  require direct Security.framework calls and corresponding signing
  entitlements.
- **Peer identity.** `peer.rs` implements the audit-token + `SecCode`
  code-signature check on macOS. Unsigned/ad-hoc macOS peers are important
  because they have no signing anchor; AgentMFA binds them to local
  executable metadata (uid, path, file id, and executable SHA-256 when
  available) and displays that weaker identity explicitly. Non-macOS dev
  builds pin the peer UID instead (there is no code-signature oracle) and
  mark the identity `dev-unverified`.
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
- **HTTP consequence classification.** For access-session scope, idempotency,
  and the extra confirmation on *Allow once*, AgentMFA classifies `GET` and
  `HEAD` as read-like and every other accepted method as potentially mutating.
  In the desktop app, starting an access session always requires native
  confirmation, including for a read. The method classification is a
  heuristic, not a guarantee about upstream behavior: an action performed
  through `GET` can fit in read access, while a harmless `POST` requires full
  access.
- **Agent-visible redaction.** Exact matches of rendered credential material
  in relayed upstream responses **MUST** be redacted. Implementations **SHOULD**
  make a best effort to redact common components and reversible encodings, but
  arbitrary upstream transformations cannot be guaranteed. Broker-generated
  responses and errors **MUST NOT** disclose stored secret names or values.
- **Activity log.** Activity entries are a local product log, not a
  tamper-evident audit ledger. Appends are best effort: serialization or disk
  failures are logged but do not fail the broker operation, and an event shown
  live in the UI may therefore be absent after restart. Exact stored secret
  values **MUST NOT** be written to activity entries, but local UI-oriented
  entries may include user-facing secret names.
- **On-disk integrity and identity strength.** `index.json`, `rules.json`, and
  `agents.json` are sealed with HMAC-SHA256 under a vault-held key and refuse
  to load on a verification failure (bare pre-seal files migrate
  trust-on-first-use). Identity pinning remains intentionally limited:
  interpreted runtimes may present a coarse shared identity, and unsigned or
  ad-hoc peers use a weaker best-effort local executable fingerprint.

## Persistence map

```text
AgentMFA persistence
|
|-- macOS production app state
|   `~/Library/Application Support/agentmfa/`        0700 dir
|   |
|   |-- index.json                                  0600, atomic, HMAC-sealed
|   |   `-- secret metadata, connection configs, settings
|   |       - secret ids/names/timestamps only
|   |       - connection targets/templates/secret UUID refs
|   |       - settings: reauth, hide prefixes, pg CA bundle path,
|   |         menu bar Dock behavior
|   |
|   |-- rules.json                                  0600, atomic, HMAC-sealed
|   |   `-- standing "always allow" rules:
|   |       agent name + stable connection UUID
|   |
|   |-- agents.json                                 0600, atomic, HMAC-sealed
|   |   `-- paired agent records:
|   |       token hash, token preview, identity pin, last_used
|   |       no raw bearer token
|   |
|   |-- audit.jsonl                                 0600, append-only, not sealed
|   |   `-- audit/event stream; no intentionally recorded stored values
|   |
|   `-- dev-vault.json                              non-macOS dev fallback only
|       `-- unencrypted file vault: secret values + integrity key
|
|-- macOS Keychain
|   |
|   |-- service: com.aka.desktop
|   |   |
|   |   |-- account: <secret UUID>
|   |   |   `-- raw secret value
|   |   |
|   |   `-- account: 00000000-0000-0000-0000-000000000000
|   |       `-- state integrity HMAC key
|   |
|   `-- dev-root services:
|       com.aka.desktop.dev.<sha256(canonical root)>
|       `-- same account layout, isolated per `--root`
|
|-- runtime / agent rendezvous state
|   `~/.agentmfa/`                                  0700 dir
|   |
|   |-- broker.lock                                 0600 persistent advisory lock
|   |
|   |-- broker.sock                                 0600 Unix socket, ephemeral
|   |
|   |-- tokens/                                     0700 dir
|   |   `-- <agent-name>                            raw bearer token, written by agents
|   |                                               broker only advertises this path
|   |
|   `-- ssh/
|       `-- agent-<random>.sock                     0600 per-approved SSH socket,
|                                                   ephemeral/swept
|
|-- dev/test root layout with `--root /path/to/root`
|   `/path/to/root/`
|   |
|   |-- data/
|   |   |-- index.json
|   |   |-- rules.json
|   |   |-- agents.json
|   |   |-- audit.jsonl
|   |   `-- dev-vault.json                          non-macOS only
|   |
|   `-- sock/
|       |-- broker.lock
|       |-- broker.sock
|       |-- tokens/
|       `-- ssh/
|
`-- in-memory only
    |-- approval queue
    |-- fixed-lifetime access sessions and their authorization state
    |-- bounded idempotency tombstones and replay bodies
    |-- WS/PG/SSH tickets and live sessions
    |-- rate-limit buckets
    |-- superseded-token hints
    `-- loopback WS/PG proxy ports
```

Integrity checks apply to `index.json`, `rules.json`, and `agents.json`. They
are sealed as `{"v","alg","mac","payload"}` using an HMAC key stored in the
vault/Keychain. `audit.jsonl` is append-only and tolerant of bad lines, but not
integrity-sealed.

The archive action moves only the persistent app data directory, so on macOS
it archives:

```text
~/Library/Application Support/agentmfa
-> ~/Library/Application Support/agentmfa.bak-YYYYMMDD-HHMMSS
```

It deliberately does not move `~/.agentmfa`, so broker sockets, agent token
files, and SSH socket directories are left alone. It also does not delete
Keychain secret values or the integrity key.
