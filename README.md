# AgentMFA

AgentMFA is a secrets manager for agents. Make API calls, open database and WebSocket connections, and authenticate SSH sessions — with unmodified tools like `curl`, `psql`, and `git` — without exposing critical secrets to Claude, Codex, or other local agents.

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

- **Secrets manager for agents.** Raw values live in macOS Keychain items, and are only injected into approved outgoing requests, and bidirectional connections.
- **Per-use human approval.** Requests wait for your approval. Click *Allow once*, *Always allow…* or a Touch ID approval for high-consequence actions.
- **Supports most agent workflows:** Injects credentials for HTTP, WebSocket, Postgres, and SSH.
  - **HTTP** — the agent supplies method/path/headers/body; the connection pins the host; redirects are only followed within that host.
  - **WebSocket** — the agent gets a short-lived `ws://127.0.0.1:…` bridge URL usable by any stock WS client.
  - **Postgres** — the agent gets a password-less DSN + one-time ticket; unmodified `psql` works, while the broker speaks TLS + SCRAM upstream.
  - **SSH** — the agent gets an `SSH_AUTH_SOCK` path; unmodified `ssh`/`git`/`rsync` work, while the broker holds the private key and signs — but only a login as the connection's pinned user, and nothing else.
- **Identity-pinned pairing.** Connected agents are pinned to their code-signing identity, or to a best-effort local executable fingerprint for unsigned/ad-hoc peers, so a copied token is not generally reusable by another process.
- **Local activity log.** Pairing, approval, denial, and upstream events are shown in the app's Activity view for review, but the log is not a tamper-evident audit ledger.
- **Free and open source.** MIT licensed desktop application for individuals and small teams; contact us for enterprise support.

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

The intended Data Protection Keychain backend also needs a macOS entitlement file referenced by `bundle.macOS.entitlements`:

```xml
<key>keychain-access-groups</key>
<array>
  <string>TEAMID.com.aka.desktop</string>
</array>
```

Replace `TEAMID` with the signing team's App Identifier Prefix and keep the bundle identifier (`com.aka.desktop`) stable. The current `keyring` backend compiles without this entitlement, but real Data Protection Keychain support for iCloud sync and per-item access control should ship with it.

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
   only; never secret names or values) and whether each one `will_prompt`
   or is already `auto_allowed`.
3. Call a capability, naming a connection:
   - `POST /v1/http` — `{status, headers, body}`; the broker injects the
     credential, validates the path, and follows redirects only within the
     connection's pinned host.
   - `POST /v1/ws/open` — a `ws://127.0.0.1:<port>/…/<ticket>` bridge URL for
     any stock WebSocket client.
   - `POST /v1/pg/open` — a password-less DSN + a ticket to pass via
     `PGPASSWORD`; unmodified `psql` runs against the local proxy.
   - `POST /v1/ssh/open` — an `auth_sock` path to point `SSH_AUTH_SOCK` at;
     unmodified `ssh`/`git`/`rsync` authenticate through the broker's
     ssh-agent, which signs only a login as the connection's pinned user.

Every use is surfaced to the human for approval (per-request by default, or a
standing "always allow" rule); the approval is a **held-open request** — the
call simply blocks until the user decides or the 120 s timeout auto-denies.

## Conformance

- The **core** owns the Keychain, the daemon, the policy engine, and the audit log.
- The **webview** gets masked metadata only and cannot complete high-consequence actions without a
core-owned Touch ID sheet.

Documented differences from DESIGN.md:

- **Keychain backend.** `vault.rs` uses the `keyring` crate's apple-native
  backend, which targets the login keychain and does not expose the Data
  Protection keychain's `kSecAttrSynchronizable` / `SecAccessControl`.
  Touch-ID-on-read is enforced by the broker before app-initiated vault
  reads; true Keychain-enforced sync/per-item ACL semantics still require
  direct Security.framework calls plus the `keychain-access-groups`
  entitlement.
- **Peer identity.** `peer.rs` implements the audit-token + `SecCode`
  code-signature check on macOS. Unsigned/ad-hoc macOS peers are important
  because they have no signing anchor; AgentMFA binds them to local
  executable metadata (uid, path, file id, and executable SHA-256 when
  available) and displays that weaker identity explicitly. Non-macOS dev
  builds pin the peer UID instead (there is no code-signature oracle) and
  mark the identity `dev-unverified`.
- **Touch ID / clipboard.** `auth.rs` and `clipboard.rs` use
  LocalAuthentication and `NSPasteboard` on macOS; on other platforms the
  gate is a loud no-op and the concealed-clipboard write is skipped (both are
  macOS product features).
- **Activity log.** Activity entries are a local product log, not a
  tamper-evident audit ledger. Secret values are not written to the log, but
  local UI-oriented entries may include user-facing secret names.
- **On-disk integrity — closed; identity strength — deferred.** DESIGN.md
  §13.1 is implemented: `index.json`, `rules.json`, and `agents.json` are
  sealed with HMAC-SHA256 under a vault-held key and refuse to load on a
  verification failure (bare pre-seal files migrate trust-on-first-use).
  The §13.2 deferral (the interpreted-runtime signature caveat) is
  unchanged — noted, not solved.
