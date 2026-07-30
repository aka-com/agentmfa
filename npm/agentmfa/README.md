# AgentMFA

AgentMFA is a credential broker for AI coding agents. Agents make API
calls, open database connections, and reach SSH servers using
unmodified tools like `curl`, `psql`, and `git`.

The broker keeps the raw credentials in a local secret store and
injects them on the upstream leg only, so agents never hold them.
Access is authorized per tool: an enabled connection executes
immediately, a disabled one is refused for every agent at once.

This package installs the broker's command line as both `agentmfa` and
`mfa`: the headless broker, the store seeding commands, and the
skill-file generator that teaches agents how to use the broker.

- **HTTP**: the agent supplies method/path/headers/body to a pinned host
- **Postgres**: the agent gets a password-less DSN plus a short-lived ticket
- **SSH**: the agent gets an `SSH_AUTH_SOCK` that signs only for the
  connection's pinned user and server host key

## Install

```sh
npm install -g agentmfa
```

This requires Node 22 or newer. It installs a prebuilt binary via a
platform-specific optional dependency plus a self-contained JavaScript MCP
host. The MCP host reuses the Node executable that launches `mfa`; npm does not
install a second runtime. There is no postinstall script and no install-time
network access beyond npm itself.

Supported platforms: macOS (Apple silicon and Intel) and Linux
(x64 and arm64, glibc). The broker rendezvous is a Unix domain socket, so
Windows is not supported.

## Quick start

Run a broker headless (the desktop app is the primary interface; the
CLI is its dev/headless counterpart):

```sh
mfa serve
```

Seed the store from another terminal (offline edits require the broker to
be stopped first, so it cannot overwrite them from memory):

```sh
printf '%s' "$GITHUB_TOKEN" | mfa secret add GITHUB_TOKEN
mfa conn add github --kind api --host api.github.com \
    --template 'Authorization: Bearer {{GITHUB_TOKEN}}'
mfa conn list
```

The rest of the lifecycle is headless too: `mfa secret
list|rename|replace|rm`, `mfa conn update|rename|rm`, per-tool agent
access with `mfa conn enable|disable`, and `mfa conn test` to check a
connection against its pinned destination. These edits run through the
broker's own management layer, so audit entries and side effects (a
retarget revoking direct endpoints, for example) match the app exactly.

Management commands also work against a **running** broker — no
stop/start needed — over its manage API, authorized by the management
token (never the agent key):

```sh
mfa manage token                # once, while the broker is stopped
mfa manage login                # paste the token; stored per broker
mfa conn disable github        # edits the live broker over its socket
mfa conn list --broker https://broker.example.dev   # hosted brokers too
```

`mfa manage login --broker <url>` stores a token for a hosted broker
(macOS: the Keychain; elsewhere a 0600 file), and `AKA_MANAGE_TOKEN`
overrides for CI. With no broker running, the same commands fall back
to editing the local files offline, exactly as before.

The operator's view is covered by `mfa key` (print the shared agent
key; `--rotate` disconnects every agent at once), `mfa status` (is a
broker up, and what does it serve), and `mfa activity` (the audit
trail, readable while the broker runs).

Open Postgres and SSH sessions straight from the shell — each command
prints the one value a stock client needs, minted by the running broker
(the DSN embeds a short-lived session ticket):

```sh
psql "$(mfa dsn analytics)"
export SSH_AUTH_SOCK="$(mfa ssh production)"
git push production main
```

Teach the agents in a repository about the broker:

```sh
mfa skill --write          # writes .claude/skills/mfa/SKILL.md
mfa skill --write --user   # or ~/.claude/skills/mfa/SKILL.md for all repos
```

Agents discover the live contract from the broker itself:

```sh
curl --unix-socket ~/.aka/broker.sock http://localhost/instructions
```

Every command accepts `--root <dir>` to run against an isolated directory
(data and socket under it) instead of the per-user defaults — handy for
demos, tests, and CI.

## Platform notes

- **macOS** is the fully supported product platform: secrets live in the
  Keychain. Explicit app actions authorize management changes, and copies are
  audited. ABP/0 agents authenticate with the machine's shared broker key; the
  key is not bound to a process or code-signing identity.

  The signed AgentMFA app reads its Keychain items without any OS approval
  dialog, because it is entitled to the data-protection keychain. This `mfa`
  binary is published unsigned, so when it opens the store *offline* (with no
  broker running) it uses the login keychain and macOS asks you to approve
  each item. Working against a running broker — the normal path, and every
  `--broker` command — goes over the socket and never touches the Keychain.
  `mfa status` reports which keychain the store is on.
- **Linux** support is developer-grade: secrets are kept in a `0600` JSON
  file vault that is **not encrypted at rest**. `mfa serve` prints a warning
  to this effect. It is intended for development, integration testing, and
  evaluation rather than production use.
