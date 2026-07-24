# Multitool

Multitool is a credential broker for AI coding agents. Agents make API
calls, open database connections, and reach SSH servers using
unmodified tools like `curl`, `psql`, and `git`.

The broker keeps the raw credentials in a local secret store and
injects them on the upstream leg only, so agents never hold them.
Access is authorized per tool: an enabled connection executes
immediately, a disabled one is refused for every agent at once.

This package installs the broker's command line as both `multitool` and
`aka`: the headless broker, the store seeding commands, and the
skill-file generator that teaches agents how to use the broker.

- **HTTP**: the agent supplies method/path/headers/body to a pinned host
- **Postgres**: the agent gets a password-less DSN plus a short-lived ticket
- **SSH**: the agent gets an `SSH_AUTH_SOCK` that signs only for the
  connection's pinned user and server host key
- **WebSocket**: the agent gets a short-lived `ws://127.0.0.1:…` bridge URL

## Install

```sh
npm install -g @aka-labs/multitool
```

This requires Node 22 or newer. It installs a prebuilt binary via a
platform-specific optional dependency plus a self-contained JavaScript MCP
host. The MCP host reuses the Node executable that launches `aka`; npm does not
install a second runtime. There is no postinstall script and no install-time
network access beyond npm itself.

Supported platforms: macOS (Apple silicon and Intel) and Linux
(x64 and arm64, glibc). The broker rendezvous is a Unix domain socket, so
Windows is not supported.

## Quick start

Run a broker headless (the desktop app is the primary interface; the
CLI is its dev/headless counterpart):

```sh
aka serve
```

Seed the store from another terminal (offline edits require the broker to
be stopped first, so it cannot overwrite them from memory):

```sh
printf '%s' "$GITHUB_TOKEN" | aka secret add GITHUB_TOKEN
aka conn add github --kind api --host api.github.com \
    --template 'Authorization: Bearer {{GITHUB_TOKEN}}'
aka conn list
```

The rest of the lifecycle is headless too: `aka secret
list|rename|replace|rm`, `aka conn update|rename|rm`, per-tool agent
access with `aka conn enable|disable`, and `aka conn test` to check a
connection against its pinned destination. These edits run through the
broker's own management layer, so audit entries and side effects (a
retarget revoking direct endpoints, for example) match the app exactly.

Management commands also work against a **running** broker — no
stop/start needed — over its manage API, authorized by the management
token (never the agent key):

```sh
aka manage token                # once, while the broker is stopped
aka manage login                # paste the token; stored per broker
aka conn disable github        # edits the live broker over its socket
aka conn list --broker https://broker.example.dev   # hosted brokers too
```

`aka manage login --broker <url>` stores a token for a hosted broker
(macOS: login Keychain; elsewhere a 0600 file), and `AKA_MANAGE_TOKEN`
overrides for CI. With no broker running, the same commands fall back
to editing the local files offline, exactly as before.

The operator's view is covered by `aka key` (print the shared agent
key; `--rotate` disconnects every agent at once), `aka status` (is a
broker up, and what does it serve), and `aka activity` (the audit
trail, readable while the broker runs).

Open Postgres and SSH sessions straight from the shell — each command
prints the one value a stock client needs, minted by the running broker
(the DSN embeds a short-lived session ticket):

```sh
psql "$(aka dsn analytics)"
export SSH_AUTH_SOCK="$(aka ssh production)"
git push production main
```

Teach the agents in a repository about the broker:

```sh
aka skill --write          # writes .claude/skills/aka/SKILL.md
aka skill --write --user   # or ~/.claude/skills/aka/SKILL.md for all repos
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
  Keychain, and copying a secret's full value from the desktop app can
  require native reauthentication (Touch ID). ABP/0
  agents authenticate with the machine's shared broker key; the key is not
  bound to a process or code-signing identity.
- **Linux** support is developer-grade: secrets are kept in a `0600` JSON
  file vault that is **not encrypted at rest**. `aka serve` prints a warning
  to this effect. It is intended for development, integration testing, and
  evaluation rather than production use.
