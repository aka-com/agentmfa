# Multitool

Multitool is a credential broker for AI coding agents. Agents make API
calls, open database connections, and reach SSH servers using
unmodified tools like `curl`, `psql`, and `git`.

The broker keeps the raw credentials in a local secret store and
injects them on the upstream leg only, so agents never hold them.
Access is authorized per tool: an enabled connection executes
immediately, a disabled one is refused for every agent at once.

This package installs the broker's command line as `multitool`, with `mfa`
and `agentmfa` retained as compatibility aliases. It includes the headless
broker, store-seeding commands, and the skill-file generator that teaches
agents how to use the broker.

- **HTTP**: the agent supplies method/path/headers/body to a pinned host
- **Postgres**: the agent gets a password-less DSN plus a short-lived ticket
- **SSH**: the agent gets an `SSH_AUTH_SOCK` that signs only for the
  connection's pinned user and server host key

## Install

```sh
npm install -g @aka-com/multitool
```

This requires Node 22 or newer. It installs a prebuilt binary via a
platform-specific optional dependency. There is no postinstall script and no
install-time network access beyond npm itself.

Supported platforms: macOS (Apple silicon and Intel) and Linux
(x64 and arm64, glibc). The broker rendezvous is a Unix domain socket, so
Windows is not supported.

## Quick start

Run a broker headless (the desktop app is the primary interface; the
CLI is its dev/headless counterpart):

```sh
multitool serve
```

Seed the running broker from another terminal:

```sh
printf '%s' "$GITHUB_TOKEN" | multitool secret add GITHUB_TOKEN
multitool conn add github --kind api --host api.github.com \
    --template 'Authorization: Bearer {{GITHUB_TOKEN}}'
multitool conn list
```

The rest of the lifecycle is headless too: `multitool secret
list|rename|replace|rm`, `multitool conn update|rename|rm`, per-tool agent
access with `multitool conn enable|disable`, and `multitool conn test` to check a
connection against its pinned destination. These edits run through the
broker's own management layer, so audit entries and side effects (a
retarget revoking direct endpoints, for example) match the app exactly.

With a local broker running, management commands use its manage API
automatically — no stop/start needed — authorized by the management token
(never the agent key):

```sh
multitool serve                       # first start writes ~/.aka/manage-token (0600)
multitool manage token                # rotate it online and store the replacement
multitool conn disable github         # edits the live broker over its socket
multitool conn list --broker https://broker.example.dev   # hosted brokers too
```

`multitool manage login --broker <url>` stores a token for a hosted broker
(macOS: the Keychain; elsewhere a 0600 file), and `AKA_MANAGE_TOKEN`
overrides for CI. `multitool manage token --broker <url>` rotates a hosted
broker using that current credential. With no local broker running,
commands fall back to editing the local files offline, exactly as before.

The operator's view is covered by `multitool key` (print the shared agent
key; `--rotate` disconnects every agent at once), `multitool status` (is a
broker up, and what does it serve), and `multitool activity` (the audit
trail, readable while the broker runs).

Open Postgres and SSH sessions straight from the shell — each command
prints the one value a stock client needs, minted by the running broker
(the DSN embeds a short-lived session ticket):

```sh
psql "$(multitool dsn analytics)"
export SSH_AUTH_SOCK="$(multitool ssh production)"
git push production main
```

Teach the agents in a repository about the broker:

```sh
multitool skill --write          # writes .claude/skills/multitool/SKILL.md
multitool skill --write --user   # or ~/.claude/skills/multitool/SKILL.md for all repos
multitool skill --write --broker https://broker.example.dev  # hosted setup
```

Local agents discover the live contract from the broker itself; hosted skill
generation fetches the selected broker's authoritative setup text:

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

  The signed Multitool app reads its Keychain items without any OS approval
  dialog, because it is entitled to the data-protection keychain. This `multitool`
  binary is published unsigned, so when it opens the store *offline* (with no
  broker running) it uses the login keychain and macOS asks you to approve
  each item. Working against a running broker — the normal path, and every
  `--broker` command — goes over the socket and never touches the Keychain.
  `multitool status` reports which keychain the store is on.
- **Linux** uses a `0600` JSON development vault when no master key is
  configured. That fallback is **not encrypted at rest**, and `multitool serve`
  prints a warning. Set `AKA_VAULT_KEY` or `AKA_VAULT_KEY_FILE` to use the
  encrypted XChaCha20-Poly1305 file vault. Never expose a network broker with
  the plaintext fallback; follow the
  [hosted Linux runbook](https://github.com/aka-com/multitool/blob/main/dev/hosted-linux/README.md)
  for deployment.
