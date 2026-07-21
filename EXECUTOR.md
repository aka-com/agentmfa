# Executor integration plan

Multitool gains MCP — and a uniform tool model for everything else — by
embedding [executor](https://executor.sh) as a **Node sidecar** next to
the Rust broker. We import executor's published libraries and
reimplement their host, because the host is the part that has to answer
to our security model.

## What executor is

A Bun/Effect-TS monorepo (MIT, `github.com/UsefulSoftwareCo/executor`,
workspace `1.4.0-beta.0`). It models *integrations* → *connections* →
*tools*, resolves credentials through a provider seam, and serves the
result to agents over MCP.

**Published on npm (we import these):**

| Package | Why we want it |
| --- | --- |
| `@executor-js/sdk` | `createExecutor`, plugin API, `CredentialProvider` |
| `@executor-js/execution` | tool execution + result shaping |
| `@executor-js/plugin-mcp` | consume external MCP servers as tools |
| `@executor-js/config` | `executor.jsonc` plugin loading (optional) |
| `plugin-openapi`, `plugin-graphql` | later, for richer API tools |

**Private (not on npm — we reimplement):** `host-mcp`, `api`, `app`,
`react`, `local`, `desktop`, `integrations-registry`. This is why the
task is "reimplement their main host": `apps/local` and
`packages/hosts/mcp` are exactly the pieces npm does not give us.

Node compatibility checked: no `bun:` imports and no
`@effect/platform-bun` under `sdk`, `execution`, `config`, or
`plugins/mcp`, and `@effect/platform-node` is an optional peer. The
libraries we need run on Node.

## The two seams that make this tractable

`packages/hosts/mcp/src/seams.ts` reduces MCP serving to two tags —
`McpAuthProvider` (called on every request; authenticate *and*
authorize) and `McpSessionStore` (session lifecycle + dispatch). Our
reimplementation supplies both, so authorization stays ours.

`packages/core/sdk/src/provider.ts` defines `CredentialProvider`:
resolve an opaque `ProviderItemId` to a string, with optional
`has`/`set`/`delete`/`list`. Our Keychain vault becomes one of these.
Secrets never live in the sidecar's own store.

And plugins define `listTools` / `invokeTool`. That is the finding that
sets the shape of this plan: **Postgres, SSH and Custom API can be a
Multitool plugin**, not a special case bolted next to MCP. Executor's
tool model then covers the whole catalog.

## Architecture

```
   agent (Claude Code, …)
     │  MCP — streamable HTTP on loopback, per-agent bearer token
     ▼
   Node sidecar ── executor engine (@executor-js/sdk)
     │               ├─ @executor-js/plugin-mcp  → external MCP servers
     │               └─ plugin-multitool [ours]  → pg / ssh / api / ws
     │                      └─ CredentialProvider "multitool"
     ▼  ABP/0 over the existing Unix socket (mode 0600)
   Rust broker (aka-core) ── wirings · vault · audit · data planes
```

Three rules keep the security model intact:

1. **The sidecar is not trusted to authorize.** Every `invokeTool` round
   trips to the broker, which checks the wiring for the *calling* agent.
   The sidecar carries identity, it does not grant it.
2. **The broker stays the source of truth** for connections, wirings and
   secrets. Executor's SQLite store is sidecar-local cache and tool
   metadata only — never a second copy of a credential.
3. **Secrets do not enter the sidecar's storage.** They arrive, if at
   all, through the credential provider at call time; the preferred path
   is that they never arrive — the broker injects on the upstream leg as
   it does today.

Per-agent identity: `POST /v1/pair` already mints a stable `client_id`.
It additionally mints an MCP bearer token. Our `McpAuthProvider`
resolves token → `client_id` against the broker on every request, which
is what makes wiring enforcement work over MCP.

## Phases

Each phase ends with a commit and a review pass before the next starts.

**Phase 1 — sidecar lifecycle.** A Node process supervised by the Rust
shell: spawn on start, health endpoint on loopback, structured logs into
our activity log, dies with the app, restarts on crash with backoff. No
tools yet. *Verify:* app start brings it up, `/health` answers, app quit
reaps it, `kill -9` triggers one clean restart.

**Phase 2 — the reimplemented MCP host.** `McpAuthProvider` (bearer →
`client_id` via broker) and an in-process `McpSessionStore`, serving
`tools/list` and `tools/call` over `@modelcontextprotocol/sdk` against a
stub tool source. *Verify:* Claude Code connects and lists tools; a
wired agent calls the stub; an unwired agent gets `denied_by_policy`.

**Phase 3 — `plugin-multitool`.** Postgres, SSH, Custom API and Custom
WebSocket surface as executor tools whose `invokeTool` proxies to the
broker's existing data planes over ABP. *Verify:* a real query runs
through MCP end to end, with the password never leaving the broker;
audit entries land; the existing CLI path still works unchanged.

**Phase 4 — real MCP.** `@executor-js/plugin-mcp` lets a catalog row be
an external MCP server, with our vault behind `CredentialProvider` for
its auth. *Verify:* add a live MCP server, wire an agent, call one of
its tools; deleting the connection drops its wirings as it does for
every other tool type.

**Phase 5 — UI.** MCP catalog rows become addable, the dimmed
GitHub/Gmail/Notion/1Password rows light up, and the Get Started "MCP
app" option stops saying *not yet available*.

## Risks

- **Beta churn.** `1.4.0-beta.0` with `effect` 4.0.0-beta. Pin exact
  versions; treat an upgrade as its own reviewed change.
- **Two stores.** The clearest failure mode is executor's connection
  rows drifting from ours. Phase 3 must make the broker authoritative
  and the sidecar derived — not a sync.
- **Sandbox mismatch.** Executor's code-mode sandbox is one-shot with no
  network, which fights our long-lived PG/SSH/WS planes. We use the tool
  path, not code mode; revisit only if there is a reason to.
- **Approval routing.** Their default elicitation resumes *through the
  agent*. Ours must not: any prompt belongs in the trusted UI.
- **Shipping Node.** The sidecar binary has to be signed and notarized
  inside the `.app`. Decide in Phase 1 between a bundled pinned Node and
  a single-file build; it affects bundle size and the release script.
- **No response redaction** upstream. If a tool result can echo a
  secret, redaction is ours to add.
