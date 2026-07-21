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

Per-agent identity: `POST /v1/pair` already mints a stable `client_id`
and a bearer token, and that existing token *is* the MCP credential.
Phase 2 found no reason to mint a second one — the sidecar simply passes
the agent's token through, and the broker resolves it on every request.
One credential, one lifecycle, and revoking it in the app takes effect
on the next call rather than whenever a cache expires.

## Phases

Each phase ends with a commit and a review pass before the next starts.

**Phase 1 — sidecar lifecycle. Done.** A Node process supervised by
`aka_core::sidecar`: spawned on start, announcing an ephemeral loopback
port on stdout, gated by a per-process bearer token, forwarding JSON log
lines into our tracing output, restarted with backoff, and reaped on
drop. Path policy lives in the shell (`src-tauri/src/sidecar.rs`), so the
core stays testable without a Node toolchain. A missing bundle is not an
error — the app runs without MCP.

Shipping: the bundle is a Tauri resource; the pinned Node is an
`externalBin` declared in `tauri.bundle.conf.json` rather than the base
config, because Tauri validates external binaries on *every* build of the
shell crate and that would make `cargo test` require the download.

**Phase 2 — the reimplemented MCP host. Done.** The two seams, ours:
`BrokerAuthProvider` resolves a bearer token by asking the broker, and
`SessionStore` owns sessions keyed to the principal that opened them.
Streamable HTTP at `/mcp` via `@modelcontextprotocol/sdk`.

The simplification that made this small: **agents already hold a broker
token**, so the sidecar proxies that same credential rather than minting
a second one. No new token type, no new lifecycle, and revocation is
immediate because the token is re-resolved on every request. `/health`
(supervisor token) and `/mcp` (agent token) authenticate separately, so
routing precedes authentication.

Two audiences, two credentials, one decision-maker: the broker. Unwired
connections are not listed, and naming one directly is refused with the
same message as a name that does not exist — an agent cannot enumerate
what the user declined to wire.

**Phase 3 — `plugin-multitool`. Done.** Every wired connection is now a
real MCP tool in `tools/list`, shaped by what its plane does: `api`
connections are *called* (`multitool_<name>_request`, method/path/body,
one round trip), while `pg`/`ssh`/`ws` are *opened*
(`multitool_<name>_open`, returning a password-less DSN and ticket, an
`SSH_AUTH_SOCK` path, or a bridge URL). Unwired connections are never
registered at all.

`multitool_status` is always registered. It is what installs the MCP tool
handlers — a server with zero tools answers `tools/list` with "Method not
found", a baffling thing for an agent wired to nothing to meet — and it
tells that agent who it is and what to ask the user for.

Verified end to end against a real broker and a real upstream: the
`Authorization` header arrives upstream with the injected credential, and
the same secret is absent from everything the agent sees.

**Phase 4 — real MCP. Done.** An API connection gained one optional
field, `mcp_path`. When set, that upstream speaks MCP, and the sidecar
re-exposes its tools as `multitool_<namespace>_<tool>`.

No new connection kind, deliberately. An MCP server reached over HTTP
*is* an API connection in every way that matters: pinned host, pinned
scheme and port, credential injected on the upstream leg. Making it a
field rather than a kind is also what keeps the secret out of the
sidecar — MCP JSON-RPC rides the existing `/v1/http` plane, so the
sidecar never opens a socket to the upstream and never sees its
credential. It is wiring-checked like everything else, and the field is
omitted from `/v1/connections` when unset, so the payload is unchanged
for every other connection.

From executor we import `deriveMcpNamespace` and `joinToolPath` out of
`@executor-js/plugin-mcp/core`, so a tool surfaced here is named the way
an executor host would name it. We do **not** adopt `mcpPlugin` itself:
it needs `createExecutor` with a SQLite store, which is precisely the
second source of truth for connections that the risks section warns
against — and it peer-depends on React and TanStack Router, which have
no business in a headless sidecar.

Stdio MCP servers are not supported. Spawning one requires putting its
credential in the sidecar's environment, which this design exists to
avoid; doing it properly means the broker spawns the process.

The review here caught a **credential leak**: registering a tool with no
input schema makes the MCP SDK pass its `extra` — session id, request
headers, the agent's own `Authorization` — as the handler's first
argument, which we then forwarded upstream as tool arguments. Declaring a
permissive `z.looseObject({})` fixes it; a regression test asserts the
agent's token never appears in what the upstream receives.

**Phase 5 — UI. Done.** GitHub, Gmail, Notion and 1Password are no longer
dimmed: they are `mcp: true` catalog rows that add an API connection with
an `mcp_path`. A generic **MCP server** row covers anything else. The add
form asks for a server URL rather than an API root, splits it into a
pinned origin plus the MCP path, and defaults a bare origin to `/mcp`.
The Get Started "MCP server" option is real.

No vendor endpoint URLs are shipped. A branded row is a labelled
shortcut; the user supplies the server URL their provider gave them,
because guessing at someone else's infrastructure is not something to
hard-code.

Two things the headless UI pass caught: the dialog was titled "Add Custom
API" for the Notion row (it now names the row the user clicked), and a
dev fixture referencing an unseeded secret left frontend-only mode on a
blank page — that lookup now says what is wrong instead of throwing.

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
