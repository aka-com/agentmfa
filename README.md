# AgentMFA

AgentMFA lets your agents make API calls, connect to databases and
servers, and talk to MCPs without exposing credentials.

It combines a secrets vault, connection broker, and tool router into
one application, so your agents can use unmodified CLI tools like
`curl`, `psql`, and `git`, with credentials stored in a secure vault.

## How it works

Giving an agent real access usually means pasting live credentials
into its environment, whether through a `.env` file or global
environment variables. That means:

- Every agent holds every secret in plaintext, in context.
- A prompt injection can copy those plaintext credentials and use them
  outside the intended service.
- Rotating a key means hunting down every config that copied it.
- Use may leave no central record.

AgentMFA sits between your agents and everything they reach. Agents
talk to services through a local proxied endpoint to make API calls or
open database connections. The real upstream credential is injected on
the upstream leg only and never enters agent context. AgentMFA records
brokered use and lets you disable a connection centrally instead of
redistributing its upstream credential.

AgentMFA is primarily tested locally today, but a hosted version has
been implemented for a shared vault. Hosted mode is one broker per trust
domain, not a multi-user authorization system: see [HOSTING.md](HOSTING.md)
before exposing it to a network. We also support limited audit logging,
and team management is coming soon.

### Security boundary

AgentMFA keeps the real API token, database password, or SSH private key
out of the agent's files and context. It does not sandbox agents from one
another. Every process running as the same local user can read the shared
0600 broker key (or pair over the private local socket) and can use every
connection currently enabled for agents. Client labels are self-reported
audit attribution, not identities or authorization boundaries.

Connections are enabled for agents by default when added. Turning one off
prevents new calls and closes broker-owned HTTP/Postgres sessions; an SSH
login that already authenticated is between the SSH client and server and
cannot be terminated by the broker. Rotating the broker key is the broad
revocation action: it revokes tickets and standing endpoints and closes
broker-owned sessions, but it still cannot kill an already-authenticated SSH
process.

Direct endpoints deliberately expose a separate broker credential to their
client. Each one expires after 30 days; renewal preserves the address and
secret so long-lived client configuration does not need to change, while
rotation invalidates the old secret immediately. Treat that endpoint secret
like any other standing credential and revoke or rotate it if copied somewhere
untrusted. Response scrubbing removes recognized reflections of injected
credentials, but cannot guarantee that an upstream will not transform or
encode credential material into a new form.

1. **Create a connection.** Select a destination to connect to: an API
   host, Postgres database, SSH server, or MCP server.

2. **Create a secret.** Pin an API token, database password, or SSH key
   inside the application, using the desktop app or `mfa secret add`.

3. **Give your agent the endpoint.** Each connection gets its own local
   credential-free endpoint, that you can provide to your agent as a
   DATABASE_URL, SSH endpoint, etc., while MCPs get a unified tool.

   ```sh
   eval "$(mfa dsn analytics)" && psql             # ticket stays in PGPASSWORD
   export SSH_AUTH_SOCK="$(mfa ssh production)"    # scoped signing agent
   claude mcp add agentmfa -- mfa mcp             # unified MCP tool
   ```

   For each connection type, the broker injects the real credential on
   the upstream connection. Turn the connection off in the app to refuse
   new use; rotate the broker key for broad revocation, subject to the
   already-authenticated SSH limitation above.

## Supported agents

Any agent that uses MCP or the CLI works: Claude Code, Claude Desktop,
Codex, Cursor, your own harness using `curl`.

### Direct connection setup

Agents that run shell commands don't need MCP at all: each connection
is automatically exposed as a local endpoint, that automatically
injects the credential on the upstream.

- **Postgres** — `mfa dsn <connection>` prints shell-safe `PG*` exports with
  the short-lived ticket in `PGPASSWORD`, keeping it out of process-visible
  argv:

  ```sh
  eval "$(mfa dsn analytics)"
  psql
  ```

  The broker-facing Postgres leg does not support TLS and therefore sets
  `PGSSLMODE=disable`; use it only over the trusted path to the broker.
  Upstream TLS from the broker to the database is configured separately on
  the connection. `--format uri` is available for compatibility but embeds
  the ticket in argv.

- **SSH** — `mfa ssh <connection>` prints an `SSH_AUTH_SOCK` backed by a
  scoped signing agent; the private key never leaves the broker. Works
  with stock `ssh`, `git`, `scp`, and `rsync`:

  ```sh
  export SSH_AUTH_SOCK="$(mfa ssh production)"
  ssh production uptime
  git push production main
  scp app.tar.gz production:/srv/app/
  rsync -av build/ production:/srv/app/
  ```

- **HTTP / API** — each API connection gets a loopback endpoint, which
  you can use to directly reach the upstream with `curl` and SDKs.
  Issue the endpoint in the app, then send its endpoint secret in place
  of the real credential; the broker swaps it for the real one upstream:

  ```sh
  curl -H "Authorization: Bearer $ENDPOINT_SECRET" \
    http://127.0.0.1:52000/user/repos
  ```

### AgentMFA MCP setup

Every connection is also exposed as an MCP tool. API connections are
exposed as `agentmfa_<name>_request`, and databases/servers as
`agentmfa_<name>_open`, which returns a ready-to-use local endpoint.

Upstream MCP servers are proxied through the same broker, so their
credentials stay in the vault too. HTTP/Postgres/SSH connections are
registered as one native AgentMFA tool each. Streamable-HTTP MCP upstreams
contribute their own bounded tool names and may be limited to a curated
subset in the app; upstream stdio servers are not supported. Native
connection enable/rename changes are announced during a session, while an
upstream MCP catalog is discovered at session start—reconnect to refresh it.
Use `agentmfa_status` first when a tool is missing or an upstream failed.

**Claude Code**:

```sh
claude mcp add agentmfa -- mfa mcp --client claude-code
```

**Claude Desktop** in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "agentmfa": {
      "command": "mfa",
      "args": ["mcp", "--client", "claude-desktop"]
    }
  }
}
```

**Codex** in `~/.codex/config.toml`:

```toml
[mcp_servers.agentmfa]
command = "mfa"
args = ["mcp", "--client", "codex"]
```

Any client that launches stdio servers can run `mfa mcp` directly,
which discovers the broker and its key automatically.

## Contributing

To build the desktop app, run the test suites, or iterate on the UI
against a mock broker, see [DEVELOPING.md](DEVELOPING.md).

## License

AgentMFA is available under the [MIT License](LICENSE).
