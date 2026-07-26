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
- One prompt injection can read all of them at once.
- Rotating a key means hunting down every config that copied it.
- There's no record of which agent used which credential, or when.

AgentMFA sits between your agents and everything they reach. Agents
talk to services through a local proxied endpoint to make API calls or
open database connections, Credentials are injected on the upstream
leg only, and never enter an agent's context.

AgentMFA is primarily tested locally today, but a hosted version has
been implemented, that can be used with a shared vault. We also
support limited audit logging, and team management is coming soon.

## How it works

1. **Create a connection.** Select a destination to connect to: an API
   host, Postgres database, SSH server, or MCP server.

2. **Create a secret.** Pin an API token, database password, or SSH key
   inside the application, using the desktop app or `mfa secret add`.

3. **Give your agent the endpoint.** Each connection gets its own local
   credential-free endpoint, that you can provide to your agent as a
   DATABASE_URL, SSH endpoint, etc., while MCPs get a unified tool.

   ```sh
   psql "$(mfa dsn analytics)"                     # passwordless DSN
   export SSH_AUTH_SOCK="$(mfa ssh production)"    # scoped signing agent
   claude mcp add agentmfa -- mfa mcp             # unified MCP tool
   ```

   For each connection type, the broker injects the real credential on
   the upstream connection, and strips it from anything the agent sees
   coming downstream. Revoking access is easy - just turn off the
   connection inside the app.

## Supported agents

Any agent that uses MCP or the CLI works: Claude Code, Claude Desktop,
Codex, Cursor, your own harness using `curl`.

### Direct connection setup

Agents that run shell commands don't need MCP at all: each connection
is automatically exposed as a local endpoint, that automatically
injects the credential on the upstream.

- **Postgres** — `mfa dsn <connection>` prints a passwordless DSN with a
  short-lived ticket, ready for `psql`, ORMs, or migration tools:

  ```sh
  psql "$(mfa dsn analytics)"
  ```

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
credentials stay in the vault too.

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
