# Multitool

Multitool lets your agents make API calls, open database connections,
access servers, and connect to MCPs without sensitive credentials.

It combines a **secrets vault**, **connection broker**, and **router**
into one application, so your agents can use unmodified CLI tools like
`curl`, `psql`, and `git`, plus MCP servers where those exist.

## Why Multitool

Giving an agent real access usually means pasting live credentials
into its environment, whether through a `.env` file or global
environment variables. That means:

- Every agent holds every secret in plaintext, in context.
- One prompt injection can read all of them at once.
- Rotating a key means hunting down every config that copied it.
- There's no record of which agent used which credential, or when.

Multitool sits between your agents and everything they reach. Secrets
stay sealed in a local vault, and agents talk to services through
brokered endpoints to make API calls, or open streaming connections.
Credentials are injected on the upstream leg only, and never enter an
agent's context.

## How it works

1. **Store a secret.** Add API tokens, database passwords, or SSH keys to
   the vault, by using the desktop app or `aka secret add`.

2. **Create a connection.** Pin a secret to a destination: an API host, a
   Postgres database, an SSH server, a WebSocket URL, or an MCP server.

3. **Hand your agent an endpoint.** Each connection gets is own local
   credential-free endpoint, that you can provide to your agent as a
   DATABASE_URL, SSH endpoint, etc.

   ```sh
   psql "$(aka dsn analytics)"                     # passwordless DSN
   export SSH_AUTH_SOCK="$(aka ssh production)"    # scoped signing agent
   claude mcp add multitool -- aka mcp             # unified MCP tool
   ```

   The broker validates each call against the pinned destination, injects
   the real credential upstream, and strips it from anything the agent
   sees. To revoke access, turn the connection off inside the app.

## Using Multitool

Anything that speaks MCP or plain HTTP works: Claude Code, Claude
Desktop, Codex, Cursor, or your own harness with `curl`.

### Using direct connections

Agents that run shell commands don't need MCP at all: each connection
is automatically exposed as a local endpoint, that automatically
injects the credential on the upstream.

- **Postgres** — `aka dsn <connection>` prints a passwordless DSN with a
  short-lived ticket, ready for `psql`, ORMs, or migration tools:

  ```sh
  psql "$(aka dsn analytics)"
  ```

- **SSH** — `aka ssh <connection>` prints an `SSH_AUTH_SOCK` backed by a
  scoped signing agent; the private key never leaves the broker. Works
  with stock `ssh`, `git`, `scp`, and `rsync`:

  ```sh
  export SSH_AUTH_SOCK="$(aka ssh production)"
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

- **WebSocket** — opening a connection returns a local bridge URL. Auth
  is checked at open, and the credential is injected on the upstream dial:

  ```sh
  curl -s --unix-socket ~/.aka/broker.sock \
    -H "Authorization: Bearer $(cat ~/.aka/token)" \
    -H "Content-Type: application/json" \
    -d '{"connection": "market-feed"}' \
    http://localhost/v1/ws/open
  # → {"ws_url": "ws://127.0.0.1:<port>/v1/ws/bridge/<ticket>", ...}
  websocat "ws://127.0.0.1:<port>/v1/ws/bridge/<ticket>"
  ```

### Using Multitool over MCP

Every connection is exposed as an MCP tool. API connections are exposed
 as `multitool_<name>_request`, and databases/servers as
`multitool_<name>_open`, which returns a ready-to-use local endpoint.
Upstream MCP servers are proxied through the same broker, so their
credentials stay in the vault too.

**Claude Code** in the terminal:

```sh
claude mcp add multitool -- aka mcp --client claude-code
```

**Claude Desktop** in `claude_desktop_config.json`:

```json
{ "mcpServers": { "multitool": { "command": "aka", "args": ["mcp", "--client", "claude-desktop"] } } }
```

**Codex** in `~/.codex/config.toml`:

```toml
[mcp_servers.multitool]
command = "aka"
args = ["mcp", "--client", "codex"]
```

Any client that launches stdio servers can run `aka mcp` directly,
which discovers the broker and its key automatically.

## Contributing

To build the desktop app, run the test suites, or iterate on the UI
against a mock broker, see [DEVELOPING.md](DEVELOPING.md).
