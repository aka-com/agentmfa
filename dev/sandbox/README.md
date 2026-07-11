# Developer service sandbox

This Docker Compose stack provides disposable upstream services for manually
exercising every AgentMFA connection type. AgentMFA itself runs natively so it
can continue to use the host Keychain, Tauri webview, and Unix socket.

The stack contains:

- go-httpbin for HTTP requests, status codes, redirects, bodies, and delays;
- an HTTP/WebSocket echo server for bridge and frame tests;
- Postgres with a fixed, test-only login; and
- OpenSSH with a generated, sandbox-only client key.

All published ports bind to `127.0.0.1`. The credentials are intentionally
fake and must never be reused outside this sandbox.

## Start and stop

Prerequisites are Docker with Compose v2, `curl`, `ssh-keygen`, and
`ssh-keyscan`.

```sh
npm run sandbox:up
```

The first start creates a dedicated SSH client key under the ignored
`dev/sandbox/state/` directory. Once all services answer, the command prints
the exact values to enter in AgentMFA, including the current SSH host-key
fingerprint.

Inspect the current containers and print the connection values again:

```sh
npm run sandbox:status
```

Stop and remove the containers:

```sh
npm run sandbox:down
```

Normal shutdown preserves the generated client key in `dev/sandbox/state/`
and the SSH server host keys in a Docker volume. To reset the server host key,
run `docker compose -f dev/sandbox/compose.yaml down --volumes`; to reset the
client key as well, remove `dev/sandbox/state/` before the next start. Either
reset changes the SSH identity, so update the service in AgentMFA afterward.

## Suggested smoke checks

### HTTP API

Create an HTTP API service using the printed origin, fake secret, and Bearer
template. The built-in service test calls the origin root. Agent-driven checks
can exercise behavior such as:

```text
GET /status/200
GET /status/401
GET /redirect/2
GET /delay/2
POST /anything
```

Only use the documented fake token. Echo endpoints can reflect request data.

### WebSocket

Create a WebSocket service using the printed URL and fake Bearer token. The
server accepts the header without validating it. Open the service through
AgentMFA, connect a normal WebSocket client to the returned loopback URL, and
verify that text and binary messages are echoed unchanged.

### Postgres

Create a Postgres service from the printed values. The local container does
not use TLS, so select `disable` for SSL mode. After the built-in connection
test succeeds, open it through AgentMFA and run:

```sql
SELECT current_user, current_database(), version();
```

### SSH

Create an SSH service from the printed values and import the generated private
key. After the reachability test succeeds, open it through AgentMFA and run a
harmless command such as `whoami` or `uname -a` with the returned
`SSH_AUTH_SOCK`.

The built-in SSH test checks key parsing and the server banner only. A real
agent-mediated login is needed to exercise host-bound signing and host-key
pinning.

## Troubleshooting

If a published port is already occupied, change it in `compose.yaml` and keep
the printed connection information in `scripts/sandbox-status.sh` in sync.

Container logs are available with:

```sh
docker compose -f dev/sandbox/compose.yaml logs
```

Do not mount the repository, home directory, or real credentials into these
containers.
