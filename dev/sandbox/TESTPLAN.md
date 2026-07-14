# Sandbox test plan

Test in two layers: first verify the containers directly, then exercise
the same surfaces through AKA. Layer 2 can run against the desktop
app or the headless broker (see the end); the expected values below were
verified against both the fixture and the broker.

Default ports are used throughout; substitute yours if you exported
`SANDBOX_*_PORT` overrides.

## 1. Start the sandbox

From the repository root:

```sh
npm run sandbox:up
```

Expected output:

- a first-build notice (first start only), then
- `ready: HTTP`, `ready: WebSocket`, `ready: Postgres`, `ready: SSH`
- the Postgres and SSH Quick setup lines, all form values, and the SSH
  fingerprint

Check it again with `npm run sandbox:status`. The WebSocket readiness
check performs an authenticated upgrade and requires HTTP `101`; the
Postgres check probes over TCP so first-boot `initdb` cannot report
ready early.

## 2. Verify the containers directly

### HTTP authentication

Without the token, expect `401` with a `www-authenticate: Bearer`
header:

```sh
curl -i http://127.0.0.1:18080/authenticated
```

With the token, expect `200` and `{"authenticated":true}`:

```sh
curl -i \
  -H 'Authorization: Bearer aka-test-token' \
  http://127.0.0.1:18080/authenticated
```

Other useful checks (all with the same `Authorization` header):

```sh
curl -i http://127.0.0.1:18080/status/418        # 418 I'm a teapot
curl -i http://127.0.0.1:18080/redirect/same-origin   # 302, location: /authenticated
curl -i http://127.0.0.1:18080/redirect/cross-origin  # 302, location on port 18081
curl -i -H 'Content-Type: application/json' \
  --data '{"hello":"sandbox"}' \
  http://127.0.0.1:18080/echo                    # 200, body echoed
```

### Postgres

```sh
PGPASSWORD=aka-test-password \
  psql -h 127.0.0.1 -p 15432 \
  -U aka -d aka_sandbox \
  -c 'SELECT current_user, current_database();'
```

Expect `aka` and `aka_sandbox`.

### SSH

```sh
ssh \
  -i dev/sandbox/state/ssh/client_key \
  -p 12222 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  sandbox@127.0.0.1 \
  'whoami'
```

Expect `sandbox`. The relaxed host-key options are appropriate only for
this direct disposable-container check — never for AKA itself,
which pins the host key.

## 3. Add the services to AKA Desktop

Run AKA Desktop natively and add the four services by pasting each Quick
setup line printed by `sandbox:status` into **Services → Add a service
for your agent** (details in [README.md](README.md)). Then press
**Test** on each and expect:

| Service | Expected Test result |
| --- | --- |
| `sandbox-http` | an authenticated `HTTP 200 OK` from `GET /` |
| `sandbox-websocket` | `WebSocket handshake succeeded` |
| `sandbox-postgres` | `Signed in to aka_sandbox as aka` |
| `sandbox-ssh` | `Key loaded; 127.0.0.1:12222 answered with SSH-2.0-…` |

The SSH test checks key parsing and the server banner only; it does not
log in. Host-bound signing and host-key pinning are exercised by a real
agent connection in §5.

## 4. Exercise HTTP through a paired agent

Have the agent discover the connections (`GET /v1/connections`), then
make these requests through `sandbox-http`.

| Request | Expected result |
| --- | --- |
| `GET /authenticated` | `200`, `{"authenticated":true}` |
| `GET /redirect/same-origin` | final `200` from `/authenticated` — AKA followed the redirect and re-injected the credential |
| `GET /redirect/cross-origin` | the raw `302` with a `location` on port `18081`, not followed; a `418` means the credential sink was reached and is a failure |
| `GET /binary` | `200` with `body_encoding: "base64"` (5 bytes) |
| `GET /large/12582912` | `502` broker error, reason `response_too_large` (“upstream body exceeds the 10485760 byte cap”) |
| `POST /echo` with a JSON body | the same body back; also exercises the full-access approval path for a mutating request |

### Wrong credential

In the app, edit `sandbox-http` to use an incorrect token value and
press **Test**. Expect a failure reporting that the host rejected the
credential (HTTP `401`). Restore the correct token afterward. (The CLI
deliberately refuses to overwrite secrets, so this check is app-only.)

## 5. Exercise the session services through an agent

Session tickets expire quickly (about 60 seconds) — connect promptly
after each open.

### WebSocket

Open `sandbox-websocket` (`POST /v1/ws/open`). Connect any stock
WebSocket client to the returned `ws_url`
(`ws://127.0.0.1:<port>/v1/ws/bridge/<ticket>`), then send text and
binary messages. Each should be echoed back unchanged. For example:

```sh
websocat 'RETURNED_WS_URL'
```

### Postgres

Open `sandbox-postgres` (`POST /v1/pg/open`) and use the returned DSN
and ticket:

```sh
PGPASSWORD='RETURNED_TICKET' psql 'RETURNED_DSN' \
  -c 'SELECT current_user, current_database();'
```

Expect the upstream identity `aka` / `aka_sandbox`, not a
local proxy identity.

### SSH

Open `sandbox-ssh` (`POST /v1/ssh/open`), then use the returned
`auth_sock`:

```sh
SSH_AUTH_SOCK='RETURNED_AUTH_SOCK' \
  ssh -p 12222 sandbox@127.0.0.1 \
  'whoami && uname -a'
```

Expect `sandbox` and the container's system information. This is the
test that exercises AKA's host-bound signing and pinned host key.
If the service was saved without a fingerprint, expect the trust-on-
first-use prompt showing the observed key before the login proceeds.

## 6. Check application behavior

After the end-to-end requests:

- Every operation appears under **Activity** with the correct agent and
  service names.
- Secret values never appear in activity entries or responses.
- A GET can receive read-scoped permission; POST and session opens
  require full-access approval.
- Removing a permission makes the next request prompt again.
- Editing a service destination invalidates prior permission (the next
  request prompts again).

## 7. Shutdown and reset

Stop while preserving the generated SSH identities:

```sh
npm run sandbox:down
```

Delete containers, volumes, and both SSH identities:

```sh
npm run sandbox:reset        # asks for confirmation; -- --yes skips it
```

After a reset the SSH fingerprint changes, so update or recreate
`sandbox-ssh` before testing again.

## Appendix: running layer 2 headless

On any platform (including Linux, where the desktop app does not
build), the whole broker runs headless and the same layer-2 checks
apply. Seed the store, start an auto-approving broker, and drive it over
the Unix socket:

```sh
cargo build --workspace
B=./target/debug/aka; ROOT=/tmp/aka   # keep the root path short

printf '%s' aka-test-token       | $B secret add SANDBOX_HTTP_TOKEN --root $ROOT
printf '%s' aka-ws-test-token    | $B secret add SANDBOX_WEBSOCKET_TOKEN --root $ROOT
printf '%s' aka-test-password    | $B secret add SANDBOX_POSTGRES_PASSWORD --root $ROOT
KEY="$(cat dev/sandbox/state/ssh/client_key)" \
  $B secret add SANDBOX_SSH_KEY --value-env KEY --root $ROOT

$B conn add sandbox-http --kind api --scheme http --host 127.0.0.1 --port 18080 \
  --template 'Authorization: Bearer {{SANDBOX_HTTP_TOKEN}}' --root $ROOT
$B conn add sandbox-websocket --kind ws --url ws://127.0.0.1:18081/ws \
  --secret SANDBOX_WEBSOCKET_TOKEN --root $ROOT
$B conn add sandbox-postgres --kind pg --host 127.0.0.1 --port 15432 \
  --dbname aka_sandbox --user aka \
  --secret SANDBOX_POSTGRES_PASSWORD --sslmode disable --root $ROOT
$B conn add sandbox-ssh --kind ssh --host 127.0.0.1 --port 12222 --user sandbox \
  --secret SANDBOX_SSH_KEY --root $ROOT

$B serve --root $ROOT --yes &          # auto-approves every request
```

Pair and call exactly as an agent would:

```sh
SOCK=$ROOT/sock/broker.sock
TOKEN=$(curl -s --unix-socket $SOCK -X POST http://localhost/v1/pair \
  -H 'Content-Type: application/json' \
  -d '{"agent_name":"sandbox-tester"}' | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
curl -s --unix-socket $SOCK -X POST http://localhost/v1/http \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"connection":"sandbox-http","method":"GET","path":"/authenticated"}'
```

`/v1/ws/open`, `/v1/pg/open`, and `/v1/ssh/open` return the same
payloads described in §5. The audit trail for §6 is
`<root>/data/audit.jsonl`. Note the Linux vault is a plaintext dev
fallback, and the `--yes` broker approves everything — both are for
disposable test roots only.
