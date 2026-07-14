# Try AKA against the local sandbox

```text
     _                    _   __  __ _____ _
    / \   __ _  ___ _ __ | |_|  \/  |  ___/ \
   / _ \ / _` |/ _ \ '_ \| __| |\/| | |_ / _ \
  / ___ \ (_| |  __/ | | | |_| |  | |  _/ ___ \
 /_/   \_\__, |\___|_| |_|\__|_|  |_|_|/_/   \_\
         |___/
```

The sandbox is a disposable Docker Compose stack with one upstream for
every AKA connection type — an authenticated HTTP API, a WebSocket
echo, Postgres, and SSH — so you can try the whole app in minutes
without touching a real service. Every port binds to `127.0.0.1` and
every credential is a fake, fixed test value that must never be reused
outside the sandbox. AKA Desktop runs natively so it keeps using the
host Keychain, webview, and Unix socket.

A copy of this walkthrough formatted for the browser is in
[`quickstart.html`](quickstart.html).

## 1. What you need

- Docker with Compose v2, **running** (start Docker Desktop first)
- Node.js with `npm` (only to run the `npm run sandbox:*` scripts —
  `bash scripts/sandbox-up.sh` works without it)
- `curl`, `ssh-keygen`, and `ssh-keyscan` (preinstalled on macOS)
- AKA Desktop: the desktop app, or the headless broker
  (`cargo run -p aka -- serve`) on any platform

## 2. Start the sandbox

From the repository root:

```sh
npm run sandbox:up
```

The first start compiles the HTTP/WebSocket fixture inside Docker and
can take several minutes; later starts take seconds. The command
generates a sandbox-only SSH key under the ignored `dev/sandbox/state/`
directory, waits until all four services answer, and prints the exact
values to enter in AKA Desktop — including paste-ready “Quick setup” lines
for Postgres and SSH and the current SSH host-key fingerprint.

Print the containers and connection values again at any time:

```sh
npm run sandbox:status
```

## 3. Add the services in AKA Desktop

<!-- Keep this walkthrough in sync with scripts/sandbox-status.sh and
     quickstart.html (step 3). -->

Open AKA Desktop from the menu bar icon; **Services** is the first tab.
At the top is an **Add a service for your agent** card. (If the card
isn't shown, re-enable it from the **Walkthroughs** menu — the ?
button in the Services header — or use **＋ Add service** to fill the
form by hand.)

For HTTP API and WebSocket, use **＋ Add service** and enter the printed
fields manually. For Postgres and SSH, paste the **Quick setup** line
from the `sandbox:up` output into the card and press **Continue** — the
service type is detected automatically and the form opens pre-filled.
Enter any remaining values, press **Add service**, then press **Test**
on the service's card in the list. The Postgres **TLS mode** and SSH
**Host key fingerprint** fields are under the form's **Advanced**
section. With the default ports:

| Service | Setup | Then |
| --- | --- | --- |
| HTTP API | Enter manually: API root `http://127.0.0.1:18080` | Name `sandbox-http`, authentication type **Bearer token**, credential value `aka-test-token` |
| WebSocket | Enter manually: URL `ws://127.0.0.1:18081/ws` | Name `sandbox-websocket`, authentication type **Bearer token**, credential value `aka-ws-test-token` |
| Postgres | Quick setup: `postgres://aka:aka-test-password@127.0.0.1:15432/aka_sandbox?sslmode=disable` | Name `sandbox-postgres`; host, database, TLS mode **Disable** (under **Advanced**), and password all pre-fill |
| SSH | Quick setup: `ssh -i <printed key path> -p 12222 sandbox@127.0.0.1` | Name `sandbox-ssh`; AKA Desktop reads the key file itself — never paste key contents |

The SSH **Host key fingerprint** field (under **Advanced**) is
optional: paste the printed `SHA256:…` value, or leave it blank and
AKA Desktop will show the observed key for confirmation at the first
agent connection and pin it then.

Press **Test** on each service's card and expect:

- **sandbox-http** — an authenticated `HTTP 200 OK` from the API root.
- **sandbox-websocket** — `WebSocket handshake succeeded`.
- **sandbox-postgres** — `Signed in to aka_sandbox as aka`.
- **sandbox-ssh** — `Key loaded; 127.0.0.1:12222 answered with
  SSH-2.0-…`. This test checks key parsing and reachability only; a
  real agent connection is what exercises login, host-bound signing,
  and host-key pinning.

## 4. Let an agent use the services

Pair an agent (the **Connect an agent** walkthrough shows the exact
command), then ask it to use the services in plain language, e.g.:

- “Using my AKA service `sandbox-http`, make a GET request to
  `/authenticated` and summarize the response.”
- “Using my AKA service `sandbox-postgres`, run
  `SELECT current_user, current_database();`.”
- “Using my AKA service `sandbox-ssh`, run `uname -a`.”
- “Using my AKA service `sandbox-websocket`, connect and echo a
  message.”

Approve the prompts AKA Desktop raises. GET/HEAD requests fit a read-scoped
access session; POST, Postgres, SSH, and WebSocket opens require full
access. The fixture serves deterministic routes for deeper checks:

```text
GET  /authenticated            {"authenticated":true} with the token; 401 without
GET  /status/{200..599}        the selected status code
GET  /delay/{seconds}          response delayed up to 20 seconds
GET  /redirect/same-origin     302 → /authenticated; AKA follows it and
                               re-injects the credential (expect a final 200)
GET  /redirect/cross-origin    302 to the fixture's other published port;
                               AKA returns the raw 302 rather than follow
                               it (the target answers 418 if ever reached)
GET  /binary                   5 non-UTF-8 bytes (body_encoding "base64")
GET  /large/{bytes}            generated body up to 12 MiB; /large/12582912
                               exceeds the broker's 10 MB cap → 502
                               response_too_large
POST /echo                     reflects the request body and content type
```

The fixture checks the documented fake tokens but never returns or logs
them. Afterwards, check the **Activity** tab: every call appears under
the right agent and service, and no secret value is ever shown.

## 5. Stop or reset

```sh
npm run sandbox:down          # stop; keeps both generated SSH identities
npm run sandbox:reset         # delete containers, volumes, and SSH identities
npm run sandbox:reset -- --yes   # same, without the confirmation prompt
```

After a reset the SSH host key and fingerprint change: run
`npm run sandbox:up` and update (or re-create) `sandbox-ssh` before
connecting again.

## Troubleshooting

- **“cannot reach the Docker daemon”** — start Docker Desktop (or the
  `docker` service) and rerun `npm run sandbox:up`.
- **A port is already in use** — export any of `SANDBOX_HTTP_PORT`,
  `SANDBOX_WS_PORT`, `SANDBOX_PG_PORT`, `SANDBOX_SSH_PORT` before
  `sandbox:up`; `sandbox:status` reads the same variables, so export
  them for the whole shell session. Defaults: 18080, 18081, 15432,
  12222.
- **The fixture build fails downloading crates** (for example
  “self-signed certificate in certificate chain”) — a TLS-intercepting
  proxy is rewriting the build's connection to crates.io. Build once on
  a network without interception, or extend
  `dev/sandbox/fixture/Dockerfile` to install your proxy's CA
  certificate before `cargo build`.
- **Container logs**:

  ```sh
  docker compose -f dev/sandbox/compose.yaml logs
  ```

## Notes for maintainers

The builder, runtime, Postgres, and OpenSSH images are pinned to
multi-platform manifest digests for reproducibility across Apple
Silicon and amd64 hosts; update each tag and digest together after
reviewing a new upstream release. The full two-layer test plan
(container checks, then the same surfaces through AKA) is in
[`TESTPLAN.md`](TESTPLAN.md).

Do not mount the repository, home directory, or real credentials into
these containers.
