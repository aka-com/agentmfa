//! Self-describing discovery surface.
//!
//! `GET /.well-known/agent-broker.json` serves machine-readable manifest.
//! `GET /instructions` serves the human/agent-readable version.
//! `mfa skill` emits the same instructions as a checked-in skill file.

use serde_json::json;

use crate::config::BrokerConfig;
use crate::paths::Paths;
use crate::wire::{AuthScheme, PROTOCOL_VERSION, REQUEST_ID_MAX_BYTES};

pub fn manifest(
    config: &BrokerConfig,
    paths: &Paths,
    mcp_url: Option<String>,
) -> serde_json::Value {
    let mut m = json!({
        "name": "aka",
        "version": config.version,
        // The Agent Broker Protocol revision (PROTOCOL.md / wire.rs); the
        // `version` above is the broker build, this is the wire contract.
        "protocol_version": PROTOCOL_VERSION,
        "transport": "http-over-unix-socket",
        "socket": paths.socket_display(),
        // The shared key's plaintext home; the pair response repeats it in
        // `store_at`.
        "token_file": paths.token_display(),
        "capabilities": ["http", "postgres", "ssh"],
        // Capability flags: how a client may authenticate. Closed
        // vocabulary (wire.rs); new schemes appear here before any client
        // is expected to use them.
        "auth_schemes": AuthScheme::ALL,
        // Confirmation + direct upload + complete upstream operation +
        // margin: machine-actionable, so agents set a concrete timeout
        // instead of parsing prose.
        "recommended_client_timeout_seconds": config.effective_client_timeout().as_secs(),
        "token_ttl_days": config.token_ttl.as_secs() / 86400,
        "ticket_ttl_seconds": config.ticket_ttl.as_secs(),
        // How long a call may be parked while the user is asked to confirm
        // it. Only tools the user switched confirmation on for ever park;
        // the value is advertised unconditionally so a client can size its
        // own timeout without first discovering which tools those are.
        "approval_timeout_seconds": config.approval_timeout.as_secs(),
        "request_id_max_bytes": REQUEST_ID_MAX_BYTES,
        "http_request_cap_bytes": config.control_plane_request_cap,
        "http_endpoint_request_cap_bytes": config.request_cap,
        "http_response_cap_bytes": config.response_cap,
        "http_max_redirects": config.max_redirects,
        "endpoints": {
            "pair": "/v1/pair",
            "whoami": "/v1/whoami",
            "connections": "/v1/connections",
            "http": "/v1/http",
            "pg_open": "/v1/pg/open",
            "ssh_open": "/v1/ssh/open",
            "instructions": "/instructions",
        },
        "pairing": "One shared key covers every local agent: read it from the token_file and send it as your Bearer token. If you cannot read files, POST /v1/pair with {\"agent_name\": \"<your-name>\"} returns the same key. Optionally send X-AgentMFA-Client: <your-name> to label your activity.",
    });
    // Where the MCP host is listening right now, when one is running: the
    // loopback streamable-HTTP endpoint `mfa mcp` (and any HTTP-native MCP
    // client) bridges to, authenticated with the same shared key. The port
    // is dynamic, so bridges discover it here instead of pinning it.
    if let Some(url) = mcp_url {
        m["mcp_url"] = json!(url);
    }
    m
}

/// The manifest a TCP (network) client sees: the same contract minus every
/// same-machine assumption. No socket or token-file paths, no pair endpoint
/// (the operator hands out the key), and MCP reached through the daemon's
/// own `/mcp` proxy rather than a loopback port the client cannot route to.
pub fn manifest_remote(
    config: &BrokerConfig,
    public_url: Option<&str>,
    mcp_available: bool,
) -> serde_json::Value {
    let mut m = json!({
        "name": "aka",
        "version": config.version,
        "protocol_version": PROTOCOL_VERSION,
        // What this listener itself speaks. TLS is the operator's proxy or
        // tunnel in front of it; the advertised base_url reflects that.
        "transport": "http",
        "capabilities": ["http", "postgres", "ssh"],
        "auth_schemes": AuthScheme::ALL,
        "recommended_client_timeout_seconds": config.effective_client_timeout().as_secs(),
        "token_ttl_days": config.token_ttl.as_secs() / 86400,
        "ticket_ttl_seconds": config.ticket_ttl.as_secs(),
        // How long a call may be parked while the user is asked to confirm
        // it. Only tools the user switched confirmation on for ever park;
        // the value is advertised unconditionally so a client can size its
        // own timeout without first discovering which tools those are.
        "approval_timeout_seconds": config.approval_timeout.as_secs(),
        "request_id_max_bytes": REQUEST_ID_MAX_BYTES,
        "http_request_cap_bytes": config.control_plane_request_cap,
        "http_endpoint_request_cap_bytes": config.request_cap,
        "http_response_cap_bytes": config.response_cap,
        "http_max_redirects": config.max_redirects,
        "endpoints": {
            "whoami": "/v1/whoami",
            "connections": "/v1/connections",
            "http": "/v1/http",
            "pg_open": "/v1/pg/open",
            "ssh_open": "/v1/ssh/open",
            "instructions": "/instructions",
        },
        "pairing": "Not served remotely: every client of this broker uses its one shared key, obtained from the broker's operator (on the broker host it lives in the token file). Send it as your Bearer token, and optionally X-AgentMFA-Client: <your-name> to label your activity.",
    });
    if let Some(base) = public_url {
        m["base_url"] = json!(base);
    }
    if mcp_available {
        m["mcp_path"] = json!("/mcp");
        if let Some(base) = public_url {
            m["mcp_url"] = json!(format!("{}/mcp", base.trim_end_matches('/')));
        }
    }
    m
}

/// The banner prepended to `/instructions` when served over TCP: the
/// document below is written for same-machine use, and a network client
/// needs its transport and auth guidance overridden up front.
/// `data_plane_host` is the advertised PG host when the operator serves
/// the data planes beyond loopback (`--advertise-host`); `None` means the
/// opens hand back broker-host-local addresses.
pub fn remote_instructions_banner(
    public_url: Option<&str>,
    data_plane_host: Option<&str>,
) -> String {
    let base = public_url.unwrap_or("<this broker's URL>");
    let data_planes = match data_plane_host {
        Some(host) => format!(
            "> not served remotely. Postgres opens hand back an address on\n\
             > `{host}`, reachable if you can route to it; SSH opens name a Unix\n\
             > socket that exists only on the broker's machine"
        ),
        None => "> not served remotely. Postgres and SSH opens currently hand\n\
                 > back broker-host-local addresses and are usable only by agents on that\n\
                 > machine"
            .to_string(),
    };
    format!(
        "> **You are reaching this broker over the network.** Use `{base}` as the\n\
         > HTTP base URL for every endpoint below and ignore the Unix-socket\n\
         > `curl --unix-socket …` forms and token-file paths — they exist on the\n\
         > broker's host machine, not yours. Authenticate with the shared key your\n\
         > operator gave you (`Authorization: Bearer <key>`). `POST /v1/pair` is\n\
         {data_planes}; HTTP calls and MCP (`{base}/mcp`) work from anywhere.\n\n"
    )
}

/// The `/instructions` markdown. The pair-or-reuse walkthrough, one worked
/// example per capability, token-storage guidance, and error semantics.
pub fn instructions(config: &BrokerConfig, paths: &Paths) -> String {
    let client_timeout = config.effective_client_timeout().as_secs();
    let approval_timeout = config.approval_timeout.as_secs();
    let ticket = config.ticket_ttl.as_secs();
    let token_days = config.token_ttl.as_secs() / 86400;
    let request_cap = config.control_plane_request_cap;
    let endpoint_request_cap = config.request_cap;
    let response_cap = config.response_cap;
    let max_redirects = config.max_redirects;
    format!(
        r#"# AKA: broker instructions

AKA holds this developer's secrets in the macOS Keychain and brokers
their use. Broker-produced fields do not expose vault-held values or secret
names; you ask the broker to *use a named connection* (make an HTTP request
through `github`, connect to `prod-db`) and the broker injects the credential
on the upstream leg. Authorization is per **tool**: the user enables or
disables each connection for agents in the AgentMFA app. An enabled call
executes immediately; a disabled call is refused with
`403 denied_by_policy` — ask your user to enable the tool in the app. A
tool may additionally be set to **confirm its traffic**, which holds each
call while the user answers (see §3).
Relayed HTTP responses are scrubbed for recognized credential material, but
arbitrary transformed upstream output cannot be guaranteed secret-free.

Protocol: Agent Broker Protocol version {protocol_version} (the manifest's
`protocol_version`; PROTOCOL.md is the spec).
Transport: HTTP over the Unix domain socket `{socket}`.
Example: `curl --unix-socket {socket} http://localhost/v1/connections`

## 1. Authenticate: one shared key for this machine

Every local agent uses the same bearer key — there are no per-agent
identities. It lives in plaintext at `{token_file}` (mode 0600).

1. Read `{token_file}` and send it on every call:

       curl --unix-socket {socket} \
            -H "Authorization: Bearer <token>" http://localhost/v1/whoami
       → 200 {{"client_id": "<uuid>", "agent": "<your-name>",
               "expires_at": "…"}}

   Follow the response-specific recovery action:

   | `/v1/whoami` result | Action |
   | --- | --- |
   | `200` | The key works; carry on. |
   | `401 token_superseded` | The key was rotated: re-read `{token_file}` (the response's `store_at`) and retry. Do **not** treat this as fatal. |
   | `401 token_expired` | POST /v1/pair once, then retry with the returned key. |
   | `401 invalid_token` | Re-read `{token_file}`; if it still fails, POST /v1/pair. |
   | Any other `401` | Correct the Authorization header or bearer credential first. |

2. If you cannot read files (a sandbox, a remote client), pair — it hands
   the same shared key back:

       curl --unix-socket {socket} -X POST http://localhost/v1/pair \
            -H "Content-Type: application/json" \
            -d '{{"agent_name": "<your-name>"}}'
       → 200 {{"token": "aka_…", "client_id": "<uuid>",
               "agent": "<your-name>",
               "expires_after_days": {token_days},
               "store_at": "{token_file}"}}

The key lasts {token_days} days, refreshed on use; the broker rewrites
`{token_file}` whenever it re-mints, so re-reading the file is always the
first recovery step. Rotating the key (user-initiated) invalidates
outstanding data-plane capabilities and closes live Postgres and SSH
connections for every agent at once.

**Label yourself.** Optionally send `X-AgentMFA-Client: <your-name>`
(1-64 chars of `[A-Za-z0-9._-]`) on every call. It names you in the user's
activity log and live-sessions view — attribution only, never
authorization.

## 2. Discover what you may ask for

    GET /v1/connections
    → [{{"name": "github", "type": "api", "target": "https://api.github.com",
         "endpoint": "/v1/http", "wired": true}}, …]

Connections name a destination. Secret names and values are never
exposed. `endpoint` is where a call naming this connection goes (POST
it). `wired` says whether agents may use the connection: an enabled call
executes immediately, a disabled call is refused with
`403 {{"reason": "denied_by_policy"}}`. Access is changed only by the user
in the AgentMFA app — if you need a connection that is disabled, ask
your user rather than retrying.

## 3. Confirmation, retries, and timeouts

Most calls execute immediately. A connection the user switched
confirmation on for is different: the call is **held** while AgentMFA asks
them about it, for up to {approval_timeout} seconds. Approving it also
covers that connection's next calls for a while, so a confirmed tool does
not ask again on every request. Three answers are possible, and you see
only the outcome:

- approved — the call proceeds normally;
- refused — `403 {{"reason": "approval_denied"}}`. The refusal also stands
  for calls made shortly after it, so **do not retry**: ask your user;
- unanswered — `408 {{"reason": "approval_timeout"}}`. A retry is
  reasonable here; it asks again.

`403 {{"reason": "approval_unavailable"}}` means the connection asks for
confirmation but no answering surface is attached, or the bounded prompt
queue is full. Retrying will not help until AgentMFA is attached or capacity
is available.

Set your HTTP client timeout to **at least {client_timeout} seconds**
(confirmation wait + direct-endpoint upload + upstream timeout + margin).

**Always send a unique `request_id` no longer than
{request_id_max_bytes} UTF-8 bytes (a UUID is recommended) on mutating calls.**
A retry that re-sends the same
`request_id` joins the in-flight execution: exactly one upstream
execution, the same response replayed while its body remains cached, and a
non-reexecute tombstone retained for 10 minutes. Confirmation timeout and
unavailability happen before execution and are not retained, so retry those
with the same `request_id`.
Reusing a `request_id` with a *different* payload is rejected with
`409 {{"reason": "request_id_mismatch"}}`. GET/HEAD are never coalesced.
The broker reserves bounded idempotency capacity before accepting a keyed
request. `503 {{"reason": "idempotency_capacity"}}` means it was not accepted:
wait, then safely retry the same ID. If a completed response was too large or
evicted, its key remains tombstoned and a retry returns
`409 {{"reason": "outcome_not_replayable"}}` without executing again. Do not
mint a new ID and repeat that operation automatically; reconcile its upstream
effect or ask the user first.
For PG/SSH opens, replay returns the originally issued capability and does
not extend its lifetime. Retry the same `request_id` only during the returned
`expires_in_seconds` window; after that, mint a fresh ID and submit a new open.

## 4. HTTP requests: POST /v1/http

    POST /v1/http
    {{
      "connection": "github",
      "method": "GET",
      "path": "/user/repos",
      "headers": {{"Accept": "application/vnd.github+json"}},
      "body": null,
      "request_id": "req-<uuid>"        // mutating calls
    }}

    → 200 {{"status": 200, "headers": {{…}},
            "set_cookie_headers": ["a=1; Path=/", "b=2; Path=/"],
            "body": "…", "body_encoding": "utf8"}}

You supply the method, path (query string included; there is no separate
query field), headers and body; the connection supplies the host and the
credential. You cannot name a host. Paths must start with `/`. The broker
controls `Host`, `Content-Length`, `Transfer-Encoding`, the hop-by-hop
headers and the injected credential header; naming one of those is
rejected with `400 {{"reason": "reserved_header"}}`. Bodies may be a JSON
string, a JSON object/array (serialized for you), or `body_base64` for
binary. Non-UTF-8 response bodies come back base64-encoded with
`"body_encoding": "base64"`. Redirects are followed only within the
connection's pinned host, up to {max_redirects} hops; a cross-host redirect is
returned to you as the raw 3xx. The `/v1/http` request body cap is
{request_cap} bytes, direct-endpoint uploads are capped at
{endpoint_request_cap} bytes, and relayed responses are capped at
{response_cap} bytes. `Accept-Encoding` is broker-controlled because the
upstream leg is HTTP/1.1-only and does not decompress responses.

ABP/0 represents headers as JSON objects with string values. Repeated upstream
response fields are combined with `, `. `Set-Cookie` is the exception: its
distinct values are also preserved in `set_cookie_headers`; use that array
rather than the lossy combined `headers["set-cookie"]` value.

## 5. Postgres: POST /v1/pg/open

    POST /v1/pg/open
    {{"connection": "prod-db", "request_id": "req-<uuid>"}}

    → 200 {{"dsn": "postgres://ticket@127.0.0.1:<port>/<dbname>?sslmode=disable",
            "ticket": "<ticket>",
            "expires_in_seconds": {ticket},
            "example": "PGPASSWORD=<ticket> psql \"<dsn>\""}}

Run any unmodified client against the DSN. PGPASSWORD or a passfile keeps
the ticket out of `ps`-visible argv and shell history; embedding it in the
DSN as the password (what `mfa dsn <connection>` prints) is an accepted
tradeoff for the ticket's short window:

    PGPASSWORD=<ticket> psql "<dsn>" -c "SELECT 1;"

The broker's local proxy speaks real Postgres on the loopback leg and
opens the upstream Postgres leg itself; you never see the real password or
host. `sslmode=disable` applies only to the loopback leg; the upstream
leg uses the connection's configured TLS. The default upstream
`sslmode=verify-full` validates the certificate chain and hostname. A
per-connection private CA bundle can extend the trusted roots.

## 6. SSH: POST /v1/ssh/open

    POST /v1/ssh/open
    {{"connection": "prod-ssh", "request_id": "req-<uuid>"}}

    → 200 {{"auth_sock": "/…/.aka/ssh/agent-<id>.sock",
            "destination": "prod",
            "host": "prod.example.com", "port": 22, "user": "deploy",
            "host_key_fingerprint": "SHA256:…" or null,
            "expires_in_seconds": {ticket}}}

Authorization is checked once, at open time. Point `SSH_AUTH_SOCK` at
`auth_sock` and run any unmodified SSH client (`ssh`, `git`, `scp`, `rsync`,
`ssh -L`):

    ssh -o IdentityAgent=<auth_sock> -o IdentityFile=none \
        -o CertificateFile=none -o ForwardAgent=no \
        -o ControlMaster=no <destination>
    SSH_AUTH_SOCK=<auth_sock> git -C repo push

Prefer `-o IdentityAgent` to `SSH_AUTH_SOCK` wherever the client accepts
`-o`: setting `SSH_AUTH_SOCK` alone leaves the default `IdentityFile` list
in place, so a working `~/.ssh/id_ed25519` can authenticate the login with
no broker involvement and no activity-log entry — a success that looks
brokered and is not. `IdentityFile=none` and `CertificateFile=none` are
what suppress that; `SSH_AUTH_SOCK` is for tools that cannot take `-o`.
Do **not** add `-o IdentitiesOnly=yes`: OpenSSH drops agent identities
that match no configured `IdentityFile`, and the broker's key has no
on-disk `.pub`, so the identity is discarded and the login fails.

The broker serves the ssh-agent protocol on that socket: it offers the one
configured key and signs your authentication with it, and the private key
never leaves the broker. It verifies OpenSSH's session binding against the
pinned host-key fingerprint and will **only** sign host-bound public-key
login as the pinned `user`; it signs nothing else.

Agent forwarding (`ssh -A`, `ForwardAgent yes`) is not supported and the
snippets disable it. The broker refuses a session-bind that admits to being
forwarded, but that flag is asserted by whichever client wrote the message,
so it stops an honest client and not a hostile one: anything reaching the
forwarded channel on the remote host can present a genuine binding it
obtained by connecting to the pinned host itself. Treat the socket as
same-machine-only.

When `host_key_fingerprint` is `null`, the server's key is not pinned yet:
the broker trusts it on first use. The key the server presents at your first
connection is pinned automatically and recorded in the activity log; every
later connection is verified against it, and a server that presents a
different key is refused.

Ticket lifetime and reconnect semantics
match Postgres: the socket accepts as many connections as needed for the
{ticket} s window, so multiple SSH
invocations as you need under the authorization that issued it.

What expiry does and does not reach. The broker participates only in
authentication: it is asked to sign once per login, and that signature is
where authorization is checked. An SSH session that has authenticated is
owned by your client and the server, and the broker is not in its path —
so ticket expiry, turning the connection off, deleting it, and shutting the
broker down all prevent **new** logins and end nothing already running.
Two consequences worth planning around:

- `ControlMaster`/`ControlPersist` multiplexing reuses one authenticated
  connection for later `ssh` invocations, which never contact the agent
  again. The emitted snippets set `ControlMaster=no` so each invocation is
  separately authorized and separately logged; if you override that, later
  invocations are outside the broker's view entirely.
- A backgrounded tunnel (`ssh -N -L …`) survives for as long as its client
  runs, with no live-session row and nothing to revoke. Bound its lifetime
  yourself.

Compatible OpenSSH clients
negotiate session binding and host-bound authentication automatically, so an
explicit `-o PubkeyAuthentication=host-bound` is optional. Clients without
those OpenSSH extensions fail closed because the broker refuses unbound or
host-key-mismatched signing requests.

## 7. Other errors

- `400 {{"reason": "invalid_json"}}`: the request body was not valid JSON
  for the endpoint (wrong/missing Content-Type, malformed JSON, or a
  missing field); the `detail` says which.
- `401 {{"reason": "missing_token", "cause": "...", "detail": "..."}}`:
  no usable bearer token reached the broker. The `cause` distinguishes an
  absent or invalid Authorization header, a non-Bearer scheme, and an empty
  bearer credential. The detail describes what arrived without assuming the
  agent itself omitted or rewrote the data.
- `401 {{"reason": "invalid_token", "detail": "..."}}`: the token that
  reached the broker was not recognized. Re-read the token file; if it
  still fails, pair.
- `401 {{"reason": "token_expired"}}`: pair once, then retry.
- `401 {{"reason": "token_superseded"}}`: the key was rotated; re-read the
  token at the response's `store_at` and retry.
- `404 {{"reason": "unknown_connection"}}`: no such connection; the detail
  lists the configured names.
- `409 {{"reason": "request_id_mismatch"}}`: you reused a request_id with a
  different payload; mint a fresh one.
- `409 {{"reason": "outcome_not_replayable"}}`: the earlier execution
  completed but its retained response is unavailable; do not repeat it
  automatically under a fresh ID. Reconcile the result or ask your user.
- `429 {{"reason": "rate_limited" | "pairing_rate_limited"}}`: over budget;
  wait `retry_after_seconds` (also in the `Retry-After` header), then
  retry.
- `502 {{"reason": "ssh_agent_open_failed"}}`: the key could not be loaded
  (missing, encrypted, or an unsupported type); the `detail` says which.
- `503 {{"reason": "ticket_session_limit" | "broker_session_limit"}}`: your
  session budget is exhausted; close sessions or wait, then reopen.
- `503 {{"reason": "idempotency_capacity"}}`: the keyed operation was not
  accepted because the bounded replay table is full; wait, then retry the
  same request_id.
"#,
        protocol_version = PROTOCOL_VERSION,
        socket = paths.socket_display(),
        token_file = paths.token_display(),
        client_timeout = client_timeout,
        approval_timeout = approval_timeout,
        ticket = ticket,
        token_days = token_days,
        request_id_max_bytes = REQUEST_ID_MAX_BYTES,
    )
}

/// The generated skill file (`mfa skill`): the same instructions
/// content under skill frontmatter; generated output, not a hand-maintained
/// artifact.
pub fn skill_file(config: &BrokerConfig, paths: &Paths) -> String {
    format!(
        r#"---
name: mfa
description: >-
  Broker credentialed HTTP, Postgres and SSH access through the local
  AgentMFA daemon. Use when a task needs an API key, database, or SSH key
  the developer has configured. The broker does not directly expose
  the stored secret; access is authorization-gated. Start by reading the live
  instructions over the broker socket.
---

<!-- Generated by `mfa skill`. Do not edit: regenerate instead.
     The daemon serves the same content at /instructions; if this file and
     the daemon disagree, the daemon wins. -->

{}"#,
        instructions(config, paths)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Paths {
        Paths::default_locations().unwrap()
    }

    #[test]
    fn manifest_advertises_the_contract() {
        let config = BrokerConfig::default();
        let m = manifest(&config, &paths(), None);
        assert_eq!(PROTOCOL_VERSION, 0);
        assert_eq!(m["protocol_version"], 0);
        assert_eq!(m["auth_schemes"], serde_json::json!(["bearer"]));
        assert_eq!(m["transport"], "http-over-unix-socket");
        assert!(m.get("approval_modes").is_none());
        assert!(m.get("access_grant_ttl_seconds").is_none());
        // A call on a confirm-on tool parks for at most this long, and the
        // advertised client timeout has to cover it.
        assert_eq!(m["approval_timeout_seconds"], 90);
        assert_eq!(m["recommended_client_timeout_seconds"], 300);
        assert!(
            m["approval_timeout_seconds"].as_u64().unwrap()
                + BrokerConfig::default().endpoint_upload_timeout.as_secs()
                + BrokerConfig::default().upstream_operation_timeout.as_secs()
                <= m["recommended_client_timeout_seconds"].as_u64().unwrap(),
            "the client timeout must cover confirmation, upload, and the whole upstream operation"
        );
        assert_eq!(m["token_ttl_days"], 30);
        assert_eq!(m["ticket_ttl_seconds"], 60);
        assert_eq!(m["request_id_max_bytes"], REQUEST_ID_MAX_BYTES);
        assert_eq!(
            m["http_request_cap_bytes"],
            config.control_plane_request_cap
        );
        assert_eq!(m["http_endpoint_request_cap_bytes"], config.request_cap);
        assert_eq!(m["http_response_cap_bytes"], config.response_cap);
        assert_eq!(m["http_max_redirects"], config.max_redirects);
        assert_eq!(m["endpoints"]["pair"], "/v1/pair");
        assert_eq!(m["endpoints"]["whoami"], "/v1/whoami");
        assert_eq!(m["endpoints"]["ssh_open"], "/v1/ssh/open");
        assert_eq!(m["socket"], "~/.aka/broker.sock");
        assert_eq!(m["token_file"], "~/.aka/token");
        assert_eq!(
            m["capabilities"],
            serde_json::json!(["http", "postgres", "ssh"])
        );
    }

    #[test]
    fn a_custom_configuration_cannot_advertise_too_short_a_timeout() {
        let config = BrokerConfig {
            recommended_client_timeout: std::time::Duration::from_secs(1),
            approval_timeout: std::time::Duration::from_secs(120),
            endpoint_upload_timeout: std::time::Duration::from_secs(70),
            upstream_operation_timeout: std::time::Duration::from_secs(80),
            ..BrokerConfig::default()
        };
        let m = manifest(&config, &paths(), None);
        assert_eq!(m["recommended_client_timeout_seconds"], 300);
    }

    #[test]
    fn remote_banner_reflects_the_data_plane_configuration() {
        // Default: PG/SSH opens are host-local and the banner says so.
        let text = remote_instructions_banner(Some("https://b.example.dev"), None);
        assert!(text.contains("broker-host-local addresses"));
        assert!(!text.contains("broker.lan"));

        // With an advertised host, PG is reachable and only SSH stays
        // host-local.
        let text = remote_instructions_banner(Some("https://b.example.dev"), Some("broker.lan"));
        assert!(text.contains("`broker.lan`"), "{text}");
        assert!(!text.contains("broker-host-local addresses"));
        assert!(text.contains("SSH opens"), "{text}");
    }

    #[test]
    fn manifest_names_the_actual_runtime_paths() {
        // A broker rooted elsewhere (`serve --root`, tests) must not claim
        // the production socket.
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let m = manifest(&BrokerConfig::default(), &paths, None);
        assert_eq!(m["socket"], paths.socket_file().display().to_string());
        let text = instructions(&BrokerConfig::default(), &paths);
        assert!(text.contains(&paths.socket_file().display().to_string()));
    }

    #[test]
    fn manifest_advertises_the_mcp_endpoint_only_while_one_runs() {
        let absent = manifest(&BrokerConfig::default(), &paths(), None);
        assert!(absent.get("mcp_url").is_none());
        let present = manifest(
            &BrokerConfig::default(),
            &paths(),
            Some("http://127.0.0.1:42117/mcp".into()),
        );
        assert_eq!(present["mcp_url"], "http://127.0.0.1:42117/mcp");
    }

    #[test]
    fn instructions_cover_the_contract() {
        let text = instructions(&BrokerConfig::default(), &paths());
        for needle in [
            "curl --unix-socket ~/.aka/broker.sock",
            "~/.aka/token",
            "X-AgentMFA-Client",
            "/v1/whoami",
            "store_at",
            "token_superseded",
            "request_id",
            "256 UTF-8 bytes",
            "PGPASSWORD",
            "expires_in_seconds",
            "at least 300 seconds",
            "denied_by_policy",
            "\"wired\": true",
            "request_id_mismatch",
            "outcome_not_replayable",
            "idempotency_capacity",
            "retry_after_seconds",
            "invalid_json",
            "\"endpoint\": \"/v1/http\"",
            "\"set_cookie_headers\"",
            "direct-endpoint uploads are capped",
            "upstream leg is HTTP/1.1-only",
            "distinct values are also preserved",
            "/v1/pg/open",
            "/v1/ssh/open",
            "SSH_AUTH_SOCK",
            "session binding and host-bound authentication automatically",
            "host-key-mismatched signing requests",
        ] {
            assert!(text.contains(needle), "instructions missing {needle:?}");
        }
        assert!(text.contains("one shared key") || text.contains("One shared key"));
        assert!(text.contains("The key was rotated: re-read"));
        assert!(text.contains("Do **not** treat this as fatal"));
        assert!(!text.contains("Any `401` means"));
        // Config-derived numbers are rendered, not hard-coded prose.
        assert!(text.contains("30 days"));
    }

    /// SSH-13 and SSH-14. The recommended incantation was
    /// `-o IdentitiesOnly=yes`, which *breaks* the brokered agent: OpenSSH's
    /// `pubkey_prepare` drops agent identities matching no configured
    /// `IdentityFile`, and the broker's key has no on-disk `.pub`. And with
    /// only `SSH_AUTH_SOCK` set, a user who already has a working
    /// `~/.ssh/id_ed25519` gets a successful login with no broker involvement
    /// and no audit entry — a false success, worse than a failure.
    #[test]
    fn the_ssh_incantation_suppresses_local_keys_without_discarding_the_brokered_one() {
        let text = instructions(&BrokerConfig::default(), &paths());
        for needle in [
            "-o IdentityAgent=<auth_sock>",
            "IdentityFile=none",
            "CertificateFile=none",
            "ForwardAgent=no",
            "ControlMaster=no",
        ] {
            assert!(text.contains(needle), "instructions missing {needle:?}");
        }
        assert!(
            text.contains("Do **not** add `-o IdentitiesOnly=yes`"),
            "the flag that looks right and breaks the agent must be called out"
        );
    }

    /// SSH-12. The docs claimed "Live SSH connections are also capped by the
    /// remaining lifetime of an access grant." Only the *agent socket
    /// connection* is; the SSH transport is client-owned and unaffected by
    /// ticket expiry, disable, delete, or broker shutdown. SSH-11 is the same
    /// statement from the client's side: `ControlPersist` and `-N` tunnels turn
    /// a 60-second capability into an indefinite, invisible one.
    #[test]
    fn the_ssh_docs_do_not_claim_revocation_reaches_established_sessions() {
        let text = instructions(&BrokerConfig::default(), &paths());
        assert!(
            !text.contains("Live SSH connections are also capped"),
            "that claim is false: the broker is not in an authenticated session's path"
        );
        for needle in [
            "prevent **new** logins and end nothing already running",
            "ControlPersist",
            "ssh -N -L",
            "Agent forwarding (`ssh -A`",
        ] {
            assert!(text.contains(needle), "instructions missing {needle:?}");
        }
    }

    #[test]
    fn skill_file_embeds_instructions() {
        let cfg = BrokerConfig::default();
        let skill = skill_file(&cfg, &paths());
        assert!(skill.starts_with("---\nname: mfa"));
        assert!(skill.contains(&instructions(&cfg, &paths())));
    }
}
