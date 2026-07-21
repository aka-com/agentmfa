//! Self-describing discovery surface.
//!
//! `GET /.well-known/agent-broker.json` serves machine-readable manifest.
//! `GET /instructions` serves the human/agent-readable version.
//! `aka skill` emits the same instructions as a checked-in skill file.

use serde_json::json;

use crate::config::BrokerConfig;
use crate::paths::Paths;
use crate::wire::{AuthScheme, PROTOCOL_VERSION, REQUEST_ID_MAX_BYTES};

pub fn manifest(config: &BrokerConfig, paths: &Paths) -> serde_json::Value {
    json!({
        "name": "aka",
        "version": config.version,
        // The Agent Broker Protocol revision (PROTOCOL.md / wire.rs); the
        // `version` above is the broker build, this is the wire contract.
        "protocol_version": PROTOCOL_VERSION,
        "transport": "http-over-unix-socket",
        "socket": paths.socket_display(),
        // The advisory token home; the pair response repeats the exact
        // per-agent path in `store_at`.
        "tokens_dir": paths.tokens_display(),
        "capabilities": ["http", "websocket", "postgres", "ssh"],
        // Capability flags: how a client may authenticate. Closed
        // vocabulary (wire.rs); new schemes appear here before any client
        // is expected to use them.
        "auth_schemes": AuthScheme::ALL,
        // upstream timeout + margin: machine-actionable, so agents set a
        // concrete client timeout instead of parsing prose.
        "recommended_client_timeout_seconds": config.recommended_client_timeout.as_secs(),
        "token_ttl_days": config.token_ttl.as_secs() / 86400,
        "ticket_ttl_seconds": config.ticket_ttl.as_secs(),
        "request_id_max_bytes": REQUEST_ID_MAX_BYTES,
        "endpoints": {
            "pair": "/v1/pair",
            "whoami": "/v1/whoami",
            "connections": "/v1/connections",
            "http": "/v1/http",
            "ws_open": "/v1/ws/open",
            "pg_open": "/v1/pg/open",
            "ssh_open": "/v1/ssh/open",
            "instructions": "/instructions",
        },
        "pairing": "Reuse a stored token if GET /v1/whoami accepts it; otherwise POST /v1/pair with {\"agent_name\": \"<your-name>\"} — registration is immediate and the returned token is your Bearer token.",
    })
}

/// The `/instructions` markdown. The pair-or-reuse walkthrough, one worked
/// example per capability, token-storage guidance, and error semantics.
pub fn instructions(config: &BrokerConfig, paths: &Paths) -> String {
    let client_timeout = config.recommended_client_timeout.as_secs();
    let ticket = config.ticket_ttl.as_secs();
    let token_days = config.token_ttl.as_secs() / 86400;
    format!(
        r#"# AKA: broker instructions

AKA holds this developer's secrets in the macOS Keychain and brokers
their use. Broker-produced fields do not expose vault-held values or secret
names; you ask the broker to *use a named connection* (make an HTTP request
through `github`, connect to `prod-db`) and the broker injects the credential
on the upstream leg. Authorization is a **wiring**: the user wires agents to
connections in the Multitool app. A wired call executes immediately, with no
prompt; an unwired call is refused with `403 denied_by_policy` — ask your
user to wire you up in the app. Relayed HTTP responses are scrubbed for
recognized credential material, but arbitrary transformed upstream output
cannot be guaranteed secret-free.

Protocol: Agent Broker Protocol version {protocol_version} (the manifest's
`protocol_version`; PROTOCOL.md is the spec).
Transport: HTTP over the Unix domain socket `{socket}`.
Example: `curl --unix-socket {socket} http://localhost/v1/connections`

## 1. Authenticate: reuse a stored token; pair only when you must

Re-pairing invalidates the name's previous token, so reuse a stored token
when one exists:

1. Read `{tokens}/<your-name>`. If it exists, probe it:

       curl --unix-socket {socket} \
            -H "Authorization: Bearer <token>" http://localhost/v1/whoami
       → 200 {{"client_id": "<uuid>", "agent": "<your-name>",
               "expires_at": "…"}}

   Follow the response-specific recovery action; do not treat every `401`
   as permission to re-pair:

   | `/v1/whoami` result | Action |
   | --- | --- |
   | `200` | Reuse the stored token and skip pairing. |
   | `401 token_superseded` | Re-read the token from the response's `store_at` path and retry. Do **not** pair. |
   | `401 token_expired` | Pair again, then replace the stored token. |
   | `401 invalid_token` | Pair again, then replace the stored token. |
   | Any other `401` | Correct the Authorization header or bearer credential first; do not pair automatically. |

2. Pair:

       curl --unix-socket {socket} -X POST http://localhost/v1/pair \
            -H "Content-Type: application/json" \
            -d '{{"agent_name": "<your-name>"}}'
       → 200 {{"token": "aka_…", "client_id": "<uuid>",
               "agent": "<your-name>",
               "expires_after_days": {token_days},
               "store_at": "{tokens}/<your-name>"}}

   Registration is immediate — no human approval. You appear in the AKA
   Desktop window as a connected agent, and the user wires you up to the
   tools you may use. Store the token at `store_at` with mode 0600 (the
   directory already exists), or in your own credential store, and send it
   on every subsequent call as `Authorization: Bearer <token>`.

Tokens last {token_days} days, refreshed on use.

**Several instances under one name share the stored token.** Pairing
again replaces the name's previous token; a call failing with
`401 {{"reason": "token_superseded"}}` means another instance re-paired:
re-read the token file and retry rather than pairing again (which would
break that instance in turn). Re-pairing or
user-initiated disconnect also invalidates outstanding data-plane capabilities
and closes live WebSocket, Postgres, and SSH connections for that agent name.

## 2. Discover what you may ask for

    GET /v1/connections
    → [{{"name": "github", "type": "api", "target": "https://api.github.com",
         "endpoint": "/v1/http", "wired": true}}, …]

Connections name a destination. Secret names and values are never
exposed. `endpoint` is where a call naming this connection goes (POST
it). `wired` says whether *you* may use the connection: a wired call
executes immediately, an unwired call is refused with
`403 {{"reason": "denied_by_policy"}}`. Wiring is changed only by the user
in the Multitool app — if you need a connection you are not wired to, ask
your user rather than retrying.

A Postgres connection you are wired to also carries a `mode`: `read-only`
means the broker opens the database session read-only, so writes are
refused by the engine (and disabling read-only ends the session);
`read-write` is full access. The mode is set by the user in the app.

## 3. Retries and timeouts

Calls execute immediately; there is no approval wait. Set your HTTP client
timeout to **at least {client_timeout} seconds** (upstream timeout +
margin).

**Always send a unique `request_id` no longer than
{request_id_max_bytes} UTF-8 bytes (a UUID is recommended) on mutating calls.**
A retry that re-sends the same
`request_id` joins the in-flight execution: exactly one upstream
execution, the same response replayed while its body remains cached, and a
non-reexecute tombstone retained for 10 minutes.
Reusing a `request_id` with a *different* payload is rejected with
`409 {{"reason": "request_id_mismatch"}}`. GET/HEAD are never coalesced.
The broker reserves bounded idempotency capacity before accepting a keyed
request. `503 {{"reason": "idempotency_capacity"}}` means it was not accepted:
wait, then safely retry the same ID. If a completed response was too large or
evicted, its key remains tombstoned and a retry returns
`409 {{"reason": "outcome_not_replayable"}}` without executing again. Do not
mint a new ID and repeat that operation automatically; reconcile its upstream
effect or ask the user first.
For WS/PG/SSH opens, replay returns the originally issued capability and does
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

    → 200 {{"status": 200, "headers": {{…}}, "body": "…", "body_encoding": "utf8"}}

You supply the method, path (query string included; there is no separate
query field), headers and body; the connection supplies the host and the
credential. You cannot name a host. Paths must start with `/`. The broker
controls `Host`, `Content-Length`, `Transfer-Encoding`, the hop-by-hop
headers and the injected credential header; naming one of those is
rejected with `400 {{"reason": "reserved_header"}}`. Bodies may be a JSON
string, a JSON object/array (serialized for you), or `body_base64` for
binary. Non-UTF-8 response bodies come back base64-encoded with
`"body_encoding": "base64"`. Redirects are followed only within the
connection's pinned host; a cross-host redirect is returned to you as the
raw 3xx.

ABP/0 represents headers as JSON objects with string values. Repeated upstream
response fields are combined with `, `, which is lossy for fields such as
`Set-Cookie`; do not assume distinct repeated fields are preserved.

## 5. WebSocket: POST /v1/ws/open

    POST /v1/ws/open
    {{"connection": "market-feed", "request_id": "req-<uuid>"}}

    → 200 {{"ws_url": "ws://127.0.0.1:<port>/v1/ws/bridge/<ticket>",
            "expires_in_seconds": {ticket}}}

Authorization is checked once, at open time. Connect any stock WebSocket
client to `ws_url`; the broker dials the connection's configured upstream
with the credential injected and pipes frames verbatim. The ticket expires
`expires_in_seconds` after issue and may be redeemed any number of times
within that window, all
under the authorization that issued it. Sessions carry a configured max TTL
(1 h) and an idle timeout (5 min; protocol ping/pong counts as activity). A
reconnect after the ticket window needs a fresh open.

## 6. Postgres: POST /v1/pg/open

    POST /v1/pg/open
    {{"connection": "prod-db", "request_id": "req-<uuid>"}}

    → 200 {{"dsn": "postgres://ticket@127.0.0.1:<port>/<dbname>?sslmode=disable",
            "ticket": "<ticket>",
            "expires_in_seconds": {ticket},
            "example": "PGPASSWORD=<ticket> psql \"<dsn>\""}}

Run any unmodified client against the DSN, supplying the ticket **via
PGPASSWORD or a passfile**, never on the command line, where it would sit
in `ps`-visible argv and shell history:

    PGPASSWORD=<ticket> psql "<dsn>" -c "SELECT 1;"

The broker's local proxy speaks real Postgres on the loopback leg and
opens the upstream Postgres leg itself; you never see the real password or
host. When your wiring's `mode` is `read-only` (see `GET /v1/connections`),
the upstream session is opened with `default_transaction_read_only=on`:
reads work, writes come back as Postgres's read-only error, and trying to
turn read-only off (`SET`/`RESET`, `BEGIN … READ WRITE`, `RESET ALL`) ends
the session — ask your user to grant read-write if you need it.
Ticket lifetime and reconnect semantics are the same as WebSocket.
`sslmode=disable` applies only to the loopback leg; the upstream
leg uses the connection's configured TLS. The default upstream
`sslmode=verify-full` validates the certificate chain and hostname. A
per-connection private CA bundle can extend the trusted roots.

## 7. SSH: POST /v1/ssh/open

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

    SSH_AUTH_SOCK=<auth_sock> ssh -o IdentitiesOnly=yes <destination>
    SSH_AUTH_SOCK=<auth_sock> git -C repo push

The broker serves the ssh-agent protocol on that socket: it offers the one
configured key and signs your authentication with it, and the private key
never leaves the broker. It verifies OpenSSH's session binding against the
pinned host-key fingerprint and will **only** sign host-bound public-key
login as the pinned `user`; it signs nothing else.

When `host_key_fingerprint` is `null`, the server's key is not pinned yet:
the broker trusts it on first use. The key the server presents at your first
connection is pinned automatically and recorded in the activity log; every
later connection is verified against it, and a server that presents a
different key is refused.

Ticket lifetime and reconnect semantics
match WebSocket and Postgres: the socket accepts as many connections as needed for the
{ticket} s window, so multiple SSH
invocations as you need under the authorization that issued it. Live SSH
connections are also capped by the remaining lifetime of an access grant.
Compatible OpenSSH clients
negotiate session binding and host-bound authentication automatically, so an
explicit `-o PubkeyAuthentication=host-bound` is optional. Clients without
those OpenSSH extensions fail closed because the broker refuses unbound or
host-key-mismatched signing requests.

## 8. Other errors

- `400 {{"reason": "invalid_json"}}`: the request body was not valid JSON
  for the endpoint (wrong/missing Content-Type, malformed JSON, or a
  missing field); the `detail` says which.
- `401 {{"reason": "missing_token", "cause": "...", "detail": "..."}}`:
  no usable bearer token reached the broker. The `cause` distinguishes an
  absent or invalid Authorization header, a non-Bearer scheme, and an empty
  bearer credential. The detail describes what arrived without assuming the
  agent itself omitted or rewrote the data.
- `401 {{"reason": "invalid_token", "detail": "..."}}`: the token that
  reached the broker was not recognized. It may have been revoked or rewritten
  by a local application; re-pair.
- `401 {{"reason": "token_expired"}}`: re-pair.
- `401 {{"reason": "token_superseded"}}`: another instance under your name
  re-paired; re-read the token at the response's `store_at`, do not pair
  again.
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
        tokens = paths.tokens_display(),
        client_timeout = client_timeout,
        ticket = ticket,
        token_days = token_days,
        request_id_max_bytes = REQUEST_ID_MAX_BYTES,
    )
}

/// The generated skill file (`aka skill`): the same instructions
/// content under skill frontmatter; generated output, not a hand-maintained
/// artifact.
pub fn skill_file(config: &BrokerConfig, paths: &Paths) -> String {
    format!(
        r#"---
name: aka
description: >-
  Broker credentialed HTTP, WebSocket, Postgres and SSH access through the
  local AKA daemon. Use when a task needs an API key, database, stream,
  or SSH key the developer has configured. The broker does not directly expose
  the stored secret; access is authorization-gated. Start by reading the live
  instructions over the broker socket.
---

<!-- Generated by `aka skill`. Do not edit: regenerate instead.
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
        let m = manifest(&BrokerConfig::default(), &paths());
        assert_eq!(PROTOCOL_VERSION, 0);
        assert_eq!(m["protocol_version"], 0);
        assert_eq!(m["auth_schemes"], serde_json::json!(["bearer"]));
        assert_eq!(m["transport"], "http-over-unix-socket");
        assert!(m.get("approval_modes").is_none());
        assert!(m.get("approval_timeout_seconds").is_none());
        assert!(m.get("access_grant_ttl_seconds").is_none());
        assert_eq!(m["recommended_client_timeout_seconds"], 120);
        assert_eq!(m["token_ttl_days"], 30);
        assert_eq!(m["ticket_ttl_seconds"], 60);
        assert_eq!(m["request_id_max_bytes"], REQUEST_ID_MAX_BYTES);
        assert_eq!(m["endpoints"]["pair"], "/v1/pair");
        assert_eq!(m["endpoints"]["whoami"], "/v1/whoami");
        assert_eq!(m["endpoints"]["ssh_open"], "/v1/ssh/open");
        assert_eq!(m["socket"], "~/.aka/broker.sock");
        assert_eq!(m["tokens_dir"], "~/.aka/tokens");
        assert_eq!(
            m["capabilities"],
            serde_json::json!(["http", "websocket", "postgres", "ssh"])
        );
    }

    #[test]
    fn manifest_names_the_actual_runtime_paths() {
        // A broker rooted elsewhere (`serve --root`, tests) must not claim
        // the production socket.
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::under(dir.path());
        let m = manifest(&BrokerConfig::default(), &paths);
        assert_eq!(m["socket"], paths.socket_file().display().to_string());
        let text = instructions(&BrokerConfig::default(), &paths);
        assert!(text.contains(&paths.socket_file().display().to_string()));
    }

    #[test]
    fn instructions_cover_the_contract() {
        let text = instructions(&BrokerConfig::default(), &paths());
        for needle in [
            "curl --unix-socket ~/.aka/broker.sock",
            "~/.aka/tokens",
            "/v1/whoami",
            "store_at",
            "token_superseded",
            "request_id",
            "256 UTF-8 bytes",
            "PGPASSWORD",
            "expires_in_seconds",
            "at least 120 seconds",
            "denied_by_policy",
            "\"wired\": true",
            "request_id_mismatch",
            "outcome_not_replayable",
            "idempotency_capacity",
            "retry_after_seconds",
            "invalid_json",
            "\"endpoint\": \"/v1/http\"",
            "/v1/ws/open",
            "/v1/pg/open",
            "/v1/ssh/open",
            "SSH_AUTH_SOCK",
            "session binding and host-bound authentication automatically",
            "host-key-mismatched signing requests",
        ] {
            assert!(text.contains(needle), "instructions missing {needle:?}");
        }
        assert!(text.contains(
            "`401 token_superseded` | Re-read the token from the response's `store_at` path"
        ));
        assert!(text.contains("Do **not** pair"));
        assert!(!text.contains("Any `401` means"));
        // Config-derived numbers are rendered, not hard-coded prose.
        assert!(text.contains("Tokens last\n30 days") || text.contains("30 days"));
    }

    #[test]
    fn skill_file_embeds_instructions() {
        let cfg = BrokerConfig::default();
        let skill = skill_file(&cfg, &paths());
        assert!(skill.starts_with("---\nname: aka"));
        assert!(skill.contains(&instructions(&cfg, &paths())));
    }
}
