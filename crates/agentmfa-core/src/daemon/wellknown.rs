//! Self-describing discovery surface (DESIGN.md §5b).
//!
//! `GET /.well-known/agent-broker.json` serves the machine-readable
//! manifest; `GET /instructions` serves the human/agent-readable version.
//! Both are served by the daemon itself, so they can never drift from
//! what's actually running, and `agentmfa skill` emits the same
//! instructions content as a checked-in skill file (§5). Both render the
//! *actual* runtime paths (a `--root` broker names its real socket, not the
//! production default), which is the point of daemon-served discovery.

use serde_json::json;

use crate::config::BrokerConfig;
use crate::paths::Paths;
use crate::wire::{ApprovalMode, AuthScheme, PROTOCOL_VERSION};

pub fn manifest(config: &BrokerConfig, paths: &Paths) -> serde_json::Value {
    json!({
        "name": "agentmfa",
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
        // Capability flags: how a client may authenticate and how approval
        // decisions reach it. Closed vocabularies (wire.rs); new schemes
        // and modes appear here before any client is expected to use them.
        "auth_schemes": AuthScheme::ALL,
        "approval_modes": ApprovalMode::ALL,
        "approval_timeout_seconds": config.approval_timeout.as_secs(),
        "access_grant_ttl_seconds": config.access_grant_ttl.as_secs(),
        // approval wait + upstream timeout + margin: machine-actionable, so
        // agents set a concrete client timeout instead of parsing prose (§4).
        "recommended_client_timeout_seconds": config.recommended_client_timeout.as_secs(),
        "token_ttl_days": config.token_ttl.as_secs() / 86400,
        "ticket_ttl_seconds": config.ticket_ttl.as_secs(),
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
        "pairing": "Reuse a stored token if GET /v1/whoami accepts it; otherwise POST /v1/pair with {\"agent_name\": \"<your-name>\"}, the user approves, and the returned token is your Bearer token.",
    })
}

/// The `/instructions` markdown. The pair-or-reuse walkthrough, one worked
/// example per capability, token-storage guidance, and error semantics.
pub fn instructions(config: &BrokerConfig, paths: &Paths) -> String {
    let approval = config.approval_timeout.as_secs();
    let client_timeout = config.recommended_client_timeout.as_secs();
    let ticket = config.ticket_ttl.as_secs();
    let token_days = config.token_ttl.as_secs() / 86400;
    let access_minutes = config.access_grant_ttl.as_secs() / 60;
    format!(
        r#"# AgentMFA: broker instructions

AgentMFA holds this developer's secrets in the macOS Keychain and brokers
their use. Broker-produced fields do not expose vault-held values or secret
names; you ask the broker to *use a named connection* (make an HTTP request
through `github`, connect to `prod-db`) and the broker injects the credential
on the upstream leg only when an exact approval, active access session, or
standing rule authorizes the request. Relayed HTTP responses are scrubbed for
recognized credential material, but arbitrary transformed upstream output
cannot be guaranteed secret-free.

The default approval creates a fixed {access_minutes}-minute in-memory access
session. A read session covers HTTP GET/HEAD; a full session covers every HTTP
method or new WebSocket/Postgres/SSH opens. Sessions are bound to this token
generation and the exact connection configuration and never extend on use.

Protocol: Agent Broker Protocol version {protocol_version} (the manifest's
`protocol_version`; PROTOCOL.md is the spec).
Transport: HTTP over the Unix domain socket `{socket}`.
Example: `curl --unix-socket {socket} http://localhost/v1/connections`

## 1. Authenticate: reuse a stored token; pair only when you must

Pairing interrupts the human; reusing a stored token does not. Check for
one first:

1. Read `{tokens}/<your-name>`. If it exists, probe it:

       curl --unix-socket {socket} \
            -H "Authorization: Bearer <token>" http://localhost/v1/whoami
       → 200 {{"agent": "<your-name>", "identity": "…", "expires_at": "…"}}

   `200` means the token works: skip pairing. Any `401` means it does
   not: fall through to pairing.

2. Pair:

       curl --unix-socket {socket} -X POST http://localhost/v1/pair \
            -H "Content-Type: application/json" \
            -d '{{"agent_name": "<your-name>"}}'
       → 200 {{"token": "amfa_…", "agent": "<your-name>",
               "identity": "<the peer identity the token is pinned to>",
               "expires_after_days": {token_days},
               "store_at": "{tokens}/<your-name>"}}

   The human approves the pairing in the AgentMFA window; the call blocks
   until they decide. Store the token at `store_at` with mode 0600 (the
   directory already exists), or in your own credential store, and send it
   on every subsequent call as `Authorization: Bearer <token>`.

The token is pinned to your process's peer identity: normally its
code-signing identity, or a best-effort local executable fingerprint when
the process is unsigned/ad-hoc. A copy lifted from disk is not generally
usable from a different pinned identity. Tokens last {token_days} days,
refreshed on use.

**Several instances under one name share the stored token.** Pairing
again replaces the name's previous token; a call failing with
`401 {{"reason": "token_superseded"}}` means another instance re-paired:
re-read the token file and retry rather than pairing again (which would
break that instance in turn). Concurrent pairings from identically-signed
processes are merged into one prompt and receive the same token. Re-pairing or
user-initiated disconnect also invalidates outstanding data-plane capabilities
and closes live WebSocket, Postgres, and SSH connections for that agent name.

## 2. Discover what you may ask for

    GET /v1/connections
    → [{{"name": "github", "type": "api", "target": "api.github.com",
         "endpoint": "/v1/http", "multi_connect": false,
         "approval": "will_prompt", "access_session": null}}, …]

Connections name a destination. Secret names and values are never
exposed. `endpoint` is where a call naming this connection goes (POST
it). `multi_connect` says whether one open's ticket may be redeemed
repeatedly within its window; ws/pg can be configured either way, while
ssh is always multi-connect because OpenSSH may use several agent
connections during one login. `approval` is what a call costs right now:
`will_prompt` blocks on a human decision (tell your user to expect the
prompt), `read_auto_allowed` covers GET/HEAD under an active access session,
and `auto_allowed` proceeds immediately under a full access session or a
standing rule. When present, `access_session` gives its scope and expiry.

## 3. Approvals: set your client timeout first

Approval waits are **held-open requests**: a prompted call simply does not
respond until the human decides or the {approval} s approval timeout
auto-denies it. Blocking on the call is the correct behavior. Set your HTTP
client timeout to **at least {client_timeout} seconds** (approval wait +
upstream timeout + margin); many client defaults are far lower.

The primary human choice allows {access_minutes} minutes. A read request starts
a read session; a mutating HTTP request or WS/PG/SSH open starts a full session.
A full approval replaces an active read session and starts a new fixed full
window; ordinary use never extends either window. The human may instead allow
only the exact request or save a standing rule.

Denials come back as `403` with a machine-readable reason:
- `{{"reason": "denied_by_user"}}`: the human said no; don't retry, ask them.
- `{{"reason": "approval_timeout"}}`: nobody decided in time; this is
  retryable after re-alerting your user.

**Always send a unique `request_id` (any unique string; a UUID is
recommended) on mutating calls.** A retry that re-sends the same
`request_id` joins the existing prompt: one approval, exactly one upstream
execution, the same response replayed to every retry (for 10 minutes).
Reusing a `request_id` with a *different* payload is rejected with
`409 {{"reason": "request_id_mismatch"}}`. GET/HEAD are never coalesced.
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
`expires_in_seconds` after issue; on multi-connect connections (the
default) it may be redeemed any number of times within that window, all
under the authorization that issued it. Sessions carry a configured max TTL
(1 h) and an idle timeout (5 min; protocol ping/pong counts as activity). A
grant-backed session is capped by the grant's remaining lifetime and closes if
the grant expires or is revoked. A reconnect after the ticket window needs a
fresh open. An active full access session or standing rule lets that open
proceed without another prompt.

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
host. Ticket lifetime and multi-connect semantics are the same as
WebSocket. `sslmode=disable` applies only to the loopback leg; the upstream
leg uses the connection's configured TLS. The default upstream
`sslmode=require` encrypts without certificate verification; use
`verify-full` when CA and hostname verification are required.

## 7. SSH: POST /v1/ssh/open

    POST /v1/ssh/open
    {{"connection": "prod-ssh", "request_id": "req-<uuid>"}}

    → 200 {{"auth_sock": "/…/.agentmfa/ssh/agent-<id>.sock",
            "host": "prod.example.com", "port": 22, "user": "deploy",
            "host_key_fingerprint": "SHA256:…",
            "expires_in_seconds": {ticket}}}

Authorization is checked once, at open time. Point `SSH_AUTH_SOCK` at
`auth_sock` and run any unmodified SSH client (`ssh`, `git`, `scp`, `rsync`,
`ssh -L`):

    SSH_AUTH_SOCK=<auth_sock> ssh -o IdentitiesOnly=yes \
      <user>@<host>
    SSH_AUTH_SOCK=<auth_sock> git -C repo push

The broker serves the ssh-agent protocol on that socket: it offers the one
configured key and signs your authentication with it, and the private key
never leaves the broker. It verifies OpenSSH's session binding against the
configured host-key fingerprint and will **only** sign host-bound public-key
login as the pinned `user`; it signs nothing else. Ticket lifetime and multi-connect semantics
match WebSocket and Postgres: the socket accepts connections for the
{ticket} s window, and with multi-connect on (the default) as many SSH
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
- `401 {{"reason": "invalid_token" | "token_expired"}}`: re-pair (the human
  will see a pairing prompt).
- `401 {{"reason": "token_superseded"}}`: another instance under your name
  re-paired; re-read the token at the response's `store_at`, do not pair
  again.
- `401 {{"reason": "peer_identity_mismatch"}}`: the token is pinned to a
  different peer identity than yours; re-pair.
- `404 {{"reason": "unknown_connection"}}`: no such connection; the detail
  lists the configured names.
- `409 {{"reason": "request_id_mismatch"}}`: you reused a request_id with a
  different payload; mint a fresh one.
- `409 {{"reason": "pairing_already_pending"}}`: a pairing prompt for this
  name from another process is on screen; retry after it resolves.
- `429 {{"reason": "rate_limited" | "pairing_rate_limited"}}`: over budget;
  wait `retry_after_seconds` (also in the `Retry-After` header), then
  retry.
- `429 {{"reason": "pairing_denied_cooldown"}}`: the human denied a pairing
  moments ago; do not retry automatically, ask your user first.
- `502 {{"reason": "ssh_agent_open_failed"}}`: the key could not be loaded
  (missing, encrypted, or an unsupported type); the `detail` says which.
- `503 {{"reason": "ticket_session_limit" | "broker_session_limit"}}`: your
  session budget is exhausted; close sessions or wait, then reopen.
"#,
        protocol_version = PROTOCOL_VERSION,
        socket = paths.socket_display(),
        tokens = paths.tokens_display(),
        approval = approval,
        client_timeout = client_timeout,
        ticket = ticket,
        token_days = token_days,
        access_minutes = access_minutes,
    )
}

/// The generated skill file (`agentmfa skill`, §5): the same instructions
/// content under skill frontmatter; generated output, not a hand-maintained
/// artifact.
pub fn skill_file(config: &BrokerConfig, paths: &Paths) -> String {
    format!(
        r#"---
name: agentmfa
description: >-
  Broker credentialed HTTP, WebSocket, Postgres and SSH access through the
  local AgentMFA daemon. Use when a task needs an API key, database, stream,
  or SSH key the developer has configured. The broker does not directly expose
  the stored secret; access is authorization-gated. Start by reading the live
  instructions over the broker socket.
---

<!-- Generated by `agentmfa skill`. Do not edit: regenerate instead.
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
        assert_eq!(m["protocol_version"], PROTOCOL_VERSION);
        assert_eq!(m["auth_schemes"], serde_json::json!(["bearer_pinned"]));
        assert_eq!(m["approval_modes"], serde_json::json!(["blocking"]));
        assert_eq!(m["transport"], "http-over-unix-socket");
        assert_eq!(m["approval_timeout_seconds"], 120);
        assert_eq!(m["access_grant_ttl_seconds"], 900);
        assert_eq!(m["recommended_client_timeout_seconds"], 240);
        assert_eq!(m["token_ttl_days"], 30);
        assert_eq!(m["ticket_ttl_seconds"], 60);
        assert_eq!(m["endpoints"]["pair"], "/v1/pair");
        assert_eq!(m["endpoints"]["whoami"], "/v1/whoami");
        assert_eq!(m["endpoints"]["ssh_open"], "/v1/ssh/open");
        assert_eq!(m["socket"], "~/.agentmfa/broker.sock");
        assert_eq!(m["tokens_dir"], "~/.agentmfa/tokens");
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
            "curl --unix-socket ~/.agentmfa/broker.sock",
            "~/.agentmfa/tokens",
            "/v1/whoami",
            "store_at",
            "token_superseded",
            "request_id",
            "PGPASSWORD",
            "expires_in_seconds",
            "at least 240 seconds",
            "denied_by_user",
            "approval_timeout",
            "request_id_mismatch",
            "pairing_already_pending",
            "pairing_denied_cooldown",
            "retry_after_seconds",
            "invalid_json",
            "will_prompt",
            "auto_allowed",
            "read_auto_allowed",
            "15-minute",
            "\"endpoint\": \"/v1/http\"",
            "multi_connect",
            "/v1/ws/open",
            "/v1/pg/open",
            "/v1/ssh/open",
            "SSH_AUTH_SOCK",
            "session binding and host-bound authentication automatically",
            "host-key-mismatched signing requests",
        ] {
            assert!(text.contains(needle), "instructions missing {needle:?}");
        }
        // Config-derived numbers are rendered, not hard-coded prose.
        assert!(text.contains("Tokens last\n30 days") || text.contains("30 days"));
    }

    #[test]
    fn skill_file_embeds_instructions() {
        let cfg = BrokerConfig::default();
        let skill = skill_file(&cfg, &paths());
        assert!(skill.starts_with("---\nname: agentmfa"));
        assert!(skill.contains(&instructions(&cfg, &paths())));
    }
}
