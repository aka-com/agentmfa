// The matrix's empty cells: broker behaviour AKA does not implement.
//
// Everything here is a passing stub (see lib/pending.ts). They are in the
// suite on purpose: the matrix is written from what an operator would
// expect of something sitting between an agent and a database, a shell, or
// an API, and the cells AKA does not fill are as much a part of that
// picture as the ones it does. Each stub names the behaviour, what happens
// instead, and where in the tree that decision is made — so implementing
// one starts from a test that already exists.
//
// Gaps that belong to one connection type are stubbed next to that type's
// real tests instead of here:
//
//   - per-statement Postgres approval, read-only sessions, schema/table
//     scoping, result-set budgets   → postgres.test.ts
//   - per-command SSH approval, command audit, path/command scoping,
//     forwarding vs shell           → ssh.test.ts
//   - approval levels by operation kind, destructive-op classes,
//     path-scoped grants            → approvals.test.ts
//
// This file holds the ones that cut across every connection type.

import test from 'node:test';

import { pending } from './lib/pending';

test('agents are not authorized separately from one another', (t) => {
  // One shared key covers every local agent (crates/aka-core/src/policy.rs:
  // "authorization is a property of the connection, not of an (agent,
  // connection) pair"), and `X-AgentMFA-Client` is a self-reported label
  // used for attribution. Approval *windows* are scoped per label, but a
  // second agent that claims the first one's label rides its window, and
  // nothing stops it: same-user processes were never securely
  // distinguishable across a 0600 socket.
  pending(
    t,
    'per-agent authorization (wire Claude Code to the database but not Cursor)',
    'one shared key per machine; access is per connection, and the agent label is attribution only',
  );
});

test('an API connection cannot be narrowed to particular paths or methods', (t) => {
  // A connection pins scheme/host/port and the credential template
  // (`ConnectionConfig::Api` in crates/aka-core/src/types.rs). Every path
  // and every accepted method on that host is in scope; the only
  // finer-grained control anywhere in the broker is the MCP tool subset.
  pending(
    t,
    'restricting an API connection to an allow-list of paths or methods (GET /repos/* only)',
    'the pinned destination is host-level; path and method validation checks shape, not policy',
  );
});

test('MCP resources and prompts have no allow-list of their own', (t) => {
  // `allowed_tools` curates `tools/call` only. `resources/read` is
  // confirmed like other real access when the switch is on, but there is no
  // subset to enable a resource in the way a tool can be enabled, and
  // `resources/list` and `prompts/list` are session plumbing
  // (`is_mcp_envelope` in crates/aka-core/src/daemon/mod.rs).
  pending(
    t,
    'curating which MCP resources or prompts an agent may reach, as tools can be curated',
    'the subset covers tools; resources and prompts are all-or-nothing with the connection',
  );
});

test('there is no read-scoped session for any connection type', (t) => {
  // Access is a boolean per connection, and an approval window covers
  // whatever the agent sends next. Nothing anywhere in the broker splits
  // reads from writes, on any plane.
  pending(
    t,
    'a read-scoped session that carries GET/HEAD (or SELECT) and refuses the rest',
    'access is enabled/disabled per connection; nothing distinguishes reads from writes',
  );
});

test('access cannot be time-boxed or scheduled', (t) => {
  // `ToolAccess` (crates/aka-core/src/types.rs) is a boolean plus the MCP
  // subset. Approval windows expire, but they are grants inside a
  // connection that is already enabled — enabling a connection until 5pm,
  // or for one hour, is not expressible.
  pending(
    t,
    'granting access that expires (enable this connection for an hour, or during work hours)',
    'a connection is enabled or disabled; only in-memory approval windows have a clock',
  );
});

test('there are no per-connection budgets', (t) => {
  // The limits are global: 60 capability calls per minute per identity, a
  // 10 MB response cap, a 150 MB request cap, and session-count backstops
  // (crates/aka-core/src/config.rs). None of them can be set per
  // connection, so a chatty tool and a sensitive one share one budget.
  pending(
    t,
    'per-connection rate limits, call quotas, or spend budgets',
    'rate limiting is per identity and broker-wide; caps are global constants',
  );
});

test('response contents are not inspected beyond credential scrubbing', (t) => {
  // `Redactions` (crates/aka-core/src/capability/http.rs) removes the
  // injected credential from a relayed body. Nothing else looks at what
  // comes back: an upstream that returns customer records, other people's
  // secrets, or a prompt injection relays as-is, and the instructions say
  // so ("arbitrary transformed upstream output cannot be guaranteed
  // secret-free").
  pending(
    t,
    'inspecting or filtering response content (redacting PII, refusing an oversized result set, flagging injected instructions)',
    'only the connection’s own credential material is scrubbed from relayed bodies',
  );
});

test('request bodies are summarized for a prompt, never recorded', (t) => {
  // The activity log keeps method, path, connection, agent, outcome and
  // duration. A confirmation prompt shows a bounded preview of the body,
  // and that preview is not retained after the decision. There is no
  // request/response archive to replay or audit after the fact.
  pending(
    t,
    'recording request and response bodies for later audit or replay',
    'the audit log records metadata; prompt previews are bounded and transient',
  );
});

test('nothing distinguishes one human operator from another', (t) => {
  // The manage token is a bearer credential for the whole management
  // plane; there is one local user, one vault, one audit trail. Team
  // management is on the roadmap (README) and not in the broker.
  pending(
    t,
    'multiple operators with different management rights, or an audit trail attributing decisions to a person',
    'one management token grants the whole manage plane; approvals record no operator identity',
  );
});
