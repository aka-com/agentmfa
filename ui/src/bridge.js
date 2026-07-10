// Bridge to the Rust core. Inside Tauri (withGlobalTauri), calls go to real
// commands over the IPC. In a plain browser, a self-contained dev mock
// stands in so the UI is developable and reviewable standalone; the mock
// mirrors the command surface and the DESIGN.md fixtures, but obviously
// enforces nothing (no Keychain, no daemon, no native OS authentication).

const tauri = typeof window !== 'undefined' ? window.__TAURI__ : undefined;

/** Which window chrome to render, from the URL hash. */
export const mode = location.hash.replace('#', '') || 'window';

export const invoke = tauri ? tauri.core.invoke : mockInvoke;
export const listen = tauri ? tauri.event.listen : mockListen;

/* ----------------------------- dev mock ---------------------------------- */

const listeners = {};
const MOCK_ACTIVITY_LIMIT = 200;
const MOCK_ACTIVITY_META = {
  denied: { icon: 'circleX', tone: 'danger' },
  secretCopied: { icon: 'clipboardCopy', tone: 'neutral' },
  sessionClosed: { icon: 'logOut', tone: 'neutral' },
  sessionOpened: { icon: 'logIn', tone: 'neutral' },
  autoAllowed: { icon: 'zap', tone: 'success' },
  requested: { icon: 'bell', tone: 'warning' },
  allowedOnce: { icon: 'circleCheck', tone: 'success' },
  paired: { icon: 'userRoundCheck', tone: 'success' },
  secretAdded: { icon: 'fileKey', tone: 'neutral' },
  secretUpdated: { icon: 'pencil', tone: 'neutral' },
  secretDeleted: { icon: 'trash', tone: 'neutral' },
  secretRevealed: { icon: 'eye', tone: 'neutral' },
  connectionAdded: { icon: 'plug', tone: 'neutral' },
  connectionUpdated: { icon: 'pencil', tone: 'neutral' },
  connectionDeleted: { icon: 'unplug', tone: 'neutral' },
  ruleRemoved: { icon: 'shieldMinus', tone: 'neutral' },
  grantRevoked: { icon: 'shieldX', tone: 'danger' },
  tokenRevoked: { icon: 'unplug', tone: 'danger' },
};
const MOCK_AGENT_SETUP = `Connect to the local AgentMFA broker. Read its current instructions with:
curl -s --unix-socket ~/.agentmfa/broker.sock http://localhost/instructions

Follow those instructions. Reuse an existing token before pairing, use a stable agent_name, and never ask me to paste a saved secret value.`;
function emit(event, payload) {
  (listeners[event] || []).forEach((cb) => cb({ event, payload }));
}
async function mockListen(event, cb) {
  (listeners[event] = listeners[event] || []).push(cb);
  return () => {};
}

// In-memory store mirroring the DESIGN.md fixtures.
let seq = 1;
const uid = () => `id-${seq++}`;
const now = () => new Date().toISOString();
const db = {
  secrets: [
    mkSecret('GITHUB_API_KEY', 'ghp_9aXf2Qe7LmNoP3demoToken41c'),
    mkSecret('DATABASE_PASSWORD', 'pg-s3cr3t-demo-pw'),
    mkSecret('STREAM_TOKEN', 'wss-tok-8f31d2-demo'),
    mkSecret('SERVICE_USER', 'svc-agent-ci'),
    mkSecret('SERVICE_PASSWORD', 'basic-pw-demo-8841'),
    mkSecret('DEPLOY_SSH_KEY', '-----BEGIN OPENSSH PRIVATE KEY-----demo'),
  ],
  connections: [],
  rules: [],
  grants: [],
  agents: [
    { name: 'claude-code', program: 'com.anthropic.claude-code', verification: 'Signed application',
      identity: 'com.anthropic.claude-code · Team 6XN7K9RPQ2', paired_at: now(), last_used: now() },
  ],
  sessions: [],
  activity: [],
  settings: { reauth_on_read: true, hide_secret_prefixes: true, pg_trusted_ca_bundle_path: null, menu_bar_hides_dock: false },
  queue: [],
};
function mkSecret(name, value) {
  return { id: uid(), name, _value: value, created_at: now(), updated_at: now() };
}
seedConnections();
function seedConnections() {
  const by = (n) => db.secrets.find((s) => s.name === n).id;
  db.connections = [
    mkConn('github', 'api', ['GITHUB_API_KEY'], { host: 'api.github.com', scheme: 'https', template: 'Authorization: Bearer {{GITHUB_API_KEY}}' }),
    mkConn('prod-db', 'pg', ['DATABASE_PASSWORD'], { host: 'db.internal.aka.com', port: 5432, dbname: 'app_production', user: 'app', sslmode: 'require' }, true),
    mkConn('market-feed', 'ws', ['STREAM_TOKEN'], { url: 'wss://stream.example.com/feed' }, true),
    mkConn('internal-api', 'api', ['SERVICE_USER', 'SERVICE_PASSWORD'], { host: 'internal.aka.com', scheme: 'https', template: 'Authorization: Basic {{base64(SERVICE_USER ":" SERVICE_PASSWORD)}}' }),
    mkConn('prod-ssh', 'ssh', ['DEPLOY_SSH_KEY'], {
      host: 'prod.example.com', port: 22, user: 'deploy',
      host_key_fingerprint: 'SHA256:vdZ5N8kNxU7J4W2WYa6qK0sJYv8oXb8s2H7n3jE5q1A',
    }, true),
  ];
  function mkConn(name, type, secretNames, cfg, multi) {
    return { id: uid(), name, type, secret_names: secretNames, secret_ids: secretNames.map(by), multi_connect: !!multi, ...cfg };
  }
}
seedFixtures();
// Illustrative broker state so the standalone dev page exercises every layout
// affordance: ongoing access, temporary access, an open connection, and activity.
function seedFixtures() {
  db.rules.push({ id: uid(), agent: 'claude-code', connection_id: db.connections[0].id });
  db.grants.push({ id: uid(), agent: 'claude-code', connection_id: db.connections[1].id,
    scope: 'full', expires_at: new Date(Date.now() + 11 * 60000).toISOString() });
  db.sessions.push({ id: 1, type: 'ws', agent: 'claude-code', connection: 'market-feed', detail: 'wss://stream.example.com/feed' });
  // Spread across a day so the relative/absolute timestamp split is visible.
  const t = (min) => new Date(Date.now() - min * 60000).toISOString();
  [
    ['denied', 'Denied: claude-code', 'POST api.github.com/repos/aka/aka/dispatches', 2],
    ['secretCopied', 'Secret copied: GITHUB_API_KEY', null, 6],
    ['sessionClosed', 'WebSocket bridge closed', 'market-feed', 14],
    ['sessionOpened', 'WebSocket connection opened', 'market-feed', 35],
    ['autoAllowed', 'Used without asking: claude-code → github', null, 90],
    ['requested', 'claude-code requested github', 'GET api.github.com/user/repos', 180],
    ['sessionClosed', 'Postgres connection closed', 'Ticket window elapsed', 400],
    ['sessionOpened', 'Postgres connection opened', 'prod-db → app_production', 402],
    ['allowedOnce', 'Allowed this request: claude-code', 'Connect to Postgres → app@db.internal.aka.com:5432/app_production', 1500],
    ['paired', 'Agent connected: claude-code', null, 3000],
  ].forEach(([kind, text, detail, min]) =>
    db.activity.push({ ...MOCK_ACTIVITY_META[kind], text, detail: detail || null, at: t(min) }));
}
function audit(kind, text, detail) {
  db.activity.unshift({ ...MOCK_ACTIVITY_META[kind], text, detail: detail || null, at: new Date().toISOString() });
  db.activity.length = Math.min(db.activity.length, MOCK_ACTIVITY_LIMIT);
}
function connDto(c) {
  return {
    id: c.id, name: c.name, type: c.type, target: connTarget(c),
    secret_names: c.secret_names, multi_connect: c.multi_connect,
    rules: db.rules.filter((r) => r.connection_id === c.id).map((r) => ({ id: r.id, agent: r.agent })),
    grants: db.grants.filter((g) => g.connection_id === c.id).map((g) => ({ ...g })),
    host: c.host || null, scheme: c.scheme || null, port: c.port || null, template: c.template || null,
    dbname: c.dbname || null, user: c.user || null, host_key_fingerprint: c.host_key_fingerprint || null,
    sslmode: c.sslmode || null, url: c.url || null,
  };
}
function connTarget(c) {
  if (c.type === 'api') return c.host;
  if (c.type === 'pg') return `${c.user}@${c.host}:${c.port}/${c.dbname}`;
  if (c.type === 'ssh') return c.port && c.port !== 22 ? `${c.user}@${c.host}:${c.port}` : `${c.user}@${c.host}`;
  return c.url;
}
function revealPrefix(v) {
  const n = Math.min(6, Math.floor(v.length / 2));
  return n < v.length ? v.slice(0, n) + '…' : v;
}

async function mockInvoke(cmd, args = {}) {
  switch (cmd) {
    case 'list_secrets':
      return db.secrets.map((s) => {
        const names = db.connections.filter((c) => c.secret_names.includes(s.name)).map((c) => c.name);
        return { id: s.id, name: s.name, used_by: names.length, used_by_names: names, created_at: s.created_at, updated_at: s.updated_at };
      });
    case 'list_connections': return db.connections.map(connDto);
    case 'list_agents':
      return db.agents.map((a) => ({ ...a,
        rule_count: db.rules.filter((r) => r.agent === a.name).length,
        temporary_access_count: db.grants.filter((g) => g.agent === a.name).length }));
    case 'list_sessions': return db.sessions.slice();
    case 'list_activity': return db.activity.slice(0, Math.min(args.limit ?? MOCK_ACTIVITY_LIMIT, MOCK_ACTIVITY_LIMIT));
    case 'get_queue': return db.queue.slice();
    case 'get_settings': return { ...db.settings };
    case 'get_agent_setup': return MOCK_AGENT_SETUP;
    case 'copy_agent_setup': return;
    case 'copy_broker_socket': return;
    case 'add_secret': {
      if (db.secrets.some((s) => s.name === args.name)) throw new Error(`A secret named ${args.name} already exists`);
      db.secrets.push(mkSecret(args.name, args.value)); audit('secretAdded', `Secret added: ${args.name}`); return;
    }
    case 'edit_secret': {
      const s = db.secrets.find((x) => x.id === args.id); if (!s) throw new Error('no such secret');
      if (args.newName && args.newName !== s.name) {
        db.connections.forEach((c) => {
          const i = c.secret_names.indexOf(s.name); if (i !== -1) c.secret_names[i] = args.newName;
          if (c.template) c.template = c.template.split(s.name).join(args.newName);
        });
        s.name = args.newName;
      }
      if (args.newValue) s._value = args.newValue;
      s.updated_at = now(); audit('secretUpdated', `Secret updated: ${s.name}`); return;
    }
    case 'delete_secret': {
      const s = db.secrets.find((x) => x.id === args.id); if (!s) throw new Error('no such secret');
      const users = db.connections.filter((c) => c.secret_names.includes(s.name)).map((c) => c.name);
      if (users.length) throw new Error(`in use by ${users.join(', ')}`);
      db.secrets = db.secrets.filter((x) => x.id !== args.id); audit('secretDeleted', `Secret deleted: ${s.name}`); return;
    }
    case 'reveal_secret_prefix': {
      const s = db.secrets.find((x) => x.id === args.id); if (!s) throw new Error('no such secret');
      audit('secretRevealed', `Secret prefix revealed: ${s.name}`); return revealPrefix(s._value);
    }
    case 'copy_secret': {
      const s = db.secrets.find((x) => x.id === args.id); if (!s) throw new Error('no such secret');
      audit('secretCopied', `Secret copied: ${s.name}`); emit('amfa://activity-appended', {}); return;
    }
    case 'add_connection': {
      const i = args.input;
      if (i.type === 'ssh' && i.multi_connect === false) throw new Error('ssh connections must allow multiple agent connections per approval');
      if (i.type === 'ssh' && !i.host_key_fingerprint) throw new Error('SSH host key fingerprint is required');
      if (db.connections.some((c) => c.name === i.name)) throw new Error(`A connection named ${i.name} already exists`);
      const secret_names = i.type === 'api'
        ? (i.template.match(/[A-Z_][A-Z0-9_]*/g) || []).filter((n) => db.secrets.some((s) => s.name === n))
        : [db.secrets.find((s) => s.id === i.secret_id)?.name].filter(Boolean);
      db.connections.push({ id: uid(), name: i.name, type: i.type, secret_names, multi_connect: i.multi_connect,
        host: i.host, scheme: i.scheme, port: i.port, template: i.template, dbname: i.dbname, user: i.user,
        host_key_fingerprint: i.host_key_fingerprint, sslmode: i.sslmode, url: i.url });
      audit('connectionAdded', `Connection added: ${i.name}`); return;
    }
    case 'edit_connection': {
      const c = db.connections.find((x) => x.id === args.id); if (!c) throw new Error('no such connection');
      const i = args.input;
      if (i.type === 'ssh' && i.multi_connect === false) throw new Error('ssh connections must allow multiple agent connections per approval');
      if (i.type === 'ssh' && !i.host_key_fingerprint) throw new Error('SSH host key fingerprint is required');
      Object.assign(c, { name: i.name, host: i.host, port: i.port, dbname: i.dbname, user: i.user,
        host_key_fingerprint: i.host_key_fingerprint, url: i.url, template: i.template, multi_connect: i.multi_connect });
      if (i.secret_id) c.secret_names = [db.secrets.find((s) => s.id === i.secret_id)?.name].filter(Boolean);
      audit('connectionUpdated', `Connection updated: ${i.name}`); return;
    }
    case 'delete_connection': {
      const c = db.connections.find((x) => x.id === args.id); if (!c) throw new Error('no such connection');
      db.connections = db.connections.filter((x) => x.id !== args.id);
      db.rules = db.rules.filter((r) => r.connection_id !== args.id); audit('connectionDeleted', `Connection deleted: ${c.name}`); return;
    }
    case 'remove_rule': db.rules = db.rules.filter((r) => r.id !== args.id); audit('ruleRemoved', 'Approval required again'); return true;
    case 'remove_grant': db.grants = db.grants.filter((g) => g.id !== args.id); audit('grantRevoked', 'Temporary access ended'); return true;
    case 'revoke_agent':
      db.agents = db.agents.filter((a) => a.name !== args.name);
      db.grants = db.grants.filter((g) => g.agent !== args.name);
      db.sessions = db.sessions.filter((s) => s.agent !== args.name);
      audit('tokenRevoked', `Agent disconnected: ${args.name}`);
      emit('amfa://agents-changed', {});
      emit('amfa://sessions-changed', {});
      return true;
    case 'close_session': db.sessions = db.sessions.filter((s) => s.id !== args.id); emit('amfa://sessions-changed', {}); return true;
    case 'set_reauth_on_read': db.settings.reauth_on_read = args.on; return;
    case 'set_hide_secret_prefixes':
      db.settings.hide_secret_prefixes = args.on;
      return;
    case 'set_menu_bar_hides_dock':
      db.settings.menu_bar_hides_dock = args.on;
      return;
    case 'set_pg_trusted_ca_bundle_path': {
      const path = (args.path || '').trim();
      db.settings.pg_trusted_ca_bundle_path = path || null;
      return;
    }
    case 'decide': {
      const req = db.queue.find((r) => r.id === args.id);
      if (req && req.kind === 'pair' && args.revokeInheritedRules) {
        db.rules = db.rules.filter((r) => r.agent !== req.agent);
        audit('ruleRemoved', `Approval required again: ${req.agent}`);
      }
      if (req && req.kind === 'pair' && args.decision === 'allow_once') {
        db.grants = db.grants.filter((g) => g.agent !== req.agent);
        db.sessions = db.sessions.filter((s) => s.agent !== req.agent);
        const existing = db.agents.find((agent) => agent.name === req.agent);
        if (existing) {
          existing.paired_at = now();
          existing.last_used = existing.paired_at;
        } else {
          db.agents.push({
            name: req.agent,
            program: req.pairing_identity.program,
            verification: req.pairing_identity.verification,
            identity: req.pairing_identity.technical,
            paired_at: now(),
            last_used: now(),
          });
        }
        emit('amfa://agents-changed', {});
        emit('amfa://sessions-changed', {});
      }
      if (req && args.decision === 'allow_session' && req.connection) {
        db.grants = db.grants.filter((g) =>
          !(g.agent === req.agent && g.connection_id === req.connection.id));
        db.grants.push({ id: uid(), agent: req.agent, connection_id: req.connection.id,
          scope: req.temporary_access.scope,
          expires_at: new Date(Date.now() + req.temporary_access.duration_seconds * 1000).toISOString() });
      }
      db.queue = db.queue.filter((r) => r.id !== args.id); emit('amfa://queue-changed', db.queue.slice()); return;
    }
    case 'ui_set_mode': case 'ui_hide_main': case 'ui_hide_dropdown': case 'ui_show_approval': return;
    default: throw new Error(`mock: unknown command ${cmd}`);
  }
}

// Expose a way for the dev page to inject a fake approval for visual testing.
// Kinds: 'http' (GET, collapsed payload), 'post' (mutating, auto-expanded
// payload with many headers + body — exercises the scroll region), 'pair'.
if (!tauri && typeof window !== 'undefined') {
  window.__mockApproval = (kind = 'http', ttlMs = 120000) => {
    const inherited = kind === 'pair'
      ? db.rules.filter((r) => r.agent === 'claude-code').map((r) => {
          const c = db.connections.find((conn) => conn.id === r.connection_id);
          return c ? { name: c.name, type: c.type, target: connTarget(c) } : null;
        }).filter(Boolean)
      : [];
    const post = kind === 'post';
    const body = post ? JSON.stringify({ event_type: 'deploy', client_payload: { ref: 'main', sha: 'a1b2c3d', env: 'production', requested_by: 'claude-code' } }, null, 2) : null;
    const http = kind === 'pair' ? null : {
      method: post ? 'POST' : 'GET',
      path: post ? '/repos/aka/aka/dispatches' : '/user/repos',
      headers: post
        ? [['Accept', 'application/vnd.github+json'], ['Content-Type', 'application/json'], ['X-GitHub-Api-Version', '2022-11-28'], ['User-Agent', 'claude-code/1.0'], ['X-Request-Id', 'req-8f31d2c4'], ['Accept-Encoding', 'gzip, deflate, br'], ['Connection', 'keep-alive'], ['Idempotency-Key', 'dispatch-20260708-01']]
        : [['Accept', 'application/vnd.github+json']],
      body_preview: body, body_len: body ? body.length : 0, body_truncated: false, mutating: post,
    };
    const req = {
      id: uid(), agent: 'claude-code', kind: kind === 'pair' ? 'pair' : 'http',
      connection: kind === 'pair' ? null : { id: db.connections[0].id, name: 'github', type: 'api', target: 'api.github.com', multi_connect: false },
      action: kind === 'pair' ? 'Connect claude-code to AgentMFA'
        : post ? 'POST api.github.com/repos/aka/aka/dispatches' : 'GET api.github.com/user/repos',
      notification: 'claude-code wants to use github: GET /user/repos',
      received_at: now(), deadline: new Date(Date.now() + ttlMs).toISOString(),
      identity: kind === 'pair' ? 'com.anthropic.claude-code · Team 6XN7K9RPQ2' : null,
      pairing_identity: kind === 'pair' ? {
        program: 'com.anthropic.claude-code', verification: 'Signed application',
        technical: 'com.anthropic.claude-code · Team 6XN7K9RPQ2', warning: null,
      } : null,
      replaces_existing_agent: kind === 'pair',
      inherited, http,
      temporary_access: kind === 'pair' ? null : { scope: post ? 'full' : 'read', duration_seconds: 900 },
    };
    db.queue = [req]; emit('amfa://queue-changed', db.queue.slice());
  };
}
