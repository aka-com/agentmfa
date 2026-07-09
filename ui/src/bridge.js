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
  agents: [
    { name: 'claude-code', identity: 'com.anthropic.claude-code · Team 6XN7K9RPQ2',
      token_preview: 'amfa_7f3a9…', paired_at: now(), rule_count: 0 },
  ],
  sessions: [],
  activity: [],
  settings: { icloud_sync: true, reauth_on_read: true, hide_secret_prefixes: true, pg_trusted_ca_bundle_path: null, menu_bar_hides_dock: false },
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
// affordance: an auto-allow rule, a live session, and a run of activity.
function seedFixtures() {
  db.rules.push({ id: uid(), agent: 'claude-code', connection_id: db.connections[0].id });
  db.sessions.push({ id: 1, type: 'ws', agent: 'claude-code', connection: 'market-feed', detail: 'wss://stream.example.com/feed' });
  // Spread across a day so the relative/absolute timestamp split is visible.
  const t = (min) => new Date(Date.now() - min * 60000).toISOString();
  [
    ['⛔', 'Denied: claude-code', 'POST api.github.com/repos/aka/aka/dispatches', 2],
    ['📋', 'Secret copied: GITHUB_API_KEY', null, 6],
    ['📤', 'WebSocket bridge closed', 'market-feed', 14],
    ['📥', 'WebSocket bridge opened', 'market-feed', 35],
    ['⚡', 'Auto-approved: claude-code → github', null, 90],
    ['📨', 'claude-code requested github', 'GET api.github.com/user/repos', 180],
    ['📤', 'Postgres session closed', 'Ticket window elapsed', 400],
    ['📥', 'Postgres session opened', 'prod-db → app_production', 402],
    ['✅', 'Allowed once: claude-code', 'Open Postgres session → app@db.internal.aka.com:5432/app_production', 1500],
    ['🔗', 'Agent paired: claude-code', null, 3000],
  ].forEach(([icon, text, detail, min]) =>
    db.activity.push({ icon, text, detail: detail || null, at: t(min) }));
}
function audit(icon, text, detail) {
  db.activity.unshift({ icon, text, detail: detail || null, at: new Date().toISOString() });
  db.activity.length = Math.min(db.activity.length, MOCK_ACTIVITY_LIMIT);
}
function connDto(c) {
  return {
    id: c.id, name: c.name, type: c.type, target: connTarget(c),
    secret_names: c.secret_names, multi_connect: c.multi_connect,
    rules: db.rules.filter((r) => r.connection_id === c.id).map((r) => ({ id: r.id, agent: r.agent })),
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
      return db.agents.map((a) => ({ ...a, rule_count: db.rules.filter((r) => r.agent === a.name).length }));
    case 'list_sessions': return db.sessions.slice();
    case 'list_activity': return db.activity.slice(0, Math.min(args.limit ?? MOCK_ACTIVITY_LIMIT, MOCK_ACTIVITY_LIMIT));
    case 'get_queue': return db.queue.slice();
    case 'get_settings': return { ...db.settings };
    case 'add_secret': {
      if (db.secrets.some((s) => s.name === args.name)) throw new Error(`A secret named ${args.name} already exists`);
      db.secrets.push(mkSecret(args.name, args.value)); audit('➕', `Secret added: ${args.name}`); return;
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
      s.updated_at = now(); audit('✏️', `Secret updated: ${s.name}`); return;
    }
    case 'delete_secret': {
      const s = db.secrets.find((x) => x.id === args.id); if (!s) throw new Error('no such secret');
      const users = db.connections.filter((c) => c.secret_names.includes(s.name)).map((c) => c.name);
      if (users.length) throw new Error(`in use by ${users.join(', ')}`);
      db.secrets = db.secrets.filter((x) => x.id !== args.id); audit('🗑', `Secret deleted: ${s.name}`); return;
    }
    case 'reveal_secret_prefix': {
      const s = db.secrets.find((x) => x.id === args.id); if (!s) throw new Error('no such secret');
      audit('👁', `Secret prefix revealed: ${s.name}`); return revealPrefix(s._value);
    }
    case 'copy_secret': {
      const s = db.secrets.find((x) => x.id === args.id); if (!s) throw new Error('no such secret');
      audit('📋', `Secret copied: ${s.name}`); emit('amfa://activity-appended', {}); return;
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
      audit('🔌', `Connection added: ${i.name}`); return;
    }
    case 'edit_connection': {
      const c = db.connections.find((x) => x.id === args.id); if (!c) throw new Error('no such connection');
      const i = args.input;
      if (i.type === 'ssh' && i.multi_connect === false) throw new Error('ssh connections must allow multiple agent connections per approval');
      if (i.type === 'ssh' && !i.host_key_fingerprint) throw new Error('SSH host key fingerprint is required');
      Object.assign(c, { name: i.name, host: i.host, port: i.port, dbname: i.dbname, user: i.user,
        host_key_fingerprint: i.host_key_fingerprint, url: i.url, template: i.template, multi_connect: i.multi_connect });
      if (i.secret_id) c.secret_names = [db.secrets.find((s) => s.id === i.secret_id)?.name].filter(Boolean);
      audit('✏️', `Connection updated: ${i.name}`); return;
    }
    case 'delete_connection': {
      const c = db.connections.find((x) => x.id === args.id); if (!c) throw new Error('no such connection');
      db.connections = db.connections.filter((x) => x.id !== args.id);
      db.rules = db.rules.filter((r) => r.connection_id !== args.id); audit('🗑', `Connection deleted: ${c.name}`); return;
    }
    case 'remove_rule': db.rules = db.rules.filter((r) => r.id !== args.id); audit('🗑', 'Auto-allow removed'); return true;
    case 'revoke_agent': db.agents = db.agents.filter((a) => a.name !== args.name); audit('🔒', `Pair token revoked: ${args.name}`); return true;
    case 'close_session': db.sessions = db.sessions.filter((s) => s.id !== args.id); emit('amfa://sessions-changed', {}); return true;
    case 'set_icloud_sync': db.settings.icloud_sync = args.on; return db.secrets.length;
    case 'set_reauth_on_read': db.settings.reauth_on_read = args.on; return;
    case 'set_hide_secret_prefixes':
      db.settings.hide_secret_prefixes = args.on;
      audit('⚙', `Secret prefixes ${args.on ? 'hidden' : 'shown'} in the secrets list`);
      return;
    case 'set_menu_bar_hides_dock':
      db.settings.menu_bar_hides_dock = args.on;
      audit('⚙', `Dock icon ${args.on ? 'hidden' : 'kept'} when minimized to the menu bar`);
      return;
    case 'set_pg_trusted_ca_bundle_path': {
      const path = (args.path || '').trim();
      db.settings.pg_trusted_ca_bundle_path = path || null;
      audit('⚙', path ? 'Postgres trusted CA bundle saved' : 'Postgres trusted CA bundle cleared');
      return;
    }
    case 'decide': {
      const req = db.queue.find((r) => r.id === args.id);
      if (req && req.kind === 'pair' && args.revokeInheritedRules) {
        db.rules = db.rules.filter((r) => r.agent !== req.agent);
        audit('🗑', `Auto-allow permissions revoked: ${req.agent}`);
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
      connection: kind === 'pair' ? null : { name: 'github', type: 'api', target: 'api.github.com', multi_connect: false },
      action: kind === 'pair' ? 'Pair new agent “claude-code”'
        : post ? 'POST api.github.com/repos/aka/aka/dispatches' : 'GET api.github.com/user/repos',
      notification: 'claude-code wants to use github: GET /user/repos',
      received_at: now(), deadline: new Date(Date.now() + ttlMs).toISOString(),
      identity: kind === 'pair' ? 'com.anthropic.claude-code · Team 6XN7K9RPQ2' : null,
      inherited, http,
    };
    db.queue = [req]; emit('amfa://queue-changed', db.queue.slice());
  };
}
