// Bridge to the Rust core. Inside Tauri (withGlobalTauri), calls go to real
// commands over the IPC. In a plain browser, a self-contained dev mock
// stands in so the UI is developable and reviewable standalone; the mock
// mirrors the command surface and its fixtures, but obviously
// enforces nothing (no Keychain, no daemon, no native OS authentication).

import type {
  ActivityEntry,
  AgentSummary,
  ApprovalRequest,
  CommandArgs,
  CommandName,
  CommandResult,
  ConnectionInput,
  ConnectionSummary,
  ConnectionType,
  EventMap,
  EventName,
  EventPayload,
  PermissionScope,
  SessionSummary,
  Settings,
  Unlisten,
} from './types';

const tauri = typeof window !== 'undefined' ? window.__TAURI__ : undefined;

/** Which window chrome to render, from the URL hash. */
export const mode = location.hash.replace('#', '') || 'window';

export async function invoke<K extends CommandName>(
  command: K,
  args?: CommandArgs<K>,
): Promise<CommandResult<K>> {
  if (tauri) {
    return tauri.core.invoke(
      command,
      args as Record<string, unknown> | undefined,
    ) as Promise<CommandResult<K>>;
  }
  return mockInvoke(command, (args ?? {}) as MockArgs) as Promise<CommandResult<K>>;
}

export async function listen<K extends EventName>(
  event: K,
  callback: (event: EventPayload<EventMap[K]>) => void,
): Promise<Unlisten> {
  if (tauri) {
    return tauri.event.listen(event, callback as (event: EventPayload<unknown>) => void);
  }
  return mockListen(event, callback);
}

/* ----------------------------- dev mock ---------------------------------- */

type MockListener = (event: EventPayload<unknown>) => void;
const listeners: Record<string, MockListener[]> = {};
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
const MOCK_AGENT_SETUP = 'Connect to the local AgentMFA broker. Read its current instructions with:\n\ncurl -fsS --unix-socket ~/.agentmfa/broker.sock http://localhost/instructions';
const MOCK_BROKER_INSTRUCTIONS = `# AgentMFA: broker instructions

AgentMFA holds this developer's secrets and brokers their use.
Transport: HTTP over the Unix domain socket \`~/.agentmfa/broker.sock\`.

## 1. Authenticate
Reuse a stored token via GET /v1/whoami, or POST /v1/pair when you must.

## 2. Discover
GET /v1/connections lists named destinations without exposing secrets.
`;
function emit<K extends EventName>(event: K, payload: EventMap[K]): void {
  (listeners[event] || []).forEach((callback) => callback({ event, payload }));
}
async function mockListen<K extends EventName>(
  event: K,
  callback: (event: EventPayload<EventMap[K]>) => void,
): Promise<Unlisten> {
  const eventListeners = listeners[event] ?? [];
  eventListeners.push(callback as MockListener);
  listeners[event] = eventListeners;
  return () => {};
}

// In-memory store mirroring the production fixtures.
let seq = 1;
const uid = () => `id-${seq++}`;
const now = () => new Date().toISOString();
const formError = (kind: string, code: string, field: string, message: string) =>
  ({ kind, code, field, message });

interface MockSecret {
  id: string;
  name: string;
  _value: string;
  created_at: string;
  updated_at: string;
}

interface MockConnection {
  id: string;
  name: string;
  type: ConnectionType;
  secret_names: string[];
  secret_ids: string[];
  destination?: string | null;
  host?: string | null;
  scheme?: string | null;
  port?: number | null;
  template?: string | null;
  dbname?: string | null;
  user?: string | null;
  host_key_fingerprint?: string | null;
  sslmode?: string | null;
  trusted_ca_bundle_path?: string | null;
  url?: string | null;
}

interface MockRule {
  id: string;
  client_id: string;
  agent: string;
  connection_id: string;
  scope: PermissionScope;
}

interface MockGrant {
  id: string;
  agent: string;
  connection_id: string;
  scope: PermissionScope;
  expires_at: string;
}

type MockAgent = Omit<AgentSummary, 'permission_count'>;

interface MockDatabase {
  secrets: MockSecret[];
  connections: MockConnection[];
  rules: MockRule[];
  grants: MockGrant[];
  agents: MockAgent[];
  sessions: SessionSummary[];
  activity: ActivityEntry[];
  settings: Settings;
  queue: ApprovalRequest[];
}

interface MockArgs {
  id: string | number;
  name: string;
  value: string;
  newName?: string | null;
  newValue?: string | null;
  input: ConnectionInput;
  limit: number;
  on: boolean;
  decision: 'deny' | 'allow_once' | 'allow_session' | 'always_allow';
  revokeInheritedRules?: boolean;
  source: string;
}

const db: MockDatabase = {
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
    { id: uid(), name: 'claude-code', program: 'com.anthropic.claude-code', verification: 'Signed application',
      identity: 'com.anthropic.claude-code · Team 6XN7K9RPQ2', paired_at: now(), last_used: now() },
  ],
  sessions: [],
  activity: [],
  settings: { reauth_on_read: true, menu_bar_hides_dock: false },
  queue: [],
};
function mkSecret(name: string, value: string): MockSecret {
  return { id: uid(), name, _value: value, created_at: now(), updated_at: now() };
}
seedConnections();
function seedConnections() {
  const by = (name: string) => db.secrets.find((secret) => secret.name === name)!.id;
  db.connections = [
    mkConn('github', 'api', ['GITHUB_API_KEY'], { host: 'api.github.com', scheme: 'https', template: 'Authorization: Bearer {{GITHUB_API_KEY}}' }),
    mkConn('prod-db', 'pg', ['DATABASE_PASSWORD'], { host: 'db.internal.aka.com', port: 5432, dbname: 'app_production', user: 'app', sslmode: 'verify-full', trusted_ca_bundle_path: null }),
    mkConn('market-feed', 'ws', ['STREAM_TOKEN'], { url: 'wss://stream.example.com/feed' }),
    mkConn('internal-api', 'api', ['SERVICE_USER', 'SERVICE_PASSWORD'], { host: 'internal.aka.com', scheme: 'https', template: 'Authorization: Basic {{base64(SERVICE_USER ":" SERVICE_PASSWORD)}}' }),
    mkConn('prod-ssh', 'ssh', ['DEPLOY_SSH_KEY'], {
      destination: 'prod', host: 'prod.example.com', port: 22, user: 'deploy',
      host_key_fingerprint: 'SHA256:vdZ5N8kNxU7J4W2WYa6qK0sJYv8oXb8s2H7n3jE5q1A',
    }),
  ];
  function mkConn(
    name: string,
    type: ConnectionType,
    secretNames: string[],
    config: Partial<MockConnection>,
  ): MockConnection {
    return {
      id: uid(),
      name,
      type,
      secret_names: secretNames,
      secret_ids: secretNames.map(by),
      ...config,
    };
  }
}
seedFixtures();
// Illustrative broker state so the standalone dev page exercises every layout
// affordance: ongoing access, temporary access, an open connection, and activity.
function seedFixtures() {
  db.rules.push({ id: uid(), client_id: db.agents[0].id, agent: 'claude-code', connection_id: db.connections[0].id, scope: 'full' });
  db.grants.push({ id: uid(), agent: 'claude-code', connection_id: db.connections[1].id,
    scope: 'full', expires_at: new Date(Date.now() + 11 * 60000).toISOString() });
  db.sessions.push({
    id: 1,
    type: 'ws',
    agent: 'claude-code',
    connection: 'market-feed',
    detail: 'wss://stream.example.com/feed',
    opened_at: now(),
  });
  // Spread across a day so the relative/absolute timestamp split is visible.
  const t = (minutes: number) => new Date(Date.now() - minutes * 60000).toISOString();
  const fixtures: Array<[keyof typeof MOCK_ACTIVITY_META, string, string | null, number]> = [
    ['denied', 'Denied: claude-code', 'POST api.github.com/repos/aka/aka/dispatches', 2],
    ['secretCopied', 'Secret copied: GITHUB_API_KEY', null, 6],
    ['sessionClosed', 'WebSocket session closed', 'market-feed', 14],
    ['sessionOpened', 'WebSocket session opened', 'market-feed', 35],
    ['autoAllowed', 'Used without asking: claude-code → github', null, 90],
    ['requested', 'claude-code requested github', 'GET api.github.com/user/repos', 180],
    ['sessionClosed', 'Postgres session closed', 'Ticket window elapsed', 400],
    ['sessionOpened', 'Postgres session opened', 'prod-db → app_production', 402],
    ['allowedOnce', 'Allowed this request: claude-code', 'Connect to Postgres → app@db.internal.aka.com:5432/app_production', 1500],
    ['paired', 'Agent connected: claude-code', null, 3000],
  ];
  fixtures.forEach(([kind, text, detail, minutes]) =>
    db.activity.push({ ...MOCK_ACTIVITY_META[kind], text, detail, at: t(minutes) }));
}
function audit(
  kind: keyof typeof MOCK_ACTIVITY_META,
  text: string,
  detail: string | null = null,
): ActivityEntry {
  const entry = { ...MOCK_ACTIVITY_META[kind], text, detail, at: new Date().toISOString() };
  db.activity.unshift(entry);
  db.activity.length = Math.min(db.activity.length, MOCK_ACTIVITY_LIMIT);
  return entry;
}
function connDto(c: MockConnection): ConnectionSummary {
  return {
    id: c.id, name: c.name, type: c.type, target: connTarget(c),
    secret_names: c.secret_names,
    permissions: [
      ...db.rules.filter((r) => r.connection_id === c.id).map((r) => ({ id: r.id, agent: r.agent, scope: r.scope, expires_at: null })),
      ...db.grants.filter((g) => g.connection_id === c.id).map((g) => ({ ...g })),
    ],
    host: c.host || null, scheme: c.scheme || null, port: c.port || null, template: c.template || null,
    dbname: c.dbname || null, user: c.user || null, host_key_fingerprint: c.host_key_fingerprint || null,
    destination: c.destination || null,
    sslmode: c.sslmode || null, url: c.url || null,
    trusted_ca_bundle_path: c.trusted_ca_bundle_path || null,
  };
}
function connTarget(c: MockConnection): string {
  if (c.type === 'api') {
    const scheme = c.scheme || 'https';
    const defaultPort = scheme === 'https' ? 443 : 80;
    return `${scheme}://${c.host}${c.port && c.port !== defaultPort ? `:${c.port}` : ''}`;
  }
  if (c.type === 'pg') return `${c.user}@${c.host}:${c.port}/${c.dbname}`;
  if (c.type === 'ssh') return c.port && c.port !== 22 ? `${c.user}@${c.host}:${c.port}` : `${c.user}@${c.host}`;
  return c.url ?? '';
}
function revealPrefix(value: string): string {
  const n = Math.min(6, Math.floor(value.length / 2));
  return n < value.length ? value.slice(0, n) + '…' : value;
}

async function mockInvoke(cmd: CommandName, args: MockArgs): Promise<unknown> {
  switch (cmd) {
    case 'list_secrets':
      return db.secrets.map((s) => {
        const names = db.connections.filter((c) => c.secret_names.includes(s.name)).map((c) => c.name);
        return { id: s.id, name: s.name, used_by: names.length, used_by_names: names, created_at: s.created_at, updated_at: s.updated_at };
      });
    case 'list_connections': return db.connections.map(connDto);
    case 'list_agents':
      return db.agents.map((a) => ({ ...a,
        permission_count: db.rules.filter((r) => r.client_id === a.id).length +
          db.grants.filter((g) => g.agent === a.name).length }));
    case 'list_sessions': return db.sessions.slice();
    case 'list_activity': return db.activity.slice(0, Math.min(args.limit ?? MOCK_ACTIVITY_LIMIT, MOCK_ACTIVITY_LIMIT));
    case 'clear_activity': db.activity = []; emit('amfa://activity-changed', {}); return;
    case 'get_queue': return db.queue.slice();
    case 'get_settings': return { ...db.settings };
    case 'get_agent_setup': return MOCK_AGENT_SETUP;
    case 'get_broker_instructions': return MOCK_BROKER_INSTRUCTIONS;
    case 'copy_agent_setup': return;
    case 'inspect_ssh_import':
      return {
        importId: 'mock-ssh-import', destination: 'prod', host: 'prod.example.com', port: 22,
        user: 'deploy', proxyJump: 'bastion', identityFiles: ['~/.ssh/deploy'],
        hostKeyCandidates: [{
          fingerprint: 'SHA256:vdZ5N8kNxU7J4W2WYa6qK0sJYv8oXb8s2H7n3jE5q1A',
          algorithm: 'ssh-ed25519', source: '~/.ssh/known_hosts',
        }],
        warnings: ['This destination connects through ProxyJump bastion.'],
      };
    case 'add_secret': {
      if (db.secrets.some((s) => s.name === args.name)) {
        throw formError('conflict', 'secret_name_taken', 'name', 'That credential name is already in use');
      }
      db.secrets.push(mkSecret(args.name, args.value)); audit('secretAdded', `Secret added: ${args.name}`); return;
    }
    case 'edit_secret': {
      const s = db.secrets.find((x) => x.id === args.id); if (!s) throw new Error('no such secret');
      if (args.newName && args.newName !== s.name) {
        const newName = args.newName;
        if (db.secrets.some((other) => other.id !== s.id && other.name === newName)) {
          throw formError('conflict', 'secret_name_taken', 'name', 'That credential name is already in use');
        }
        db.connections.forEach((c) => {
          const i = c.secret_names.indexOf(s.name); if (i !== -1) c.secret_names[i] = newName;
          if (c.template) c.template = c.template.split(s.name).join(newName);
        });
        s.name = newName;
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
      const entry = audit('secretCopied', `Secret copied: ${s.name}`);
      emit('amfa://activity-appended', entry);
      return;
    }
    case 'add_connection': {
      const i = args.input;
      if (i.type === 'ssh' && !/^SHA(?:256|512):\S+$/.test(i.host_key_fingerprint || '')) {
        throw formError('validation', 'invalid_connection_field', 'hostKeyFingerprint', 'Enter an OpenSSH SHA-256 or SHA-512 fingerprint');
      }
      if (db.connections.some((c) => c.name === i.name)) {
        throw formError('conflict', 'connection_name_taken', 'name', 'That service name is already in use');
      }
      if (i.new_secret_name && (i.new_secret_value || (i.ssh_import_id && i.identity_file))) {
        if (db.secrets.some((s) => s.name === i.new_secret_name)) {
          throw formError('conflict', 'secret_name_taken', 'newSecretName', 'That credential name is already in use');
        }
        const secret = mkSecret(i.new_secret_name, i.new_secret_value || '-----BEGIN OPENSSH PRIVATE KEY-----mock');
        db.secrets.push(secret);
        i.secret_id = secret.id;
      }
      const secret_names = i.type === 'api'
        ? ((i.template ?? '').match(/[A-Z_][A-Z0-9_]*/g) || [])
            .filter((n) => db.secrets.some((s) => s.name === n))
        : [db.secrets.find((s) => s.id === i.secret_id)?.name]
            .filter((name): name is string => Boolean(name));
      db.connections.push({ id: uid(), name: i.name, type: i.type, secret_names,
        secret_ids: i.secret_id ? [i.secret_id] : [],
        destination: i.destination, host: i.host, scheme: i.scheme, port: i.port, template: i.template, dbname: i.dbname, user: i.user,
        host_key_fingerprint: i.host_key_fingerprint, sslmode: i.sslmode,
        trusted_ca_bundle_path: i.trusted_ca_bundle_path, url: i.url });
      audit('connectionAdded', `Service added: ${i.name}`); return;
    }
    case 'edit_connection': {
      const c = db.connections.find((x) => x.id === args.id); if (!c) throw new Error('no such connection');
      const i = args.input;
      if (i.type === 'ssh' && !/^SHA(?:256|512):\S+$/.test(i.host_key_fingerprint || '')) {
        throw formError('validation', 'invalid_connection_field', 'hostKeyFingerprint', 'Enter an OpenSSH SHA-256 or SHA-512 fingerprint');
      }
      if (db.connections.some((other) => other.id !== c.id && other.name === i.name)) {
        throw formError('conflict', 'connection_name_taken', 'name', 'That service name is already in use');
      }
      Object.assign(c, { name: i.name, host: i.host, scheme: i.scheme, port: i.port,
        destination: i.destination,
        dbname: i.dbname, user: i.user, sslmode: i.sslmode, trusted_ca_bundle_path: i.trusted_ca_bundle_path,
        host_key_fingerprint: i.host_key_fingerprint, url: i.url,
        template: i.template });
      if (i.secret_id) {
        c.secret_names = [db.secrets.find((s) => s.id === i.secret_id)?.name]
          .filter((name): name is string => Boolean(name));
      }
      audit('connectionUpdated', `Service updated: ${i.name}`); return;
    }
    case 'delete_connection': {
      const c = db.connections.find((x) => x.id === args.id); if (!c) throw new Error('no such connection');
      db.connections = db.connections.filter((x) => x.id !== args.id);
      db.rules = db.rules.filter((r) => r.connection_id !== args.id); audit('connectionDeleted', `Service deleted: ${c.name}`); return;
    }
    case 'remove_permission': {
      const standing = db.rules.some((permission) => permission.id === args.id);
      db.rules = db.rules.filter((permission) => permission.id !== args.id);
      db.grants = db.grants.filter((permission) => permission.id !== args.id);
      audit(standing ? 'ruleRemoved' : 'grantRevoked', standing ? 'Approval required again' : 'Temporary access ended');
      return true;
    }
    case 'revoke_agent':
      { const agent = db.agents.find((a) => a.id === args.id); if (!agent) return false;
      db.agents = db.agents.filter((a) => a.id !== args.id);
      db.grants = db.grants.filter((g) => g.agent !== agent.name);
      db.rules = db.rules.filter((r) => r.client_id !== agent.id);
      db.sessions = db.sessions.filter((s) => s.agent !== agent.name);
      audit('tokenRevoked', `Agent disconnected: ${agent.name}`); }
      emit('amfa://agents-changed', {});
      emit('amfa://sessions-changed', {});
      return true;
    case 'close_session': db.sessions = db.sessions.filter((s) => s.id !== args.id); emit('amfa://sessions-changed', {}); return true;
    case 'set_reauth_on_read': db.settings.reauth_on_read = args.on; return;
    case 'set_menu_bar_hides_dock':
      db.settings.menu_bar_hides_dock = args.on;
      return;
    case 'decide': {
      const req = db.queue.find((r) => r.id === args.id);
      if (req && req.kind === 'pair' && args.revokeInheritedRules) {
        const client = db.agents.find((agent) => agent.name === req.agent);
        db.rules = db.rules.filter((r) => !client || r.client_id !== client.id);
        audit('ruleRemoved', `Approval required again: ${req.agent}`);
      }
      if (req && req.kind === 'pair' && args.decision === 'allow_once' && req.pairing_identity) {
        db.grants = db.grants.filter((g) => g.agent !== req.agent);
        db.sessions = db.sessions.filter((s) => s.agent !== req.agent);
        const existing = db.agents.find((agent) => agent.name === req.agent);
        if (existing) {
          existing.paired_at = now();
          existing.last_used = existing.paired_at;
        } else {
          db.agents.push({
            id: uid(),
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
      if (req && args.decision === 'allow_session' && req.connection && req.temporary_access) {
        const connection = req.connection;
        const temporaryAccess = req.temporary_access;
        db.grants = db.grants.filter((g) =>
          !(g.agent === req.agent && g.connection_id === connection.id));
        db.grants.push({ id: uid(), agent: req.agent, connection_id: connection.id,
          scope: temporaryAccess.scope,
          expires_at: new Date(Date.now() + temporaryAccess.duration_seconds * 1000).toISOString() });
      }
      if (req && args.decision === 'always_allow' && req.connection && req.temporary_access) {
        const connection = req.connection;
        const client = db.agents.find((agent) => agent.name === req.agent);
        if (client) {
          db.rules = db.rules.filter((permission) =>
            permission.client_id !== client.id || permission.connection_id !== connection.id);
          db.rules.push({ id: uid(), client_id: client.id, agent: req.agent,
            connection_id: connection.id, scope: req.temporary_access.scope });
        }
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
      ? db.rules.filter((r) => r.client_id === db.agents[0]?.id).flatMap((r) => {
          const c = db.connections.find((conn) => conn.id === r.connection_id);
          return c ? [{ name: c.name, type: c.type, target: connTarget(c) }] : [];
        })
      : [];
    const post = kind === 'post';
    const body = post ? JSON.stringify({ event_type: 'deploy', client_payload: { ref: 'main', sha: 'a1b2c3d', env: 'production', requested_by: 'claude-code' } }, null, 2) : null;
    const http: ApprovalRequest['http'] = kind === 'pair' ? null : {
      method: post ? 'POST' : 'GET',
      path: post ? '/repos/aka/aka/dispatches' : '/user/repos',
      headers: post
        ? [['Accept', 'application/vnd.github+json'], ['Content-Type', 'application/json'], ['X-GitHub-Api-Version', '2022-11-28'], ['User-Agent', 'claude-code/1.0'], ['X-Request-Id', 'req-8f31d2c4'], ['Accept-Encoding', 'gzip, deflate, br'], ['Connection', 'keep-alive'], ['Idempotency-Key', 'dispatch-20260708-01']]
        : [['Accept', 'application/vnd.github+json']],
      body_preview: body, body_len: body ? body.length : 0, body_truncated: false, mutating: post,
    };
    const firstConnection = db.connections[0]!;
    const req: ApprovalRequest = {
      id: uid(), agent: 'claude-code', kind: kind === 'pair' ? 'pair' : 'http',
      connection: kind === 'pair' ? null : { id: firstConnection.id, name: 'github', type: 'api', target: 'api.github.com' },
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
