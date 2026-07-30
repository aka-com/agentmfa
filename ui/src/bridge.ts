// Bridge to the Rust core. Inside Tauri (withGlobalTauri), calls go to real
// commands over the IPC. In a plain browser, a self-contained dev mock
// stands in so the UI is developable and reviewable standalone; the mock
// mirrors the command surface and its fixtures, but obviously
// enforces nothing (no Keychain, no daemon, no native OS authentication).

import type {
  ActivityEntry,
  Approval,
  ApprovalDecision,
  CommandArgs,
  CommandName,
  CommandResult,
  ConnectionInput,
  ConnectionSummary,
  ConnectionType,
  ElicitationRequest,
  EventMap,
  EventName,
  EventPayload,
  McpAuthDraft,
  McpAuthState,
  McpStatusReport,
  NotificationSettings,
  RequestRecord,
  SessionSummary,
  Settings,
  Unlisten,
} from './types';
import { sshInvocationCommand } from './getting-started';

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
// Mirrors the broker's ACTIVITY_VIEW_LIMIT so the mock caps a view read where
// the real command surface does.
const MOCK_ACTIVITY_LIMIT = 500;
/** The demo's answer for a passphrase-protected key import. */
const MOCK_KEY_PASSPHRASE = 'correct horse';

// The demo endpoint credential: fixed so a get_endpoint read-back
// reproduces exactly what issuance showed.
const MOCK_ENDPOINT_SECRET = 'end_' + 'demo0'.repeat(12) + '0000';
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
  connectionAdded: { icon: 'plug', tone: 'neutral' },
  connectionUpdated: { icon: 'pencil', tone: 'neutral' },
  connectionDeleted: { icon: 'unplug', tone: 'neutral' },
  wired: { icon: 'plug', tone: 'neutral' },
  unwired: { icon: 'unplug', tone: 'neutral' },
  tokenRevoked: { icon: 'unplug', tone: 'danger' },
  inputProvided: { icon: 'circleCheck', tone: 'success' },
  inputRefused: { icon: 'circleX', tone: 'danger' },
  approvalRequested: { icon: 'bell', tone: 'warning' },
  approvalTimeout: { icon: 'clockAlert', tone: 'danger' },
};
const MOCK_AGENT_SETUP = [
  'Connect to the local AgentMFA broker. Read its current instructions, then list the available connections:',
  '',
  'curl -fsS --unix-socket ~/.aka/broker.sock \\',
  '  -H "Authorization: Bearer $(cat ~/.aka/token)" \\',
  '  http://localhost/instructions',
].join('\n');
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
const formError = (
  kind: string,
  code: string,
  field: string | null,
  message: string,
  detail?: string,
) => ({
  kind, code, ...(field ? { field } : {}), message, ...(detail ? { detail } : {}),
});

/** Standalone-browser fault injection. Examples:
 * `?mockFault=locked_vault`, `partial_load`, `dead_local`,
 * `keychain_unavailable`, or `denied_presence`. */
function mockFault(name: string): boolean {
  if (typeof location === 'undefined') return false;
  return (new URLSearchParams(location.search).get('mockFault') ?? '')
    .split(',')
    .includes(name);
}

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
  oauth?: boolean;
  destination?: string | null;
  host?: string | null;
  scheme?: string | null;
  mcp_path?: string | null;
  account?: string | null;
  port?: number | null;
  template?: string | null;
  dbname?: string | null;
  user?: string | null;
  host_key_fingerprint?: string | null;
  sslmode?: string | null;
  trusted_ca_bundle_path?: string | null;
  url?: string | null;
  oauth_spec?: { auth_url: string; token_url: string; client_id: string; scopes: string[] } | null;
}

/** Per-connection agent access; a missing record means the default
 * (enabled, all tools). */
interface MockAccess {
  connection_id: string;
  enabled: boolean;
  confirm?: boolean;
  /** RFC 3339 end of an open approval window, when one is running. */
  confirm_window_until?: string | null;
  /** The agents those windows cover; approvals are scoped per agent. */
  confirm_window_agents?: string[];
  /** RFC 3339 end of a denial's cooldown, while retries are auto-refused. */
  confirm_cooldown_until?: string | null;
  allowed_tools?: string[];
  endpoint?: {
    endpoint_id: string;
    type: ConnectionType;
    dsn?: string | null;
    /**
     * An SSH endpoint's agent socket, held back from the chip the way the real
     * broker holds it back from `connection_dto`: its filename comes from the
     * endpoint secret, so naming it requires the vault. `get_endpoint` returns
     * it; the connection list does not.
     */
    sshDsn?: string;
  };
}

interface MockIdentity {
  client_id: string;
  token_path: string;
  socket_path: string;
  minted_at: string;
  last_used: string;
  legacy_aliases: number;
}

interface MockDatabase {
  secrets: MockSecret[];
  connections: MockConnection[];
  access: MockAccess[];
  identity: MockIdentity;
  sessions: SessionSummary[];
  activity: ActivityEntry[];
  elicitations: ElicitationRequest[];
  approvals: Approval[];
  requests: RequestRecord[];
  settings: Settings;
}

interface MockArgs {
  id: string | number;
  name: string;
  value: string;
  input2?: never;
  url?: string;
  options?: { whoami_tool?: string | null } | null;
  newName?: string | null;
  newValue?: string | null;
  input: ConnectionInput & Partial<McpAuthDraft>;
  limit: number;
  on: boolean;
  secs: number;
  connectionId: string;
  enabled: boolean;
  decision?: ApprovalDecision;
  tools?: string[] | null;
  clientSecret?: string | null;
  token?: string | null;
  source: string;
  host: string;
  port: number;
  approved: boolean;
  values?: Record<string, string>;
  endpointId?: string;
  orderedIds?: string[];
  settings: NotificationSettings;
}

const db: MockDatabase = {
  secrets: [
    mkSecret('GITHUB_API_KEY', 'ghp_9aXf2Qe7LmNoP3demoToken41c'),
    mkSecret('DATABASE_PASSWORD', 'pg-s3cr3t-demo-pw'),
    mkSecret('STREAM_TOKEN', 'wss-tok-8f31d2-demo'),
    mkSecret('SERVICE_USER', 'svc-agent-ci'),
    mkSecret('SERVICE_PASSWORD', 'basic-pw-demo-8841'),
    mkSecret('DEPLOY_SSH_KEY', '-----BEGIN OPENSSH PRIVATE KEY-----demo'),
    mkSecret('NOTION_MCP_TOKEN', 'ntn_demo_2f81c4a9b3e7'),
  ],
  connections: [],
  access: [],
  identity: {
    client_id: uid(),
    token_path: '~/.aka/token',
    socket_path: '~/.aka/broker.sock',
    minted_at: now(),
    last_used: now(),
    legacy_aliases: 0,
  },
  sessions: [],
  activity: [],
  elicitations: [],
  approvals: [],
  requests: [],
  settings: {
    reauth_on_read: true,
    menu_bar_hides_dock: false,
    presence_window_secs: 15 * 60,
  },
};
function mkSecret(name: string, value: string): MockSecret {
  return { id: uid(), name, _value: value, created_at: now(), updated_at: now() };
}
seedConnections();
function seedConnections() {
  // A fixture naming a secret that was never seeded used to throw here and
  // leave the whole frontend-only mode on a blank page. Say what is wrong.
  const by = (name: string): string => {
    const secret = db.secrets.find((candidate) => candidate.name === name);
    if (!secret) {
      throw new Error(`dev fixture references an unseeded secret: ${name}`);
    }
    return secret.id;
  };
  db.connections = [
    mkConn('github', 'api', ['GITHUB_API_KEY'], { host: 'api.github.com', scheme: 'https', template: 'Authorization: Bearer {{GITHUB_API_KEY}}' }),
    // An MCP server, so the catalog's MCP row has something under it in
    // frontend-only mode.
    mkConn('notion', 'api', ['NOTION_MCP_TOKEN'], {
      host: 'mcp.notion.com',
      scheme: 'https',
      template: 'Authorization: Bearer {{NOTION_MCP_TOKEN}}',
      mcp_path: '/mcp',
      account: 'Raymond (raymond@aka.com)',
      oauth: true,
    }),
    mkConn('prod-db', 'pg', ['DATABASE_PASSWORD'], { host: 'db.internal.aka.com', port: 5432, dbname: 'app_production', user: 'app', sslmode: 'verify-full', trusted_ca_bundle_path: null }),
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
  // Connections are enabled by default; record the two switched-off ones so
  // the standalone dev page shows both states.
  const disable = (i: number) =>
    db.access.push({ connection_id: db.connections[i].id, enabled: false });
  disable(3); // market-feed
  disable(4); // internal-api
  db.sessions.push({
    id: 1,
    type: 'pg',
    agent: 'claude-code',
    connection: 'prod-db',
    detail: 'app@db.internal.aka.com:5432/app_production',
    opened_at: now(),
  });
  // Spread across a day so the relative/absolute timestamp split is visible.
  const t = (minutes: number) => new Date(Date.now() - minutes * 60000).toISOString();
  const fixtures: Array<[keyof typeof MOCK_ACTIVITY_META, string, string | null, number, string | null]> = [
    ['denied', 'Denied: claude-code', 'POST api.github.com/repos/aka/aka/dispatches', 2, 'claude-code'],
    ['secretCopied', 'Secret copied: GITHUB_API_KEY', null, 6, null],
    ['sessionClosed', 'SSH session closed', 'prod-ssh', 14, 'claude-code'],
    ['sessionOpened', 'SSH session opened', 'prod-ssh', 35, 'claude-code'],
    ['autoAllowed', 'Used without asking: claude-code → github', null, 90, 'claude-code'],
    ['requested', 'codex requested github', 'GET api.github.com/user/repos', 180, 'codex'],
    ['sessionClosed', 'Postgres session closed', 'Ticket window elapsed', 400, 'deploy-script'],
    ['sessionOpened', 'Postgres session opened', 'prod-db → app_production', 402, 'deploy-script'],
    ['allowedOnce', 'Allowed this request: claude-code', 'Connect to Postgres → app@db.internal.aka.com:5432/app_production', 1500, 'claude-code'],
    ['paired', 'Agent connected: claude-code', null, 3000, 'claude-code'],
  ];
  fixtures.forEach(([kind, text, detail, minutes, agent]) =>
    db.activity.push({ ...MOCK_ACTIVITY_META[kind], text, detail, agent, at: t(minutes) }));
  // Mock fixture for a real SEP-2322 tool call paused on user input. It keeps
  // the trusted-UI answering flow usable in standalone browser development.
  const elicitation: ElicitationRequest = {
    id: uid(),
    agent: 'claude-code',
    connection: 'notion',
    tool: 'agentmfa_notion_search',
    prompt: 'Notion needs to know where to search: which workspace should this query run against?',
    fields: [{ name: 'workspace', label: 'Workspace' }],
    requested_at: t(1),
    expires_at: new Date(Date.now() + 9 * 60000).toISOString(),
  };
  db.elicitations.push(elicitation);
  db.requests.push({
    id: elicitation.id,
    kind: 'elicitation',
    status: 'pending',
    connection: elicitation.connection,
    agent: elicitation.agent,
    summary: elicitation.prompt,
    detail: elicitation.tool,
    waiting: 1,
    requested_at: elicitation.requested_at,
    expires_at: elicitation.expires_at,
  });
  // A second form whose schema reads as credential-shaped, so the warning
  // banner is designable. The field is a *label* — the exact false positive
  // the scan cannot rule out — which is why the form still works.
  db.elicitations.push({
    id: uid(),
    agent: 'claude-code',
    connection: 'notion',
    tool: 'agentmfa_notion_connect',
    prompt: 'Which stored credential should this integration use?',
    fields: [{ name: 'client_secret_name', label: 'Credential name' }],
    credential_warning: true,
    requested_at: t(1),
    expires_at: new Date(Date.now() + 8 * 60000).toISOString(),
  });
  // One tool with traffic confirmation on, and a call parked on it, so the
  // switch and the prompt are both designable standalone.
  const github = db.connections.find((c) => c.name === 'github');
  if (github) {
    db.access.push({ connection_id: github.id, enabled: true, confirm: true });
    const approval: Approval = {
      id: uid(),
      connection_id: github.id,
      connection: github.name,
      type: github.type,
      target: connTarget(github),
      agent: 'claude-code',
      summary: 'POST /repos/aka/aka/issues',
      detail: '{"title":"Flaky test in pg_proxy","labels":["bug"]}',
      waiting: 1,
      requested_at: new Date(Date.now() - 8000).toISOString(),
      expires_at: new Date(Date.now() + 82 * 1000).toISOString(),
      window_secs: 15 * 60,
    };
    db.approvals.push(approval);
    db.requests.push({
      id: approval.id,
      kind: 'approval',
      status: 'pending',
      connection_id: approval.connection_id,
      connection: approval.connection,
      connection_type: approval.type,
      unit: approval.unit,
      target: approval.target,
      agent: approval.agent,
      summary: approval.summary,
      detail: approval.detail,
      waiting: approval.waiting,
      requested_at: approval.requested_at,
      expires_at: approval.expires_at,
      window_secs: approval.window_secs,
    });
  }
  // And a Postgres one, because its prompt is the shape with a consequence
  // line: one approval carries the whole session, so the sheet has to say
  // so and the amber block has to be designable without a live broker.
  const prodDb = db.connections.find((c) => c.name === 'prod-db');
  if (prodDb) {
    db.access.push({ connection_id: prodDb.id, enabled: true, confirm: true });
    const approval: Approval = {
      id: uid(),
      connection_id: prodDb.id,
      connection: prodDb.name,
      type: prodDb.type,
      unit: 'session',
      target: connTarget(prodDb),
      agent: 'deploy-script',
      summary: 'New Postgres session',
      detail: 'psql · user=app',
      consequence:
        'Grants full SQL access for the whole session — reads, writes, schema changes, and '
        + 'anything else the role may do. Postgres is confirmed once per session, not per statement.',
      waiting: 1,
      requested_at: new Date(Date.now() - 4000).toISOString(),
      expires_at: new Date(Date.now() + 86 * 1000).toISOString(),
      window_secs: 15 * 60,
    };
    db.approvals.push(approval);
  }
  // And an SSH one. Its consequence line is the blunt case: the gate is per
  // login, and everything the login goes on to do is out of reach.
  const prodSsh = db.connections.find((c) => c.name === 'prod-ssh');
  if (prodSsh) {
    db.access.push({ connection_id: prodSsh.id, enabled: true, confirm: true });
    db.approvals.push({
      id: uid(),
      connection_id: prodSsh.id,
      connection: prodSsh.name,
      type: prodSsh.type,
      unit: 'login',
      target: connTarget(prodSsh),
      agent: 'claude-code',
      summary: `SSH login as ${connTarget(prodSsh)}`,
      detail: 'host key SHA256:t3kZ0h1Qm7pXvB2nR8sLdY4wJcF6aGuE9oNbT5iKxWs',
      consequence:
        'Approving signs one SSH login. What runs afterwards is between the client and the '
        + 'host: AgentMFA is not in that connection, so it cannot see the commands, time the '
        + 'session out, or close it.',
      waiting: 1,
      requested_at: new Date(Date.now() - 2000).toISOString(),
      expires_at: new Date(Date.now() + 88 * 1000).toISOString(),
      window_secs: 15 * 60,
    });
  }
  db.requests.push(
    {
      id: uid(),
      kind: 'approval',
      status: 'approved',
      connection: 'prod-db',
      connection_type: 'pg',
      unit: 'session',
      target: 'app@db.internal.aka.com:5432/app_production',
      agent: 'deploy-script',
      summary: 'New Postgres session',
      waiting: 1,
      requested_at: t(18),
      resolved_at: t(17),
      resolution: 'approved_for_window',
      window_secs: 15 * 60,
    },
    {
      id: uid(),
      kind: 'approval',
      status: 'denied',
      connection: 'github',
      connection_type: 'api',
      unit: 'request',
      target: 'https://api.github.com',
      agent: 'codex',
      summary: 'DELETE /repos/aka/obsolete',
      waiting: 1,
      requested_at: t(43),
      resolved_at: t(42),
      resolution: 'denied',
      window_secs: 15 * 60,
    },
    {
      id: uid(),
      kind: 'elicitation',
      status: 'expired',
      connection: 'notion',
      agent: 'claude-code',
      summary: 'Which workspace should this query use?',
      detail: 'agentmfa_notion_search',
      waiting: 1,
      requested_at: t(91),
      resolved_at: t(81),
      resolution: 'timed_out',
    },
  );
}
function audit(
  kind: keyof typeof MOCK_ACTIVITY_META,
  text: string,
  detail: string | null = null,
  attribution: Pick<ActivityEntry, 'agent' | 'connection' | 'duration_ms'> = {},
): ActivityEntry {
  const entry = {
    ...MOCK_ACTIVITY_META[kind], text, detail, ...attribution, at: new Date().toISOString(),
  };
  db.activity.unshift(entry);
  db.activity.length = Math.min(db.activity.length, MOCK_ACTIVITY_LIMIT);
  return entry;
}

function resolveMockRequest(
  id: string,
  status: RequestRecord['status'],
  resolution: string,
): void {
  const request = db.requests.find((candidate) => candidate.id === id);
  if (!request || request.status !== 'pending') return;
  request.status = status;
  request.resolution = resolution;
  request.resolved_at = now();
}
function connDto(c: MockConnection): ConnectionSummary {
  return {
    id: c.id, name: c.name, type: c.type, target: connTarget(c),
    secret_names: c.secret_names,
    oauth: c.oauth ?? false,
    agent_access: (() => {
      const record = db.access.find((a) => a.connection_id === c.id);
      return {
        enabled: record?.enabled ?? true,
        confirm: record?.confirm ?? false,
        confirm_window_until: record?.confirm_window_until ?? null,
        confirm_window_agents: record?.confirm_window_agents ?? [],
        confirm_cooldown_until: record?.confirm_cooldown_until ?? null,
        allowed_tools: record?.allowed_tools ?? null,
        // `sshDsn` is deliberately dropped: the chip is what a connection
        // listing carries, and an SSH endpoint's socket path is not in it.
        endpoint: record?.endpoint
          ? {
              endpoint_id: record.endpoint.endpoint_id,
              type: record.endpoint.type,
              dsn: record.endpoint.dsn ?? null,
            }
          : null,
      };
    })(),
    host: c.host || null, scheme: c.scheme || null, port: c.port || null, template: c.template || null,
    mcp_path: c.mcp_path || null, account: c.account || null, oauth_spec: c.oauth_spec || null,
    dbname: c.dbname || null, user: c.user || null, host_key_fingerprint: c.host_key_fingerprint || null,
    destination: c.destination || null,
    sslmode: c.sslmode || null,
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

/* --------------------------- mock MCP sign-in ----------------------------- */
// A timer-driven walk through every phase of the broker's OAuth state
// machine so the standalone dev page exercises the whole auth UI. Names
// ending in "-fail" exercise the failure state.
interface MockAuthSession {
  state: McpAuthState;
  draft: McpAuthDraft;
  timers: Array<ReturnType<typeof setTimeout>>;
}
const mockAuthSessions: Record<string, MockAuthSession> = {};

function mockAuthSet(session: MockAuthSession, phase: Partial<McpAuthState>): void {
  session.state = {
    ...session.state, ...phase, updated_at: new Date().toISOString(),
  } as McpAuthState;
  emit('aka://mcp-auth-changed', session.state);
}

function mockAuthFinish(session: MockAuthSession): void {
  const draft = session.draft;
  const account = 'Raymond (raymond@aka.com)';
  if (draft.reauth_connection_id) {
    const conn = db.connections.find((c) => c.id === draft.reauth_connection_id);
    if (!conn) {
      mockAuthSet(session, { phase: 'failed', message: 'connection disappeared' } as McpAuthState);
      return;
    }
    conn.account = account;
    audit('connectionUpdated', `MCP sign-in completed: ${conn.name}`, `Connected as ${account}`);
    emit('aka://connections-changed', {});
    mockAuthSet(session, {
      phase: 'succeeded', connection_id: conn.id, connection_name: conn.name,
      account, expires_in: 28800,
    } as McpAuthState);
    return;
  }
  const conn: MockConnection = {
    id: uid(), name: draft.name, type: 'api',
    secret_names: [], secret_ids: [], oauth: true,
    host: draft.host, scheme: draft.scheme, port: draft.port ?? null,
    template: '',
    mcp_path: draft.mcp_path, account,
  };
  db.connections.push(conn);
  audit('connectionAdded', `Tool added: ${conn.name}`, `Connected as ${account}`);
  emit('aka://connections-changed', {});
  mockAuthSet(session, {
    phase: 'succeeded', connection_id: conn.id, connection_name: conn.name,
    account, expires_in: 28800,
  } as McpAuthState);
}

function mockStartAuth(draft: McpAuthDraft): McpAuthState {
  const id = uid();
  const session: MockAuthSession = {
    draft,
    timers: [],
    state: {
      id, name: draft.name,
      target: `${draft.scheme}://${draft.host}${draft.port ? `:${draft.port}` : ''}${draft.mcp_path}`,
      phase: 'probing', updated_at: new Date().toISOString(),
    },
  };
  mockAuthSessions[id] = session;
  const at = (ms: number, run: () => void): void => { session.timers.push(setTimeout(run, ms)); };
  at(350, () => mockAuthSet(session, { phase: 'discovering' } as McpAuthState));
  at(800, () => mockAuthSet(session, { phase: 'registering' } as McpAuthState));
  at(1250, () => mockAuthSet(session, {
    phase: 'awaiting_authorization',
    authorization_url: `https://auth.${draft.host}/authorize?client_id=mock&state=demo`,
  } as McpAuthState));
  if (/-fail$/.test(draft.name)) {
    at(2800, () => mockAuthSet(session, {
      phase: 'failed',
      message: 'The authorization server does not offer automatic client registration',
      hint: 'Add this server with a token instead.',
    } as McpAuthState));
    return session.state;
  }
  at(2800, () => mockAuthSet(session, { phase: 'exchanging' } as McpAuthState));
  at(3300, () => mockAuthSet(session, { phase: 'verifying' } as McpAuthState));
  at(3900, () => mockAuthFinish(session));
  return session.state;
}

function mockStatusReport(c: MockConnection): McpStatusReport {
  const account = c.account || 'Raymond (raymond@aka.com)';
  if ((c.host || '').includes('notion')) {
    return {
      ok: true,
      detail: `Notion MCP answered as ${account} with 12 tools and 3 resources`,
      server: 'Notion MCP 1.4.0', protocol_version: '2025-06-18', account,
      tools: ['notion-search', 'notion-fetch', 'notion-create-pages',
        'notion-update-page', 'notion-get-self', 'notion-create-comment'],
      resources_supported: true,
      resources: [
        { uri: 'notion://workspaces/demo', name: 'Demo workspace' },
        { uri: 'notion://databases/roadmap', name: 'Roadmap', description: 'Product roadmap database' },
        { uri: 'notion://pages/handbook', name: 'Handbook' },
      ],
    };
  }
  if ((c.host || '').includes('github')) {
    return {
      ok: true,
      detail: `github-mcp-server answered as ${account} with 41 tools`,
      server: 'github-mcp-server 0.9.1', protocol_version: '2025-06-18', account,
      tools: ['get_me', 'search_repositories', 'get_file_contents',
        'list_issues', 'create_issue', 'create_pull_request'],
      resources_supported: true,
      resources: [
        { uri: 'repo://aka-com/agentmfa/contents', name: 'aka-com/agentmfa' },
      ],
    };
  }
  return {
    ok: true,
    detail: 'The server answered with 3 tools',
    server: 'mock-mcp 0.1.0', protocol_version: '2025-06-18',
    account, tools: ['echo', 'search', 'fetch'],    resources_supported: false, resources: [],
  };
}

// Broker-switcher mock: local by default. A URL containing "down" plays an
// unreachable broker and "badtoken" a rejected token, so the takeover panes
// are reviewable in a plain browser.
let mockBroker: import('./types').BrokerProfile = {
  mode: 'local', url: null, connected: true, error: null, has_saved_token: false,
};
let mockNotificationSettings: NotificationSettings = {
  mode: 'when_hidden',
  showContext: false,
  available: false,
  unavailableReason: 'Development build: native notifications are disabled',
  canOpenSystemSettings: false,
};

function mockConnectRemote(url: string, token: string | null): unknown {
  const trimmed = url.trim().replace(/\/+$/, '');
  if (!trimmed) throw 'enter the broker\u2019s URL';
  if (!/^https?:\/\//.test(trimmed)) throw 'enter a full URL, e.g. https://broker.example.dev';
  if (!token && !(mockBroker.has_saved_token && mockBroker.url === trimmed)) {
    throw 'enter the broker\u2019s management token';
  }
  if (trimmed.includes('down')) {
    throw 'the remote broker could not be reached: connection refused';
  }
  if (token?.includes('badtoken')) {
    throw 'the broker rejected the management token; re-issue it with `mfa manage token` and enter the new one';
  }
  mockBroker = { mode: 'remote', url: trimmed, connected: true, error: null, has_saved_token: true };
  emit('aka://broker-changed', mockBroker);
  // A "flaky" broker connects, then drops the link shortly after — the
  // full-pane error state is reviewable in a plain browser this way.
  if (trimmed.includes('flaky')) {
    setTimeout(() => {
      mockBroker = {
        ...mockBroker,
        connected: false,
        error: 'the remote broker could not be reached: connection refused',
      };
      emit('aka://broker-changed', mockBroker);
    }, 800);
  }
  return { ...mockBroker };
}

async function mockInvoke(cmd: CommandName, args: MockArgs): Promise<unknown> {
  switch (cmd) {
    case 'get_local_username': return 'satoshi';
    case 'list_secrets':
      if (mockFault('locked_vault')) {
        throw 'the encrypted vault could not be opened with this installation’s key';
      }
      return db.secrets.map((s) => {
        const names = db.connections.filter((c) => c.secret_names.includes(s.name)).map((c) => c.name);
        return { id: s.id, name: s.name, used_by: names.length, used_by_names: names, created_at: s.created_at, updated_at: s.updated_at };
      });
    case 'list_connections':
      if (mockFault('partial_load')) throw 'the mock connection index could not be read';
      return db.connections.map(connDto);
    case 'get_identity': return { ...db.identity };
    case 'list_sessions': return db.sessions.slice();
    case 'list_activity': return db.activity.slice(0, Math.min(args.limit ?? MOCK_ACTIVITY_LIMIT, MOCK_ACTIVITY_LIMIT));
    case 'clear_activity': db.activity = []; emit('aka://activity-changed', {}); return;
    case 'get_broker_profile':
      if (mockFault('dead_local')) {
        return {
          mode: 'local', url: null, connected: false,
          error: 'the local broker exited unexpectedly', has_saved_token: false,
        };
      }
      return { ...mockBroker };
    case 'connect_remote_broker': return mockConnectRemote(args.url as string, (args.token as string | null) ?? null);
    case 'retry_remote_broker': {
      if (mockBroker.url?.includes('down')) {
        mockBroker = { ...mockBroker, connected: false, error: 'the remote broker could not be reached: connection refused' };
        emit('aka://broker-changed', mockBroker);
        throw mockBroker.error;
      }
      mockBroker = { ...mockBroker, connected: true, error: null };
      emit('aka://broker-changed', mockBroker);
      return { ...mockBroker };
    }
    case 'switch_broker_local': {
      mockBroker = { mode: 'local', url: mockBroker.url, connected: true, error: null, has_saved_token: mockBroker.has_saved_token };
      emit('aka://broker-changed', mockBroker);
      return { ...mockBroker };
    }
    case 'get_settings': return { ...db.settings };
    case 'get_notification_settings': return { ...mockNotificationSettings };
    case 'set_notification_settings':
      mockNotificationSettings = {
        ...mockNotificationSettings,
        ...args.settings,
      };
      emit('aka://notification-settings-changed', { ...mockNotificationSettings });
      return { ...mockNotificationSettings };
    case 'open_notification_settings': return;
    case 'get_agent_setup': return MOCK_AGENT_SETUP;
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
    case 'check_known_hosts':
      // The prod.example.com fixture matches its known_hosts entry; other
      // hosts read as a first sighting.
      return args.host === 'prod.example.com'
        ? [{
            fingerprint: 'SHA256:vdZ5N8kNxU7J4W2WYa6qK0sJYv8oXb8s2H7n3jE5q1A',
            algorithm: 'ssh-ed25519', source: '~/.ssh/known_hosts',
          }]
        : [];
    case 'add_secret': {
      if (mockFault('keychain_unavailable')) {
        throw formError(
          'system',
          'keychain_unavailable',
          null,
          'Couldn’t save to macOS Keychain',
          'The keychain is locked or unavailable',
        );
      }
      if (db.secrets.some((s) => s.name === args.name)) {
        throw formError('conflict', 'secret_name_taken', 'name', 'That credential name is already in use');
      }
      db.secrets.push(mkSecret(args.name, args.value)); audit('secretAdded', `Secret added: ${args.name}`); return;
    }
    case 'edit_secret': {
      const s = db.secrets.find((x) => x.id === args.id);
      if (!s) {
        throw formError('conflict', 'secret_not_found', null, 'This credential was removed elsewhere');
      }
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
      const s = db.secrets.find((x) => x.id === args.id);
      if (!s) throw 'no such secret';
      const users = db.connections.filter((c) => c.secret_names.includes(s.name)).map((c) => c.name);
      if (users.length) throw `in use by ${users.join(', ')}`;
      db.secrets = db.secrets.filter((x) => x.id !== args.id); audit('secretDeleted', `Secret deleted: ${s.name}`); return;
    }
    case 'reveal_secret_prefix': {
      const s = db.secrets.find((x) => x.id === args.id); if (!s) throw 'no such secret';
      return revealPrefix(s._value);
    }
    case 'copy_secret': {
      const s = db.secrets.find((x) => x.id === args.id); if (!s) throw 'no such secret';
      const entry = audit('secretCopied', `Secret copied: ${s.name}`);
      emit('aka://activity-appended', entry);
      return;
    }
    case 'add_connection': {
      const i = args.input;
      // Empty is valid (unpinned, trusted on first use); only a malformed
      // non-empty fingerprint is rejected, mirroring the core.
      if (i.type === 'ssh' && i.host_key_fingerprint && !/^SHA(?:256|512):\S+$/.test(i.host_key_fingerprint)) {
        throw formError('validation', 'invalid_connection_field', 'hostKeyFingerprint', 'Enter an OpenSSH SHA-256 or SHA-512 fingerprint');
      }
      if (db.connections.some((c) => c.name === i.name)) {
        throw formError('conflict', 'connection_name_taken', 'name', 'That tool name is already in use');
      }
      if (i.new_secret_name && (i.new_secret_value || (i.ssh_import_id && i.identity_file))) {
        if (db.secrets.some((s) => s.name === i.new_secret_name)) {
          throw formError('conflict', 'secret_name_taken', 'newSecretName', 'That credential name is already in use');
        }
        // A passphrase-protected key is decrypted at import, so the demo models
        // both halves of that exchange: the ask, and the wrong answer. The real
        // backend detects encryption from the key itself; the mock uses the
        // OpenSSH header, which is the only marker a fixture can carry.
        if (i.type === 'ssh' && /ENCRYPTED PRIVATE KEY|aes256-ctr/.test(i.new_secret_value ?? '')) {
          if (!i.key_passphrase) {
            throw formError('validation', 'ssh_key_passphrase_required', 'keyPassphrase',
              'this private key is passphrase-protected; enter its passphrase');
          }
          if (i.key_passphrase !== MOCK_KEY_PASSPHRASE) {
            throw formError('validation', 'ssh_key_passphrase_wrong', 'keyPassphrase',
              'that passphrase did not decrypt the private key');
          }
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
        trusted_ca_bundle_path: i.trusted_ca_bundle_path, url: i.url,
        mcp_path: i.mcp_path });
      audit('connectionAdded', `Tool added: ${i.name}`); return;
    }
    case 'edit_connection': {
      const c = db.connections.find((x) => x.id === args.id);
      if (!c) {
        throw formError('conflict', 'connection_not_found', null, 'This tool was removed elsewhere');
      }
      const i = args.input;
      // Clearing the fingerprint un-pins (re-trusted at the next connection).
      if (i.type === 'ssh' && i.host_key_fingerprint && !/^SHA(?:256|512):\S+$/.test(i.host_key_fingerprint)) {
        throw formError('validation', 'invalid_connection_field', 'hostKeyFingerprint', 'Enter an OpenSSH SHA-256 or SHA-512 fingerprint');
      }
      if (db.connections.some((other) => other.id !== c.id && other.name === i.name)) {
        throw formError('conflict', 'connection_name_taken', 'name', 'That tool name is already in use');
      }
      Object.assign(c, { name: i.name, host: i.host, scheme: i.scheme, port: i.port,
        destination: i.destination,
        dbname: i.dbname, user: i.user, sslmode: i.sslmode, trusted_ca_bundle_path: i.trusted_ca_bundle_path,
        host_key_fingerprint: i.host_key_fingerprint, url: i.url,
        template: i.template, mcp_path: i.mcp_path });
      if (i.type !== 'api') {
        c.secret_names = i.secret_id
          ? [db.secrets.find((s) => s.id === i.secret_id)?.name]
              .filter((name): name is string => Boolean(name))
          : [];
        c.secret_ids = i.secret_id ? [i.secret_id] : [];
      }
      audit('connectionUpdated', `Tool updated: ${i.name}`); return;
    }
    case 'delete_connection': {
      const c = db.connections.find((x) => x.id === args.id); if (!c) throw 'no such connection';
      db.connections = db.connections.filter((x) => x.id !== args.id);
      db.access = db.access.filter((a) => a.connection_id !== args.id);
      audit('connectionDeleted', `Tool deleted: ${c.name}`); return;
    }
    case 'reorder_connections': {
      // Lenient, like the broker: named ids move to the front in order, any
      // omitted connection keeps its relative position at the end.
      const ids = (args.orderedIds ?? []) as string[];
      const remaining = db.connections.slice();
      const ordered: MockConnection[] = [];
      for (const id of ids) {
        const pos = remaining.findIndex((c) => c.id === id);
        if (pos !== -1) ordered.push(remaining.splice(pos, 1)[0]);
      }
      db.connections = ordered.concat(remaining);
      emit('aka://connections-changed', {});
      return;
    }
    case 'test_connection': {
      const c = db.connections.find((x) => x.id === args.id); if (!c) throw 'no such connection';
      await new Promise((resolve) => setTimeout(resolve, 700));
      // Deterministic mock: the internal-api fixture fails, everything else
      // passes, so both result presentations are exercisable standalone.
      const ok = c.type !== 'api' || !/internal/.test(c.name);
      if (!ok) {
        return { ok, detail: `The server at ${c.host} answered but rejected the credential (HTTP 401)`, kind: 'auth_rejected' };
      }
      const detail = c.type === 'pg' ? `Signed in to ${c.dbname} as ${c.user}`
        : c.type === 'ssh' ? `Signed in to ${c.host}:${c.port || 22} as ${c.user} with the saved key.`
        : `GET https://${c.host}/ answered HTTP 200 OK`;
      return { ok, detail };
    }
    case 'test_connection_draft': {
      const i = args.input as ConnectionInput;
      await new Promise((resolve) => setTimeout(resolve, 700));
      const host = String(i.host ?? '');
      const sslmode = String(i.sslmode ?? 'verify-full');
      const loopback = /^(localhost|127\.|\[?::1)/i.test(host.trim());
      // Deterministic mock: a loopback host with a TLS-requiring mode fails
      // the way a stock local Postgres (no TLS) would; 'unreachable' in the
      // host fails to connect; everything else passes.
      if (/unreachable/.test(host)) {
        return { ok: false, detail: `Could not reach ${host}:${i.port ?? 5432}: connection refused`, kind: 'unreachable' };
      }
      if (i.type === 'pg' && loopback && sslmode !== 'disable' && sslmode !== 'prefer') {
        return { ok: false, detail: `The server refused to start TLS, but this connection's TLS mode ("${sslmode}") requires it`, kind: 'tls_declined' };
      }
      if (i.type === 'ssh') {
        return { ok: true, detail: `${host}:${i.port ?? 22} answered with SSH-2.0-OpenSSH_9.8. Login and host key are not verified by this test.` };
      }
      const detail = i.secret_id
        ? `Reached ${host} and TLS checks passed; the saved credential is verified after adding`
        : `Signed in to ${i.dbname} as ${i.user}`;
      return { ok: true, detail };
    }
    case 'start_mcp_auth': {
      const draft = args.input as unknown as McpAuthDraft;
      if (!draft.reauth_connection_id && db.connections.some((c) => c.name === draft.name)) {
        throw formError('conflict', 'connection_name_taken', 'name', 'That tool name is already in use');
      }
      return mockStartAuth(draft);
    }
    case 'get_mcp_auth':
      return mockAuthSessions[args.id as string]?.state ?? null;
    case 'cancel_mcp_auth': {
      const session = mockAuthSessions[args.id as string];
      if (!session || ['succeeded', 'failed', 'cancelled'].includes(session.state.phase)) return false;
      session.timers.forEach(clearTimeout);
      mockAuthSet(session, { phase: 'cancelled' } as McpAuthState);
      return true;
    }
    case 'mcp_status': {
      const c = db.connections.find((x) => x.id === args.id); if (!c) throw 'no such connection';
      await new Promise((resolve) => setTimeout(resolve, 700));
      if (!c.mcp_path) {
        return {
          ok: false, detail: 'this connection has no MCP path', tools: [],          resources_supported: false, resources: [],
        };
      }
      const report = mockStatusReport(c);
      if (report.account && c.account !== report.account) {
        c.account = report.account;
        emit('aka://connections-changed', {});
      }
      return report;
    }
    case 'open_url': return;
    case 'copy_endpoint_text': return;
    case 'set_tool_access': {
      const connection = db.connections.find((c) => c.id === args.connectionId);
      if (!connection) return false;
      let record = db.access.find((a) => a.connection_id === connection.id);
      const current = record?.enabled ?? true;
      if (current === args.enabled) return false;
      if (!record) {
        record = { connection_id: connection.id, enabled: args.enabled };
        db.access.push(record);
      } else {
        record.enabled = args.enabled;
      }
      audit(args.enabled ? 'wired' : 'unwired',
        `Agent access ${args.enabled ? 'enabled' : 'disabled'} for ${connection.name}`,
        null, { connection: connection.name });
      emit('aka://wirings-changed', {});
      return true;
    }
    case 'oauth_connect': {
      const input = args.input;
      if (mockFault('denied_presence')) {
        throw formError('cancelled', 'not_confirmed', null, 'Nothing was saved');
      }
      if (db.connections.some((c) => c.name === input.name)) {
        throw formError('conflict', 'connection_name_taken', 'name', 'That tool name is already in use');
      }
      // Stand in for the whole browser dance.
      await new Promise((resolve) => setTimeout(resolve, 900));
      const secretName = `${input.name.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_OAUTH_TOKEN`;
      db.secrets.push(mkSecret(secretName, 'oauth-token-set-demo'));
      db.connections.push({
        id: `conn-${Math.random().toString(36).slice(2, 8)}`,
        name: input.name,
        type: 'api',
        secret_names: [secretName],
        secret_ids: [],
        host: input.host, scheme: input.scheme || 'https', port: input.port ?? null,
        template: `Authorization: Bearer {{${secretName}}}`,
        oauth_spec: {
          auth_url: input.oauth_auth_url || '',
          token_url: input.oauth_token_url || '',
          client_id: input.oauth_client_id || '',
          scopes: input.oauth_scopes || [],
        },
      });
      audit('connectionAdded', `Tool connected via OAuth: ${input.name}`);
      emit('aka://connections-changed', {});
      return;
    }
    case 'oauth_reconnect': {
      const c = db.connections.find((x) => x.id === args.id);
      if (!c || !c.oauth_spec) throw 'this tool is not an OAuth connection';
      await new Promise((resolve) => setTimeout(resolve, 900));
      audit('connectionUpdated', `Tool reconnected via OAuth: ${c.name}`);
      emit('aka://connections-changed', {});
      return;
    }
    case 'set_allowed_tools': {
      const connection = db.connections.find((c) => c.id === args.connectionId);
      if (!connection) return false;
      let record = db.access.find((a) => a.connection_id === connection.id);
      if (!record) {
        record = { connection_id: connection.id, enabled: true };
        db.access.push(record);
      }
      const tools = args.tools;
      if (tools == null) delete record.allowed_tools;
      else record.allowed_tools = [...tools];
      emit('aka://wirings-changed', {});
      emit('aka://connections-changed', {});
      return true;
    }
    case 'list_mcp_tools': {
      const c = db.connections.find((x) => x.id === args.id);
      if (!c || !c.mcp_path) throw 'this connection has no MCP path';
      await new Promise((resolve) => setTimeout(resolve, 500));
      // The status-report mock already knows each brand's tools; dress
      // them with light descriptions for the picker.
      return {
        tools: mockStatusReport(c).tools.map((name) => ({
          name,
          display_name: name,
          description: `The server's ${name.replace(/[_-]/g, ' ')} tool`,
        })),
        truncated: false,
        stale: false,
        fetched_at: new Date().toISOString(),
        cache_age_seconds: 0,
      };
    }
    case 'issue_endpoint': {
      const connection = db.connections.find((c) => c.id === args.connectionId);
      if (!connection) throw 'no such tool';
      let record = db.access.find((a) => a.connection_id === connection.id);
      if (record && !record.enabled) throw 'enable this tool for agents before issuing a direct endpoint';
      if (!record) {
        record = { connection_id: connection.id, enabled: true };
        db.access.push(record);
      }
      const kind = connection.type;
      const endpointId = record.endpoint?.endpoint_id ?? `mock-endpoint-${connection.id}`;
      const secret = MOCK_ENDPOINT_SECRET;
      const dir = `~/.aka/endpoints/${endpointId}`;
      let dsn: string;
      let example: string;
      let shownSecret = secret;
      if (kind === 'pg') {
        dsn = `postgresql://${connection.user ?? 'app'}:${secret}@/${connection.dbname ?? 'app'}?host=${dir}&port=5432&sslmode=disable`;
        example = `DATABASE_URL="${dsn}"`;
      } else if (kind === 'ssh') {
        // The real broker derives this filename from the endpoint secret, so
        // the socket cannot be found by listing the directory; the demo mirrors
        // the shape so the read-back path is exercised here too.
        dsn = `${dir}/agent-3f1c9a2b04d7e685.sock`;
        const invocation = sshInvocationCommand({ ...connection, target: connTarget(connection) });
        example = `SSH_AUTH_SOCK="${dsn}" ${invocation}`;
        shownSecret = ''; // ssh-agent has no presented secret
      } else {
        dsn = 'http://127.0.0.1:52000';
        example = `curl -H "Authorization: Bearer ${secret}" ${dsn}/`;
      }
      // Postgres retains its credential in the DSN. SSH does not retain its
      // socket path on the chip: the filename is derived from the endpoint
      // secret precisely so it is not enumerable, which means only a
      // vault-backed read can name it. `sshDsn` stands in for the vault here.
      record.endpoint = kind === 'ssh'
        ? { endpoint_id: endpointId, type: kind, sshDsn: dsn }
        : { endpoint_id: endpointId, type: kind, dsn };
      audit('wired', `Direct endpoint issued: ${connection.name}`);
      emit('aka://wirings-changed', {});
      return { endpoint_id: endpointId, type: kind, dsn, secret: shownSecret, example };
    }
    case 'get_endpoint': {
      // A no-gate read-back of the issued endpoint. The mock's secret is a
      // fixed demo value, so re-reading reproduces what issuance showed.
      const connection = db.connections.find((c) => c.id === args.connectionId);
      const endpoint = db.access.find((a) => a.connection_id === args.connectionId)?.endpoint;
      if (!connection || !endpoint) return null;
      const dsn = endpoint.dsn ?? endpoint.sshDsn ?? '';
      const secret = connection.type === 'ssh' ? '' : MOCK_ENDPOINT_SECRET;
      const example = connection.type === 'pg' ? `DATABASE_URL="${dsn}"`
        : connection.type === 'ssh'
          ? `SSH_AUTH_SOCK="${dsn}" ${sshInvocationCommand({ ...connection, target: connTarget(connection) })}`
        : `curl -H "Authorization: Bearer ${secret}" ${dsn}/`;
      return { endpoint_id: endpoint.endpoint_id, type: connection.type, dsn, secret, example };
    }
    case 'revoke_endpoint': {
      const record = db.access.find((a) => a.endpoint?.endpoint_id === args.endpointId);
      if (!record) return false;
      const connection = db.connections.find((c) => c.id === record.connection_id);
      delete record.endpoint;
      audit('unwired', `Direct endpoint revoked${connection ? `: ${connection.name}` : ''}`);
      emit('aka://wirings-changed', {});
      return true;
    }
    case 'copy_key':
      audit('secretCopied', 'Shared key copied');
      return;
    case 'rotate_key':
      // Stands in for the native sheet (whose reason text is the warning).
      if (!window.confirm("Rotate this computer's key?\n\nEvery live agent session closes now; agents reconnect on their own from the key file.")) throw 'declined';
      // falls through to apply
      db.identity = { ...db.identity, minted_at: now(), last_used: now(), legacy_aliases: 0 };
      db.sessions = [];
      audit('tokenRevoked', 'Key rotated; all agents disconnected');
      emit('aka://agents-changed', {});
      emit('aka://sessions-changed', {});
      return;
    case 'close_session': db.sessions = db.sessions.filter((s) => s.id !== args.id); emit('aka://sessions-changed', {}); return true;
    case 'set_confirm_mode': {
      const connection = db.connections.find((c) => c.id === args.connectionId);
      if (!connection) return false;
      let record = db.access.find((a) => a.connection_id === connection.id);
      const current = record?.confirm ?? false;
      if (current === args.on) return false;
      if (!record) {
        record = { connection_id: connection.id, enabled: true, confirm: args.on };
        db.access.push(record);
      } else {
        record.confirm = args.on;
      }
      if (!args.on) {
        // Turning it off releases anything parked on the connection — the
        // broker does the same, rather than refusing traffic the user just
        // said needs no asking. A running denial cooldown lifts with it.
        record.confirm_window_until = null;
        record.confirm_window_agents = [];
        record.confirm_cooldown_until = null;
        const released = db.approvals.filter((a) => a.connection_id === connection.id);
        released.forEach((approval) =>
          resolveMockRequest(approval.id, 'approved', 'confirmation_disabled'));
        db.approvals = db.approvals.filter((a) => a.connection_id !== connection.id);
        emit('aka://approvals-changed', {});
      }
      audit('wired',
        `Traffic confirmation ${args.on ? 'enabled' : 'disabled'} for ${connection.name}`,
        null, { connection: connection.name });
      emit('aka://wirings-changed', {});
      return true;
    }
    case 'list_approvals': return db.approvals.slice();
    case 'list_requests': return db.requests.slice();
    case 'respond_approval': {
      const approval = db.approvals.find((a) => a.id === args.id);
      if (!approval) return false;
      db.approvals = db.approvals.filter((a) => a.id !== approval.id);
      const record = db.access.find((a) => a.connection_id === approval.connection_id);
      if (args.decision === 'approve_window' && record) {
        record.confirm_window_until =
          new Date(Date.now() + approval.window_secs * 1000).toISOString();
        // Scoped to the agent the prompt named, like the broker: another
        // agent on the same connection is still asked about.
        record.confirm_window_agents = Array.from(
          new Set([...(record.confirm_window_agents ?? []), approval.agent]),
        ).sort();
      }
      if (args.decision === 'approve_all' && record) {
        record.confirm = false;
        record.confirm_window_until = null;
        record.confirm_window_agents = [];
      }
      if (args.decision === 'deny' && record) {
        // Mirror the broker's 60-second post-denial cooldown so the panel's
        // "retries are refused" line is designable in the mock.
        record.confirm_cooldown_until = new Date(Date.now() + 60_000).toISOString();
      }
      resolveMockRequest(
        approval.id,
        args.decision === 'deny' ? 'denied' : 'approved',
        args.decision === 'deny' ? 'denied'
          : args.decision === 'approve_all' ? 'approved_all' : 'approved_for_window',
      );
      const entry = args.decision === 'deny'
        ? audit('denied', `Refused by the user: ${approval.agent} → ${approval.connection}`,
            approval.summary, { connection: approval.connection, agent: approval.agent })
        : audit('allowedOnce', `Confirmed: ${approval.agent} → ${approval.connection}`,
            approval.summary, { connection: approval.connection, agent: approval.agent });
      emit('aka://approvals-changed', {});
      emit('aka://wirings-changed', {});
      emit('aka://activity-appended', entry);
      return true;
    }
    case 'list_elicitations': return db.elicitations.slice();
    case 'respond_elicitation': {
      const request = db.elicitations.find((r) => r.id === args.id);
      if (!request) return false;
      db.elicitations = db.elicitations.filter((r) => r.id !== args.id);
      resolveMockRequest(
        request.id,
        args.approved ? 'approved' : 'denied',
        args.approved ? 'input_provided' : 'input_refused',
      );
      // The values themselves are deliberately NOT audited — like a secret,
      // an answer may be sensitive; the record is that it was provided.
      const entry = args.approved
        ? audit('inputProvided', `Input provided: ${request.connection} ← you`,
            `${request.agent} · ${request.tool} resumes with your answer`)
        : audit('inputRefused', `Input refused: ${request.connection}`,
            `${request.agent} · ${request.tool} is told the user declined`);
      emit('aka://elicitations-changed', {});
      emit('aka://activity-appended', entry);
      return true;
    }
    case 'set_reauth_on_read':
      db.settings.reauth_on_read = args.on;
      emit('aka://settings-changed', {});
      return;
    case 'set_menu_bar_hides_dock':
      db.settings.menu_bar_hides_dock = args.on;
      emit('aka://settings-changed', {});
      return;
    case 'set_presence_window':
      db.settings.presence_window_secs = args.secs;
      emit('aka://settings-changed', {});
      return;
    case 'ui_set_mode': case 'ui_hide_main': case 'ui_hide_dropdown':
    case 'ui_set_dropdown_form_active': return;
    case 'ui_take_open_requests': return false;
    default: throw new Error(`mock: unknown command ${cmd}`);
  }
}
