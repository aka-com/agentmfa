// One disposable headless broker per test file.
//
// The desktop app is macOS-only, so this suite drives what the sandbox
// README calls the headless path: `mfa manage token` mints a management
// credential offline, `mfa serve --root <tmp>` runs the broker with its
// state under a throwaway directory, and the tests then speak the two wire
// planes an agent and the app speak — the control plane over the Unix
// socket, and the manage plane at /v1/manage.
//
// Each test file gets its own broker (its own store, identity, audit log,
// rate-limit buckets and approval state) so files can run in parallel and a
// test that deliberately exhausts a budget cannot leak into another file.

import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { HttpResponse, json, request, sleep, sse, waitFor, type SseStream } from './http';
import { run } from './proc';
import { closedPort, repoRoot, sandbox, sshPrivateKey } from './sandbox';

/* ------------------------------ wire shapes ------------------------------- */

export interface ConnectionDto {
  id: string;
  name: string;
  type: string;
  target: string;
  secret_names: string[];
  agent_access: {
    enabled: boolean;
    confirm?: boolean;
    confirm_window_until?: string;
    confirm_window_agents?: string[];
    confirm_cooldown_until?: string;
    allowed_tools?: string[];
    endpoint?: { endpoint_id: string; type: string; dsn?: string };
  };
  host?: string | null;
  port?: number | null;
  mcp_path?: string | null;
  host_key_fingerprint?: string | null;
  last_status?: string | null;
  last_detail?: string | null;
}

export interface SecretDto {
  id: string;
  name: string;
  used_by: number;
  used_by_names: string[];
}

export interface ApprovalDto {
  id: string;
  connection_id: string;
  connection: string;
  type: string;
  unit?: string;
  target: string;
  agent: string;
  summary: string;
  detail?: string;
  consequence?: string;
  waiting: number;
  requested_at: string;
  expires_at: string;
  window_secs: number;
}

export interface RequestDto {
  id: string;
  kind: string;
  status: string;
  connection: string;
  agent: string;
  summary: string;
  resolution?: string;
}

export interface ElicitationDto {
  id: string;
  agent: string;
  connection: string;
  tool: string;
  prompt: string;
  fields: Array<{ name: string; label: string; boolean?: boolean; options?: string[] }>;
  credential_warning?: boolean;
}

export interface SessionDto {
  id: number;
  type: string;
  agent: string;
  connection: string;
  detail: string;
  opened_at: string;
}

export interface ActivityDto {
  icon: string;
  tone: string;
  kind?: string | null;
  text: string;
  detail: string | null;
  agent: string | null;
  connection: string | null;
  outcome?: string | null;
  protocol?: string | null;
  at: string;
}

export interface IssuedEndpointDto {
  endpoint_id: string;
  type: string;
  dsn: string;
  secret: string;
  example: string;
}

/** The `{status, headers, body, body_encoding}` envelope POST /v1/http relays. */
export interface RelayedResponse {
  status: number;
  headers: Record<string, string>;
  set_cookie_headers?: string[];
  body: string;
  body_encoding: 'utf8' | 'base64';
}

export type ApprovalDecision = 'approve_window' | 'approve_all' | 'deny';

/* -------------------------------- seeding --------------------------------- */

/** The sandbox services a test file wants wired up before it starts. */
export type SeedName =
  | 'http'
  /** A second API connection to the same fixture, for per-connection state. */
  | 'http-alt'
  | 'mcp'
  | 'pg'
  | 'ssh'
  | 'dead'
  | 'wrong-credential';

export const connectionNames = {
  http: 'sandbox-http',
  'http-alt': 'sandbox-http-alt',
  mcp: 'sandbox-mcp',
  pg: 'sandbox-postgres',
  ssh: 'sandbox-ssh',
  dead: 'sandbox-unreachable',
  'wrong-credential': 'sandbox-wrong-credential',
} as const satisfies Record<SeedName, string>;

export interface StartOptions {
  /** Directory-name hint, so a leaked temp dir names its test file. */
  label: string;
  /** Which sandbox services to add as connections. */
  seed?: SeedName[];
  /** Disable the in-process MCP host for an unavailable-host test. */
  mcp?: boolean;
  /** Pin the SSH connection to this host-key fingerprint (default: TOFU). */
  sshHostKeyFingerprint?: string;
}

/* -------------------------------- harness --------------------------------- */

export function mfaBinary(): string {
  const configured = process.env.AKA_MFA_BIN;
  if (configured) return configured;
  for (const candidate of ['target/debug/mfa', 'target/release/mfa']) {
    const path = join(repoRoot, candidate);
    if (existsSync(path)) return path;
  }
  throw new Error(
    'no `mfa` binary found — run `cargo build -p mfa` or set AKA_MFA_BIN ' +
      '(`npm run sandbox:test` does this for you)',
  );
}

export class Broker {
  private constructor(
    readonly root: string,
    readonly socketPath: string,
    readonly agentToken: string,
    readonly manageToken: string,
    private readonly child: ChildProcess,
    private readonly logs: () => string,
    private readonly connections: Map<string, ConnectionDto>,
    private readonly surfaces: ApprovalSurface[],
  ) {}

  /** Start a broker, seed the requested sandbox services, and wait until it serves. */
  static async start(options: StartOptions): Promise<Broker> {
    const binary = mfaBinary();
    const root = await mkdtemp(join(tmpdir(), `aka-sandbox-${options.label}-`));

    // Offline: the manage token can only be issued while no broker holds the
    // state lease, which is exactly the app's own "run it on the host" flow.
    const issued = await run(binary, ['manage', 'token', '--root', root], { timeoutMs: 30_000 });
    const manageToken = issued.stdout.trim().split('\n').pop() ?? '';
    if (!manageToken.startsWith('akamgr_')) {
      throw new Error(`\`mfa manage token\` did not print a token: ${issued.stderr}`);
    }

    const broker = await Broker.launch(root, manageToken, options);
    await broker.seed(options);
    return broker;
  }

  /**
   * Serve an existing root again — the restart case. The management token
   * and the agent key belong to the state on disk, so both survive.
   */
  static async reopen(root: string, manageToken: string): Promise<Broker> {
    const broker = await Broker.launch(root, manageToken, {});
    for (const connection of await broker.manage<ConnectionDto[]>('GET', '/connections')) {
      broker.connections.set(connection.name, connection);
    }
    return broker;
  }

  private static async launch(
    root: string,
    manageToken: string,
    options: Pick<StartOptions, 'mcp'>,
  ): Promise<Broker> {
    const binary = mfaBinary();
    const socketPath = join(root, 'sock/broker.sock');
    const args = ['serve', '--root', root];
    if (options.mcp === false) args.push('--no-mcp');
    const child = spawn(binary, args, {
      cwd: repoRoot,
      env: {
        ...process.env,
        RUST_LOG: process.env.RUST_LOG ?? 'aka_core=warn',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let log = '';
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      log += chunk;
    });
    child.stderr?.on('data', (chunk: string) => {
      log += chunk;
    });
    let exited = false;
    child.on('exit', () => {
      exited = true;
    });

    await waitFor(
      'the broker to serve its control socket',
      async () => {
        if (exited) throw new Error(`the broker exited during startup:\n${log}`);
        if (!existsSync(socketPath)) return undefined;
        const response = await request({
          socketPath,
          path: '/.well-known/agent-broker.json',
          timeoutMs: 2_000,
        });
        return response.status === 200 ? true : undefined;
      },
      30_000,
    );

    const agentToken = (await readFile(join(root, 'sock/token'), 'utf8')).trim();
    return new Broker(root, socketPath, agentToken, manageToken, child, () => log, new Map(), []);
  }

  /** The broker's own stdout/stderr, for failure messages. */
  get output(): string {
    return this.logs();
  }

  conn(name: string): ConnectionDto {
    const found = this.connections.get(name);
    if (!found) throw new Error(`connection ${name} was not seeded`);
    return found;
  }

  /** Re-read a seeded connection's current DTO from the manage plane. */
  async refresh(name: string): Promise<ConnectionDto> {
    const all = await this.manage<ConnectionDto[]>('GET', '/connections');
    const found = all.find((connection) => connection.name === name);
    if (!found) throw new Error(`connection ${name} is gone`);
    this.connections.set(name, found);
    return found;
  }

  async stop(): Promise<void> {
    await this.stopKeepingState();
    await removeKeychainItems(this.root);
    await rm(this.root, { recursive: true, force: true });
  }

  /** Stop the process but leave the root on disk, for a restart. */
  async stopKeepingState(): Promise<void> {
    for (const surface of this.surfaces.splice(0)) surface.detach();
    if (this.child.exitCode === null && this.child.signalCode === null) {
      const exited = new Promise<void>((resolve) => this.child.once('exit', () => resolve()));
      this.child.kill('SIGINT');
      const killer = setTimeout(() => this.child.kill('SIGKILL'), 5_000);
      await exited;
      clearTimeout(killer);
    }
  }

  /* ------------------------------ agent plane ----------------------------- */

  /** A raw control-plane request; `token: null` sends no Authorization. */
  async agentRaw(
    method: string,
    path: string,
    options: { body?: unknown; token?: string | null; client?: string; headers?: Record<string, string> } = {},
  ): Promise<HttpResponse> {
    const headers: Record<string, string> = { ...(options.headers ?? {}) };
    const token = options.token === undefined ? this.agentToken : options.token;
    if (token !== null) headers.authorization = `Bearer ${token}`;
    if (options.client) headers['x-agentmfa-client'] = options.client;
    return json({
      socketPath: this.socketPath,
      method,
      path,
      headers,
      json: options.body,
      timeoutMs: 120_000,
    });
  }

  /** `POST /v1/http` — the API/MCP capability call. */
  async http(
    body: Record<string, unknown>,
    options: { client?: string } = {},
  ): Promise<HttpResponse> {
    return this.agentRaw('POST', '/v1/http', { body, client: options.client });
  }

  /** `POST /v1/http` for a call expected to reach the upstream. */
  async call(body: Record<string, unknown>, options: { client?: string } = {}): Promise<RelayedResponse> {
    const response = await this.http(body, options);
    if (response.status !== 200) {
      throw new Error(`brokered call failed: HTTP ${response.status} ${response.text}`);
    }
    return response.json<RelayedResponse>();
  }

  async pgOpen(connection: string, requestId?: string): Promise<HttpResponse> {
    return this.agentRaw('POST', '/v1/pg/open', {
      body: { connection, ...(requestId ? { request_id: requestId } : {}) },
    });
  }

  async sshOpen(connection: string, requestId?: string): Promise<HttpResponse> {
    return this.agentRaw('POST', '/v1/ssh/open', {
      body: { connection, ...(requestId ? { request_id: requestId } : {}) },
    });
  }

  /* ----------------------------- manage plane ----------------------------- */

  async manageRaw(
    method: string,
    path: string,
    options: { body?: unknown; token?: string | null } = {},
  ): Promise<HttpResponse> {
    const headers: Record<string, string> = {};
    const token = options.token === undefined ? this.manageToken : options.token;
    if (token !== null) headers.authorization = `Bearer ${token}`;
    return json({
      socketPath: this.socketPath,
      method,
      path: `/v1/manage${path}`,
      headers,
      json: options.body,
      timeoutMs: 120_000,
    });
  }

  /** A manage call that must succeed, decoded. */
  async manage<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
    const response = await this.manageRaw(method, path, { body });
    if (response.status < 200 || response.status >= 300) {
      throw new Error(`manage ${method} ${path} failed: HTTP ${response.status} ${response.text}`);
    }
    return response.body.length === 0 ? (undefined as T) : response.json<T>();
  }

  async secrets(): Promise<SecretDto[]> {
    return this.manage<SecretDto[]>('GET', '/secrets');
  }

  async addSecret(name: string, value: string): Promise<void> {
    await this.manage('POST', '/secrets', { name, value });
  }

  /** Add a secret unless a seed already stored it under that name. */
  async ensureSecret(name: string, value: string): Promise<void> {
    if ((await this.secrets()).some((secret) => secret.name === name)) return;
    await this.addSecret(name, value);
  }

  async secretId(name: string): Promise<string> {
    const found = (await this.secrets()).find((secret) => secret.name === name);
    if (!found) throw new Error(`secret ${name} does not exist`);
    return found.id;
  }

  async addConnection(spec: Record<string, unknown>): Promise<ConnectionDto> {
    await this.manage('POST', '/connections', { spec });
    const all = await this.manage<ConnectionDto[]>('GET', '/connections');
    const added = all.find((connection) => connection.name === spec.name);
    if (!added) throw new Error(`connection ${String(spec.name)} was not stored`);
    this.connections.set(added.name, added);
    return added;
  }

  async setAccess(connectionId: string, enabled: boolean): Promise<void> {
    await this.manage('POST', `/connections/${connectionId}/access`, { enabled });
  }

  async setConfirm(connectionId: string, on: boolean): Promise<void> {
    await this.manage('POST', `/connections/${connectionId}/confirm`, { on });
  }

  async setAllowedTools(connectionId: string, tools: string[] | null): Promise<void> {
    await this.manage('POST', `/connections/${connectionId}/allowed-tools`, { tools });
  }

  async approvals(): Promise<ApprovalDto[]> {
    return this.manage<ApprovalDto[]>('GET', '/approvals');
  }

  async respondApproval(id: string, decision: ApprovalDecision): Promise<boolean> {
    const answered = await this.manage<{ answered: boolean }>('POST', `/approvals/${id}`, {
      decision,
    });
    return answered.answered;
  }

  async elicitations(): Promise<ElicitationDto[]> {
    return this.manage<ElicitationDto[]>('GET', '/elicitations');
  }

  async requests(): Promise<RequestDto[]> {
    return this.manage<RequestDto[]>('GET', '/requests');
  }

  async sessions(): Promise<SessionDto[]> {
    return this.manage<SessionDto[]>('GET', '/sessions');
  }

  async activity(limit = 500): Promise<ActivityDto[]> {
    return this.manage<ActivityDto[]>('GET', `/activity?limit=${limit}`);
  }

  /** Wait until a prompt is on the queue, then return it. */
  async waitForApproval(timeoutMs = 15_000): Promise<ApprovalDto> {
    return waitFor(
      'a confirmation prompt',
      async () => (await this.approvals())[0],
      timeoutMs,
    );
  }

  async waitForElicitation(timeoutMs = 15_000): Promise<ElicitationDto> {
    return waitFor(
      'an elicitation',
      async () => (await this.elicitations())[0],
      timeoutMs,
    );
  }

  /* --------------------------- approval surface --------------------------- */

  /**
   * Attach a request inbox, the way the desktop app does: an authenticated
   * manage event stream carrying the request-surface header, renewed on a
   * heartbeat. Without one the broker fails confirmed traffic closed, so
   * every approval test starts here.
   */
  async attachApprovalSurface(): Promise<ApprovalSurface> {
    const stream = await sse({
      socketPath: this.socketPath,
      path: '/v1/manage/events',
      headers: {
        authorization: `Bearer ${this.manageToken}`,
        'x-aka-approval-surface': 'request-inbox-v1',
      },
    });
    const status = stream.headers['x-aka-approval-surface-status'];
    const id = stream.headers['x-aka-approval-surface-id'];
    if (status !== 'active' || typeof id !== 'string') {
      stream.close();
      throw new Error(`the broker classified the stream as ${String(status)}, not an active surface`);
    }
    const surface = new ApprovalSurface(this, stream, id);
    this.surfaces.push(surface);
    return surface;
  }

  /* -------------------------------- seeding -------------------------------- */

  private async seed(options: StartOptions): Promise<void> {
    for (const name of options.seed ?? []) {
      switch (name) {
        case 'http':
        case 'http-alt':
          await this.ensureSecret('SANDBOX_HTTP_TOKEN', sandbox.httpToken);
          await this.addConnection({
            name: connectionNames[name],
            config: {
              kind: 'api',
              host: sandbox.host,
              scheme: 'http',
              port: sandbox.httpPort,
              template: 'Authorization: Bearer {{SANDBOX_HTTP_TOKEN}}',
            },
            secrets: [],
          });
          break;
        case 'mcp':
          await this.addSecret('SANDBOX_MCP_TOKEN', sandbox.mcpToken);
          await this.addConnection({
            name: connectionNames.mcp,
            config: {
              kind: 'api',
              host: sandbox.host,
              scheme: 'http',
              port: sandbox.httpPort,
              template: 'Authorization: Bearer {{SANDBOX_MCP_TOKEN}}',
              mcp_path: sandbox.mcpPath,
            },
            secrets: [],
          });
          break;
        case 'pg':
          await this.addSecret('SANDBOX_PG_PASSWORD', sandbox.pgPassword);
          await this.addConnection({
            name: connectionNames.pg,
            config: {
              kind: 'pg',
              host: sandbox.host,
              port: sandbox.pgPort,
              dbname: sandbox.pgDatabase,
              user: sandbox.pgUser,
              sslmode: 'disable',
            },
            secrets: [await this.secretId('SANDBOX_PG_PASSWORD')],
          });
          break;
        case 'ssh':
          await this.addSecret('SANDBOX_SSH_KEY', await sshPrivateKey());
          await this.addConnection({
            name: connectionNames.ssh,
            config: {
              kind: 'ssh',
              host: sandbox.host,
              port: sandbox.sshPort,
              user: sandbox.sshUser,
              host_key_fingerprint: options.sshHostKeyFingerprint ?? '',
            },
            secrets: [await this.secretId('SANDBOX_SSH_KEY')],
          });
          break;
        case 'dead':
          await this.addSecret('SANDBOX_DEAD_TOKEN', 'unused-fake-token');
          await this.addConnection({
            name: connectionNames.dead,
            config: {
              kind: 'api',
              host: sandbox.host,
              scheme: 'http',
              // Nothing listens here: the connect-failure case.
              port: closedPort,
              template: 'Authorization: Bearer {{SANDBOX_DEAD_TOKEN}}',
            },
            secrets: [],
          });
          break;
        case 'wrong-credential':
          await this.addSecret('SANDBOX_WRONG_TOKEN', 'not-the-sandbox-token');
          await this.addConnection({
            name: connectionNames['wrong-credential'],
            config: {
              kind: 'api',
              host: sandbox.host,
              scheme: 'http',
              port: sandbox.httpPort,
              template: 'Authorization: Bearer {{SANDBOX_WRONG_TOKEN}}',
            },
            secrets: [],
          });
          break;
      }
    }
  }
}

/**
 * Take a throwaway root's vault items back out of the macOS Keychain.
 *
 * A `serve --root` broker on macOS stores its secrets in the login
 * Keychain under a service name derived from the canonical root path
 * (`dev_root_vault_service` in crates/aka-core/src/vault.rs). Deleting the
 * directory would otherwise leave one item per secret behind on every run.
 * Everywhere else the vault is a file inside the root, so this is a no-op.
 */
async function removeKeychainItems(root: string): Promise<void> {
  if (process.platform !== 'darwin') return;
  const { createHash } = await import('node:crypto');
  const { realpath } = await import('node:fs/promises');
  let canonical: string;
  try {
    canonical = await realpath(root);
  } catch {
    return;
  }
  const service = `com.aka.desktop.dev.${createHash('sha256').update(canonical).digest('hex')}`;
  // One call deletes one item; stop as soon as none is left (or the tool is
  // unavailable), and never let cleanup fail a test run.
  for (let i = 0; i < 64; i += 1) {
    try {
      const result = await run('security', ['delete-generic-password', '-s', service], {
        timeoutMs: 10_000,
      });
      if (result.code !== 0) return;
    } catch {
      return;
    }
  }
}

/** An attached request inbox: the app's half of traffic confirmation. */
export class ApprovalSurface {
  private readonly heartbeat: NodeJS.Timeout;
  private detached = false;

  constructor(
    private readonly broker: Broker,
    private readonly stream: SseStream,
    readonly id: string,
  ) {
    // The broker allows three missed 5s heartbeats; renew at 4s so a slow
    // test machine never drops the lease mid-prompt.
    this.heartbeat = setInterval(() => {
      void this.broker.manageRaw('PUT', `/approval-surfaces/${this.id}`).catch(() => {});
    }, 4_000);
    this.heartbeat.unref();
  }

  /** Manage events this surface has seen, as `{event: …}` objects. */
  get events(): Array<Record<string, unknown>> {
    return this.stream.frames.flatMap((frame) => {
      try {
        return [JSON.parse(frame.data) as Record<string, unknown>];
      } catch {
        return [];
      }
    });
  }

  async waitForEvent(name: string, timeoutMs = 10_000): Promise<Record<string, unknown>> {
    const frame = await this.stream.waitFor((f) => {
      try {
        return (JSON.parse(f.data) as { event?: string }).event === name;
      } catch {
        return false;
      }
    }, timeoutMs);
    return JSON.parse(frame.data) as Record<string, unknown>;
  }

  /**
   * Stand in for a user watching the inbox: answer each prompt as `decide`
   * says. Returns the prompts answered so far, so a test can assert what
   * the user was actually shown.
   */
  autoAnswer(decide: (approval: ApprovalDto) => ApprovalDecision): AutoAnswer {
    const seen: ApprovalDto[] = [];
    // Per stand-in user, not per surface: two overlapping answerers in one
    // test file must not answer (or count) each other's prompts.
    let answering = true;
    const loop = async (): Promise<void> => {
      while (answering && !this.detached) {
        try {
          for (const approval of await this.broker.approvals()) {
            if (seen.some((prompt) => prompt.id === approval.id)) continue;
            seen.push(approval);
            await this.broker.respondApproval(approval.id, decide(approval));
          }
        } catch {
          // The broker is going away, or the prompt lapsed between the
          // listing and the answer. Either way, stop trying on the next tick.
        }
        await sleep(25);
      }
    };
    void loop();
    return {
      answered: seen,
      stop: () => {
        answering = false;
      },
    };
  }

  detach(): void {
    this.detached = true;
    clearInterval(this.heartbeat);
    this.stream.close();
  }
}

export interface AutoAnswer {
  /** Prompts this stand-in user answered, in order. */
  answered: ApprovalDto[];
  stop(): void;
}
