// The Multitool sidecar's HTTP surface.
//
// Two audiences share this listener, and they authenticate differently:
//
//   * `/health` is ours. It carries the per-process token the supervisor
//     minted, which nothing outside the broker ever sees.
//   * `/mcp` is the agent's. It carries the agent's own broker token, which
//     the broker — not us — resolves to an identity.
//
// Routing therefore comes before authentication: there is no single
// credential that opens both doors, and treating the supervisor's token as
// though it could serve an agent would be exactly the confusion to avoid.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';

import { BrokerClient } from './broker';
import { BrokerAuthProvider, MCP_PATH, SessionStore, openSession } from './mcp';

export const SIDECAR_VERSION = '0.1.0';

export interface SidecarEnv {
  /** Shared secret minted by the supervisor and passed in the environment. */
  token: string;
  /** Path to the broker's Unix socket — the sidecar's only way back in. */
  brokerSocket: string;
}

export type Level = 'info' | 'warn' | 'error';

/** Structured log line on stderr; the supervisor forwards these to tracing. */
export function log(level: Level, msg: string, fields: Record<string, unknown> = {}): void {
  process.stderr.write(`${JSON.stringify({ level, msg, ...fields })}\n`);
}

/** Constant-time compare that also tolerates a length mismatch. */
export function tokenMatches(presented: string, expected: string): boolean {
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function bearer(req: IncomingMessage): string | null {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  return header.slice('Bearer '.length);
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

/** JSON-RPC shaped error, which is what an MCP client knows how to read. */
function rpcError(res: ServerResponse, status: number, code: number, message: string): void {
  const payload = JSON.stringify({ jsonrpc: '2.0', error: { code, message }, id: null });
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  if (chunks.length === 0) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

export function createSidecarServer(env: SidecarEnv): Server {
  const broker = new BrokerClient(env.brokerSocket);
  const auth = new BrokerAuthProvider(broker);
  const sessions = new SessionStore();

  return createServer((req, res) => {
    const path = (req.url ?? '').split('?')[0];

    if (path === MCP_PATH) {
      handleMcp(req, res, { broker, auth, sessions }).catch((error) => {
        log('error', 'mcp request failed', { error: String(error) });
        if (!res.headersSent) rpcError(res, 500, -32603, 'Internal error');
      });
      return;
    }

    const presented = bearer(req);
    if (presented === null || !tokenMatches(presented, env.token)) {
      json(res, 401, { error: 'unauthorized' });
      return;
    }

    if (req.method === 'GET' && path === '/health') {
      json(res, 200, {
        status: 'ok',
        version: SIDECAR_VERSION,
        pid: process.pid,
        sessions: sessions.size,
      });
      return;
    }

    json(res, 404, { error: 'not_found' });
  });
}

interface McpDeps {
  broker: BrokerClient;
  auth: BrokerAuthProvider;
  sessions: SessionStore;
}

async function handleMcp(
  req: IncomingMessage,
  res: ServerResponse,
  { broker, auth, sessions }: McpDeps,
): Promise<void> {
  // Every request, including one carrying a live session id: a token
  // revoked in the app must stop working on the very next call.
  const principal = await auth.authenticate(bearer(req));
  if (!principal) {
    res.setHeader('www-authenticate', 'Bearer');
    rpcError(res, 401, -32001, 'Unauthorized: pair this agent with Multitool first');
    return;
  }

  const sessionId = req.headers['mcp-session-id'];
  const existing = typeof sessionId === 'string' ? sessions.get(sessionId, principal.clientId) : null;

  if (existing) {
    await existing.handleRequest(req, res, req.method === 'POST' ? await readBody(req) : undefined);
    return;
  }

  // A session id we do not recognize — or one belonging to another agent —
  // is refused rather than silently reopened, so a leaked id cannot be
  // turned into a working session by anyone else.
  if (typeof sessionId === 'string') {
    rpcError(res, 404, -32001, 'Unknown or expired session');
    return;
  }

  if (req.method !== 'POST') {
    rpcError(res, 405, -32000, 'Expected an initialize request');
    return;
  }

  const transport = await openSession(broker, principal, sessions);
  await transport.handleRequest(req, res, await readBody(req));
}
