// The Multitool sidecar's HTTP surface.
//
// Split from the entry point so tests can drive the server without spawning
// a process. Phase 1 is lifecycle only — no executor, no tools — but the
// contract here is what the Rust supervisor depends on and what every later
// phase builds on: every request carries the shared token the supervisor
// generated, so nothing else on loopback can reach us.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';

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

export function createSidecarServer(env: SidecarEnv): Server {
  return createServer((req, res) => {
    const presented = bearer(req);
    if (presented === null || !tokenMatches(presented, env.token)) {
      json(res, 401, { error: 'unauthorized' });
      return;
    }

    if (req.method === 'GET' && req.url === '/health') {
      json(res, 200, { status: 'ok', version: SIDECAR_VERSION, pid: process.pid });
      return;
    }

    json(res, 404, { error: 'not_found' });
  });
}
