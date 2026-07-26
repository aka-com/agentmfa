// HTTP for the broker's two planes, plus the sandbox upstreams.
//
// The control plane and the manage plane are served over a Unix socket, and
// direct endpoints over loopback TCP, so every request in this suite goes
// through one helper that speaks both. Nothing here depends on a package
// outside Node: the suite has to run from a checkout with only the repo's
// own dev dependencies installed.

import { request as nodeRequest, type IncomingMessage } from 'node:http';

export interface Target {
  /** Unix socket path (the broker's control/manage plane). */
  socketPath?: string;
  /** Loopback host/port (direct endpoints, the sandbox fixture). */
  host?: string;
  port?: number;
}

export interface RequestOptions extends Target {
  method?: string;
  path: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  /** Whole-request deadline; the broker's own budgets are much longer. */
  timeoutMs?: number;
}

export class HttpResponse {
  constructor(
    readonly status: number,
    readonly headers: Record<string, string | string[] | undefined>,
    readonly body: Buffer,
  ) {}

  get text(): string {
    return this.body.toString('utf8');
  }

  json<T = unknown>(): T {
    try {
      return JSON.parse(this.text) as T;
    } catch {
      throw new Error(`response body is not JSON (${this.status}): ${this.text.slice(0, 400)}`);
    }
  }

  header(name: string): string | undefined {
    const value = this.headers[name.toLowerCase()];
    return Array.isArray(value) ? value[0] : value;
  }

  /** The `{reason}` of a broker error body, or undefined for anything else. */
  get reason(): string | undefined {
    try {
      const body = this.json<{ reason?: string }>();
      return typeof body.reason === 'string' ? body.reason : undefined;
    } catch {
      return undefined;
    }
  }
}

export async function request(options: RequestOptions): Promise<HttpResponse> {
  const { socketPath, host, port, method = 'GET', path, headers = {}, body } = options;
  const timeoutMs = options.timeoutMs ?? 30_000;
  const payload = body === undefined ? undefined : Buffer.from(body);
  // Unix-socket HTTP still needs a Host header; `localhost` is what the
  // broker's own instructions tell agents to send.
  const sent: Record<string, string> = { host: 'localhost', ...headers };
  if (payload) sent['content-length'] = String(payload.byteLength);

  return new Promise<HttpResponse>((resolve, reject) => {
    const req = nodeRequest(
      {
        socketPath,
        host: socketPath ? undefined : (host ?? '127.0.0.1'),
        port: socketPath ? undefined : port,
        method,
        path,
        headers: sent,
      },
      (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve(
            new HttpResponse(
              res.statusCode ?? 0,
              res.headers as Record<string, string | string[] | undefined>,
              Buffer.concat(chunks),
            ),
          );
        });
        res.on('error', reject);
      },
    );
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`request timed out: ${method} ${path}`)));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

export async function json(
  options: RequestOptions & { json?: unknown },
): Promise<HttpResponse> {
  const { json: payload, ...rest } = options;
  if (payload === undefined) return request(rest);
  return request({
    ...rest,
    headers: { 'content-type': 'application/json', ...(rest.headers ?? {}) },
    body: JSON.stringify(payload),
  });
}

/* --------------------------------- SSE ----------------------------------- */

export interface SseFrame {
  id?: string;
  event?: string;
  data: string;
}

export interface SseStream {
  /** Response headers of the stream's own HTTP response. */
  headers: Record<string, string | string[] | undefined>;
  /** Frames received so far, oldest first. */
  frames: SseFrame[];
  /** Resolve once a frame satisfying `predicate` arrives (or reject on timeout). */
  waitFor(predicate: (frame: SseFrame) => boolean, timeoutMs?: number): Promise<SseFrame>;
  close(): void;
}

/** Open a server-sent-events stream and collect its frames in the background. */
export async function sse(options: RequestOptions): Promise<SseStream> {
  const { socketPath, host, port, path, headers = {} } = options;
  return new Promise<SseStream>((resolve, reject) => {
    const req = nodeRequest(
      {
        socketPath,
        host: socketPath ? undefined : (host ?? '127.0.0.1'),
        port: socketPath ? undefined : port,
        method: 'GET',
        path,
        headers: { host: 'localhost', accept: 'text/event-stream', ...headers },
      },
      (res: IncomingMessage) => {
        if ((res.statusCode ?? 0) !== 200) {
          res.resume();
          reject(new Error(`event stream refused with HTTP ${res.statusCode}`));
          return;
        }
        const frames: SseFrame[] = [];
        const waiters: Array<{
          predicate: (frame: SseFrame) => boolean;
          resolve: (frame: SseFrame) => void;
        }> = [];
        let buffer = '';

        const deliver = (frame: SseFrame): void => {
          frames.push(frame);
          for (let i = waiters.length - 1; i >= 0; i -= 1) {
            const waiter = waiters[i];
            if (waiter.predicate(frame)) {
              waiters.splice(i, 1);
              waiter.resolve(frame);
            }
          }
        };

        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          buffer += chunk;
          let boundary = buffer.indexOf('\n\n');
          while (boundary !== -1) {
            const block = buffer.slice(0, boundary);
            buffer = buffer.slice(boundary + 2);
            const frame: SseFrame = { data: '' };
            const data: string[] = [];
            for (const line of block.split('\n')) {
              if (line.startsWith(':')) continue; // comment (the ready ping)
              if (line.startsWith('id:')) frame.id = line.slice(3).trim();
              else if (line.startsWith('event:')) frame.event = line.slice(6).trim();
              else if (line.startsWith('data:')) data.push(line.slice(5).trim());
            }
            frame.data = data.join('\n');
            if (frame.data !== '' || frame.event !== undefined) deliver(frame);
            boundary = buffer.indexOf('\n\n');
          }
        });
        res.on('error', () => {});

        resolve({
          headers: res.headers as Record<string, string | string[] | undefined>,
          frames,
          waitFor(predicate, timeoutMs = 10_000) {
            const existing = frames.find(predicate);
            if (existing) return Promise.resolve(existing);
            return new Promise<SseFrame>((resolveFrame, rejectFrame) => {
              const timer = setTimeout(() => {
                rejectFrame(new Error('timed out waiting for an event-stream frame'));
              }, timeoutMs);
              waiters.push({
                predicate,
                resolve: (frame) => {
                  clearTimeout(timer);
                  resolveFrame(frame);
                },
              });
            });
          },
          close() {
            res.destroy();
            req.destroy();
          },
        });
      },
    );
    req.on('error', reject);
    req.end();
  });
}

/* ------------------------------- utilities -------------------------------- */

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Poll `probe` until it returns a value, or throw after `timeoutMs`. */
export async function waitFor<T>(
  what: string,
  probe: () => Promise<T | undefined> | (T | undefined),
  timeoutMs = 10_000,
  intervalMs = 50,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  for (;;) {
    try {
      const value = await probe();
      if (value !== undefined) return value;
    } catch (error) {
      lastError = error;
    }
    if (Date.now() > deadline) {
      const detail = lastError instanceof Error ? `: ${lastError.message}` : '';
      throw new Error(`timed out waiting for ${what}${detail}`);
    }
    await sleep(intervalMs);
  }
}
