// The sidecar's client for the broker's control plane.
//
// The sidecar holds no authority of its own. Every call here carries the
// *agent's* own bearer token — the same one it would use to talk to the
// broker directly — so identity and wiring are decided in exactly one
// place, by the broker, and the sidecar cannot widen anyone's access by
// getting something wrong. It is a translator, not a gate.

import { request } from 'node:http';

export interface BrokerIdentity {
  clientId: string;
  agent: string;
}

/**
 * What broker calls authenticate as: the shared key, plus the caller's
 * self-reported label, forwarded so the user's activity log names the real
 * client instead of the generic fallback. The label is cosmetic — the
 * broker treats it as attribution, never authorization.
 */
export interface AgentAuth {
  token: string;
  label?: string;
}

export interface BrokerConnection {
  name: string;
  /** `http` | `pg` | `ssh` — the broker's own type names. */
  type: string;
  target: string;
  /** Control-plane path a call against this connection goes to. */
  endpoint: string;
  /** Whether agents may use it. Access is connection-wide; we only report. */
  wired: boolean;
  /** Set when this upstream speaks MCP at that path, e.g. `/mcp`. */
  mcp_path?: string | null;
  /** Curated upstream MCP tool subset for this connection; absent means all. */
  allowed_tools?: string[] | null;
  /** Whether this connection asks a human to confirm traffic. */
  confirm?: boolean;
}

/**
 * What a caller wants to know while a streamed call is still running.
 *
 * Deliberately narrow: the broker's stream carries facts about the *call*
 * (parked on a user, bytes arriving), and interpreting the bytes — finding an
 * upstream progress notification in them — is the caller's job, because only
 * the caller knows what protocol they are in.
 */
export interface StreamWatcher {
  /** The call is parked on a human decision. */
  onWaiting?: () => void;
  /** Body bytes, in arrival order, already redacted by the broker. */
  onBody?: (chunk: Buffer) => void;
}

/** One SSE block, or `null` when it carries no data line. */
function parseSseBlock(block: string): { event: string; data: unknown } | null {
  let event = 'message';
  const data: string[] = [];
  for (const line of block.replace(/\r\n/g, '\n').split('\n')) {
    if (line.startsWith('event:')) {
      event = line.slice('event:'.length).trim();
    } else if (line.startsWith('data:')) {
      const value = line.slice('data:'.length);
      data.push(value.startsWith(' ') ? value.slice(1) : value);
    }
  }
  if (!data.length) return null;
  try {
    return { event, data: JSON.parse(data.join('\n')) };
  } catch {
    return null;
  }
}

/** A non-2xx from the broker, carried through with its status intact. */
export class BrokerError extends Error {
  constructor(
    readonly status: number,
    readonly reason: string,
    readonly detail?: string,
    /** Seconds to back off, from a 429's `retry_after_seconds` body field. */
    readonly retryAfterSeconds?: number,
  ) {
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = 'BrokerError';
  }
}

interface RawResponse {
  status: number;
  body: string;
}

export interface BrokerCallTimeouts {
  controlMs: number;
  upstreamMs: number;
  elicitationMs: number;
}

const DEFAULT_TIMEOUTS: BrokerCallTimeouts = {
  controlMs: 10_000,
  // The broker's complete upstream-operation budget is 120 seconds.
  upstreamMs: 130_000,
  // The broker may wait five minutes for a person to answer an elicitation.
  elicitationMs: 310_000,
};

export class BrokerClient {
  constructor(
    private readonly socketPath: string,
    private readonly timeouts: BrokerCallTimeouts = DEFAULT_TIMEOUTS,
  ) {}

  private timeoutFor(path: string): number {
    if (path === '/v1/elicit') return this.timeouts.elicitationMs;
    if (path === '/v1/http') return this.timeouts.upstreamMs;
    return this.timeouts.controlMs;
  }

  private call(
    method: string,
    path: string,
    auth: AgentAuth,
    body?: unknown,
    signal?: AbortSignal,
  ): Promise<RawResponse> {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
    return new Promise((resolve, reject) => {
      const req = request(
        {
          socketPath: this.socketPath,
          path,
          method,
          headers: {
            authorization: `Bearer ${auth.token}`,
            accept: 'application/json',
            ...(auth.label ? { 'x-agentmfa-client': auth.label } : {}),
            ...(payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () =>
            resolve({
              status: res.statusCode ?? 0,
              body: Buffer.concat(chunks).toString('utf8'),
            }),
          );
        },
      );
      req.setTimeout(this.timeoutFor(path), () => {
        req.destroy(
          new Error(
            `AgentMFA broker call ${method} ${path} timed out after ` +
              `${this.timeoutFor(path)}ms`,
          ),
        );
      });
      req.on('error', reject);
      const abort = () => req.destroy(signal?.reason ?? new Error('request cancelled'));
      if (signal?.aborted) {
        abort();
      } else {
        signal?.addEventListener('abort', abort, { once: true });
      }
      req.on('close', () => signal?.removeEventListener('abort', abort));
      if (payload) req.write(payload);
      req.end();
    });
  }

  private async json<T>(
    method: string,
    path: string,
    auth: AgentAuth,
    body?: unknown,
    signal?: AbortSignal,
  ): Promise<T> {
    const response = await this.call(method, path, auth, body, signal);
    let parsed: unknown = null;
    try {
      parsed = response.body ? JSON.parse(response.body) : null;
    } catch {
      throw new BrokerError(response.status, 'invalid_response', 'the broker returned malformed JSON');
    }
    if (response.status < 200 || response.status >= 300) {
      const error = (parsed ?? {}) as {
        reason?: string;
        detail?: string;
        retry_after_seconds?: number;
      };
      throw new BrokerError(
        response.status,
        error.reason ?? 'broker_error',
        error.detail,
        error.retry_after_seconds,
      );
    }
    return parsed as T;
  }

  /** Resolve a bearer token (plus its self-reported label), or throw. */
  async whoami(auth: AgentAuth): Promise<BrokerIdentity> {
    const body = await this.json<{ client_id: string; agent: string }>(
      'GET',
      '/v1/whoami',
      auth,
    );
    return { clientId: body.client_id, agent: body.agent };
  }

  /** Every connection the broker knows, each flagged for agent access. */
  async connections(auth: AgentAuth): Promise<BrokerConnection[]> {
    return this.json<BrokerConnection[]>('GET', '/v1/connections', auth);
  }

  /**
   * Ask the user (through the broker and the app) to connect a service
   * that is not configured. Advisory: nothing is granted by this call.
   */
  async requestConnect(
    auth: AgentAuth,
    service: string,
  ): Promise<{ status: string; detail?: string }> {
    return this.json<{ status: string; detail?: string }>(
      'POST',
      '/v1/connect-requests',
      auth,
      { service },
    );
  }

  /**
   * Call a data plane on the agent's behalf.
   *
   * The connection-access check happens on the far side of this call. The
   * sidecar cannot skip it, and a bug here cannot widen access.
   */
  async invoke(
    path: string,
    auth: AgentAuth,
    body: unknown,
    signal?: AbortSignal,
  ): Promise<unknown> {
    return this.json<unknown>('POST', path, auth, body, signal);
  }

  /**
   * Call `/v1/http` and watch it happen, rather than waiting for one object.
   *
   * The broker answers a streamed call as `text/event-stream`: `waiting` while
   * a confirmation is on screen, `head` when the upstream answers, `chunk` for
   * body bytes, then `end` — or a single terminal `error`. Body chunks are
   * handed to `onBody` as they arrive so a caller watching an upstream SSE
   * stream can act on a notification before the response frame exists, and the
   * accumulated body is returned in exactly the buffered shape so callers that
   * only want the answer are unchanged.
   */
  async invokeStreamed(
    auth: AgentAuth,
    body: unknown,
    watch: StreamWatcher,
    signal?: AbortSignal,
  ): Promise<unknown> {
    const chunks: Buffer[] = [];
    let head: { status?: number; headers?: Record<string, string> } | undefined;
    let trailer: Record<string, unknown> = {};
    let failure: BrokerError | undefined;
    const { status } = await this.stream(
      '/v1/http',
      auth,
      { ...(body as Record<string, unknown>), stream: true },
      (event, data) => {
        switch (event) {
          case 'waiting':
            watch.onWaiting?.();
            break;
          case 'head':
            head = data as { status?: number; headers?: Record<string, string> };
            break;
          case 'chunk': {
            const chunk = Buffer.from(String((data as { b64?: string }).b64 ?? ''), 'base64');
            chunks.push(chunk);
            watch.onBody?.(chunk);
            break;
          }
          case 'end':
            // The call's own record, carrying whatever the broker attached
            // after the relay — the elicitation permits an interactive result
            // mints, which a buffered answer would have had in its envelope.
            trailer = (data ?? {}) as Record<string, unknown>;
            break;
          case 'error': {
            const failed = data as { status?: number; body?: { reason?: string; detail?: string } };
            failure = new BrokerError(
              failed.status ?? 500,
              failed.body?.reason ?? 'broker_error',
              failed.body?.detail,
            );
            break;
          }
          default:
            break;
        }
      },
      signal,
    );
    if (failure) throw failure;
    if (status < 200 || status >= 300) {
      throw new BrokerError(status, 'broker_error', 'the broker refused the streamed call');
    }
    if (!head) {
      // The stream ended without ever committing to an answer. Saying so beats
      // handing back an empty body that reads like a successful empty response.
      throw new BrokerError(502, 'upstream_error', 'the broker stream ended before the upstream answered');
    }
    return {
      status: head.status,
      headers: head.headers,
      body: Buffer.concat(chunks).toString('base64'),
      body_encoding: 'base64',
      ...(trailer.elicitation_tokens
        ? { elicitation_tokens: trailer.elicitation_tokens }
        : {}),
    };
  }

  /**
   * POST and deliver each SSE frame as it arrives.
   *
   * The parser is incremental on purpose: buffering to the end would make the
   * whole exercise pointless, and the frames that matter (a `waiting`, an
   * upstream progress notification) are the ones that arrive before it.
   */
  private stream(
    path: string,
    auth: AgentAuth,
    body: unknown,
    onEvent: (event: string, data: unknown) => void,
    signal?: AbortSignal,
  ): Promise<{ status: number }> {
    const payload = Buffer.from(JSON.stringify(body));
    return new Promise((resolve, reject) => {
      const req = request(
        {
          socketPath: this.socketPath,
          path,
          method: 'POST',
          headers: {
            authorization: `Bearer ${auth.token}`,
            accept: 'text/event-stream',
            ...(auth.label ? { 'x-agentmfa-client': auth.label } : {}),
            'content-type': 'application/json',
            'content-length': payload.length,
          },
        },
        (res) => {
          const status = res.statusCode ?? 0;
          let pending = '';
          res.on('data', (chunk: Buffer) => {
            pending += chunk.toString('utf8');
            let boundary = pending.indexOf('\n\n');
            while (boundary !== -1) {
              const block = pending.slice(0, boundary);
              pending = pending.slice(boundary + 2);
              const parsed = parseSseBlock(block);
              if (parsed) onEvent(parsed.event, parsed.data);
              boundary = pending.indexOf('\n\n');
            }
          });
          res.on('end', () => resolve({ status }));
          res.on('error', reject);
        },
      );
      // The inactivity timeout is the right one for a stream: a transfer that
      // keeps delivering bytes is healthy however long it runs, and a stalled
      // one is not rescued by a longer total budget.
      req.setTimeout(this.timeouts.upstreamMs, () => {
        req.destroy(new Error(`AgentMFA broker stream ${path} stalled for ${this.timeouts.upstreamMs}ms`));
      });
      req.on('error', reject);
      const abort = () => req.destroy(signal?.reason ?? new Error('request cancelled'));
      if (signal?.aborted) abort();
      else signal?.addEventListener('abort', abort, { once: true });
      req.on('close', () => signal?.removeEventListener('abort', abort));
      req.write(payload);
      req.end();
    });
  }

  /**
   * Park one upstream elicitation on the user and wait for the answer.
   *
   * An upstream MCP server that needs interactive input mid tool call
   * (SEP-2322) cannot be answered by the sidecar or the agent — the user
   * answers it in the AgentMFA app. This call blocks until they do (or it
   * lapses), and returns the answer as an MCP `ElicitResult`. The access
   * check is the broker's, like every other call here.
   */
  async elicit(
    auth: AgentAuth,
    request: { connection: string; correlationToken: string },
    signal?: AbortSignal,
  ): Promise<{ action: string; content?: Record<string, unknown> }> {
    return this.json<{ action: string; content?: Record<string, unknown> }>(
      'POST',
      '/v1/elicit',
      auth,
      {
        connection: request.connection,
        correlation_token: request.correlationToken,
      },
      signal,
    );
  }

  /** Cancel a broker-side elicitation whose downstream MCP call was abandoned. */
  async cancelElicitation(
    auth: AgentAuth,
    request: { connection: string; correlationToken: string },
  ): Promise<void> {
    await this.json(
      'POST',
      '/v1/elicit/cancel',
      auth,
      {
        connection: request.connection,
        correlation_token: request.correlationToken,
      },
    );
  }
}
