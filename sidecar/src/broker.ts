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
  /** Whether *this* agent may use it. The broker decides; we only report. */
  wired: boolean;
  /** Set when this upstream speaks MCP at that path, e.g. `/mcp`. */
  mcp_path?: string | null;
  /** Curated upstream MCP tool subset for this agent; absent means all. */
  allowed_tools?: string[] | null;
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

export class BrokerClient {
  constructor(private readonly socketPath: string) {}

  private call(
    method: string,
    path: string,
    auth: AgentAuth,
    body?: unknown,
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
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  private async json<T>(method: string, path: string, auth: AgentAuth, body?: unknown): Promise<T> {
    const response = await this.call(method, path, auth, body);
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
   * The wiring check happens on the far side of this call, which is the
   * point: the sidecar cannot skip it, and a bug here cannot widen access.
   */
  async invoke(path: string, auth: AgentAuth, body: unknown): Promise<unknown> {
    return this.json<unknown>('POST', path, auth, body);
  }

  /**
   * Park one upstream elicitation on the user and wait for the answer.
   *
   * An upstream MCP server that needs interactive input mid tool call
   * (SEP-2322) cannot be answered by the sidecar or the agent — the user
   * answers it in the AgentMFA app. This call blocks until they do (or it
   * lapses), and returns the answer as an MCP `ElicitResult`. The wiring
   * check is the broker's, like every other call here.
   */
  async elicit(
    auth: AgentAuth,
    request: { connection: string; correlationToken: string },
  ): Promise<{ action: string; content?: Record<string, unknown> }> {
    return this.json<{ action: string; content?: Record<string, unknown> }>(
      'POST',
      '/v1/elicit',
      auth,
      {
        connection: request.connection,
        correlation_token: request.correlationToken,
      },
    );
  }
}
