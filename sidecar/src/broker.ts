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

export interface BrokerConnection {
  name: string;
  /** `http` | `pg` | `ssh` | `ws` — the broker's own type names. */
  type: string;
  target: string;
  /** Control-plane path a call against this connection goes to. */
  endpoint: string;
  /** Whether *this* agent may use it. The broker decides; we only report. */
  wired: boolean;
  /** Set when this upstream speaks MCP at that path, e.g. `/mcp`. */
  mcp_path?: string | null;
}

/** A non-2xx from the broker, carried through with its status intact. */
export class BrokerError extends Error {
  constructor(
    readonly status: number,
    readonly reason: string,
    readonly detail?: string,
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
    token: string,
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
            authorization: `Bearer ${token}`,
            accept: 'application/json',
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

  private async json<T>(method: string, path: string, token: string, body?: unknown): Promise<T> {
    const response = await this.call(method, path, token, body);
    let parsed: unknown = null;
    try {
      parsed = response.body ? JSON.parse(response.body) : null;
    } catch {
      throw new BrokerError(response.status, 'invalid_response', 'the broker returned malformed JSON');
    }
    if (response.status < 200 || response.status >= 300) {
      const error = (parsed ?? {}) as { reason?: string; detail?: string };
      throw new BrokerError(response.status, error.reason ?? 'broker_error', error.detail);
    }
    return parsed as T;
  }

  /** Resolve a bearer token to the agent behind it, or throw. */
  async whoami(token: string): Promise<BrokerIdentity> {
    const body = await this.json<{ client_id: string; agent: string }>(
      'GET',
      '/v1/whoami',
      token,
    );
    return { clientId: body.client_id, agent: body.agent };
  }

  /** Every connection the broker knows, each flagged for this agent. */
  async connections(token: string): Promise<BrokerConnection[]> {
    return this.json<BrokerConnection[]>('GET', '/v1/connections', token);
  }

  /**
   * Call a data plane on the agent's behalf.
   *
   * The wiring check happens on the far side of this call, which is the
   * point: the sidecar cannot skip it, and a bug here cannot widen access.
   */
  async invoke(path: string, token: string, body: unknown): Promise<unknown> {
    return this.json<unknown>('POST', path, token, body);
  }
}
