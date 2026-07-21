// The Multitool MCP host.
//
// A reimplementation of executor's serving envelope, kept to the same two
// seams their `host-mcp` reduces it to:
//
//   * an auth provider, consulted on EVERY request — here it resolves the
//     agent's own broker token to an identity by asking the broker;
//   * a session store owning the serving-session lifecycle, with sessions
//     belonging to the principal that created them.
//
// Ours is deliberately thinner than theirs because our authorization story
// is simpler and stricter: there is no org/tenant model, and no decision is
// ever made here. `tools/list` reports what the broker says this agent is
// wired to; `tools/call` refuses anything the broker has not wired. The
// sidecar cannot grant access it was not handed.

import { randomUUID } from 'node:crypto';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

import { BrokerClient, BrokerError, type BrokerConnection, type BrokerIdentity } from './broker';

export const MCP_PATH = '/mcp';

/**
 * Reject a request whose `Host` is not the loopback address we bound.
 *
 * The bearer token already stops a web page from doing anything useful,
 * but the port is guessable and defence in depth is cheap. The SDK's own
 * `allowedHosts` compares against the host *including the port*, which is
 * ephemeral and unknown when the transport is built — so the check lives
 * here, where the accepting socket knows which port it answered on.
 */
export function hostIsLoopback(host: string | undefined, localPort: number): boolean {
  if (!host) return false;
  return (
    host === `127.0.0.1:${localPort}` ||
    host === `localhost:${localPort}` ||
    host === `[::1]:${localPort}`
  );
}

/** What a request has proven about its caller. */
export interface Principal extends BrokerIdentity {
  /** The token itself, reused for the broker calls made on its behalf. */
  token: string;
}

/**
 * Seam 1 — authenticate and authorize on every request.
 *
 * Deliberately no caching: a token the user revoked in the app must stop
 * working on the next call, not when a TTL happens to lapse.
 */
export class BrokerAuthProvider {
  constructor(private readonly broker: BrokerClient) {}

  async authenticate(token: string | null): Promise<Principal | null> {
    if (!token) return null;
    try {
      const identity = await this.broker.whoami(token);
      return { ...identity, token };
    } catch (error) {
      if (error instanceof BrokerError && (error.status === 401 || error.status === 403)) {
        return null;
      }
      throw error;
    }
  }
}

/** Sessions belong to the principal that created them. */
interface Session {
  transport: StreamableHTTPServerTransport;
  clientId: string;
  lastSeen: number;
}

/** An abandoned session is closed after this long without a request. */
export const SESSION_IDLE_MS = 30 * 60 * 1000;
/** Hard ceiling; the least recently used session goes first. */
export const SESSION_LIMIT = 256;

/**
 * Seam 2 — the serving-session lifecycle.
 *
 * Ownership is checked on every reuse: a leaked `mcp-session-id` is useless
 * to another agent, because the token still has to resolve to the client id
 * that opened it.
 *
 * Sessions are also evicted when idle or when too many pile up. Only a
 * clean shutdown closes a transport, and agents crash — without eviction a
 * sidecar that runs for weeks accumulates every session it ever served.
 * Sweeping on write keeps this timer-free, so nothing here holds the
 * process open.
 */
export class SessionStore {
  private readonly sessions = new Map<string, Session>();

  constructor(
    private readonly idleMs: number = SESSION_IDLE_MS,
    private readonly limit: number = SESSION_LIMIT,
  ) {}

  get(id: string, clientId: string): StreamableHTTPServerTransport | null {
    const session = this.sessions.get(id);
    if (!session) return null;
    // Not "not found" — a session that exists but belongs to someone else
    // must not be usable, and must not be distinguishable either.
    if (session.clientId !== clientId) return null;
    session.lastSeen = Date.now();
    return session.transport;
  }

  put(id: string, clientId: string, transport: StreamableHTTPServerTransport): void {
    this.sweep();
    this.sessions.set(id, { transport, clientId, lastSeen: Date.now() });
  }

  delete(id: string): void {
    this.sessions.delete(id);
  }

  get size(): number {
    return this.sessions.size;
  }

  /** Drop idle sessions, then the oldest ones if still over the limit. */
  private sweep(): void {
    const cutoff = Date.now() - this.idleMs;
    for (const [id, session] of this.sessions) {
      if (session.lastSeen < cutoff) this.close(id, session);
    }
    if (this.sessions.size < this.limit) return;

    const oldest = [...this.sessions.entries()].sort(
      (a, b) => a[1].lastSeen - b[1].lastSeen,
    );
    for (const [id, session] of oldest.slice(0, this.sessions.size - this.limit + 1)) {
      this.close(id, session);
    }
  }

  private close(id: string, session: Session): void {
    this.sessions.delete(id);
    // The transport's own onclose also deletes; already gone is harmless.
    void Promise.resolve(session.transport.close()).catch(() => {});
  }
}

/** The MCP tool name for a connection. Kept stable and legible. */
export function toolNameFor(connection: BrokerConnection): string {
  return `multitool_${connection.name}`.replace(/[^a-zA-Z0-9_-]/g, '_');
}

/**
 * Build the tool surface for one agent.
 *
 * Phase 2 exposes description only — the data planes arrive in phase 3.
 * What is real here is the gate: unwired connections are not listed, and
 * naming one anyway is refused.
 */
export function createToolServer(broker: BrokerClient, principal: Principal): McpServer {
  const server = new McpServer(
    { name: 'multitool', version: '0.1.0' },
    {
      instructions:
        'Multitool brokers database, SSH, and API access. Tools appear here only ' +
        'when the user has wired this agent to them in the Multitool app.',
    },
  );

  server.registerTool(
    'multitool_list_tools',
    {
      title: 'List Multitool tools',
      description:
        'List the tools this agent is wired to, with what each one connects to. ' +
        'Tools the user has not wired are not returned.',
      inputSchema: {},
    },
    async () => {
      const connections = await broker.connections(principal.token);
      const wired = connections.filter((connection) => connection.wired);
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              wired.map((connection) => ({
                tool: toolNameFor(connection),
                name: connection.name,
                type: connection.type,
                target: connection.target,
              })),
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  server.registerTool(
    'multitool_describe_tool',
    {
      title: 'Describe a Multitool tool',
      description: 'Describe one tool this agent is wired to.',
      inputSchema: { name: z.string().describe('The tool name as shown by multitool_list_tools') },
    },
    async ({ name }) => {
      const connections = await broker.connections(principal.token);
      const match = connections.find(
        (connection) => connection.name === name || toolNameFor(connection) === name,
      );

      // Unwired and unknown are answered the same way on purpose: an agent
      // should not be able to enumerate what the user has declined to wire.
      if (!match || !match.wired) {
        return {
          isError: true,
          content: [
            {
              type: 'text' as const,
              text:
                `No tool named "${name}" is available to this agent. ` +
                'Ask the user to wire it in the Multitool app.',
            },
          ],
        };
      }

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                tool: toolNameFor(match),
                name: match.name,
                type: match.type,
                target: match.target,
                endpoint: match.endpoint,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  return server;
}

/** Mint a transport + server pair for a new session. */
export async function openSession(
  broker: BrokerClient,
  principal: Principal,
  store: SessionStore,
): Promise<StreamableHTTPServerTransport> {
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    onsessioninitialized: (id) => store.put(id, principal.clientId, transport),
  });
  transport.onclose = () => {
    if (transport.sessionId) store.delete(transport.sessionId);
  };
  await createToolServer(broker, principal).connect(transport);
  return transport;
}
