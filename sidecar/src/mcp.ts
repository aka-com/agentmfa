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

import { BrokerClient, BrokerError, type BrokerConnection, type BrokerIdentity } from './broker';
import { log } from './log';
import { describe, invoke, schemaFor, toolNameFor } from './tools';

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

/**
 * Build the tool surface for one agent.
 *
 * Every connection the broker reports as wired becomes a tool; unwired
 * ones are never registered. The list is fixed for the life of the
 * session — a wiring changed in the app takes effect when the agent
 * reconnects, and the broker refuses anything stale in the meantime.
 */
export async function createToolServer(
  broker: BrokerClient,
  principal: Principal,
): Promise<McpServer> {
  const server = new McpServer(
    { name: 'multitool', version: '0.1.0' },
    {
      // Declared up front rather than implied by the first `registerTool`.
      // An agent wired to nothing has zero tools, and without this it would
      // meet `Method not found` on `tools/list` instead of an empty list.
      capabilities: { tools: {} },
      instructions:
        'Multitool brokers database, SSH, API and WebSocket access. Tools appear ' +
        'here only when the user has wired this agent to them in the Multitool ' +
        'app. Credentials are injected by the broker and never visible to you.',
    },
  );

  let connections: BrokerConnection[] = [];
  try {
    connections = await broker.connections(principal.token);
  } catch (error) {
    // A broker that cannot be listed yields a session with no tools rather
    // than a failed connection: the agent gets a usable, empty surface.
    log('warn', 'could not list connections', { error: String(error) });
  }

  const wired = connections.filter((candidate) => candidate.wired);

  // Always registered, for two reasons. It is what installs the MCP tool
  // handlers at all — a server with no tools answers `tools/list` with
  // "Method not found", which is a baffling thing for an agent wired to
  // nothing to meet. And it gives that agent somewhere to look: the reply
  // says who it is and what to ask the user for.
  server.registerTool(
    'multitool_status',
    {
      title: 'Multitool status',
      description:
        'Report which Multitool tools this agent can use, and what to do when ' +
        'there are none.',
      inputSchema: {},
    },
    async () => {
      // Deliberately re-queried rather than reported from the list captured
      // at session open: the user may have wired something since, and the
      // whole point of this tool is to answer "why can't I see it?".
      const live = (await broker.connections(principal.token)).filter(
        (candidate) => candidate.wired,
      );
      const registered = new Set(wired.map((connection) => connection.name));
      const pending = live
        .filter((connection) => !registered.has(connection.name))
        .map((connection) => connection.name);

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                agent: principal.agent,
                tools: live
                  .filter((connection) => registered.has(connection.name))
                  .map((connection) => ({
                    tool: toolNameFor(connection),
                    name: connection.name,
                    type: connection.type,
                    target: connection.target,
                  })),
                ...(pending.length
                  ? {
                      pending,
                      hint:
                        `Wired since this session started: ${pending.join(', ')}. ` +
                        'Reconnect to Multitool to use them.',
                    }
                  : {}),
                ...(live.length === 0
                  ? {
                      hint:
                        'This agent is not wired to any tools yet. Ask the user to ' +
                        'open Multitool, find the tool under Tools, and wire this ' +
                        `agent ("${principal.agent}") to it.`,
                    }
                  : {}),
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  // Connection names are freer than MCP tool names, so two of them can slug
  // to the same thing. Registering a duplicate throws, which would fail the
  // whole session — one awkwardly named connection must not cost an agent
  // every other tool it has.
  const taken = new Set<string>(['multitool_status']);
  for (const connection of wired) {
    const toolName = toolNameFor(connection);
    if (taken.has(toolName)) {
      log('warn', 'skipping a connection whose tool name collides', {
        connection: connection.name,
        toolName,
      });
      continue;
    }
    taken.add(toolName);

    server.registerTool(
      toolName,
      {
        title: connection.name,
        description: describe(connection),
        inputSchema: schemaFor(connection),
      },
      async (args: Record<string, unknown>) =>
        invoke(broker, principal.token, connection, args ?? {}),
    );
  }

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
  await (await createToolServer(broker, principal)).connect(transport);
  return transport;
}
