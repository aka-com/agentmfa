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
import { z } from 'zod';

import { log } from './log';
import { describe, invoke, schemaFor, toolNameFor } from './tools';
import {
  callUpstreamTool,
  listUpstreamTools,
  upstreamToolName,
  type UpstreamTool,
} from './upstream-mcp';

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

/** What a single wired connection actually contributed to the tool surface. */
interface Registration {
  connection: BrokerConnection;
  /** The MCP tool names registered for it — one, several, or (on failure) none. */
  tools: string[];
  /** Set when an MCP upstream could not be reached at session open. */
  error?: string;
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

  // Per-connection registration outcomes, filled in by the loop below and
  // read by `multitool_status`. An MCP upstream contributes many tool names
  // (or none plus an error, when it is unreachable); a plain connection
  // contributes exactly one. Status must report the names actually
  // registered, not what a naming convention would guess them to be.
  const registrations: Registration[] = [];

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
      const liveNames = new Set(live.map((connection) => connection.name));
      const registeredNames = new Set(
        registrations.map((registration) => registration.connection.name),
      );

      // Report the tools actually registered for connections that are still
      // wired — an MCP upstream by each of its own tool names, a plain
      // connection by its one. A connection unwired since session open drops
      // out (the broker would refuse it now); one wired since shows as pending.
      const tools = registrations
        .filter((registration) => liveNames.has(registration.connection.name))
        .flatMap((registration) =>
          registration.tools.map((tool) => ({
            tool,
            name: registration.connection.name,
            type: registration.connection.type,
            target: registration.connection.target,
          })),
        );

      // Upstreams that were wired but unreachable when the session opened:
      // their tools are absent above, so naming them here is how a confused
      // agent learns the connection exists but is unavailable this session.
      const errors = registrations
        .filter(
          (registration) =>
            registration.error && liveNames.has(registration.connection.name),
        )
        .map((registration) => ({
          name: registration.connection.name,
          error: registration.error,
        }));

      const pending = live
        .filter((connection) => !registeredNames.has(connection.name))
        .map((connection) => connection.name);

      // One hint, chosen by what is most actionable. Reconnecting re-runs this
      // whole build, so it resolves both pending wirings and dead upstreams.
      let hint: string | undefined;
      if (live.length === 0) {
        hint =
          'This agent is not wired to any tools yet. Ask the user to open ' +
          'Multitool, find the tool under Tools, and wire this agent ' +
          `("${principal.agent}") to it.`;
      } else if (pending.length) {
        hint =
          `Wired since this session started: ${pending.join(', ')}. ` +
          'Reconnect to Multitool to use them.';
      } else if (errors.length) {
        hint =
          `Wired but unreachable this session: ${errors
            .map((entry) => entry.name)
            .join(', ')}. Reconnect once the server is reachable to use ` +
          'their tools.';
      }

      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify(
              {
                agent: principal.agent,
                tools,
                ...(errors.length ? { errors } : {}),
                ...(pending.length ? { pending } : {}),
                ...(hint ? { hint } : {}),
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
    // An MCP upstream contributes its own tools rather than one request
    // tool. Its traffic still rides the broker's HTTP plane, so the
    // credential stays where it belongs.
    if (connection.mcp_path) {
      const outcome = await registerUpstream(server, broker, principal, connection, taken);
      registrations.push({ connection, tools: outcome.tools, error: outcome.error });
      continue;
    }

    const toolName = toolNameFor(connection);
    if (taken.has(toolName)) {
      log('warn', 'skipping a connection whose tool name collides', {
        connection: connection.name,
        toolName,
      });
      // A dropped collision registers no tool; record that so status does
      // not advertise a name that isn't there.
      registrations.push({ connection, tools: [] });
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
    registrations.push({ connection, tools: [toolName] });
  }

  return server;
}

/**
 * What the agent is told about an upstream tool.
 *
 * The upstream's JSON Schema is inlined here because our own declared
 * schema is deliberately permissive — this is where the agent learns what
 * the tool actually takes.
 */
function describeUpstream(connection: BrokerConnection, tool: UpstreamTool): string {
  const base = tool.description ?? `${tool.name} via ${connection.name}`;
  if (!tool.inputSchema) return `${base} (via ${connection.name})`;
  return `${base} (via ${connection.name}). Parameters: ${JSON.stringify(tool.inputSchema)}`;
}

/** What re-exposing one upstream produced: the tool names it added, or why not. */
interface UpstreamRegistration {
  tools: string[];
  error?: string;
}

/**
 * Re-expose an upstream MCP server's tools under this connection's name.
 *
 * A server that cannot be reached costs its own tools and nothing else: the
 * session still opens, and `multitool_status` reports the failure (via the
 * returned `error`), because one unreachable upstream must not take down
 * every other tool the agent has.
 */
async function registerUpstream(
  server: McpServer,
  broker: BrokerClient,
  principal: Principal,
  connection: BrokerConnection,
  taken: Set<string>,
): Promise<UpstreamRegistration> {
  let tools: Awaited<ReturnType<typeof listUpstreamTools>> = [];
  try {
    tools = await listUpstreamTools(broker, principal.token, connection);
  } catch (error) {
    log('warn', 'could not list tools from an MCP upstream', {
      connection: connection.name,
      error: String(error),
    });
    return { tools: [], error: `could not reach the MCP server: ${String(error)}` };
  }

  // A curated wiring lists only its allowed subset. This mirrors what the
  // broker enforces on tools/call; hiding the rest keeps the agent's tool
  // budget honest and its failures unconfusing.
  if (connection.allowed_tools) {
    const allowed = new Set(connection.allowed_tools);
    tools = tools.filter((tool) => allowed.has(tool.name));
  }

  const registered: string[] = [];
  for (const tool of tools) {
    const toolName = upstreamToolName(connection, tool.name);
    if (taken.has(toolName)) {
      log('warn', 'skipping an upstream tool whose name collides', {
        connection: connection.name,
        tool: tool.name,
        toolName,
      });
      continue;
    }
    taken.add(toolName);

    server.registerTool(
      toolName,
      {
        title: tool.name,
        description: describeUpstream(connection, tool),
        // A permissive object, NOT `undefined`. With no schema the SDK
        // calls the handler with its `extra` (session id, request headers,
        // the agent's own Authorization) as the first argument — which we
        // would then forward to the upstream as tool arguments. Declaring a
        // schema keeps the callback's first argument the agent's arguments
        // and nothing else. Loose, so the upstream's own parameters pass
        // through unvalidated by us; the upstream validates them.
        inputSchema: z.looseObject({}),
      },
      async (args: Record<string, unknown>) => {
        try {
          const result = await callUpstreamTool(
            broker,
            principal.token,
            connection,
            tool.name,
            args ?? {},
          );
          // The upstream already speaks MCP, so its result is returned as
          // it stands rather than rewrapped.
          return result as { content: Array<{ type: 'text'; text: string }> };
        } catch (error) {
          return {
            isError: true,
            content: [
              {
                type: 'text' as const,
                text: `${connection.name} failed: ${String(error)}`,
              },
            ],
          };
        }
      },
    );
    registered.push(toolName);
  }
  return { tools: registered };
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
