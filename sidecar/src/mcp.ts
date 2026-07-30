// The AgentMFA MCP host.
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
// ever made here. `tools/list` reports connections the broker says are
// enabled for agents; `tools/call` refuses anything the broker has disabled
// or excluded from a curated subset. The sidecar cannot grant access it was
// not handed.

import { randomUUID } from 'node:crypto';

import {
  McpServer,
  ResourceTemplate,
} from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { GetPromptResult, ReadResourceResult } from '@modelcontextprotocol/sdk/types.js';

import { BrokerClient, BrokerError, type BrokerConnection, type BrokerIdentity } from './broker';
import { z } from 'zod';

import { log } from './log';
import { describe, invoke, schemaFor, toolNameCandidateFor, toolNameFor } from './tools';
import {
  callUpstreamTool,
  completeUpstream,
  discoverUpstream,
  getUpstreamPrompt,
  namespaceFor,
  readUpstreamResource,
  upstreamToolName,
  upstreamToolNameCandidate,
  type CompletionContext,
  UpstreamRpcError,
  type UpstreamPrompt,
  type UpstreamResource,
  type UpstreamResourceTemplate,
  type UpstreamTool,
} from './upstream-mcp';
import { alternateToolName } from './tool-names';
import {
  ProtocolToolRegistry,
  type RegisteredProtocolTool,
  zodToolInput,
} from './tool-registry';
import {
  frameUntrustedText,
  sanitizeUntrustedText,
  sanitizeUpstreamResult,
} from './untrusted';
import { SIDECAR_VERSION } from './version';

export const MCP_PATH = '/mcp';

/**
 * How many upstream MCP tools are registered as first-class tools before
 * the rest become searchable-only. Big catalogs must not flood an agent's
 * context: beyond the budget, tools stay in the search index and are
 * callable through `agentmfa_call_tool` — enforcement is unchanged, the
 * broker still checks connection access and any curated subset on every call.
 */
function upstreamToolBudget(): number {
  // Read per session build (not at import) so tests and operators can
  // adjust it without a restart.
  const raw = Number(process.env.AGENTMFA_TOOL_BUDGET ?? 40);
  return Number.isFinite(raw) && raw >= 0 ? raw : 40;
}

/**
 * How many upstream resources and templates a session registers before the
 * rest are dropped. Resources live in their own list rather than the tool
 * surface, but a runaway catalog should still not balloon a session.
 */
function resourceBudget(): number {
  const raw = Number(process.env.AGENTMFA_RESOURCE_BUDGET ?? 100);
  return Number.isFinite(raw) && raw >= 0 ? raw : 100;
}

/**
 * How many upstream prompts a session registers before the rest are dropped.
 * Prompts are small, but a runaway catalog should not balloon a session any
 * more than a runaway tool list may.
 */
function promptBudget(): number {
  const raw = Number(process.env.AGENTMFA_PROMPT_BUDGET ?? 100);
  return Number.isFinite(raw) && raw >= 0 ? raw : 100;
}

/**
 * The resource surface shared across a session's connections: the URIs and
 * template names already claimed (so two upstreams cannot collide), and the
 * running budget count. Registered as one flat namespace, the way the SDK
 * keys resources by URI and templates by name.
 */
interface ResourceSurface {
  takenUris: Set<string>;
  takenTemplateNames: Set<string>;
  takenTemplateUris: Set<string>;
  registered: number;
  withheld: number;
}

interface UpstreamToolSurface {
  registered: number;
}

/** Prompt names claimed this session, and the running budget count. */
interface PromptSurface {
  takenNames: Set<string>;
  registered: number;
  withheld: number;
}

/** One upstream tool in the session's search index. */
interface IndexedTool {
  connection: BrokerConnection;
  tool: UpstreamTool;
  /** The registered MCP tool name, or null when over budget (search-only). */
  registeredAs: string | null;
}

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
  /** Self-reported client label, forwarded to the broker for attribution. */
  label?: string;
}

/**
 * Seam 1 — authenticate and authorize on every request.
 *
 * Deliberately no caching: a token the user revoked in the app must stop
 * working on the next call, not when a TTL happens to lapse.
 */
export class BrokerAuthProvider {
  constructor(private readonly broker: BrokerClient) {}

  async authenticate(token: string | null, label?: string): Promise<Principal | null> {
    if (!token) return null;
    try {
      const identity = await this.broker.whoami({ token, label });
      return { ...identity, token, label };
    } catch (error) {
      if (error instanceof BrokerError && (error.status === 401 || error.status === 403)) {
        return null;
      }
      throw error;
    }
  }
}

/** Sessions belong to the broker identity that created them. */
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
 * Ownership is checked on every reuse against the broker's `client_id`.
 * Production has one shared client id for every local agent, so this prevents
 * cross-broker reuse, not reuse by another process holding the same machine
 * key. Treat the session id as machine-scoped, not per-agent isolation.
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
    if (!session) {
      this.sweep();
      return null;
    }
    // Not "not found" — a session that exists but belongs to someone else
    // must not be usable, and must not be distinguishable either.
    if (session.clientId !== clientId) return null;
    session.lastSeen = Date.now();
    return session.transport;
  }

  put(id: string, clientId: string, transport: StreamableHTTPServerTransport): void {
    this.sweep(true);
    this.sessions.set(id, { transport, clientId, lastSeen: Date.now() });
  }

  delete(id: string): void {
    this.sessions.delete(id);
  }

  get size(): number {
    return this.sessions.size;
  }

  /** Drop idle sessions, then the oldest ones if still over the limit. */
  sweep(reserveSlot = false): void {
    const cutoff = Date.now() - this.idleMs;
    for (const [id, session] of this.sessions) {
      if (session.lastSeen < cutoff) this.close(id, session);
    }
    const allowed = Math.max(0, this.limit - (reserveSlot ? 1 : 0));
    if (this.sessions.size <= allowed) return;

    const oldest = [...this.sessions.entries()].sort(
      (a, b) => a[1].lastSeen - b[1].lastSeen,
    );
    for (const [id, session] of oldest.slice(0, this.sessions.size - allowed)) {
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
  /** Upstream tool names indexed but not registered (over the tool budget). */
  withheld?: string[];
  /** How many resources + templates this upstream contributed. */
  resources?: number;
  /** How many prompts this upstream contributed. */
  prompts?: number;
  /** Set when an MCP upstream could not be reached at session open. */
  error?: string;
  /** Non-fatal upstream state that explains an intentionally empty surface. */
  status?: 'no_tools_capability' | 'empty_tools' | 'no_allowed_tools';
  /** Non-fatal naming adjustments worth exposing to a diagnosing agent. */
  warnings?: string[];
}

/**
 * Build the tool surface for one agent.
 *
 * Every connection the broker reports as enabled becomes a tool; disabled
 * ones are never registered. Native connection tools reconcile during the
 * session. Upstream MCP catalogs are discovered once at session open and
 * require a reconnect to refresh.
 */
/// How often a session re-reads the wiring so its tool list can follow it.
/// Short enough that a user who switches a tool off sees the agent lose it
/// while they are still looking, long enough to be nothing on a local socket.
const WIRING_REFRESH_MS = 10_000;

/// Register one connection's `_request`/`_open` tool and hand back its handle,
/// so the surface can be reconciled later rather than only built once.
function registerNative(
  tools: ProtocolToolRegistry,
  broker: BrokerClient,
  principal: Principal,
  connection: BrokerConnection,
  toolName: string,
): RegisteredProtocolTool {
  const input = zodToolInput(schemaFor(connection));
  const outputSchema =
    connection.type === 'api'
      ? {
          type: 'object',
          properties: {
            status: { type: 'integer' },
            headers: { type: 'object' },
            body: { type: 'string' },
            body_encoding: { enum: ['utf8', 'base64'] },
          },
          additionalProperties: true,
        }
      : connection.type === 'pg'
        ? {
            type: 'object',
            properties: {
              dsn: { type: 'string' },
              ticket: { type: 'string' },
              expires_in_seconds: { type: 'integer' },
            },
            additionalProperties: true,
          }
        : {
            type: 'object',
            properties: {
              auth_sock: { type: 'string' },
              destination: { type: 'string' },
              host: { type: 'string' },
              port: { type: 'integer' },
              user: { type: 'string' },
              host_key_fingerprint: { type: ['string', 'null'] },
              expires_in_seconds: { type: 'integer' },
            },
            additionalProperties: true,
          };
  return tools.register(
    toolName,
    {
      title: connection.name,
      description: describe(connection),
      inputSchema: input.inputSchema,
      outputSchema,
      annotations: {
        idempotentHint: false,
        openWorldHint: connection.type === 'api',
      },
    },
    async (args) =>
      invoke(broker, principal, connection, args ?? {}),
    input.parse,
  );
}

export async function createToolServer(
  broker: BrokerClient,
  principal: Principal,
): Promise<McpServer> {
  const server = new McpServer(
    { name: 'agentmfa', version: SIDECAR_VERSION },
    {
      // Declared up front rather than implied by the first `registerTool`.
      // A broker with no enabled tools has zero tools, and without this it would
      // meet `Method not found` on `tools/list` instead of an empty list.
      //
      // `listChanged` is real: the per-connection tools below track the user's
      // access state for the life of the session (see `refreshWiring`), so a tool
      // that has been renamed away or switched off stops being offered instead
      // of sitting there answering 404 or 403 until the agent reconnects.
      // Prompts and resources are declared up front for the same reason
      // tools are: a server that registers none still has to answer their
      // list methods with an empty list rather than "method not found".
      capabilities: {
        tools: { listChanged: true },
        prompts: { listChanged: true },
        resources: { listChanged: true },
      },
      instructions:
        'AgentMFA brokers API, database, SSH, and Streamable-HTTP MCP access. ' +
        'Connections are enabled for all local agents by default when added; ' +
        'the user can disable them or curate an upstream MCP subset in the app. ' +
        'Credentials are injected by the broker and never visible to you. A ' +
        '`_request` tool accepts method, pinned-origin path, repeated headers, ' +
        'and either a UTF-8/JSON or base64 body; authentication, cookie, and ' +
        'hop-by-hop headers are reserved. Its bounded result is ' +
        '{status, headers, body, body_encoding}; use request_id on mutating ' +
        'retries. A `_open` tool returns a short-lived ticket and local endpoint. ' +
        'An upstream MCP server also contributes its own resources and prompts, ' +
        'namespaced by connection: list them with resources/list and prompts/list. ' +
        'Native connection tools refresh during this session; reconnect to ' +
        'refresh an upstream MCP catalog. Use agentmfa_status first when a tool ' +
        'is missing, and search/call meta-tools for catalog overflow.',
    },
  );
  const toolRegistry = new ProtocolToolRegistry(server);

  let connections: BrokerConnection[] = [];
  let connectionListError: string | undefined;
  try {
    connections = await broker.connections(principal);
  } catch (error) {
    connectionListError = `could not list AgentMFA connections: ${String(error)}`;
    log('warn', 'could not list connections', { error: String(error) });
  }

  const wired = connections.filter((candidate) => candidate.wired);

  // Per-connection registration outcomes, filled in by the loop below and
  // read by `agentmfa_status`. An MCP upstream contributes many tool names
  // (or none plus an error, when it is unreachable); a plain connection
  // contributes exactly one. Status must report the names actually
  // registered, not what a naming convention would guess them to be.
  const registrations: Registration[] = [];

  // Live handles for the per-connection native tools, keyed by tool name so a
  // rename reads as one name leaving and another arriving — which is exactly
  // what it is, since the tool name is derived from the connection's name.
  const native = new Map<string, RegisteredProtocolTool>();

  // Always registered, for two reasons. It is what installs the MCP tool
  // handlers at all — a server with no tools answers `tools/list` with
  // "Method not found", which is a baffling result when no connections are
  // enabled. It also gives the agent somewhere to look: the reply says what
  // is available and what to ask the user for.
  const statusInput = zodToolInput({});
  toolRegistry.register(
    'agentmfa_status',
    {
      title: 'AgentMFA status',
      description:
        'Report which AgentMFA tools this agent can use, and what to do when ' +
        'there are none.',
      inputSchema: statusInput.inputSchema,
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async () => {
      // Deliberately re-queried rather than reported from the list captured
      // at session open: the user may have changed connection access since,
      // and the whole point of this tool is to answer "why can't I see it?".
      // Asking also reconciles the tool list, so an agent that noticed
      // something was wrong does not wait for the next tick to have it fixed.
      if (await refreshWiring()) server.sendToolListChanged();
      let live = wired;
      try {
        live = (await broker.connections(principal)).filter(
          (candidate) => candidate.wired,
        );
        connectionListError = undefined;
      } catch (error) {
        connectionListError = `could not list AgentMFA connections: ${String(error)}`;
        log('warn', 'could not list connections for status', { error: String(error) });
      }
      const liveNames = new Set(live.map((connection) => connection.name));
      const registeredNames = new Set(
        registrations.map((registration) => registration.connection.name),
      );

      // Report the tools actually registered for connections still enabled
      // for agents — an MCP upstream by each of its own tool names, a plain
      // connection by its one. A connection disabled since session open drops
      // out; one enabled since shows as pending.
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
      const errors: Array<{ scope: string; name?: string; error: string }> = registrations
        .filter(
          (registration) =>
            registration.error && liveNames.has(registration.connection.name),
        )
        .map((registration) => ({
          scope: 'upstream',
          name: registration.connection.name,
          error: registration.error!,
        }));
      if (connectionListError) {
        errors.unshift({ scope: 'broker', error: connectionListError });
      }

      const upstreams = registrations
        .filter(
          (registration) =>
            registration.status && liveNames.has(registration.connection.name),
        )
        .map((registration) => ({
          name: registration.connection.name,
          status: registration.status,
        }));
      const warnings = registrations
        .filter(
          (registration) =>
            registration.warnings?.length && liveNames.has(registration.connection.name),
        )
        .flatMap((registration) =>
          registration.warnings!.map((warning) => ({
            name: registration.connection.name,
            warning,
          })),
        );

      const pending = live
        .filter((connection) => !registeredNames.has(connection.name))
        .map((connection) => connection.name);

      const searchOnly = registrations
        .filter((registration) => liveNames.has(registration.connection.name))
        .reduce((sum, registration) => sum + (registration.withheld?.length ?? 0), 0);

      const resources = registrations
        .filter((registration) => liveNames.has(registration.connection.name))
        .reduce((sum, registration) => sum + (registration.resources ?? 0), 0);

      const prompts = registrations
        .filter((registration) => liveNames.has(registration.connection.name))
        .reduce((sum, registration) => sum + (registration.prompts ?? 0), 0);

      // One hint, chosen by what is most actionable. Reconnecting re-runs this
      // whole build, so it resolves both pending wirings and dead upstreams.
      let hint: string | undefined;
      if (connectionListError) {
        hint =
          'AgentMFA could not list connections. Reconnect this MCP session after ' +
          'the broker is reachable or its retry delay has elapsed.';
      } else if (live.length === 0) {
        hint =
          'No tools are enabled for agents. Ask the user to open AgentMFA ' +
          'and enable or add the needed tool under Tools.';
      } else if (pending.length) {
        hint =
          `Enabled since this session started: ${pending.join(', ')}. ` +
          'Native tools refresh automatically; reconnect to refresh an upstream MCP catalog.';
      } else if (errors.length) {
        hint =
          `Enabled but unreachable this session: ${errors
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
                ...(resources
                  ? {
                      resources,
                      resource_hint:
                        'list them with resources/list and resources/templates/list',
                    }
                  : {}),
                ...(prompts
                  ? { prompts, prompt_hint: 'list them with prompts/list' }
                  : {}),
                ...(searchOnly
                  ? {
                      search_only_tools: searchOnly,
                      search_hint:
                        'more tools are available via agentmfa_search_tools',
                    }
                  : {}),
                ...(errors.length ? { errors } : {}),
                ...(upstreams.length ? { upstreams } : {}),
                ...(warnings.length ? { warnings } : {}),
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
    statusInput.parse,
  );

  // Connection names are freer than MCP tool names, so two of them can slug
  // to the same thing. Registering a duplicate throws, which would fail the
  // whole session — one awkwardly named connection must not cost an agent
  // every other tool it has.
  const taken = new Set<string>([
    'agentmfa_status', 'agentmfa_connect', 'agentmfa_search_tools', 'agentmfa_call_tool',
  ]);
  // Every upstream tool this session knows about, registered or not; the
  // search and generic-call meta-tools work over it.
  const upstreamIndex: IndexedTool[] = [];
  // Resources and templates share one flat namespace across connections,
  // keyed by URI (resources) and name (templates), with a shared budget.
  const resourceSurface: ResourceSurface = {
    takenUris: new Set<string>(),
    takenTemplateNames: new Set<string>(),
    takenTemplateUris: new Set<string>(),
    registered: 0,
    withheld: 0,
  };
  const upstreamToolSurface: UpstreamToolSurface = { registered: 0 };
  const promptSurface: PromptSurface = {
    takenNames: new Set<string>(),
    registered: 0,
    withheld: 0,
  };
  // Discovery is independent per upstream. Start every handshake together
  // and wait only for their bounded session-open attempts; registration below
  // remains deterministic in broker order after the promises settle.
  const discoveries = new Map<
    BrokerConnection,
    Promise<Awaited<ReturnType<typeof discoverUpstream>>>
  >();
  for (const connection of wired) {
    if (connection.mcp_path) {
      discoveries.set(
        connection,
        discoverUpstreamForSession(broker, principal, connection),
      );
    }
  }
  await Promise.allSettled(discoveries.values());

  for (const connection of wired) {
    // An MCP upstream contributes its own tools rather than one request
    // tool. Its traffic still rides the broker's HTTP plane, so the
    // credential stays where it belongs.
    if (connection.mcp_path) {
      const outcome = await registerUpstream(
        server, toolRegistry, broker, principal, connection, taken, upstreamIndex,
        upstreamToolSurface, resourceSurface, promptSurface,
        discoveries.get(connection)!,
      );
      registrations.push({
        connection,
        tools: outcome.tools,
        withheld: outcome.withheld,
        resources: outcome.resources,
        prompts: outcome.prompts,
        error: outcome.error,
        status: outcome.status,
        warnings: outcome.warnings,
      });
      continue;
    }

    const toolName = toolNameFor(connection);
    const namingWarnings =
      toolNameCandidateFor(connection).length > toolName.length
        ? [
            `connection name "${connection.name}" was shortened to bounded tool ` +
              `name "${toolName}"`,
          ]
        : undefined;
    if (namingWarnings) {
      log('warn', 'shortened a native MCP tool name', {
        connection: connection.name,
        toolName,
      });
    }
    if (taken.has(toolName)) {
      log('warn', 'skipping a connection whose tool name collides', {
        connection: connection.name,
        toolName,
      });
      // A dropped collision registers no tool; record that so status does
      // not advertise a name that isn't there.
      registrations.push({
        connection,
        tools: [],
        error: `tool name collided with another connection (${toolName})`,
      });
      continue;
    }
    taken.add(toolName);
    native.set(
      toolName,
      registerNative(toolRegistry, broker, principal, connection, toolName),
    );
    registrations.push({ connection, tools: [toolName], warnings: namingWarnings });
  }

  registerMetaTools(toolRegistry, broker, principal, upstreamIndex);

  /**
   * Bring the native per-connection tools back in line with current access.
   *
   * The surface used to be a snapshot taken at session open, so renaming a
   * connection left a tool whose calls 404 and switching one off left a tool
   * whose calls 403 — with nothing telling the agent why, and no way to find
   * out short of reconnecting. Only the native `_request`/`_open` tools are
   * reconciled: re-running MCP upstream discovery would cost several round
   * trips per connection per tick, and its tools are keyed on the upstream's
   * own catalogue rather than on connection access alone.
   *
   * Returns whether anything changed, so callers can decide about notifying.
   */
  async function refreshWiring(): Promise<boolean> {
    let live: BrokerConnection[];
    try {
      live = await broker.connections(principal);
      connectionListError = undefined;
    } catch (error) {
      // A failed listing is not evidence that the user unwired everything.
      // Leave the surface alone and try again on the next tick.
      log('warn', 'could not refresh the wiring', { error: String(error) });
      connectionListError = `could not list AgentMFA connections: ${String(error)}`;
      return false;
    }
    const desired = new Map<string, BrokerConnection>();
    for (const candidate of live) {
      if (!candidate.wired || candidate.mcp_path) continue;
      const name = toolNameFor(candidate);
      // First writer wins, matching the collision rule at session open.
      if (!desired.has(name)) desired.set(name, candidate);
    }

    let changed = false;
    for (const [toolName, handle] of [...native]) {
      if (desired.has(toolName)) continue;
      handle.remove();
      native.delete(toolName);
      taken.delete(toolName);
      changed = true;
    }
    for (const [toolName, connection] of desired) {
      if (native.has(toolName) || taken.has(toolName)) continue;
      taken.add(toolName);
      native.set(
        toolName,
        registerNative(toolRegistry, broker, principal, connection, toolName),
      );
      changed = true;
    }
    if (changed) {
      // Keep `agentmfa_status` honest about what is registered now: replace the
      // native rows wholesale, leaving the MCP upstream rows as discovered.
      for (let i = registrations.length - 1; i >= 0; i -= 1) {
        if (!registrations[i].connection.mcp_path) registrations.splice(i, 1);
      }
      for (const [toolName, connection] of desired) {
        registrations.push({ connection, tools: [toolName] });
      }
    }
    return changed;
  }

  // Poll rather than subscribe: the broker has no agent-facing change stream
  // yet, and `/v1/connections` over the local socket is cheap. `unref` keeps
  // the timer from holding the process open.
  const ticker = setInterval(() => {
    void refreshWiring().then((changed) => {
      if (changed) server.sendToolListChanged();
    });
  }, WIRING_REFRESH_MS);
  ticker.unref?.();
  server.server.onclose = () => clearInterval(ticker);

  return server;
}

/**
 * The discovery meta-tools.
 *
 * `agentmfa_connect` is always present: it is how an agent asks the user
 * for a tool that is not configured (a request only — the broker audits it
 * and pokes the app; nothing exists until the user adds and wires it).
 *
 * Search and the generic invoker appear once any upstream tool was
 * withheld over the registration budget, so big catalogs stay reachable
 * without flooding the agent's context. Every call still crosses the
 * broker's access and allowed-tools checks — these tools change
 * discovery, never authorization.
 */
function registerMetaTools(
  tools: ProtocolToolRegistry,
  broker: BrokerClient,
  principal: Principal,
  index: IndexedTool[],
): void {
  const connectInput = zodToolInput({ service: z.string().min(1).max(120) });
  tools.register(
    'agentmfa_connect',
    {
      title: 'Request a new tool',
      description:
        'Ask the user to connect a service that is not configured (for example ' +
        '"linear" or "https://mcp.example.com/mcp"). This only files a request in ' +
        'the AgentMFA app — the user adds and enables the tool there, and its ' +
        'tools appear on your next session (check with agentmfa_status).',
      inputSchema: connectInput.inputSchema,
      annotations: {
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (args) => {
      const { service } = args as { service: string };
      try {
        const outcome = await broker.requestConnect(principal, service);
        return {
          content: [{
            type: 'text' as const,
            text:
              outcome.status === 'already_requested'
                ? `Already requested. Ask the user to approve "${service}" in AgentMFA; ` +
                  'its tools appear once they add and enable it for agents.'
                : `Requested. Ask the user to add "${service}" in the AgentMFA app and ` +
                  'enable it for agents; then reconnect or call agentmfa_status.',
          }],
        };
      } catch (error) {
        return {
          isError: true,
          content: [{ type: 'text' as const, text: `could not file the request: ${String(error)}` }],
        };
      }
    },
    connectInput.parse,
  );

  const withheld = index.filter((entry) => entry.registeredAs === null);
  if (!withheld.length) return;

  const searchInput = zodToolInput({ query: z.string().min(1).max(200) });
  tools.register(
    'agentmfa_search_tools',
    {
      title: 'Search available tools',
      description:
        `${withheld.length} of this session's upstream tools are not listed here ` +
        '(tool-budget). Search them by name or purpose; call the results with ' +
        'agentmfa_call_tool (or directly, when a tool name is listed).',
      inputSchema: searchInput.inputSchema,
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (args) => {
      const { query } = args as { query: string };
      const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
      const scored = index
        .map((entry) => {
          const name = entry.tool.name.toLowerCase();
          const description = (entry.tool.description ?? '').toLowerCase();
          let score = 0;
          for (const term of terms) {
            if (name.includes(term)) score += 2;
            if (description.includes(term)) score += 1;
          }
          return { entry, score };
        })
        .filter(({ score }) => score > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, 20);
      const results = scored.map(({ entry }) => ({
        tool: entry.tool.name,
        connection: entry.connection.name,
        description: frameUntrustedText(entry.tool.description ?? '', 1024).text,
        ...(entry.tool.inputSchema
          ? {
              parameters: frameUntrustedText(
                JSON.stringify(entry.tool.inputSchema),
                4096,
              ).text,
            }
          : {}),
        call: entry.registeredAs
          ? { tool: entry.registeredAs }
          : {
              tool: 'agentmfa_call_tool',
              arguments: { connection: entry.connection.name, tool: entry.tool.name },
            },
      }));
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify(
            results.length ? { results } : { results, hint: 'no tools matched; try broader terms' },
            null,
            2,
          ),
        }],
      };
    },
    searchInput.parse,
  );

  const callInput = zodToolInput({
    connection: z.string().min(1),
    tool: z.string().min(1),
    arguments: z.looseObject({}).optional(),
  });
  tools.register(
    'agentmfa_call_tool',
    {
      title: 'Call a searchable tool',
      description:
        'Invoke an upstream tool found via agentmfa_search_tools, by connection ' +
        'and tool name. Subject to the same access and tool-selection checks as ' +
        'every other call.',
      inputSchema: callInput.inputSchema,
      annotations: { openWorldHint: true },
    },
    async (input, signal) => {
      const { connection, tool, arguments: args } = input as {
        connection: string;
        tool: string;
        arguments?: Record<string, unknown>;
      };
      const entry = index.find(
        (candidate) =>
          candidate.connection.name === connection && candidate.tool.name === tool,
      );
      if (!entry) {
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: `no such tool in this session: ${connection} / ${tool} — ` +
              'find callable tools with agentmfa_search_tools',
          }],
        };
      }
      try {
        const result = await callUpstreamTool(
          broker, principal, entry.connection, entry.tool.name, args ?? {}, signal,
        );
        return sanitizeUpstreamResult(result) as {
          content: Array<{ type: 'text'; text: string }>;
        };
      } catch (error) {
        return upstreamToolFailure(entry.connection, error);
      }
    },
    callInput.parse,
  );
}

/**
 * What the agent is told about an upstream tool.
 *
 * The schema itself is exposed in tools/list; the description only adds a
 * fixed provenance label around the upstream's untrusted prose.
 */
function describeUpstream(connection: BrokerConnection, tool: UpstreamTool): string {
  const base = tool.description ?? `${tool.name} via ${connection.name}`;
  const description = frameUntrustedText(base, 1024);
  const safeConnection = sanitizeUntrustedText(connection.name, 200).text;
  if (description.truncated) {
    log('warn', 'truncated an upstream MCP tool description', {
      connection: connection.name,
      tool: tool.name,
    });
  }
  return `Proxied from ${safeConnection}.\n${description.text}`;
}

function upstreamToolFailure(connection: BrokerConnection, error: unknown) {
  const payload =
    error instanceof UpstreamRpcError
      ? {
          connection: connection.name,
          error: {
            type: 'json_rpc',
            code: error.code,
            message: error.message,
            ...(error.data === undefined ? {} : { data: error.data }),
          },
        }
      : {
          connection: connection.name,
          error: { type: 'transport', message: String(error) },
        };
  return {
    isError: true,
    content: [
      {
        type: 'text' as const,
        text: frameUntrustedText(JSON.stringify(payload), 16 * 1024).text,
      },
    ],
  };
}

/** What re-exposing one upstream produced: the tool names it added, or why not. */
interface UpstreamRegistration {
  tools: string[];
  /** Upstream tools indexed but not registered (over the tool budget). */
  withheld: string[];
  /** How many resources + templates this upstream contributed. */
  resources: number;
  /** How many prompts this upstream contributed. */
  prompts: number;
  error?: string;
  status?: 'no_tools_capability' | 'empty_tools' | 'no_allowed_tools';
  warnings?: string[];
}

/**
 * Re-expose an upstream MCP server's tools and resources under this
 * connection.
 *
 * A server that cannot be reached costs its own tools and nothing else: the
 * session still opens, and `agentmfa_status` reports the failure (via the
 * returned `error`), because one unreachable upstream must not take down
 * every other tool the agent has.
 */
async function registerUpstream(
  server: McpServer,
  toolRegistry: ProtocolToolRegistry,
  broker: BrokerClient,
  principal: Principal,
  connection: BrokerConnection,
  taken: Set<string>,
  index: IndexedTool[],
  toolSurface: UpstreamToolSurface,
  resourceSurface: ResourceSurface,
  promptSurface: PromptSurface,
  discoveryPromise: Promise<Awaited<ReturnType<typeof discoverUpstream>>>,
): Promise<UpstreamRegistration> {
  let discovery: Awaited<ReturnType<typeof discoverUpstream>>;
  try {
    discovery = await discoveryPromise;
  } catch (error) {
    log('warn', 'could not discover an MCP upstream', {
      connection: connection.name,
      error: String(error),
    });
    return {
      tools: [],
      withheld: [],
      resources: 0,
      prompts: 0,
      error: frameUntrustedText(
        `could not reach the MCP server: ${String(error)}`,
        2048,
      ).text,
    };
  }

  let tools = discovery.tools;
  let status: UpstreamRegistration['status'];
  if (discovery.capabilities.tools === undefined) {
    status = 'no_tools_capability';
  } else if (tools.length === 0) {
    status = 'empty_tools';
  }
  // A curated connection lists only its allowed subset. This mirrors what the
  // broker enforces on tools/call; hiding the rest keeps the agent's tool
  // budget honest and its failures unconfusing.
  if (connection.allowed_tools) {
    const allowed = new Set(connection.allowed_tools);
    tools = tools.filter((tool) => allowed.has(tool.name));
    if (discovery.tools.length > 0 && tools.length === 0) {
      status = 'no_allowed_tools';
    }
  }

  const registered: string[] = [];
  const withheld: string[] = [];
  const warnings: string[] = [];
  for (const tool of tools) {
    const preferredName = upstreamToolName(connection, tool.name);
    if (upstreamToolNameCandidate(connection, tool.name).length > preferredName.length) {
      const warning =
        `upstream tool "${tool.name}" was shortened to bounded tool name ` +
        `"${preferredName}"`;
      warnings.push(warning);
      log('warn', 'shortened an upstream MCP tool name', {
        connection: connection.name,
        tool: tool.name,
        toolName: preferredName,
      });
    }
    let toolName = preferredName;
    if (taken.has(toolName)) {
      let attempt = 1;
      do {
        toolName = alternateToolName(
          preferredName,
          `${connection.name}\0${tool.name}`,
          attempt,
        );
        attempt += 1;
      } while (taken.has(toolName) && attempt <= 32);

      if (taken.has(toolName)) {
        const warning =
          `could not expose upstream tool "${tool.name}": every bounded name collided`;
        log('warn', 'an upstream tool remains search-only after name collisions', {
          connection: connection.name,
          tool: tool.name,
          toolName: preferredName,
        });
        warnings.push(warning);
        withheld.push(tool.name);
        index.push({ connection, tool, registeredAs: null });
        continue;
      }
      const warning =
        `upstream tool "${tool.name}" was exposed as "${toolName}" because ` +
        `"${preferredName}" was already in use`;
      log('warn', 'disambiguated a colliding upstream tool name', {
        connection: connection.name,
        tool: tool.name,
        preferredName,
        toolName,
      });
      warnings.push(warning);
    }
    // Over the registration budget: the tool stays discoverable through
    // agentmfa_search_tools and callable through agentmfa_call_tool, it
    // just doesn't occupy a slot in the agent's tool list.
    if (toolSurface.registered >= upstreamToolBudget()) {
      withheld.push(tool.name);
      index.push({ connection, tool, registeredAs: null });
      continue;
    }
    taken.add(toolName);
    index.push({ connection, tool, registeredAs: toolName });
    toolSurface.registered += 1;

    toolRegistry.register(
      toolName,
      {
        title: sanitizeUntrustedText(tool.title ?? tool.name, 200).text,
        description: describeUpstream(connection, tool),
        inputSchema: tool.inputSchema ?? {
          type: 'object',
          additionalProperties: true,
        },
        ...(tool.outputSchema ? { outputSchema: tool.outputSchema } : {}),
        ...(tool.annotations ? { annotations: tool.annotations } : {}),
      },
      async (args, signal) => {
        try {
          const result = await callUpstreamTool(
            broker,
            principal,
            connection,
            tool.name,
            args ?? {},
            signal,
          );
          return sanitizeUpstreamResult(result) as {
            content: Array<{ type: 'text'; text: string }>;
          };
        } catch (error) {
          return upstreamToolFailure(connection, error);
        }
      },
    );
    registered.push(toolName);
  }
  if (withheld.length) {
    log('info', 'upstream tools over the registration budget are search-only', {
      connection: connection.name,
      withheld: withheld.length,
    });
  }

  const resources = registerUpstreamResources(
    server,
    broker,
    principal,
    connection,
    discovery,
    resourceSurface,
  );
  const prompts = registerUpstreamPrompts(
    server,
    broker,
    principal,
    connection,
    discovery.prompts,
    promptSurface,
  );

  return {
    tools: registered,
    withheld,
    resources,
    prompts,
    status,
    warnings: warnings.length ? warnings : undefined,
  };
}

const MAX_DISCOVERY_RETRY_DELAY_MS = 10_000;
const DEFAULT_DISCOVERY_DEADLINE_MS = 10_000;

function discoveryDeadlineMs(): number {
  const configured = Number(process.env.AGENTMFA_DISCOVERY_DEADLINE_MS);
  return Number.isFinite(configured) && configured > 0
    ? Math.floor(configured)
    : DEFAULT_DISCOVERY_DEADLINE_MS;
}

function discoveryRetryDelay(error: unknown): number {
  if (
    error instanceof BrokerError
    && error.status === 429
    && Number.isFinite(error.retryAfterSeconds)
  ) {
    return Math.min(
      MAX_DISCOVERY_RETRY_DELAY_MS,
      Math.max(0, (error.retryAfterSeconds ?? 0) * 1000),
    );
  }
  // One small jittered backoff for transient network/server failures keeps
  // concurrently opening agent sessions from retrying in lockstep.
  return 200 + Math.floor(Math.random() * 201);
}

async function discoverUpstreamWithRetry(
  broker: BrokerClient,
  principal: Principal,
  connection: BrokerConnection,
  signal?: AbortSignal,
): Promise<Awaited<ReturnType<typeof discoverUpstream>>> {
  try {
    return await discoverUpstream(broker, principal, connection, signal);
  } catch (firstError) {
    signal?.throwIfAborted();
    const delayMs = discoveryRetryDelay(firstError);
    log('info', 'retrying MCP upstream discovery once', {
      connection: connection.name,
      delayMs,
      error: String(firstError),
    });
    if (delayMs > 0) {
      await new Promise<void>((resolve, reject) => {
        const done = () => {
          signal?.removeEventListener('abort', abort);
          resolve();
        };
        const timer = setTimeout(done, delayMs);
        const abort = () => {
          clearTimeout(timer);
          reject(signal?.reason ?? new Error('MCP discovery cancelled'));
        };
        signal?.addEventListener('abort', abort, { once: true });
      });
    }
    return discoverUpstream(broker, principal, connection, signal);
  }
}

async function discoverUpstreamForSession(
  broker: BrokerClient,
  principal: Principal,
  connection: BrokerConnection,
): Promise<Awaited<ReturnType<typeof discoverUpstream>>> {
  const controller = new AbortController();
  const deadlineMs = discoveryDeadlineMs();
  const timer = setTimeout(
    () => controller.abort(
      new Error(`MCP discovery exceeded its ${deadlineMs}ms session-open deadline`),
    ),
    deadlineMs,
  );
  timer.unref?.();
  try {
    return await discoverUpstreamWithRetry(
      broker,
      principal,
      connection,
      controller.signal,
    );
  } finally {
    clearTimeout(timer);
  }
}

/** The description an agent sees for a re-exposed resource or template. */
function describeResource(
  connection: BrokerConnection,
  item: UpstreamResource | UpstreamResourceTemplate,
): string {
  const base = item.description ?? item.name ?? ('uri' in item ? item.uri : item.uriTemplate);
  const safeConnection = sanitizeUntrustedText(connection.name, 200).text;
  return `Proxied from ${safeConnection}.\n${frameUntrustedText(base, 1024).text}`;
}

/**
 * Re-expose an upstream's static resources and resource templates.
 *
 * Resources keep their real upstream URI so the agent addresses them exactly
 * as the upstream named them; the read routes back to this connection through
 * the closure, over the broker's HTTP plane, credential injected upstream.
 * Templates additionally proxy argument completion to the upstream — but only
 * when it advertised the completions capability, so the SDK does not offer an
 * autocomplete the upstream cannot answer.
 *
 * Collisions across connections are dropped rather than fatal (the SDK keys
 * resources by URI and templates by name), and a shared budget bounds how
 * many a single session registers. Returns the count actually registered.
 */
function registerUpstreamResources(
  server: McpServer,
  broker: BrokerClient,
  principal: Principal,
  connection: BrokerConnection,
  discovery: { resources: UpstreamResource[]; resourceTemplates: UpstreamResourceTemplate[]; capabilities: { completions?: unknown } },
  surface: ResourceSurface,
): number {
  let count = 0;

  for (const resource of discovery.resources) {
    if (!resource.uri) continue;
    if (surface.registered >= resourceBudget()) {
      surface.withheld++;
      continue;
    }
    if (surface.takenUris.has(resource.uri)) {
      log('warn', 'skipping an upstream resource whose URI collides', {
        connection: connection.name,
        uri: resource.uri,
      });
      continue;
    }
    try {
      server.registerResource(
        resource.name ?? resource.uri,
        resource.uri,
        {
          description: describeResource(connection, resource),
          ...(resource.title
            ? { title: sanitizeUntrustedText(resource.title, 200).text }
            : {}),
          ...(resource.mimeType ? { mimeType: resource.mimeType } : {}),
        },
        async (uri: URL, extra) =>
          sanitizeUpstreamResult(
            await readUpstreamResource(
              broker, principal, connection, uri.toString(), extra.signal,
            ),
          ) as ReadResourceResult,
      );
      surface.takenUris.add(resource.uri);
      surface.registered++;
      count++;
    } catch (error) {
      log('warn', 'could not register an upstream resource', {
        connection: connection.name,
        uri: resource.uri,
        error: String(error),
      });
    }
  }

  const supportsCompletions = !!discovery.capabilities.completions;
  for (const template of discovery.resourceTemplates) {
    if (!template.uriTemplate) continue;
    if (surface.registered >= resourceBudget()) {
      surface.withheld++;
      continue;
    }
    if (surface.takenTemplateUris.has(template.uriTemplate)) {
      log('warn', 'skipping an upstream template whose URI pattern collides', {
        connection: connection.name,
        uriTemplate: template.uriTemplate,
      });
      continue;
    }
    const name = `${namespaceFor(connection)}/${template.name ?? template.uriTemplate}`;
    if (surface.takenTemplateNames.has(name)) {
      log('warn', 'skipping an upstream template whose name collides', {
        connection: connection.name,
        name,
      });
      continue;
    }
    // Proxy each template variable's completion to the upstream. A JS Proxy
    // answers for any variable the SDK asks about, so we need not parse the
    // URI template ourselves; an upstream without completions gets no proxy,
    // so the SDK never advertises an autocomplete it cannot serve.
    const complete = supportsCompletions
      ? (new Proxy(
          {},
          {
            get: (_target, variable) => {
              if (typeof variable !== 'string') return undefined;
              return async (value: string, context?: CompletionContext) => {
                try {
                  const values = await completeUpstream(
                    broker,
                    principal,
                    connection,
                    { type: 'ref/resource', uri: template.uriTemplate },
                    { name: variable, value },
                    context,
                  );
                  return values.map((value) => sanitizeUntrustedText(value, 500).text);
                } catch {
                  return [];
                }
              };
            },
          },
        ) as Record<string, (value: string, context?: CompletionContext) => Promise<string[]>>)
      : undefined;
    try {
      server.registerResource(
        name,
        new ResourceTemplate(template.uriTemplate, { list: undefined, complete }),
        {
          description: describeResource(connection, template),
          ...(template.title
            ? { title: sanitizeUntrustedText(template.title, 200).text }
            : {}),
          ...(template.mimeType ? { mimeType: template.mimeType } : {}),
        },
        async (uri: URL, _variables, extra) =>
          sanitizeUpstreamResult(
            await readUpstreamResource(
              broker, principal, connection, uri.toString(), extra.signal,
            ),
          ) as ReadResourceResult,
      );
      surface.takenTemplateUris.add(template.uriTemplate);
      surface.takenTemplateNames.add(name);
      surface.registered++;
      count++;
    } catch (error) {
      log('warn', 'could not register an upstream resource template', {
        connection: connection.name,
        uriTemplate: template.uriTemplate,
        error: String(error),
      });
    }
  }

  if (surface.withheld) {
    log('info', 'some upstream resources were over the registration budget', {
      connection: connection.name,
      withheld: surface.withheld,
    });
  }
  return count;
}

/**
 * Register an upstream's prompts under this connection's namespace.
 *
 * Prompts are the third thing an MCP server offers and the one AgentMFA was
 * dropping on the floor: a server's tools and resources were re-exposed while
 * its prompts stayed invisible, so a curated workflow the vendor shipped was
 * simply unavailable through the broker. Fetching one rides the same HTTP
 * plane as a tool call, so the credential never leaves the vault.
 *
 * Namespaced by connection because prompt names are a flat space in the SDK
 * and two upstreams may both offer a `review`. Names that still collide are
 * dropped rather than fatal, matching the tool and resource surfaces.
 */
function registerUpstreamPrompts(
  server: McpServer,
  broker: BrokerClient,
  principal: Principal,
  connection: BrokerConnection,
  prompts: UpstreamPrompt[],
  surface: PromptSurface,
): number {
  let count = 0;
  for (const prompt of prompts) {
    if (!prompt.name) continue;
    if (surface.registered >= promptBudget()) {
      surface.withheld++;
      continue;
    }
    const name = `${namespaceFor(connection)}/${prompt.name}`;
    if (surface.takenNames.has(name)) {
      log('warn', 'skipping an upstream prompt whose name collides', {
        connection: connection.name,
        name,
      });
      continue;
    }
    // The SDK builds the prompt's argument schema from a zod shape. Every
    // upstream argument is a string; `required` decides whether it is
    // optional, and the description is upstream prose, so it is sanitized
    // like every other piece of catalog text.
    const argsShape: Record<string, z.ZodType<string | undefined>> = {};
    for (const argument of prompt.arguments ?? []) {
      if (!argument.name) continue;
      const described = argument.description
        ? z.string().describe(sanitizeUntrustedText(argument.description, 500).text)
        : z.string();
      argsShape[argument.name] = argument.required ? described : described.optional();
    }
    try {
      server.registerPrompt(
        name,
        {
          description: describePrompt(connection, prompt),
          ...(prompt.title
            ? { title: sanitizeUntrustedText(prompt.title, 200).text }
            : {}),
          argsSchema: argsShape,
        },
        async (args: Record<string, string | undefined>, extra) => {
          const supplied: Record<string, string> = {};
          for (const [key, value] of Object.entries(args ?? {})) {
            if (typeof value === 'string') supplied[key] = value;
          }
          return sanitizeUpstreamResult(
            await getUpstreamPrompt(
              broker, principal, connection, prompt.name, supplied, extra?.signal,
            ),
          ) as GetPromptResult;
        },
      );
      surface.takenNames.add(name);
      surface.registered++;
      count++;
    } catch (error) {
      log('warn', 'could not register an upstream prompt', {
        connection: connection.name,
        name,
        error: String(error),
      });
    }
  }
  if (surface.withheld) {
    log('info', 'some upstream prompts were over the registration budget', {
      connection: connection.name,
      withheld: surface.withheld,
    });
  }
  return count;
}

/** What an agent is told a re-exposed upstream prompt is, and whose it is. */
function describePrompt(connection: BrokerConnection, prompt: UpstreamPrompt): string {
  const own = prompt.description
    ? frameUntrustedText(prompt.description, 2000).text
    : '';
  return `Prompt from the "${connection.name}" MCP server (${connection.target}), `
    + `brokered by AgentMFA.${own ? `\n${own}` : ''}`;
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
