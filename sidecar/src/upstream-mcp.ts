// Consuming an external MCP server as a AgentMFA tool.
//
// The important property here is where the credential lives. An MCP server
// reached over HTTP is, to the broker, an ordinary API connection: pinned
// host, pinned scheme and port, credential injected on the upstream leg. So
// the sidecar does not open a socket to the MCP server at all — it posts
// JSON-RPC through the broker's existing `/v1/http` plane and lets the
// broker attach the credential. The secret never enters this process, and
// the call is wiring-checked like every other.
//
// Sessions are held for one operation and then closed: `initialize` →
// `notifications/initialized` → the work → `DELETE`. Nothing survives a
// sidecar restart, which keeps us stateless where it matters, while a
// stateful upstream (the default posture of SDK-built servers) still sees
// the handshake it requires — its `mcp-session-id` is echoed back, the
// negotiated protocol version rides every follow-up request, and the
// session is torn down rather than leaked.
//
// Naming follows executor's own conventions (`deriveMcpNamespace` /
// `joinToolPath`) so a tool this surfaces is named the way an executor host
// would name it.

import { deriveMcpNamespace, joinToolPath } from '@executor-js/plugin-mcp/core';

import type { AgentAuth, BrokerClient, BrokerConnection } from './broker';
import { log } from './log';

/** One tool as the upstream MCP server describes it. */
export interface UpstreamTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

/** The version we offer; the server's `initialize` answer overrides it. */
export const SUPPORTED_PROTOCOL_VERSION = '2025-06-18';

/** A hostile or looping `nextCursor` must not page forever. */
export const MAX_TOOL_PAGES = 32;

/** The namespace an upstream's tools are grouped under. */
export function namespaceFor(connection: BrokerConnection): string {
  return deriveMcpNamespace({ name: connection.name });
}

/** The MCP tool name we expose for one of the upstream's tools. */
export function upstreamToolName(connection: BrokerConnection, tool: string): string {
  const path = joinToolPath(namespaceFor(connection), tool);
  return `agentmfa_${path}`.replace(/[^a-zA-Z0-9_-]/g, '_');
}

/** The broker's relay of the upstream response: `PROTOCOL.md`, HTTP plane. */
interface UpstreamResponse {
  status?: number;
  headers?: Record<string, string>;
  body?: unknown;
  body_encoding?: string;
}

/** Response header names arrive in whatever case the broker preserved. */
function headerValue(headers: Record<string, string> | undefined, name: string): string | null {
  if (!headers) return null;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name) return value;
  }
  return null;
}

/**
 * The upstream body as a list of JSON-RPC messages.
 *
 * A plain JSON server answers with one document; a streamable-HTTP server
 * may answer with an SSE body whose frames include notifications as well as
 * the response we asked for. Every parseable frame is returned, and the
 * caller picks the one bearing its request id.
 */
function messages(response: UpstreamResponse): unknown[] {
  const raw =
    response.body_encoding === 'base64' && typeof response.body === 'string'
      ? Buffer.from(response.body, 'base64').toString('utf8')
      : response.body;
  if (raw === null || raw === undefined || raw === '') return [];
  if (typeof raw !== 'string') return [raw];

  try {
    return [JSON.parse(raw)];
  } catch {
    const found: unknown[] = [];
    for (const line of raw.split('\n')) {
      if (!line.startsWith('data: ')) continue;
      try {
        found.push(JSON.parse(line.slice(6)));
      } catch {
        // an SSE comment or partial frame; skip it
      }
    }
    return found;
  }
}

/**
 * One short-lived session against an upstream MCP server.
 *
 * All traffic rides the broker's `/v1/http` plane; this class only supplies
 * the MCP framing the transport spec asks a client for.
 */
class UpstreamClient {
  private nextId = 1;
  private sessionId: string | null = null;
  private protocolVersion = SUPPORTED_PROTOCOL_VERSION;

  constructor(
    private readonly broker: BrokerClient,
    private readonly auth: AgentAuth,
    private readonly connection: BrokerConnection,
  ) {}

  private async send(method: 'POST' | 'DELETE', payload?: unknown): Promise<UpstreamResponse> {
    return (await this.broker.invoke('/v1/http', this.auth, {
      connection: this.connection.name,
      method,
      path: this.connection.mcp_path,
      headers: {
        ...(payload === undefined ? {} : { 'content-type': 'application/json' }),
        accept: 'application/json, text/event-stream',
        ...(this.sessionId ? { 'mcp-session-id': this.sessionId } : {}),
        // Required on every request after `initialize` completes.
        ...(this.initialized ? { 'mcp-protocol-version': this.protocolVersion } : {}),
      },
      ...(payload === undefined ? {} : { body: payload }),
    })) as UpstreamResponse;
  }

  private initialized = false;

  /** `initialize`, adopt what it negotiates, then `notifications/initialized`. */
  async initialize(): Promise<void> {
    const id = this.nextId++;
    const response = await this.send('POST', {
      jsonrpc: '2.0',
      id,
      method: 'initialize',
      params: {
        protocolVersion: SUPPORTED_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: 'agentmfa', version: '0.1.0' },
      },
    });
    const result = this.result(response, id) as { protocolVersion?: string } | undefined;

    // A stateful server issues its session id here and requires it on
    // every request that follows; a stateless server issues none and we
    // send none.
    this.sessionId = headerValue(response.headers, 'mcp-session-id');
    if (typeof result?.protocolVersion === 'string') {
      this.protocolVersion = result.protocolVersion;
    }
    this.initialized = true;

    // Fire-and-forget by design (the spec's answer is an empty 202), so a
    // server that dislikes it costs a log line, not the operation.
    try {
      await this.send('POST', { jsonrpc: '2.0', method: 'notifications/initialized' });
    } catch (error) {
      log('warn', 'the initialized notification was refused', {
        connection: this.connection.name,
        error: String(error),
      });
    }
  }

  /** One request; the answer is the frame bearing this request's id. */
  async request(method: string, params: unknown): Promise<unknown> {
    const id = this.nextId++;
    const response = await this.send('POST', { jsonrpc: '2.0', id, method, params });
    return this.result(response, id);
  }

  /**
   * The result frame for `id`, or a thrown error.
   *
   * Matching on the id is what keeps a notification frame — a progress or
   * log message a server may stream ahead of its answer — from being
   * mistaken for the response.
   */
  private result(response: UpstreamResponse, id: number): unknown {
    if (response.status && (response.status < 200 || response.status >= 300)) {
      throw new Error(`the MCP server answered ${response.status}`);
    }
    const answer = messages(response).find(
      (frame) => !!frame && typeof frame === 'object' && (frame as { id?: unknown }).id === id,
    ) as { error?: { message?: string }; result?: unknown } | undefined;
    if (!answer) {
      throw new Error('the MCP server sent no response to the request');
    }
    if (answer.error) {
      throw new Error(answer.error.message ?? 'the MCP server returned an error');
    }
    return answer.result;
  }

  /** Tear the session down; an upstream that keeps state must not leak it. */
  async close(): Promise<void> {
    if (!this.sessionId) return;
    try {
      await this.send('DELETE');
    } catch {
      // Best effort: the spec allows 405 from servers that do not support
      // client-initiated teardown, and an idle timeout reaps the rest.
    }
  }
}

/**
 * Ask an upstream MCP server what it offers.
 *
 * MCP requires `initialize` before anything else. We do not hold a session
 * across operations: each is independent, which costs round trips and buys
 * us statelessness across sidecar restarts.
 */
export async function listUpstreamTools(
  broker: BrokerClient,
  auth: AgentAuth,
  connection: BrokerConnection,
): Promise<UpstreamTool[]> {
  const client = new UpstreamClient(broker, auth, connection);
  await client.initialize();
  try {
    const tools: UpstreamTool[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < MAX_TOOL_PAGES; page++) {
      const result = (await client.request('tools/list', cursor ? { cursor } : {})) as {
        tools?: UpstreamTool[];
        nextCursor?: string;
      };
      tools.push(...(result?.tools ?? []));
      if (!result?.nextCursor) return tools;
      cursor = result.nextCursor;
    }
    log('warn', 'tool list truncated: the upstream kept paginating', {
      connection: connection.name,
      pages: MAX_TOOL_PAGES,
    });
    return tools;
  } finally {
    await client.close();
  }
}

/** Call one of the upstream's tools. */
export async function callUpstreamTool(
  broker: BrokerClient,
  auth: AgentAuth,
  connection: BrokerConnection,
  tool: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  const client = new UpstreamClient(broker, auth, connection);
  await client.initialize();
  try {
    return await client.request('tools/call', { name: tool, arguments: args });
  } finally {
    await client.close();
  }
}
