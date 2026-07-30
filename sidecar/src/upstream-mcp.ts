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

/** One static resource as the upstream describes it. */
export interface UpstreamResource {
  uri: string;
  name?: string;
  title?: string;
  description?: string;
  mimeType?: string;
}

/** One resource template (an RFC 6570 URI with variables) the upstream offers. */
export interface UpstreamResourceTemplate {
  uriTemplate: string;
  name?: string;
  title?: string;
  description?: string;
  mimeType?: string;
}

/** The subset of the upstream's advertised capabilities we act on. */
export interface UpstreamCapabilities {
  tools?: unknown;
  resources?: unknown;
  completions?: unknown;
  prompts?: unknown;
}

/** One session's worth of what an upstream offers, fetched at session open. */
export interface UpstreamDiscovery {
  capabilities: UpstreamCapabilities;
  tools: UpstreamTool[];
  resources: UpstreamResource[];
  resourceTemplates: UpstreamResourceTemplate[];
}

/** The version we offer; the server's `initialize` answer overrides it. */
export const SUPPORTED_PROTOCOL_VERSION = '2025-06-18';

/** A hostile or looping `nextCursor` must not page forever. */
export const MAX_TOOL_PAGES = 32;

/** Resources and templates page too; keep the same guard, a little tighter. */
export const MAX_RESOURCE_PAGES = 16;

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
  elicitation_tokens?: Record<string, string>;
}

/** Response header names arrive in whatever case the broker preserved. */
export function relayHeaderValue(
  headers: Record<string, string> | undefined,
  name: string,
): string | null {
  if (!headers) return null;
  const normalizedName = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === normalizedName) return value;
  }
  return null;
}

/**
 * SEP-2243 routing headers for one JSON-RPC message: `mcp-method` mirrors
 * the body's method, and `mcp-name` the tool/prompt name when the call
 * names one. A load balancer can then route without parsing the body, and a
 * 2026-07-28 server that rejects headers disagreeing with the body sees them
 * agree. A name that is not header-safe is dropped rather than risking a
 * rejected request — the header is a routing hint and the body still carries
 * the authoritative value.
 */
function routingHeaders(payload: unknown): Record<string, string> {
  if (!payload || typeof payload !== 'object') return {};
  const message = payload as { method?: unknown; params?: { name?: unknown } };
  if (typeof message.method !== 'string') return {};
  const headers: Record<string, string> = { 'mcp-method': message.method };
  const name = message.params?.name;
  if (typeof name === 'string' && /^[\x20-\x7e]+$/.test(name)) {
    headers['mcp-name'] = name;
  }
  return headers;
}

/**
 * The upstream body as a list of JSON-RPC messages.
 *
 * A plain JSON server answers with one document; a streamable-HTTP server
 * may answer with an SSE body whose frames include notifications as well as
 * the response we asked for. Every parseable frame is returned, and the
 * caller picks the one bearing its request id.
 */
export function relayMessages(response: UpstreamResponse): unknown[] {
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
  /** What the server said it offers; empty until `initialize` returns. */
  capabilities: UpstreamCapabilities = {};

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
        ...routingHeaders(payload),
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
        // We advertise elicitation so a 2026-spec upstream may request user
        // input mid-call (SEP-2322), which we surface through the AgentMFA
        // app. We do NOT advertise sampling or roots: we cannot answer them,
        // they are deprecated, and per the spec a server must not request an
        // input kind the client did not declare.
        capabilities: { elicitation: {} },
        clientInfo: { name: 'agentmfa', version: '0.1.0' },
      },
    });
    const result = this.result(response, id) as
      | { protocolVersion?: string; capabilities?: UpstreamCapabilities }
      | undefined;

    // A stateful server issues its session id here and requires it on
    // every request that follows; a stateless server issues none and we
    // send none.
    this.sessionId = relayHeaderValue(response.headers, 'mcp-session-id');
    if (typeof result?.protocolVersion === 'string') {
      this.protocolVersion = result.protocolVersion;
    }
    if (result?.capabilities && typeof result.capabilities === 'object') {
      this.capabilities = result.capabilities;
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
    return (await this.requestWithElicitationTokens(method, params)).result;
  }

  /** One request plus broker-minted capabilities for its elicitation legs. */
  async requestWithElicitationTokens(
    method: string,
    params: unknown,
  ): Promise<{ result: unknown; elicitationTokens: Record<string, string> }> {
    const id = this.nextId++;
    const response = await this.send('POST', { jsonrpc: '2.0', id, method, params });
    return {
      result: this.result(response, id),
      elicitationTokens: response.elicitation_tokens ?? {},
    };
  }

  /**
   * Drain a paginated list method (`tools/list`, `resources/list`, …) into
   * a flat array, following `nextCursor` up to `maxPages` so a looping or
   * hostile server cannot page us forever.
   */
  async listPaged<T>(method: string, key: string, maxPages: number): Promise<T[]> {
    const items: T[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < maxPages; page++) {
      const result = (await this.request(method, cursor ? { cursor } : {})) as
        | (Record<string, unknown> & { nextCursor?: string })
        | undefined;
      const list = result?.[key];
      if (Array.isArray(list)) items.push(...(list as T[]));
      if (!result?.nextCursor) return items;
      cursor = result.nextCursor;
    }
    log('warn', 'a paginated list was truncated: the upstream kept paginating', {
      connection: this.connection.name,
      method,
      pages: maxPages,
    });
    return items;
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
    const answer = relayMessages(response).find(
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
 * Ask an upstream MCP server what it offers — tools, resources, and resource
 * templates — in one short-lived session.
 *
 * MCP requires `initialize` before anything else. We do not hold a session
 * across operations: each is independent, which costs round trips and buys
 * us statelessness across sidecar restarts. Tool discovery is load-bearing
 * (a failure here means the upstream is unreachable this session); resource
 * discovery is best-effort, so a server that advertises resources but stumbles
 * listing them still contributes its tools.
 */
export async function discoverUpstream(
  broker: BrokerClient,
  auth: AgentAuth,
  connection: BrokerConnection,
): Promise<UpstreamDiscovery> {
  const client = new UpstreamClient(broker, auth, connection);
  await client.initialize();
  try {
    const capabilities = client.capabilities;
    const tools = capabilities.tools
      ? await client.listPaged<UpstreamTool>('tools/list', 'tools', MAX_TOOL_PAGES)
      : [];

    let resources: UpstreamResource[] = [];
    let resourceTemplates: UpstreamResourceTemplate[] = [];
    if (capabilities.resources) {
      try {
        resources = await client.listPaged<UpstreamResource>(
          'resources/list',
          'resources',
          MAX_RESOURCE_PAGES,
        );
      } catch (error) {
        log('warn', 'an upstream advertised resources but failed to list them', {
          connection: connection.name,
          error: String(error),
        });
      }
      try {
        // Many servers expose resources without any templates and answer
        // this with "method not found"; that is not an error worth surfacing.
        resourceTemplates = await client.listPaged<UpstreamResourceTemplate>(
          'resources/templates/list',
          'resourceTemplates',
          MAX_RESOURCE_PAGES,
        );
      } catch {
        resourceTemplates = [];
      }
    }
    return { capabilities, tools, resources, resourceTemplates };
  } finally {
    await client.close();
  }
}

/** How many input-required round trips a single call may take before we give
 * up rather than let a misbehaving upstream loop us forever. */
export const MAX_MRTR_ROUNDS = 8;

/** One entry of an upstream's `inputRequests` map (SEP-2322). */
interface InputRequest {
  method?: string;
  params?: { message?: string; requestedSchema?: unknown };
}

/** An upstream result that may be an interim `input_required` (SEP-2322). */
interface MrtrResult {
  resultType?: string;
  inputRequests?: Record<string, InputRequest>;
  requestState?: unknown;
}

/**
 * Drive a request that the upstream may answer with `input_required`
 * (SEP-2322 multi round-trip). Each round is a fresh short-lived session —
 * the spec terminates the initial request and expects an independent retry,
 * so nothing is held open across the user's think-time. When the upstream
 * asks for input, each `elicitation/create` is surfaced to the AgentMFA user
 * through the broker; the answers ride the retry as `inputResponses`
 * (keyed to match) alongside the echoed opaque `requestState`.
 *
 * We only advertise the elicitation capability, so a conforming upstream
 * sends nothing else; any other input kind is declined defensively.
 *
 * Note: the draft schema does not pin where `inputResponses`/`requestState`
 * travel on the retry. We place them in the request `params`; this is the one
 * spot to adjust if the finalized wire format differs.
 */
async function runWithMrtr(
  broker: BrokerClient,
  auth: AgentAuth,
  connection: BrokerConnection,
  method: 'tools/call' | 'resources/read',
  baseParams: Record<string, unknown>,
  _toolLabel: string,
): Promise<unknown> {
  let inputResponses: Record<string, unknown> | undefined;
  let requestState: unknown;

  for (let round = 0; round < MAX_MRTR_ROUNDS; round++) {
    const client = new UpstreamClient(broker, auth, connection);
    await client.initialize();
    let result: MrtrResult | undefined;
    let elicitationTokens: Record<string, string> = {};
    try {
      const params = {
        ...baseParams,
        ...(inputResponses ? { inputResponses } : {}),
        ...(requestState !== undefined ? { requestState } : {}),
      };
      const response = await client.requestWithElicitationTokens(method, params);
      result = response.result as MrtrResult | undefined;
      Object.assign(elicitationTokens, response.elicitationTokens);
    } finally {
      await client.close();
    }

    // A pre-2026 server omits `resultType`; that (and an explicit "complete")
    // is the final answer, returned as it stands.
    if (!result || result.resultType !== 'input_required') {
      return result;
    }

    const requests = result.inputRequests ?? {};
    const responses: Record<string, unknown> = {};
    for (const [key, request] of Object.entries(requests)) {
      if (request?.method !== 'elicitation/create') {
        // We never advertised sampling or roots; decline anything else so
        // the upstream can decide how to proceed without them.
        responses[key] = { action: 'decline' };
        continue;
      }
      const answer = await broker.elicit(auth, {
        connection: connection.name,
        correlationToken: elicitationTokens[key] ?? '',
      });
      responses[key] = answer;
    }

    // Nothing actionable and no state to carry forward: returning avoids an
    // infinite loop against a server that keeps asking for nothing.
    if (Object.keys(requests).length === 0 && result.requestState === undefined) {
      return result;
    }
    inputResponses = responses;
    requestState = result.requestState;
  }

  throw new Error(
    `the MCP server kept requesting input after ${MAX_MRTR_ROUNDS} rounds`,
  );
}

/** Read one of an upstream's resources by its (concrete) URI. */
export async function readUpstreamResource(
  broker: BrokerClient,
  auth: AgentAuth,
  connection: BrokerConnection,
  uri: string,
): Promise<unknown> {
  return runWithMrtr(broker, auth, connection, 'resources/read', { uri }, uri);
}

/** Argument-completion context, forwarded verbatim to the upstream. */
export interface CompletionContext {
  arguments?: Record<string, string>;
}

/**
 * Ask an upstream to complete one argument of a prompt or resource template.
 * Returns just the suggestion strings (the SDK rebuilds the envelope); an
 * upstream that does not support completion yields none rather than an error.
 */
export async function completeUpstream(
  broker: BrokerClient,
  auth: AgentAuth,
  connection: BrokerConnection,
  ref: { type: 'ref/resource'; uri: string } | { type: 'ref/prompt'; name: string },
  argument: { name: string; value: string },
  context?: CompletionContext,
): Promise<string[]> {
  const client = new UpstreamClient(broker, auth, connection);
  await client.initialize();
  try {
    const result = (await client.request('completion/complete', {
      ref,
      argument,
      ...(context ? { context } : {}),
    })) as { completion?: { values?: unknown } } | undefined;
    const values = result?.completion?.values;
    return Array.isArray(values) ? values.filter((value): value is string => typeof value === 'string') : [];
  } finally {
    await client.close();
  }
}

/** Call one of the upstream's tools, resolving any elicitation it requests. */
export async function callUpstreamTool(
  broker: BrokerClient,
  auth: AgentAuth,
  connection: BrokerConnection,
  tool: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  return runWithMrtr(
    broker,
    auth,
    connection,
    'tools/call',
    { name: tool, arguments: args },
    tool,
  );
}
