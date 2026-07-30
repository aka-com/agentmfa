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
import { boundedToolName } from './tool-names';
import { sanitizeUntrustedText } from './untrusted';
import { SIDECAR_VERSION } from './version';

/** One tool as the upstream MCP server describes it. */
export interface UpstreamTool {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  annotations?: {
    title?: string;
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
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

/** One prompt as the upstream describes it. */
export interface UpstreamPrompt {
  name: string;
  title?: string;
  description?: string;
  arguments?: Array<{ name: string; description?: string; required?: boolean }>;
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
  prompts: UpstreamPrompt[];
}

/**
 * Protocol revisions this client can actually speak, newest first.
 *
 * `initialize` offers the newest; a server may answer with an older one it
 * prefers. Both are accepted because nothing here differs between them — the
 * client posts JSON-RPC, reads the catalog, calls tools, and closes the
 * session. Accepting only the newest turned a correct negotiation into an
 * unreachable upstream.
 */
export const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26'] as const;
export const SUPPORTED_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0];

/** A hostile or looping `nextCursor` must not page forever. */
export const MAX_TOOL_PAGES = 32;

/** Resources and templates page too; keep the same guard, a little tighter. */
export const MAX_RESOURCE_PAGES = 16;
/** A single listing cannot grow the session without bound. */
export const MAX_CATALOG_ITEMS = 2_000;
/** Schemas larger than this are omitted from the in-memory search index. */
export const MAX_TOOL_SCHEMA_BYTES = 64 * 1024;
const MAX_CATALOG_TEXT = 8 * 1024;

function boundedString(value: unknown, max = MAX_CATALOG_TEXT): string | undefined {
  if (typeof value !== 'string') return undefined;
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}

const ANNOTATION_HINTS = [
  'readOnlyHint',
  'destructiveHint',
  'idempotentHint',
  'openWorldHint',
] as const;

/** Annotations are relayed to the agent verbatim in tools/list, so project
 * them onto the known hint fields rather than passing an arbitrary upstream
 * object through the catalog's size bounds unchecked. */
function boundedToolAnnotations(value: unknown): UpstreamTool['annotations'] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const raw = value as Record<string, unknown>;
  const annotations: NonNullable<UpstreamTool['annotations']> = {};
  if (typeof raw.title === 'string') {
    annotations.title = sanitizeUntrustedText(raw.title, 200).text;
  }
  for (const hint of ANNOTATION_HINTS) {
    if (typeof raw[hint] === 'boolean') annotations[hint] = raw[hint];
  }
  return annotations;
}

function boundedCatalogItem(method: string, value: unknown): unknown | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  if (method === 'tools/list') {
    const name = boundedString(item.name, 1024);
    if (!name || name !== item.name) return null;
    let inputSchema =
      item.inputSchema && typeof item.inputSchema === 'object'
        ? item.inputSchema
        : undefined;
    let outputSchema =
      item.outputSchema && typeof item.outputSchema === 'object'
        ? item.outputSchema
        : undefined;
    if (
      inputSchema !== undefined &&
      Buffer.byteLength(JSON.stringify(inputSchema)) > MAX_TOOL_SCHEMA_BYTES
    ) {
      inputSchema = undefined;
    }
    if (
      outputSchema !== undefined &&
      Buffer.byteLength(JSON.stringify(outputSchema)) > MAX_TOOL_SCHEMA_BYTES
    ) {
      outputSchema = undefined;
    }
    const annotations = boundedToolAnnotations(item.annotations);
    return {
      name,
      ...(boundedString(item.title, 1024) === undefined
        ? {}
        : { title: boundedString(item.title, 1024) }),
      ...(boundedString(item.description) === undefined
        ? {}
        : { description: boundedString(item.description) }),
      ...(inputSchema === undefined ? {} : { inputSchema }),
      ...(outputSchema === undefined ? {} : { outputSchema }),
      ...(annotations === undefined ? {} : { annotations }),
    };
  }
  if (method === 'prompts/list') {
    const name = boundedString(item.name, 1024);
    if (!name || name !== item.name) return null;
    // Argument metadata is relayed to the agent verbatim, so it is projected
    // onto the known fields and bounded rather than passed through whole.
    const args = Array.isArray(item.arguments)
      ? item.arguments
          .slice(0, 64)
          .map((raw) => {
            if (!raw || typeof raw !== 'object') return null;
            const argument = raw as Record<string, unknown>;
            const argName = boundedString(argument.name, 256);
            if (!argName || argName !== argument.name) return null;
            return {
              name: argName,
              ...(boundedString(argument.description) === undefined
                ? {}
                : { description: boundedString(argument.description) }),
              ...(typeof argument.required === 'boolean'
                ? { required: argument.required }
                : {}),
            };
          })
          .filter((argument): argument is NonNullable<typeof argument> => argument !== null)
      : undefined;
    return {
      name,
      ...(boundedString(item.title, 1024) === undefined
        ? {}
        : { title: boundedString(item.title, 1024) }),
      ...(boundedString(item.description) === undefined
        ? {}
        : { description: boundedString(item.description) }),
      ...(args === undefined ? {} : { arguments: args }),
    };
  }
  if (method === 'resources/list') {
    const uri = boundedString(item.uri);
    if (!uri || uri !== item.uri) return null;
    return {
      uri,
      ...(boundedString(item.name) === undefined ? {} : { name: boundedString(item.name) }),
      ...(boundedString(item.title) === undefined ? {} : { title: boundedString(item.title) }),
      ...(boundedString(item.description) === undefined
        ? {}
        : { description: boundedString(item.description) }),
      ...(boundedString(item.mimeType, 256) === undefined
        ? {}
        : { mimeType: boundedString(item.mimeType, 256) }),
    };
  }
  if (method === 'resources/templates/list') {
    const uriTemplate = boundedString(item.uriTemplate);
    if (!uriTemplate || uriTemplate !== item.uriTemplate) return null;
    return {
      uriTemplate,
      ...(boundedString(item.name) === undefined ? {} : { name: boundedString(item.name) }),
      ...(boundedString(item.title) === undefined ? {} : { title: boundedString(item.title) }),
      ...(boundedString(item.description) === undefined
        ? {}
        : { description: boundedString(item.description) }),
      ...(boundedString(item.mimeType, 256) === undefined
        ? {}
        : { mimeType: boundedString(item.mimeType, 256) }),
    };
  }
  return null;
}

/** The namespace an upstream's tools are grouped under. */
export function namespaceFor(connection: BrokerConnection): string {
  return deriveMcpNamespace({ name: connection.name });
}

/** The MCP tool name we expose for one of the upstream's tools. */
export function upstreamToolNameCandidate(connection: BrokerConnection, tool: string): string {
  const path = joinToolPath(namespaceFor(connection), tool);
  return `agentmfa_${path}`.replace(/[^a-zA-Z0-9_-]/g, '_');
}

export function upstreamToolName(connection: BrokerConnection, tool: string): string {
  return boundedToolName(
    upstreamToolNameCandidate(connection, tool),
    `${connection.name}\0${tool}`,
  );
}

/** A JSON-RPC failure returned by an upstream MCP server. */
export class UpstreamRpcError extends Error {
  constructor(
    readonly code: number,
    message: string,
    readonly data?: unknown,
  ) {
    super(message);
    this.name = 'UpstreamRpcError';
  }
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
    const normalized = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    for (const frame of normalized.split('\n\n')) {
      const data = frame
        .split('\n')
        .filter((line) => line.startsWith('data:'))
        .map((line) => {
          const value = line.slice('data:'.length);
          return value.startsWith(' ') ? value.slice(1) : value;
        })
        .join('\n');
      if (!data) continue;
      try {
        found.push(JSON.parse(data));
      } catch {
        // A comment-only, incomplete, or non-JSON event is not a JSON-RPC
        // message. Other complete frames remain independently usable.
      }
    }
    return found;
  }
}

/**
 * What a caller wants to hear about while an upstream operation is still
 * running, rather than after.
 *
 * A tool call against a slow server used to be indistinguishable from a hung
 * one, because the whole exchange was one buffered request. With the broker
 * streaming, the frames a server emits ahead of its answer — progress,
 * logging — arrive while they still mean something.
 */
export interface UpstreamWatch {
  /** The broker parked this call on a human decision. */
  onWaiting?: () => void;
  /** A server→client JSON-RPC notification that arrived before the answer. */
  onNotification?: (frame: { method: string; params?: unknown }) => void;
}

/**
 * Turn a byte stream of SSE (or of plain JSON) into JSON-RPC frames as they
 * complete.
 *
 * Incremental because that is the entire point: the frames worth forwarding
 * are the ones that arrive *before* the response, and a parser that waits for
 * the end sees them at the same time as everyone else. Plain-JSON bodies have
 * no frame boundary short of the end, so they simply never emit early — which
 * is correct, since such a body is the answer.
 */
export class UpstreamFrameParser {
  private pending = '';

  push(chunk: Buffer | string): { method: string; params?: unknown }[] {
    this.pending += typeof chunk === 'string' ? chunk : chunk.toString('utf8');
    const frames: { method: string; params?: unknown }[] = [];
    for (;;) {
      const normalized = this.pending.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      const boundary = normalized.indexOf('\n\n');
      if (boundary === -1) {
        this.pending = normalized;
        break;
      }
      const block = normalized.slice(0, boundary);
      this.pending = normalized.slice(boundary + 2);
      const data = block
        .split('\n')
        .filter((line) => line.startsWith('data:'))
        .map((line) => {
          const value = line.slice('data:'.length);
          return value.startsWith(' ') ? value.slice(1) : value;
        })
        .join('\n');
      if (!data) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(data);
      } catch {
        continue;
      }
      // Only notifications: a frame with an `id` is a response (which the
      // caller reads from the assembled body) or a server→client *request*,
      // which this transport cannot answer and must not pretend to.
      const frame = parsed as { id?: unknown; method?: unknown; params?: unknown };
      if (frame && typeof frame === 'object' && frame.id === undefined && typeof frame.method === 'string') {
        frames.push({ method: frame.method, params: frame.params });
      }
    }
    return frames;
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
  private protocolVersion: string = SUPPORTED_PROTOCOL_VERSION;
  /** What the server said it offers; empty until `initialize` returns. */
  capabilities: UpstreamCapabilities = {};

  constructor(
    private readonly broker: BrokerClient,
    private readonly auth: AgentAuth,
    private readonly connection: BrokerConnection,
    /**
     * Set for the one operation the caller wants to watch. Only that
     * operation streams; `initialize`, the initialized notification, and the
     * teardown DELETE are short exchanges with nothing to report, and
     * streaming them would cost a second transport path for no signal.
     */
    private readonly watch?: UpstreamWatch,
  ) {}

  private async send(
    method: 'POST' | 'DELETE',
    payload?: unknown,
    signal?: AbortSignal,
    watched = false,
  ): Promise<UpstreamResponse> {
    const call = {
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
    };
    if (!watched || !this.watch) {
      return (await this.broker.invoke('/v1/http', this.auth, call, signal)) as UpstreamResponse;
    }
    const watch = this.watch;
    const parser = new UpstreamFrameParser();
    return (await this.broker.invokeStreamed(
      this.auth,
      call,
      {
        onWaiting: () => watch.onWaiting?.(),
        onBody: (chunk) => {
          for (const frame of parser.push(chunk)) watch.onNotification?.(frame);
        },
      },
      signal,
    )) as UpstreamResponse;
  }

  private initialized = false;

  /** `initialize`, adopt what it negotiates, then `notifications/initialized`. */
  async initialize(signal?: AbortSignal): Promise<void> {
    const id = this.nextId++;
    const response = await this.send('POST', {
      jsonrpc: '2.0',
      id,
      method: 'initialize',
      params: {
        protocolVersion: SUPPORTED_PROTOCOL_VERSION,
        // We do not advertise server-initiated elicitation, sampling, or
        // roots because this short-lived request/response transport cannot
        // answer server→client requests. Draft SEP-2322 `input_required`
        // results remain supported below without claiming that capability.
        capabilities: {},
        clientInfo: { name: 'agentmfa', version: SIDECAR_VERSION },
      },
    }, signal);
    const result = this.result(response, id) as
      | { protocolVersion?: string; capabilities?: UpstreamCapabilities }
      | undefined;

    // A stateful server issues its session id here and requires it on
    // every request that follows; a stateless server issues none and we
    // send none.
    this.sessionId = relayHeaderValue(response.headers, 'mcp-session-id');
    if (typeof result?.protocolVersion === 'string') {
      if (!(SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(result.protocolVersion)) {
        throw new Error(
          `the MCP server negotiated unsupported protocol version ${result.protocolVersion}; ` +
          `supported: ${SUPPORTED_PROTOCOL_VERSIONS.join(', ')}`,
        );
      }
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
  async request(method: string, params: unknown, signal?: AbortSignal): Promise<unknown> {
    return (await this.requestWithElicitationTokens(method, params, signal)).result;
  }

  /** One request plus broker-minted capabilities for its elicitation legs. */
  async requestWithElicitationTokens(
    method: string,
    params: unknown,
    signal?: AbortSignal,
  ): Promise<{ result: unknown; elicitationTokens: Record<string, string> }> {
    const id = this.nextId++;
    let cancellation: Promise<void> | undefined;
    const forwardCancellation = () => {
      cancellation = this.send('POST', {
        jsonrpc: '2.0',
        method: 'notifications/cancelled',
        params: {
          requestId: id,
          reason: String(signal?.reason ?? 'downstream request cancelled'),
        },
      }).then(() => {}).catch((error) => {
        log('warn', 'could not forward MCP cancellation upstream', {
          connection: this.connection.name,
          requestId: id,
          error: String(error),
        });
      });
    };
    if (signal?.aborted) forwardCancellation();
    else signal?.addEventListener('abort', forwardCancellation, { once: true });
    let response: UpstreamResponse;
    try {
      response = await this.send(
        'POST',
        { jsonrpc: '2.0', id, method, params },
        signal,
        // This is the operation worth watching: everything the server has to
        // say about a long call arrives on it.
        true,
      );
    } finally {
      signal?.removeEventListener('abort', forwardCancellation);
      if (cancellation) await cancellation;
    }
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
  async listPaged<T>(
    method: string,
    key: string,
    maxPages: number,
    signal?: AbortSignal,
  ): Promise<T[]> {
    const items: T[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < maxPages; page++) {
      const result = (await this.request(method, cursor ? { cursor } : {}, signal)) as
        | (Record<string, unknown> & { nextCursor?: string })
        | undefined;
      const list = result?.[key];
      if (Array.isArray(list)) {
        for (const rawItem of list) {
          if (items.length >= MAX_CATALOG_ITEMS) {
            log('warn', 'an upstream catalog exceeded the item cap', {
              connection: this.connection.name,
              method,
              items: MAX_CATALOG_ITEMS,
            });
            return items;
          }
          const item = boundedCatalogItem(method, rawItem);
          if (item !== null) items.push(item as T);
        }
      }
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
    ) as {
      error?: { code?: unknown; message?: unknown; data?: unknown };
      result?: unknown;
    } | undefined;
    if (!answer) {
      throw new Error('the MCP server sent no response to the request');
    }
    if (answer.error) {
      throw new UpstreamRpcError(
        typeof answer.error.code === 'number' ? answer.error.code : -32603,
        typeof answer.error.message === 'string'
          ? answer.error.message
          : 'the MCP server returned an error',
        answer.error.data,
      );
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
  signal?: AbortSignal,
): Promise<UpstreamDiscovery> {
  const client = new UpstreamClient(broker, auth, connection);
  try {
    // Inside the try: `initialize` sets the session id from the response
    // header before it can throw (e.g. on an unsupported negotiated version),
    // so the `finally` must run to DELETE that session rather than leak it.
    await client.initialize(signal);
    const capabilities = client.capabilities;
    const tools = capabilities.tools
      ? await client.listPaged<UpstreamTool>('tools/list', 'tools', MAX_TOOL_PAGES, signal)
      : [];

    let resources: UpstreamResource[] = [];
    let resourceTemplates: UpstreamResourceTemplate[] = [];
    if (capabilities.resources) {
      try {
        resources = await client.listPaged<UpstreamResource>(
          'resources/list',
          'resources',
          MAX_RESOURCE_PAGES,
          signal,
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
          signal,
        );
      } catch {
        resourceTemplates = [];
      }
    }
    let prompts: UpstreamPrompt[] = [];
    if (capabilities.prompts) {
      try {
        prompts = await client.listPaged<UpstreamPrompt>(
          'prompts/list',
          'prompts',
          MAX_RESOURCE_PAGES,
          signal,
        );
      } catch (error) {
        // Best-effort like resources: a server that advertises prompts and
        // stumbles listing them still contributes its tools.
        log('warn', 'an upstream advertised prompts but failed to list them', {
          connection: connection.name,
          error: String(error),
        });
      }
    }
    return { capabilities, tools, resources, resourceTemplates, prompts };
  } finally {
    // Best-effort: a failed teardown must not mask the real error, nor turn a
    // successful discovery into a failure.
    await client.close().catch(() => {});
  }
}

/** How many input-required round trips a single call may take before we give
 * up rather than let a misbehaving upstream loop us forever. */
export const MAX_MRTR_ROUNDS = 8;
/** Total user-think-time and upstream work one MRTR call may consume. */
export const MAX_MRTR_DURATION_MS = 8 * 60 * 1000;

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
 * This supports the draft `input_required` result without advertising the
 * standard server-initiated elicitation capability. Any other draft input
 * kind is declined defensively.
 *
 * Note: the draft schema does not pin where `inputResponses`/`requestState`
 * travel on the retry. We place them in the request `params`; this is the one
 * spot to adjust if the finalized wire format differs.
 */
async function runWithMrtr(
  broker: BrokerClient,
  auth: AgentAuth,
  connection: BrokerConnection,
  method: 'tools/call' | 'resources/read' | 'prompts/get',
  baseParams: Record<string, unknown>,
  _toolLabel: string,
  signal?: AbortSignal,
  watch?: UpstreamWatch,
): Promise<unknown> {
  let inputResponses: Record<string, unknown> | undefined;
  let requestState: unknown;
  let terminalAnswerForwarded = false;
  const deadline = Date.now() + MAX_MRTR_DURATION_MS;

  const withinBudget = async <T>(operation: Promise<T>): Promise<T> => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      throw new Error('the MCP input flow exceeded its 8 minute time budget');
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        operation,
        new Promise<T>((_, reject) => {
          timer = setTimeout(
            () => reject(new Error('the MCP input flow exceeded its 8 minute time budget')),
            remaining,
          );
          timer.unref?.();
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };

  for (let round = 0; round < MAX_MRTR_ROUNDS; round++) {
    signal?.throwIfAborted();
    const client = new UpstreamClient(broker, auth, connection, watch);
    let result: MrtrResult | undefined;
    let elicitationTokens: Record<string, string> = {};
    try {
      // Inside the try so a throw after the session id is set still tears the
      // session down (see `discoverUpstream`).
      await withinBudget(client.initialize(signal));
      const params = {
        ...baseParams,
        ...(inputResponses ? { inputResponses } : {}),
        ...(requestState !== undefined ? { requestState } : {}),
      };
      const response = await withinBudget(
        client.requestWithElicitationTokens(method, params, signal),
      );
      result = response.result as MrtrResult | undefined;
      Object.assign(elicitationTokens, response.elicitationTokens);
    } finally {
      // Teardown is cheap and best-effort: wrapping it in `withinBudget` let an
      // exhausted budget throw here and mask the real error from the try (and
      // skip the DELETE entirely).
      await client.close().catch(() => {});
    }

    // A pre-2026 server omits `resultType`; that (and an explicit "complete")
    // is the final answer, returned as it stands.
    if (!result || result.resultType !== 'input_required') {
      return result;
    }
    if (terminalAnswerForwarded) {
      throw new Error('the MCP input flow remained open after the user declined or cancelled it');
    }

    const requests = result.inputRequests ?? {};
    const responses: Record<string, unknown> = {};
    let hasTerminalAnswer = false;
    for (const [key, request] of Object.entries(requests)) {
      if (request?.method !== 'elicitation/create') {
        // We never advertised sampling or roots; decline anything else so
        // the upstream can decide how to proceed without them.
        responses[key] = { action: 'decline' };
        continue;
      }
      const correlationToken = elicitationTokens[key] ?? '';
      let cancellation: Promise<void> | undefined;
      const cancelElicitation = () => {
        cancellation = broker.cancelElicitation(auth, {
          connection: connection.name,
          correlationToken,
        }).catch((error) => {
          log('warn', 'could not cancel broker elicitation', {
            connection: connection.name,
            error: String(error),
          });
        });
      };
      if (signal?.aborted) cancelElicitation();
      else signal?.addEventListener('abort', cancelElicitation, { once: true });
      let answer: Awaited<ReturnType<BrokerClient['elicit']>>;
      try {
        answer = await withinBudget(
          broker.elicit(auth, {
            connection: connection.name,
            correlationToken,
          }, signal),
        );
      } finally {
        signal?.removeEventListener('abort', cancelElicitation);
        if (cancellation) await cancellation;
      }
      responses[key] = answer;
      if (answer.action === 'decline' || answer.action === 'cancel') {
        hasTerminalAnswer = true;
      }
    }

    // Nothing actionable and no state to carry forward: returning avoids an
    // infinite loop against a server that keeps asking for nothing.
    if (Object.keys(requests).length === 0 && result.requestState === undefined) {
      return result;
    }
    inputResponses = responses;
    requestState = result.requestState;
    // Forward the user's terminal answer exactly once. If the upstream asks
    // again on the following round, stop instead of raising another prompt.
    terminalAnswerForwarded = hasTerminalAnswer;
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
  signal?: AbortSignal,
): Promise<unknown> {
  return runWithMrtr(broker, auth, connection, 'resources/read', { uri }, uri, signal);
}

/**
 * Fetch one prompt's messages from the upstream.
 *
 * Like a tool call, this rides the broker's HTTP plane, so the credential
 * stays in the vault and the call is access-checked on the way through.
 */
export async function getUpstreamPrompt(
  broker: BrokerClient,
  auth: AgentAuth,
  connection: BrokerConnection,
  name: string,
  args: Record<string, string>,
  signal?: AbortSignal,
): Promise<unknown> {
  return runWithMrtr(
    broker,
    auth,
    connection,
    'prompts/get',
    { name, arguments: args },
    name,
    signal,
  );
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
  try {
    // Inside the try so a throw after the session id is set still tears the
    // session down (see `discoverUpstream`).
    await client.initialize();
    const result = (await client.request('completion/complete', {
      ref,
      argument,
      ...(context ? { context } : {}),
    })) as { completion?: { values?: unknown } } | undefined;
    const values = result?.completion?.values;
    return Array.isArray(values) ? values.filter((value): value is string => typeof value === 'string') : [];
  } finally {
    await client.close().catch(() => {});
  }
}

/** Call one of the upstream's tools, resolving any elicitation it requests. */
export async function callUpstreamTool(
  broker: BrokerClient,
  auth: AgentAuth,
  connection: BrokerConnection,
  tool: string,
  args: Record<string, unknown>,
  signal?: AbortSignal,
  watch?: UpstreamWatch,
): Promise<unknown> {
  return runWithMrtr(
    broker,
    auth,
    connection,
    'tools/call',
    { name: tool, arguments: args },
    tool,
    signal,
    watch,
  );
}
