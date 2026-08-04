// An MCP client for the broker's own MCP host (in-process, reverse-proxied
// at /mcp on the control socket).
//
// This is the surface `claude mcp add multitool -- multitool mcp` ends up talking
// to, so the suite exercises it the way a client does: streamable HTTP,
// `initialize` then a session id on every later request, responses that may
// arrive as JSON or as a one-frame event stream.

import { request, type HttpResponse } from './http';

export interface RpcError {
  code: number;
  message: string;
}

export class McpError extends Error {
  constructor(readonly rpc: RpcError) {
    super(`MCP error ${rpc.code}: ${rpc.message}`);
    this.name = 'McpError';
  }
}

export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

/** The JSON body of an MCP response, whichever framing carried it. */
function decode(response: HttpResponse): Record<string, unknown> {
  const contentType = String(response.header('content-type') ?? '');
  if (!contentType.includes('text/event-stream')) return response.json<Record<string, unknown>>();
  for (const line of response.text.split('\n')) {
    if (line.startsWith('data:')) return JSON.parse(line.slice(5).trim()) as Record<string, unknown>;
  }
  throw new Error(`no data frame in the event stream: ${response.text.slice(0, 200)}`);
}

export class McpClient {
  private id = 0;
  private sessionId: string | undefined;

  constructor(
    private readonly socketPath: string,
    private readonly token: string,
    private readonly path = '/mcp',
  ) {}

  private headers(): Record<string, string> {
    return {
      authorization: `Bearer ${this.token}`,
      'content-type': 'application/json',
      // The SDK's streamable-HTTP transport requires a client to accept both.
      accept: 'application/json, text/event-stream',
      ...(this.sessionId ? { 'mcp-session-id': this.sessionId } : {}),
    };
  }

  /** One JSON-RPC round trip; returns the raw HTTP response. */
  async send(method: string, params?: unknown, id?: number | null): Promise<HttpResponse> {
    const body: Record<string, unknown> = { jsonrpc: '2.0', method };
    if (params !== undefined) body.params = params;
    if (id !== null) body.id = id ?? (this.id += 1);
    return request({
      socketPath: this.socketPath,
      method: 'POST',
      path: this.path,
      headers: this.headers(),
      body: JSON.stringify(body),
      timeoutMs: 60_000,
    });
  }

  /** One JSON-RPC call, decoded, throwing on a JSON-RPC error. */
  async call<T = Record<string, unknown>>(method: string, params?: unknown): Promise<T> {
    const response = await this.send(method, params);
    if (response.status < 200 || response.status >= 300) {
      throw new Error(`MCP ${method} failed: HTTP ${response.status} ${response.text.slice(0, 300)}`);
    }
    const message = decode(response);
    if (message.error) throw new McpError(message.error as RpcError);
    return message.result as T;
  }

  async initialize(clientName = 'multitool-sandbox-tests'): Promise<Record<string, unknown>> {
    const response = await this.send('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: clientName, version: '0.0.0' },
    });
    if (response.status < 200 || response.status >= 300) {
      throw new Error(`MCP initialize failed: HTTP ${response.status} ${response.text.slice(0, 300)}`);
    }
    const session = response.header('mcp-session-id');
    if (session) this.sessionId = session;
    const message = decode(response);
    if (message.error) throw new McpError(message.error as RpcError);
    // The handshake is not complete until the client says so.
    await this.send('notifications/initialized', {}, null);
    return message.result as Record<string, unknown>;
  }

  async tools(): Promise<McpTool[]> {
    const result = await this.call<{ tools: McpTool[] }>('tools/list');
    return result.tools;
  }

  async callTool(name: string, args: Record<string, unknown> = {}) {
    return this.call<{ content: Array<{ type: string; text?: string }>; isError?: boolean }>(
      'tools/call',
      { name, arguments: args },
    );
  }

  get session(): string | undefined {
    return this.sessionId;
  }
}
