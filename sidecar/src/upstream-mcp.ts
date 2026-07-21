// Consuming an external MCP server as a Multitool tool.
//
// The important property here is where the credential lives. An MCP server
// reached over HTTP is, to the broker, an ordinary API connection: pinned
// host, pinned scheme and port, credential injected on the upstream leg. So
// the sidecar does not open a socket to the MCP server at all — it posts
// JSON-RPC through the broker's existing `/v1/http` plane and lets the
// broker attach the credential. The secret never enters this process, and
// the call is wiring-checked like every other.
//
// Naming follows executor's own conventions (`deriveMcpNamespace` /
// `joinToolPath`) so a tool this surfaces is named the way an executor host
// would name it.

import { deriveMcpNamespace, joinToolPath } from '@executor-js/plugin-mcp/core';

import type { BrokerClient, BrokerConnection } from './broker';

/** One tool as the upstream MCP server describes it. */
export interface UpstreamTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

/** The namespace an upstream's tools are grouped under. */
export function namespaceFor(connection: BrokerConnection): string {
  return deriveMcpNamespace({ name: connection.name });
}

/** The MCP tool name we expose for one of the upstream's tools. */
export function upstreamToolName(connection: BrokerConnection, tool: string): string {
  const path = joinToolPath(namespaceFor(connection), tool);
  return `multitool_${path}`.replace(/[^a-zA-Z0-9_-]/g, '_');
}

/** A JSON-RPC call to the upstream, carried by the broker's HTTP plane. */
async function rpc(
  broker: BrokerClient,
  token: string,
  connection: BrokerConnection,
  method: string,
  params: unknown,
  id: number,
): Promise<unknown> {
  const response = (await broker.invoke('/v1/http', token, {
    connection: connection.name,
    method: 'POST',
    path: connection.mcp_path,
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    },
    body: { jsonrpc: '2.0', id, method, params },
  })) as { status?: number; body?: unknown; body_base64?: string };

  if (response.status && (response.status < 200 || response.status >= 300)) {
    throw new Error(`the MCP server answered ${response.status}`);
  }

  const envelope = decode(response);
  if (envelope && typeof envelope === 'object' && 'error' in envelope) {
    const failure = (envelope as { error: { message?: string } }).error;
    throw new Error(failure.message ?? 'the MCP server returned an error');
  }
  return (envelope as { result?: unknown })?.result;
}

/** The broker returns a body as JSON, as text, or base64 for binary. */
function decode(response: { body?: unknown; body_base64?: string }): unknown {
  const raw =
    response.body ??
    (response.body_base64 ? Buffer.from(response.body_base64, 'base64').toString('utf8') : null);
  if (raw === null || raw === undefined) return null;
  if (typeof raw !== 'string') return raw;

  try {
    return JSON.parse(raw);
  } catch {
    // A streamable-HTTP server may answer with a single SSE frame.
    for (const line of raw.split('\n')) {
      if (line.startsWith('data: ')) {
        try {
          return JSON.parse(line.slice(6));
        } catch {
          // fall through to the next frame
        }
      }
    }
    return null;
  }
}

/**
 * Ask an upstream MCP server what it offers.
 *
 * MCP requires `initialize` before anything else. We do not hold a session:
 * each call is independent, which costs a round trip and buys us statelessness
 * across sidecar restarts.
 */
export async function listUpstreamTools(
  broker: BrokerClient,
  token: string,
  connection: BrokerConnection,
): Promise<UpstreamTool[]> {
  await rpc(broker, token, connection, 'initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'multitool', version: '0.1.0' },
  }, 1);
  const result = (await rpc(broker, token, connection, 'tools/list', {}, 2)) as {
    tools?: UpstreamTool[];
  };
  return result?.tools ?? [];
}

/** Call one of the upstream's tools. */
export async function callUpstreamTool(
  broker: BrokerClient,
  token: string,
  connection: BrokerConnection,
  tool: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  await rpc(broker, token, connection, 'initialize', {
    protocolVersion: '2025-06-18',
    capabilities: {},
    clientInfo: { name: 'multitool', version: '0.1.0' },
  }, 1);
  return rpc(broker, token, connection, 'tools/call', { name: tool, arguments: args }, 2);
}
