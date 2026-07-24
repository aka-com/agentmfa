import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

import { createSidecarServer } from '../src/server';
import { SessionStore } from '../src/mcp';

const SUPERVISOR_TOKEN = 'a'.repeat(64);

// Two agents: one wired to `prod-db`, one wired to nothing. This is the
// whole point of the phase — the broker decides, the sidecar reports.
const AGENTS: Record<string, { client_id: string; agent: string }> = {
  'token-wired': { client_id: 'client-wired', agent: 'claude-code' },
  'token-bare': { client_id: 'client-bare', agent: 'other-agent' },
  'token-collide': { client_id: 'client-collide', agent: 'collide-agent' },
  'token-mcp': { client_id: 'client-mcp', agent: 'mcp-agent' },
  'token-throttled': { client_id: 'client-throttled', agent: 'throttled-agent' },
};
const WIRED: Record<string, string[]> = {
  'client-wired': ['prod-db'],
  'client-collide': ['prod.db', 'prod db'],
  'client-mcp': ['notion'],
  'client-bare': [],
  'client-throttled': [],
};
/** Connect-requests the fake broker has seen (debounce simulation). */
const connectRequests = new Set<string>();

const CONNECTIONS = [
  { name: 'prod-db', type: 'pg', target: 'db.internal:5432/app', endpoint: '/v1/pg/open' },
  { name: 'deploy-host', type: 'ssh', target: 'deploy@host.internal', endpoint: '/v1/ssh/open' },
  // These two slug to the same MCP tool name: `agentmfa_prod_db_open`.
  // Hyphens survive; dots and spaces do not.
  { name: 'prod.db', type: 'pg', target: 'db.other:5432/app', endpoint: '/v1/pg/open' },
  { name: 'prod db', type: 'pg', target: 'db.third:5432/app', endpoint: '/v1/pg/open' },
  {
    name: 'notion',
    type: 'api',
    target: 'https://mcp.notion.com',
    endpoint: '/v1/http',
    mcp_path: '/mcp',
  },
];

/**
 * A stand-in for an upstream MCP server, reached through the broker.
 *
 * Deliberately *stateful*, because that is the default posture of a server
 * built on the official SDKs: `initialize` issues a session id in a response
 * header, every later request must echo it plus the negotiated
 * `MCP-Protocol-Version`, requests before `notifications/initialized` are
 * refused, `tools/list` paginates, and `tools/call` answers as an SSE body
 * whose first frame is a notification — everything the old
 * treat-it-as-stateless client got wrong.
 */
const upstream = {
  sessions: new Map<string, { initialized: boolean }>(),
  counter: 0,
  deleted: [] as string[],
};

function resetUpstream(): void {
  upstream.sessions.clear();
  upstream.deleted = [];
}

interface UpstreamReply {
  status: number;
  headers?: Record<string, string>;
  body: string;
}

function upstreamHttp(call: {
  method: string;
  headers?: Record<string, string>;
  body?: { id?: number; method: string; params?: unknown };
}): UpstreamReply {
  const requestHeaders = Object.fromEntries(
    Object.entries(call.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]),
  );
  const sessionId = requestHeaders['mcp-session-id'];

  if (call.method === 'DELETE') {
    if (sessionId && upstream.sessions.delete(sessionId)) {
      upstream.deleted.push(sessionId);
      return { status: 200, body: '' };
    }
    return { status: 404, body: '' };
  }

  const request = call.body!;
  const reply = (result: unknown): UpstreamReply => ({
    status: 200,
    body: JSON.stringify({ jsonrpc: '2.0', id: request.id, result }),
  });
  const failure = (message: string): UpstreamReply => ({
    status: 200,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: request.id ?? null,
      error: { code: -32600, message },
    }),
  });

  if (request.method === 'initialize') {
    const id = `sess-${++upstream.counter}`;
    upstream.sessions.set(id, { initialized: false });
    return {
      status: 200,
      // Mixed case on purpose: the client must match header names
      // case-insensitively, as the broker relays whatever case it saw.
      headers: { 'Mcp-Session-Id': id },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        result: { protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'notion' } },
      }),
    };
  }

  const session = sessionId ? upstream.sessions.get(sessionId) : undefined;
  if (!session) return { status: 404, body: 'missing or unknown Mcp-Session-Id' };

  if (request.method === 'notifications/initialized') {
    session.initialized = true;
    return { status: 202, body: '' };
  }
  if (!session.initialized) return failure('server not initialized');
  if (requestHeaders['mcp-protocol-version'] !== '2025-06-18') {
    return { status: 400, body: 'missing or wrong MCP-Protocol-Version' };
  }

  if (request.method === 'tools/list') {
    const cursor = (request.params as { cursor?: string } | undefined)?.cursor;
    if (!cursor) {
      return reply({
        tools: [{ name: 'search', description: 'Search the workspace' }],
        nextCursor: 'page-2',
      });
    }
    return reply({ tools: [{ name: 'create_page', description: 'Create a page' }] });
  }

  if (request.method === 'tools/call') {
    const params = request.params as { name: string; arguments: Record<string, unknown> };
    // A notification frame ahead of the response, so a client that grabs
    // the first parseable frame instead of matching its request id fails.
    const notification = JSON.stringify({
      jsonrpc: '2.0',
      method: 'notifications/message',
      params: { level: 'info', data: 'working…' },
    });
    const response = JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: {
        content: [{ type: 'text', text: `${params.name}:${JSON.stringify(params.arguments)}` }],
      },
    });
    return {
      status: 200,
      headers: { 'content-type': 'text/event-stream' },
      body: `event: message\ndata: ${notification}\n\nevent: message\ndata: ${response}\n\n`,
    };
  }
  return failure('Method not found');
}

/** A stand-in for the broker's control plane, on a Unix socket. */
function fakeBroker(socketPath: string): Promise<Server> {
  const server = createServer((req, res) => {
    const header = req.headers.authorization ?? '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    const identity = AGENTS[token];

    const send = (status: number, body: unknown): void => {
      const payload = JSON.stringify(body);
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(payload);
    };

    if (!identity) {
      send(401, { reason: 'invalid_token' });
      return;
    }
    if (req.url === '/v1/whoami') {
      // The broker throttles per token; the sidecar hits whoami on every
      // request, so a busy agent can trip it here while merely authenticating.
      if (token === 'token-throttled') {
        send(429, { reason: 'rate_limited', retry_after_seconds: 7 });
        return;
      }
      send(200, identity);
      return;
    }
    if (req.url === '/v1/connections') {
      send(
        200,
        CONNECTIONS.map((connection) => ({
          ...connection,
          wired: WIRED[identity.client_id].includes(connection.name),
        })),
      );
      return;
    }
    if (req.method === 'POST' && req.url === '/v1/connect-requests') {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        const body = JSON.parse(Buffer.concat(chunks).toString() || '{}') as { service?: string };
        const key = `${identity.client_id}:${body.service ?? ''}`;
        const fresh = !connectRequests.has(key);
        connectRequests.add(key);
        send(202, { status: fresh ? 'requested' : 'already_requested' });
      });
      return;
    }
    // Data planes: echo what arrived so the test can assert on it, but
    // only for a connection this agent is actually wired to.
    if (req.method === 'POST' && req.url?.startsWith('/v1/')) {
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => chunks.push(chunk));
      req.on('end', () => {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!WIRED[identity.client_id].includes(body.connection)) {
          send(403, { reason: 'denied_by_policy' });
          return;
        }
        if (req.url === '/v1/http' && body.path === '/mcp') {
          // Relay the upstream's answer the way the real broker does:
          // `{status, headers, body, body_encoding}`, body as a string.
          const relayed = upstreamHttp(body);
          send(200, {
            status: relayed.status,
            headers: relayed.headers ?? {},
            body: relayed.body,
            body_encoding: 'utf8',
          });
          return;
        }
        // An MCP upstream that answers, but with an error status — the shape
        // of a server that is reachable through the broker yet not serving.
        if (req.url === '/v1/http' && body.path === '/broken') {
          send(200, { status: 502, body: 'upstream down' });
          return;
        }
        send(200, { endpoint: req.url, body });
      });
      return;
    }
    send(404, { reason: 'not_found' });
  });
  return new Promise((resolve) => server.listen(socketPath, () => resolve(server)));
}

interface Harness {
  url: URL;
  connect: (token: string) => Promise<Client>;
  close: () => Promise<void>;
}

async function harness(): Promise<Harness> {
  resetUpstream();
  const dir = mkdtempSync(join(tmpdir(), 'aka-mcp-'));
  const socketPath = join(dir, 'broker.sock');
  const broker = await fakeBroker(socketPath);

  const sidecar = createSidecarServer({ token: SUPERVISOR_TOKEN, brokerSocket: socketPath });
  await new Promise<void>((resolve) => sidecar.listen(0, '127.0.0.1', resolve));
  const { port } = sidecar.address() as AddressInfo;
  const url = new URL(`http://127.0.0.1:${port}/mcp`);

  const clients: Client[] = [];
  return {
    url,
    connect: async (token: string) => {
      const client = new Client({ name: 'test', version: '1.0.0' });
      await client.connect(
        new StreamableHTTPClientTransport(url, {
          requestInit: { headers: { authorization: `Bearer ${token}` } },
        }),
      );
      clients.push(client);
      return client;
    },
    close: async () => {
      for (const client of clients) await client.close().catch(() => {});
      await new Promise<void>((resolve) => {
        sidecar.closeAllConnections();
        sidecar.close(() => resolve());
      });
      await new Promise<void>((resolve) => broker.close(() => resolve()));
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

/** The text payload of a tool result, parsed. */
function payload(result: unknown): unknown {
  const content = (result as { content: Array<{ type: string; text: string }> }).content;
  return JSON.parse(content[0].text);
}

test('wired connections appear in tools/list as real tools', async () => {
  const app = await harness();
  try {
    const client = await app.connect('token-wired');
    const { tools } = await client.listTools();
    // `prod-db` is wired and `deploy-host` is not, so exactly one tool.
    assert.deepEqual(tools.map((tool) => tool.name).sort(), [
      'agentmfa_connect',
      'agentmfa_prod-db_open',
      'agentmfa_status',
    ]);
    const db = tools.find((tool) => tool.name === 'agentmfa_prod-db_open');
    assert.match(db?.description ?? '', /Postgres/);
  } finally {
    await app.close();
  }
});

test('an agent wired to nothing is told so, not left guessing', async () => {
  const app = await harness();
  try {
    const client = await app.connect('token-bare');
    const { tools } = await client.listTools();
    // Even an unwired agent can ask for tools by name (agentmfa_connect);
    // status remains the "why can't I see it?" explainer.
    assert.deepEqual(tools.map((tool) => tool.name).sort(), [
      'agentmfa_connect',
      'agentmfa_status',
    ]);

    const status = payload(
      await client.callTool({ name: 'agentmfa_status', arguments: {} }),
    ) as { tools: unknown[]; hint?: string };
    assert.deepEqual(status.tools, []);
    assert.match(status.hint ?? '', /wire this agent/i);
  } finally {
    await app.close();
  }
});

test('a colliding tool name costs one tool, not the whole session', async () => {
  const app = await harness();
  try {
    const client = await app.connect('token-collide');
    const { tools } = await client.listTools();
    // The session works, and the second colliding connection is dropped
    // rather than taking every other tool down with it.
    assert.deepEqual(tools.map((tool) => tool.name).sort(), [
      'agentmfa_connect',
      'agentmfa_prod_db_open',
      'agentmfa_status',
    ]);
  } finally {
    await app.close();
  }
});

test('status reports tools wired after the session opened', async () => {
  const app = await harness();
  try {
    const client = await app.connect('token-bare');
    // The user wires something while the agent is already connected.
    WIRED['client-bare'] = ['deploy-host'];
    try {
      const status = payload(
        await client.callTool({ name: 'agentmfa_status', arguments: {} }),
      ) as { pending?: string[]; hint?: string };
      assert.deepEqual(status.pending, ['deploy-host']);
      assert.match(status.hint ?? '', /reconnect/i);
    } finally {
      WIRED['client-bare'] = [];
    }
  } finally {
    await app.close();
  }
});

test("an MCP upstream's own tools are re-exposed, credential-side untouched", async () => {
  const app = await harness();
  try {
    const client = await app.connect('token-mcp');
    const { tools } = await client.listTools();
    // Both pages of the upstream's paginated `tools/list` are present.
    assert.deepEqual(tools.map((tool) => tool.name).sort(), [
      'agentmfa_connect',
      'agentmfa_notion_create_page',
      'agentmfa_notion_search',
      'agentmfa_status',
    ]);

    const result = await client.callTool({
      name: 'agentmfa_notion_search',
      arguments: { query: 'roadmap' },
    });
    // The upstream's own result comes back as it stands.
    assert.deepEqual((result as { content: Array<{ text: string }> }).content, [
      { type: 'text', text: 'search:{"query":"roadmap"}' },
    ]);
  } finally {
    await app.close();
  }
});

test('a curated wiring lists only its allowed subset of upstream tools', async () => {
  // The broker advertises `allowed_tools` on the connection when the user
  // curated a subset; the sidecar's listing mirrors it (the broker enforces
  // it on tools/call regardless).
  const notion = CONNECTIONS.find((c) => c.name === 'notion')! as {
    allowed_tools?: string[] | null;
  };
  notion.allowed_tools = ['search'];
  const app = await harness();
  try {
    const client = await app.connect('token-mcp');
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((tool) => tool.name).sort(), [
      'agentmfa_connect',
      'agentmfa_notion_search',
      'agentmfa_status',
    ]);
  } finally {
    delete notion.allowed_tools;
    await app.close();
  }
});

test('a stateful upstream sees the full handshake and no leaked sessions', async () => {
  // The fake upstream refuses anything without its session id, before
  // `notifications/initialized`, or missing the negotiated protocol-version
  // header — so tools appearing at all proves the handshake. What is
  // asserted here is the cleanup: every session the sidecar opened was
  // DELETEd rather than left for the server's idle reaper.
  const app = await harness();
  try {
    const client = await app.connect('token-mcp');
    await client.callTool({ name: 'agentmfa_notion_search', arguments: { query: 'x' } });
    assert.ok(upstream.deleted.length >= 2, 'list + call should each close their session');
    assert.equal(upstream.sessions.size, 0, 'no upstream session may be left open');
  } finally {
    await app.close();
  }
});

test('an upstream tool call carries only the agent arguments', async () => {
  // Regression: with no declared input schema the MCP SDK hands the
  // handler its `extra` — session id, request headers, and the agent's own
  // Authorization — as the first argument. Forwarding that to the upstream
  // would leak the agent's broker token to a third-party server.
  const app = await harness();
  try {
    const client = await app.connect('token-mcp');
    const result = await client.callTool({
      name: 'agentmfa_notion_search',
      arguments: { query: 'roadmap' },
    });
    const echoed = (result as { content: Array<{ text: string }> }).content[0].text;
    assert.equal(echoed, 'search:{"query":"roadmap"}');
    assert.ok(!echoed.includes('token-mcp'), 'the agent token must not reach the upstream');
    assert.ok(!echoed.includes('authorization'), 'headers must not reach the upstream');
  } finally {
    await app.close();
  }
});

test('an unreachable MCP upstream costs only its own tools', async () => {
  const app = await harness();
  try {
    // `prod-db` is wired alongside nothing that can serve MCP; point the
    // agent at an upstream whose path the fake broker will not answer.
    WIRED['client-wired'] = ['prod-db', 'notion'];
    const notion = CONNECTIONS.find((c) => c.name === 'notion')!;
    notion.mcp_path = '/unreachable';
    try {
      const client = await app.connect('token-wired');
      const { tools } = await client.listTools();
      // The session opened and the healthy tool survived.
      assert.ok(
        tools.some((tool) => tool.name === 'agentmfa_prod-db_open'),
        'the healthy tool should still be registered',
      );
      assert.ok(!tools.some((tool) => tool.name.startsWith('agentmfa_notion')));
    } finally {
      WIRED['client-wired'] = ['prod-db'];
      notion.mcp_path = '/mcp';
    }
  } finally {
    await app.close();
  }
});

test('status reports an MCP upstream by its real tool names', async () => {
  // Regression: status used to map every connection through the request-tool
  // naming convention, so an MCP upstream was advertised as
  // `agentmfa_notion_request` — a tool that does not exist. It must report
  // the names actually registered (`agentmfa_notion_search`).
  const app = await harness();
  try {
    const client = await app.connect('token-mcp');
    const status = payload(
      await client.callTool({ name: 'agentmfa_status', arguments: {} }),
    ) as { tools: Array<{ tool: string; name: string }> };
    assert.deepEqual(
      status.tools.map((entry) => entry.tool).sort(),
      ['agentmfa_notion_create_page', 'agentmfa_notion_search'],
    );
    assert.ok(status.tools.every((entry) => entry.name === 'notion'));
    // The advertised names are exactly the tools the agent can actually call.
    const { tools } = await client.listTools();
    const callable = new Set(tools.map((tool) => tool.name));
    assert.ok(status.tools.every((entry) => callable.has(entry.tool)));
  } finally {
    await app.close();
  }
});

test('status reports an unreachable MCP upstream as an error, not a phantom tool', async () => {
  const app = await harness();
  try {
    WIRED['client-wired'] = ['prod-db', 'notion'];
    const notion = CONNECTIONS.find((c) => c.name === 'notion')!;
    notion.mcp_path = '/broken';
    try {
      const client = await app.connect('token-wired');
      const status = payload(
        await client.callTool({ name: 'agentmfa_status', arguments: {} }),
      ) as {
        tools: Array<{ tool: string; name: string }>;
        errors?: Array<{ name: string; error: string }>;
      };
      // No phantom tool for the dead upstream…
      assert.ok(!status.tools.some((entry) => entry.name === 'notion'));
      // …but the healthy connection is still reported…
      assert.ok(status.tools.some((entry) => entry.tool === 'agentmfa_prod-db_open'));
      // …and the upstream's failure is surfaced, as the docstring promises.
      assert.deepEqual(status.errors?.map((entry) => entry.name), ['notion']);
    } finally {
      WIRED['client-wired'] = ['prod-db'];
      notion.mcp_path = '/mcp';
    }
  } finally {
    await app.close();
  }
});

test('a throttled broker surfaces a retryable 429, not an opaque 500', async () => {
  // The sidecar resolves the token on every request, so a busy agent can trip
  // the broker's per-token limit while merely authenticating. That must reach
  // the agent as a 429 with backoff, not a 500 it will hammer blindly.
  const app = await harness();
  try {
    const response = await fetch(app.url, {
      method: 'POST',
      headers: {
        authorization: 'Bearer token-throttled',
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
    });
    assert.equal(response.status, 429);
    assert.equal(response.headers.get('retry-after'), '7');
    const body = (await response.json()) as { error?: { code: number; message: string } };
    assert.equal(body.error?.code, -32029);
    assert.match(body.error?.message ?? '', /rate limit/i);
  } finally {
    await app.close();
  }
});

test('an unpaired token cannot open a session at all', async () => {
  const app = await harness();
  try {
    await assert.rejects(() => app.connect('token-nonsense'), /401|Unauthorized/i);
  } finally {
    await app.close();
  }
});




test('an unwired connection is never even registered as a tool', async () => {
  const app = await harness();
  try {
    const client = await app.connect('token-wired');
    // Calling it by the name it *would* have had must fail at the protocol
    // level: there is no such tool to invoke.
    const result = await client.callTool({
      name: 'agentmfa_deploy-host_open',
      arguments: {},
    });
    assert.equal((result as { isError?: boolean }).isError, true);
  } finally {
    await app.close();
  }
});

test('invoking a tool proxies to the broker data plane', async () => {
  const app = await harness();
  try {
    const client = await app.connect('token-wired');
    const result = await client.callTool({ name: 'agentmfa_prod-db_open', arguments: {} });
    // The fake broker echoes the request it received, which is how we can
    // see the sidecar named the right connection on the right endpoint.
    assert.deepEqual(payload(result), {
      endpoint: '/v1/pg/open',
      body: { connection: 'prod-db' },
    });
  } finally {
    await app.close();
  }
});

test("one agent cannot ride another agent's session id", async () => {
  const app = await harness();
  try {
    const owner = await app.connect('token-wired');
    // Reach into the transport for the id the way a leak would expose it.
    const sessionId = (owner as unknown as { _transport: { sessionId?: string } })._transport
      .sessionId;
    assert.ok(sessionId, 'the session should have an id to steal');

    const stolen = await fetch(app.url, {
      method: 'POST',
      headers: {
        authorization: 'Bearer token-bare',
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-session-id': sessionId,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
    });
    assert.equal(stolen.status, 404, "another agent's session must not be usable");
  } finally {
    await app.close();
  }
});

test('idle sessions are evicted rather than accumulating forever', async () => {
  // Agents crash without closing; only a clean shutdown fires `onclose`.
  const store = new SessionStore(5, 10);
  const fake = { close: () => Promise.resolve() } as never;
  store.put('a', 'client-1', fake);
  assert.equal(store.size, 1);
  await new Promise((resolve) => setTimeout(resolve, 20));
  store.put('b', 'client-1', fake);
  assert.equal(store.size, 1, 'the idle session should have been swept');
  assert.equal(store.get('a', 'client-1'), null);
});

test('the session count is capped', async () => {
  const store = new SessionStore(60_000, 3);
  const fake = { close: () => Promise.resolve() } as never;
  for (const id of ['a', 'b', 'c', 'd', 'e']) store.put(id, 'client-1', fake);
  assert.ok(store.size <= 3, `expected at most 3 sessions, got ${store.size}`);
  // The most recent survives; the oldest are the ones dropped.
  assert.ok(store.get('e', 'client-1'), 'the newest session should survive');
  assert.equal(store.get('a', 'client-1'), null, 'the oldest should be gone');
});

test('over-budget upstream tools are searchable and callable, not lost', async () => {
  // A budget of one: the upstream's first tool registers, the second is
  // search-only.
  process.env.AGENTMFA_TOOL_BUDGET = '1';
  const app = await harness();
  try {
    const client = await app.connect('token-mcp');
    const { tools } = await client.listTools();
    const names = tools.map((tool) => tool.name).sort();
    assert.ok(names.includes('agentmfa_notion_search'), String(names));
    assert.ok(!names.includes('agentmfa_notion_create_page'), 'second tool is withheld');
    assert.ok(names.includes('agentmfa_search_tools'));
    assert.ok(names.includes('agentmfa_call_tool'));

    // Status owns up to the withheld tools instead of hiding them.
    const status = payload(
      await client.callTool({ name: 'agentmfa_status', arguments: {} }),
    ) as { search_only_tools?: number };
    assert.equal(status.search_only_tools, 1);

    // Search finds the withheld tool and says how to call it.
    const found = payload(
      await client.callTool({
        name: 'agentmfa_search_tools',
        arguments: { query: 'create page' },
      }),
    ) as { results: Array<{ tool: string; call: { tool: string } }> };
    const hit = found.results.find((result) => result.tool === 'create_page');
    assert.ok(hit, JSON.stringify(found));
    assert.equal(hit!.call.tool, 'agentmfa_call_tool');

    // …and the generic invoker reaches it through the broker as usual.
    const result = await client.callTool({
      name: 'agentmfa_call_tool',
      arguments: { connection: 'notion', tool: 'create_page', arguments: { title: 'Hi' } },
    });
    assert.deepEqual((result as { content: Array<{ text: string }> }).content, [
      { type: 'text', text: 'create_page:{"title":"Hi"}' },
    ]);

    // An unknown tool is refused with a pointer at search, not a crash.
    const missing = await client.callTool({
      name: 'agentmfa_call_tool',
      arguments: { connection: 'notion', tool: 'not_a_tool', arguments: {} },
    });
    assert.equal((missing as { isError?: boolean }).isError, true);
  } finally {
    delete process.env.AGENTMFA_TOOL_BUDGET;
    await app.close();
  }
});

test('agentmfa_connect files a request with the broker and reports back', async () => {
  const app = await harness();
  try {
    const client = await app.connect('token-bare');
    const text = (result: unknown): string =>
      (result as { content: Array<{ text: string }> }).content[0].text;
    const first = text(await client.callTool({
      name: 'agentmfa_connect',
      arguments: { service: 'linear' },
    }));
    assert.match(first, /add "linear" in the AgentMFA app/i);
    const again = text(await client.callTool({
      name: 'agentmfa_connect',
      arguments: { service: 'linear' },
    }));
    assert.match(again, /already requested/i);
  } finally {
    await app.close();
  }
});
