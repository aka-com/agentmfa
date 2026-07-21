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
};
const WIRED: Record<string, string[]> = {
  'client-wired': ['prod-db'],
  'client-collide': ['prod.db', 'prod db'],
  'client-mcp': ['notion'],
  'client-bare': [],
};
const CONNECTIONS = [
  { name: 'prod-db', type: 'pg', target: 'db.internal:5432/app', endpoint: '/v1/pg/open' },
  { name: 'deploy-host', type: 'ssh', target: 'deploy@host.internal', endpoint: '/v1/ssh/open' },
  // These two slug to the same MCP tool name: `multitool_prod_db_open`.
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

/** A stand-in for an upstream MCP server, reached through the broker. */
function upstreamRpc(request: { id: number; method: string; params?: unknown }): unknown {
  const reply = (result: unknown) => ({ jsonrpc: '2.0', id: request.id, result });
  if (request.method === 'initialize') {
    return reply({ protocolVersion: '2025-06-18', capabilities: {}, serverInfo: { name: 'notion' } });
  }
  if (request.method === 'tools/list') {
    return reply({
      tools: [{ name: 'search', description: 'Search the workspace' }],
    });
  }
  if (request.method === 'tools/call') {
    const params = request.params as { name: string; arguments: Record<string, unknown> };
    return reply({ content: [{ type: 'text', text: `${params.name}:${JSON.stringify(params.arguments)}` }] });
  }
  return { jsonrpc: '2.0', id: request.id, error: { code: -32601, message: 'Method not found' } };
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
          send(200, { status: 200, body: upstreamRpc(body.body) });
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
      'multitool_prod-db_open',
      'multitool_status',
    ]);
    const db = tools.find((tool) => tool.name === 'multitool_prod-db_open');
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
    assert.deepEqual(tools.map((tool) => tool.name), ['multitool_status']);

    const status = payload(
      await client.callTool({ name: 'multitool_status', arguments: {} }),
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
      'multitool_prod_db_open',
      'multitool_status',
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
        await client.callTool({ name: 'multitool_status', arguments: {} }),
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
    assert.deepEqual(tools.map((tool) => tool.name).sort(), [
      'multitool_notion_search',
      'multitool_status',
    ]);

    const result = await client.callTool({
      name: 'multitool_notion_search',
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

test('an upstream tool call carries only the agent arguments', async () => {
  // Regression: with no declared input schema the MCP SDK hands the
  // handler its `extra` — session id, request headers, and the agent's own
  // Authorization — as the first argument. Forwarding that to the upstream
  // would leak the agent's broker token to a third-party server.
  const app = await harness();
  try {
    const client = await app.connect('token-mcp');
    const result = await client.callTool({
      name: 'multitool_notion_search',
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
        tools.some((tool) => tool.name === 'multitool_prod-db_open'),
        'the healthy tool should still be registered',
      );
      assert.ok(!tools.some((tool) => tool.name.startsWith('multitool_notion')));
    } finally {
      WIRED['client-wired'] = ['prod-db'];
      notion.mcp_path = '/mcp';
    }
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
      name: 'multitool_deploy-host_open',
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
    const result = await client.callTool({ name: 'multitool_prod-db_open', arguments: {} });
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
