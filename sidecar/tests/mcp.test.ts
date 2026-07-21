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
};
const WIRED: Record<string, string[]> = {
  'client-wired': ['prod-db'],
  'client-bare': [],
};
const CONNECTIONS = [
  { name: 'prod-db', type: 'pg', target: 'db.internal:5432/app', endpoint: '/v1/pg/open' },
  { name: 'deploy-host', type: 'ssh', target: 'deploy@host.internal', endpoint: '/v1/ssh/open' },
];

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

test('a paired agent can open a session and list tools', async () => {
  const app = await harness();
  try {
    const client = await app.connect('token-wired');
    const { tools } = await client.listTools();
    assert.deepEqual(
      tools.map((tool) => tool.name).sort(),
      ['multitool_describe_tool', 'multitool_list_tools'],
    );
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

test('only wired tools are listed to the agent', async () => {
  const app = await harness();
  try {
    const wired = await app.connect('token-wired');
    const listed = payload(await wired.callTool({ name: 'multitool_list_tools', arguments: {} }));
    assert.deepEqual(listed, [
      {
        tool: 'multitool_prod-db',
        name: 'prod-db',
        type: 'pg',
        target: 'db.internal:5432/app',
      },
    ]);

    // Same broker, same connections, no wirings: the agent sees nothing.
    const bare = await app.connect('token-bare');
    assert.deepEqual(payload(await bare.callTool({ name: 'multitool_list_tools', arguments: {} })), []);
  } finally {
    await app.close();
  }
});

test('an unwired tool is refused even when named directly', async () => {
  const app = await harness();
  try {
    const client = await app.connect('token-wired');
    const result = await client.callTool({
      name: 'multitool_describe_tool',
      arguments: { name: 'deploy-host' },
    });
    assert.equal((result as { isError?: boolean }).isError, true);

    // Refused identically to a name that does not exist, so the reply
    // cannot be used to enumerate what the user declined to wire.
    const unknown = await client.callTool({
      name: 'multitool_describe_tool',
      arguments: { name: 'no-such-thing' },
    });
    const refusal = (r: unknown) =>
      (r as { content: Array<{ text: string }> }).content[0].text.replace(/"[^"]*"/, '"X"');
    assert.equal(refusal(result), refusal(unknown));
  } finally {
    await app.close();
  }
});

test('a wired tool describes itself', async () => {
  const app = await harness();
  try {
    const client = await app.connect('token-wired');
    const described = payload(
      await client.callTool({ name: 'multitool_describe_tool', arguments: { name: 'prod-db' } }),
    );
    assert.deepEqual(described, {
      tool: 'multitool_prod-db',
      name: 'prod-db',
      type: 'pg',
      target: 'db.internal:5432/app',
      endpoint: '/v1/pg/open',
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
