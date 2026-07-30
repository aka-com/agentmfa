import test from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';

import { createSidecarServer, tokenMatches } from '../src/server';
import { SIDECAR_VERSION } from '../src/version';

const TOKEN = 'a'.repeat(64);

/** Start the server on an ephemeral port and hand back a fetch helper. */
async function serving(): Promise<{
  get: (path: string, token?: string | null) => Promise<Response>;
  post: (path: string, body: string, headers?: Record<string, string>) => Promise<Response>;
  close: () => Promise<void>;
}> {
  const server = createSidecarServer({ token: TOKEN, brokerSocket: '/tmp/aka.sock' });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    get: (path, token = TOKEN) =>
      fetch(`http://127.0.0.1:${port}${path}`, {
        headers: token === null ? {} : { authorization: `Bearer ${token}` },
      }),
    post: (path, body, headers = {}) =>
      fetch(`http://127.0.0.1:${port}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body,
      }),
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

test('health reports ok to a caller holding the token', async () => {
  const app = await serving();
  try {
    const response = await app.get('/health');
    assert.equal(response.status, 200);
    const body = (await response.json()) as Record<string, unknown>;
    assert.equal(body.status, 'ok');
    assert.equal(body.pid, process.pid);
    assert.equal(body.version, SIDECAR_VERSION);
  } finally {
    await app.close();
  }
});

test('health surfaces sidecar and broker version skew', async () => {
  const server = createSidecarServer({
    token: TOKEN,
    brokerSocket: '/tmp/aka.sock',
    brokerVersion: 'different-version',
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = server.address() as AddressInfo;
    const response = await fetch(`http://127.0.0.1:${port}/health`, {
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    const body = (await response.json()) as Record<string, unknown>;
    assert.equal(body.version, SIDECAR_VERSION);
    assert.equal(body.broker_version, 'different-version');
    assert.equal(body.version_skew, true);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('the token is the whole story on loopback', async () => {
  const app = await serving();
  try {
    assert.equal((await app.get('/health', null)).status, 401, 'no header');
    assert.equal((await app.get('/health', '')).status, 401, 'empty token');
    assert.equal((await app.get('/health', 'b'.repeat(64))).status, 401, 'wrong token');
    assert.equal((await app.get('/health', TOKEN.slice(0, 32))).status, 401, 'prefix');
  } finally {
    await app.close();
  }
});

test('an unknown route is a 404, not a hint', async () => {
  const app = await serving();
  try {
    assert.equal((await app.get('/nope')).status, 404);
  } finally {
    await app.close();
  }
});

test('token comparison survives a length mismatch', () => {
  // timingSafeEqual throws on differing lengths; the guard must catch that
  // before it becomes a 500 that leaks length information.
  assert.equal(tokenMatches('short', TOKEN), false);
  assert.equal(tokenMatches(`${TOKEN}extra`, TOKEN), false);
  assert.equal(tokenMatches(TOKEN, TOKEN), true);
});

test('malformed MCP JSON reports a parse error before authentication', async () => {
  const app = await serving();
  try {
    const response = await app.post('/mcp', '{"jsonrpc":');
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), {
      jsonrpc: '2.0',
      error: { code: -32700, message: 'Parse error' },
      id: null,
    });
  } finally {
    await app.close();
  }
});

test('MCP request bodies are capped before authentication', async () => {
  const app = await serving();
  try {
    const response = await app.post('/mcp', 'x'.repeat(8 * 1024 * 1024 + 1));
    assert.equal(response.status, 413);
    const body = (await response.json()) as { error?: { message?: string } };
    assert.match(body.error?.message ?? '', /8 MiB/);
  } finally {
    await app.close();
  }
});

test('MCP rejects non-loopback browser origins before authentication', async () => {
  const app = await serving();
  try {
    const rejected = await app.post('/mcp', '{}', {
      origin: 'https://attacker.example',
    });
    assert.equal(rejected.status, 403);

    const loopback = await app.post('/mcp', '{}', {
      origin: 'http://localhost:3000',
    });
    assert.notEqual(loopback.status, 403);
  } finally {
    await app.close();
  }
});

test('the sidecar pins HTTP parser resource budgets', async () => {
  const server = createSidecarServer({ token: TOKEN, brokerSocket: '/tmp/aka.sock' });
  assert.equal(server.maxHeadersCount, 100);
  assert.equal(server.requestTimeout, 30_000);
  assert.equal(server.headersTimeout, 10_000);
  server.close();
});
