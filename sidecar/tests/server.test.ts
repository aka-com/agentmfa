import test from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';

import { createSidecarServer, tokenMatches } from '../src/server';

const TOKEN = 'a'.repeat(64);

/** Start the server on an ephemeral port and hand back a fetch helper. */
async function serving(): Promise<{
  get: (path: string, token?: string | null) => Promise<Response>;
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
  } finally {
    await app.close();
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
