import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { BrokerClient } from '../src/broker';

test('a broker that accepts but never answers is timed out', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'agentmfa-broker-timeout-'));
  const socket = join(dir, 'broker.sock');
  const server = createServer(() => {
    // Deliberately retain the request without responding.
  });
  await new Promise<void>((resolve) => server.listen(socket, resolve));
  try {
    const broker = new BrokerClient(socket, {
      controlMs: 25,
      upstreamMs: 50,
      elicitationMs: 75,
    });
    await assert.rejects(
      broker.whoami({ token: 'token' }),
      /broker call GET \/v1\/whoami timed out after 25ms/,
    );
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(dir, { recursive: true, force: true });
  }
});
