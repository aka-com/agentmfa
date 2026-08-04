// Discovery and pairing: what an agent can learn before it holds a key.
//
// Matrix row: "no connection yet". These are the only unauthenticated
// routes on the control plane, so they are also the only ones a process
// that has just found the socket can reach.

import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';

import { Broker } from './lib/broker';
import { requireFixture } from './lib/sandbox';

let broker: Broker;

before(async () => {
  await requireFixture();
  broker = await Broker.start({ label: 'discovery', seed: ['http'] });
});

after(async () => {
  await broker?.stop();
});

test('the manifest describes the protocol without a credential', async () => {
  const response = await broker.agentRaw('GET', '/.well-known/agent-broker.json', { token: null });
  assert.equal(response.status, 200);

  const manifest = response.json<Record<string, unknown>>();
  assert.equal(manifest.name, 'aka');
  assert.equal(manifest.protocol_version, 0);
  assert.equal(manifest.transport, 'http-over-unix-socket');
  assert.deepEqual(manifest.auth_schemes, ['bearer']);
  assert.deepEqual(manifest.capabilities, ['http', 'postgres', 'ssh']);
  assert.deepEqual(manifest.endpoints, {
    connections: '/v1/connections',
    http: '/v1/http',
    instructions: '/instructions',
    pair: '/v1/pair',
    pg_open: '/v1/pg/open',
    ssh_open: '/v1/ssh/open',
    whoami: '/v1/whoami',
  });
  // The budgets an agent needs to plan retries and timeouts are machine
  // readable, not prose-only.
  assert.equal(manifest.ticket_ttl_seconds, 60);
  assert.equal(manifest.approval_timeout_seconds, 90);
  assert.equal(manifest.request_id_max_bytes, 256);
  assert.ok(Number(manifest.recommended_client_timeout_seconds) >= 90);
  assert.equal(manifest.socket, broker.socketPath);
});

test('the manifest never carries the key itself', async () => {
  const response = await broker.agentRaw('GET', '/.well-known/agent-broker.json', { token: null });
  assert.ok(!response.text.includes(broker.agentToken));
  assert.ok(!response.text.includes(broker.manageToken));
  // It names where the key lives, which is how a file-reading agent skips
  // pairing entirely.
  assert.equal(response.json<{ token_file: string }>().token_file, `${broker.root}/sock/token`);
});

test('instructions are served as markdown to an unauthenticated caller', async () => {
  const response = await broker.agentRaw('GET', '/instructions', { token: null });
  assert.equal(response.status, 200);
  assert.match(response.text, /^# Multitool: broker instructions/);
  assert.ok(response.text.includes(broker.socketPath));
  assert.ok(response.text.includes('403 denied_by_policy'));
  assert.ok(!response.text.includes(broker.agentToken));
});

test('an unknown path is a 404, not a hint', async () => {
  const response = await broker.agentRaw('GET', '/v1/nope', { token: null });
  assert.equal(response.status, 404);
});

test('a listed connection names the endpoint that carries it', async () => {
  const response = await broker.agentRaw('GET', '/v1/connections');
  assert.equal(response.status, 200);
  const [connection] = response.json<Array<Record<string, unknown>>>();
  assert.equal(connection.name, 'sandbox-http');
  assert.equal(connection.type, 'api');
  assert.equal(connection.endpoint, '/v1/http');
  assert.equal(connection.wired, true);
  assert.equal(connection.target, `http://127.0.0.1:${new URL(String(connection.target)).port}`);
});

test('listing connections is audited but leaks no credential', async () => {
  await broker.agentRaw('GET', '/v1/connections', { client: 'sandbox-tests' });
  const activity = await broker.activity();
  const listed = activity.filter((entry) => entry.text.includes('listed connections'));
  assert.ok(listed.length > 0, 'the listing appears in the activity log');
  assert.ok(listed.some((entry) => entry.agent === 'sandbox-tests'));
  const dump = JSON.stringify(activity);
  assert.ok(!dump.includes('aka-test-token'), 'no upstream credential in the activity log');
});

// Deliberately last in this file: the discovery limiter is global and
// per-minute, so exhausting it would starve any test that ran after it.
test('discovery is rate limited globally, with machine-readable backoff', async () => {
  let limited: Awaited<ReturnType<typeof broker.agentRaw>> | undefined;
  for (let i = 0; i < 200 && !limited; i += 1) {
    const response = await broker.agentRaw('GET', '/instructions', { token: null });
    if (response.status === 429) limited = response;
  }
  assert.ok(limited, 'the unauthenticated surface refuses a flood');
  assert.equal(limited.reason, 'rate_limited');
  assert.ok(Number(limited.header('retry-after')) >= 1);
});
