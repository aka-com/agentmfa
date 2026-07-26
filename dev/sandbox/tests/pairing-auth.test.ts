// Pairing, the shared key, and how every plane refuses a bad credential.
//
// Matrix row: "the connection is authenticated" — the leg that runs before
// any connection type matters, plus the two credentials that must never be
// interchangeable (the agent key and the management token).

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import test, { after, before } from 'node:test';

import { Broker } from './lib/broker';
import { requireFixture } from './lib/sandbox';

let broker: Broker;

before(async () => {
  await requireFixture();
  broker = await Broker.start({ label: 'auth', seed: ['http'] });
});

after(async () => {
  await broker?.stop();
});

test('pairing hands back the same shared key that is on disk', async () => {
  const response = await broker.agentRaw('POST', '/v1/pair', {
    token: null,
    body: { agent_name: 'sandbox-tests' },
  });
  assert.equal(response.status, 200);

  const paired = response.json<Record<string, string>>();
  const onDisk = (await readFile(join(broker.root, 'sock/token'), 'utf8')).trim();
  assert.equal(paired.token, onDisk);
  assert.equal(paired.agent, 'sandbox-tests');
  assert.equal(paired.store_at, join(broker.root, 'sock/token'));
  assert.equal(Number(paired.expires_after_days), 30);
});

test('an unusable agent name is refused before anything is minted', async () => {
  const response = await broker.agentRaw('POST', '/v1/pair', {
    token: null,
    body: { agent_name: 'not a valid name!!' },
  });
  assert.equal(response.status, 400);
  assert.equal(response.reason, 'invalid_agent_name');
});

test('whoami reports the identity and the self-reported label', async () => {
  const response = await broker.agentRaw('GET', '/v1/whoami', { client: 'claude-code' });
  assert.equal(response.status, 200);
  const body = response.json<Record<string, string>>();
  assert.equal(body.agent, 'claude-code');
  assert.match(body.client_id, /^[0-9a-f-]{36}$/);
  assert.ok(Date.parse(body.expires_at) > Date.now());
});

test('the client label is attribution only: any label gets the same access', async () => {
  const mine = await broker.agentRaw('GET', '/v1/connections', { client: 'agent-one' });
  const yours = await broker.agentRaw('GET', '/v1/connections', { client: 'agent-two' });
  assert.equal(mine.status, 200);
  assert.equal(yours.status, 200);
  assert.deepEqual(mine.json(), yours.json());
});

test('each way of losing the bearer names its own cause', async () => {
  const absent = await broker.agentRaw('GET', '/v1/whoami', { token: null });
  assert.equal(absent.status, 401);
  assert.equal(absent.reason, 'missing_token');
  assert.equal(absent.json<{ cause: string }>().cause, 'authorization_header_absent');

  const wrongScheme = await broker.agentRaw('GET', '/v1/whoami', {
    token: null,
    headers: { authorization: 'Basic aGVsbG8=' },
  });
  assert.equal(wrongScheme.json<{ cause: string }>().cause, 'authorization_scheme_invalid');

  const empty = await broker.agentRaw('GET', '/v1/whoami', {
    token: null,
    headers: { authorization: 'Bearer ' },
  });
  assert.equal(empty.json<{ cause: string }>().cause, 'bearer_token_empty');
});

test('an unrecognized token is invalid_token with recovery prose', async () => {
  const response = await broker.agentRaw('GET', '/v1/whoami', { token: 'aka_not-a-real-key' });
  assert.equal(response.status, 401);
  assert.equal(response.reason, 'invalid_token');
  assert.match(response.json<{ detail: string }>().detail, /token file|\/v1\/pair/);
});

test('the two credentials are not interchangeable', async () => {
  // The management token on the agent plane…
  const asAgent = await broker.agentRaw('GET', '/v1/connections', { token: broker.manageToken });
  assert.equal(asAgent.status, 401);
  assert.equal(asAgent.reason, 'invalid_token');

  // …and the agent key on the management plane.
  const asManager = await broker.manageRaw('GET', '/connections', { token: broker.agentToken });
  assert.equal(asManager.status, 401);
  assert.equal(asManager.reason, 'invalid_manage_token');
});

test('capability calls are refused the same way as reads', async () => {
  const response = await broker.agentRaw('POST', '/v1/http', {
    token: null,
    body: { connection: 'sandbox-http', method: 'GET', path: '/authenticated' },
  });
  assert.equal(response.status, 401);
  assert.equal(response.reason, 'missing_token');
});

test('pairing has its own brake, separate from the agent limiter', async () => {
  let limited: Awaited<ReturnType<typeof broker.agentRaw>> | undefined;
  for (let i = 0; i < 12 && !limited; i += 1) {
    const response = await broker.agentRaw('POST', '/v1/pair', {
      token: null,
      body: { agent_name: `flood-${i}` },
    });
    if (response.status === 429) limited = response;
  }
  assert.ok(limited, 'a pairing flood is refused');
  assert.equal(limited.reason, 'pairing_rate_limited');
  assert.ok(Number(limited.header('retry-after')) >= 1);
});

// Rotation is last: it invalidates the key every earlier test used.
test('rotating the key supersedes the old one and points at the new file', async () => {
  const stale = broker.agentToken;
  await broker.manage('POST', '/identity/rotate');

  const refused = await broker.agentRaw('GET', '/v1/whoami', { token: stale });
  assert.equal(refused.status, 401);
  assert.equal(refused.reason, 'token_superseded');
  assert.equal(refused.json<{ store_at: string }>().store_at, join(broker.root, 'sock/token'));
  assert.match(refused.json<{ detail: string }>().detail, /re-read the token file/);

  const rotated = (await readFile(join(broker.root, 'sock/token'), 'utf8')).trim();
  assert.notEqual(rotated, stale);
  const accepted = await broker.agentRaw('GET', '/v1/whoami', { token: rotated });
  assert.equal(accepted.status, 200);
});
