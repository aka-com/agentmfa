// Everything the broker refuses before an API call reaches an upstream.
//
// Matrix row: an `api` connection crossed with a malformed, mis-aimed, or
// unauthorized request. Each case names a reason from the closed error
// registry in `crates/aka-core/src/wire.rs`; the agent branches on the
// reason, so drift here is a protocol break.

import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';

import { Broker, connectionNames } from './lib/broker';
import { requireFixture } from './lib/sandbox';

let broker: Broker;

before(async () => {
  await requireFixture();
  broker = await Broker.start({ label: 'api-refusals', seed: ['http', 'pg'] });
});

after(async () => {
  await broker?.stop();
});

const http = connectionNames.http;

test('an unknown connection is a 404 that names the ones that exist', async () => {
  const response = await broker.http({
    connection: 'not-a-connection',
    method: 'GET',
    path: '/authenticated',
  });
  assert.equal(response.status, 404);
  assert.equal(response.reason, 'unknown_connection');
  assert.match(response.json<{ detail: string }>().detail, /sandbox-http/);
});

test('naming a Postgres connection on the HTTP plane says where to go instead', async () => {
  const response = await broker.http({
    connection: connectionNames.pg,
    method: 'GET',
    path: '/authenticated',
  });
  assert.equal(response.status, 400);
  assert.equal(response.reason, 'wrong_connection_type');
  assert.match(response.json<{ detail: string }>().detail, /POST \/v1\/pg\/open/);
});

test('an HTTP connection on the Postgres plane is refused the same way', async () => {
  const response = await broker.pgOpen(http);
  assert.equal(response.status, 400);
  assert.equal(response.reason, 'wrong_connection_type');
  assert.match(response.json<{ detail: string }>().detail, /POST \/v1\/http/);
});

test('a method outside the allowed set is invalid_method', async () => {
  for (const method of ['TRACE', 'CONNECT', 'BREW']) {
    const response = await broker.http({ connection: http, method, path: '/authenticated' });
    assert.equal(response.status, 400, `${method} is refused`);
    assert.equal(response.reason, 'invalid_method');
  }
});

test('paths that could re-aim the request are invalid_path', async () => {
  const paths = [
    'authenticated', // no leading slash
    '//evil.example/authenticated', // protocol-relative
    'http://evil.example/authenticated', // absolute
    '/authenticated\\..\\x', // backslash
    '/authenticated#fragment',
  ];
  for (const path of paths) {
    const response = await broker.http({ connection: http, method: 'GET', path });
    assert.equal(response.status, 400, `${path} is refused`);
    assert.equal(response.reason, 'invalid_path');
  }
});

test('the credential header cannot be supplied by the agent', async () => {
  const response = await broker.http({
    connection: http,
    method: 'GET',
    path: '/authenticated',
    headers: { Authorization: 'Bearer something-the-agent-picked' },
  });
  assert.equal(response.status, 400);
  assert.equal(response.reason, 'reserved_header');
});

test('transport-owned headers are reserved too', async () => {
  const response = await broker.http({
    connection: http,
    method: 'GET',
    path: '/authenticated',
    headers: { Host: 'evil.example' },
  });
  assert.equal(response.status, 400);
  assert.equal(response.reason, 'reserved_header');
});

test('a header that is not a header is invalid_header', async () => {
  const response = await broker.http({
    connection: http,
    method: 'GET',
    path: '/authenticated',
    headers: { 'x bad name': 'value' },
  });
  assert.equal(response.status, 400);
  assert.equal(response.reason, 'invalid_header');
});

test('sending both body forms at once is invalid_body', async () => {
  const response = await broker.http({
    connection: http,
    method: 'POST',
    path: '/echo',
    body: 'text',
    body_base64: Buffer.from('bytes').toString('base64'),
  });
  assert.equal(response.status, 400);
  assert.equal(response.reason, 'invalid_body');
  assert.match(response.json<{ detail: string }>().detail, /not both/);
});

test('an undecodable base64 body is invalid_body', async () => {
  const response = await broker.http({
    connection: http,
    method: 'POST',
    path: '/echo',
    body_base64: 'not really base64!!!',
  });
  assert.equal(response.status, 400);
  assert.equal(response.reason, 'invalid_body');
});

test('an over-long idempotency key is refused with its own limit', async () => {
  const response = await broker.http({
    connection: http,
    method: 'POST',
    path: '/echo',
    body: 'x',
    request_id: 'k'.repeat(257),
  });
  assert.equal(response.status, 400);
  assert.equal(response.reason, 'invalid_body');
  assert.match(response.json<{ detail: string }>().detail, /256/);
});

test('a body that is not JSON is invalid_json, with the parser diagnosis', async () => {
  const response = await broker.agentRaw('POST', '/v1/http', {
    headers: { 'content-type': 'application/json' },
    body: undefined,
  });
  assert.equal(response.status, 400);
  assert.equal(response.reason, 'invalid_json');
  assert.ok(typeof response.json<{ detail: string }>().detail === 'string');
});

test('a connection with agent access off is refused, and says who can fix it', async () => {
  const connection = broker.conn(http);
  await broker.setAccess(connection.id, false);
  try {
    const response = await broker.http({
      connection: http,
      method: 'GET',
      path: '/authenticated',
    });
    assert.equal(response.status, 403);
    assert.equal(response.reason, 'denied_by_policy');
    assert.match(response.json<{ detail: string }>().detail, /enable it in AgentMFA/);

    // A disabled connection is still *visible*: an agent has to be able to
    // see that the tool exists and is switched off.
    const listed = await broker.agentRaw('GET', '/v1/connections');
    const entry = listed
      .json<Array<Record<string, unknown>>>()
      .find((row) => row.name === http);
    assert.equal(entry?.wired, false);

    const refusal = (await broker.activity()).find((row) =>
      row.text.includes('Refused (agents disabled)'),
    );
    assert.ok(refusal, 'the refusal is audited');
  } finally {
    await broker.setAccess(connection.id, true);
  }
});

// Last in the file: the per-identity limiter is a rolling minute, so
// exhausting it would refuse whatever ran next.
test('capability calls are rate limited per identity, with a Retry-After', async () => {
  let limited: Awaited<ReturnType<typeof broker.http>> | undefined;
  for (let i = 0; i < 120 && !limited; i += 1) {
    const response = await broker.http({ connection: http, method: 'GET', path: '/status/200' });
    if (response.status === 429) limited = response;
  }
  assert.ok(limited, 'the identity budget is enforced');
  assert.equal(limited.reason, 'rate_limited');
  assert.ok(Number(limited.header('retry-after')) >= 1);
  assert.ok(Number(limited.json<{ retry_after_seconds: number }>().retry_after_seconds) >= 1);

  const audited = (await broker.activity()).some((row) => row.text.includes('Rate limited'));
  assert.ok(audited, 'the throttle is visible to the user');
});
