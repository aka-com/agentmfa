// The API connection type, carrying real traffic.
//
// Matrix row: an `api` connection (`POST /v1/http`) against the sandbox
// HTTP fixture, crossed with what an upstream can do to a request —
// answer, redirect, stall, send bytes that are not text, send more than the
// broker will relay, or reject the credential.

import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';

import { Broker, connectionNames, type RelayedResponse } from './lib/broker';
import { requireFixture, sandbox } from './lib/sandbox';

let broker: Broker;

before(async () => {
  await requireFixture();
  broker = await Broker.start({
    label: 'api-requests',
    seed: ['http', 'wrong-credential', 'dead'],
  });
});

after(async () => {
  await broker?.stop();
});

const http = connectionNames.http;

test('a GET reaches the upstream with the credential injected', async () => {
  const relayed = await broker.call({ connection: http, method: 'GET', path: '/authenticated' });
  assert.equal(relayed.status, 200);
  assert.equal(relayed.body_encoding, 'utf8');
  assert.deepEqual(JSON.parse(relayed.body), { authenticated: true });
});

test('the credential never comes back down to the agent', async () => {
  const response = await broker.http({ connection: http, method: 'GET', path: '/authenticated' });
  assert.ok(!response.text.includes(sandbox.httpToken), 'the token is not in the relayed response');

  // …and the same call is in the activity log without it.
  const activity = await broker.activity();
  assert.ok(!JSON.stringify(activity).includes(sandbox.httpToken));
});

test('a credential echoed back by an upstream is redacted on the way out', async () => {
  // The fixture reflects whatever it is sent. A response that happens to
  // contain the credential must not relay it verbatim.
  const relayed = await broker.call({
    connection: http,
    method: 'POST',
    path: '/echo',
    body: `the token is ${sandbox.httpToken} for this connection`,
  });
  assert.equal(relayed.status, 200);
  assert.ok(!relayed.body.includes(sandbox.httpToken), 'the reflected credential is scrubbed');
  assert.ok(relayed.body.includes('[REDACTED]'));
});

test('upstream status codes are relayed, not translated', async () => {
  for (const status of [201, 204, 400, 404, 418, 500, 503]) {
    const relayed = await broker.call({
      connection: http,
      method: 'GET',
      path: `/status/${status}`,
    });
    assert.equal(relayed.status, status, `status ${status} is relayed`);
  }
});

test('a JSON body round-trips, and so does a raw string body', async () => {
  const asJson = await broker.call({
    connection: http,
    method: 'POST',
    path: '/echo',
    headers: { 'content-type': 'application/json' },
    body: { hello: 'sandbox', nested: [1, 2, 3] },
  });
  assert.equal(asJson.status, 200);
  assert.deepEqual(JSON.parse(asJson.body), { hello: 'sandbox', nested: [1, 2, 3] });
  assert.equal(asJson.headers['content-type'], 'application/json');

  const asText = await broker.call({
    connection: http,
    method: 'POST',
    path: '/echo',
    headers: { 'content-type': 'text/plain' },
    body: 'plain bytes, sent as a JSON string',
  });
  assert.equal(asText.body, 'plain bytes, sent as a JSON string');
  assert.equal(asText.headers['content-type'], 'text/plain');
});

test('a base64 body is sent as bytes and binary responses come back base64', async () => {
  const bytes = Buffer.from([0x00, 0x9f, 0x92, 0x96, 0xff]);
  const echoed = await broker.call({
    connection: http,
    method: 'POST',
    path: '/echo',
    body_base64: bytes.toString('base64'),
  });
  assert.equal(echoed.body_encoding, 'base64');
  assert.deepEqual(Buffer.from(echoed.body, 'base64'), bytes);

  const binary = await broker.call({ connection: http, method: 'GET', path: '/binary' });
  assert.equal(binary.status, 200);
  assert.equal(binary.body_encoding, 'base64');
  assert.deepEqual(Buffer.from(binary.body, 'base64'), bytes);
});

test('a same-origin redirect is followed with the credential re-injected', async () => {
  const relayed = await broker.call({
    connection: http,
    method: 'GET',
    path: '/redirect/same-origin',
  });
  // The 302 points at /authenticated, which 401s without the credential:
  // a 200 proves the broker re-injected it on the second hop.
  assert.equal(relayed.status, 200);
  assert.deepEqual(JSON.parse(relayed.body), { authenticated: true });
});

test('a cross-origin redirect is handed back unfollowed', async () => {
  const relayed = await broker.call({
    connection: http,
    method: 'GET',
    path: '/redirect/cross-origin',
  });
  assert.equal(relayed.status, 302);
  // The fixture's credential sink answers 418 if it is ever reached; the
  // raw 302 is what the agent gets instead.
  assert.match(String(relayed.headers.location), /credential-sink/);
  assert.ok(!relayed.body.includes(sandbox.httpToken));
});

test('a slow upstream is waited for, inside the broker budget', async () => {
  const started = Date.now();
  const relayed = await broker.call({ connection: http, method: 'GET', path: '/delay/1' });
  assert.equal(relayed.status, 200);
  assert.ok(Date.now() - started >= 900, 'the broker actually waited');
  assert.deepEqual(JSON.parse(relayed.body), { delayed_seconds: 1 });
});

test('a response under the cap is relayed whole', async () => {
  const relayed = await broker.call({ connection: http, method: 'GET', path: '/large/1048576' });
  assert.equal(relayed.status, 200);
  assert.equal(relayed.body.length, 1024 * 1024);
});

test('a response over the 10 MB cap is refused, not truncated', async () => {
  const response = await broker.http({
    connection: http,
    method: 'GET',
    path: '/large/12582912',
  });
  assert.equal(response.status, 502);
  assert.equal(response.reason, 'response_too_large');
});

test('an upstream that rejects the credential relays its own 401', async () => {
  const relayed = await broker.call({
    connection: connectionNames['wrong-credential'],
    method: 'GET',
    path: '/authenticated',
  });
  assert.equal(relayed.status, 401);

  // The broker also remembers that the destination answered but refused.
  const connection = await broker.refresh(connectionNames['wrong-credential']);
  assert.equal(connection.last_status, 'needs_reconnect');
});

test('an upstream that is not listening is a broker-side 502', async () => {
  const response = await broker.http({
    connection: connectionNames.dead,
    method: 'GET',
    path: '/authenticated',
  });
  assert.equal(response.status, 502);
  // The HTTP plane reports a dial failure as `upstream_error` with the
  // transport diagnosis in `detail`; `upstream_connect_failed` is the
  // Postgres proxy's reason for the same shape of failure.
  assert.equal(response.reason, 'upstream_error');
  assert.match(response.json<{ detail: string }>().detail, /connect|refused|error/i);
  // Whatever the wording, the failure must not carry the credential.
  assert.ok(!response.text.includes('unused-fake-token'));
});

test('a retried mutating call coalesces under its idempotency key', async () => {
  const body = { connection: http, method: 'POST', path: '/echo', body: 'once', request_id: 'ik-1' };
  const first = await broker.call(body);
  const replay = await broker.call(body);
  assert.deepEqual(replay, first);
});

test('the same key with a different payload is a conflict, not a silent replay', async () => {
  await broker.call({
    connection: http,
    method: 'POST',
    path: '/echo',
    body: 'first payload',
    request_id: 'ik-2',
  });
  const response = await broker.http({
    connection: http,
    method: 'POST',
    path: '/echo',
    body: 'a different payload',
    request_id: 'ik-2',
  });
  assert.equal(response.status, 409);
  assert.equal(response.reason, 'request_id_mismatch');
});

test('reads are never coalesced, so a key on a GET is inert', async () => {
  const first = await broker.call({
    connection: http,
    method: 'GET',
    path: '/status/200',
    request_id: 'ik-3',
  });
  const second = await broker.call({
    connection: http,
    method: 'GET',
    // Same key, different path: a coalesced read would 409 here.
    path: '/authenticated',
    request_id: 'ik-3',
  });
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.deepEqual(JSON.parse(second.body), { authenticated: true });
});

test('every brokered call lands in the activity log with its outcome', async () => {
  await broker.call({ connection: http, method: 'GET', path: '/status/404' }, { client: 'auditor' });
  const activity = await broker.activity();
  const entry = activity.find(
    (row) => row.agent === 'auditor' && row.connection === http && row.text.includes('/status/404'),
  );
  assert.ok(entry, 'the call is attributed to the agent and the connection');
});

test('concurrent calls on one connection all complete', async () => {
  const calls: Array<Promise<RelayedResponse>> = [];
  for (let i = 0; i < 8; i += 1) {
    calls.push(broker.call({ connection: http, method: 'GET', path: `/status/${200 + i}` }));
  }
  const results = await Promise.all(calls);
  assert.deepEqual(
    results.map((relayed) => relayed.status),
    [200, 201, 202, 203, 204, 205, 206, 207],
  );
});
