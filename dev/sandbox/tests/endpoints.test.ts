// Direct endpoints: standing access an unmodified client can hold.
//
// Matrix row: each connection type crossed with its endpoint's lifecycle —
// issue, use with a stock client, present the wrong secret, rotate, revoke,
// and lose it when the connection is switched off. Tickets are the short
// path; an endpoint is the one an agent keeps in its own config, so the
// secret it carries is a separate, individually revocable capability.

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import test, { after, before } from 'node:test';

import { Broker, connectionNames, type IssuedEndpointDto } from './lib/broker';
import { request } from './lib/http';
import { parseDsn, queryOnce } from './lib/pgwire';
import { requireFixture, sandbox } from './lib/sandbox';
import { listIdentities } from './lib/sshagent';

let broker: Broker;

before(async () => {
  await requireFixture();
  broker = await Broker.start({ label: 'endpoints', seed: ['http', 'pg', 'ssh'] });
});

after(async () => {
  await broker?.stop();
});

async function issue(name: string): Promise<IssuedEndpointDto> {
  return broker.manage<IssuedEndpointDto>('POST', `/connections/${broker.conn(name).id}/endpoint`);
}

/** Call an API endpoint the way a `curl` in the agent's shell would. */
async function callEndpoint(dsn: string, secret: string, path = '/authenticated') {
  const url = new URL(dsn);
  return request({
    host: url.hostname,
    port: Number(url.port),
    path,
    headers: { authorization: `Bearer ${secret}` },
    timeoutMs: 30_000,
  });
}

test('an API endpoint is a loopback address plus its own secret', async () => {
  const endpoint = await issue(connectionNames.http);
  assert.equal(endpoint.type, 'api');
  assert.match(endpoint.secret, /^end_[0-9a-f]{64}$/);
  assert.match(endpoint.dsn, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.match(endpoint.example, /^curl -H "Authorization: Bearer end_/);

  const response = await callEndpoint(endpoint.dsn, endpoint.secret);
  assert.equal(response.status, 200);
  assert.deepEqual(response.json(), { authenticated: true });
  // The endpoint secret is what the caller holds; the upstream credential
  // is swapped in on the way out and never comes back.
  assert.ok(!response.text.includes(sandbox.httpToken));
});

test('the endpoint secret is not the broker key, and neither substitutes', async () => {
  const endpoint = await issue(connectionNames.http);

  const wrongSecret = await callEndpoint(endpoint.dsn, 'end_not-a-real-secret');
  assert.equal(wrongSecret.status, 401);

  const brokerKey = await callEndpoint(endpoint.dsn, broker.agentToken);
  assert.equal(brokerKey.status, 401, 'the shared agent key does not open an endpoint');
});

test('reissuing rotates the secret in place', async () => {
  const first = await issue(connectionNames.http);
  const second = await issue(connectionNames.http);
  assert.equal(second.endpoint_id, first.endpoint_id, 'the address is stable');
  assert.notEqual(second.secret, first.secret);

  const stale = await callEndpoint(first.dsn, first.secret);
  assert.equal(stale.status, 401, 'the previously pasted secret stops working');
  const fresh = await callEndpoint(second.dsn, second.secret);
  assert.equal(fresh.status, 200);
});

test('the issued endpoint shows up on the connection, without its secret', async () => {
  const endpoint = await issue(connectionNames.http);
  const connection = await broker.refresh(connectionNames.http);
  assert.equal(connection.agent_access.endpoint?.endpoint_id, endpoint.endpoint_id);
  assert.equal(connection.agent_access.endpoint?.type, 'api');
  // The API chip carries the address only; the secret is fetched explicitly.
  assert.ok(!JSON.stringify(connection.agent_access.endpoint).includes(endpoint.secret));
});

test('revoking an endpoint takes the listener down with it', async () => {
  const endpoint = await issue(connectionNames.http);
  const revoked = await broker.manage<{ revoked: boolean }>(
    'DELETE',
    `/endpoints/${endpoint.endpoint_id}`,
  );
  assert.equal(revoked.revoked, true);
  await assert.rejects(callEndpoint(endpoint.dsn, endpoint.secret));

  const connection = await broker.refresh(connectionNames.http);
  assert.equal(connection.agent_access.endpoint, undefined);
});

test('an endpoint cannot be issued for a connection agents may not use', async () => {
  const connection = broker.conn(connectionNames.http);
  await broker.setAccess(connection.id, false);
  try {
    const response = await broker.manageRaw('POST', `/connections/${connection.id}/endpoint`);
    assert.equal(response.status, 409);
    assert.equal(response.json<{ code: string }>().code, 'endpoint_requires_wiring');
  } finally {
    await broker.setAccess(connection.id, true);
  }
});

test('a Postgres endpoint is a pasteable DSN a stock client can use', async () => {
  const endpoint = await issue(connectionNames.pg);
  assert.equal(endpoint.type, 'pg');
  // libpq reaches the per-endpoint Unix socket from `host=<dir>`; the
  // secret rides in the password slot so the string works standalone.
  assert.match(endpoint.dsn, /^postgresql:\/\/aka:end_[0-9a-f]{64}@\/aka_sandbox\?host=/);
  assert.match(endpoint.example, /^DATABASE_URL=/);

  const result = await queryOnce(parseDsn(endpoint.dsn), 'SELECT current_user, current_database()');
  assert.deepEqual(result.rows, [[sandbox.pgUser, sandbox.pgDatabase]]);
});

test('a Postgres endpoint refuses the wrong secret', async () => {
  const endpoint = await issue(connectionNames.pg);
  const options = parseDsn(endpoint.dsn);
  await assert.rejects(
    queryOnce({ ...options, password: 'end_not-the-secret' }, 'SELECT 1'),
    /FATAL|closed/,
  );
});

test('a Postgres endpoint session is visible and closable like a ticket session', async () => {
  const endpoint = await issue(connectionNames.pg);
  const result = await queryOnce(parseDsn(endpoint.dsn), 'SELECT 1');
  assert.equal(result.rows[0][0], '1');

  const activity = await broker.activity();
  assert.ok(
    activity.some((entry) => entry.connection === connectionNames.pg),
    'endpoint sessions are audited against the connection',
  );
  assert.ok(!JSON.stringify(activity).includes(endpoint.secret));
});

test('an SSH endpoint is a stable agent socket, with no secret to carry', async () => {
  const endpoint = await issue(connectionNames.ssh);
  assert.equal(endpoint.type, 'ssh');
  assert.equal(endpoint.secret, '', 'the socket path is the whole capability');
  assert.ok(existsSync(endpoint.dsn));
  assert.match(endpoint.example, /^SSH_AUTH_SOCK=/);

  const identities = await listIdentities(endpoint.dsn);
  assert.equal(identities.length, 1);
  assert.equal(identities[0].type, 'ssh-ed25519');
});

test('switching a connection off closes its endpoint too', async () => {
  const endpoint = await issue(connectionNames.pg);
  const connection = broker.conn(connectionNames.pg);
  await broker.setAccess(connection.id, false);
  try {
    await assert.rejects(queryOnce(parseDsn(endpoint.dsn), 'SELECT 1'));
  } finally {
    await broker.setAccess(connection.id, true);
  }
});

test('deleting a connection revokes the endpoint it issued', async () => {
  await broker.addSecret('THROWAWAY_TOKEN', sandbox.httpToken);
  const added = await broker.addConnection({
    name: 'sandbox-throwaway',
    config: {
      kind: 'api',
      host: sandbox.host,
      scheme: 'http',
      port: sandbox.httpPort,
      template: 'Authorization: Bearer {{THROWAWAY_TOKEN}}',
    },
    secrets: [],
  });
  const endpoint = await broker.manage<IssuedEndpointDto>(
    'POST',
    `/connections/${added.id}/endpoint`,
  );
  assert.equal((await callEndpoint(endpoint.dsn, endpoint.secret)).status, 200);

  await broker.manage('DELETE', `/connections/${added.id}`);
  await assert.rejects(callEndpoint(endpoint.dsn, endpoint.secret));
});
