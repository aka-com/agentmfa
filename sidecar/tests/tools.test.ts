import assert from 'node:assert/strict';
import test from 'node:test';

import { BrokerError, type BrokerClient, type BrokerConnection } from '../src/broker';
import { callFor, invoke, projectForMcp, schemaFor } from '../src/tools';

const connection: BrokerConnection = {
  name: 'analytics',
  type: 'pg',
  target: 'db.example:5432/app',
  endpoint: '/v1/pg/open',
  wired: true,
};

const apiConnection: BrokerConnection = {
  name: 'github',
  type: 'api',
  target: 'https://api.github.com',
  endpoint: '/v1/http',
  wired: true,
};

test('API tool schema matches the broker method, path, header, and binary-body contract', () => {
  const schema = schemaFor(apiConnection);
  assert.equal(schema.method.safeParse('POST').success, true);
  assert.equal(schema.method.safeParse('TRACE').success, false);
  assert.equal(schema.path.safeParse('/repos?state=open').success, true);
  assert.equal(schema.path.safeParse('//evil.example/x').success, false);
  assert.equal(schema.path.safeParse('/bad\\path').success, false);
  assert.equal(
    schema.headers.safeParse([
      ['X-Tag', 'first'],
      ['X-Tag', 'second'],
    ]).success,
    true,
  );
  assert.equal(schema.body_base64.safeParse('AQID').success, true);

  const call = callFor(apiConnection, {
    method: 'POST',
    path: '/upload',
    headers: [
      ['X-Tag', 'first'],
      ['X-Tag', 'second'],
    ],
    body_base64: 'AQID',
  });
  assert.deepEqual(call.body.headers, [
    ['X-Tag', 'first'],
    ['X-Tag', 'second'],
  ]);
  assert.equal(call.body.body_base64, 'AQID');
});

test('MCP HTTP projection omits cookie arrays and masks cookie header values', () => {
  const projected = projectForMcp(apiConnection, {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'set-cookie': 'session=secret',
      Cookie: 'other=secret',
    },
    set_cookie_headers: ['session=secret', 'other=secret'],
    body: '{}',
    body_encoding: 'utf8',
  }) as Record<string, unknown>;
  assert.equal('set_cookie_headers' in projected, false);
  assert.deepEqual(projected.headers, {
    'content-type': 'application/json',
    'set-cookie': '[OMITTED BY AGENTMFA]',
    Cookie: '[OMITTED BY AGENTMFA]',
  });
});

test('broker refusal detail survives the MCP tool projection', async () => {
  const broker = {
    invoke: async () => {
      throw new BrokerError(
        403,
        'denied_by_policy',
        'analytics is disabled; the user can enable it in AgentMFA',
      );
    },
  } as unknown as BrokerClient;

  const result = await invoke(broker, { token: 'token' }, connection, {});
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /analytics is disabled/);
  assert.doesNotMatch(result.content[0].text, /wire this agent/);
});

test('broker retry timing survives the MCP tool projection', async () => {
  const broker = {
    invoke: async () => {
      throw new BrokerError(429, 'rate_limited', undefined, 7);
    },
  } as unknown as BrokerClient;

  const result = await invoke(broker, { token: 'token' }, connection, {});
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /Retry after 7 seconds/);
});
