import assert from 'node:assert/strict';
import test from 'node:test';

import { BrokerError, type BrokerClient, type BrokerConnection } from '../src/broker';
import { invoke } from '../src/tools';

const connection: BrokerConnection = {
  name: 'analytics',
  type: 'pg',
  target: 'db.example:5432/app',
  endpoint: '/v1/pg/open',
  wired: true,
};

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
