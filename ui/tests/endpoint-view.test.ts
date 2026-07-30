import assert from 'node:assert/strict';
import test from 'node:test';
import { anchorEndpointExpiries, endpointExpired } from '../src/endpoint-expiry';
import type { ConnectionSummary } from '../src/types';

test('endpoint expiry re-anchors the broker-clock remainder across clock skew', () => {
  const connection = {
    id: 'c1',
    name: 'database',
    agent_access: {
      enabled: true,
      endpoint: {
        endpoint_id: 'e1',
        type: 'pg',
        expires_at: '2000-01-01T00:00:00Z',
        expires_in_secs: 60,
      },
    },
  } as ConnectionSummary;
  const [anchored] = anchorEndpointExpiries([connection], 1_000);
  assert.equal(anchored.agent_access.endpoint?.expires_at, '1970-01-01T00:01:01.000Z');
  assert.equal(connection.agent_access.endpoint?.expires_at, '2000-01-01T00:00:00Z');
});

test('endpoint expiry falls back to the absolute deadline', () => {
  const now = Date.parse('2026-07-30T12:00:00Z');
  assert.equal(endpointExpired('2026-07-30T11:59:59Z', undefined, now), true);
  assert.equal(endpointExpired('2026-07-30T12:00:01Z', undefined, now), false);
  assert.equal(endpointExpired('', undefined, now), false);
});
