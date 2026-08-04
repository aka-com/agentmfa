import assert from 'node:assert/strict';
import test from 'node:test';
import {
  anchorEndpointExpiries,
  endpointExpired,
  expiredAgoLabel,
} from '../src/endpoint-expiry';
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

test('expiredAgoLabel phrases how long ago the address stopped working', () => {
  const now = Date.parse('2026-07-30T12:00:00Z');
  assert.equal(expiredAgoLabel('2026-07-30T12:00:01Z', undefined, now), '');
  assert.equal(expiredAgoLabel('2026-07-30T11:59:30Z', undefined, now), 'Expired');
  assert.equal(expiredAgoLabel('2026-07-30T11:00:00Z', undefined, now), 'Expired 1 hour ago');
  assert.equal(expiredAgoLabel('2026-07-28T12:00:00Z', undefined, now), 'Expired 2 days ago');
  assert.equal(expiredAgoLabel('', 0, now), 'Expired');
});
