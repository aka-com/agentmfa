import assert from 'node:assert/strict';
import test from 'node:test';

import { activeRequestCount, activeRequests, anchorExpiry, recentRequests } from '../src/requests';
import type { Approval, ElicitationRequest, RequestRecord } from '../src/types';

function approval(id: string, expiresAt: string): Approval {
  return {
    id,
    connection_id: 'connection',
    connection: 'github',
    type: 'api',
    unit: 'request',
    target: 'https://api.github.com',
    agent: 'codex',
    summary: 'GET /user',
    waiting: 1,
    requested_at: '2026-07-24T12:00:00Z',
    expires_at: expiresAt,
    window_secs: 900,
  };
}

function elicitation(id: string, expiresAt: string): ElicitationRequest {
  return {
    id,
    agent: 'claude-code',
    connection: 'notion',
    tool: 'search',
    prompt: 'Which workspace?',
    fields: [{ name: 'workspace', label: 'Workspace' }],
    requested_at: '2026-07-24T12:00:10Z',
    expires_at: expiresAt,
  };
}

test('a broker-relative deadline is re-anchored to the local clock', () => {
  // The broker's wall clock is an hour ahead; its absolute expires_at would
  // render a 90-second prompt as an hour-long fuse. The relative form wins.
  const now = Date.parse('2026-07-24T12:00:00Z');
  const skewed = approval('one', '2026-07-24T13:01:30Z');
  const [anchored] = anchorExpiry([{ ...skewed, expires_in_secs: 90 }], now);

  assert.equal(Date.parse(anchored.expires_at) - now, 90_000);
  assert.equal(skewed.expires_at, '2026-07-24T13:01:30Z', 'inputs are not mutated');
});

test('snapshots from brokers without relative deadlines pass through unchanged', () => {
  const legacy = approval('one', '2026-07-24T12:01:30Z');
  assert.deepEqual(anchorExpiry([legacy], Date.parse('2026-07-24T12:00:00Z')), [legacy]);
});

test('active requests are unified and ordered by the soonest deadline', () => {
  const requests = activeRequests(
    [approval('approval-later', '2026-07-24T12:05:00Z')],
    [elicitation('elicitation-first', '2026-07-24T12:01:00Z')],
  );

  assert.deepEqual(requests.map((request) => request.id), [
    'elicitation-first',
    'approval-later',
  ]);
  assert.equal(activeRequestCount([approval('one', '2026-07-24T12:01:00Z')], []), 1);
});

test('active request sorting does not mutate broker snapshots', () => {
  const approvals = [
    approval('later', '2026-07-24T12:10:00Z'),
    approval('sooner', '2026-07-24T12:02:00Z'),
  ];

  assert.deepEqual(activeRequests(approvals, []).map((request) => request.id), [
    'sooner',
    'later',
  ]);
  assert.deepEqual(approvals.map((request) => request.id), ['later', 'sooner']);
});

function history(
  id: string,
  status: RequestRecord['status'],
  resolvedAt?: string,
): RequestRecord {
  return {
    id,
    kind: 'approval',
    status,
    connection: 'github',
    agent: 'codex',
    summary: 'GET /user',
    waiting: 1,
    requested_at: '2026-07-24T12:00:00Z',
    resolved_at: resolvedAt,
  };
}

test('recent requests contain terminal records newest first', () => {
  const records = [
    history('older', 'denied', '2026-07-24T12:01:00Z'),
    history('pending', 'pending'),
    history('newer', 'approved', '2026-07-24T12:02:00Z'),
  ];

  assert.deepEqual(recentRequests(records).map((request) => request.id), ['newer', 'older']);
  assert.deepEqual(records.map((request) => request.id), ['older', 'pending', 'newer']);
});

test('recent requests exclude ids still present in an active snapshot', () => {
  const records = [history('raced', 'denied', '2026-07-24T12:01:00Z')];
  assert.deepEqual(recentRequests(records, new Set(['raced'])), []);
});
