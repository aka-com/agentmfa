import assert from 'node:assert/strict';
import test from 'node:test';

import { activeRequestCount, activeRequests } from '../src/requests';
import type { Approval, ElicitationRequest } from '../src/types';

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
