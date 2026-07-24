import assert from 'node:assert/strict';
import test from 'node:test';
import { activityIdentity } from '../src/activity';
import type { ActivityEntry } from '../src/types';

const base: ActivityEntry = {
  at: '2026-07-24T12:00:00.000Z',
  icon: 'plug',
  tone: 'neutral',
  text: 'Connected',
  detail: null,
  agent: 'agent-a',
  connection: 'tool-a',
  duration_ms: 12,
  confirmation: 'os_authentication',
};

test('activity identity includes attribution and event metadata', () => {
  const identity = activityIdentity(base);

  for (const changed of [
    { ...base, agent: 'agent-b' },
    { ...base, connection: 'tool-b' },
    { ...base, tone: 'warning' },
    { ...base, duration_ms: 13 },
    { ...base, confirmation: 'management_token' },
  ]) {
    assert.notEqual(activityIdentity(changed), identity);
  }
});

test('activity identity treats absent optional metadata consistently', () => {
  assert.equal(
    activityIdentity({ ...base, agent: undefined, duration_ms: undefined }),
    activityIdentity({ ...base, agent: null, duration_ms: null }),
  );
});
