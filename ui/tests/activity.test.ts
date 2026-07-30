import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { activityIdentity } from '../src/activity';
import type { ActivityEntry } from '../src/types';

/** `const NAME: usize = 123;` or `const NAME = 123;`, underscores allowed. */
function constant(source: string, name: string): number {
  const found = source.match(new RegExp(`${name}(?:: usize)? = ([\\d_]+)`))?.[1];
  assert.ok(found, `${name} is present`);
  return Number(found.replace(/_/g, ''));
}

const base: ActivityEntry = {
  at: '2026-07-24T12:00:00.000Z',
  icon: 'plug',
  tone: 'neutral',
  text: 'Connected',
  detail: null,
  agent: 'agent-a',
  connection: 'tool-a',
  duration_ms: 12,
  approver: 'local-user',
  surface: 'app_window',
  confirmation: 'os_authentication',
};

test('activity identity includes attribution and event metadata', () => {
  const identity = activityIdentity(base);

  for (const changed of [
    { ...base, agent: 'agent-b' },
    { ...base, connection: 'tool-b' },
    { ...base, tone: 'warning' },
    { ...base, duration_ms: 13 },
    { ...base, approver: '192.0.2.7:4242' },
    { ...base, surface: 'remote' as const },
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

test('a view read does not ask for more of the log than the broker will return', async () => {
  const [app, mock, command, route] = await Promise.all([
    readFile(new URL('../app.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/bridge.ts', import.meta.url), 'utf8'),
    readFile(new URL('../../src-tauri/src/commands.rs', import.meta.url), 'utf8'),
    readFile(new URL('../../crates/aka-core/src/daemon/manage.rs', import.meta.url), 'utf8'),
  ]);

  // The Tauri command clamps to its own ceiling, so a UI asking for more would
  // silently get less: the tail would be shorter than the code above believes,
  // and the filters would quietly search a smaller window than intended.
  const requested = constant(app, 'ACTIVITY_RENDER_LIMIT');
  assert.ok(
    requested <= constant(command, 'ACTIVITY_VIEW_LIMIT'),
    'ACTIVITY_RENDER_LIMIT exceeds the ceiling list_activity clamps to',
  );
  // The manage route's default is what a caller passing no limit receives; a
  // smaller default would make an HTTP read disagree with the app's own read.
  assert.ok(
    requested <= constant(route, 'ACTIVITY_VIEW_LIMIT'),
    'ACTIVITY_RENDER_LIMIT exceeds the manage route default',
  );
  // The dev mock stands in for the command surface; capping lower would make
  // the frontend-only build behave unlike the app it stands in for.
  assert.ok(
    requested <= constant(mock, 'MOCK_ACTIVITY_LIMIT'),
    'the dev mock caps a view read below what the app asks for',
  );
});
