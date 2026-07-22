import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CONNECT_MODE_LABELS,
  START_OPTIONS,
  START_PROMISE,
  connectModesFor,
  firstTaskPrompt,
  resolveConnectMode,
  startOptionById,
  startProgress,
  startTask,
} from '../src/getting-started';
import { catalogEntryById } from '../src/catalog';
import type { ConnectionSummary, ConnectionType } from '../src/types';

function conn(
  type: ConnectionType,
  name: string,
  enabled = false,
): ConnectionSummary {
  return {
    id: name, name, type, target: name, secret_names: [], oauth: false,
    agent_access: { enabled },
    host: null, scheme: null, port: null, template: null, dbname: null, user: null,
    host_key_fingerprint: null, destination: null, sslmode: null, url: null,
    trusted_ca_bundle_path: null,
  };
}

test('every option that can be added points at a real catalog row', () => {
  for (const option of START_OPTIONS) {
    if (!option.connType) {
      assert.equal(option.catalogId, null, option.id);
      continue;
    }
    const entry = option.catalogId ? catalogEntryById(option.catalogId) : undefined;
    assert.ok(entry, `${option.id} names a catalog row`);
    assert.equal(entry?.connType, option.connType, option.id);
    assert.equal(entry?.via, 'connection', option.id);
  }
});

test('an unknown option id falls back to the first option', () => {
  assert.equal(startOptionById('nope').id, START_OPTIONS[0].id);
  assert.equal(startOptionById('ssh').id, 'ssh');
});

test('the picker omits Custom API and keeps labeled Custom MCP last', () => {
  assert.equal(START_OPTIONS.some((option) => option.id === 'api'), false);
  assert.deepEqual(
    START_OPTIONS.slice(-2).map((option) => option.id),
    ['vercel', 'mcp'],
  );
  assert.equal(START_OPTIONS.at(-1)?.label, 'Custom MCP');
  assert.equal(START_OPTIONS.filter((option) => option.showPickerLabel).length, 1);
  assert.equal(
    START_PROMISE,
    "Give your agent a whole app's tools — GitHub, Notion, anything with MCP.",
  );
});

test('progress tracks add, connect, and enable independently', () => {
  const option = startOptionById('postgres');

  const empty = startProgress(option, [], false);
  assert.deepEqual(
    [empty.added, empty.connected, empty.wired],
    [false, false, false],
  );

  const added = startProgress(option, [conn('pg', 'prod-db')], false);
  assert.deepEqual([added.added, added.connected, added.wired], [true, false, false]);
  assert.equal(added.toolName, 'prod-db');

  const connected = startProgress(option, [conn('pg', 'prod-db')], true);
  assert.deepEqual([connected.added, connected.connected, connected.wired], [true, true, false]);

  const enabled = startProgress(option, [conn('pg', 'prod-db', true)], true);
  assert.ok(enabled.wired);
});

test('a tool of another type does not count toward this option', () => {
  const progress = startProgress(startOptionById('postgres'), [conn('ssh', 'prod-ssh')], false);
  assert.equal(progress.added, false);
  assert.equal(progress.toolName, null);
});

test('the example names an enabled tool when there is one', () => {
  const progress = startProgress(
    startOptionById('postgres'),
    [conn('pg', 'scratch'), conn('pg', 'prod-db', true)],
    true,
  );
  assert.equal(progress.toolName, 'prod-db');
});

test('the ready nudge and the walkthrough resolve to the same first task', () => {
  // Both surfaces route through firstTaskPrompt / the option task, so a given
  // connection type can never show two different first asks.
  for (const type of ['pg', 'ssh'] as const) {
    const option = START_OPTIONS.find((o) => o.connType === type && !o.mcp);
    assert.ok(option, `an option exists for ${type}`);
    assert.equal(firstTaskPrompt('prod', type), option!.task('prod'));
  }
});

test('an unenumerated type (ws) gets a generic read-only first task', () => {
  const task = firstTaskPrompt('feed', 'ws');
  assert.match(task, /feed/);
  assert.match(task, /read-only/);
});

test('the task reads sensibly before any tool exists', () => {
  const option = startOptionById('ssh');
  const task = startTask(option, startProgress(option, [], false));
  assert.match(task, /my-tool/);
  assert.match(task, /disk and memory/);
});

test('the MCP option is not satisfied by a plain API connection', () => {
  const mcp = startOptionById('mcp');
  const plainApi = conn('api', 'billing-api');
  assert.equal(startProgress(mcp, [plainApi], false).added, false);

  const server = {
    ...conn('api', 'custom'), host: 'mcp.internal.example.com', mcp_path: '/mcp',
  };
  assert.equal(startProgress(mcp, [server], false).added, true);
});

test('Direct is offered first, and only for kinds with a direct endpoint', () => {
  for (const id of ['postgres', 'ssh']) {
    const modes = connectModesFor(startOptionById(id));
    assert.equal(modes[0], 'direct', id);
  }
  for (const id of ['notion', 'github', 'mcp']) {
    const modes = connectModesFor(startOptionById(id));
    assert.equal(modes.includes('direct'), false, id);
    assert.equal(modes[0], 'claude-code', id);
  }
  // Every offered mode has a picker label.
  for (const mode of connectModesFor(startOptionById('postgres'))) {
    assert.ok(CONNECT_MODE_LABELS[mode], mode);
  }
});

test('the picked mode survives while offered and falls back when not', () => {
  const postgres = startOptionById('postgres');
  const notion = startOptionById('notion');
  assert.equal(resolveConnectMode('direct', postgres), 'direct');
  assert.equal(resolveConnectMode('codex-desktop', notion), 'codex-desktop');
  // Direct is not offered for an API tool; the pane falls back to the first mode.
  assert.equal(resolveConnectMode('direct', notion), 'claude-code');
  assert.equal(resolveConnectMode('nonsense', postgres), 'direct');
});

test('a branded option is satisfied only by its own connection', () => {
  const notion = startOptionById('notion');
  const notionServer = {
    ...conn('api', 'Notion'), host: 'mcp.notion.com', mcp_path: '/mcp',
  };
  const githubServer = {
    ...conn('api', 'GitHub'), host: 'api.githubcopilot.com', mcp_path: '/mcp',
  };
  assert.equal(startProgress(notion, [githubServer], false).added, false);
  assert.equal(startProgress(notion, [notionServer], false).added, true);
});
