import test from 'node:test';
import assert from 'node:assert/strict';

import {
  START_OPTIONS,
  firstTaskPrompt,
  startOptionById,
  startProgress,
  startTask,
} from '../src/getting-started';
import { CATALOG } from '../src/catalog';
import type { AgentSummary, ConnectionSummary, ConnectionType } from '../src/types';

function conn(
  type: ConnectionType,
  name: string,
  wired: string[] = [],
): ConnectionSummary {
  return {
    id: name, name, type, target: name, secret_names: [], oauth: false,
    wired_agents: wired.map((agent) => ({ agent_id: agent, agent, mode: 'read-write' as const })),
    host: null, scheme: null, port: null, template: null, dbname: null, user: null,
    host_key_fingerprint: null, destination: null, sslmode: null, url: null,
    trusted_ca_bundle_path: null,
  };
}
const agent = (name: string): AgentSummary =>
  ({ id: name, name, paired_at: '', last_used: '', wiring_count: 0 });

test('every option that can be added points at a real catalog row', () => {
  for (const option of START_OPTIONS) {
    if (!option.connType) {
      assert.equal(option.catalogId, null, option.id);
      continue;
    }
    const entry = CATALOG.find((candidate) => candidate.id === option.catalogId);
    assert.ok(entry, `${option.id} names a catalog row`);
    assert.equal(entry?.connType, option.connType, option.id);
    assert.equal(entry?.via, 'connection', option.id);
  }
});

test('an unknown option id falls back to the first option', () => {
  assert.equal(startOptionById('nope').id, START_OPTIONS[0].id);
  assert.equal(startOptionById('ssh').id, 'ssh');
});

test('progress tracks add, connect, and wire independently', () => {
  const option = startOptionById('postgres');

  const empty = startProgress(option, [], []);
  assert.deepEqual(
    [empty.added, empty.connected, empty.wired],
    [false, false, false],
  );

  const added = startProgress(option, [conn('pg', 'prod-db')], []);
  assert.deepEqual([added.added, added.connected, added.wired], [true, false, false]);
  assert.equal(added.toolName, 'prod-db');

  const connected = startProgress(option, [conn('pg', 'prod-db')], [agent('claude-code')]);
  assert.deepEqual([connected.added, connected.connected, connected.wired], [true, true, false]);
  assert.equal(connected.agentName, 'claude-code');

  const wired = startProgress(
    option,
    [conn('pg', 'prod-db', ['claude-code'])],
    [agent('claude-code')],
  );
  assert.ok(wired.wired);
});

test('a tool of another type does not count toward this option', () => {
  const progress = startProgress(startOptionById('postgres'), [conn('ssh', 'prod-ssh')], []);
  assert.equal(progress.added, false);
  assert.equal(progress.toolName, null);
});

test('the example names a wired tool when there is one', () => {
  const progress = startProgress(
    startOptionById('postgres'),
    [conn('pg', 'scratch'), conn('pg', 'prod-db', ['claude-code'])],
    [agent('claude-code')],
  );
  assert.equal(progress.toolName, 'prod-db');
});

test('the wire step names the agent that actually holds the wiring', () => {
  // Two agents registered; only the second is wired. The step must name the
  // wired one, not agents[0].
  const progress = startProgress(
    startOptionById('postgres'),
    [conn('pg', 'prod-db', ['ci-bot'])],
    [agent('claude-code'), agent('ci-bot')],
  );
  assert.ok(progress.wired);
  assert.equal(progress.agentName, 'ci-bot');
});

test('the ready nudge and the walkthrough resolve to the same first task', () => {
  // Both surfaces route through firstTaskPrompt / the option task, so a given
  // connection type can never show two different first asks.
  for (const type of ['pg', 'ssh', 'api'] as const) {
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
  const task = startTask(option, startProgress(option, [], []));
  assert.match(task, /my-tool/);
  assert.match(task, /disk and memory/);
});

test('the MCP option is not satisfied by a plain API connection', () => {
  const mcp = startOptionById('mcp');
  const plainApi = conn('api', 'billing-api');
  assert.equal(startProgress(mcp, [plainApi], []).added, false);

  const server = { ...conn('api', 'notion'), mcp_path: '/mcp' };
  assert.equal(startProgress(mcp, [server], []).added, true);
});

test('the Custom API option is not satisfied by an MCP server', () => {
  const api = startOptionById('api');
  const server = { ...conn('api', 'notion'), mcp_path: '/mcp' };
  assert.equal(startProgress(api, [server], []).added, false);
  assert.equal(startProgress(api, [conn('api', 'billing-api')], []).added, true);
});
