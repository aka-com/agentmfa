import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CATALOG,
  CATALOG_SECTIONS,
  connectionsForEntry,
  entryForConnection,
  filterCatalog,
  visibleCatalog,
} from '../src/catalog';
import type { ConnectionSummary, ConnectionType } from '../src/types';

function conn(type: ConnectionType, host: string | null, name = 'x'): ConnectionSummary {
  return {
    id: name, name, type, target: host || '', secret_names: [], wired_agents: [],
    host, scheme: null, port: null, template: null, dbname: null, user: null,
    host_key_fingerprint: null, destination: null, sslmode: null, url: null,
    trusted_ca_bundle_path: null,
  };
}

test('every entry lives in a known section; only connection entries are addable', () => {
  for (const entry of CATALOG) {
    assert.ok(CATALOG_SECTIONS.includes(entry.section), entry.id);
    if (entry.via === 'connection') assert.ok(entry.connType, entry.id);
    else assert.equal(entry.connType, undefined, entry.id);
  }
});

test('branded apps are MCP-bound, not raw connections', () => {
  for (const id of ['github', 'gmail', 'notion', 'onepassword']) {
    assert.equal(CATALOG.find((entry) => entry.id === id)?.via, 'mcp', id);
  }
});

test('the built-in credentials store is a Secrets row', () => {
  const credentials = CATALOG.find((entry) => entry.id === 'credentials');
  assert.equal(credentials?.via, 'builtin');
  assert.equal(credentials?.section, 'Secrets');
});

test('each protocol maps to exactly one infrastructure row', () => {
  assert.equal(entryForConnection(conn('api', 'api.github.com'))?.id, 'http');
  assert.equal(entryForConnection(conn('api', 'internal.example.com'))?.id, 'http');
  assert.equal(entryForConnection(conn('pg', 'db.internal'))?.id, 'postgres');
  assert.equal(entryForConnection(conn('ssh', 'prod.example.com'))?.id, 'ssh');
  assert.equal(entryForConnection(conn('ws', null))?.id, 'websocket');
});

test('every connection is counted by exactly one row', () => {
  const connections = [
    conn('api', 'api.github.com', 'gh-1'),
    conn('api', 'internal.example.com', 'internal'),
    conn('pg', 'db.internal', 'db'),
    conn('ssh', 'prod', 'prod-ssh'),
    conn('ws', null, 'feed'),
  ];
  const counted = CATALOG.flatMap((entry) => connectionsForEntry(entry, connections));
  assert.equal(counted.length, connections.length);
  const api = CATALOG.find((entry) => entry.id === 'http')!;
  assert.deepEqual(connectionsForEntry(api, connections).map((c) => c.name), ['gh-1', 'internal']);
});

test('search filters by name and description, empty query returns all', () => {
  assert.equal(filterCatalog('').length, CATALOG.length);
  assert.deepEqual(filterCatalog('git').map((entry) => entry.id), ['github']);
  assert.ok(filterCatalog('database').some((entry) => entry.id === 'postgres'));
  assert.ok(filterCatalog('custom').some((entry) => entry.id === 'websocket'));
  assert.equal(filterCatalog('zzz-nothing').length, 0);
});

test('WebSockets are hidden until the setting is on', () => {
  const ids = (entries: { id: string }[]) => entries.map((entry) => entry.id);

  const off = visibleCatalog('', { showWebsockets: false, connections: [] });
  assert.ok(!ids(off).includes('websocket'));
  assert.ok(ids(off).includes('postgres'), 'only WebSocket is affected');

  const on = visibleCatalog('', { showWebsockets: true, connections: [] });
  assert.ok(ids(on).includes('websocket'));
});

test('a configured WebSocket tool stays visible even with the setting off', () => {
  // Hiding a row must never strand a tool the user already has.
  const entries = visibleCatalog('', {
    showWebsockets: false,
    connections: [conn('ws', null, 'market-feed')],
  });
  assert.ok(entries.map((entry) => entry.id).includes('websocket'));
});

test('search still respects the WebSocket setting', () => {
  const hidden = visibleCatalog('websocket', { showWebsockets: false, connections: [] });
  assert.equal(hidden.length, 0);
});
