import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CATALOG,
  CATALOG_SECTIONS,
  catalogNameForType,
  connectionsForEntry,
  entryForConnection,
  filterCatalog,
  presetHost,
  visibleCatalog,
} from '../src/catalog';
import { authTemplate, parseApiOrigin } from '../src/connection-input';
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

test('branded apps are added as MCP servers, not raw API origins', () => {
  for (const id of ['github', 'gmail', 'notion', 'onepassword']) {
    const entry = CATALOG.find((candidate) => candidate.id === id);
    assert.equal(entry?.via, 'connection', id);
    assert.equal(entry?.mcp, true, id);
    // Stored as an API connection underneath — same pinned host and same
    // upstream credential injection as any other API tool.
    assert.equal(entry?.connType, 'api', id);
  }
});

test('an MCP connection lists under the generic MCP row', () => {
  const mcp = entryForConnection({
    type: 'api', mcp_path: '/mcp',
  } as never);
  assert.equal(mcp?.id, 'mcp');

  // …and a plain API connection still lists under Custom API.
  const plain = entryForConnection({ type: 'api' } as never);
  assert.equal(plain?.id, 'http');
});

test('the built-in credentials store is a Secrets row', () => {
  const credentials = CATALOG.find((entry) => entry.id === 'credentials');
  assert.equal(credentials?.via, 'builtin');
  assert.equal(credentials?.section, 'Secrets');
});

test('every preset is a valid, addable API prefill', () => {
  const presets = CATALOG.filter((entry) => entry.preset);
  assert.ok(presets.length >= 8, 'the branded API catalog exists');
  for (const entry of presets) {
    const preset = entry.preset!;
    // A preset row is a plain API connection — never MCP, always addable.
    assert.equal(entry.via, 'connection', entry.id);
    assert.equal(entry.connType, 'api', entry.id);
    assert.notEqual(entry.mcp, true, entry.id);
    // The origin must be exactly what the add form accepts (root, no path).
    assert.doesNotThrow(() => parseApiOrigin(preset.origin), entry.id);
    assert.ok(presetHost(preset), entry.id);
    // The auth recipe must compile to an injection template as-is.
    assert.doesNotThrow(
      () => authTemplate('api', preset.authMode, 'A_TOKEN', preset.authDetail ?? ''),
      entry.id,
    );
    assert.ok(preset.name, entry.id);
  }
});

test('preset hosts are unique so host→row mapping stays deterministic', () => {
  const hosts = CATALOG.filter((e) => e.preset).map((e) => presetHost(e.preset!));
  assert.equal(new Set(hosts).size, hosts.length);
});

test('a connection pinned to a preset host lists under its branded row', () => {
  assert.equal(entryForConnection(conn('api', 'api.stripe.com'))?.id, 'stripe');
  assert.equal(entryForConnection(conn('api', 'api.openai.com'))?.id, 'openai');
  // …while an unrecognized host still lists under Custom API.
  assert.equal(entryForConnection(conn('api', 'internal.example.com'))?.id, 'http');
  // An MCP connection at a preset host is still an MCP connection.
  assert.equal(
    entryForConnection({ ...conn('api', 'api.stripe.com'), mcp_path: '/mcp' })?.id,
    'mcp',
  );
});

test('preset rows never rename the generic type dialogs', () => {
  assert.equal(catalogNameForType('api'), 'Custom API');
});

test('keyword search finds apps by what they do', () => {
  assert.ok(filterCatalog('payments').some((entry) => entry.id === 'stripe'));
  assert.ok(filterCatalog('email').some((entry) => entry.id === 'gmail'));
  assert.ok(filterCatalog('errors').some((entry) => entry.id === 'sentry'));
  assert.ok(filterCatalog('sql').some((entry) => entry.id === 'postgres'));
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
