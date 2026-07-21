import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CATALOG,
  CATALOG_SECTIONS,
  connectionsForEntry,
  entryForConnection,
  filterCatalog,
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

test('every entry lives in a known section and mcp entries are not addable', () => {
  for (const entry of CATALOG) {
    assert.ok(CATALOG_SECTIONS.includes(entry.section), entry.id);
    if (entry.via === 'mcp') assert.equal(entry.connType, undefined);
    if (entry.via === 'connection') assert.ok(entry.connType, entry.id);
  }
});

test('branded api hosts claim their row; other api hosts fall to HTTP API', () => {
  assert.equal(entryForConnection(conn('api', 'api.github.com'))?.id, 'github');
  assert.equal(entryForConnection(conn('api', 'api.notion.com'))?.id, 'notion');
  assert.equal(entryForConnection(conn('api', 'internal.example.com'))?.id, 'http');
});

test('protocol types map to their infrastructure rows', () => {
  assert.equal(entryForConnection(conn('pg', 'db.internal'))?.id, 'postgres');
  assert.equal(entryForConnection(conn('ssh', 'prod.example.com'))?.id, 'ssh');
  assert.equal(entryForConnection(conn('ws', null))?.id, 'websocket');
});

test('every connection is counted by exactly one row', () => {
  const connections = [
    conn('api', 'api.github.com', 'gh-1'),
    conn('api', 'API.GitHub.com', 'gh-2'),
    conn('api', 'internal.example.com', 'internal'),
    conn('pg', 'db.internal', 'db'),
    conn('ssh', 'prod', 'prod-ssh'),
    conn('ws', null, 'feed'),
  ];
  const counted = CATALOG.flatMap((entry) => connectionsForEntry(entry, connections));
  assert.equal(counted.length, connections.length);
  const github = CATALOG.find((entry) => entry.id === 'github')!;
  assert.deepEqual(connectionsForEntry(github, connections).map((c) => c.name), ['gh-1', 'gh-2']);
});

test('search filters by name and description, empty query returns all', () => {
  assert.equal(filterCatalog('').length, CATALOG.length);
  assert.deepEqual(filterCatalog('git').map((entry) => entry.id), ['github']);
  assert.ok(filterCatalog('database').some((entry) => entry.id === 'postgres'));
  assert.equal(filterCatalog('zzz-nothing').length, 0);
});
