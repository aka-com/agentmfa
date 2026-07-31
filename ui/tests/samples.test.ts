import test from 'node:test';
import assert from 'node:assert/strict';

import { entryForConnection } from '../src/catalog';
import {
  SAMPLE_TOOLS,
  persistSamplesDismissed,
  readSamplesDismissed,
  sampleConnection,
  sampleToolById,
} from '../src/samples';
import type { ConnectionSummary } from '../src/types';
import { ICONS } from '../src/util';

function conn(
  host: string | null,
  overrides: Partial<ConnectionSummary> = {},
): ConnectionSummary {
  return {
    id: 'x', name: 'x', updated_at: '2026-07-30T12:00:00.000Z',
    type: 'api', target: host || '', secret_names: [], oauth: false,
    agent_access: { enabled: true } as ConnectionSummary['agent_access'],
    host, scheme: 'https', port: null, template: null, dbname: null, user: null,
    host_key_fingerprint: null, destination: null, sslmode: null,
    trusted_ca_bundle_path: null,
    ...overrides,
  };
}

test('every sample can honestly promise a one-press connect', () => {
  assert.ok(SAMPLE_TOOLS.length >= 2);
  const ids = new Set(SAMPLE_TOOLS.map((sample) => sample.id));
  assert.equal(ids.size, SAMPLE_TOOLS.length);
  for (const sample of SAMPLE_TOOLS) {
    // The pinned origin is a bare host — no scheme, path, or credentials.
    assert.ok(sample.host, sample.id);
    assert.ok(!/[/@:]/.test(sample.host), sample.id);
    // The health probe matches the broker's test-path grammar: one leading
    // slash, no fragment (query strings are fine).
    assert.match(sample.testPath, /^\/(?!\/)/, sample.id);
    assert.ok(!sample.testPath.includes('#'), sample.id);
    // The card renders its mark from the shared icon set.
    assert.ok(ICONS[sample.icon], sample.id);
  }
});

test('sampleToolById resolves samples and nothing else', () => {
  assert.equal(sampleToolById('sample-hackernews')?.name, 'Hacker News');
  assert.equal(sampleToolById('sample-stackoverflow')?.name, 'Stack Overflow');
  assert.equal(sampleToolById('github'), undefined);
});

test('a sample is recognized by its pinned host, not its name', () => {
  const [hn] = SAMPLE_TOOLS;
  assert.equal(sampleConnection(hn, []), null);
  // Renamed by the user: still the same pinned origin, still connected.
  const renamed = conn('hn.algolia.com', { name: 'my news feed' });
  assert.equal(sampleConnection(hn, [renamed]), renamed);
  // Host matching is case-insensitive, mirroring the catalog's rule.
  assert.ok(sampleConnection(hn, [conn('HN.Algolia.com')]));
  // A different origin, an MCP server on the same host, or another protocol
  // is someone else's connection.
  assert.equal(sampleConnection(hn, [conn('api.stackexchange.com')]), null);
  assert.equal(sampleConnection(hn, [conn('hn.algolia.com', { mcp_path: '/mcp' })]), null);
  assert.equal(sampleConnection(hn, [conn('hn.algolia.com', { type: 'pg' })]), null);
});

test('sample connections list under the generic Custom API row', () => {
  // No catalog preset pins these hosts, so a connected sample must fall
  // through to the plain API row rather than hijacking a branded one.
  for (const sample of SAMPLE_TOOLS) {
    assert.equal(entryForConnection(conn(sample.host))?.id, 'http', sample.id);
  }
});

test('dismissal storage degrades to not-dismissed without localStorage', () => {
  // Node test processes have no localStorage; the guards must absorb that.
  assert.equal(readSamplesDismissed(), false);
  assert.doesNotThrow(() => persistSamplesDismissed());
});
