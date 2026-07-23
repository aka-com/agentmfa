import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CATALOG,
  CATALOG_SECTIONS,
  REGISTRY_CATALOG,
  canQuickConnectMcp,
  catalogEntryById,
  catalogNameForType,
  collapsedCatalogGroup,
  connectedCatalogFirst,
  connectionEditPresentation,
  connectionsForEntry,
  entryForConnection,
  filterCatalog,
  mcpTemplateForConnection,
  presetHost,
  visibleCatalog,
} from '../src/catalog';
import { authTemplate, parseApiOrigin } from '../src/connection-input';
import type { ConnectionSummary, ConnectionType } from '../src/types';
import { ICONS } from '../src/util';

function conn(type: ConnectionType, host: string | null, name = 'x'): ConnectionSummary {
  return {
    id: name, name, type, target: host || '', secret_names: [], oauth: false, agent_access: { enabled: true },
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

test('infrastructure precedes MCP Apps and generic endpoints live under Custom Apps', () => {
  assert.ok(
    CATALOG_SECTIONS.indexOf('Infrastructure') < CATALOG_SECTIONS.indexOf('MCP Apps'),
  );
  assert.ok(CATALOG_SECTIONS.indexOf('MCP Apps') < CATALOG_SECTIONS.indexOf('Custom Apps'));
  assert.ok(CATALOG_SECTIONS.indexOf('API Apps') < CATALOG_SECTIONS.indexOf('Custom Apps'));
  assert.deepEqual(
    CATALOG.filter((entry) => entry.section === 'Custom Apps').map((entry) => entry.id),
    ['mcp', 'http'],
  );
});

test('setup-required apps lead the disconnected MCP app rows', () => {
  const apps = CATALOG.filter((entry) => entry.section === 'MCP Apps').map((entry) => entry.id);
  const displayed = connectedCatalogFirst(
    CATALOG.filter((entry) => entry.section === 'MCP Apps'),
    [],
  );
  assert.deepEqual(displayed.slice(0, 2).map((entry) => entry.id), ['slack', 'gmail']);
  assert.deepEqual(
    CATALOG.filter((entry) => entry.requiresSetup).map((entry) => entry.id),
    ['slack', 'gmail'],
  );
  assert.ok(apps.indexOf('airtable') < apps.indexOf('linear'));
});

test('key-only vendors live in API Apps, not MCP Apps', () => {
  assert.deepEqual(
    CATALOG.filter((entry) => entry.section === 'API Apps').map((entry) => entry.id),
    ['anthropic', 'openai', 'vercel'],
  );
});

test('branded apps are added as MCP servers, not raw API origins', () => {
  for (const id of ['github', 'gmail', 'notion',
    'airtable', 'linear', 'sentry', 'stripe', 'cloudflare']) {
    const entry = CATALOG.find((candidate) => candidate.id === id);
    assert.equal(entry?.via, 'connection', id);
    assert.equal(entry?.mcp, true, id);
    // Stored as an API connection underneath — same pinned host and same
    // upstream credential injection as any other API tool.
    assert.equal(entry?.connType, 'api', id);
  }
});

test('an unbranded MCP connection lists under the generic MCP row', () => {
  const mcp = entryForConnection({
    type: 'api', mcp_path: '/mcp', host: 'mcp.internal.example.com',
  } as never);
  assert.equal(mcp?.id, 'mcp');

  // …and a plain API connection still lists under Custom API.
  const plain = entryForConnection({ type: 'api' } as never);
  assert.equal(plain?.id, 'http');
});

test('templated vendors ship a server URL and a whoami tool', () => {
  for (const id of ['github', 'notion', 'airtable', 'sentry', 'stripe']) {
    const template = CATALOG.find((entry) => entry.id === id)?.mcpTemplate;
    assert.ok(template?.serverUrl?.startsWith('https://'), id);
    assert.ok(template?.whoamiTool, id);
  }
  // Linear and Cloudflare publish no whoami-style tool.
  for (const id of ['linear', 'cloudflare']) {
    const template = CATALOG.find((entry) => entry.id === id)?.mcpTemplate;
    assert.ok(template?.serverUrl?.startsWith('https://'), id);
    assert.equal(template?.whoamiTool, undefined, id);
  }
  // Gmail's endpoint is published, but Google has no dynamic client
  // registration: the template carries an oauthApp block, so the add form
  // collects the user's OAuth client before the sign-in starts.
  const gmail = CATALOG.find((entry) => entry.id === 'gmail')?.mcpTemplate;
  assert.ok(gmail?.serverUrl?.startsWith('https://'));
  assert.ok(gmail?.oauthApp);
  assert.ok((gmail?.oauthApp?.scopes?.length ?? 0) > 0);
});

test('only MCP rows with a prefilled server URL offer quick OAuth connect', () => {
  for (const id of ['github', 'notion', 'airtable', 'linear', 'sentry', 'stripe', 'cloudflare']) {
    assert.equal(canQuickConnectMcp(CATALOG.find((entry) => entry.id === id)!), true, id);
  }
  for (const id of ['gmail', 'mcp', 'http']) {
    assert.equal(canQuickConnectMcp(CATALOG.find((entry) => entry.id === id)!), false, id);
  }
  assert.ok(REGISTRY_CATALOG.every(canQuickConnectMcp));
});

test('MCP connections group under the brand whose endpoint they pin', () => {
  const github = conn('api', 'api.githubcopilot.com', 'github-work');
  github.mcp_path = '/mcp';
  assert.equal(entryForConnection(github)?.id, 'github');
  assert.equal(mcpTemplateForConnection(github)?.whoamiTool, 'get_me');

  // Host matching is case-insensitive (DNS semantics).
  const shouty = conn('api', 'MCP.NOTION.COM', 'notion-1');
  shouty.mcp_path = '/mcp';
  assert.equal(entryForConnection(shouty)?.id, 'notion');

  // Two accounts on one service are two connections under one brand row.
  const second = conn('api', 'mcp.notion.com', 'notion-personal');
  second.mcp_path = '/mcp';
  const notionEntry = CATALOG.find((entry) => entry.id === 'notion')!;
  assert.deepEqual(
    connectionsForEntry(notionEntry, [shouty, second, conn('api', 'api.example.com')])
      .map((connection) => connection.name),
    ['notion-1', 'notion-personal'],
  );

  // A non-MCP API connection to the same host stays a Custom API: the
  // template covers MCP connections only.
  const rawApi = conn('api', 'mcp.notion.com', 'raw');
  assert.equal(entryForConnection(rawApi)?.id, 'http');
  assert.equal(mcpTemplateForConnection(rawApi), undefined);
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
    // A preset row is addable as a plain API connection (dual-mode rows
    // also carry an MCP template — the preset covers the key path).
    assert.equal(entry.via, 'connection', entry.id);
    assert.equal(entry.connType, 'api', entry.id);
    // The origin must be exactly what the add form accepts (root, no path).
    assert.doesNotThrow(() => parseApiOrigin(preset.origin), entry.id);
    assert.ok(presetHost(preset), entry.id);
    // The auth recipe must compile to an injection template as-is.
    assert.doesNotThrow(
      () => authTemplate('api', preset.authMode, 'A_TOKEN', preset.authDetail ?? ''),
      entry.id,
    );
    assert.equal(preset.name, entry.name, entry.id);
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

test('connection edits preserve MCP branding and identify managed OAuth authentication', () => {
  const notion = {
    ...conn('api', 'mcp.notion.com', 'Notion'),
    mcp_path: '/mcp',
    oauth: true,
  };
  assert.deepEqual(connectionEditPresentation(notion), {
    label: 'Notion',
    managedMcpOAuth: true,
  });

  const custom = {
    ...conn('api', 'mcp.internal.example.com', 'Internal'),
    mcp_path: '/mcp',
  };
  assert.deepEqual(connectionEditPresentation(custom), {
    label: 'MCP server',
    managedMcpOAuth: false,
  });
});

test('keyword search finds apps by what they do', () => {
  assert.ok(filterCatalog('payments').some((entry) => entry.id === 'stripe'));
  assert.ok(filterCatalog('email').some((entry) => entry.id === 'gmail'));
  assert.ok(filterCatalog('errors').some((entry) => entry.id === 'sentry'));
  assert.ok(filterCatalog('sql').some((entry) => entry.id === 'postgres'));
});

test('each protocol maps to exactly one generic catalog row', () => {
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

test('connected tools sort above setup-required tools', () => {
  const apps = CATALOG.filter((entry) => entry.section === 'MCP Apps');
  const sorted = connectedCatalogFirst(apps, [
    conn('api', 'api.stripe.com', 'billing'),
    conn('api', 'sentry.io', 'errors'),
  ]);
  assert.deepEqual(sorted.slice(0, 2).map((entry) => entry.id), ['sentry', 'stripe']);
  assert.deepEqual(sorted.slice(2, 4).map((entry) => entry.id), ['slack', 'gmail']);
});

test('collapsed app groups show at least three rows and never hide connected tools', () => {
  const apps = CATALOG.filter((entry) => entry.section === 'MCP Apps');
  const oneConnected = collapsedCatalogGroup(apps, [
    conn('api', 'api.stripe.com', 'billing'),
  ]);
  assert.equal(oneConnected.visible.length, 3);
  assert.equal(oneConnected.visible[0]?.id, 'stripe');
  assert.equal(oneConnected.hiddenCount, apps.length - 3);

  const fourConnected = collapsedCatalogGroup(apps, [
    conn('api', 'api.airtable.com', 'crm'),
    conn('api', 'sentry.io', 'errors'),
    conn('api', 'api.stripe.com', 'billing'),
    conn('api', 'api.linear.app', 'tickets'),
  ]);
  assert.deepEqual(
    fourConnected.visible.map((entry) => entry.id),
    ['airtable', 'linear', 'sentry', 'stripe'],
  );
  assert.equal(fourConnected.hiddenCount, apps.length - 4);
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

test('the registry tail follows the curated MCP app rows and is searchable', () => {
  const all = visibleCatalog('', { showWebsockets: true, connections: [] });
  for (const entry of REGISTRY_CATALOG) {
    assert.ok(all.some((row) => row.id === entry.id), entry.id);
  }
  const mcpApps = all.filter((entry) => entry.section === 'MCP Apps').map((entry) => entry.id);
  const lastCuratedMcpApp = CATALOG.filter((entry) => entry.section === 'MCP Apps').at(-1)!.id;
  assert.ok(mcpApps.indexOf(lastCuratedMcpApp) < mcpApps.indexOf('mcp-vercel'));
  assert.equal(mcpApps.indexOf('mcp-figma'), mcpApps.indexOf('mcp-vercel') + 1);
  assert.equal(mcpApps.indexOf('mcp-atlassian'), mcpApps.indexOf('mcp-figma') + 1);

  const hits = visibleCatalog('paypal', { showWebsockets: true, connections: [] });
  assert.ok(hits.some((entry) => entry.id === 'mcp-paypal'));

  // Registry rows are ordinary addable MCP rows.
  for (const entry of REGISTRY_CATALOG) {
    assert.equal(entry.via, 'connection', entry.id);
    assert.equal(entry.connType, 'api', entry.id);
    assert.equal(entry.mcp, true, entry.id);
    assert.equal(entry.section, 'MCP Apps', entry.id);
    assert.notEqual(entry.icon, 'plug', entry.id);
    assert.ok(ICONS[entry.icon], `${entry.id}: ${entry.icon}`);
    assert.ok(CATALOG_SECTIONS.includes(entry.section), entry.id);
    const url = new URL(entry.mcpTemplate!.serverUrl!);
    assert.equal(url.protocol, 'https:', entry.id);
    // Ids never collide with the curated catalog (some brands appear in
    // both: a REST preset row and a hosted-MCP registry row).
    assert.ok(!CATALOG.some((curated) => curated.id === entry.id), entry.id);
    assert.ok(catalogEntryById(entry.id) === entry, entry.id);
  }
});

test('a configured registry server stays visible and groups under its row', () => {
  const paypal = conn('api', 'mcp.paypal.com', 'paypal-main');
  (paypal as { mcp_path?: string }).mcp_path = '/mcp';

  // Host-matching is deterministic: the connection lists under the
  // registry row, not the generic MCP row…
  assert.equal(entryForConnection(paypal)?.id, 'mcp-paypal');
  // …and the row surfaces even with no search query, so a configured tool
  // never becomes unreachable.
  const rows = visibleCatalog('', { showWebsockets: true, connections: [paypal] });
  assert.ok(rows.some((entry) => entry.id === 'mcp-paypal'));
  const row = REGISTRY_CATALOG.find((entry) => entry.id === 'mcp-paypal')!;
  assert.deepEqual(connectionsForEntry(row, [paypal]).map((c) => c.name), ['paypal-main']);

  // A promoted brand's endpoint groups under the curated row now that the
  // tail dupe is gone.
  const linear = conn('api', 'mcp.linear.app', 'linear-work');
  (linear as { mcp_path?: string }).mcp_path = '/mcp';
  assert.equal(entryForConnection(linear)?.id, 'linear');
});
