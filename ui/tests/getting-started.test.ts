import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CLAUDE_DESKTOP_CONFIG_PATH, CLI_INSTALL_COMMAND,
  CONNECT_CLIENTS,
  CONNECT_MODE_LABELS,
  START_OPTIONS,
  clientMatchesLabel,
  connectClientById, connectGuideSteps,
  connectModesFor,
  directEndpointAddress,
  directStartTask,
  resolveConnectMode,
  sshAuthSockCommand,
  sshDirectCommand,
  sshInvocationCommand,
  startKindLabel,
  startOptionById,
  startProgress,
  startTask,
} from '../src/getting-started';
import type { ConnectClientEnv } from '../src/getting-started';
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
});

test('progress tracks added and enabled tools independently', () => {
  const option = startOptionById('postgres');

  const empty = startProgress(option, []);
  assert.deepEqual([empty.added, empty.wired], [false, false]);

  const added = startProgress(option, [conn('pg', 'prod-db')]);
  assert.deepEqual([added.added, added.wired], [true, false]);
  assert.equal(added.toolName, 'prod-db');

  const enabled = startProgress(option, [conn('pg', 'prod-db', true)]);
  assert.ok(enabled.wired);
});

test('a tool of another type does not count toward this option', () => {
  const progress = startProgress(startOptionById('postgres'), [conn('ssh', 'prod-ssh')]);
  assert.equal(progress.added, false);
  assert.equal(progress.toolName, null);
});

test('the example names an enabled tool when there is one', () => {
  const progress = startProgress(
    startOptionById('postgres'),
    [conn('pg', 'scratch'), conn('pg', 'prod-db', true)],
  );
  assert.equal(progress.toolName, 'prod-db');
});

test('the direct-mode task leads with the endpoint, secret included', () => {
  const postgres = startOptionById('postgres');
  const progress = startProgress(postgres, []);
  const dsn = 'postgresql://app:end_s3cret@/app?host=~/.aka/endpoints/e1&port=5432';
  const withDsn = directStartTask(postgres, progress, { dsn });
  assert.ok(withDsn.startsWith(`Connect to this Postgres DSN: ${dsn}`));
  assert.match(withDsn, /\n\nThen list the 10 largest tables/);
  assert.match(withDsn, /10 largest tables/);
  // SSH carries its stable socket into the copied task as a runnable export.
  const ssh = startOptionById('ssh');
  const authSock = '/Users/test/.aka/endpoints/e1/agent.sock';
  const socket = directStartTask(ssh, startProgress(ssh, []), {
    dsn: authSock,
    sshInvocation: 'ssh deploy@prod.example.com',
  });
  assert.equal(
    socket,
    `Use this SSH agent socket: SSH_AUTH_SOCK="${authSock}"\nSSH to the server with ssh deploy@prod.example.com, then report disk and memory usage, then show the last 20 lines of any log that contains errors.`,
  );
  assert.equal(socket.split('\n').length, 2);
  // No endpoint issued yet: fall back to the tool-name prompt.
  assert.equal(directStartTask(postgres, progress, null), startTask(postgres, progress));
});

test('SSH_AUTH_SOCK commands quote shell-sensitive socket paths', () => {
  assert.equal(
    sshAuthSockCommand('/Users/test/$work/"agent".sock'),
    'export SSH_AUTH_SOCK="/Users/test/\\$work/\\"agent\\".sock"',
  );
});

test('direct SSH commands combine the socket with the configured destination', () => {
  assert.equal(
    sshInvocationCommand({
      destination: null,
      user: 'deploy',
      host: 'prod.example.com',
      port: 2222,
      target: 'deploy@prod.example.com:2222',
    }),
    'ssh -p 2222 deploy@prod.example.com',
  );
  assert.equal(
    sshDirectCommand('/tmp/agent.sock', {
      destination: 'production',
      user: 'deploy',
      host: 'prod.example.com',
      port: 2222,
      target: 'deploy@prod.example.com:2222',
    }),
    'SSH_AUTH_SOCK="/tmp/agent.sock" ssh production',
  );
  assert.equal(
    sshDirectCommand('/tmp/agent.sock', {
      destination: null,
      user: 'deploy',
      host: 'prod.example.com',
      port: 2222,
      target: 'deploy@prod.example.com:2222',
    }),
    'SSH_AUTH_SOCK="/tmp/agent.sock" ssh -p 2222 deploy@prod.example.com',
  );
});

test('older SSH endpoint summaries derive their stable agent socket', () => {
  assert.equal(
    directEndpointAddress(
      'ssh',
      { endpoint_id: 'endpoint-1', dsn: null },
      '/Users/test/.aka/broker.sock',
    ),
    '/Users/test/.aka/endpoints/endpoint-1/agent.sock',
  );
  assert.equal(
    directEndpointAddress('pg', { endpoint_id: 'endpoint-1', dsn: null }, '~/.aka/broker.sock'),
    null,
  );
});

test('the task reads sensibly before any tool exists', () => {
  const option = startOptionById('ssh');
  const task = startTask(option, startProgress(option, []));
  assert.match(task, /my-tool/);
  assert.match(task, /disk and memory/);
});

test('the MCP option is not satisfied by a plain API connection', () => {
  const mcp = startOptionById('mcp');
  const plainApi = conn('api', 'billing-api');
  assert.equal(startProgress(mcp, [plainApi]).added, false);

  const server = {
    ...conn('api', 'custom'), host: 'mcp.internal.example.com', mcp_path: '/mcp',
  };
  assert.equal(startProgress(mcp, [server]).added, true);
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
  // Other MCP client stays a guides card, not a step-2 mode.
  assert.equal(connectModesFor(startOptionById('postgres')).includes('mcp'), false);
  assert.equal(connectModesFor(startOptionById('notion')).includes('mcp'), false);
});

test('picker kind labels: MCP for MCP-backed, API for plain APIs, none otherwise', () => {
  assert.equal(startKindLabel(startOptionById('postgres')), '');
  assert.equal(startKindLabel(startOptionById('ssh')), '');
  assert.equal(startKindLabel(startOptionById('slack')), 'API');
  assert.equal(startKindLabel(startOptionById('github')), 'MCP');
  // Custom MCP already says MCP in its name.
  assert.equal(startKindLabel(startOptionById('mcp')), '');
});

test('the picked mode survives while offered and falls back when not', () => {
  const postgres = startOptionById('postgres');
  const notion = startOptionById('notion');
  assert.equal(resolveConnectMode('direct', postgres), 'direct');
  assert.equal(resolveConnectMode('codex', notion), 'codex');
  // Codex Desktop merged into Codex; a stale pick falls back like any unknown.
  assert.equal(resolveConnectMode('codex-desktop', notion), 'claude-code');
  // Direct is not offered for an API tool; the pane falls back to the first mode.
  assert.equal(resolveConnectMode('direct', notion), 'claude-code');
  assert.equal(resolveConnectMode('nonsense', postgres), 'direct');
});

const ENV: ConnectClientEnv = {
  socket: '/tmp/aka/broker.sock',
  token: '/tmp/aka/token',
  platform: 'macos',
};

test('every shared-key mode renders from a client definition; direct has none', () => {
  for (const mode of connectModesFor(startOptionById('postgres'))) {
    if (mode === 'direct') {
      assert.equal(connectClientById(mode), undefined);
      continue;
    }
    const client = connectClientById(mode);
    assert.ok(client, mode);
    assert.ok(client!.lead(ENV).length, mode);
    assert.ok(client!.snippet(ENV).length, mode);
    assert.ok(client!.steps(ENV).length, mode);
  }
  // The two escape hatches keep their spelled-out labels.
  assert.equal(CONNECT_MODE_LABELS.mcp, 'Other MCP client');
  assert.equal(CONNECT_MODE_LABELS.cli, 'Anything else (HTTP API)');
});

test('stdio connection guides and quick-start clients require the separate CLI', () => {
  const requiringCli = CONNECT_CLIENTS.filter((client) => client.requiresCli);
  assert.deepEqual(
    requiringCli.map((client) => client.id),
    ['claude-code', 'claude-desktop', 'codex'],
  );
  assert.equal(connectClientById('claude-code')!.inlineCliInstall, true);
  assert.equal(connectClientById('claude-code')!.steps(ENV)[1].followup, undefined);
  assert.equal(connectClientById('claude-code')!.note, undefined);
  assert.equal(connectClientById('claude-desktop')!.inlineCliInstall, undefined);
  assert.equal(connectClientById('claude-desktop')!.note, undefined);
  assert.equal(connectClientById('codex')!.inlineCliInstall, undefined);
  assert.equal(connectClientById('cli')!.note, undefined);
  assert.equal(
    connectClientById('cli')!.steps(ENV)[0].followup,
    'Speaking MCP over HTTP instead? See “Other MCP client” above.',
  );
  for (const client of requiringCli) {
    const [install, ...steps] = connectGuideSteps(client, ENV);
    assert.equal(install.title, 'Install the Multitool CLI', client.id);
    assert.equal(install.snippet, CLI_INSTALL_COMMAND, client.id);
    assert.deepEqual(steps, client.steps(ENV), client.id);
  }
  assert.match(
    connectClientById('mcp')!.steps(ENV)[1].detail ?? '',
    /After installing the Multitool CLI/,
  );
  assert.equal(connectClientById('mcp')!.steps(ENV)[1].snippet, CLI_INSTALL_COMMAND);
});

test('activity labels attribute to the right client', () => {
  const codex = connectClientById('codex')!;
  const claudeCode = connectClientById('claude-code')!;
  const mcp = connectClientById('mcp')!;
  // Codex Desktop's old label still counts as Codex after the merge.
  assert.ok(clientMatchesLabel(codex, 'codex'));
  assert.ok(clientMatchesLabel(codex, 'codex-desktop'));
  assert.equal(clientMatchesLabel(codex, 'my-harness'), false);
  // A branded label never lights up another client — branded or self-named.
  assert.equal(clientMatchesLabel(claudeCode, 'codex'), false);
  assert.equal(clientMatchesLabel(mcp, 'claude-code'), false);
  // Self-named harnesses count only for the self-named clients.
  assert.ok(clientMatchesLabel(mcp, 'my-harness'));
});

test('the Claude Desktop lead names the config path for each platform', () => {
  const claudeDesktop = connectClientById('claude-desktop')!;
  for (const platform of ['macos', 'windows', 'linux'] as const) {
    const path = CLAUDE_DESKTOP_CONFIG_PATH[platform];
    assert.ok(path.length, platform);
    const env = { ...ENV, platform };
    assert.ok(claudeDesktop.lead(env).includes(path), platform);
    assert.ok(claudeDesktop.lead(env).endsWith('then restart Claude.'), platform);
    assert.ok(claudeDesktop.steps(env)[0].detail?.includes(path), platform);
  }
});

test('the Codex config instruction includes the required restart', () => {
  const codex = connectClientById('codex')!;
  const instruction = 'Add this to ~/.codex/config.toml, then restart Codex.';

  assert.equal(codex.lead(ENV), instruction);
  assert.equal(codex.steps(ENV)[0].detail, instruction);
});

test('snippets interpolate the broker socket and token paths', () => {
  for (const id of ['mcp', 'cli'] as const) {
    const snippet = connectClientById(id)!.snippet(ENV);
    assert.ok(snippet.includes(ENV.socket), id);
    assert.ok(snippet.includes(ENV.token), id);
  }
  // Guide steps and the walkthrough pane share the same snippet source.
  for (const client of CONNECT_CLIENTS) {
    const stepSnippets = client.steps(ENV).map((step) => step.snippet).filter(Boolean);
    if (stepSnippets.length) assert.equal(stepSnippets[0], client.snippet(ENV), client.id);
  }
});

test('a branded option is satisfied only by its own connection', () => {
  const notion = startOptionById('notion');
  const notionServer = {
    ...conn('api', 'Notion'), host: 'mcp.notion.com', mcp_path: '/mcp',
  };
  const githubServer = {
    ...conn('api', 'GitHub'), host: 'api.githubcopilot.com', mcp_path: '/mcp',
  };
  assert.equal(startProgress(notion, [githubServer]).added, false);
  assert.equal(startProgress(notion, [notionServer]).added, true);
});
