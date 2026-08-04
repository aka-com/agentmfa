// The manage plane: what the desktop app does to a broker.
//
// Matrix row: the configuration side of a connection's life — created,
// tested against the sandbox, edited, renamed, reordered, deleted — plus
// the vault operations underneath it and the validation that stops a
// half-formed connection from ever being stored.

import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';

import { Broker, connectionNames, type ConnectionDto, type SecretDto } from './lib/broker';
import { requireFixture, sandbox, sshPrivateKey } from './lib/sandbox';

let broker: Broker;

before(async () => {
  await requireFixture();
  broker = await Broker.start({ label: 'manage', seed: ['http', 'mcp', 'pg', 'ssh'] });
});

after(async () => {
  await broker?.stop();
});

test('whoami identifies the broker and what it can do', async () => {
  const whoami = await broker.manage<Record<string, unknown>>('GET', '/whoami');
  assert.equal(whoami.ok, true);
  assert.ok(String(whoami.version).length > 0);
  assert.deepEqual(whoami.capabilities, ['request_surface_v1']);
});

test('secrets report which connections depend on them', async () => {
  const secrets = await broker.secrets();
  const http = secrets.find((secret) => secret.name === 'SANDBOX_HTTP_TOKEN');
  assert.ok(http);
  assert.equal(http.used_by, 1);
  assert.deepEqual(http.used_by_names, [connectionNames.http]);
  // A listing never carries values.
  assert.ok(!JSON.stringify(secrets).includes(sandbox.httpToken));
});

test('a secret in use cannot be deleted out from under a connection', async () => {
  const id = await broker.secretId('SANDBOX_HTTP_TOKEN');
  const response = await broker.manageRaw('DELETE', `/secrets/${id}`);
  assert.equal(response.status, 409);
  const error = response.json<{ code: string; connections: string[] }>();
  assert.equal(error.code, 'secret_in_use');
  assert.deepEqual(error.connections, [connectionNames.http]);
});

test('a secret can be renamed, rotated, revealed, and copied', async () => {
  await broker.addSecret('SPARE_TOKEN', 'first-value');
  const id = await broker.secretId('SPARE_TOKEN');

  // Reveal hands back the whole value: the client shows it on screen after
  // the user has confirmed that.
  const revealed = await broker.manage<{ value: string }>('POST', `/secrets/${id}/reveal`);
  assert.equal(revealed.value, 'first-value');

  await broker.manage('PATCH', `/secrets/${id}`, { new_value: 'second-value' });
  const copied = await broker.manage<{ value: string }>('POST', `/secrets/${id}/copy-value`);
  assert.equal(copied.value, 'second-value');

  await broker.manage('PATCH', `/secrets/${id}`, { new_name: 'SPARE_TOKEN_RENAMED' });
  assert.ok((await broker.secrets()).some((secret) => secret.name === 'SPARE_TOKEN_RENAMED'));

  // Releasing a value to a remote app is itself an audited event.
  const audited = (await broker.activity()).some((entry) => /copied/i.test(entry.text));
  assert.ok(audited);

  await broker.manage('DELETE', `/secrets/${id}`);
  assert.ok(!(await broker.secrets()).some((secret) => secret.id === id));
});

test('an unusable secret name is refused with the field named', async () => {
  const response = await broker.manageRaw('POST', '/secrets', {
    body: { name: '1nvalid name', value: 'x' },
  });
  assert.equal(response.status, 422);
  assert.equal(response.json<{ code: string }>().code, 'invalid_secret_name');
});

test('a connection template must reference secrets that exist', async () => {
  const response = await broker.manageRaw('POST', '/connections', {
    body: {
      spec: {
        name: 'sandbox-missing-secret',
        config: {
          kind: 'api',
          host: sandbox.host,
          scheme: 'http',
          port: sandbox.httpPort,
          template: 'Authorization: Bearer {{NO_SUCH_SECRET}}',
        },
        secrets: [],
      },
    },
  });
  assert.equal(response.status, 422);
  assert.equal(response.json<{ code: string }>().code, 'unknown_template_ref');
});

test('connection names are validated and unique', async () => {
  const badName = await broker.manageRaw('POST', '/connections', {
    body: {
      spec: {
        name: ' leading space',
        config: {
          kind: 'api',
          host: sandbox.host,
          scheme: 'http',
          template: 'Authorization: Bearer {{SANDBOX_HTTP_TOKEN}}',
        },
        secrets: [],
      },
    },
  });
  assert.equal(badName.status, 422);
  assert.equal(badName.json<{ code: string }>().code, 'invalid_connection_name');

  const duplicate = await broker.manageRaw('POST', '/connections', {
    body: {
      spec: {
        name: connectionNames.http,
        config: {
          kind: 'api',
          host: sandbox.host,
          scheme: 'http',
          template: 'Authorization: Bearer {{SANDBOX_HTTP_TOKEN}}',
        },
        secrets: [],
      },
    },
  });
  assert.equal(duplicate.status, 409);
  assert.equal(duplicate.json<{ code: string }>().code, 'connection_name_taken');
});

test('a connection’s type is fixed once it exists', async () => {
  const connection = broker.conn(connectionNames.http);
  const response = await broker.manageRaw('PUT', `/connections/${connection.id}`, {
    body: {
      spec: {
        name: connectionNames.http,
        config: {
          kind: 'pg',
          host: sandbox.host,
          port: sandbox.pgPort,
          dbname: sandbox.pgDatabase,
          user: sandbox.pgUser,
          sslmode: 'disable',
        },
        secrets: [],
      },
    },
  });
  assert.equal(response.status, 409);
  assert.equal(response.json<{ code: string }>().code, 'kind_change');
});

test('an ssh host key fingerprint is validated before it is stored', async () => {
  const connection = broker.conn(connectionNames.ssh);
  const response = await broker.manageRaw('PUT', `/connections/${connection.id}`, {
    body: {
      spec: {
        name: connectionNames.ssh,
        config: {
          kind: 'ssh',
          host: sandbox.host,
          port: sandbox.sshPort,
          user: sandbox.sshUser,
          host_key_fingerprint: 'definitely-not-a-fingerprint',
        },
        secrets: [await broker.secretId('SANDBOX_SSH_KEY')],
      },
    },
  });
  assert.equal(response.status, 422);
  const error = response.json<{ code: string; field: string }>();
  assert.equal(error.code, 'invalid_connection_field');
  assert.equal(error.field, 'host_key_fingerprint');
});

test('an unknown connection id is a 404 on every route that takes one', async () => {
  const missing = '00000000-0000-4000-8000-000000000000';
  for (const [method, path] of [
    ['POST', `/connections/${missing}/test`],
    ['POST', `/connections/${missing}/access`],
    ['GET', `/connections/${missing}/endpoint`],
  ] as const) {
    const response = await broker.manageRaw(method, path, { body: { enabled: true } });
    assert.equal(response.status, 404, `${method} ${path}`);
    assert.equal(response.json<{ code: string }>().code, 'connection_not_found');
  }
});

test('testing a connection reaches the sandbox service it names', async () => {
  const results: Record<string, string> = {};
  for (const name of [connectionNames.http, connectionNames.pg, connectionNames.ssh]) {
    const outcome = await broker.manage<Record<string, unknown>>(
      'POST',
      `/connections/${broker.conn(name).id}/test`,
    );
    results[name] = JSON.stringify(outcome);
  }
  // An MCP connection is checked with the MCP status probe instead: `test`
  // is an HTTP probe of the API root, which the fixture guards with the
  // *other* credential, so a 401 there says nothing about the MCP server.
  results[connectionNames.mcp] = JSON.stringify(
    await broker.manage<Record<string, unknown>>(
      'POST',
      `/connections/${broker.conn(connectionNames.mcp).id}/mcp-status`,
      {},
    ),
  );

  // The wording belongs to the core; the substance is what each test proves.
  assert.match(results[connectionNames.http], /200|ok/i);
  assert.match(results[connectionNames.mcp], /sandbox_echo|sandbox_ping/);
  assert.match(results[connectionNames.pg], new RegExp(sandbox.pgDatabase));
  // With a key stored, the SSH test is a real login through a throwaway
  // agent; without one it degrades to a reachability probe.
  assert.match(results[connectionNames.ssh], /Signed in|SSH-2\.0|Key loaded/);

  // A test records health on the connection, without exposing credentials.
  const http = await broker.refresh(connectionNames.http);
  assert.equal(http.last_status, 'ok');
  assert.ok(!JSON.stringify(results).includes(sandbox.httpToken));
  assert.ok(!JSON.stringify(results).includes(sandbox.pgPassword));
});

test('a draft can be tested before it is saved', async () => {
  const outcome = await broker.manage<Record<string, unknown>>('POST', '/connections/test-draft', {
    spec: {
      name: 'sandbox-draft',
      config: {
        kind: 'api',
        host: sandbox.host,
        scheme: 'http',
        port: sandbox.httpPort,
        template: 'Authorization: Bearer {{SANDBOX_HTTP_TOKEN}}',
      },
      secrets: [],
    },
  });
  assert.match(JSON.stringify(outcome), /200|ok/i);
  assert.ok(
    !(await broker.manage<ConnectionDto[]>('GET', '/connections')).some(
      (connection) => connection.name === 'sandbox-draft',
    ),
    'testing a draft does not store it',
  );
});

test('a failing test is reported as failure, not as an error', async () => {
  await broker.addSecret('BAD_TOKEN', 'not-the-sandbox-token');
  const added = await broker.addConnection({
    name: 'sandbox-bad-credential',
    config: {
      kind: 'api',
      host: sandbox.host,
      scheme: 'http',
      port: sandbox.httpPort,
      template: 'Authorization: Bearer {{BAD_TOKEN}}',
    },
    secrets: [],
  });
  const response = await broker.manageRaw('POST', `/connections/${added.id}/test`);
  assert.equal(response.status, 200, 'the call succeeded; the destination refused');
  assert.match(response.text, /401|reject/i);

  const connection = await broker.refresh('sandbox-bad-credential');
  assert.ok(['failed', 'needs_reconnect'].includes(String(connection.last_status)));
  await broker.manage('DELETE', `/connections/${added.id}`);
});

test('connections can be renamed, reordered, and deleted', async () => {
  await broker.ensureSecret('SANDBOX_HTTP_TOKEN', sandbox.httpToken);
  const temporary = await broker.addConnection({
    name: 'sandbox-temporary',
    config: {
      kind: 'api',
      host: sandbox.host,
      scheme: 'http',
      port: sandbox.httpPort,
      template: 'Authorization: Bearer {{SANDBOX_HTTP_TOKEN}}',
    },
    secrets: [],
  });

  await broker.manage('PUT', `/connections/${temporary.id}`, {
    spec: {
      name: 'sandbox-renamed',
      config: {
        kind: 'api',
        host: sandbox.host,
        scheme: 'http',
        port: sandbox.httpPort,
        template: 'Authorization: Bearer {{SANDBOX_HTTP_TOKEN}}',
      },
      secrets: [],
    },
  });
  const all = await broker.manage<ConnectionDto[]>('GET', '/connections');
  assert.ok(all.some((connection) => connection.name === 'sandbox-renamed'));

  const reversed = [...all].reverse().map((connection) => connection.id);
  await broker.manage('POST', '/connections/reorder', { ordered_ids: reversed });
  const reordered = await broker.manage<ConnectionDto[]>('GET', '/connections');
  assert.deepEqual(
    reordered.map((connection) => connection.id),
    reversed,
    'the app owns the order agents see',
  );

  await broker.manage('DELETE', `/connections/${temporary.id}`);
  assert.ok(
    !(await broker.manage<ConnectionDto[]>('GET', '/connections')).some(
      (connection) => connection.id === temporary.id,
    ),
  );
});

test('a connection created with its credential in one call is atomic', async () => {
  const response = await broker.manageRaw('POST', '/connections', {
    body: {
      spec: {
        name: 'sandbox-connection-first',
        config: {
          kind: 'ssh',
          host: sandbox.host,
          port: sandbox.sshPort,
          user: sandbox.sshUser,
          host_key_fingerprint: '',
        },
        secrets: [],
      },
      new_secret: { name: 'CONNECTION_FIRST_KEY', value: await sshPrivateKey() },
    },
  });
  assert.equal(response.status, 200, response.text);
  const stored = (await broker.secrets()).find(
    (secret: SecretDto) => secret.name === 'CONNECTION_FIRST_KEY',
  );
  assert.ok(stored);
  assert.equal(stored.used_by, 1);
});

test('access and confirmation settings round-trip through the DTO', async () => {
  const connection = broker.conn(connectionNames.http);
  await broker.setAccess(connection.id, false);
  assert.equal((await broker.refresh(connectionNames.http)).agent_access.enabled, false);
  await broker.setAccess(connection.id, true);
  await broker.setConfirm(connection.id, true);
  assert.equal((await broker.refresh(connectionNames.http)).agent_access.confirm, true);
  await broker.setConfirm(connection.id, false);
  assert.equal((await broker.refresh(connectionNames.http)).agent_access.confirm, false);
});

test('settings and identity are readable and writable', async () => {
  const settings = await broker.manage<Record<string, unknown>>('GET', '/settings');
  assert.equal(typeof settings.menu_bar_hides_dock, 'boolean');
  assert.equal(typeof settings.confirm_ssh_host_keys, 'boolean');

  const patched = await broker.manage<Record<string, unknown>>('PATCH', '/settings', {
    confirm_ssh_host_keys: true,
  });
  assert.equal(patched.confirm_ssh_host_keys, true);

  const identity = await broker.manage<Record<string, string>>('GET', '/identity');
  assert.equal(identity.socket_path, broker.socketPath);
  assert.equal(identity.token_path, `${broker.root}/sock/token`);

  const key = await broker.manage<{ token: string }>('GET', '/identity/agent-key');
  assert.equal(key.token, broker.agentToken, 'the app can copy the key it tells agents to use');
});

test('the agent setup instructions name this broker', async () => {
  const setup = await broker.manage<{ instructions: string }>('GET', '/agent-setup');
  assert.ok(setup.instructions.includes(broker.socketPath));
});

test('the activity log can be read, bounded, and cleared', async () => {
  const all = await broker.activity();
  assert.ok(all.length > 0);
  const bounded = await broker.activity(3);
  assert.ok(bounded.length <= 3);

  await broker.manage('DELETE', '/activity');
  const cleared = await broker.activity();
  // Clearing is itself an event, so the log is empty or holds only that.
  assert.ok(cleared.length <= 1, `expected an empty log, saw ${cleared.length} entries`);
});
