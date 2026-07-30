// The MCP connection type, on both of the paths it travels.
//
// An MCP server is an API connection carrying an `mcp_path`, so its traffic
// rides the same credential-injecting HTTP plane. Matrix row: an `api` +
// `mcp_path` connection crossed with the JSON-RPC an MCP client sends
// (handshake, listing, tool call), the curated tool subset, and the
// confirmation that treats a `tools/call` differently from plumbing.
//
// The second path is the broker's own in-process MCP host, reverse-proxied
// at /mcp, which re-exposes every wired connection as a tool.

import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';

import { Broker, connectionNames, mfaBinary } from './lib/broker';
import { waitFor } from './lib/http';
import { McpClient } from './lib/mcpclient';
import { run } from './lib/proc';
import { requireFixture, sandbox } from './lib/sandbox';

let broker: Broker;
let host: McpClient;

const mcp = connectionNames.mcp;

/** One JSON-RPC message to the upstream MCP server, through the broker. */
async function rpc(method: string, params?: unknown, id: number | string = 1) {
  const relayed = await broker.call({
    connection: mcp,
    method: 'POST',
    path: sandbox.mcpPath,
    headers: { 'content-type': 'application/json' },
    body: { jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) },
  });
  assert.equal(relayed.status, 200, `upstream answered ${relayed.status}`);
  return JSON.parse(relayed.body) as Record<string, unknown>;
}

before(async () => {
  await requireFixture();
  broker = await Broker.start({
    label: 'mcp',
    seed: ['http', 'mcp', 'pg'],
  });
  host = new McpClient(broker.socketPath, broker.agentToken);
  await waitFor(
    'the broker MCP host to start',
    async () => ((await host.send('ping', {}, 1)).status === 503 ? undefined : true),
    30_000,
    250,
  );
});

after(async () => {
  await broker?.stop();
});

/* ------------------------- through /v1/http ------------------------------- */

test('the MCP handshake reaches the upstream with its own credential', async () => {
  const initialize = await rpc('initialize', { protocolVersion: '2025-06-18' });
  const result = initialize.result as { serverInfo: { name: string } };
  assert.equal(result.serverInfo.name, 'aka-sandbox-mcp');
});

test('the MCP connection carries a different credential from the API connection', async () => {
  // Same host and port, different template: the broker picks the credential
  // from the connection the agent named, not from the destination.
  const response = await broker.http({
    connection: connectionNames.http,
    method: 'POST',
    path: sandbox.mcpPath,
    body: { jsonrpc: '2.0', id: 1, method: 'initialize' },
  });
  const relayed = response.json<{ status: number }>();
  assert.equal(relayed.status, 401, 'the API token is not accepted by the MCP endpoint');
});

test('tools are listed and callable', async () => {
  const listed = await rpc('tools/list');
  const tools = (listed.result as { tools: Array<{ name: string }> }).tools.map((t) => t.name);
  assert.deepEqual(tools.sort(), ['sandbox_echo', 'sandbox_ping']);

  const called = await rpc('tools/call', { name: 'sandbox_echo', arguments: { text: 'hello' } });
  const content = (called.result as { content: Array<{ text: string }> }).content;
  assert.equal(content[0].text, 'hello');
});

test('a curated tool subset is enforced by the broker, not just displayed', async () => {
  const connection = broker.conn(mcp);
  await broker.setAllowedTools(connection.id, ['sandbox_ping']);
  try {
    // The agent's own listing tells it what it may call…
    const listed = await broker.agentRaw('GET', '/v1/connections');
    const entry = listed
      .json<Array<Record<string, unknown>>>()
      .find((row) => row.name === mcp);
    assert.deepEqual(entry?.allowed_tools, ['sandbox_ping']);

    // …and calling outside it is refused at the trust boundary.
    const refused = await broker.http({
      connection: mcp,
      method: 'POST',
      path: sandbox.mcpPath,
      body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'sandbox_echo' } },
    });
    assert.equal(refused.status, 403);
    assert.equal(refused.reason, 'denied_by_policy');
    assert.match(refused.json<{ detail: string }>().detail, /sandbox_echo/);

    // The allowed one still works.
    const allowed = await rpc('tools/call', { name: 'sandbox_ping', arguments: {} });
    assert.equal(
      (allowed.result as { content: Array<{ text: string }> }).content[0].text,
      'pong',
    );

    // A batch cannot smuggle a disallowed call past the check either.
    const batch = await broker.http({
      connection: mcp,
      method: 'POST',
      path: sandbox.mcpPath,
      body: [
        { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'sandbox_ping' } },
        { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'sandbox_echo' } },
      ],
    });
    assert.equal(batch.status, 403);
    assert.equal(batch.reason, 'denied_by_policy');
  } finally {
    await broker.setAllowedTools(connection.id, null);
  }
});

test('the app can list an upstream’s tools and check its status', async () => {
  const connection = broker.conn(mcp);
  const tools = await broker.manage<Array<{ name: string }>>(
    'GET',
    `/connections/${connection.id}/mcp-tools`,
  );
  assert.deepEqual(
    tools.map((tool) => tool.name).sort(),
    ['sandbox_echo', 'sandbox_ping'],
  );

  const status = await broker.manage<Record<string, unknown>>(
    'POST',
    `/connections/${connection.id}/mcp-status`,
    {},
  );
  assert.ok(JSON.stringify(status).includes('sandbox_'), 'the check reports what it found');
});

test('confirmation asks about tool calls, not about session plumbing', async () => {
  const connection = broker.conn(mcp);
  const surface = await broker.attachApprovalSurface();
  const answering = surface.autoAnswer(() => 'approve_window');
  await broker.setConfirm(connection.id, true);
  try {
    // Plumbing: the handshake and the listing are wrapped around every call
    // a host makes, so they raise no question.
    await rpc('initialize', { protocolVersion: '2025-06-18' });
    await rpc('tools/list');
    await rpc('ping');
    assert.equal(answering.answered.length, 0, 'nothing was asked about the envelope');

    // The tool call is the unit the user cares about.
    const called = await broker.http(
      {
        connection: mcp,
        method: 'POST',
        path: sandbox.mcpPath,
        body: {
          jsonrpc: '2.0',
          id: 9,
          method: 'tools/call',
          params: { name: 'sandbox_echo', arguments: { text: 'confirm me' } },
        },
      },
      { client: 'mcp-agent' },
    );
    assert.equal(called.status, 200);
    assert.equal(answering.answered.length, 1);

    const [prompt] = answering.answered;
    assert.equal(prompt.unit, 'tool');
    assert.equal(prompt.summary, 'sandbox_echo', 'the prompt names the tool, not the transport');
    assert.equal(prompt.agent, 'mcp-agent');
    assert.match(String(prompt.detail), /confirm me/);
  } finally {
    answering.stop();
    await broker.setConfirm(connection.id, false);
    surface.detach();
  }
});

test('a request off the pinned MCP path is ordinary traffic, asked about as such', async () => {
  const connection = broker.conn(mcp);
  const surface = await broker.attachApprovalSurface();
  const answering = surface.autoAnswer(() => 'approve_window');
  await broker.setConfirm(connection.id, true);
  try {
    await broker.http(
      { connection: mcp, method: 'GET', path: '/authenticated' },
      { client: 'off-path' },
    );
    assert.equal(answering.answered.length, 1);
    assert.equal(answering.answered[0].unit, 'request');
    assert.equal(answering.answered[0].summary, 'GET /authenticated');
  } finally {
    answering.stop();
    await broker.setConfirm(connection.id, false);
    surface.detach();
  }
});

/* ------------------------- upstream elicitations -------------------------- */

test('an upstream input request parks on the user and answers the call', async () => {
  const surface = await broker.attachApprovalSurface();
  try {
    const asked = broker.agentRaw('POST', '/v1/elicit', {
      body: {
        connection: mcp,
        tool: 'sandbox_echo',
        message: 'Which environment should this run against?',
        requested_schema: {
          type: 'object',
          properties: {
            environment: { type: 'string', enum: ['staging', 'production'] },
            confirm: { type: 'boolean' },
          },
        },
      },
    });

    const elicitation = await broker.waitForElicitation();
    assert.equal(elicitation.connection, mcp);
    assert.equal(elicitation.tool, 'sandbox_echo');
    assert.equal(elicitation.prompt, 'Which environment should this run against?');
    assert.deepEqual(
      elicitation.fields.map((field) => field.name).sort(),
      ['confirm', 'environment'],
    );
    assert.deepEqual(
      elicitation.fields.find((field) => field.name === 'environment')?.options,
      ['staging', 'production'],
    );
    assert.equal(elicitation.fields.find((field) => field.name === 'confirm')?.boolean, true);
    assert.notEqual(elicitation.credential_warning, true);

    await broker.manage('POST', `/elicitations/${elicitation.id}`, {
      approved: true,
      values: { environment: 'staging', confirm: 'true' },
    });

    const answer = (await asked).json<{ action: string; content: Record<string, unknown> }>();
    assert.equal(answer.action, 'accept');
    assert.equal(answer.content.environment, 'staging');
  } finally {
    surface.detach();
  }
});

test('declining an input request cancels it rather than inventing an answer', async () => {
  const surface = await broker.attachApprovalSurface();
  try {
    const asked = broker.agentRaw('POST', '/v1/elicit', {
      body: { connection: mcp, tool: 'sandbox_echo', message: 'Anything?', requested_schema: {} },
    });
    const elicitation = await broker.waitForElicitation();
    await broker.manage('POST', `/elicitations/${elicitation.id}`, { approved: false });
    const answer = (await asked).json<{ action: string }>();
    assert.equal(answer.action, 'decline');
  } finally {
    surface.detach();
  }
});

test('a credential-shaped input request is flagged for the user', async () => {
  const surface = await broker.attachApprovalSurface();
  try {
    const asked = broker.agentRaw('POST', '/v1/elicit', {
      body: {
        connection: mcp,
        tool: 'sandbox_echo',
        message: 'Paste your API key to continue',
        requested_schema: {
          type: 'object',
          properties: { api_key: { type: 'string', format: 'password' } },
        },
      },
    });
    const elicitation = await broker.waitForElicitation();
    assert.equal(elicitation.credential_warning, true, 'the form warns instead of masking');
    await broker.manage('POST', `/elicitations/${elicitation.id}`, { approved: false });
    await asked;

    const audited = (await broker.activity()).some((entry) =>
      /credential-shaped/i.test(entry.text),
    );
    assert.ok(audited, 'the attempt is recorded whatever the user does');
  } finally {
    surface.detach();
  }
});

test('with no app attached, an input request is cancelled, not left hanging', async () => {
  const response = await broker.agentRaw('POST', '/v1/elicit', {
    body: { connection: mcp, tool: 'sandbox_echo', message: 'Anyone there?', requested_schema: {} },
  });
  assert.equal(response.status, 200);
  assert.equal(response.json<{ action: string }>().action, 'cancel');
});

test('an input request on a disabled connection is refused before the user sees it', async () => {
  const connection = broker.conn(mcp);
  await broker.setAccess(connection.id, false);
  try {
    const response = await broker.agentRaw('POST', '/v1/elicit', {
      body: { connection: mcp, tool: 'sandbox_echo', message: 'hello', requested_schema: {} },
    });
    assert.equal(response.status, 403);
    assert.equal(response.reason, 'denied_by_policy');
  } finally {
    await broker.setAccess(connection.id, true);
  }
});

/* --------------------- the broker’s own MCP host -------------------------- */

test('the MCP host exposes every wired connection as a tool', async () => {
  const initialized = await host.initialize();
  assert.equal((initialized.serverInfo as { name: string }).name, 'agentmfa');
  assert.match(host.session ?? '', /^[0-9a-f-]{36}$/);

  const tools = (await host.tools()).map((tool) => tool.name);
  // An API connection is called; a database is opened; an upstream MCP
  // server's own tools are re-exposed under the connection's name.
  assert.ok(tools.includes('agentmfa_sandbox-http_request'), tools.join(', '));
  assert.ok(tools.includes('agentmfa_sandbox-postgres_open'), tools.join(', '));
  assert.ok(
    tools.some((name) => name.includes('sandbox_echo')),
    tools.join(', '),
  );
});

test('the `mfa mcp` binary bridges a real stdio initialize', async () => {
  const initialize = {
    jsonrpc: '2.0',
    id: 41,
    method: 'initialize',
    params: {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'sandbox-cli-spawn', version: '0.0.0' },
    },
  };
  const result = await run(
    mfaBinary(),
    ['mcp', '--root', broker.root, '--client', 'cli-spawn'],
    { input: `${JSON.stringify(initialize)}\n`, timeoutMs: 30_000 },
  );
  assert.equal(result.code, 0, result.stderr);
  const messages = result.stdout
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  const response = messages.find((message) => message.id === 41);
  assert.ok(response?.result, `initialize response missing from ${result.stdout}`);
  assert.equal(
    ((response.result as Record<string, unknown>).serverInfo as Record<string, unknown>).name,
    'agentmfa',
  );
});

test('a tool call through the host reaches the upstream', async () => {
  const result = await host.callTool('agentmfa_sandbox-http_request', {
    method: 'GET',
    path: '/authenticated',
  });
  assert.notEqual(result.isError, true);
  const text = result.content.map((part) => part.text ?? '').join('');
  assert.match(text, /"authenticated\\?":\s*true|authenticated/);
  assert.ok(!text.includes(sandbox.httpToken), 'the credential stays on the upstream leg');
});

test('an upstream MCP tool is callable through the host', async () => {
  const name = (await host.tools()).map((tool) => tool.name).find((n) => n.endsWith('sandbox_echo'));
  assert.ok(name, 'the upstream tool is exposed');
  const result = await host.callTool(name, { text: 'through the host' });
  assert.notEqual(result.isError, true);
  assert.match(result.content.map((part) => part.text ?? '').join(''), /through the host/);
});

test('a disabled connection is refused by the broker and gone from a fresh session', async () => {
  const connection = broker.conn(connectionNames.http);
  await broker.setAccess(connection.id, false);
  try {
    // A client that already listed the tool still holds its name; the
    // refusal comes from the broker, not from the listing being current.
    const refused = await host.callTool('agentmfa_sandbox-http_request', {
      method: 'GET',
      path: '/authenticated',
    });
    assert.equal(refused.isError, true);
    assert.match(
      refused.content.map((part) => part.text ?? '').join(''),
      /denied_by_policy|refused/i,
    );

    // A new session lists what is wired now.
    const fresh = new McpClient(broker.socketPath, broker.agentToken);
    await fresh.initialize();
    const names = (await fresh.tools()).map((tool) => tool.name);
    assert.ok(!names.includes('agentmfa_sandbox-http_request'), names.join(', '));
  } finally {
    await broker.setAccess(connection.id, true);
  }
});

test('the MCP host refuses a caller with no broker key', async () => {
  const anonymous = new McpClient(broker.socketPath, 'aka_not-a-real-key');
  await assert.rejects(anonymous.initialize(), /40[13]/);
});

test('without the MCP host, its endpoint says so instead of hanging', async () => {
  const headless = await Broker.start({ label: 'mcp-disabled', seed: ['http'], mcp: false });
  try {
    const client = new McpClient(headless.socketPath, headless.agentToken);
    const response = await client.send('initialize', { protocolVersion: '2025-06-18' });
    assert.equal(response.status, 503);
    assert.equal(response.reason, 'mcp_unavailable');
  } finally {
    await headless.stop();
  }
});
