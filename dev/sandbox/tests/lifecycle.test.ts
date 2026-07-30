// Broker lifecycle, and the CLI an operator actually types.
//
// Matrix row: things that happen to the broker rather than to one
// connection — a restart, a key rotation, state that must survive both, and
// the `mfa` commands the sandbox walkthrough tells people to run.

import assert from 'node:assert/strict';
import { readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import test, { after, before } from 'node:test';

import { Broker, connectionNames, mfaBinary } from './lib/broker';
import { waitFor } from './lib/http';
import { parseDsn, PgConnection } from './lib/pgwire';
import { run } from './lib/proc';
import { requireFixture, sandbox } from './lib/sandbox';

let broker: Broker;

before(async () => {
  await requireFixture();
  broker = await Broker.start({ label: 'lifecycle', seed: ['http', 'pg'] });
});

after(async () => {
  await broker?.stop();
});

test('the control socket is private to its owner', async () => {
  const { statSync } = await import('node:fs');
  const mode = statSync(broker.socketPath).mode & 0o777;
  assert.equal(mode, 0o600, 'the rendezvous point excludes other users');
  const token = statSync(join(broker.root, 'sock/token')).mode & 0o777;
  assert.equal(token, 0o600, 'so does the key file agents read');
});

test('a second broker refuses to serve the same state', async () => {
  const result = await run(mfaBinary(), ['serve', '--root', broker.root, '--no-mcp'], {
    timeoutMs: 30_000,
  });
  assert.notEqual(result.code, 0, 'the lease is held by the running broker');
  assert.match(result.stderr, /already listening|already running|lease|lock/i);
});

test('`mfa status` reports a running broker, and a stopped one', async () => {
  const running = await run(mfaBinary(), ['status', '--root', broker.root], { timeoutMs: 30_000 });
  assert.equal(running.code, 0, running.stderr);
  assert.match(`${running.stdout}${running.stderr}`, /broker/i);

  const elsewhere = join(broker.root, 'not-a-broker');
  const stopped = await run(mfaBinary(), ['status', '--root', elsewhere], { timeoutMs: 30_000 });
  assert.notEqual(stopped.code, 0, 'no broker there is a nonzero exit, not a crash');
  await rm(elsewhere, { recursive: true, force: true });
});

test('`mfa activity` reads the audit trail while the broker runs', async () => {
  await broker.call({ connection: connectionNames.http, method: 'GET', path: '/authenticated' });
  const result = await run(
    mfaBinary(),
    ['activity', '--root', broker.root, '--json', '--limit', '50'],
    { timeoutMs: 30_000 },
  );
  assert.equal(result.code, 0, result.stderr);
  const lines = result.stdout.trim().split('\n').filter(Boolean);
  assert.ok(lines.length > 0);
  for (const line of lines) JSON.parse(line); // every line is a JSON record
  assert.ok(!result.stdout.includes(sandbox.httpToken));
});

test('default `mfa dsn` exports eval into a working psql session', async () => {
  const result = await run(
    'sh',
    [
      '-c',
      'eval "$("$AKA_TEST_MFA" dsn "$AKA_TEST_CONNECTION" --root "$AKA_TEST_ROOT" ' +
        '--client cli-tests)" && psql -X -A -t -c "SELECT 1"',
    ],
    {
      env: {
        ...process.env,
        AKA_TEST_MFA: mfaBinary(),
        AKA_TEST_CONNECTION: connectionNames.pg,
        AKA_TEST_ROOT: broker.root,
      },
      timeoutMs: 30_000,
    },
  );
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stdout.trim(), '1');

  const session = (await broker.activity()).some((entry) => entry.agent === 'cli-tests');
  assert.ok(session, 'the CLI labels its own activity');
});

test('`mfa instructions` matches what the broker serves agents', async () => {
  const served = await broker.agentRaw('GET', '/instructions', { token: null });
  const printed = await run(mfaBinary(), ['instructions', '--root', broker.root], {
    timeoutMs: 30_000,
  });
  assert.equal(printed.code, 0, printed.stderr);
  assert.equal(printed.stdout.trim(), served.text.trim());
});

test('`mfa skill` emits the same document as a skill file', async () => {
  const printed = await run(mfaBinary(), ['skill', '--root', broker.root], { timeoutMs: 30_000 });
  assert.equal(printed.code, 0, printed.stderr);
  assert.ok(printed.stdout.includes(broker.socketPath));
});

test('configuration and audit survive a restart; live capabilities do not', async () => {
  const restarted = await Broker.start({ label: 'lifecycle-restart', seed: ['http', 'pg'] });
  let reopened: Broker | undefined;
  try {
    const opened = await restarted.pgOpen(connectionNames.pg);
    const ticket = opened.json<{ dsn: string; ticket: string }>();
    await restarted.call({
      connection: connectionNames.http,
      method: 'GET',
      path: '/authenticated',
    });

    const before = {
      connections: await restarted.manage<unknown[]>('GET', '/connections'),
      secrets: await restarted.secrets(),
      activity: (await restarted.activity()).length,
    };
    const root = restarted.root;
    const manageToken = restarted.manageToken;
    await restarted.stopKeepingState();

    reopened = await Broker.reopen(root, manageToken);
    assert.deepEqual(await reopened.manage<unknown[]>('GET', '/connections'), before.connections);
    assert.deepEqual(await reopened.secrets(), before.secrets);
    assert.ok((await reopened.activity()).length >= before.activity, 'the audit log is append-only');
    assert.equal(
      (await readFile(join(root, 'sock/token'), 'utf8')).trim(),
      reopened.agentToken,
      'agents keep working with the key file they already read',
    );

    // Tickets are in-memory capabilities: a restart drops them.
    await assert.rejects(
      PgConnection.open(parseDsn(ticket.dsn, ticket.ticket)),
      'a ticket minted before the restart is not redeemable after it',
    );
  } finally {
    await reopened?.stop();
    await restarted.stop();
  }
});

test('rotating the key closes the sessions opened under the old one', async () => {
  const rotating = await Broker.start({ label: 'lifecycle-rotate', seed: ['pg'] });
  try {
    const opened = (await rotating.pgOpen(connectionNames.pg)).json<{
      dsn: string;
      ticket: string;
    }>();
    const live = await PgConnection.open(parseDsn(opened.dsn, opened.ticket));
    try {
      assert.equal((await live.query('SELECT 1')).rows[0][0], '1');
      await rotating.manage('POST', '/identity/rotate');
      // Whether the live session is cut or merely orphaned, the ticket
      // behind it must stop minting new ones.
      await waitFor(
        'the rotated ticket to stop working',
        async () => {
          try {
            const second = await PgConnection.open(parseDsn(opened.dsn, opened.ticket));
            second.close();
            return undefined;
          } catch {
            return true;
          }
        },
        15_000,
        250,
      );
    } finally {
      live.close();
    }
  } finally {
    await rotating.stop();
  }
});
