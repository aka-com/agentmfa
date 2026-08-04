// The Postgres connection type: ticket, proxy, session.
//
// Matrix row: a `pg` connection (`POST /v1/pg/open` plus the wire proxy)
// crossed with what can happen between minting a ticket and running a
// query — the ticket is reused, the connection is switched off, retargeted,
// the session is closed by the user, the traffic is confirmed or refused.
//
// The client here is the small protocol implementation in lib/pgwire.ts, so
// the assertions are about the bytes a stock client would exchange.

import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';

import { Broker, connectionNames } from './lib/broker';
import { waitFor } from './lib/http';
import { pending } from './lib/pending';
import { parseDsn, PgConnection, PostgresError, queryOnce } from './lib/pgwire';
import { requireFixture, sandbox } from './lib/sandbox';

let broker: Broker;

const pg = connectionNames.pg;

interface Opened {
  dsn: string;
  ticket: string;
  example: string;
  expires_in_seconds: number;
}

async function open(client = 'pg-tests'): Promise<Opened> {
  const response = await broker.agentRaw('POST', '/v1/pg/open', {
    body: { connection: pg },
    client,
  });
  assert.equal(response.status, 200, response.text);
  return response.json<Opened>();
}

before(async () => {
  await requireFixture();
  broker = await Broker.start({ label: 'postgres', seed: ['pg', 'http'] });
});

after(async () => {
  await broker?.stop();
});

test('opening mints a password-less DSN and a separate short-lived ticket', async () => {
  const opened = await open();
  const dsn = new URL(opened.dsn);
  assert.equal(dsn.protocol, 'postgres:');
  assert.equal(dsn.username, 'ticket');
  assert.equal(dsn.password, '', 'the ticket is handed over separately, not embedded');
  assert.equal(dsn.hostname, '127.0.0.1');
  assert.notEqual(Number(dsn.port), sandbox.pgPort, 'the agent dials the broker, not the database');
  assert.equal(dsn.pathname, `/${sandbox.pgDatabase}`);
  assert.equal(dsn.searchParams.get('sslmode'), 'disable');

  assert.match(opened.ticket, /^tkt_[0-9a-f]{32}$/);
  assert.equal(opened.expires_in_seconds, 60);
  assert.match(opened.example, /PGPASSWORD=<ticket> psql/);

  // Nothing about the upstream credential crosses to the agent.
  assert.ok(!JSON.stringify(opened).includes(sandbox.pgPassword));
});

test('redeeming the ticket connects as the configured upstream user', async () => {
  const opened = await open();
  const result = await queryOnce(parseDsn(opened.dsn, opened.ticket), 'SELECT current_user, current_database()');
  assert.deepEqual(result.rows, [[sandbox.pgUser, sandbox.pgDatabase]]);
});

test('the agent never learns the database password, even mid-session', async () => {
  const opened = await open();
  const connection = await PgConnection.open(parseDsn(opened.dsn, opened.ticket));
  try {
    // `password` is not readable back out of the server, but the proxy also
    // must not put it anywhere the client can see: check the parameters the
    // server did report.
    const settings = await connection.query("SELECT name, setting FROM pg_settings WHERE name = 'application_name'");
    assert.ok(!JSON.stringify(settings.rows).includes(sandbox.pgPassword));
  } finally {
    connection.close();
  }
});

test('one ticket can open several sessions inside its window', async () => {
  const opened = await open();
  const first = await PgConnection.open(parseDsn(opened.dsn, opened.ticket));
  const second = await PgConnection.open(parseDsn(opened.dsn, opened.ticket));
  try {
    assert.equal((await first.query('SELECT 1')).rows[0][0], '1');
    assert.equal((await second.query('SELECT 2')).rows[0][0], '2');
  } finally {
    first.close();
    second.close();
  }
});

test('a repeated open under one idempotency key hands back the same ticket', async () => {
  const first = await broker.pgOpen(pg, 'pg-open-1');
  const replay = await broker.pgOpen(pg, 'pg-open-1');
  assert.equal(first.status, 200);
  assert.deepEqual(replay.json(), first.json());
});

test('a live session shows up in the sessions band and can be closed there', async () => {
  const opened = await open('session-watcher');
  const connection = await PgConnection.open({
    ...parseDsn(opened.dsn, opened.ticket),
    applicationName: 'sandbox-suite',
  });
  try {
    const session = await waitFor('the session to register', async () =>
      (await broker.sessions()).find((row) => row.agent === 'session-watcher'),
    );
    assert.equal(session.type, 'pg');
    assert.equal(session.connection, pg);
    assert.match(session.detail, new RegExp(`${sandbox.pgUser}@`));

    // The user closing a session from the app must actually cut the wire.
    await broker.manage('DELETE', `/sessions/${session.id}`);
    await connection.waitForClose();
    assert.ok(connection.isClosed);
  } finally {
    connection.close();
  }
});

test('an unknown ticket is refused by the proxy as an authentication failure', async () => {
  const opened = await open();
  await assert.rejects(
    queryOnce(parseDsn(opened.dsn, 'tkt_00000000000000000000000000000000'), 'SELECT 1'),
    (error: unknown) => {
      assert.ok(error instanceof PostgresError);
      assert.equal(error.fields.severity, 'FATAL');
      assert.equal(error.fields.code, '28P01');
      assert.match(error.fields.message, /unknown_ticket/);
      return true;
    },
  );
});

test('turning agent access off refuses new opens and kills issued tickets', async () => {
  const connection = broker.conn(pg);
  const opened = await open();
  await broker.setAccess(connection.id, false);
  try {
    const refusedOpen = await broker.pgOpen(pg);
    assert.equal(refusedOpen.status, 403);
    assert.equal(refusedOpen.reason, 'denied_by_policy');

    // The ticket minted while it was enabled is not a way around that.
    // Withdrawing access invalidates the outstanding tickets, so the proxy
    // meets a dead ticket before it ever gets to the policy check — hence
    // `ticket_expired` rather than `denied_by_policy`.
    await assert.rejects(
      queryOnce(parseDsn(opened.dsn, opened.ticket), 'SELECT 1'),
      (error: unknown) => {
        assert.ok(error instanceof PostgresError);
        assert.equal(error.fields.code, '28P01');
        assert.match(error.fields.message, /ticket_expired|denied_by_policy/);
        return true;
      },
    );
  } finally {
    await broker.setAccess(connection.id, true);
  }
});

test('withdrawing a connection closes the sessions already running on it', async () => {
  const connection = broker.conn(pg);
  const opened = await open('withdrawal');
  const live = await PgConnection.open(parseDsn(opened.dsn, opened.ticket));
  try {
    await waitFor('the session to register', async () =>
      (await broker.sessions()).find((row) => row.agent === 'withdrawal'),
    );
    await broker.setAccess(connection.id, false);
    await live.waitForClose();
    assert.ok(live.isClosed, 'the live session was cut, not left running');
  } finally {
    live.close();
    await broker.setAccess(connection.id, true);
  }
});

test('a ticket does not survive its connection being retargeted', async () => {
  const connection = broker.conn(pg);
  const opened = await open();
  // Same database, different login user: any change to the authority the
  // ticket was minted against invalidates it.
  await broker.manage('PUT', `/connections/${connection.id}`, {
    spec: {
      name: pg,
      config: {
        kind: 'pg',
        host: sandbox.host,
        port: sandbox.pgPort,
        dbname: sandbox.pgDatabase,
        user: 'someone-else',
        sslmode: 'disable',
      },
      secrets: [await broker.secretId('SANDBOX_PG_PASSWORD')],
    },
  });
  try {
    // As with withdrawal, the edit invalidates outstanding tickets, so this
    // is reported as a dead ticket rather than as a policy refusal; the
    // proxy's `updated_at` check behind it refuses a stale approval too.
    await assert.rejects(
      queryOnce(parseDsn(opened.dsn, opened.ticket), 'SELECT 1'),
      (error: unknown) => {
        assert.ok(error instanceof PostgresError);
        assert.match(error.fields.message, /ticket_expired|denied_by_policy/);
        return true;
      },
    );
  } finally {
    await broker.manage('PUT', `/connections/${connection.id}`, {
      spec: {
        name: pg,
        config: {
          kind: 'pg',
          host: sandbox.host,
          port: sandbox.pgPort,
          dbname: sandbox.pgDatabase,
          user: sandbox.pgUser,
          sslmode: 'disable',
        },
        secrets: [await broker.secretId('SANDBOX_PG_PASSWORD')],
      },
    });
    await broker.refresh(pg);
  }
});

test('a wrong upstream password fails at the proxy, not at the agent', async () => {
  const secretId = await broker.secretId('SANDBOX_PG_PASSWORD');
  await broker.manage('PATCH', `/secrets/${secretId}`, { new_value: 'not-the-password' });
  try {
    const opened = await open();
    await assert.rejects(
      queryOnce(parseDsn(opened.dsn, opened.ticket), 'SELECT 1'),
      (error: unknown) => {
        assert.ok(error instanceof PostgresError);
        // The agent is told the upstream leg failed; it never sees why in
        // credential terms, and never sees the value it tried.
        assert.match(error.fields.message, /upstream_connect_failed/);
        assert.ok(!error.fields.message.includes('not-the-password'));
        return true;
      },
    );
  } finally {
    await broker.manage('PATCH', `/secrets/${secretId}`, { new_value: sandbox.pgPassword });
  }
});

test('confirmation is asked once per session, and says what a session is', async () => {
  const connection = broker.conn(pg);
  const surface = await broker.attachApprovalSurface();
  const answering = surface.autoAnswer(() => 'approve_window');
  await broker.setConfirm(connection.id, true);
  try {
    const opened = await open('psql-user');
    // Nothing is asked at open time: the ticket may never be redeemed.
    assert.deepEqual(await broker.approvals(), []);

    const live = await PgConnection.open({
      ...parseDsn(opened.dsn, opened.ticket),
      applicationName: 'psql',
    });
    try {
      assert.equal((await live.query('SELECT 1')).rows[0][0], '1');
      // …and every statement after the first runs unasked.
      assert.equal((await live.query('SELECT 2')).rows[0][0], '2');
      assert.equal(answering.answered.length, 1, 'one prompt for the whole session');

      const [prompt] = answering.answered;
      assert.equal(prompt.unit, 'session');
      assert.equal(prompt.summary, 'New Postgres session');
      assert.equal(prompt.agent, 'psql-user');
      assert.match(String(prompt.detail), /psql/);
      assert.match(String(prompt.consequence), /once per session, not per statement/);
    } finally {
      live.close();
    }
  } finally {
    answering.stop();
    await broker.setConfirm(connection.id, false);
    surface.detach();
  }
});

test('a refused session never reaches the database', async () => {
  const connection = broker.conn(pg);
  const surface = await broker.attachApprovalSurface();
  const answering = surface.autoAnswer(() => 'deny');
  await broker.setConfirm(connection.id, true);
  try {
    const opened = await open('unwelcome');
    await assert.rejects(
      queryOnce(parseDsn(opened.dsn, opened.ticket), 'SELECT 1'),
      (error: unknown) => {
        assert.ok(error instanceof PostgresError);
        assert.equal(error.fields.code, '28000');
        assert.match(error.fields.message, /approval_denied/);
        return true;
      },
    );
    assert.equal(answering.answered.length, 1);
  } finally {
    answering.stop();
    await broker.setConfirm(connection.id, false);
    surface.detach();
  }
});

test('with no app attached, a confirmed session fails closed', async () => {
  const headless = await Broker.start({ label: 'postgres-headless', seed: ['pg'] });
  try {
    await headless.setConfirm(headless.conn(pg).id, true);
    const response = await headless.pgOpen(pg);
    const opened = response.json<Opened>();
    await assert.rejects(
      queryOnce(parseDsn(opened.dsn, opened.ticket), 'SELECT 1'),
      (error: unknown) => {
        assert.ok(error instanceof PostgresError);
        assert.match(error.fields.message, /approval_unavailable/);
        return true;
      },
    );
  } finally {
    await headless.stop();
  }
});

test('sessions and refusals are audited', async () => {
  const activity = await broker.activity();
  assert.ok(
    activity.some((entry) => entry.connection === pg && /session/i.test(entry.text)),
    'session activity is attributed to the connection',
  );
  assert.ok(!JSON.stringify(activity).includes(sandbox.pgPassword));
});

test('a ticket expires 60 seconds after issue', { skip: !process.env.AKA_SANDBOX_SLOW }, async () => {
  const opened = await open();
  await new Promise((resolve) => setTimeout(resolve, 61_000));
  await assert.rejects(
    queryOnce(parseDsn(opened.dsn, opened.ticket), 'SELECT 1'),
    (error: unknown) => {
      assert.ok(error instanceof PostgresError);
      assert.match(error.fields.message, /ticket_expired/);
      return true;
    },
  );
});

// ---------------------------------------------------------------------------
// Postgres-shaped policy Multitool does not have.
// ---------------------------------------------------------------------------

test('statements inside a session are not inspected', (t) => {
  // The proxy splices bytes once the session is established
  // (`handle_conn` in crates/aka-core/src/capability/pg.rs). Nothing parses
  // the SQL, so nothing can approve, refuse, rewrite, or log individual
  // statements. `SESSION_CONSEQUENCE` in that file is the broker admitting
  // as much to the user, in the prompt.
  pending(
    t,
    'per-statement inspection of a Postgres session (approve SELECT, ask about UPDATE, refuse DROP)',
    'one confirmation covers the whole session; statements are spliced through unparsed',
  );
});

test('a session cannot be limited to reads', (t) => {
  pending(
    t,
    'opening a read-only Postgres session (SET TRANSACTION READ ONLY, or a read-only role, enforced by the broker)',
    'the session runs with whatever the configured upstream role may do, writes included',
  );
});

test('collections (schemas, tables, columns) cannot be scoped or inspected', (t) => {
  // A connection pins host/port/database/user and nothing finer: there is
  // no allow-list of schemas or tables, no per-table approval, and no
  // record of which relations a session touched.
  pending(
    t,
    'scoping a connection to specific schemas/tables, or reporting which ones a session read',
    'a pg connection pins user@host:port/database; everything inside the database is in scope',
  );
});

test('result sets are not measured or capped', (t) => {
  // The 10 MB response cap applies to relayed HTTP bodies only; a spliced
  // Postgres session has no byte or row budget of its own.
  pending(
    t,
    'row/byte budgets on a Postgres session (stop a SELECT * FROM everything)',
    'the proxy splices without accounting; only HTTP responses have a size cap',
  );
});
