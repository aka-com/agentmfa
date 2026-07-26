// Traffic confirmation: agent traffic parked on a human decision.
//
// Matrix row: any connection with its confirm switch on, crossed with what
// the user does — nothing (no app attached), approve for the window,
// approve and stop asking, refuse — and with what happens to the
// connection while a call is parked.
//
// The "user" here is a request inbox attached exactly the way the desktop
// app attaches one: an authenticated manage event stream carrying the
// request-surface header, heartbeat and all.

import assert from 'node:assert/strict';
import test, { after, before } from 'node:test';

import { Broker, connectionNames, type ApprovalSurface } from './lib/broker';
import { sleep } from './lib/http';
import { pending } from './lib/pending';
import { requireFixture } from './lib/sandbox';

let broker: Broker;
let surface: ApprovalSurface;

const http = connectionNames.http;
const alt = connectionNames['http-alt'];

/** Confirmed traffic, run under a stand-in user with a fixed answer. */
async function callUnder(
  decision: 'approve_window' | 'approve_all' | 'deny',
  body: Record<string, unknown>,
  client: string,
) {
  const answering = surface.autoAnswer(() => decision);
  try {
    return { response: await broker.http(body, { client }), prompts: answering.answered };
  } finally {
    answering.stop();
  }
}

before(async () => {
  await requireFixture();
  broker = await Broker.start({ label: 'approvals', seed: ['http', 'http-alt'] });
  surface = await broker.attachApprovalSurface();
  await broker.setConfirm(broker.conn(http).id, true);
  await broker.setConfirm(broker.conn(alt).id, true);
});

after(async () => {
  await broker?.stop();
});

test('with nothing attached, confirmed traffic fails closed', async () => {
  // Its own broker: "is a surface attached" is a property of the whole
  // broker, and this file's other tests need one attached.
  const headless = await Broker.start({ label: 'approvals-headless', seed: ['http'] });
  try {
    await headless.setConfirm(headless.conn(http).id, true);
    const response = await headless.http({
      connection: http,
      method: 'GET',
      path: '/authenticated',
    });
    assert.equal(response.status, 403);
    assert.equal(response.reason, 'approval_unavailable');

    const history = await headless.requests();
    assert.equal(history[0]?.status, 'unavailable');
  } finally {
    await headless.stop();
  }
});

test('an attached stream is classified as an active request surface', () => {
  assert.match(surface.id, /^[0-9a-f-]{36}$/);
});

test('the prompt describes the call in the user’s terms', async () => {
  const { response, prompts } = await callUnder(
    'approve_window',
    { connection: http, method: 'POST', path: '/echo', body: 'a body the user should see' },
    'prompt-shape',
  );
  assert.equal(response.status, 200);
  assert.equal(prompts.length, 1);

  const [prompt] = prompts;
  assert.equal(prompt.connection, http);
  assert.equal(prompt.type, 'api');
  assert.equal(prompt.unit, 'request');
  assert.equal(prompt.agent, 'prompt-shape');
  assert.equal(prompt.summary, 'POST /echo');
  assert.match(String(prompt.detail), /a body the user should see/);
  assert.match(prompt.target, /^http:\/\/127\.0\.0\.1/);
  assert.equal(prompt.window_secs, 900);
  assert.ok(Date.parse(prompt.expires_at) > Date.parse(prompt.requested_at));
});

test('approving for the window covers that agent’s later calls', async () => {
  const answering = surface.autoAnswer(() => 'approve_window');
  try {
    const first = await broker.http(
      { connection: http, method: 'GET', path: '/authenticated' },
      { client: 'window-rider' },
    );
    assert.equal(first.status, 200);
    assert.equal(answering.answered.length, 1);

    // Inside the window, nothing is asked again.
    for (let i = 0; i < 3; i += 1) {
      const again = await broker.http(
        { connection: http, method: 'GET', path: `/status/${200 + i}` },
        { client: 'window-rider' },
      );
      assert.equal(again.status, 200);
    }
    assert.equal(answering.answered.length, 1, 'one decision covered them all');
  } finally {
    answering.stop();
  }

  const connection = await broker.refresh(http);
  assert.ok(connection.agent_access.confirm_window_until, 'the app can say a window is open');
  assert.ok(connection.agent_access.confirm_window_agents?.includes('window-rider'));
});

test('a window is scoped to the agent it was shown for', async () => {
  // `window-rider` above still has an open window; a different label is a
  // different question, so this call raises its own prompt.
  const { response, prompts } = await callUnder(
    'approve_window',
    { connection: http, method: 'GET', path: '/authenticated' },
    'someone-else',
  );
  assert.equal(response.status, 200);
  assert.equal(prompts.length, 1);
  assert.equal(prompts[0].agent, 'someone-else');
});

test('concurrent calls ride one prompt instead of burying the user', async () => {
  const answering = surface.autoAnswer(() => 'approve_window');
  try {
    const calls = Array.from({ length: 5 }, (_, i) =>
      broker.http(
        { connection: http, method: 'GET', path: `/status/${200 + i}` },
        { client: 'coalescing' },
      ),
    );
    // Let the prompt gather its waiters before the stand-in user answers.
    await sleep(150);
    const pendingPrompts = await broker.approvals();
    const results = await Promise.all(calls);

    assert.deepEqual(
      results.map((response) => response.status),
      [200, 200, 200, 200, 200],
    );
    assert.equal(answering.answered.length, 1, 'one prompt for five calls');
    if (pendingPrompts.length > 0) {
      assert.ok(pendingPrompts[0].waiting > 1, 'the prompt names how many calls ride it');
    }
  } finally {
    answering.stop();
  }
});

test('approve-all turns the connection’s switch off', async () => {
  const { response, prompts } = await callUnder(
    'approve_all',
    { connection: http, method: 'GET', path: '/authenticated' },
    'stop-asking',
  );
  assert.equal(response.status, 200);
  assert.equal(prompts.length, 1);

  const connection = await broker.refresh(http);
  assert.equal(connection.agent_access.confirm, false);

  // And traffic now runs with nothing asked.
  const after = await broker.http(
    { connection: http, method: 'GET', path: '/authenticated' },
    { client: 'stop-asking' },
  );
  assert.equal(after.status, 200);
  assert.deepEqual(await broker.approvals(), []);
});

test('the request history keeps terminal records after traffic resumes', async () => {
  const history = await broker.requests();
  assert.ok(history.length > 0);
  assert.ok(history.every((record) => record.kind === 'approval'));
  assert.ok(history.some((record) => record.status === 'approved'));
  const approved = history.find((record) => record.status === 'approved');
  assert.ok(approved?.resolution, 'the record says how it ended');
});

test('a connection disabled while a call is parked refuses that call', async () => {
  const connection = broker.conn(alt);
  const parked = broker.http(
    { connection: alt, method: 'GET', path: '/authenticated' },
    { client: 'racer' },
  );
  await broker.waitForApproval();
  await broker.setAccess(connection.id, false);

  const response = await parked;
  assert.equal(response.status, 403);
  assert.equal(response.reason, 'denied_by_policy');
  assert.deepEqual(await broker.approvals(), [], 'the stale prompt was withdrawn');
  await broker.setAccess(connection.id, true);
});

// Denial is deliberately near the end: it starts a 60-second cooldown on
// the connection, which by design refuses everything that follows.
test('a refusal is a refusal, and it cools down', async () => {
  const { response, prompts } = await callUnder(
    'deny',
    { connection: alt, method: 'GET', path: '/authenticated' },
    'refused',
  );
  assert.equal(response.status, 403);
  assert.equal(response.reason, 'approval_denied');
  assert.equal(prompts.length, 1);
  assert.match(response.json<{ detail: string }>().detail, new RegExp(alt));

  // A retry inside the cooldown is refused without asking again — that is
  // what stops a looping agent from becoming a prompt loop.
  const retry = await broker.http(
    { connection: alt, method: 'GET', path: '/authenticated' },
    { client: 'refused' },
  );
  assert.equal(retry.status, 403);
  assert.equal(retry.reason, 'approval_denied');
  assert.deepEqual(await broker.approvals(), [], 'no second prompt was raised');

  // Another agent is covered by the same cooldown: it is per connection.
  const other = await broker.http(
    { connection: alt, method: 'GET', path: '/authenticated' },
    { client: 'bystander' },
  );
  assert.equal(other.reason, 'approval_denied');

  const connection = await broker.refresh(alt);
  assert.ok(connection.agent_access.confirm_cooldown_until, 'the app can say why');

  const denied = (await broker.requests()).find((record) => record.status === 'denied');
  assert.ok(denied, 'the refusal is in the request history');
});

test('an unanswered prompt eventually times out', { skip: !process.env.AKA_SANDBOX_SLOW }, async (t) => {
  // 90 seconds of wall clock, so it runs only under AKA_SANDBOX_SLOW=1.
  const connection = broker.conn(http);
  await broker.setConfirm(connection.id, true);
  const parked = broker.http(
    { connection: http, method: 'GET', path: '/authenticated' },
    { client: 'never-answered' },
  );
  await broker.waitForApproval();
  const response = await parked;
  assert.equal(response.status, 408);
  assert.equal(response.reason, 'approval_timeout');
  t.diagnostic('the parked call was refused on the broker clock, not the client’s');
});

// ---------------------------------------------------------------------------
// Approval granularity that AKA does not have. Kept in this file (rather
// than only in unsupported.test.ts) because this is where an implementer
// would look for it.
// ---------------------------------------------------------------------------

test('approval levels do not differ by operation kind', (t) => {
  // A user gets one switch per connection and one decision vocabulary —
  // approve for the window, approve and stop asking, deny
  // (`ApprovalDecisionDto` in crates/aka-api/src/lib.rs). There is no
  // "ask me only for writes", no separate level for destructive calls, and
  // the window a GET opens covers the DELETE that follows it.
  pending(
    t,
    'confirming reads and writes at different levels (e.g. GET waved through, POST/DELETE always asked)',
    'one confirm switch per connection; any approval opens a window covering every method',
  );
});

test('destructive operations are not recognized as a class', (t) => {
  // `is_mutating()` in crates/aka-core/src/capability/http.rs exists, but
  // only to decide whether an idempotency key may coalesce a retry — it
  // never reaches the approval gate, and DELETE is not distinguished from
  // POST anywhere in policy.
  pending(
    t,
    'treating destructive operations (DELETE, DROP, rm -rf) as their own approval class',
    'mutating-ness only affects idempotency coalescing, never the decision the user is asked for',
  );
});

test('an approval cannot be scoped to a path, method, or resource', (t) => {
  // The prompt shows `GET /repos/x/y`, but approving it grants the whole
  // connection for the window; there is no way to answer "this path only".
  pending(
    t,
    'answering a prompt with a narrower grant than the connection (this path/method only)',
    'a grant is keyed on (connection, agent) and covers every call for the window',
  );
});
