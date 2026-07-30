// The SSH connection type: a scoped signing agent, not a shell.
//
// Matrix row: an `ssh` connection (`POST /v1/ssh/open`) crossed with what
// can happen around a login — the key is listed but not usable out of
// band, a stock client authenticates through it, the host key is pinned on
// first use or refused when it does not match, access is withdrawn.
//
// The broker never runs a command: it signs a userauth request for the
// pinned user on a session whose host key it has bound. So the tests split
// in two — what the agent socket does on its own (no external tooling), and
// what a real `ssh` does with it (skipped where no client is installed).

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import test, { after, before } from 'node:test';

import {
  Broker,
  connectionNames,
  mfaBinary,
  type ApprovalSurface,
  type AutoAnswer,
} from './lib/broker';
import { run } from './lib/proc';
import {
  hasSshClient,
  requireFixture,
  sandbox,
  sshHostFingerprint,
  sshKeyExists,
} from './lib/sandbox';
import { listIdentities, signRequest, SSH_AGENT_FAILURE } from './lib/sshagent';

let broker: Broker;
let sshClient = false;

const ssh = connectionNames.ssh;

interface OpenedAgent {
  auth_sock: string;
  destination: string;
  host: string;
  port: number;
  user: string;
  host_key_fingerprint: string | null;
  expires_in_seconds: number;
}

async function open(client = 'ssh-tests'): Promise<OpenedAgent> {
  const response = await broker.agentRaw('POST', '/v1/ssh/open', {
    body: { connection: ssh },
    client,
  });
  assert.equal(response.status, 200, response.text);
  return response.json<OpenedAgent>();
}

/** Run a command on the sandbox host through a broker-issued agent socket. */
async function sshCommand(authSock: string, command: string, extra: string[] = []) {
  return run(
    'ssh',
    [
      '-o',
      'BatchMode=yes',
      '-o',
      'IdentitiesOnly=no',
      '-o',
      'StrictHostKeyChecking=no',
      '-o',
      'UserKnownHostsFile=/dev/null',
      '-p',
      String(sandbox.sshPort),
      ...extra,
      `${sandbox.sshUser}@${sandbox.host}`,
      command,
    ],
    { env: { ...process.env, SSH_AUTH_SOCK: authSock }, timeoutMs: 30_000 },
  );
}

before(async () => {
  await requireFixture();
  assert.ok(
    sshKeyExists(),
    'the sandbox SSH key is missing — run `npm run sandbox:up` to generate it',
  );
  sshClient = await hasSshClient();
  broker = await Broker.start({ label: 'ssh', seed: ['ssh'] });
});

after(async () => {
  await broker?.stop();
});

test('opening mints an agent socket and describes the destination', async () => {
  const opened = await open();
  assert.ok(existsSync(opened.auth_sock), 'the socket exists where the agent was told to look');
  assert.equal(opened.host, sandbox.host);
  assert.equal(opened.port, sandbox.sshPort);
  assert.equal(opened.user, sandbox.sshUser);
  assert.equal(opened.expires_in_seconds, 60);
  // Unpinned by default in this file's seed: the key is confirmed and
  // pinned at the first real connection.
  assert.equal(opened.host_key_fingerprint, null);
});

test('the private key stays in the broker: only a public identity is listed', async () => {
  const opened = await open();
  const identities = await listIdentities(opened.auth_sock);
  assert.equal(identities.length, 1);
  assert.equal(identities[0].type, 'ssh-ed25519');
  assert.match(identities[0].comment, /sandbox-ssh|aka/i);

  // Nothing on this socket, or in the open response, is private key material.
  assert.ok(!JSON.stringify(opened).includes('PRIVATE KEY'));
  assert.ok(!identities[0].blob.toString('utf8').includes('PRIVATE KEY'));
});

test('a signature request outside a bound session is refused', async () => {
  // A stock client sends `session-bind@openssh.com` (proving it holds the
  // server's host key) before it asks for a signature. Anything else is a
  // process on this machine trying to borrow the key for its own session.
  const opened = await open();
  const [identity] = await listIdentities(opened.auth_sock);
  const reply = await signRequest(opened.auth_sock, identity.blob, Buffer.from('sign me'));
  assert.equal(reply.type, SSH_AGENT_FAILURE);
});

test('the socket dies with agent access', async () => {
  const connection = broker.conn(ssh);
  const opened = await open();
  await broker.setAccess(connection.id, false);
  try {
    const refused = await broker.sshOpen(ssh);
    assert.equal(refused.status, 403);
    assert.equal(refused.reason, 'denied_by_policy');
    await assert.rejects(listIdentities(opened.auth_sock));
  } finally {
    await broker.setAccess(connection.id, true);
  }
});

test('a stock ssh client logs in through the socket', async (t) => {
  if (!sshClient) return t.skip('no ssh client on PATH');
  const opened = await open('ssh-login');
  const result = await sshCommand(opened.auth_sock, 'echo brokered-login-ok');
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /brokered-login-ok/);

  const activity = await broker.activity();
  assert.ok(
    activity.some((entry) => entry.connection === ssh),
    'the session is attributed to the connection',
  );
});

test('the `mfa ssh` binary opens a socket a stock client can use', async (t) => {
  if (!sshClient) return t.skip('no ssh client on PATH');
  const opened = await run(
    mfaBinary(),
    ['ssh', ssh, '--root', broker.root, '--client', 'cli-spawn'],
    { timeoutMs: 30_000 },
  );
  assert.equal(opened.code, 0, opened.stderr);
  const authSock = opened.stdout.trim();
  assert.ok(existsSync(authSock), `mfa returned a live socket: ${authSock}`);

  const result = await sshCommand(authSock, 'echo cli-spawn-ok');
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /cli-spawn-ok/);
  assert.ok(
    (await broker.activity()).some(
      (entry) => entry.connection === ssh && entry.agent === 'cli-spawn',
    ),
    'the spawned CLI preserves its client attribution',
  );
});

test('the host key is pinned on first use', async (t) => {
  if (!sshClient) return t.skip('no ssh client on PATH');
  // This file's connection starts unpinned; the login above pinned it.
  const connection = await broker.refresh(ssh);
  const observed = await sshHostFingerprint();
  assert.ok(connection.host_key_fingerprint, 'the observed key was pinned');
  if (observed) assert.equal(connection.host_key_fingerprint, observed);
});

test('a mismatched host key stops the login', async (t) => {
  if (!sshClient) return t.skip('no ssh client on PATH');
  const connection = broker.conn(ssh);
  const pinned = (await broker.refresh(ssh)).host_key_fingerprint;
  await broker.manage('PUT', `/connections/${connection.id}`, {
    spec: {
      name: ssh,
      config: {
        kind: 'ssh',
        host: sandbox.host,
        port: sandbox.sshPort,
        user: sandbox.sshUser,
        // A syntactically valid fingerprint for a key the sandbox does not have.
        host_key_fingerprint: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      },
      secrets: [await broker.secretId('SANDBOX_SSH_KEY')],
    },
  });
  try {
    const opened = await open('ssh-mitm');
    const result = await sshCommand(opened.auth_sock, 'echo should-not-run');
    assert.notEqual(result.code, 0, 'the client could not authenticate');
    assert.ok(!result.stdout.includes('should-not-run'));
  } finally {
    await broker.manage('PUT', `/connections/${connection.id}`, {
      spec: {
        name: ssh,
        config: {
          kind: 'ssh',
          host: sandbox.host,
          port: sandbox.sshPort,
          user: sandbox.sshUser,
          host_key_fingerprint: pinned ?? '',
        },
        secrets: [await broker.secretId('SANDBOX_SSH_KEY')],
      },
    });
    await broker.refresh(ssh);
  }
});

test('the broker signs only for the pinned login user', async (t) => {
  if (!sshClient) return t.skip('no ssh client on PATH');
  const opened = await open('ssh-wrong-user');
  const result = await run(
    'ssh',
    [
      '-o',
      'BatchMode=yes',
      '-o',
      'StrictHostKeyChecking=no',
      '-o',
      'UserKnownHostsFile=/dev/null',
      '-p',
      String(sandbox.sshPort),
      `root@${sandbox.host}`,
      'id',
    ],
    { env: { ...process.env, SSH_AUTH_SOCK: opened.auth_sock }, timeoutMs: 30_000 },
  );
  assert.notEqual(result.code, 0, 'a login as another user is not signed for');
});

test('SSH login confirmation approves, denies, and fails closed when the app is away', async (t) => {
  if (!sshClient) return t.skip('no ssh client on PATH');

  for (const scenario of ['approve', 'deny', 'away'] as const) {
    await t.test(scenario, async () => {
      const confirming = await Broker.start({
        label: `ssh-confirm-${scenario}`,
        seed: ['ssh'],
      });
      try {
        let answering: AutoAnswer | undefined;
        let surface: ApprovalSurface | undefined;
        if (scenario !== 'away') {
          surface = await confirming.attachApprovalSurface();
          answering = surface.autoAnswer(() =>
            scenario === 'approve' ? 'approve_window' : 'deny',
          );
        }
        await confirming.setConfirm(confirming.conn(ssh).id, true);

        const response = await confirming.sshOpen(ssh);
        assert.equal(response.status, 200, response.text);
        const opened = response.json<OpenedAgent>();
        const result = await sshCommand(opened.auth_sock, `echo ssh-${scenario}`);

        if (scenario === 'approve') {
          assert.equal(result.code, 0, result.stderr);
          assert.match(result.stdout, /ssh-approve/);
          assert.equal(answering?.answered.length, 1);
          assert.equal(answering?.answered[0].unit, 'login');
          assert.match(answering?.answered[0].summary ?? '', /SSH login as sandbox@/);
          assert.match(answering?.answered[0].consequence ?? '', /signs one SSH login/i);
        } else {
          assert.notEqual(result.code, 0, 'the broker declined the authentication signature');
          assert.ok(!result.stdout.includes(`ssh-${scenario}`));
          if (scenario === 'deny') assert.equal(answering?.answered.length, 1);
          const expected = scenario === 'deny' ? 'approval_denied' : 'approval_unavailable';
          assert.ok(
            (await confirming.activity()).some(
              (entry) =>
                entry.connection === ssh &&
                entry.text.includes('SSH signature refused') &&
                entry.outcome === expected,
            ),
            `the ${scenario} refusal is attributable as ${expected}`,
          );
        }

        answering?.stop();
        surface?.detach();
      } finally {
        await confirming.stop();
      }
    });
  }
});
