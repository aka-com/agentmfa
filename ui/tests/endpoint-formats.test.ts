import { readFile } from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ENDPOINT_FORMATS,
  endpointFormatByKey,
  libpqKeywords,
  scpCommand,
  sshConfigBlock,
} from '../src/endpoint-formats';
import { SSH_BROKER_OPTIONS, sshBrokerFlags } from '../src/getting-started';
import type { ConnectionSummary, ConnectionType } from '../src/types';

function conn(
  type: ConnectionType,
  name: string,
  extra: Partial<ConnectionSummary> = {},
): ConnectionSummary {
  return {
    id: name, name, type, target: name, secret_names: [], oauth: false,
    agent_access: { enabled: true },
    host: null, scheme: null, port: null, template: null, dbname: null, user: null,
    host_key_fingerprint: null, destination: null, sslmode: null,
    trusted_ca_bundle_path: null,
    ...extra,
  };
}

// The broker's issued Postgres DSN: empty authority host, the Unix socket
// directory riding in ?host=.
const PG_SOCKET_DSN =
  'postgresql://app:s3cret@/appdb?host=/Users/me/.aka/endpoints/ep1&port=5432&sslmode=disable';

test('button order and labels match the agreed set per kind', () => {
  assert.deepEqual(
    ENDPOINT_FORMATS.pg.map((f) => f.label),
    ['psql', 'libpq', '.env snippet', 'TCP URL'],
  );
  assert.deepEqual(
    ENDPOINT_FORMATS.ssh.map((f) => f.label),
    // No sftp button: the URL referenced no issued socket, so it could not
    // work, and the GUI clients it targeted read ~/.ssh/config instead.
    ['ssh', 'scp', 'SSH config'],
  );
  assert.deepEqual(
    ENDPOINT_FORMATS.api.map((f) => f.label),
    ['curl', '.env snippet'],
  );
});

test('pg formats wrap the DSN for psql and .env', () => {
  const c = conn('pg', 'prod-db');
  assert.equal(
    endpointFormatByKey('pg', 'psql')?.build(c, PG_SOCKET_DSN),
    `psql "${PG_SOCKET_DSN}"`,
  );
  assert.equal(
    endpointFormatByKey('pg', 'env')?.build(c, PG_SOCKET_DSN),
    `DATABASE_URL="${PG_SOCKET_DSN}"`,
  );
});

test('libpq keywords come from the query for socket-shaped DSNs', () => {
  assert.equal(
    libpqKeywords(PG_SOCKET_DSN),
    'host=/Users/me/.aka/endpoints/ep1 port=5432 dbname=appdb user=app'
      + ' password=s3cret sslmode=disable',
  );
});

test('libpq keywords come from the authority for TCP DSNs', () => {
  assert.equal(
    libpqKeywords('postgresql://alice:p%40ss@db.internal:15432/orders'),
    "host=db.internal port=15432 dbname=orders user=alice password=p@ss",
  );
});

test('libpq quotes values with spaces and rejects non-DSN strings', () => {
  assert.equal(
    libpqKeywords('postgresql://u:two%20words@h/db'),
    "host=h dbname=db user=u password='two words'",
  );
  assert.equal(libpqKeywords('not-a-dsn'), null);
});

// The filename is derived from the endpoint secret (SSH-1), so it is not
// `agent.sock` and not reconstructible from the endpoint id.
const SOCK = '/Users/me/.aka/endpoints/ep2/agent-3f1c9a2b04d7e685.sock';
const FLAGS = sshBrokerFlags();

test('ssh format reuses the runnable command over the issued socket', () => {
  const c = conn('ssh', 'Sandbox', { user: 'sandbox', host: '127.0.0.1', port: 12222 });
  assert.equal(
    endpointFormatByKey('ssh', 'ssh')?.build(c, SOCK),
    `SSH_AUTH_SOCK="${SOCK}" ssh -p 12222 ${FLAGS} sandbox@127.0.0.1`,
  );
});

// SSH-14: SSH_AUTH_SOCK alone leaves the default IdentityFile list in place, so
// a working ~/.ssh/id_ed25519 completes the login with no broker involvement
// and no audit entry. IdentitiesOnly is the flag that looks right and is wrong:
// OpenSSH drops agent identities matching no IdentityFile, and the broker's key
// has no on-disk .pub.
test('every emitted ssh invocation suppresses on-disk keys, forwarding, and muxing', () => {
  const c = conn('ssh', 'Sandbox', { user: 'sandbox', host: '127.0.0.1', port: 12222 });
  for (const built of [
    endpointFormatByKey('ssh', 'ssh')?.build(c, SOCK) ?? '',
    scpCommand(SOCK, c),
  ]) {
    assert.match(built, /-o IdentityFile=none\b/, built);
    assert.match(built, /-o CertificateFile=none\b/, built);
    assert.match(built, /-o ForwardAgent=no\b/, built);
    assert.match(built, /-o ControlMaster=no\b/, built);
    // SSH-5: the jump hop is a separate login against the jump host, which the
    // broker cannot authenticate — a tool pins one host key. Refusing the jump
    // fails at connect instead of as a host-key mismatch.
    assert.match(built, /-o ProxyJump=none\b/, built);
    assert.doesNotMatch(built, /IdentitiesOnly/, built);
  }
});

test('scp mirrors the ssh destination logic with the -P flag', () => {
  const explicit = conn('ssh', 'Sandbox', { user: 'sandbox', host: '127.0.0.1', port: 12222 });
  assert.equal(
    scpCommand(SOCK, explicit),
    `SSH_AUTH_SOCK="${SOCK}" scp -P 12222 ${FLAGS} <file> sandbox@127.0.0.1:`,
  );
  const defaultPort = conn('ssh', 'Box', { user: 'deploy', host: 'box.example', port: 22 });
  assert.equal(
    scpCommand(SOCK, defaultPort),
    `SSH_AUTH_SOCK="${SOCK}" scp ${FLAGS} <file> deploy@box.example:`,
  );
  const imported = conn('ssh', 'Alias', { destination: 'myserver', port: 2200 });
  assert.equal(
    scpCommand(SOCK, imported),
    `SSH_AUTH_SOCK="${SOCK}" scp -P 2200 ${FLAGS} <file> myserver:`,
  );
});

test('SSH config block names the tool, pins the agent, and skips port 22', () => {
  const c = conn('ssh', 'Prod Sandbox', { user: 'sandbox', host: '127.0.0.1', port: 12222 });
  assert.equal(
    sshConfigBlock(SOCK, c),
    [
      'Host Prod-Sandbox',
      '  HostName 127.0.0.1',
      '  Port 12222',
      '  User sandbox',
      `  IdentityAgent "${SOCK}"`,
      '  IdentityFile none',
      '  CertificateFile none',
      '  ForwardAgent no',
      '  ControlMaster no',
      '  ProxyJump none',
    ].join('\n'),
  );
  const plain = conn('ssh', 'Box', { user: 'deploy', host: 'box.example', port: 22 });
  assert.equal(
    sshConfigBlock(SOCK, plain),
    [
      'Host Box',
      '  HostName box.example',
      '  User deploy',
      `  IdentityAgent "${SOCK}"`,
      '  IdentityFile none',
      '  CertificateFile none',
      '  ForwardAgent no',
      '  ControlMaster no',
      '  ProxyJump none',
    ].join('\n'),
  );
});

test('api formats embed the fetched secret, or a placeholder without one', () => {
  const c = conn('api', 'Internal API');
  const base = 'http://127.0.0.1:52000';
  const curl = endpointFormatByKey('api', 'curl');
  assert.equal(curl?.needsSecret, true);
  assert.equal(
    curl?.build(c, base, 'end_secret'),
    `curl -H "Authorization: Bearer end_secret" ${base}/`,
  );
  assert.equal(
    curl?.build(c, base, null),
    `curl -H "Authorization: Bearer <endpoint-secret>" ${base}/`,
  );
  assert.equal(
    endpointFormatByKey('api', 'env')?.build(c, base, 'end_secret'),
    `API_BASE_URL=${base}\nAPI_TOKEN=end_secret`,
  );
});

test('unknown format keys resolve to null', () => {
  assert.equal(endpointFormatByKey('pg', 'nope'), null);
});

test('the pg TCP format copies the broker-supplied second address verbatim', () => {
  const c = conn('pg', 'prod-db');
  const tcp = endpointFormatByKey('pg', 'tcp');
  // Marked so the click handler reads the address back from the broker: the
  // pinned port lives there, not in the connection summary.
  assert.equal(tcp?.needsAltAddress, true);
  const url = 'postgresql://app:end_abc@127.0.0.1:54329/app_production?sslmode=disable';
  assert.equal(tcp?.build(c, url), url);
});

// The same flag list exists in Rust (`capability::ssh::SSH_BROKER_OPTIONS`),
// which the CLI hint and the endpoint example both read. Two lists in two
// languages drift, and the failure mode is silent: a user pasting the UI's
// snippet gets a login the broker never mediated. Compare them.
test('the emitted ssh options match the broker\'s list', async () => {
  const source = await readFile(
    new URL('../../crates/aka-core/src/capability/ssh.rs', import.meta.url),
    'utf8',
  );
  const block = source.match(
    /pub const SSH_BROKER_OPTIONS: &\[&str\] = &\[([\s\S]*?)\];/,
  );
  assert.ok(block, 'SSH_BROKER_OPTIONS not found in capability/ssh.rs');
  const fromRust = [...block[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual([...SSH_BROKER_OPTIONS], fromRust);
});
