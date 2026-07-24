import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ENDPOINT_FORMATS,
  endpointFormatByKey,
  libpqKeywords,
  scpCommand,
  sftpUrl,
  sshConfigBlock,
} from '../src/endpoint-formats';
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
    host_key_fingerprint: null, destination: null, sslmode: null, url: null,
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
    ['psql', 'libpq', '.env snippet'],
  );
  assert.deepEqual(
    ENDPOINT_FORMATS.ssh.map((f) => f.label),
    ['ssh', 'scp', 'sftp', 'SSH config'],
  );
  assert.deepEqual(
    ENDPOINT_FORMATS.api.map((f) => f.label),
    ['curl', '.env snippet'],
  );
  assert.deepEqual(ENDPOINT_FORMATS.ws, []);
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

const SOCK = '/Users/me/.aka/endpoints/ep2/agent.sock';

test('ssh format reuses the runnable command over the issued socket', () => {
  const c = conn('ssh', 'Sandbox', { user: 'sandbox', host: '127.0.0.1', port: 12222 });
  assert.equal(
    endpointFormatByKey('ssh', 'ssh')?.build(c, SOCK),
    `SSH_AUTH_SOCK="${SOCK}" ssh -p 12222 sandbox@127.0.0.1`,
  );
});

test('scp mirrors the ssh destination logic with the -P flag', () => {
  const explicit = conn('ssh', 'Sandbox', { user: 'sandbox', host: '127.0.0.1', port: 12222 });
  assert.equal(
    scpCommand(SOCK, explicit),
    `SSH_AUTH_SOCK="${SOCK}" scp -P 12222 <file> sandbox@127.0.0.1:`,
  );
  const defaultPort = conn('ssh', 'Box', { user: 'deploy', host: 'box.example', port: 22 });
  assert.equal(
    scpCommand(SOCK, defaultPort),
    `SSH_AUTH_SOCK="${SOCK}" scp <file> deploy@box.example:`,
  );
  const imported = conn('ssh', 'Alias', { destination: 'myserver', port: 2200 });
  assert.equal(
    scpCommand(SOCK, imported),
    `SSH_AUTH_SOCK="${SOCK}" scp -P 2200 <file> myserver:`,
  );
});

test('sftp URL carries user and non-default port, omitting port 22', () => {
  assert.equal(
    sftpUrl(conn('ssh', 'Sandbox', { user: 'sandbox', host: '127.0.0.1', port: 12222 })),
    'sftp://sandbox@127.0.0.1:12222',
  );
  assert.equal(
    sftpUrl(conn('ssh', 'Box', { user: 'deploy', host: 'box.example', port: 22 })),
    'sftp://deploy@box.example',
  );
  assert.equal(
    sftpUrl(conn('ssh', 'Split', { destination: 'deploy@box.example' })),
    'sftp://deploy@box.example',
  );
  assert.equal(sftpUrl(conn('ssh', 'Bare', {})), null);
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
    ].join('\n'),
  );
  const plain = conn('ssh', 'Box', { user: 'deploy', host: 'box.example', port: 22 });
  assert.equal(
    sshConfigBlock(SOCK, plain),
    ['Host Box', '  HostName box.example', '  User deploy', `  IdentityAgent "${SOCK}"`].join('\n'),
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
