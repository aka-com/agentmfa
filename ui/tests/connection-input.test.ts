import test from 'node:test';
import assert from 'node:assert/strict';

import {
  apiOriginFromParts,
  authTemplate,
  firstTaskPrompt,
  parseConnectionImport,
  parseApiOrigin,
  portForTypeSwitch,
  quickSetupPlaceholder,
  shouldResolveSshImport,
  sshImportFromPreview,
  suggestedSecretName,
} from '../src/connection-input';

test('provides task-first examples for every connection type', () => {
  assert.equal(quickSetupPlaceholder('pg'), 'postgresql://app@db.example.com/production');
  assert.equal(quickSetupPlaceholder('ssh'), 'ssh deploy@prod.example.com');
  assert.match(firstTaskPrompt('prod-db', 'pg'), /SELECT current_database\(\)/);
  assert.match(firstTaskPrompt('prod-ssh', 'ssh'), /uname -a/);
});

test('API origins preserve scheme and custom port', () => {
  assert.deepEqual(parseApiOrigin('http://localhost:8080'), {
    scheme: 'http', host: 'localhost', port: 8080,
  });
  assert.equal(apiOriginFromParts('http', 'localhost', 8080), 'http://localhost:8080');
});

test('API origins reject paths and embedded credentials', () => {
  assert.throws(() => parseApiOrigin('https://api.example.com/v1'), /cannot contain a path/);
  assert.throws(() => parseApiOrigin('https://token@api.example.com'), /must not contain credentials/);
});

test('switching PG and SSH only replaces a carried default port', () => {
  assert.equal(portForTypeSwitch('pg', 'ssh', '5432'), '22');
  assert.equal(portForTypeSwitch('ssh', 'pg', '22'), '5432');
  assert.equal(portForTypeSwitch('pg', 'ssh', '6543'), '6543');
});

test('imports a percent-encoded Postgres DSN without putting its password in fields', () => {
  const imported = parseConnectionImport(
    'DATABASE_URL="postgresql://app%40worker:p%40ss%2Fword@db.example.com:6543/app%20prod?sslmode=verify-full"',
  );
  if (imported.type !== 'pg') assert.fail('expected a Postgres import');
  assert.equal(imported.type, 'pg');
  assert.deepEqual(imported.fields, {
    host: 'db.example.com', port: 6543, user: 'app@worker',
    dbname: 'app prod', sslmode: 'verify-full', pgCaBundlePath: null,
  });
  assert.equal(imported.credential, 'p@ss/word');
  assert.equal(JSON.stringify(imported.fields).includes('p@ss/word'), false);
});

test('Postgres imports default to verified TLS and keep a private CA path', () => {
  const imported = parseConnectionImport(
    'postgresql://app@db.example.com/app?sslrootcert=%2Fetc%2Fcompany-ca.pem',
  );
  if (imported.type !== 'pg') assert.fail('expected a Postgres import');
  assert.equal(imported.fields.sslmode, 'verify-full');
  assert.equal(imported.fields.pgCaBundlePath, '/etc/company-ca.pem');
});

test('imports API and WebSocket URLs', () => {
  const api = parseConnectionImport('https://api.example.com/v1/items?limit=1');
  assert.deepEqual(api.fields, { origin: 'https://api.example.com' });
  assert.match(api.warnings[0], /Only the API origin/);
  const ws = parseConnectionImport('wss://stream.example.com/feed');
  assert.deepEqual(ws.fields, { url: 'wss://stream.example.com/feed' });
});

test('does not suggest connection names for IPv4 or IPv6 targets', () => {
  const postgres = parseConnectionImport('postgresql://app@192.0.2.10/production');
  assert.equal(postgres.name, '');

  const api = parseConnectionImport('https://[2001:db8::10]/');
  assert.equal(api.name, '');

  const ssh = sshImportFromPreview({
    importId: 'preview-ip', destination: '2001:db8::20', host: '2001:db8::20',
    port: 22, user: 'deploy',
  });
  assert.equal(ssh.name, '');
});

test('imports common SSH commands but rejects shell operators', () => {
  const ssh = parseConnectionImport('ssh -i ~/.ssh/deploy -p 2222 deploy@prod.example.com');
  if (ssh.type !== 'ssh') assert.fail('expected an SSH import');
  assert.deepEqual(ssh.fields, {
    host: 'prod.example.com', port: 2222, user: 'deploy', hostKeyFingerprint: '',
  });
  assert.match(ssh.warnings.join(' '), /not read automatically/);
  assert.throws(() => parseConnectionImport('ssh prod; rm -rf /'), /without shell operators/);
});

test('maps trusted SSH previews without including private key contents', () => {
  assert.equal(shouldResolveSshImport('ssh prod'), true);
  assert.equal(shouldResolveSshImport('deploy@prod'), true);
  assert.equal(shouldResolveSshImport('https://api.example.com'), false);
  const imported = sshImportFromPreview({
    importId: 'preview-1', destination: 'prod', host: 'prod.example.com', port: 2222,
    user: 'deploy', proxyJump: 'bastion', identityFiles: ['/Users/me/.ssh/deploy'],
    hostKeyCandidates: [{ fingerprint: 'SHA256:abc', algorithm: 'ssh-ed25519', source: 'known_hosts' }],
    warnings: ['This destination connects through ProxyJump bastion.'],
  });
  if (imported.type !== 'ssh') assert.fail('expected an SSH import');
  assert.equal(imported.fields.destination, 'prod');
  assert.equal(imported.fields.identityFile, '/Users/me/.ssh/deploy');
  assert.equal(imported.fields.hostKeyFingerprint, 'SHA256:abc');
  assert.equal(JSON.stringify(imported).includes('PRIVATE KEY'), false);
});

test('builds transparent templates for common authentication recipes', () => {
  assert.equal(authTemplate('api', 'bearer', 'GITHUB_TOKEN'), 'Authorization: Bearer {{GITHUB_TOKEN}}');
  assert.equal(authTemplate('api', 'header', 'API_KEY', 'X-API-Key'), 'X-API-Key: {{API_KEY}}');
  assert.equal(authTemplate('api', 'query', 'API_KEY', 'token'), '?token={{url(API_KEY)}}');
  assert.throws(() => authTemplate('api', 'header', 'API_KEY', 'Bad Header'), /valid HTTP header/);
  assert.equal(suggestedSecretName('prod-db', 'pg'), 'PROD_DB_PASSWORD');
  assert.equal(suggestedSecretName('deploy ssh', 'ssh'), 'DEPLOY_SSH_SSH_KEY');
});
