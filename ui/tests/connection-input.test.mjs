import test from 'node:test';
import assert from 'node:assert/strict';

import {
  apiOriginFromParts,
  authTemplate,
  parseConnectionImport,
  parseApiOrigin,
  portForTypeSwitch,
  suggestedSecretName,
} from '../src/connection-input.mjs';

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
  assert.equal(imported.type, 'pg');
  assert.deepEqual(imported.fields, {
    host: 'db.example.com', port: 6543, user: 'app@worker',
    dbname: 'app prod', sslmode: 'verify-full',
  });
  assert.equal(imported.credential, 'p@ss/word');
  assert.equal(JSON.stringify(imported.fields).includes('p@ss/word'), false);
});

test('imports API and WebSocket URLs', () => {
  const api = parseConnectionImport('https://api.example.com/v1/items?limit=1');
  assert.deepEqual(api.fields, { origin: 'https://api.example.com' });
  assert.match(api.warnings[0], /Only the API origin/);
  const ws = parseConnectionImport('wss://stream.example.com/feed');
  assert.deepEqual(ws.fields, { url: 'wss://stream.example.com/feed' });
});

test('imports common SSH commands but rejects shell operators', () => {
  const ssh = parseConnectionImport('ssh -i ~/.ssh/deploy -p 2222 deploy@prod.example.com');
  assert.deepEqual(ssh.fields, {
    host: 'prod.example.com', port: 2222, user: 'deploy', hostKeyFingerprint: '',
  });
  assert.match(ssh.warnings.join(' '), /not read automatically/);
  assert.throws(() => parseConnectionImport('ssh prod; rm -rf /'), /without shell operators/);
});

test('builds transparent templates for common authentication recipes', () => {
  assert.equal(authTemplate('api', 'bearer', 'GITHUB_TOKEN'), 'Authorization: Bearer {{GITHUB_TOKEN}}');
  assert.equal(authTemplate('api', 'header', 'API_KEY', 'X-API-Key'), 'X-API-Key: {{API_KEY}}');
  assert.equal(authTemplate('api', 'query', 'API_KEY', 'token'), '?token={{url(API_KEY)}}');
  assert.throws(() => authTemplate('api', 'header', 'API_KEY', 'Bad Header'), /valid HTTP header/);
  assert.equal(suggestedSecretName('prod-db', 'pg'), 'PROD_DB_PASSWORD');
  assert.equal(suggestedSecretName('deploy ssh', 'ssh'), 'DEPLOY_SSH_SSH_KEY');
});
