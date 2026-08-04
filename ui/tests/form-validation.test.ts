import assert from 'node:assert/strict';
import test from 'node:test';
import {
  normalizedSitePreview,
  retargetsIssuedEndpoint,
  validateConnectionForm,
  validateSecretForm,
} from '../src/form-validation';

const validApi = {
  adding: false,
  type: 'api' as const,
  name: 'GitHub',
  user: '',
  oauthClientRequired: false,
  needsCredentialChoice: false,
  secretSource: 'none' as const,
  selectedSecretPresent: false,
  hasImportedIdentity: false,
  advancedTemplateRequired: false,
  injectionTemplate: '',
  editingTemplateRequired: false,
};

test('secret validation distinguishes adds from untouched and replaced edits', () => {
  assert.deepEqual(validateSecretForm({
    adding: true, name: '', value: '', valueModified: false,
  }), {
    name: 'Name is required',
    value: 'Value is required',
  });
  assert.deepEqual(validateSecretForm({
    adding: false, name: 'TOKEN', value: '', valueModified: false,
  }), {});
  assert.deepEqual(validateSecretForm({
    adding: false, name: 'TOKEN', value: '', valueModified: true,
  }), { value: 'Invalid value' });
});

test('password site previews mirror the broker canonical form', () => {
  assert.equal(normalizedSitePreview('https://WWW.Example.com/login'), 'example.com');
  assert.equal(normalizedSitePreview('www.com'), 'www.com');
  assert.equal(normalizedSitePreview('http://Example.com:8080/path'), 'example.com:8080');
  assert.equal(normalizedSitePreview('http://example.com:443'), 'example.com');
  assert.equal(normalizedSitePreview('example.com:80'), 'example.com');
  assert.equal(normalizedSitePreview('example.com.'), 'example.com');
  assert.equal(normalizedSitePreview('ftp://example.com'), null);
  assert.equal(normalizedSitePreview('https://user@example.com'), null);
  for (const input of [
    'http://example.com:443',
    'https://www.x.com/login',
    'x.com:8443',
    'example.com.',
  ]) {
    const stored = normalizedSitePreview(input);
    assert.ok(stored);
    assert.equal(normalizedSitePreview(stored), stored, input);
  }
});

test('credential-less API edits do not invent a template requirement', () => {
  assert.deepEqual(validateConnectionForm(validApi).errors, {});
  assert.equal(validateConnectionForm({
    ...validApi,
    editingTemplateRequired: true,
  }).errors.template, 'Credential template is required');
  assert.equal(validateConnectionForm({
    ...validApi,
    advancedTemplateRequired: true,
  }).errors.template, 'Credential template is required');
});

test('database, SSH, credential, and OAuth validation share one pure matrix', () => {
  const pg = validateConnectionForm({
    ...validApi,
    adding: true,
    type: 'pg',
    host: '',
    port: '70000',
    dbname: '',
    user: '',
    needsCredentialChoice: true,
    secretSource: 'new',
    newSecretName: '9 invalid',
    newSecretValue: '',
  });
  assert.deepEqual(Object.keys(pg.errors).sort(), [
    'dbname', 'host', 'newSecretName', 'newSecretValue', 'port', 'user',
  ]);

  const oauth = validateConnectionForm({
    ...validApi,
    adding: true,
    oauthClientRequired: true,
    oauthClientId: '',
    oauthUrls: { auth: 'http://auth.example', token: '' },
  });
  assert.deepEqual(Object.keys(oauth.errors).sort(), [
    'oauthAuthUrl', 'oauthClientId', 'oauthTokenUrl',
  ]);
});

test('endpoint retarget detection covers address-defining fields only', () => {
  const pg = {
    type: 'pg' as const,
    host: 'db.example',
    port: 5432,
    dbname: 'app',
    user: 'deploy',
  };
  assert.equal(retargetsIssuedEndpoint(pg, { ...pg }), false);
  assert.equal(retargetsIssuedEndpoint(pg, { ...pg, dbname: 'staging' }), true);

  const ssh = {
    type: 'ssh' as const,
    destination: 'deploy@host',
    host: 'host',
    port: 22,
    user: 'deploy',
    hostKeyFingerprint: 'SHA256:old',
  };
  assert.equal(retargetsIssuedEndpoint(ssh, { ...ssh, destination: 'root@host' }), false);
  assert.equal(retargetsIssuedEndpoint(ssh, { ...ssh, hostKeyFingerprint: 'SHA256:new' }), true);

  const api = {
    type: 'api' as const,
    scheme: 'https',
    host: 'api.example',
    port: 443,
    mcpPath: '/mcp',
  };
  assert.equal(retargetsIssuedEndpoint(api, { ...api, mcpPath: '/v2/mcp' }), false);
  assert.equal(retargetsIssuedEndpoint(api, { ...api, host: 'other.example' }), true);
});
