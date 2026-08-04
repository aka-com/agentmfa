import assert from 'node:assert/strict';
import test from 'node:test';
import { invoke } from '../src/mock-bridge';

test('the credential mock validates a compound edit before renaming', async () => {
  const before = await invoke('list_secrets');
  const password = before.find((secret) => secret.site === 'x.com');
  assert.ok(password);

  await assert.rejects(invoke('edit_secret', {
    id: password.id,
    newName: 'RENAMED_ANYWAY',
    newSite: 'not a host',
  }));

  const after = await invoke('list_secrets');
  assert.equal(after.find((secret) => secret.id === password.id)?.name, password.name);
});

test('the credential mock shares canonical sites and TOTP limits with the broker', async () => {
  await invoke('add_secret', {
    kind: 'password',
    site: 'http://WWW.Example.com:443/login',
    value: 'password',
  });
  const secrets = await invoke('list_secrets');
  assert.ok(secrets.some((secret) => secret.site === 'example.com'));

  await assert.rejects(invoke('add_secret', {
    kind: 'password',
    site: 'short-seed.example',
    value: 'password',
    totp: 'GEZD',
  }));
  const after = await invoke('list_secrets');
  assert.equal(after.some((secret) => secret.site === 'short-seed.example'), false);
});
