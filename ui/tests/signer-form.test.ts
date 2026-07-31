import test from 'node:test';
import assert from 'node:assert/strict';

import { invoke } from '../src/mock-bridge';
import type { ConnectionInput, ConnectionSummary } from '../src/types';

// The mock bridge mirrors the core's signer semantics so the form can be
// exercised without a broker: the four required parts are all-or-nothing,
// the signer's references are the bound credentials, and an omitted signer
// survives a non-retargeting edit but not a retarget
// (`inherit_signer_and_mtls` in crates/aka-core/src/store.rs).

const signerInput: ConnectionInput = {
  name: 'aws-s3',
  type: 'api',
  host: 's3.eu-west-1.amazonaws.com',
  scheme: 'https',
  template: '',
  signer_region: 'eu-west-1',
  signer_service: 's3',
  signer_access_key_ref: 'AWS_ACCESS_KEY_ID',
  signer_secret_key_ref: 'AWS_SECRET_ACCESS_KEY',
  client_cert_path: '/etc/pki/client.pem',
  client_key_path: '/etc/pki/client-key.pem',
};

async function connection(name: string): Promise<ConnectionSummary> {
  const listed = await invoke('list_connections', undefined);
  const found = (listed as ConnectionSummary[]).find((c) => c.name === name);
  assert.ok(found, `${name} is listed`);
  return found;
}

test('a signer connection round-trips through the mock bridge', async () => {
  await invoke('add_connection', { input: signerInput });
  const c = await connection('aws-s3');
  assert.equal(c.signer?.algorithm, 'aws_sigv4');
  assert.equal(c.signer?.region, 'eu-west-1');
  assert.equal(c.signer?.service, 's3');
  assert.deepEqual(c.secret_names, ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']);
  assert.equal(c.client_cert_path, '/etc/pki/client.pem');
  assert.equal(c.client_key_path, '/etc/pki/client-key.pem');

  // A non-retargeting edit that omits the signer keeps it.
  await invoke('edit_connection', {
    id: c.id,
    expectedUpdatedAt: c.updated_at,
    input: { ...signerInput, name: 'aws-s3-renamed', signer_region: undefined,
      signer_service: undefined, signer_access_key_ref: undefined,
      signer_secret_key_ref: undefined },
  });
  const renamed = await connection('aws-s3-renamed');
  assert.equal(renamed.signer?.region, 'eu-west-1');

  // A retargeting edit drops it.
  await invoke('edit_connection', {
    id: renamed.id,
    expectedUpdatedAt: renamed.updated_at,
    input: { ...signerInput, name: 'aws-s3-renamed', host: 'sts.amazonaws.com',
      signer_region: undefined, signer_service: undefined,
      signer_access_key_ref: undefined, signer_secret_key_ref: undefined,
      client_cert_path: undefined, client_key_path: undefined },
  });
  const retargeted = await connection('aws-s3-renamed');
  assert.equal(retargeted.signer, null);
});

test('a partial signer quartet builds no signer at all', async () => {
  await invoke('add_connection', {
    input: { ...signerInput, name: 'aws-partial', signer_secret_key_ref: undefined,
      client_cert_path: undefined, client_key_path: undefined },
  });
  const c = await connection('aws-partial');
  assert.equal(c.signer, null);
});
