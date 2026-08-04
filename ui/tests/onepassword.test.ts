import assert from 'node:assert/strict';
import test from 'node:test';
import {
  onePasswordAliasError,
  onePasswordAllVaultsOption,
  onePasswordFieldKey,
  onePasswordFieldIsUnsupported,
  onePasswordFieldTypeLabel,
  onePasswordSelectionKey,
  suggestedOnePasswordAlias,
} from '../src/onepassword';

const item = { id: 'item-1', title: 'Production API', category: 'login' };
const field = {
  id: 'credential',
  title: 'client secret',
  section_id: 'oauth',
  section_title: 'OAuth 2',
  field_type: 'concealed',
};

test('1Password fields have stable section-aware selection keys', () => {
  assert.equal(onePasswordFieldKey(field), 'oauth:credential');
  assert.equal(onePasswordFieldKey({ ...field, section_id: null }), ':credential');
  assert.equal(
    onePasswordSelectionKey({ id: 'vault-1', title: 'Work', item_count: 1 }, item, field),
    'vault-1:item-1:oauth:credential',
  );
});

test('1Password unsupported fields are recognized across provider spellings', () => {
  assert.equal(onePasswordFieldIsUnsupported({ ...field, field_type: 'Unsupported' }), true);
  assert.equal(onePasswordFieldIsUnsupported({ ...field, field_type: 'UNKNOWN' }), true);
  assert.equal(onePasswordFieldIsUnsupported({ ...field, field_type: 'Totp' }), false);
});

test('1Password field type labels use TOTP for OTP spellings', () => {
  assert.equal(onePasswordFieldTypeLabel('Totp'), 'TOTP');
  assert.equal(onePasswordFieldTypeLabel('totp'), 'TOTP');
  assert.equal(onePasswordFieldTypeLabel('OTP'), 'TOTP');
  assert.equal(onePasswordFieldTypeLabel('Concealed'), 'Concealed');
  assert.equal(onePasswordFieldTypeLabel('Text'), 'Text');
});

test('1Password offers aggregate browsing only for one to ten vaults', () => {
  const vaults = Array.from({ length: 10 }, (_, index) => ({
    id: `vault-${index}`,
    title: `Vault ${index}`,
    item_count: index,
  }));
  assert.equal(onePasswordAllVaultsOption([]), null);
  assert.equal(onePasswordAllVaultsOption(vaults)?.item_count, 45);
  assert.equal(onePasswordAllVaultsOption([...vaults, {
    id: 'vault-10', title: 'Vault 10', item_count: 10,
  }]), null);
});

test('1Password alias suggestions are valid and avoid existing names', () => {
  assert.equal(
    suggestedOnePasswordAlias(item, field, []),
    'PRODUCTION_API_OAUTH_2_CLIENT_SECRET',
  );
  assert.equal(
    suggestedOnePasswordAlias(item, field, ['PRODUCTION_API_OAUTH_2_CLIENT_SECRET']),
    'PRODUCTION_API_OAUTH_2_CLIENT_SECRET_2',
  );
});

test('1Password alias validation rejects invalid and occupied names', () => {
  assert.equal(onePasswordAliasError('9TOKEN', []),
    'Use letters, numbers, and underscores; start with a letter or underscore');
  assert.equal(onePasswordAliasError('TOKEN', ['token']), 'That stored name is already in use');
  assert.equal(onePasswordAliasError('_TOKEN_2', []), null);
});
