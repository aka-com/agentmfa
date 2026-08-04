import assert from 'node:assert/strict';
import test from 'node:test';
import {
  onePasswordAliasError,
  onePasswordFieldKey,
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
    onePasswordSelectionKey({ id: 'vault-1', title: 'Work' }, item, field),
    'vault-1:item-1:oauth:credential',
  );
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
