import test from 'node:test';
import assert from 'node:assert/strict';

import {
  formErrorKind, formErrorMessage, inlineFormError, sentenceCase,
} from '../src/form-errors';

test('routes validation and conflict failures to their fields', () => {
  assert.deepEqual(inlineFormError({
    kind: 'conflict', code: 'connection_name_taken', field: 'name',
    message: 'That service name is already in use',
  }), { field: 'name', message: 'That service name is already in use' });
  assert.deepEqual(inlineFormError(JSON.stringify({
    kind: 'validation', code: 'invalid_connection_field', field: 'hostKeyFingerprint',
    message: 'enter an OpenSSH fingerprint',
  })), { field: 'hostKeyFingerprint', message: 'Enter an OpenSSH fingerprint' });
});

test('keeps cancellation and system failures global', () => {
  const cancelled = { kind: 'cancelled', code: 'not_confirmed', message: 'Nothing was saved' };
  assert.equal(inlineFormError(cancelled), null);
  assert.equal(formErrorKind(cancelled), 'cancelled');
  assert.equal(formErrorMessage(cancelled), 'Nothing was saved');
  assert.equal(formErrorMessage(new Error('legacy failure')), 'Legacy failure');
});

test('capitalizes complete user-facing error messages', () => {
  assert.equal(sentenceCase('the server did not answer'), 'The server did not answer');
  assert.equal(sentenceCase('Already capitalized'), 'Already capitalized');
  assert.equal(sentenceCase(''), '');
});
