import assert from 'node:assert/strict';
import test from 'node:test';
import { brokerScopeKey, sameBrokerScope } from '../src/broker-scope';

test('broker query scopes distinguish remote brokers by URL', () => {
  const remoteA = { mode: 'remote' as const, url: 'https://a.example' };
  const remoteB = { mode: 'remote' as const, url: 'https://b.example' };

  assert.equal(sameBrokerScope(remoteA, remoteA), true);
  assert.equal(sameBrokerScope(remoteA, remoteB), false);
  assert.deepEqual(brokerScopeKey(remoteA), ['remote', 'https://a.example']);
});

test('local brokers with null URLs share one scope', () => {
  assert.equal(
    sameBrokerScope(
      { mode: 'local', url: null },
      { mode: 'local', url: null },
    ),
    true,
  );
});
