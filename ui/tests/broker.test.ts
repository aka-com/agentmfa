import test from 'node:test';
import assert from 'node:assert/strict';

import {
  LOCAL_BROKER,
  brokerLabel,
  brokerTakeover,
  brokerTone,
  remoteFeatureNote,
} from '../src/broker';
import type { BrokerProfile } from '../src/types';

function remote(overrides: Partial<BrokerProfile> = {}): BrokerProfile {
  return {
    mode: 'remote',
    url: 'https://broker.example.dev',
    connected: true,
    error: null,
    has_saved_token: true,
    ...overrides,
  };
}

test('the switcher labels local mode and remote hosts', () => {
  assert.equal(brokerLabel(LOCAL_BROKER), 'This Mac');
  assert.equal(brokerLabel(remote()), 'broker.example.dev');
  assert.equal(brokerLabel(remote({ url: 'http://10.0.1.5:4780' })), '10.0.1.5:4780');
  // An unparseable URL falls back to the raw value rather than throwing.
  assert.equal(brokerLabel(remote({ url: 'not a url' })), 'not a url');
  assert.equal(brokerLabel(remote({ url: null })), 'Remote broker');
});

test('the status dot follows the link state', () => {
  assert.equal(brokerTone(LOCAL_BROKER), 'local');
  assert.equal(brokerTone(remote()), 'ok');
  assert.equal(brokerTone(remote({ connected: false })), 'pending');
  assert.equal(brokerTone(remote({ connected: false, error: 'refused' })), 'error');
});

test('the takeover pane renders exactly when the remote link is unusable', () => {
  // Local mode and a healthy remote link: normal tabs.
  assert.equal(brokerTakeover(LOCAL_BROKER, false), null);
  assert.equal(brokerTakeover(remote(), false), null);
  // The user opened the configuration form (from any mode).
  assert.equal(brokerTakeover(LOCAL_BROKER, true), 'setup');
  assert.equal(brokerTakeover(remote(), true), 'setup');
  // Remote without a saved token: nothing to retry — configure.
  assert.equal(
    brokerTakeover(remote({ connected: false, has_saved_token: false }), false),
    'setup',
  );
  // Saved token, no verdict yet: connecting; with an error: the error pane.
  assert.equal(brokerTakeover(remote({ connected: false }), false), 'connecting');
  assert.equal(
    brokerTakeover(remote({ connected: false, error: 'connection refused' }), false),
    'error',
  );
});

test('remote-only feature notes gate OAuth and endpoints', () => {
  assert.equal(remoteFeatureNote(LOCAL_BROKER, 'oauth'), null);
  assert.equal(remoteFeatureNote(LOCAL_BROKER, 'endpoints'), null);
  assert.match(remoteFeatureNote(remote(), 'oauth') ?? '', /paste a token/);
  assert.match(remoteFeatureNote(remote(), 'endpoints') ?? '', /Direct endpoints/);
});
