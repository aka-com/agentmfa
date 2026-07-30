import assert from 'node:assert/strict';
import test from 'node:test';

// bridge.ts selects the window shell at module evaluation time. This test
// imports only the state/query layer, but supplies the same location surface
// that a browser would before loading it.
Object.defineProperty(globalThis, 'location', {
  configurable: true,
  value: { hash: '' },
});

test('query-backed state follows the active broker scope', async () => {
  const { state } = await import('../src/app-state');
  const {
    getBrokerQueryData,
    queryClient,
    removeBrokerQueries,
  } = await import('../src/query-client');
  const localBroker = state.broker;
  const remoteBroker = {
    ...localBroker,
    mode: 'remote' as const,
    url: 'https://broker.example.test',
  };

  try {
    const localConnections: typeof state.connections = [];
    state.connections = localConnections;
    assert.equal(
      getBrokerQueryData(localBroker, 'list_connections'),
      localConnections,
    );

    const localSettings = {
      ...state.settings,
      presence_window_secs: 60 * 60,
    };
    state.settings = localSettings;
    assert.equal(getBrokerQueryData(localBroker, 'get_settings'), localSettings);

    state.broker = remoteBroker;
    assert.deepEqual(state.connections, []);
    assert.notEqual(state.settings, localSettings);

    const remoteConnections: typeof state.connections = [];
    state.connections = remoteConnections;
    assert.equal(
      getBrokerQueryData(remoteBroker, 'list_connections'),
      remoteConnections,
    );

    state.broker = localBroker;
    assert.equal(state.connections, localConnections);
    assert.equal(state.settings, localSettings);

    removeBrokerQueries(localBroker);
    assert.deepEqual(state.connections, []);
    assert.notEqual(state.connections, localConnections);
    assert.notEqual(state.settings, localSettings);
  } finally {
    state.broker = localBroker;
    queryClient.clear();
  }
});
