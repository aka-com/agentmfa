import assert from 'node:assert/strict';
import test from 'node:test';
import { UiStore } from '../src/ui-store';

test('the UI store owns state and publishes monotonic revisions', () => {
  const store = new UiStore({ tab: 'connections' });
  const seen: number[] = [];
  const unsubscribe = store.subscribe(() => seen.push(store.getSnapshot()));

  store.state.tab = 'activity';
  store.publish();
  store.publish();
  unsubscribe();
  store.publish();

  assert.equal(store.state.tab, 'activity');
  assert.deepEqual(seen, [1, 2]);
  assert.equal(store.getSnapshot(), 3);
});
