import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('the standalone browser mock stays behind the development boundary', async () => {
  const bridge = await readFile(new URL('../src/bridge.ts', import.meta.url), 'utf8');

  assert.match(bridge, /if \(!import\.meta\.env\.DEV\)/);
  assert.match(bridge, /return import\('\.\/mock-bridge'\)/);
  assert.doesNotMatch(bridge, /MOCK_ENDPOINT_SECRET|MOCK_ACTIVITY_LIMIT|mockInvoke/);
});
