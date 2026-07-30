import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { relayHeaderValue, relayMessages } from '../src/upstream-mcp';

test('the sidecar consumes the shared broker relay envelope', () => {
  const fixture = JSON.parse(
    readFileSync(new URL('../../fixtures/mcp-http-relay.json', import.meta.url), 'utf8'),
  ) as {
    headers: Record<string, string>;
    body: string;
    body_encoding: string;
  };

  assert.equal(relayHeaderValue(fixture.headers, 'MCP-Session-Id'), 'golden-session');
  assert.deepEqual(relayMessages(fixture), [JSON.parse(fixture.body)]);
});

test('SSE relay accepts optional spaces, continuations, CRLF, and comments', () => {
  const response = relayMessages({
    body:
      ': keepalive\r\n' +
      'event: message\r\n' +
      'data:{"jsonrpc":"2.0",\r\n' +
      'data: "id":7,"result":{"ok":true}}\r\n' +
      '\r\n' +
      'data: {"jsonrpc":"2.0","method":"notifications/message"}\n\n',
  });
  assert.deepEqual(response, [
    { jsonrpc: '2.0', id: 7, result: { ok: true } },
    { jsonrpc: '2.0', method: 'notifications/message' },
  ]);
});
