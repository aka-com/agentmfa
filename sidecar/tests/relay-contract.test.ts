import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { relayHeaderValue, relayMessages, UpstreamFrameParser } from '../src/upstream-mcp';

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

test('the streaming parser emits notifications as they complete, not at the end', () => {
  const parser = new UpstreamFrameParser();

  // A frame split across transport chunks is not a frame yet.
  assert.deepEqual(parser.push('event: message\ndata: {"jsonrpc":"2.0",'), []);
  assert.deepEqual(
    parser.push('"method":"notifications/progress","params":{"progress":3}}\n\n'),
    [{ method: 'notifications/progress', params: { progress: 3 } }],
  );

  // The response frame is not a notification: it carries an id, and the
  // caller reads it from the assembled body rather than from here.
  assert.deepEqual(
    parser.push('data: {"jsonrpc":"2.0","id":7,"result":{"ok":true}}\n\n'),
    [],
  );

  // Nor is a server→client *request*: this transport cannot answer one, and
  // forwarding it would claim otherwise.
  assert.deepEqual(
    parser.push('data: {"jsonrpc":"2.0","id":8,"method":"sampling/createMessage"}\n\n'),
    [],
  );
});

test('the streaming parser survives CRLF, comments, and non-JSON events', () => {
  const parser = new UpstreamFrameParser();
  assert.deepEqual(
    parser.push(
      ': keepalive\r\n\r\n' +
        'event: ping\r\n\r\n' +
        'data: not json\r\n\r\n' +
        'data: {"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}\r\n\r\n',
    ),
    [{ method: 'notifications/message', params: { level: 'info' } }],
  );
});

test('a plain-JSON body never yields an early frame', () => {
  // No SSE boundary short of the end, so nothing is emitted before the answer
  // — which is right, because such a body *is* the answer.
  const parser = new UpstreamFrameParser();
  assert.deepEqual(parser.push('{"jsonrpc":"2.0","id":1,"result":{}}'), []);
});
