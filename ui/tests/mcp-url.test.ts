import test from 'node:test';
import assert from 'node:assert/strict';

import { parseMcpServerUrl } from '../src/connection-input';

test('a server URL splits into a pinned origin and an MCP path', () => {
  assert.deepEqual(parseMcpServerUrl('https://mcp.notion.com/mcp'), {
    scheme: 'https', host: 'mcp.notion.com', port: null, mcpPath: '/mcp',
  });
});

test('a bare origin defaults to the conventional /mcp path', () => {
  assert.deepEqual(parseMcpServerUrl('https://example.com'), {
    scheme: 'https', host: 'example.com', port: null, mcpPath: '/mcp',
  });
});

test('a port and a nested path both survive', () => {
  assert.deepEqual(parseMcpServerUrl('http://127.0.0.1:8080/api/mcp/'), {
    scheme: 'http', host: '127.0.0.1', port: 8080, mcpPath: '/api/mcp',
  });
});

test('credentials in the URL are refused rather than stored', () => {
  assert.throws(() => parseMcpServerUrl('https://user:pw@example.com/mcp'), /credentials/);
});

test('a non-HTTP scheme is refused', () => {
  assert.throws(() => parseMcpServerUrl('ws://example.com/mcp'), /https?:\/\//);
});
