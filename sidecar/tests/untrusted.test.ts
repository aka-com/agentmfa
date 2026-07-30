import test from 'node:test';
import assert from 'node:assert/strict';

import {
  UNTRUSTED_BEGIN,
  UNTRUSTED_END,
  frameUntrustedText,
  sanitizeUntrustedText,
  sanitizeUpstreamResult,
} from '../src/untrusted';

test('upstream text strips control, format, tag, and filler characters', () => {
  const value = 'safe\u0007\u202e\u200b\u3164\u{e0001}text\n\tkept';
  assert.equal(
    sanitizeUntrustedText(value, 100).text,
    'safe\ufffd\ufffd\ufffd\ufffd\ufffdtext\n\tkept',
  );
});

test('upstream descriptions are capped inside fixed provenance markers', () => {
  const framed = frameUntrustedText('abcdef', 3);
  assert.equal(framed.truncated, true);
  assert.equal(framed.text, `${UNTRUSTED_BEGIN}\nabc…\n${UNTRUSTED_END}`);
});

test('tool result text shares one cap and carries provenance metadata', () => {
  const result = sanitizeUpstreamResult({
    content: [
      { type: 'text', text: 'abc\u200bdef' },
      { type: 'text', text: 'second block' },
    ],
    structuredContent: { note: 'safe\u202etext' },
  }, 8) as {
    content: Array<{ text: string }>;
    structuredContent: unknown;
    _meta: { agentmfa: { provenance: string; text_truncated: boolean } };
  };
  assert.equal(
    result.content[0].text,
    `${UNTRUSTED_BEGIN}\nabc\ufffddef\n${UNTRUSTED_END}`,
  );
  assert.match(result.content[1].text, /s…/);
  assert.equal(result._meta.agentmfa.provenance, 'untrusted upstream MCP content');
  assert.equal(result._meta.agentmfa.text_truncated, true);
});
