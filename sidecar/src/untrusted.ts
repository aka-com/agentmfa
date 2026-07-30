// Display-safe boundaries for text supplied by an upstream MCP server.
//
// This does not make third-party content trustworthy. It makes provenance
// explicit, prevents invisible Unicode formatting from rewriting what an
// agent sees, and bounds how much one upstream can inject into context.

export const UNTRUSTED_BEGIN = '[BEGIN UNTRUSTED UPSTREAM MCP CONTENT]';
export const UNTRUSTED_END = '[END UNTRUSTED UPSTREAM MCP CONTENT]';

const unsafeUnicode = /[\p{Cc}\p{Cf}\u115f\u1160\u17b4\u17b5\u3164\uffa0]/u;

// Upstream text that itself contains the frame delimiters could otherwise
// close the untrusted region early and present attacker text as if it were
// AgentMFA's own contract. Neutralize any occurrence (case-insensitive,
// whitespace-tolerant) so the only real delimiters are the ones
// `frameUntrustedText` adds. The replacement uses guillemets, not brackets,
// so it can never re-match.
const delimiterEcho =
  /\[\s*(?:BEGIN|END)\s+UNTRUSTED\s+UPSTREAM\s+MCP\s+CONTENT\s*\]/giu;
function neutralizeDelimiters(text: string): string {
  return text.replace(delimiterEcho, '‹elided upstream boundary marker›');
}

export interface SanitizedText {
  text: string;
  truncated: boolean;
  consumed: number;
}

/** Strip invisible/control formatting and cap by Unicode code point count. */
export function sanitizeUntrustedText(value: string, limit: number): SanitizedText {
  let text = '';
  let count = 0;
  let truncated = false;
  for (const character of value) {
    if (count >= limit) {
      truncated = true;
      break;
    }
    text += character === '\n' || character === '\t'
      ? character
      : unsafeUnicode.test(character)
        ? '\ufffd'
        : character;
    count++;
  }
  text = neutralizeDelimiters(text);
  if (truncated) text += '…';
  return { text, truncated, consumed: count };
}

/** Fixed delimiters keep upstream prose visually separate from our contract. */
export function frameUntrustedText(value: string, limit: number): SanitizedText {
  const sanitized = sanitizeUntrustedText(value, limit);
  return {
    text: `${UNTRUSTED_BEGIN}\n${sanitized.text}\n${UNTRUSTED_END}`,
    truncated: sanitized.truncated,
    consumed: sanitized.consumed,
  };
}

/**
 * Sanitize textual fields in an MCP tool result and mark their provenance.
 * A single shared budget prevents an upstream from multiplying the per-field
 * cap across thousands of content blocks.
 */
export function sanitizeUpstreamResult(value: unknown, limit = 128 * 1024): unknown {
  if (!value || typeof value !== 'object') {
    return {
      isError: true,
      content: [{ type: 'text', text: frameUntrustedText(String(value), limit).text }],
    };
  }

  const result = value as {
    content?: unknown;
    contents?: unknown;
    structuredContent?: unknown;
    _meta?: Record<string, unknown>;
  };
  let remaining = limit;
  let truncated = false;
  let exhaustedNoticeAdded = false;
  const sanitizeItems = (items: unknown[], requireTextType: boolean): unknown[] => {
    const sanitizedItems: unknown[] = [];
    for (const rawItem of items) {
        if (!rawItem || typeof rawItem !== 'object') {
          sanitizedItems.push(rawItem);
          continue;
        }
        const item = rawItem as Record<string, unknown>;
        if ((requireTextType && item.type !== 'text') || typeof item.text !== 'string') {
          sanitizedItems.push(item);
          continue;
        }
        if (remaining === 0) {
          truncated = true;
          if (!exhaustedNoticeAdded) {
            sanitizedItems.push({
              ...item,
              text: frameUntrustedText('[additional upstream text truncated]', 64).text,
            });
            exhaustedNoticeAdded = true;
          }
          continue;
        }
        const sanitized = frameUntrustedText(item.text, remaining);
        remaining -= sanitized.consumed;
        truncated ||= sanitized.truncated;
        sanitizedItems.push({ ...item, text: sanitized.text });
      }
    return sanitizedItems;
  };
  const content = Array.isArray(result.content)
    ? sanitizeItems(result.content, true)
    : result.content;
  const contents = Array.isArray(result.contents)
    ? sanitizeItems(result.contents, false)
    : result.contents;

  let structuredContent = result.structuredContent;
  if (structuredContent !== undefined) {
    const serialized = JSON.stringify(structuredContent);
    const sanitized = sanitizeUntrustedText(serialized, Math.min(remaining, 32 * 1024));
    remaining -= sanitized.consumed;
    truncated ||= sanitized.truncated;
    try {
      structuredContent = JSON.parse(sanitized.text);
    } catch {
      structuredContent = {
        agentmfa_notice: 'Upstream structured content was truncated',
        preview: sanitized.text,
      };
    }
  }

  return {
    ...result,
    ...(content === undefined ? {} : { content }),
    ...(contents === undefined ? {} : { contents }),
    ...(structuredContent === undefined ? {} : { structuredContent }),
    _meta: {
      ...(result._meta ?? {}),
      agentmfa: {
        ...(result._meta?.agentmfa &&
        typeof result._meta.agentmfa === 'object' &&
        !Array.isArray(result._meta.agentmfa)
          ? result._meta.agentmfa
          : {}),
        provenance: 'untrusted upstream MCP content',
        text_truncated: truncated,
      },
    },
  };
}
