// Display-safe boundaries for text supplied by an upstream MCP server.
//
// This does not make third-party content trustworthy. It makes provenance
// explicit, prevents invisible Unicode formatting from rewriting what an
// agent sees, and bounds how much one upstream can inject into context.

export const UNTRUSTED_BEGIN = '[BEGIN UNTRUSTED UPSTREAM MCP CONTENT]';
export const UNTRUSTED_END = '[END UNTRUSTED UPSTREAM MCP CONTENT]';
export const MAX_UPSTREAM_RESULT_BLOCKS = 64;

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
  const result = (!value || typeof value !== 'object'
    ? {
        isError: true,
        content: [{ type: 'text', text: String(value) }],
      }
    : value) as {
    content?: unknown;
    contents?: unknown;
    structuredContent?: unknown;
    _meta?: Record<string, unknown>;
  };
  let remaining = Math.max(0, limit);
  let remainingBlocks = MAX_UPSTREAM_RESULT_BLOCKS;
  let truncated = false;
  let exhaustedNoticeAdded = false;

  const utf8Prefix = (text: string, byteLimit: number): { text: string; truncated: boolean } => {
    let prefix = '';
    let bytes = 0;
    for (const character of text) {
      const size = Buffer.byteLength(character);
      if (bytes + size > byteLimit) return { text: prefix, truncated: true };
      prefix += character;
      bytes += size;
    }
    return { text: prefix, truncated: false };
  };
  const framedWithin = (text: string, byteLimit: number): {
    text: string;
    truncated: boolean;
  } | null => {
    const clean = sanitizeUntrustedText(text, Number.MAX_SAFE_INTEGER).text;
    const frameOverhead = Buffer.byteLength(`${UNTRUSTED_BEGIN}\n\n${UNTRUSTED_END}`);
    if (byteLimit < frameOverhead) return null;
    const prefix = utf8Prefix(clean, byteLimit - frameOverhead);
    return {
      text: `${UNTRUSTED_BEGIN}\n${prefix.text}\n${UNTRUSTED_END}`,
      truncated: prefix.truncated,
    };
  };
  const addTextItem = (
    destination: unknown[],
    item: Record<string, unknown>,
    text: string,
  ): boolean => {
    const empty = { ...item, text: '' };
    const overhead = Buffer.byteLength(JSON.stringify(empty));
    const framed = framedWithin(text, Math.max(0, remaining - overhead));
    if (!framed) return false;
    const bounded = { ...item, text: framed.text };
    const bytes = Buffer.byteLength(JSON.stringify(bounded));
    if (bytes > remaining) return false;
    remaining -= bytes;
    truncated ||= framed.truncated;
    destination.push(bounded);
    return true;
  };
  const addNotice = (destination: unknown[]): void => {
    if (exhaustedNoticeAdded) return;
    if (addTextItem(
      destination,
      { type: 'text' },
      '[additional upstream content truncated]',
    )) {
      exhaustedNoticeAdded = true;
    }
  };

  const sanitizeItems = (items: unknown[], requireTextType: boolean): unknown[] => {
    const sanitizedItems: unknown[] = [];
    for (const rawItem of items) {
      if (remainingBlocks === 0) {
        truncated = true;
        addNotice(sanitizedItems);
        break;
      }
      remainingBlocks -= 1;
      if (!rawItem || typeof rawItem !== 'object') {
        const serialized = JSON.stringify(rawItem);
        const bytes = Buffer.byteLength(serialized ?? '');
        if (bytes <= remaining) {
          remaining -= bytes;
          sanitizedItems.push(rawItem);
        } else {
          truncated = true;
          addNotice(sanitizedItems);
        }
        continue;
      }
      const item = rawItem as Record<string, unknown>;
      if (!requireTextType && typeof item.text === 'string') {
        if (!addTextItem(sanitizedItems, item, item.text)) {
          truncated = true;
          addNotice(sanitizedItems);
        }
        continue;
      }
      if (requireTextType && item.type === 'text' && typeof item.text === 'string') {
        if (!addTextItem(sanitizedItems, item, item.text)) {
          truncated = true;
          addNotice(sanitizedItems);
        }
        continue;
      }

      let boundedItem = item;
      if (
        item.type === 'resource'
        && item.resource
        && typeof item.resource === 'object'
        && typeof (item.resource as Record<string, unknown>).text === 'string'
      ) {
        const resource = item.resource as Record<string, unknown>;
        const shell = { ...item, resource: { ...resource, text: '' } };
        const overhead = Buffer.byteLength(JSON.stringify(shell));
        const framed = framedWithin(
          resource.text as string,
          Math.max(0, remaining - overhead),
        );
        if (!framed) {
          truncated = true;
          addNotice(sanitizedItems);
          continue;
        }
        boundedItem = {
          ...item,
          resource: { ...resource, text: framed.text },
        };
        truncated ||= framed.truncated;
      }
      const serialized = JSON.stringify(boundedItem);
      const bytes = Buffer.byteLength(serialized);
      if (bytes <= remaining) {
        remaining -= bytes;
        sanitizedItems.push(boundedItem);
      } else {
        truncated = true;
        addNotice(sanitizedItems);
      }
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
    const sanitized = sanitizeUntrustedText(serialized, Number.MAX_SAFE_INTEGER).text;
    const bytes = Buffer.byteLength(sanitized);
    if (bytes <= Math.min(remaining, 32 * 1024)) {
      remaining -= bytes;
      structuredContent = JSON.parse(sanitized);
    } else {
      truncated = true;
      const notice = { agentmfa_notice: 'Upstream structured content was truncated' };
      const noticeBytes = Buffer.byteLength(JSON.stringify(notice));
      if (noticeBytes <= remaining) {
        remaining -= noticeBytes;
        structuredContent = notice;
      } else {
        structuredContent = undefined;
      }
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
