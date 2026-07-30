import { createHash } from 'node:crypto';

/** Conservative limit accepted by the MCP hosts AgentMFA interoperates with. */
export const MCP_TOOL_NAME_LIMIT = 64;

function hash(value: string): string {
  return createHash('sha256').update(value).digest('hex').slice(0, 10);
}

/**
 * Sanitize and bound an MCP tool name. Long names retain a readable prefix
 * and gain a stable hash so truncation does not turn distinct names into the
 * same tool.
 */
export function boundedToolName(candidate: string, identity = candidate): string {
  const sanitized = candidate.replace(/[^a-zA-Z0-9_-]/g, '_');
  if (sanitized.length <= MCP_TOOL_NAME_LIMIT) return sanitized;
  const suffix = `_${hash(identity)}`;
  return `${sanitized.slice(0, MCP_TOOL_NAME_LIMIT - suffix.length)}${suffix}`;
}

/**
 * Produce a bounded alternate when two already-sanitized names collide.
 * The identity and attempt make the result stable for a stable catalog.
 */
export function alternateToolName(
  candidate: string,
  identity: string,
  attempt: number,
): string {
  const suffix = `_${hash(`${identity}\0${attempt}`)}`;
  const sanitized = candidate.replace(/[^a-zA-Z0-9_-]/g, '_');
  return `${sanitized.slice(0, MCP_TOOL_NAME_LIMIT - suffix.length)}${suffix}`;
}
