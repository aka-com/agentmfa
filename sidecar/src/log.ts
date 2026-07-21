// Structured logging for the sidecar.
//
// Its own module because both the HTTP surface and the MCP host log, and
// having either import the other would make a cycle.

export type Level = 'info' | 'warn' | 'error';

/** JSON log line on stderr; the supervisor forwards these to tracing. */
export function log(level: Level, msg: string, fields: Record<string, unknown> = {}): void {
  process.stderr.write(`${JSON.stringify({ level, msg, ...fields })}\n`);
}
