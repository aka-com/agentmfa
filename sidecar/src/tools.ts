// AgentMFA's tools, as MCP sees them.
//
// This is the `plugin-agentmfa` role from the plan: every connection the
// broker knows becomes an MCP tool whose invocation proxies to the broker's
// existing data planes. The shape of each tool follows what its plane
// actually does:
//
//   * `api` connections are *called* — the agent supplies method/path and
//     the broker injects the credential on the upstream leg. One round
//     trip, one result.
//   * `pg` / `ssh` connections are *opened* — the broker hands back a
//     password-less DSN and ticket, or an `SSH_AUTH_SOCK` path, which the
//     agent then uses with stock tools.
//
// No authorization happens here. An unwired connection never becomes a
// tool, and if one slipped through, the broker would still refuse it.

import { z } from 'zod';

import type { AgentAuth, BrokerClient, BrokerConnection } from './broker';
import { boundedToolName } from './tool-names';

/** MCP tool names allow `[a-zA-Z0-9_-]`; connection names are freer. */
export function toolNameCandidateFor(connection: BrokerConnection): string {
  const slug = connection.name.replace(/[^a-zA-Z0-9_-]/g, '_');
  return connection.type === 'api' ? `agentmfa_${slug}_request` : `agentmfa_${slug}_open`;
}

export function toolNameFor(connection: BrokerConnection): string {
  return boundedToolName(
    toolNameCandidateFor(connection),
    `${connection.type}\0${connection.name}`,
  );
}

/** What an agent is told a tool is for, before it calls it. */
export function describe(connection: BrokerConnection): string {
  switch (connection.type) {
    case 'api':
      return (
        `Make an HTTP request to ${connection.target} through AgentMFA. ` +
        'The API credential is injected by the broker and never exposed here. ' +
        'The result is {status, headers, body, body_encoding}; body is a string and ' +
        'body_encoding is utf8 or base64. Response cookies are omitted from this MCP view.'
      );
    case 'pg':
      return (
        `Open a Postgres session on ${connection.target}. Returns a password-less ` +
        'DSN and a short-lived ticket to use as PGPASSWORD with psql or any ' +
        'standard client. The broker-facing leg is plaintext and requires ' +
        'sslmode=disable; use it only over the trusted path to the broker. ' +
        'The configured upstream TLS mode still applies from broker to database.'
      );
    case 'ssh':
      return (
        `Open an SSH session to ${connection.target}. Returns an SSH_AUTH_SOCK ` +
        'path that ssh, git and rsync can use; the private key stays in the broker. ' +
        'Pass -o IdentityFile=none -o CertificateFile=none so an on-disk key ' +
        'cannot authenticate instead, and -o ForwardAgent=no -o ControlMaster=no; ' +
        'do not pass -o IdentitiesOnly=yes, which discards the brokered identity.'
      );
    default:
      return `Use the AgentMFA connection "${connection.name}" (${connection.target}).`;
  }
}

/** The input schema for a tool, by connection type. */
export function schemaFor(connection: BrokerConnection): Record<string, z.ZodTypeAny> {
  if (connection.type !== 'api') {
    return {
      request_id: z
        .string()
        .optional()
        .describe('Idempotency key; a retry with the same value will not open a second session'),
    };
  }
  return {
    method: z
      .enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
      .describe('HTTP method'),
    path: z
      .string()
      .regex(/^\/(?!\/)[^\\#\x00-\x1f\x7f]*$/)
      .describe('Absolute path and optional query, e.g. /repos/owner/name/issues?state=open'),
    headers: z
      .union([
        z.record(z.string(), z.string()),
        z.array(z.tuple([z.string(), z.string()])),
      ])
      .optional()
      .describe(
        'Extra headers as an object or [name, value] pairs (pairs preserve repeats). ' +
          'Reserved: authorization, host, content-length, transfer-encoding, connection, ' +
          'upgrade, proxy-authorization, proxy-authenticate, proxy-connection, keep-alive, ' +
          'te, trailer, expect, accept-encoding, content-encoding, and the connection credential header.',
      ),
    body: z
      .unknown()
      .optional()
      .describe('JSON body; a string is sent as raw bytes. Do not combine with body_base64'),
    body_base64: z
      .string()
      .optional()
      .describe('Base64-encoded binary body. Do not combine with body'),
    request_id: z
      .string()
      .optional()
      .describe('Idempotency key; a retried mutating call with the same value is coalesced'),
  };
}

/** The broker call a tool invocation turns into. */
export function callFor(
  connection: BrokerConnection,
  args: Record<string, unknown>,
): { path: string; body: Record<string, unknown> } {
  if (connection.type === 'api') {
    const { method, path, headers, body, body_base64: bodyBase64, request_id: requestId } = args as {
      method: string;
      path: string;
      headers?: Record<string, string> | Array<[string, string]>;
      body?: unknown;
      body_base64?: string;
      request_id?: string;
    };
    return {
      path: connection.endpoint,
      body: {
        connection: connection.name,
        method,
        path,
        ...(headers ? { headers } : {}),
        ...(body === undefined ? {} : { body }),
        ...(bodyBase64 === undefined ? {} : { body_base64: bodyBase64 }),
        ...(requestId ? { request_id: requestId } : {}),
      },
    };
  }
  const requestId = (args as { request_id?: string }).request_id;
  return {
    path: connection.endpoint,
    body: {
      connection: connection.name,
      ...(requestId ? { request_id: requestId } : {}),
    },
  };
}

/** The MCP SDK's result type carries an index signature; match it. */
export interface ToolResult {
  [key: string]: unknown;
  isError?: boolean;
  content: Array<{ type: 'text'; text: string }>;
}

function text(value: unknown): ToolResult {
  return {
    content: [
      {
        type: 'text',
        text: typeof value === 'string' ? value : JSON.stringify(value, null, 2),
      },
    ],
  };
}

const COOKIE_PLACEHOLDER = '[OMITTED BY AGENTMFA]';

/** Remove HTTP cookie material that has no legitimate MCP use before the
 * broker envelope is serialized into agent context. */
export function projectForMcp(connection: BrokerConnection, value: unknown): unknown {
  if (
    connection.type !== 'api' ||
    value === null ||
    typeof value !== 'object' ||
    Array.isArray(value)
  ) {
    return value;
  }
  const source = value as Record<string, unknown>;
  const projected: Record<string, unknown> = { ...source };
  delete projected.set_cookie_headers;
  if (source.headers && typeof source.headers === 'object' && !Array.isArray(source.headers)) {
    const headers: Record<string, unknown> = { ...(source.headers as Record<string, unknown>) };
    for (const name of Object.keys(headers)) {
      if (name.toLowerCase() === 'set-cookie' || name.toLowerCase() === 'cookie') {
        headers[name] = COOKIE_PLACEHOLDER;
      }
    }
    projected.headers = headers;
  }
  return projected;
}

export function toolError(message: string): ToolResult {
  return { isError: true, content: [{ type: 'text', text: message }] };
}

/**
 * Invoke one tool against the broker.
 *
 * A broker refusal is returned as a tool error rather than thrown: the
 * agent should be told it lacks access and why, not handed a transport
 * failure it will retry blindly.
 */
export async function invoke(
  broker: BrokerClient,
  auth: AgentAuth,
  connection: BrokerConnection,
  args: Record<string, unknown>,
): Promise<ToolResult> {
  const { path, body } = callFor(connection, args);
  try {
    return text(projectForMcp(connection, await broker.invoke(path, auth, body)));
  } catch (error) {
    const failure = error as {
      status?: number;
      reason?: string;
      detail?: string;
      retryAfterSeconds?: number;
      message?: string;
    };
    if (failure.status === 403) {
      switch (failure.reason) {
        case 'approval_denied':
          return toolError(
            `The user refused this call to "${connection.name}". Do not retry it; ` +
              'ask the user before trying a changed request.',
          );
        case 'approval_unavailable':
          return toolError(
            `Confirmation is enabled for "${connection.name}", but no AgentMFA ` +
              'approval window is attached. Ask the user to open AgentMFA.',
          );
        case 'denied_by_policy':
        default:
          return toolError(
            `AgentMFA policy refused "${connection.name}". ` +
              (failure.detail ??
                `Ask the user to enable "${connection.name}" for agents in AgentMFA.`),
          );
      }
    }
    if (failure.status === 408 || failure.reason === 'approval_timeout') {
      return toolError(
        `Nobody answered the confirmation for "${connection.name}" in time. ` +
          'Retrying will ask the user again.',
      );
    }
    if (failure.status === 429) {
      const retry = failure.retryAfterSeconds;
      return toolError(
        `AgentMFA rate limited this call: ${failure.detail ?? failure.reason ?? 'rate_limited'}.` +
          (retry === undefined ? '' : ` Retry after ${retry} second${retry === 1 ? '' : 's'}.`),
      );
    }
    return toolError(`AgentMFA call failed: ${failure.message ?? String(error)}`);
  }
}
