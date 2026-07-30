import type { ConnectionSummary } from './types';

export function endpointExpired(
  expiresAt: string,
  expiresInSecs?: number | null,
  now = Date.now(),
): boolean {
  return expiresInSecs === 0 || new Date(expiresAt).getTime() <= now;
}

/** Re-anchor endpoint deadlines to the UI clock when a remote broker supplies
 * its own remaining seconds, just like approval deadlines. */
export function anchorEndpointExpiries(
  connections: ConnectionSummary[],
  now = Date.now(),
): ConnectionSummary[] {
  return connections.map((connection) => {
    const endpoint = connection.agent_access.endpoint;
    if (!endpoint || typeof endpoint.expires_in_secs !== 'number') return connection;
    return {
      ...connection,
      agent_access: {
        ...connection.agent_access,
        endpoint: {
          ...endpoint,
          expires_at: new Date(now + endpoint.expires_in_secs * 1000).toISOString(),
        },
      },
    };
  });
}
