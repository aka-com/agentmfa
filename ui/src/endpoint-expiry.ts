import type { ConnectionSummary } from './types';

export function endpointExpired(
  expiresAt: string,
  expiresInSecs?: number | null,
  now = Date.now(),
): boolean {
  return expiresInSecs === 0 || new Date(expiresAt).getTime() <= now;
}

/** Relative phrasing for an already-elapsed endpoint deadline, e.g.
 * "Expired", "Expired 2 days ago". Empty when the deadline is still ahead
 * or missing. */
export function expiredAgoLabel(
  expiresAt: string,
  expiresInSecs?: number | null,
  now = Date.now(),
): string {
  if (!endpointExpired(expiresAt, expiresInSecs, now)) return '';
  const t = Date.parse(expiresAt);
  if (Number.isNaN(t)) return 'Expired';
  const secs = Math.max(0, Math.round((now - t) / 1000));
  if (secs < 60) return 'Expired';
  const mins = Math.round(secs / 60);
  if (mins < 60) return `Expired ${mins} minute${mins === 1 ? '' : 's'} ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `Expired ${hrs} hour${hrs === 1 ? '' : 's'} ago`;
  const days = Math.round(hrs / 24);
  if (days < 45) return `Expired ${days} day${days === 1 ? '' : 's'} ago`;
  const months = Math.round(days / 30);
  if (months < 18) return `Expired ${months} month${months === 1 ? '' : 's'} ago`;
  const years = Math.round(days / 365);
  return `Expired ${years} year${years === 1 ? '' : 's'} ago`;
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
