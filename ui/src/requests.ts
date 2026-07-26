import type { Approval, ElicitationRequest, RequestRecord } from './types';

/**
 * Re-anchor broker-relative deadlines to this machine's clock at receipt.
 *
 * `expires_at` is written by the broker's wall clock; rendering a countdown
 * from it trusts the broker's and this machine's clocks to agree, and a
 * remote broker's offset would show "any moment now" immediately or a
 * too-long fuse. Brokers therefore also send `expires_in_secs`, measured on
 * their clock as the snapshot was built; when present it wins, and
 * `expires_at` is rewritten as local-now plus that remainder. Snapshots from
 * older brokers (no relative field) pass through unchanged.
 */
export function anchorExpiry<T extends { expires_in_secs?: number | null }>(
  items: T[],
  now = Date.now(),
): T[] {
  return items.map((item) => (
    typeof item.expires_in_secs === 'number'
      ? { ...item, expires_at: new Date(now + item.expires_in_secs * 1000).toISOString() }
      : item
  ));
}

export type ActiveRequest =
  | {
      kind: 'approval';
      id: string;
      requestedAt: string;
      expiresAt: string;
      approval: Approval;
    }
  | {
      kind: 'elicitation';
      id: string;
      requestedAt: string;
      expiresAt: string;
      elicitation: ElicitationRequest;
    };

function timestamp(value: string): number {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : Number.POSITIVE_INFINITY;
}

/** Soonest deadline first; when deadlines match, newest request first. */
export function activeRequests(
  approvals: readonly Approval[],
  elicitations: readonly ElicitationRequest[],
): ActiveRequest[] {
  const requests: ActiveRequest[] = [
    ...approvals.map((approval): ActiveRequest => ({
      kind: 'approval',
      id: approval.id,
      requestedAt: approval.requested_at,
      expiresAt: approval.expires_at,
      approval,
    })),
    ...elicitations.map((elicitation): ActiveRequest => ({
      kind: 'elicitation',
      id: elicitation.id,
      requestedAt: elicitation.requested_at,
      expiresAt: elicitation.expires_at,
      elicitation,
    })),
  ];
  return requests.sort((left, right) =>
    timestamp(left.expiresAt) - timestamp(right.expiresAt)
      || timestamp(right.requestedAt) - timestamp(left.requestedAt));
}

export function activeRequestCount(
  approvals: readonly Approval[],
  elicitations: readonly ElicitationRequest[],
): number {
  return approvals.length + elicitations.length;
}

/** Terminal request history, newest resolution first. Active ids are excluded
 * defensively so independently refreshed active/history snapshots never show
 * the same lifecycle in both sections. */
export function recentRequests(
  records: readonly RequestRecord[],
  activeIds: ReadonlySet<string> = new Set(),
): RequestRecord[] {
  return records
    .filter((record) => record.status !== 'pending' && !activeIds.has(record.id))
    .slice()
    .sort((left, right) => {
      const leftAt = Date.parse(left.resolved_at ?? left.requested_at);
      const rightAt = Date.parse(right.resolved_at ?? right.requested_at);
      const safeLeft = Number.isFinite(leftAt) ? leftAt : Number.NEGATIVE_INFINITY;
      const safeRight = Number.isFinite(rightAt) ? rightAt : Number.NEGATIVE_INFINITY;
      return safeRight - safeLeft
        || right.requested_at.localeCompare(left.requested_at)
        || right.id.localeCompare(left.id);
    });
}
