import type { Approval, ElicitationRequest } from './types';

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
