import type { ActivityEntry } from '/src/types';

/**
 * Full event identity for reconciliation and live-event deduplication.
 *
 * Activity entries have no broker-issued id, so include every payload field
 * that can distinguish two otherwise simultaneous actions.
 */
export function activityIdentity(entry: ActivityEntry): string {
  return JSON.stringify([
    entry.at,
    entry.icon,
    entry.tone,
    entry.text,
    entry.detail ?? null,
    entry.agent ?? null,
    entry.connection ?? null,
    entry.duration_ms ?? null,
    entry.approver ?? null,
    entry.surface ?? null,
    entry.confirmation ?? null,
  ]);
}
