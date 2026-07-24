import { useSyncExternalStore } from 'react';

/**
 * Small external-store bridge for the existing action layer.
 *
 * UI state remains mutable during the migration, but React is the only DOM
 * owner. Publishing a revision makes every mutation visible through React's
 * external-store contract instead of imperatively replacing #root.
 */
export class UiStore<T> {
  private revision = 0;
  private readonly listeners = new Set<() => void>();

  constructor(readonly state: T) {}

  readonly getSnapshot = (): number => this.revision;

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  publish(): void {
    this.revision += 1;
    for (const listener of this.listeners) listener();
  }
}

export function useUiRevision<T>(store: UiStore<T>): number {
  return useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot);
}
