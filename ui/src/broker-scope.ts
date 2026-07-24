import type { BrokerProfile } from '/src/types';

export type BrokerScope = Pick<BrokerProfile, 'mode' | 'url'>;

export function brokerScopeKey(broker: BrokerScope): readonly [string, string | null] {
  return [broker.mode, broker.url ?? null];
}

export function sameBrokerScope(left: BrokerScope, right: BrokerScope): boolean {
  return left.mode === right.mode && (left.url ?? null) === (right.url ?? null);
}
