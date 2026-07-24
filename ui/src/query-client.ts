import { QueryClient } from '@tanstack/react-query';
import { invoke } from '/src/bridge';
import { brokerScopeKey } from '/src/broker-scope';
import type { BrokerScope } from '/src/broker-scope';
import type { CommandArgs, CommandName, CommandResult } from '/src/types';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      networkMode: 'always',
      retry: false,
      staleTime: Number.POSITIVE_INFINITY,
    },
    mutations: {
      networkMode: 'always',
      retry: false,
    },
  },
});

/** Keep local and remote broker responses in distinct cache namespaces. */
export function brokerQueryKey<K extends CommandName>(
  broker: BrokerScope,
  command: K,
  args?: CommandArgs<K>,
): readonly unknown[] {
  return ['broker', ...brokerScopeKey(broker), command, args ?? null] as const;
}

/**
 * Read broker-owned state through one cache, always with a fresh fetch.
 *
 * fetchQuery alone would join an already-in-flight fetch for the same key,
 * so a read issued right after a mutation could return pre-mutation data.
 * Cancelling first makes the newest caller authoritative; an older caller
 * whose joined fetch is cancelled rejects (its load() logs and the fresh
 * result lands via this call's state write instead).
 */
export async function refetchBrokerQuery<K extends CommandName>(
  broker: BrokerScope,
  command: K,
  args?: CommandArgs<K>,
): Promise<CommandResult<K>> {
  const queryKey = brokerQueryKey(broker, command, args);
  await queryClient.cancelQueries({ queryKey, exact: true });
  await queryClient.invalidateQueries({ queryKey, exact: true });
  return queryClient.fetchQuery({
    queryKey,
    queryFn: () => invoke(command, args),
  });
}

export function removeBrokerQueries(broker: BrokerScope): void {
  queryClient.removeQueries({
    queryKey: ['broker', ...brokerScopeKey(broker)],
  });
}
