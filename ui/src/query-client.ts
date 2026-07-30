import { QueryClient } from '@tanstack/react-query';
import { useSyncExternalStore } from 'react';
import { invoke } from './bridge';
import { brokerScopeKey } from './broker-scope';
import type { BrokerScope } from './broker-scope';
import type { CommandArgs, CommandName, CommandResult } from './types';

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

export function getBrokerQueryData<K extends CommandName>(
  broker: BrokerScope,
  command: K,
  args?: CommandArgs<K>,
): CommandResult<K> | undefined {
  return queryClient.getQueryData<CommandResult<K>>(
    brokerQueryKey(broker, command, args),
  );
}

export function setBrokerQueryData<K extends CommandName>(
  broker: BrokerScope,
  command: K,
  data: CommandResult<K>,
  args?: CommandArgs<K>,
): void {
  queryClient.setQueryData(brokerQueryKey(broker, command, args), data);
}

export function removeBrokerQueryData<K extends CommandName>(
  broker: BrokerScope,
  command: K,
  args?: CommandArgs<K>,
): void {
  queryClient.removeQueries({
    queryKey: brokerQueryKey(broker, command, args),
    exact: true,
  });
}

export function removeBrokerQueries(broker: BrokerScope): void {
  queryClient.removeQueries({
    queryKey: ['broker', ...brokerScopeKey(broker)],
  });
}

let cacheRevision = 0;

const QUERY_BACKED_COMMANDS = new Set<CommandName>([
  'list_secrets',
  'list_connections',
  'get_identity',
  'list_sessions',
  'list_elicitations',
  'list_approvals',
  'list_requests',
  'get_settings',
]);

function subscribeToQueryCache(listener: () => void): () => void {
  return queryClient.getQueryCache().subscribe((event) => {
    if (event.type !== 'updated' && event.type !== 'removed') return;
    const command = event.query.queryKey[3];
    if (
      typeof command !== 'string'
      || !QUERY_BACKED_COMMANDS.has(command as CommandName)
    ) return;
    cacheRevision += 1;
    listener();
  });
}

function getCacheRevision(): number {
  return cacheRevision;
}

/**
 * Subscribe the React shell to cache writes performed by command refreshes.
 *
 * Feature views read the canonical broker resources through app-state's
 * query-backed accessors. This bridge lets direct cache updates reconcile
 * them without copying query results into a second external-store snapshot.
 * Other cached commands (such as one endpoint per SSH connection) do not
 * cause unrelated full-shell renders.
 */
export function useBrokerQueryRevision(): number {
  return useSyncExternalStore(
    subscribeToQueryCache,
    getCacheRevision,
    getCacheRevision,
  );
}
