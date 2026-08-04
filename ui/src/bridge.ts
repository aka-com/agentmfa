// Bridge to the Rust core. Inside Tauri (withGlobalTauri), calls go to real
// commands over IPC. Frontend-only development lazily loads a mock adapter;
// the compile-time DEV branch keeps its fixtures out of production bundles.

import type {
  CommandArgs,
  CommandName,
  CommandResult,
  EventMap,
  EventName,
  EventPayload,
  Unlisten,
} from './types';

const tauri = typeof window !== 'undefined' ? window.__TAURI__ : undefined;

async function developmentMock() {
  if (!import.meta.env.DEV) {
    throw new Error('The Multitool frontend must run inside Tauri');
  }
  return import('./mock-bridge');
}

/** Which window chrome to render, from the URL hash. */
export const mode = location.hash.replace('#', '') || 'window';

export async function invoke<K extends CommandName>(
  command: K,
  args?: CommandArgs<K>,
): Promise<CommandResult<K>> {
  if (tauri) {
    return tauri.core.invoke(
      command,
      args as Record<string, unknown> | undefined,
    ) as Promise<CommandResult<K>>;
  }
  const mock = await developmentMock();
  return mock.invoke(command, args);
}

export async function listen<K extends EventName>(
  event: K,
  callback: (event: EventPayload<EventMap[K]>) => void,
): Promise<Unlisten> {
  if (tauri) {
    return tauri.event.listen(event, callback as (event: EventPayload<unknown>) => void);
  }
  const mock = await developmentMock();
  return mock.listen(event, callback);
}
