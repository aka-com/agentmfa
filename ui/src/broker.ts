// Broker-switcher helpers: which broker the app manages (this Mac or a
// remote one over its manage API), how the header labels it, and which
// full-pane takeover the main content shows while a remote link is not
// usable. Pure functions — the shell owns the actual state.

import type { BrokerProfile, ConnectionType } from './types';

export const LOCAL_BROKER: BrokerProfile = {
  mode: 'local',
  url: null,
  connected: true,
  error: null,
  has_saved_token: false,
  // Fail closed until the native shell reports its actual capability.
  native_authentication: false,
};

/** The switcher's label: "Local" for this machine, or the remote host. */
export function brokerLabel(profile: BrokerProfile): string {
  if (profile.mode === 'local') return 'Local';
  if (!profile.url) return 'Remote broker';
  try {
    return new URL(profile.url).host;
  } catch {
    return profile.url;
  }
}

export type BrokerTone = 'local' | 'ok' | 'pending' | 'error';

/** The status dot next to the switcher label. */
export function brokerTone(profile: BrokerProfile): BrokerTone {
  if (profile.mode === 'local' && profile.connected) return 'local';
  if (profile.connected) return 'ok';
  return profile.error ? 'error' : 'pending';
}

export type BrokerTakeover = 'setup' | 'connecting' | 'error' | null;

/**
 * Which full-pane takeover the main content shows. `setupOpen` is the
 * user-driven "configure a remote broker" form; the others derive from the
 * link state: an unavailable broker owns the whole content pane (and
 * disables the nav) until it responds or the user switches brokers.
 */
export function brokerTakeover(
  profile: BrokerProfile,
  setupOpen: boolean,
): BrokerTakeover {
  if (setupOpen) return 'setup';
  if (profile.connected) return null;
  if (profile.mode === 'local') return 'error';
  if (profile.mode === 'remote' && !profile.has_saved_token) return 'setup';
  return profile.error ? 'error' : 'connecting';
}

/**
 * A caution shown alongside direct-endpoint issuance on a remote broker, or
 * null in local mode. Endpoints work remotely, but PG/SSH ones are Unix
 * sockets on the broker host and the SSH agent socket is a filesystem path;
 * only the HTTP endpoint's address (advertised host) is reachable off-box.
 */
export function remoteEndpointCaution(
  profile: BrokerProfile,
  type: ConnectionType,
): string | null {
  if (profile.mode !== 'remote') return null;
  if (type === 'api') {
    return 'The address uses the broker’s advertised host — make sure agents can reach it.';
  }
  if (type === 'pg') {
    return 'A remote broker’s Postgres endpoint is a socket on the broker host; agents must run there.';
  }
  if (type === 'ssh') {
    return 'A remote broker’s SSH agent socket lives on the broker host; agents must run there.';
  }
  return null;
}
