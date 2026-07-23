// Broker-switcher helpers: which broker the app manages (this Mac or a
// remote one over its manage API), how the header labels it, and which
// full-pane takeover the main content shows while a remote link is not
// usable. Pure functions — the shell owns the actual state.

import type { BrokerProfile } from './types';

export const LOCAL_BROKER: BrokerProfile = {
  mode: 'local',
  url: null,
  connected: true,
  error: null,
  has_saved_token: false,
};

/** The switcher's label: "This Mac", or the remote host. */
export function brokerLabel(profile: BrokerProfile): string {
  if (profile.mode === 'local') return 'This Mac';
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
  if (profile.mode === 'local') return 'local';
  if (profile.connected) return 'ok';
  return profile.error ? 'error' : 'pending';
}

export type BrokerTakeover = 'setup' | 'connecting' | 'error' | null;

/**
 * Which full-pane takeover the main content shows. `setupOpen` is the
 * user-driven "configure a remote broker" form; the others derive from the
 * link state: a remote broker that is not connected owns the whole content
 * pane (and disables the nav) until it connects or the user switches back.
 */
export function brokerTakeover(
  profile: BrokerProfile,
  setupOpen: boolean,
): BrokerTakeover {
  if (setupOpen) return 'setup';
  if (profile.mode !== 'remote' || profile.connected) return null;
  if (!profile.has_saved_token) return 'setup';
  return profile.error ? 'error' : 'connecting';
}

/**
 * Why a feature is unavailable against a remote broker, or null when it
 * works. BYO-app OAuth is relayed (the consent page opens in this
 * machine's browser); MCP sign-in and direct endpoints still need their
 * remote flows.
 */
export function remoteFeatureNote(
  profile: BrokerProfile,
  feature: 'mcp-auth' | 'endpoints',
): string | null {
  if (profile.mode !== 'remote') return null;
  return feature === 'mcp-auth'
    ? 'MCP sign-in isn’t available for a remote broker yet — paste a token instead'
    : 'Direct endpoints aren’t available for a remote broker yet';
}
