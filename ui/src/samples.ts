// Sample tools: the spotlight card pinned above the Tools tab.
//
// Both samples are public, keyless, read-only APIs — the Hacker News search
// API (Algolia-backed) and the Stack Exchange API. That is what makes their
// one-press Connect honest: there is no credential to collect and no form to
// fill, so pressing the button registers the pinned origin and the tool is
// immediately live. The card stays put — first run and steady state alike —
// until its ✕ stores a dismissal, and connecting one sample keeps the card
// up so the other stays one press away.

import type { ConnectionSummary } from './types';

export interface SampleTool {
  id: string;
  name: string;
  /** Key into ICONS (a Simple Icons brand mark). */
  icon: string;
  description: string;
  /** The vendor's documented public API host, pinned like any API origin. */
  host: string;
  /**
   * The route the health check probes instead of the origin root — both
   * vendors answer their root with an error page, so the row carries a
   * documented request that actually returns data.
   */
  testPath: string;
}

export const SAMPLE_TOOLS: SampleTool[] = [
  {
    id: 'sample-hackernews',
    name: 'Hacker News',
    icon: 'hackernews',
    description: 'Front-page stories, comments & search. No account needed.',
    host: 'hn.algolia.com',
    testPath: '/api/v1/search?hitsPerPage=1',
  },
  {
    id: 'sample-stackoverflow',
    name: 'Stack Overflow',
    icon: 'stackoverflow',
    description: 'Search questions & answers across Stack Exchange. No key needed.',
    host: 'api.stackexchange.com',
    testPath: '/2.3/info?site=stackoverflow',
  },
];

export function sampleToolById(id: string): SampleTool | undefined {
  return SAMPLE_TOOLS.find((sample) => sample.id === id);
}

/**
 * The stored connection backing a sample, recognized by its pinned host —
 * the same exact-host rule the catalog uses to list a connection under a
 * branded row. Renaming the tool keeps the sample marked connected;
 * deleting it offers Connect again.
 */
export function sampleConnection(
  sample: SampleTool,
  connections: ConnectionSummary[],
): ConnectionSummary | null {
  return connections.find(
    (connection) => connection.type === 'api' && !connection.mcp_path
      && (connection.host || '').toLowerCase() === sample.host,
  ) ?? null;
}

/* ---- dismissal ---------------------------------------------------------- */
// The ✕ is per-machine UI preference, not broker state, so it lives beside
// the stored theme choice. Storage access is guarded the same way: a
// missing or refusing localStorage (tests, private mode) reads as
// not-dismissed and fails the write silently.

const DISMISS_KEY = 'samplesDismissed';

export function readSamplesDismissed(): boolean {
  try { return localStorage.getItem(DISMISS_KEY) === '1'; } catch { return false; }
}

export function persistSamplesDismissed(): void {
  try { localStorage.setItem(DISMISS_KEY, '1'); } catch { /* see above */ }
}
