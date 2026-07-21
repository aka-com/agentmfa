// The tool catalog: the static registry behind the "Add tools" screen.
//
// Connections are stored by protocol (api/pg/ws/ssh); the catalog presents
// them as tools grouped into sections. Each entry either maps to a
// connection type the broker serves today (`via: 'connection'`) or fronts
// a built-in store (`via: 'builtin'` — the Keychain-backed saved
// credentials).
//
// Branded apps (GitHub, Gmail, Notion, 1Password) are `mcp: true`: they are
// richer than a single credentialed origin, so they are added by pointing
// at that service's MCP server. Underneath they are still API connections —
// same pinned host, same credential injected on the upstream leg — with an
// MCP path set, which is what lets the sidecar re-expose their tools.
//
// We do not ship endpoint URLs for these: the user supplies the server URL
// their vendor gave them. A branded row is a labelled shortcut, not a claim
// about someone else's infrastructure.

import type { ConnectionSummary, ConnectionType } from './types';

export type CatalogSection = 'Apps' | 'Infrastructure' | 'Secrets';

export interface CatalogEntry {
  id: string;
  name: string;
  /** Key into ICONS (Lucide) or BRAND_ICONS (Simple Icons brand marks). */
  icon: string;
  description: string;
  section: CatalogSection;
  via: 'connection' | 'builtin';
  connType?: ConnectionType;
  /**
   * Added by pointing at an MCP server. Stored as an API connection with
   * `mcp_path` set; the form asks for a server URL rather than an API root.
   */
  mcp?: boolean;
}

export const CATALOG: CatalogEntry[] = [
  {
    id: 'github',
    name: 'GitHub',
    icon: 'github',
    description: 'Repos, issues, PRs — via MCP',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
  },
  {
    id: 'gmail',
    name: 'Gmail',
    icon: 'gmail',
    description: 'Read & send email — via MCP',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
  },
  {
    id: 'notion',
    name: 'Notion',
    icon: 'notion',
    description: 'Pages & databases — via MCP',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
  },
  {
    id: 'mcp',
    name: 'MCP server',
    icon: 'plug',
    description: 'Any MCP server, by URL',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
  },
  {
    id: 'postgres',
    name: 'Postgres',
    icon: 'postgres',
    description: 'Query your database',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'pg',
  },
  {
    id: 'ssh',
    name: 'SSH',
    icon: 'terminal',
    description: 'Remote shell access',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'ssh',
  },
  {
    id: 'http',
    name: 'Custom API',
    icon: 'globe',
    description: 'Any credentialed REST API',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'api',
  },
  {
    id: 'websocket',
    name: 'Custom WebSocket',
    icon: 'radioTower',
    description: 'Streaming connections',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'ws',
  },
  {
    id: 'credentials',
    name: 'Saved credentials',
    icon: 'keyRound',
    description: 'API keys, passwords, and private keys in your Keychain',
    section: 'Secrets',
    via: 'builtin',
  },
  {
    id: 'onepassword',
    name: '1Password',
    icon: 'onepassword',
    description: 'Vault & credentials — via MCP',
    section: 'Secrets',
    via: 'connection',
    connType: 'api',
    mcp: true,
  },
];

export const CATALOG_SECTIONS: CatalogSection[] = ['Apps', 'Infrastructure', 'Secrets'];

/**
 * Which catalog row owns a connection.
 *
 * A stored connection does not remember which shortcut created it — a
 * GitHub MCP server and a Notion one are both an API connection with an
 * `mcp_path`. So every MCP connection lists under the generic MCP row, and
 * everything else under the row for its protocol. Deterministic beats
 * guessing at a vendor from a hostname.
 */
export function entryForConnection(connection: ConnectionSummary): CatalogEntry | undefined {
  if (connection.type === 'api' && connection.mcp_path) {
    return CATALOG.find((entry) => entry.id === 'mcp');
  }
  return CATALOG.find(
    (entry) => entry.via === 'connection' && entry.connType === connection.type && !entry.mcp,
  );
}

export function connectionsForEntry(
  entry: CatalogEntry,
  connections: ConnectionSummary[],
): ConnectionSummary[] {
  return connections.filter((connection) => entryForConnection(connection)?.id === entry.id);
}

/** Case-insensitive name/description filter for the search box. */
export function filterCatalog(query: string): CatalogEntry[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return CATALOG;
  return CATALOG.filter((entry) =>
    entry.name.toLowerCase().includes(needle) ||
    entry.description.toLowerCase().includes(needle) ||
    entry.id.includes(needle));
}

export interface CatalogVisibility {
  /** The "Show WebSockets" setting; off by default. */
  showWebsockets: boolean;
  connections: ConnectionSummary[];
}

/**
 * The rows to render: the search filter, minus anything switched off.
 *
 * A hidden row still appears when something is configured under it — a tool
 * you already have must never become invisible (and therefore unmanageable)
 * because of a display preference.
 */
export function visibleCatalog(query: string, visibility: CatalogVisibility): CatalogEntry[] {
  return filterCatalog(query).filter((entry) => {
    if (entry.id !== 'websocket' || visibility.showWebsockets) return true;
    return connectionsForEntry(entry, visibility.connections).length > 0;
  });
}

/** The catalog's name for a connection type — the dialog titles reuse it. */
export function catalogNameForType(type: ConnectionType): string {
  return CATALOG.find(
    (entry) => entry.via === 'connection' && entry.connType === type && !entry.mcp,
  )?.name ?? 'tool';
}

/** The dialog title for a row: branded MCP rows keep their own name. */
export function catalogNameForEntry(entry: CatalogEntry): string {
  return entry.name;
}

/** Catalog entries that can be added today, in display order. */
export function addableEntries(): CatalogEntry[] {
  return CATALOG.filter((entry) => entry.via === 'connection');
}
