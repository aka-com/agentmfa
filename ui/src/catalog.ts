// The tool catalog: the static registry behind the "Add tools" screen.
//
// Connections are stored by protocol (api/pg/ws/ssh); the catalog presents
// them as tools grouped into sections. Each entry either maps to a
// connection type the broker serves today (`via: 'connection'`), fronts a
// built-in store (`via: 'builtin'` — the Keychain-backed saved
// credentials), or names an integration that arrives later through the MCP
// layer (`via: 'mcp'`, shown dimmed and not yet addable).
//
// Branded apps (GitHub, Gmail, Notion, 1Password) are all MCP-bound: they
// are richer than a single credentialed origin, so they wait for the MCP
// layer rather than being approximated by a raw HTTP connection.

import type { ConnectionSummary, ConnectionType } from './types';

export type CatalogSection = 'Apps' | 'Infrastructure' | 'Secrets';

export interface CatalogEntry {
  id: string;
  name: string;
  /** Key into ICONS (Lucide) or BRAND_ICONS (Simple Icons brand marks). */
  icon: string;
  description: string;
  section: CatalogSection;
  via: 'connection' | 'builtin' | 'mcp';
  connType?: ConnectionType;
}

export const CATALOG: CatalogEntry[] = [
  {
    id: 'github',
    name: 'GitHub',
    icon: 'github',
    description: 'Repos, issues, PRs',
    section: 'Apps',
    via: 'mcp',
  },
  {
    id: 'gmail',
    name: 'Gmail',
    icon: 'gmail',
    description: 'Read & send email',
    section: 'Apps',
    via: 'mcp',
  },
  {
    id: 'notion',
    name: 'Notion',
    icon: 'notion',
    description: 'Pages & databases',
    section: 'Apps',
    via: 'mcp',
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
    description: 'Vault & credentials',
    section: 'Secrets',
    via: 'mcp',
  },
];

export const CATALOG_SECTIONS: CatalogSection[] = ['Apps', 'Infrastructure', 'Secrets'];

/** Which catalog row owns a connection: the row for its protocol. */
export function entryForConnection(connection: ConnectionSummary): CatalogEntry | undefined {
  return CATALOG.find((entry) => entry.via === 'connection' && entry.connType === connection.type);
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
  return CATALOG.find((entry) => entry.via === 'connection' && entry.connType === type)?.name
    ?? 'tool';
}

/** Catalog entries that can be added today, in display order. */
export function addableEntries(): CatalogEntry[] {
  return CATALOG.filter((entry) => entry.via === 'connection');
}
