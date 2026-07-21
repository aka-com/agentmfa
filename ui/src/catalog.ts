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
  /** Short chip label rendered as the row icon (GH, PG, SSH, …). */
  chip: string;
  description: string;
  section: CatalogSection;
  via: 'connection' | 'builtin' | 'mcp';
  connType?: ConnectionType;
}

export const CATALOG: CatalogEntry[] = [
  {
    id: 'github',
    name: 'GitHub',
    chip: 'GH',
    description: 'Repos, issues, PRs',
    section: 'Apps',
    via: 'mcp',
  },
  {
    id: 'gmail',
    name: 'Gmail',
    chip: 'G',
    description: 'Read & send email',
    section: 'Apps',
    via: 'mcp',
  },
  {
    id: 'notion',
    name: 'Notion',
    chip: 'N',
    description: 'Pages & databases',
    section: 'Apps',
    via: 'mcp',
  },
  {
    id: 'postgres',
    name: 'Postgres',
    chip: 'PG',
    description: 'Query your database',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'pg',
  },
  {
    id: 'ssh',
    name: 'SSH',
    chip: 'SSH',
    description: 'Remote shell access',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'ssh',
  },
  {
    id: 'http',
    name: 'Custom API',
    chip: 'API',
    description: 'Any credentialed REST API',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'api',
  },
  {
    id: 'websocket',
    name: 'Custom WebSocket',
    chip: 'WS',
    description: 'Streaming connections',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'ws',
  },
  {
    id: 'credentials',
    name: 'Saved credentials',
    chip: 'KEY',
    description: 'API keys, passwords, and private keys in your Keychain',
    section: 'Secrets',
    via: 'builtin',
  },
  {
    id: 'onepassword',
    name: '1Password',
    chip: '1P',
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
