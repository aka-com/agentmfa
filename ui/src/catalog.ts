// The tool catalog: the static registry behind the "Add tools" screen.
//
// Connections are stored by protocol (api/pg/ws/ssh); the catalog presents
// them as branded tools grouped into sections. Each entry maps to a
// connection type the broker can serve today (`via: 'connection'`, with an
// optional prefill for the add sheet), fronts a built-in store
// (`via: 'builtin'` — today the Keychain-backed saved credentials), or
// names an integration arriving later through the MCP layer
// (`via: 'mcp'`, shown dimmed and not yet addable).

import type { ConnectionSummary, ConnectionType } from './types';

export type CatalogSection = 'Apps' | 'Infrastructure' | 'Secrets';

/** Values dropped into the add-connection sheet when a row's Add is used. */
export interface CatalogPrefill {
  name?: string;
  origin?: string;
  template?: string;
}

export interface CatalogEntry {
  id: string;
  name: string;
  /** Short chip label rendered as the row icon (GH, PG, SSH, …). */
  chip: string;
  description: string;
  section: CatalogSection;
  via: 'connection' | 'builtin' | 'mcp';
  connType?: ConnectionType;
  /** api entries only: claim api connections whose host contains this. */
  hostHint?: string;
  prefill?: CatalogPrefill;
}

export const CATALOG: CatalogEntry[] = [
  {
    id: 'github',
    name: 'GitHub',
    chip: 'GH',
    description: 'Repos, issues, PRs',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    hostHint: 'github',
    prefill: {
      name: 'github',
      origin: 'https://api.github.com',
      template: 'Authorization: Bearer {{GITHUB_API_KEY}}',
    },
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
    via: 'connection',
    connType: 'api',
    hostHint: 'notion',
    prefill: {
      name: 'notion',
      origin: 'https://api.notion.com',
      template: 'Authorization: Bearer {{NOTION_API_KEY}}',
    },
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
    name: 'HTTP API',
    chip: 'API',
    description: 'Any credentialed REST API',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'api',
  },
  {
    id: 'websocket',
    name: 'WebSocket',
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

/** Which catalog row owns a connection. Branded api entries claim api
 * connections by host hint; the generic HTTP API row takes the rest. */
export function entryForConnection(connection: ConnectionSummary): CatalogEntry | undefined {
  if (connection.type === 'api') {
    const host = (connection.host || '').toLowerCase();
    const branded = CATALOG.find((entry) =>
      entry.connType === 'api' && entry.hostHint && host.includes(entry.hostHint));
    if (branded) return branded;
    return CATALOG.find((entry) => entry.id === 'http');
  }
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
