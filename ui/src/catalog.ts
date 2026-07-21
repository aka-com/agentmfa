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
//
// Branded API rows (Stripe, OpenAI, …) carry a `preset` instead: the
// vendor's *documented public API root* and auth recipe, prefilled into the
// add form where they stay visible and editable. That is different in kind
// from an MCP endpoint guess — these roots are the vendor's published API
// contract, and the user still sees exactly what gets pinned before saving.

import type { ConnectionSummary, ConnectionType } from './types';

export type CatalogSection = 'Apps' | 'Infrastructure' | 'Secrets';

/**
 * Prefill for a branded API row: everything the add form needs so the user
 * only pastes their credential. Values land in ordinary form fields —
 * nothing here is hidden configuration.
 */
export interface ConnectionPreset {
  /** The vendor's documented public API root, e.g. https://api.stripe.com */
  origin: string;
  /** Auth recipe: 'bearer' | 'header' | 'query' (matches the form's modes). */
  authMode: 'bearer' | 'header' | 'query';
  /** Header or query-parameter name when the recipe needs one. */
  authDetail?: string;
  /** Suggested tool name, e.g. 'stripe'. */
  name: string;
  /** Where to create or find the credential (shown as plain text, not a link). */
  docsUrl?: string;
  /** Placeholder for the credential value input, e.g. 'sk_live_…'. */
  credentialHint?: string;
}

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
  /** Prefill for a branded API row; see ConnectionPreset. */
  preset?: ConnectionPreset;
  /** Extra search terms ("payments", "email") the row answers to. */
  keywords?: string[];
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
    keywords: ['git', 'repos', 'issues', 'pull requests', 'code'],
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
    keywords: ['email', 'mail', 'google', 'inbox'],
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
    keywords: ['docs', 'wiki', 'notes', 'pages'],
  },
  {
    id: 'airtable',
    name: 'Airtable',
    icon: 'airtable',
    description: 'Bases, tables & records',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    keywords: ['spreadsheet', 'tables', 'records', 'bases'],
    preset: {
      origin: 'https://api.airtable.com',
      authMode: 'bearer',
      name: 'airtable',
      docsUrl: 'airtable.com/create/tokens',
      credentialHint: 'pat…',
    },
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    icon: 'anthropic',
    description: 'Claude models & messages',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    keywords: ['claude', 'llm', 'ai', 'models'],
    preset: {
      origin: 'https://api.anthropic.com',
      authMode: 'header',
      authDetail: 'x-api-key',
      name: 'anthropic',
      docsUrl: 'console.anthropic.com/settings/keys',
      credentialHint: 'sk-ant-…',
    },
  },
  {
    id: 'linear',
    name: 'Linear',
    icon: 'linear',
    description: 'Issues, projects & cycles',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    keywords: ['issues', 'tickets', 'projects', 'sprint'],
    preset: {
      origin: 'https://api.linear.app',
      authMode: 'header',
      authDetail: 'Authorization',
      name: 'linear',
      docsUrl: 'linear.app/settings/api',
      credentialHint: 'lin_api_…',
    },
  },
  {
    id: 'openai',
    name: 'OpenAI',
    icon: 'openai',
    description: 'GPT models & responses',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    keywords: ['gpt', 'llm', 'ai', 'models'],
    preset: {
      origin: 'https://api.openai.com',
      authMode: 'bearer',
      name: 'openai',
      docsUrl: 'platform.openai.com/api-keys',
      credentialHint: 'sk-…',
    },
  },
  {
    id: 'sentry',
    name: 'Sentry',
    icon: 'sentry',
    description: 'Errors, issues & releases',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    keywords: ['errors', 'crashes', 'monitoring', 'issues'],
    preset: {
      origin: 'https://sentry.io',
      authMode: 'bearer',
      name: 'sentry',
      docsUrl: 'sentry.io/settings/account/api/auth-tokens',
      credentialHint: 'sntrys_…',
    },
  },
  {
    id: 'slack',
    name: 'Slack',
    icon: 'slack',
    description: 'Messages, channels & users',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    keywords: ['chat', 'messages', 'channels', 'team'],
    preset: {
      origin: 'https://slack.com',
      authMode: 'bearer',
      name: 'slack',
      docsUrl: 'api.slack.com/apps',
      credentialHint: 'xoxb-…',
    },
  },
  {
    id: 'stripe',
    name: 'Stripe',
    icon: 'stripe',
    description: 'Payments, customers & invoices',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    keywords: ['payments', 'billing', 'charges', 'invoices'],
    preset: {
      origin: 'https://api.stripe.com',
      authMode: 'bearer',
      name: 'stripe',
      docsUrl: 'dashboard.stripe.com/apikeys',
      credentialHint: 'sk_live_… or rk_live_…',
    },
  },
  {
    id: 'vercel',
    name: 'Vercel',
    icon: 'vercel',
    description: 'Deployments, projects & domains',
    section: 'Apps',
    via: 'connection',
    connType: 'api',
    keywords: ['deploy', 'hosting', 'domains', 'frontend'],
    preset: {
      origin: 'https://api.vercel.com',
      authMode: 'bearer',
      name: 'vercel',
      docsUrl: 'vercel.com/account/settings/tokens',
      credentialHint: 'Vercel access token',
    },
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
    keywords: ['server', 'tools', 'model context protocol'],
  },
  {
    id: 'postgres',
    name: 'Postgres',
    icon: 'postgres',
    description: 'Query your database',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'pg',
    keywords: ['database', 'sql', 'db', 'postgresql'],
  },
  {
    id: 'ssh',
    name: 'SSH',
    icon: 'terminal',
    description: 'Remote shell access',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'ssh',
    keywords: ['server', 'shell', 'remote', 'terminal'],
  },
  {
    id: 'http',
    name: 'Custom API',
    icon: 'globe',
    description: 'Any credentialed REST API',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'api',
    keywords: ['rest', 'http', 'endpoint'],
  },
  {
    id: 'websocket',
    name: 'Custom WebSocket',
    icon: 'radioTower',
    description: 'Streaming connections',
    section: 'Infrastructure',
    via: 'connection',
    connType: 'ws',
    keywords: ['stream', 'realtime', 'socket'],
  },
  {
    id: 'credentials',
    name: 'Saved credentials',
    icon: 'keyRound',
    description: 'API keys, passwords, and private keys in your Keychain',
    section: 'Secrets',
    via: 'builtin',
    keywords: ['secrets', 'tokens', 'keychain'],
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
    keywords: ['vault', 'passwords', 'secrets'],
  },
];

export const CATALOG_SECTIONS: CatalogSection[] = ['Apps', 'Infrastructure', 'Secrets'];

/** The pinned host of a preset's API root, e.g. 'api.stripe.com'. */
export function presetHost(preset: ConnectionPreset): string {
  try { return new URL(preset.origin).hostname; } catch { return ''; }
}

/**
 * Which catalog row owns a connection.
 *
 * A stored connection does not remember which shortcut created it — a
 * GitHub MCP server and a Notion one are both an API connection with an
 * `mcp_path`. So every MCP connection lists under the generic MCP row.
 * A plain API connection whose pinned host equals a branded row's preset
 * root lists under that row (an exact host match is deterministic, not a
 * guess); everything else lists under the row for its protocol.
 */
export function entryForConnection(connection: ConnectionSummary): CatalogEntry | undefined {
  if (connection.type === 'api' && connection.mcp_path) {
    return CATALOG.find((entry) => entry.id === 'mcp');
  }
  if (connection.type === 'api' && connection.host) {
    const branded = CATALOG.find(
      (entry) => entry.preset && presetHost(entry.preset) === connection.host,
    );
    if (branded) return branded;
  }
  return CATALOG.find(
    (entry) => entry.via === 'connection' && entry.connType === connection.type
      && !entry.mcp && !entry.preset,
  );
}

export function connectionsForEntry(
  entry: CatalogEntry,
  connections: ConnectionSummary[],
): ConnectionSummary[] {
  return connections.filter((connection) => entryForConnection(connection)?.id === entry.id);
}

/**
 * Case-insensitive filter for the search box. Matches the name,
 * description, id, and each keyword — so "payments" finds Stripe and
 * "email" finds Gmail without the user knowing the vendor first.
 */
export function filterCatalog(query: string): CatalogEntry[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return CATALOG;
  return CATALOG.filter((entry) =>
    entry.name.toLowerCase().includes(needle) ||
    entry.description.toLowerCase().includes(needle) ||
    entry.id.includes(needle) ||
    (entry.keywords || []).some((keyword) => keyword.toLowerCase().includes(needle)));
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
    (entry) => entry.via === 'connection' && entry.connType === type
      && !entry.mcp && !entry.preset,
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
