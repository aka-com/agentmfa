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
// Vendors with an *official, documented* hosted MCP server carry an
// `mcpTemplate`: the server URL is prefilled (still editable), the tools we
// expect the server to advertise are checked by the status button, and the
// whoami tool acknowledges which account a credential belongs to. A vendor
// without a published endpoint (Gmail today) keeps the template minus the
// URL — the user pastes the one their provider gave them.
//
// Branded API rows (Stripe, OpenAI, …) carry a `preset` instead: the
// vendor's *documented public API root* and auth recipe, prefilled into the
// add form where they stay visible and editable. Like template endpoints,
// these roots are the vendor's published contract, and the user still sees
// exactly what gets pinned before saving.

import type { ConnectionSummary, ConnectionType } from './types';
import { REGISTRY_SERVERS } from './registry-data';

export type CatalogSection = 'Apps' | 'Infrastructure' | 'Secrets' | 'MCP registry';

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

/**
 * A branded MCP server the catalog knows how to reach and talk to.
 *
 * `serverUrl` is the vendor's published endpoint, prefilled into the add
 * form but always editable. `expectedTools` is advisory: the status check
 * reports (never blocks on) tools the server stopped advertising.
 * `whoamiTool` names the tool that identifies the connected account.
 */
export interface McpTemplate {
  serverUrl?: string;
  expectedTools: string[];
  whoamiTool?: string;
  /** Copy shown under the URL field in the add form. */
  urlHint?: string;
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
  /** Branded MCP details (endpoint, expected tools, whoami). */
  mcpTemplate?: McpTemplate;
  /** Extra search terms ("payments", "email") the row answers to. */
  keywords?: string[];
  /** From the generated MCP-registry tail, not the curated catalog. */
  registry?: boolean;
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
    mcpTemplate: {
      serverUrl: 'https://api.githubcopilot.com/mcp/',
      expectedTools: [
        'get_me', 'search_repositories', 'get_file_contents',
        'list_issues', 'create_issue', 'create_pull_request',
      ],
      whoamiTool: 'get_me',
      urlHint: 'GitHub’s hosted MCP server. Sign in with your GitHub account, or paste a personal access token.',
    },
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
    // Google publishes no hosted Gmail MCP endpoint yet, so there is no URL
    // to encode — paste the one your provider gave you. Sign-in and status
    // checks work the same once the URL is known.
    mcpTemplate: {
      expectedTools: [],
      urlHint: 'Google doesn’t publish a hosted Gmail MCP endpoint yet — paste the server URL from your Gmail MCP provider.',
    },
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
    mcpTemplate: {
      serverUrl: 'https://mcp.notion.com/mcp',
      expectedTools: [
        'notion-search', 'notion-fetch', 'notion-create-pages',
        'notion-update-page', 'notion-get-self',
      ],
      whoamiTool: 'notion-get-self',
      urlHint: 'Notion’s hosted MCP server. Sign in with your Notion account to pick the workspace.',
    },
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

export const CATALOG_SECTIONS: CatalogSection[] =
  ['Apps', 'Infrastructure', 'MCP registry', 'Secrets'];

/**
 * The registry tail: hosted MCP servers from the public index, each an
 * ordinary addable MCP row (OAuth-first, endpoint prefilled but editable).
 * They surface on search — and whenever one is configured — rather than
 * padding the default catalog view.
 */
export const REGISTRY_CATALOG: CatalogEntry[] = REGISTRY_SERVERS.map((server) => ({
  id: server.id,
  name: server.name,
  icon: server.icon,
  description: server.description,
  section: 'MCP registry',
  via: 'connection',
  connType: 'api',
  mcp: true,
  registry: true,
  keywords: [...server.keywords, 'mcp', 'registry'],
  mcpTemplate: {
    serverUrl: server.serverUrl,
    expectedTools: [],
    urlHint: 'The vendor’s published MCP endpoint, from the public MCP registry. Sign in, or paste a token.',
  },
}));

/** Every row Add can act on: the curated catalog plus the registry tail. */
export function catalogEntryById(id: string): CatalogEntry | undefined {
  return CATALOG.find((entry) => entry.id === id)
    ?? REGISTRY_CATALOG.find((entry) => entry.id === id);
}

/** The pinned host of a preset's API root, e.g. 'api.stripe.com'. */
export function presetHost(preset: ConnectionPreset): string {
  try { return new URL(preset.origin).hostname; } catch { return ''; }
}

/** Hostname of a template's published server URL, lowercased. */
function templateHost(entry: CatalogEntry): string | null {
  const raw = entry.mcpTemplate?.serverUrl;
  if (!raw) return null;
  try { return new URL(raw).hostname.toLowerCase(); } catch { return null; }
}

/**
 * Which catalog row owns a connection.
 *
 * An MCP connection whose pinned host matches a branded template's
 * published endpoint lists under that brand — that is what lets several
 * GitHub accounts stack under the GitHub row. Every other MCP connection
 * lists under the generic MCP row (deterministic beats guessing at a
 * vendor from an arbitrary hostname). A plain API connection whose pinned
 * host equals a branded row's preset root lists under that row (an exact
 * host match is deterministic, not a guess); everything else lists under
 * the row for its protocol.
 */
export function entryForConnection(connection: ConnectionSummary): CatalogEntry | undefined {
  if (connection.type === 'api' && connection.mcp_path) {
    const host = (connection.host || '').toLowerCase();
    const branded = CATALOG.find((entry) => entry.mcp && host && templateHost(entry) === host)
      ?? REGISTRY_CATALOG.find((entry) => host && templateHost(entry) === host);
    return branded ?? CATALOG.find((entry) => entry.id === 'mcp');
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

/**
 * The branded template covering a connection, when its pinned host matches
 * a template's published endpoint. Feeds the status check's expectations
 * (whoami tool, expected tools) and the reconnect flow.
 */
export function mcpTemplateForConnection(connection: ConnectionSummary): McpTemplate | undefined {
  if (connection.type !== 'api' || !connection.mcp_path) return undefined;
  const host = (connection.host || '').toLowerCase();
  if (!host) return undefined;
  return (CATALOG.find((entry) => entry.mcp && templateHost(entry) === host)
    ?? REGISTRY_CATALOG.find((entry) => templateHost(entry) === host))?.mcpTemplate;
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
function matchesQuery(entry: CatalogEntry, needle: string): boolean {
  return entry.name.toLowerCase().includes(needle) ||
    entry.description.toLowerCase().includes(needle) ||
    entry.id.includes(needle) ||
    (entry.keywords || []).some((keyword) => keyword.toLowerCase().includes(needle));
}

export function filterCatalog(query: string): CatalogEntry[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return CATALOG;
  return CATALOG.filter((entry) => matchesQuery(entry, needle));
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
  const needle = query.trim().toLowerCase();
  const curated = filterCatalog(query).filter((entry) => {
    if (entry.id !== 'websocket' || visibility.showWebsockets) return true;
    return connectionsForEntry(entry, visibility.connections).length > 0;
  });
  // The registry tail stays out of the default view — search brings it in,
  // and a row with something configured under it must never be invisible.
  const registry = REGISTRY_CATALOG.filter((entry) =>
    needle
      ? matchesQuery(entry, needle)
      : connectionsForEntry(entry, visibility.connections).length > 0);
  return [...curated, ...registry];
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
