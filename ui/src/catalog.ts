// The tool catalog: the static registry behind the "Add tools" screen.
//
// Connections are stored by protocol (api/pg/ws/ssh); the catalog presents
// them as tools grouped into sections. Each entry either maps to a
// connection type the broker serves today (`via: 'connection'`) or fronts
// a built-in store (`via: 'builtin'` — the Keychain-backed saved
// credentials).
//
// Branded apps (GitHub, Gmail, Notion, …) are `mcp: true`: they are
// richer than a single credentialed origin, so they are added by pointing
// at that service's MCP server. Underneath they are still API connections —
// same pinned host, same credential injected on the upstream leg — with an
// MCP path set, which is what lets the sidecar re-expose their tools.
//
// Vendors with an *official, documented* hosted MCP server carry an
// `mcpTemplate`: the server URL is prefilled (still editable), and the
// whoami tool (when the server has one) acknowledges which account a
// credential belongs to. A vendor whose authorization server has no
// dynamic client registration (Gmail) adds an `oauthApp` block so the
// form collects a one-time OAuth client before sign-in.
//
// Branded API rows (Stripe, OpenAI, …) carry a `preset` instead: the
// vendor's *documented public API root* and auth recipe, prefilled into the
// add form where they stay visible and editable. Like template endpoints,
// these roots are the vendor's published contract, and the user still sees
// exactly what gets pinned before saving.

import type { ConnectionSummary, ConnectionType } from './types';
import { REGISTRY_SERVERS } from './registry-data';

export type CatalogSection =
  | 'MCP Apps' | 'Custom Apps' | 'Infrastructure' | 'Secrets'
  | 'API Apps';

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
  /** Display-name fallback for consumers outside the catalog row. */
  name: string;
  /** Where to create or find the credential (opened as an external link). */
  docsUrl?: string;
  /** Placeholder for the credential value input, e.g. 'sk_live_…'. */
  credentialHint?: string;
}

/**
 * Prefill for a browser sign-in against the user's own OAuth app (BYO-app
 * loopback PKCE) on a plain REST row: the provider's documented endpoints
 * and sensible default scopes, all editable in the form.
 */
export interface OAuthPreset {
  authUrl: string;
  tokenUrl: string;
  /** Default scopes, offered as checkboxes (all on by default). */
  scopes: string[];
  /** Extra authorize-URL params some providers need for a refresh token. */
  extraAuthParams?: Array<[string, string]>;
  /** Where to create the OAuth app (shown as plain text, not a link). */
  appDocsUrl?: string;
}

/**
 * A branded MCP server the catalog knows how to reach and talk to.
 *
 * `serverUrl` is the vendor's published endpoint, prefilled into the add
 * form but always editable. `whoamiTool` names the tool that identifies
 * the connected account, so the status check can acknowledge it.
 */
export interface McpTemplate {
  serverUrl?: string;
  whoamiTool?: string;
  /** Copy shown under the URL field in the add form. */
  urlHint?: string;
  /**
   * Set when the vendor's authorization server has no dynamic client
   * registration: the user creates an OAuth client with the provider once
   * and pastes its ID (and secret) into the add form. Everything else —
   * discovery, browser consent, token storage, refresh — stays the
   * standard flow.
   */
  oauthApp?: {
    /** Where to create the OAuth client (shown as plain text). */
    docsUrl?: string;
    /** Scopes to request instead of everything the server advertises. */
    scopes?: string[];
    /** Extra authorize-URL params (e.g. Google's access_type=offline). */
    extraAuthParams?: Array<[string, string]>;
  };
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
  /** Branded MCP details (endpoint, whoami, OAuth-app prefill). */
  mcpTemplate?: McpTemplate;
  /** BYO-app OAuth prefill for a plain REST row; see OAuthPreset. */
  oauthPreset?: OAuthPreset;
  /** Requires provider-side configuration before it can be connected. */
  requiresSetup?: boolean;
  /** Extra search terms ("payments", "email") the row answers to. */
  keywords?: string[];
  /** From the generated MCP-registry tail, not the curated catalog. */
  registry?: boolean;
  /**
   * The vendor only admits pre-whitelisted OAuth clients, so connecting may
   * be refused for us. Shown as a "Limited support" badge on the row.
   */
  limitedSupport?: boolean;
  /** Announced but not yet available: rendered grayed out with no action. */
  disabled?: boolean;
}

export const CATALOG: CatalogEntry[] = [
  {
    id: 'github',
    name: 'GitHub',
    icon: 'github',
    description: 'Repos, issues, PRs',
    section: 'MCP Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
    keywords: ['git', 'repos', 'issues', 'pull requests', 'code'],
    mcpTemplate: {
      serverUrl: 'https://api.githubcopilot.com/mcp/',
      whoamiTool: 'get_me',
      urlHint: 'GitHub’s hosted MCP server. Sign in with your GitHub account, or paste a personal access token.',
    },
  },
  {
    id: 'slack',
    name: 'Slack',
    icon: 'slack',
    description: 'Messages, channels & users',
    section: 'MCP Apps',
    via: 'connection',
    connType: 'api',
    requiresSetup: true,
    keywords: ['chat', 'messages', 'channels', 'team'],
    preset: {
      origin: 'https://slack.com',
      authMode: 'bearer',
      name: 'Slack',
      docsUrl: 'api.slack.com/apps',
      credentialHint: 'xoxb-…',
    },
    oauthPreset: {
      authUrl: 'https://slack.com/oauth/v2/authorize',
      tokenUrl: 'https://slack.com/api/oauth.v2.access',
      scopes: ['channels:history', 'channels:read', 'chat:write', 'users:read'],
      appDocsUrl: 'api.slack.com/apps (create an app, add a redirect URL later)',
    },
  },
  {
    id: 'gmail',
    name: 'Gmail',
    icon: 'gmail',
    description: 'Read & send email',
    section: 'MCP Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
    requiresSetup: true,
    keywords: ['email', 'mail', 'google', 'inbox'],
    // Google's hosted Gmail MCP server uses plain OAuth 2.0 — no dynamic
    // client registration — so connecting takes a one-time OAuth client
    // ("Desktop app" type, which allows loopback redirects on any port)
    // created in the user's own Google Cloud console.
    mcpTemplate: {
      serverUrl: 'https://gmailmcp.googleapis.com/mcp/v1',
      urlHint: 'Google’s hosted Gmail MCP server. Needs a one-time OAuth client from your Google Cloud console; then sign in with your Google account.',
      oauthApp: {
        docsUrl: 'console.cloud.google.com/apis/credentials (create an OAuth client, type “Desktop app”)',
        scopes: [
          'https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.compose',
        ],
        extraAuthParams: [['access_type', 'offline'], ['prompt', 'consent']],
      },
    },
  },
  {
    id: 'notion',
    name: 'Notion',
    icon: 'notion',
    description: 'Pages & databases',
    section: 'MCP Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
    keywords: ['docs', 'wiki', 'notes', 'pages'],
    mcpTemplate: {
      serverUrl: 'https://mcp.notion.com/mcp',
      whoamiTool: 'notion-get-self',
      urlHint: 'Notion’s hosted MCP server. Sign in with your Notion account to pick the workspace.',
    },
  },
  {
    id: 'airtable',
    name: 'Airtable',
    icon: 'airtable',
    description: 'Bases, tables & records',
    section: 'MCP Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
    keywords: ['spreadsheet', 'tables', 'records', 'bases'],
    mcpTemplate: {
      serverUrl: 'https://mcp.airtable.com/mcp',
      whoamiTool: 'whoami',
      urlHint: 'Airtable’s hosted MCP server. Sign in with your Airtable account, or paste a personal access token.',
    },
    preset: {
      origin: 'https://api.airtable.com',
      authMode: 'bearer',
      name: 'Airtable',
      docsUrl: 'airtable.com/create/tokens',
      credentialHint: 'pat…',
    },
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    icon: 'anthropic',
    description: 'Claude models & messages',
    section: 'API Apps',
    via: 'connection',
    connType: 'api',
    keywords: ['claude', 'llm', 'ai', 'models'],
    preset: {
      origin: 'https://api.anthropic.com',
      authMode: 'header',
      authDetail: 'x-api-key',
      name: 'Anthropic',
      docsUrl: 'console.anthropic.com/settings/keys',
      credentialHint: 'sk-ant-…',
    },
  },
  {
    id: 'openai',
    name: 'OpenAI',
    icon: 'openai',
    description: 'GPT models & responses',
    section: 'API Apps',
    via: 'connection',
    connType: 'api',
    keywords: ['gpt', 'llm', 'ai', 'models'],
    preset: {
      origin: 'https://api.openai.com',
      authMode: 'bearer',
      name: 'OpenAI',
      docsUrl: 'platform.openai.com/api-keys',
      credentialHint: 'sk-…',
    },
  },
  {
    id: 'linear',
    name: 'Linear',
    icon: 'linear',
    description: 'Issues, projects & cycles',
    section: 'MCP Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
    keywords: ['issues', 'tickets', 'projects', 'sprint'],
    // Linear's server has no whoami-style tool (identity is a resource,
    // linear://viewer), so the template carries expectations only.
    mcpTemplate: {
      serverUrl: 'https://mcp.linear.app/mcp',
      urlHint: 'Linear’s hosted MCP server. Sign in with your Linear account, or paste an API key.',
    },
    preset: {
      origin: 'https://api.linear.app',
      authMode: 'header',
      authDetail: 'Authorization',
      name: 'Linear',
      docsUrl: 'linear.app/settings/api',
      credentialHint: 'lin_api_…',
    },
    oauthPreset: {
      authUrl: 'https://linear.app/oauth/authorize',
      tokenUrl: 'https://api.linear.app/oauth/token',
      scopes: ['read', 'write'],
      appDocsUrl: 'linear.app/settings/api/applications',
    },
  },
  {
    id: 'sentry',
    name: 'Sentry',
    icon: 'sentry',
    description: 'Errors, issues & releases',
    section: 'MCP Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
    keywords: ['errors', 'crashes', 'monitoring', 'issues'],
    mcpTemplate: {
      serverUrl: 'https://mcp.sentry.dev/mcp',
      whoamiTool: 'whoami',
      urlHint: 'Sentry’s hosted MCP server. Sign in with your Sentry account, or paste an auth token.',
    },
    preset: {
      origin: 'https://sentry.io',
      authMode: 'bearer',
      name: 'Sentry',
      docsUrl: 'sentry.io/settings/account/api/auth-tokens',
      credentialHint: 'sntrys_…',
    },
  },
  {
    id: 'stripe',
    name: 'Stripe',
    icon: 'stripe',
    description: 'Payments, customers & invoices',
    section: 'MCP Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
    keywords: ['payments', 'billing', 'charges', 'invoices'],
    mcpTemplate: {
      serverUrl: 'https://mcp.stripe.com/',
      whoamiTool: 'get_stripe_account_info',
      urlHint: 'Stripe’s hosted MCP server. Sign in with your Stripe account, or paste a restricted API key.',
    },
    preset: {
      origin: 'https://api.stripe.com',
      authMode: 'bearer',
      name: 'Stripe',
      docsUrl: 'dashboard.stripe.com/apikeys',
      credentialHint: 'sk_live_… or rk_live_…',
    },
  },
  {
    id: 'vercel',
    name: 'Vercel',
    icon: 'vercel',
    // Vercel's hosted MCP (mcp.vercel.com) only accepts Vercel-approved
    // clients, so the API key stays the reliable path; the MCP row lives in
    // the registry tail for anyone allowlisted.
    description: 'Deployments, projects & domains',
    section: 'API Apps',
    via: 'connection',
    connType: 'api',
    keywords: ['deploy', 'hosting', 'domains', 'frontend'],
    preset: {
      origin: 'https://api.vercel.com',
      authMode: 'bearer',
      name: 'Vercel',
      docsUrl: 'vercel.com/account/settings/tokens',
      credentialHint: 'Vercel access token',
    },
  },
  {
    id: 'cloudflare',
    name: 'Cloudflare',
    icon: 'cloudflare',
    description: 'DNS, Workers & zone config',
    section: 'MCP Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
    keywords: ['dns', 'cdn', 'workers', 'zones', 'edge', 'r2'],
    // Cloudflare's unified server fronts the whole API through two
    // Code-Mode tools (search + execute); there is no whoami-style tool.
    mcpTemplate: {
      serverUrl: 'https://mcp.cloudflare.com/mcp',
      urlHint: 'Cloudflare’s hosted MCP server for the full API. Sign in with your Cloudflare account, or paste an API token.',
    },
  },
  {
    id: 'mcp',
    name: 'MCP server',
    icon: 'plug',
    description: 'Any MCP server, by URL',
    section: 'Custom Apps',
    via: 'connection',
    connType: 'api',
    mcp: true,
    keywords: ['server', 'tools', 'model context protocol'],
  },
  {
    id: 'http',
    name: 'Custom API',
    icon: 'globe',
    description: 'Any credentialed REST API',
    section: 'Custom Apps',
    via: 'connection',
    connType: 'api',
    keywords: ['rest', 'http', 'endpoint'],
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
    id: 'credentials',
    name: 'Saved credentials',
    icon: 'keyRound',
    description: 'API keys, passwords, and private keys in your Keychain',
    section: 'Secrets',
    via: 'builtin',
    keywords: ['secrets', 'tokens', 'keychain'],
  },
  {
    id: 'onepassword-vault',
    name: '1Password Vault',
    icon: 'onepassword',
    description: 'Bring secrets from your 1Password vaults',
    section: 'Secrets',
    via: 'builtin',
    disabled: true,
    keywords: ['1password', 'vault', 'op'],
  },
];

export const CATALOG_SECTIONS: CatalogSection[] =
  ['Infrastructure', 'MCP Apps', 'API Apps', 'Custom Apps', 'Secrets'];

/**
 * The registry tail: hosted MCP servers from the public index, each an
 * ordinary addable MCP row (OAuth-first, endpoint prefilled but editable),
 * shown after the curated rows in the combined MCP Apps section. Some
 * brands appear twice — a curated REST preset row and a hosted-MCP row.
 */
export const REGISTRY_CATALOG: CatalogEntry[] = REGISTRY_SERVERS.map((server) => ({
  id: server.id,
  name: server.name,
  icon: server.icon,
  description: server.description,
  section: 'MCP Apps',
  via: 'connection',
  connType: 'api',
  mcp: true,
  registry: true,
  limitedSupport: server.limitedSupport,
  keywords: [...server.keywords, 'mcp', 'registry'],
  mcpTemplate: {
    serverUrl: server.serverUrl,
    urlHint: 'The vendor’s published MCP endpoint, from the public MCP registry. Sign in, or paste a token.',
  },
}));

/** Every row Add can act on: the curated catalog plus the registry tail. */
export function catalogEntryById(id: string): CatalogEntry | undefined {
  return CATALOG.find((entry) => entry.id === id)
    ?? REGISTRY_CATALOG.find((entry) => entry.id === id);
}

/**
 * A known MCP endpoint can begin server discovery and OAuth immediately.
 * A template needing a pre-registered OAuth client can't: the add form
 * must collect the client ID first.
 */
export function canQuickConnectMcp(entry: CatalogEntry): boolean {
  return Boolean(entry.mcp && entry.mcpTemplate?.serverUrl && !entry.mcpTemplate.oauthApp);
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
 * Product-facing identity and edit policy for a stored connection.
 *
 * OAuth-managed remote MCP servers are API connections internally, but the
 * edit sheet should keep their catalog identity and hide the mutable
 * credential-template implementation detail.
 */
export function connectionEditPresentation(connection: ConnectionSummary): {
  label: string;
  managedMcpOAuth: boolean;
} {
  return {
    label: entryForConnection(connection)?.name ?? catalogNameForType(connection.type),
    managedMcpOAuth: connection.type === 'api'
      && Boolean(connection.mcp_path)
      && connection.oauth,
  };
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

/** Connected rows first, then setup-required rows, preserving catalog order within each set. */
export function connectedCatalogFirst(
  entries: CatalogEntry[],
  connections: ConnectionSummary[],
): CatalogEntry[] {
  const disconnected = entries.filter(
    (entry) => connectionsForEntry(entry, connections).length === 0,
  );
  return [
    ...entries.filter((entry) => connectionsForEntry(entry, connections).length > 0),
    ...disconnected.filter((entry) => entry.requiresSetup),
    ...disconnected.filter((entry) => !entry.requiresSetup),
  ];
}

export interface CollapsedCatalogGroup {
  visible: CatalogEntry[];
  hiddenCount: number;
}

/**
 * Keep every connected row visible, then fill to the group's minimum size.
 * `connectedCatalogFirst` makes both halves stable in catalog order.
 */
export function collapsedCatalogGroup(
  entries: CatalogEntry[],
  connections: ConnectionSummary[],
  minimumVisible = 3,
): CollapsedCatalogGroup {
  const ordered = connectedCatalogFirst(entries, connections);
  const connectedCount = ordered.filter(
    (entry) => connectionsForEntry(entry, connections).length > 0,
  ).length;
  const visibleCount = Math.min(ordered.length, Math.max(minimumVisible, connectedCount));
  return {
    visible: ordered.slice(0, visibleCount),
    hiddenCount: ordered.length - visibleCount,
  };
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

/** The curated and registry rows matching the search filter. */
export function visibleCatalog(query: string): CatalogEntry[] {
  const needle = query.trim().toLowerCase();
  const registry = needle
    ? REGISTRY_CATALOG.filter((entry) => matchesQuery(entry, needle))
    : REGISTRY_CATALOG;
  return [...filterCatalog(query), ...registry];
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
