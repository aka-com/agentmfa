#!/usr/bin/env node
// Regenerate ui/src/registry-data.ts from the public MCP registry.
//
//   node scripts/registry/sync-mcp-registry.mjs [--limit N] [--dry-run]
//
// Keeps only servers that publish a *remote streamable-HTTP* endpoint —
// the transport the broker speaks — newest version per server name, and
// skips endpoints already covered by the curated catalog (GitHub, Notion).
// The output is static display data: name, endpoint, keywords. Nothing
// executable and no auth material ever lands in the file; connecting still
// runs the broker's own discovery + sign-in against the (editable) URL.

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REGISTRY = 'https://registry.modelcontextprotocol.io/v0/servers';
const OUT = join(dirname(fileURLToPath(import.meta.url)), '../../ui/src/registry-data.ts');

// Hosts the curated catalog already brands; the registry tail must not
// duplicate them.
const CURATED_HOSTS = new Set(['api.githubcopilot.com', 'mcp.notion.com']);

// Brand marks bundled in ui/src/brand-icons.ts, by lowercased brand name.
const KNOWN_ICONS = new Set([
  'airtable', 'anthropic', 'asana', 'atlassian', 'figma', 'github', 'gmail',
  'hubspot', 'huggingface', 'intercom', 'neon', 'notion', 'linear',
  'onepassword', 'openai', 'paypal', 'postgres', 'sentry', 'slack', 'square',
  'stripe', 'vercel',
]);

// Registry display names do not always match the bundled icon key, and a
// few products are better served by a distinct Lucide metaphor than `plug`.
const ICON_BY_SLUG = new Map([
  ['canva', 'palette'],
  ['context7', 'library'],
  ['deepwiki', 'bookOpen'],
  ['globalping', 'radioTower'],
  ['hugging-face', 'huggingface'],
  ['semgrep', 'scanSearch'],
]);

const args = process.argv.slice(2);
const limit = Number(args[args.length - 1]) || (args.includes('--limit')
  ? Number(args[args.indexOf('--limit') + 1]) || 500 : 500);
const dryRun = args.includes('--dry-run');

async function fetchAll() {
  const servers = [];
  let cursor = null;
  do {
    const url = new URL(REGISTRY);
    url.searchParams.set('limit', '100');
    if (cursor) url.searchParams.set('cursor', cursor);
    const response = await fetch(url, { headers: { accept: 'application/json' } });
    if (!response.ok) throw new Error(`registry answered HTTP ${response.status}`);
    const page = await response.json();
    servers.push(...(page.servers ?? []));
    cursor = page.metadata?.next_cursor ?? page.metadata?.nextCursor ?? null;
  } while (cursor && servers.length < limit);
  return servers;
}

/** The server's remote streamable-HTTP endpoint, when it has one. */
function streamableRemote(server) {
  const remotes = server.remotes ?? server.server?.remotes ?? [];
  const remote = remotes.find((entry) =>
    (entry.type ?? entry.transport_type) === 'streamable-http'
    || (entry.type ?? entry.transport_type) === 'streamable_http');
  const url = remote?.url;
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return null;
    if (parsed.username || parsed.password || parsed.search) return null;
    return parsed;
  } catch {
    return null;
  }
}

function slug(value) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

function displayName(server) {
  // Registry names are reverse-DNS (io.github.owner/name); the tail after
  // the slash reads best, title-cased.
  const raw = (server.name ?? server.server?.name ?? '').split('/').pop() ?? '';
  return raw
    .split(/[-_.]/)
    .filter(Boolean)
    .map((word) => word[0].toUpperCase() + word.slice(1))
    .join(' ');
}

function keywords(server) {
  const description = (server.description ?? server.server?.description ?? '').toLowerCase();
  // Cheap keyword harvest: distinctive words from the description.
  return [...new Set(description.match(/[a-z]{4,}/g) ?? [])]
    .filter((word) => !['with', 'from', 'your', 'that', 'this', 'server', 'model',
      'context', 'protocol', 'official', 'hosted'].includes(word))
    .slice(0, 6);
}

const servers = await fetchAll();
const seen = new Set();
const rows = [];
for (const server of servers) {
  const url = streamableRemote(server);
  if (!url) continue;
  const host = url.hostname.toLowerCase();
  if (CURATED_HOSTS.has(host) || seen.has(host)) continue;
  const status = server.status ?? server._meta?.status ?? 'active';
  if (status === 'deleted' || status === 'deprecated') continue;
  const name = displayName(server);
  if (!name) continue;
  const nameSlug = slug(name);
  seen.add(host);
  rows.push({
    id: `mcp-${nameSlug}`,
    name,
    icon: ICON_BY_SLUG.get(nameSlug) ?? (KNOWN_ICONS.has(nameSlug) ? nameSlug : 'plug'),
    description: (server.description ?? server.server?.description ?? '').slice(0, 100)
      || 'Hosted MCP server',
    serverUrl: url.toString(),
    keywords: keywords(server),
  });
  if (rows.length >= limit) break;
}
rows.sort((a, b) => a.name.localeCompare(b.name));

const banner = `// Hosted remote MCP servers from the public MCP registry.
//
// GENERATED DATA — refresh with \`node scripts/registry/sync-mcp-registry.mjs\`
// (it rewrites this file from registry.modelcontextprotocol.io, keeping only
// servers that publish a remote streamable-HTTP endpoint).
//
// Static data only: names, endpoints, and search keywords. Nothing here is
// hidden configuration — the endpoint is prefilled into the add form where
// it stays visible and editable, and connecting still runs the ordinary
// sign-in (or paste-a-token) flow with the broker's own discovery.

/** One hosted MCP server the catalog can offer beyond the curated rows. */
export interface RegistryServer {
  /** Catalog row id; \`mcp-\` prefixed so it never collides with curated rows. */
  id: string;
  name: string;
  /** Key into ICONS; brands without a bundled mark fall back to \`plug\`. */
  icon: string;
  description: string;
  /** The vendor's published streamable-HTTP MCP endpoint. */
  serverUrl: string;
  keywords: string[];
}

export const REGISTRY_SERVERS: RegistryServer[] = `;

const body = JSON.stringify(rows, null, 2)
  .replace(/"([a-zA-Z_]+)":/g, '$1:')
  .replace(/"/g, "'");
const output = `${banner}${body};\n`;

if (dryRun) {
  console.log(output);
} else {
  writeFileSync(OUT, output);
  console.log(`wrote ${rows.length} servers to ${OUT}`);
}
