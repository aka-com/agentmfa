// Hosted remote MCP servers from the public MCP registry.
//
// GENERATED DATA — refresh with `node scripts/registry/sync-mcp-registry.mjs`
// (it rewrites this file from registry.modelcontextprotocol.io, keeping only
// servers that publish a remote streamable-HTTP endpoint). The current
// contents are a hand-checked seed snapshot of well-known first-party hosted
// servers; the sync script exists so this list can grow from the public
// index instead of by hand.
//
// Static data only: names, endpoints, and search keywords. Nothing here is
// hidden configuration — the endpoint is prefilled into the add form where
// it stays visible and editable, and connecting still runs the ordinary
// sign-in (or paste-a-token) flow with the broker's own discovery.

/** One hosted MCP server the catalog can offer beyond the curated rows. */
export interface RegistryServer {
  /** Catalog row id; `mcp-` prefixed so it never collides with curated rows. */
  id: string;
  name: string;
  /** Key into ICONS; brands without a bundled mark fall back to `plug`. */
  icon: string;
  description: string;
  /** The vendor's published streamable-HTTP MCP endpoint. */
  serverUrl: string;
  keywords: string[];
}

export const REGISTRY_SERVERS: RegistryServer[] = [
  {
    id: 'mcp-linear',
    name: 'Linear',
    icon: 'linear',
    description: 'Issues, projects & cycles — official hosted MCP',
    serverUrl: 'https://mcp.linear.app/mcp',
    keywords: ['issues', 'tickets', 'projects', 'sprint'],
  },
  {
    id: 'mcp-sentry',
    name: 'Sentry',
    icon: 'sentry',
    description: 'Errors, issues & releases — official hosted MCP',
    serverUrl: 'https://mcp.sentry.dev/mcp',
    keywords: ['errors', 'crashes', 'monitoring', 'issues'],
  },
  {
    id: 'mcp-stripe',
    name: 'Stripe',
    icon: 'stripe',
    description: 'Payments, customers & invoices — official hosted MCP',
    serverUrl: 'https://mcp.stripe.com/',
    keywords: ['payments', 'billing', 'charges', 'invoices'],
  },
  {
    id: 'mcp-vercel',
    name: 'Vercel',
    icon: 'vercel',
    description: 'Deployments, projects & domains — official hosted MCP',
    serverUrl: 'https://mcp.vercel.com/',
    keywords: ['deploy', 'hosting', 'domains', 'frontend'],
  },
  {
    id: 'mcp-paypal',
    name: 'PayPal',
    icon: 'plug',
    description: 'Payments & invoicing — official hosted MCP',
    serverUrl: 'https://mcp.paypal.com/mcp',
    keywords: ['payments', 'invoices', 'checkout'],
  },
  {
    id: 'mcp-intercom',
    name: 'Intercom',
    icon: 'plug',
    description: 'Customer conversations & tickets — official hosted MCP',
    serverUrl: 'https://mcp.intercom.com/mcp',
    keywords: ['support', 'chat', 'customers', 'helpdesk'],
  },
  {
    id: 'mcp-neon',
    name: 'Neon',
    icon: 'plug',
    description: 'Serverless Postgres — official hosted MCP',
    serverUrl: 'https://mcp.neon.tech/mcp',
    keywords: ['database', 'postgres', 'sql', 'branching'],
  },
  {
    id: 'mcp-huggingface',
    name: 'Hugging Face',
    icon: 'plug',
    description: 'Models, datasets & Spaces — official hosted MCP',
    serverUrl: 'https://huggingface.co/mcp',
    keywords: ['ml', 'models', 'datasets', 'ai', 'spaces'],
  },
  {
    id: 'mcp-deepwiki',
    name: 'DeepWiki',
    icon: 'plug',
    description: 'Ask questions about public GitHub repositories',
    serverUrl: 'https://mcp.deepwiki.com/mcp',
    keywords: ['docs', 'code', 'repos', 'research'],
  },
  {
    id: 'mcp-context7',
    name: 'Context7',
    icon: 'plug',
    description: 'Up-to-date library documentation for prompts',
    serverUrl: 'https://mcp.context7.com/mcp',
    keywords: ['docs', 'libraries', 'code', 'reference'],
  },
  {
    id: 'mcp-semgrep',
    name: 'Semgrep',
    icon: 'plug',
    description: 'Static analysis & security scanning — official hosted MCP',
    serverUrl: 'https://mcp.semgrep.ai/mcp',
    keywords: ['security', 'lint', 'sast', 'scanning'],
  },
  {
    id: 'mcp-globalping',
    name: 'Globalping',
    icon: 'plug',
    description: 'Network measurements from probes worldwide',
    serverUrl: 'https://mcp.globalping.dev/mcp',
    keywords: ['network', 'ping', 'latency', 'traceroute', 'dns'],
  },
];
