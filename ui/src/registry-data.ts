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
  /**
   * The vendor only admits pre-whitelisted OAuth clients, so connecting may
   * be refused for us. Surfaced as a "Limited support" badge on the row.
   */
  limitedSupport?: boolean;
}

export const REGISTRY_SERVERS: RegistryServer[] = [
  {
    id: 'mcp-vercel',
    name: 'Vercel',
    icon: 'vercel',
    description: 'Deployments, projects & domains',
    serverUrl: 'https://mcp.vercel.com/',
    keywords: ['deploy', 'hosting', 'domains', 'frontend'],
    limitedSupport: true,
  },
  {
    id: 'mcp-figma',
    name: 'Figma',
    icon: 'figma',
    description: 'Design files & components',
    serverUrl: 'https://mcp.figma.com/mcp',
    keywords: ['design', 'ui', 'prototypes', 'components'],
    limitedSupport: true,
  },
  {
    id: 'mcp-atlassian',
    name: 'Atlassian',
    icon: 'atlassian',
    description: 'Jira, Confluence & Compass',
    serverUrl: 'https://mcp.atlassian.com/v1/mcp',
    keywords: ['jira', 'confluence', 'tickets', 'wiki', 'issues'],
  },
  {
    id: 'mcp-asana',
    name: 'Asana',
    icon: 'asana',
    description: 'Tasks, projects & goals',
    serverUrl: 'https://mcp.asana.com/v2/mcp',
    keywords: ['tasks', 'projects', 'work management'],
  },
  {
    id: 'mcp-hubspot',
    name: 'HubSpot',
    icon: 'hubspot',
    description: 'CRM contacts, deals & tickets',
    serverUrl: 'https://mcp.hubspot.com/',
    keywords: ['crm', 'contacts', 'deals', 'marketing'],
  },
  {
    id: 'mcp-square',
    name: 'Square',
    icon: 'square',
    description: 'Payments, orders & inventory',
    serverUrl: 'https://mcp.squareup.com/mcp',
    keywords: ['payments', 'pos', 'orders', 'inventory'],
  },
  {
    id: 'mcp-canva',
    name: 'Canva',
    icon: 'palette',
    description: 'Designs, assets & exports',
    serverUrl: 'https://mcp.canva.com/mcp',
    keywords: ['design', 'graphics', 'templates', 'assets'],
  },
  {
    id: 'mcp-paypal',
    name: 'PayPal',
    icon: 'paypal',
    description: 'Payments & invoicing',
    serverUrl: 'https://mcp.paypal.com/mcp',
    keywords: ['payments', 'invoices', 'checkout'],
  },
  {
    id: 'mcp-intercom',
    name: 'Intercom',
    icon: 'intercom',
    description: 'Customer conversations & tickets',
    serverUrl: 'https://mcp.intercom.com/mcp',
    keywords: ['support', 'chat', 'customers', 'helpdesk'],
  },
  {
    id: 'mcp-neon',
    name: 'Neon',
    icon: 'neon',
    description: 'Serverless Postgres',
    serverUrl: 'https://mcp.neon.tech/mcp',
    keywords: ['database', 'postgres', 'sql', 'branching'],
  },
  {
    id: 'mcp-huggingface',
    name: 'Hugging Face',
    icon: 'huggingface',
    description: 'Models, datasets & Spaces',
    serverUrl: 'https://huggingface.co/mcp',
    keywords: ['ml', 'models', 'datasets', 'ai', 'spaces'],
  },
  {
    id: 'mcp-semgrep',
    name: 'Semgrep',
    icon: 'scanSearch',
    description: 'Static analysis & security scanning',
    serverUrl: 'https://mcp.semgrep.ai/mcp',
    keywords: ['security', 'lint', 'sast', 'scanning'],
  },
  {
    id: 'mcp-globalping',
    name: 'Globalping',
    icon: 'radioTower',
    description: 'Network measurements from probes worldwide',
    serverUrl: 'https://mcp.globalping.dev/mcp',
    keywords: ['network', 'ping', 'latency', 'traceroute', 'dns'],
  },
];
