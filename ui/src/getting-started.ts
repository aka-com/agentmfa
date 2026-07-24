// The Get started walkthrough: pick what you want your agent to reach, then
// three steps that mirror how the broker actually works — add the tool,
// register the agent, wire them together and ask for something worth having.
//
// The copy lives here (rather than inline in the renderer) so the prompts and
// the progress rules are testable on their own.

import { catalogEntryById, connectionsForEntry } from './catalog';
import type { ConnectionSummary, ConnectionType } from './types';

export interface StartOption {
  id: string;
  /** Label on the small picker row. */
  label: string;
  /** Key into the shared icon set. */
  icon: string;
  /** Custom MCP keeps its label visible; branded choices use their logo. */
  showPickerLabel?: boolean;
  /** Connection type this sets up. */
  connType: ConnectionType | null;
  /** Catalog row the Add button opens. */
  catalogId: string | null;
  /** This option is backed by an MCP connection. */
  mcp?: boolean;
  /**
   * The first ask's body — chosen to be immediately useful, not a
   * hello-world. The lead-in (the broker tool's name, or the direct
   * endpoint itself) is prepended by startTask/directStartTask.
   */
  taskBody: string;
}

export const START_OPTIONS: StartOption[] = [
  {
    id: 'postgres',
    label: 'Postgres',
    icon: 'postgres',
    connType: 'pg',
    catalogId: 'postgres',
    taskBody: `list the 10 largest tables with their row counts, and flag any foreign key that has no index.`,
  },
  {
    id: 'ssh',
    label: 'SSH',
    icon: 'terminal',
    connType: 'ssh',
    catalogId: 'ssh',
    taskBody: `report disk and memory usage, then show the last 20 lines of any log that contains errors.`,
  },
  {
    id: 'notion',
    label: 'Notion',
    icon: 'notion',
    connType: 'api',
    catalogId: 'notion',
    mcp: true,
    taskBody: `summarize the pages I changed this week and list any open action items.`,
  },
  {
    id: 'github',
    label: 'GitHub',
    icon: 'github',
    connType: 'api',
    catalogId: 'github',
    mcp: true,
    taskBody: `summarize the pull requests and issues that changed this week.`,
  },
  {
    id: 'slack',
    label: 'Slack',
    icon: 'slack',
    connType: 'api',
    catalogId: 'slack',
    taskBody: `summarize the important conversations from this week and list the decisions that were made.`,
  },
  {
    id: 'stripe',
    label: 'Stripe',
    icon: 'stripe',
    connType: 'api',
    catalogId: 'stripe',
    mcp: true,
    taskBody: `summarize payment activity from the last seven days and flag anything that needs attention.`,
  },
  {
    id: 'sentry',
    label: 'Sentry',
    icon: 'sentry',
    connType: 'api',
    catalogId: 'sentry',
    mcp: true,
    taskBody: `summarize the highest-impact unresolved issues from this week.`,
  },
  {
    id: 'vercel',
    label: 'Vercel',
    icon: 'vercel',
    connType: 'api',
    catalogId: 'mcp-vercel',
    mcp: true,
    taskBody: `summarize this week’s deployments and explain any failures.`,
  },
  {
    id: 'mcp',
    label: 'Custom MCP',
    icon: 'plug',
    showPickerLabel: true,
    connType: 'api',
    catalogId: 'mcp',
    mcp: true,
    taskBody: `list the tools it exposes, then use them to summarize what changed this week.`,
  },
];

export function startOptionById(id: string): StartOption {
  return START_OPTIONS.find((option) => option.id === id) ?? START_OPTIONS[0];
}

/**
 * The kind suffix folded into the tool's name (the Add button, aria labels):
 * MCP-backed tools say MCP, plain API integrations say API, databases and SSH
 * say nothing. Skipped when the name already carries it (Custom MCP).
 */
export function startKindLabel(option: StartOption): string {
  const kind = option.mcp ? 'MCP' : option.connType === 'api' ? 'API' : '';
  return kind && !option.label.includes(kind) ? kind : '';
}

/**
 * How the agent reaches the broker in step 2. `direct` is the per-tool
 * endpoint (a Postgres DSN or SSH agent socket) and is only offered for
 * kinds that have one; every other mode rides the shared key.
 */
export type ConnectModeId =
  | 'direct' | 'claude-code' | 'claude-desktop' | 'codex' | 'mcp' | 'cli';

export const CONNECT_MODE_LABELS: Record<ConnectModeId, string> = {
  direct: 'Direct',
  'claude-code': 'Claude Code',
  'claude-desktop': 'Claude Desktop',
  codex: 'Codex',
  mcp: 'Other MCP client',
  cli: 'Anything else (HTTP API)',
};

// Other MCP clients still have a guides card; step 2 keeps to named clients.
const SHARED_KEY_MODES: ConnectModeId[] =
  ['claude-code', 'claude-desktop', 'codex', 'cli'];

/* ---- per-client definitions -------------------------------------------- */
// One definition per client drives both step 2 of the walkthrough (the
// one-pane lead + snippet) and the Connection guides view (the full card),
// so the two surfaces can never disagree.

export type Platform = 'macos' | 'windows' | 'linux';

/** Where Claude Desktop keeps its MCP config, per platform. */
export const CLAUDE_DESKTOP_CONFIG_PATH: Record<Platform, string> = {
  macos: '~/Library/Application Support/Claude/claude_desktop_config.json',
  windows: '%APPDATA%\\Claude\\claude_desktop_config.json',
  linux: '~/.config/Claude/claude_desktop_config.json',
};

/** Broker facts the snippets interpolate. */
export interface ConnectClientEnv {
  /** Broker socket path, e.g. ~/.aka/broker.sock */
  socket: string;
  /** Shared-key token path, e.g. ~/.aka/token */
  token: string;
  platform: Platform;
}

export interface ConnectStep {
  title: string;
  detail?: string;
  /** A distinct follow-up paragraph under the main detail. */
  followup?: string;
  /** A copyable snippet, rendered monospace with a Copy button. */
  snippet?: string;
}

export interface ConnectClient {
  id: Exclude<ConnectModeId, 'direct'>;
  /** Guide-card title (the walkthrough chip uses CONNECT_MODE_LABELS). */
  name: string;
  /** Guide-card subtitle. */
  sub: string;
  /** Text fallback on the card row. */
  mark: string;
  /** Brand mark used instead of the text fallback. */
  icon?: string;
  /**
   * Activity labels that mean this client reached the broker. Absent = the
   * client names itself, so any label no listed client claims counts.
   */
  labels?: string[];
  /** One-line lead above the walkthrough pane's snippet. */
  lead: (env: ConnectClientEnv) => string;
  /** The walkthrough pane's copy-button label. */
  copyLabel: string;
  snippet: (env: ConnectClientEnv) => string;
  /** This client launches `aka mcp`, which must be installed separately. */
  requiresCli?: boolean;
  /** Its Quick Start snippet is shell commands, so CLI installation can be
   * prepended to the same runnable block. */
  inlineCliInstall?: boolean;
  /**
   * The walkthrough pane normally shows `snippet`; 'agent-setup' shows the
   * broker-generated setup message instead (guides still use `snippet`).
   */
  paneSource?: 'agent-setup';
  steps: (env: ConnectClientEnv) => ConnectStep[];
  /** A closing one-liner under the guide steps. */
  note?: string;
}

export const CLI_INSTALL_COMMAND = 'npm install -g @aka-labs/multitool';

/** Connection-guide steps include the CLI prerequisite as its own first step
 * for clients that launch the stdio bridge. */
export function connectGuideSteps(client: ConnectClient, env: ConnectClientEnv): ConnectStep[] {
  const steps = client.steps(env);
  if (!client.requiresCli) return steps;
  return [{
    title: 'Install the Multitool CLI',
    detail: 'Install the aka command globally and keep it available on PATH. Requires Node.js 22 or newer.',
    snippet: CLI_INSTALL_COMMAND,
  }, ...steps];
}

const SNIPPETS: Record<string, (env: ConnectClientEnv) => string> = {
  'claude-code': () => 'claude mcp add multitool -- aka mcp --client claude-code',
  'claude-desktop': () =>
    '{\n'
    + '  "mcpServers": {\n'
    + '    "multitool": {\n'
    + '      "command": "aka",\n'
    + '      "args": [\n'
    + '        "mcp",\n'
    + '        "--client",\n'
    + '        "claude-desktop"\n'
    + '      ]\n'
    + '    }\n'
    + '  }\n'
    + '}',
  codex: () => '[mcp_servers.multitool]\ncommand = "aka"\nargs = ["mcp", "--client", "codex"]',
  mcp: (env: ConnectClientEnv) =>
    `# the MCP URL's port moves with restarts — read mcp_url from the manifest\n`
    + `curl -fsS --unix-socket ${env.socket} http://localhost/.well-known/agent-broker.json\n\n`
    + `# connect your MCP client to mcp_url with this header\n`
    + `Authorization: Bearer $(cat ${env.token})`,
  cli: (env: ConnectClientEnv) =>
    `# discover what's available (and full API docs)\ncurl -fsS --unix-socket ${env.socket} http://localhost/instructions\n\n`
    + `# authenticated calls: one shared key for this machine\nexport MULTITOOL_TOKEN="$(cat ${env.token})"\n`
    + `curl -fsS --unix-socket ${env.socket} \\\n  -H "Authorization: Bearer $MULTITOOL_TOKEN" \\\n  -H "X-Multitool-Client: my-harness" \\\n  http://localhost/v1/connections`,
};

export const CONNECT_CLIENTS: ConnectClient[] = [
  {
    id: 'claude-code',
    name: 'Claude Code',
    sub: 'Terminal · connects over MCP',
    mark: 'CC',
    icon: 'anthropic',
    labels: ['claude-code'],
    lead: () => 'Install the Multitool CLI, then add it to Claude Code:',
    copyLabel: 'Copy',
    snippet: SNIPPETS['claude-code'],
    requiresCli: true,
    inlineCliInstall: true,
    steps: (env) => [
      {
        title: 'Add Multitool as an MCP server',
        snippet: SNIPPETS['claude-code'](env),
      },
      {
        title: 'Check for valid tools',
        detail: 'In any Claude Code session, ask it to run multitool_status to list your enabled tools.',
      },
    ],
  },
  {
    id: 'claude-desktop',
    name: 'Claude Desktop',
    sub: 'App · connects over MCP',
    mark: 'CD',
    icon: 'anthropic',
    labels: ['claude-desktop'],
    lead: (env) =>
      `Add this to ${CLAUDE_DESKTOP_CONFIG_PATH[env.platform]}, then restart Claude Desktop.`,
    copyLabel: 'Copy config',
    snippet: SNIPPETS['claude-desktop'],
    requiresCli: true,
    steps: (env) => [
      {
        title: 'Add Multitool to Claude Desktop’s config',
        detail: `Merge this into ${CLAUDE_DESKTOP_CONFIG_PATH[env.platform]}, or copy the whole file if you don’t have one yet.`,
        snippet: SNIPPETS['claude-desktop'](env),
      },
      {
        title: 'Restart Claude Desktop',
        detail: 'Multitool appears under the tools icon. Ask Claude to run multitool_status to confirm.',
      },
    ],
  },
  {
    id: 'codex',
    name: 'Codex',
    sub: 'Terminal & desktop · connects over MCP',
    mark: 'CX',
    icon: 'openai',
    labels: ['codex', 'codex-desktop'],
    lead: () => 'Add this to ~/.codex/config.toml:',
    copyLabel: 'Copy config',
    snippet: SNIPPETS.codex,
    requiresCli: true,
    steps: (env) => [
      {
        title: 'Register the MCP server',
        detail: 'Add this to ~/.codex/config.toml:',
        snippet: SNIPPETS.codex(env),
      },
      {
        title: 'Verify from a Codex session',
        detail: 'Ask Codex to call multitool_status. Your enabled tools show up as multitool_* tools.',
      },
    ],
  },
  {
    id: 'mcp',
    name: 'Other MCP client',
    sub: 'Any MCP client that speaks HTTP — no stdio needed',
    mark: '⌁',
    icon: 'plug',
    lead: () =>
      "For MCP clients that speak HTTP: connect to the broker's mcp_url with this computer's key as the bearer token.",
    copyLabel: 'Copy setup instructions',
    snippet: SNIPPETS.mcp,
    steps: (env) => [
      {
        title: 'Point your client at the broker’s MCP URL',
        detail: 'The MCP host’s loopback URL is advertised as mcp_url in the manifest (its port moves with restarts), authenticated with this computer’s key.',
        snippet: SNIPPETS.mcp(env),
      },
      {
        title: 'Or skip HTTP entirely',
        detail: 'After installing the Multitool CLI, clients that launch stdio servers can run aka mcp directly.',
        snippet: CLI_INSTALL_COMMAND,
      },
    ],
  },
  {
    id: 'cli',
    name: 'Anything else (HTTP API)',
    sub: 'curl, scripts, your own agent loop',
    mark: '>_',
    icon: 'terminal',
    lead: () => 'Paste this into any agent:',
    copyLabel: 'Copy setup instructions',
    snippet: SNIPPETS.cli,
    paneSource: 'agent-setup',
    steps: (env) => [
      {
        title: 'Point your harness at the broker',
        detail: `The socket and key live in ${env.socket.replace(/\/broker\.sock$/, '')}. Everything is plain HTTP with a bearer header.`,
        snippet: SNIPPETS.cli(env),
        followup: 'Speaking MCP over HTTP instead? See “Other MCP client” above.',
      },
    ],
  },
];

export function connectClientById(id: string): ConnectClient | undefined {
  return CONNECT_CLIENTS.find((client) => client.id === id);
}

// Labels some client claims explicitly; a self-named client matches anything else.
const CLAIMED_LABELS = new Set(CONNECT_CLIENTS.flatMap((client) => client.labels ?? []));

/** Whether an activity label counts as this client having reached the broker. */
export function clientMatchesLabel(client: ConnectClient, label: string): boolean {
  return client.labels ? client.labels.includes(label) : !CLAIMED_LABELS.has(label);
}

/** The connect modes step 2 offers for the picked tool, in display order. */
export function connectModesFor(option: StartOption): ConnectModeId[] {
  const hasDirect = option.connType === 'pg' || option.connType === 'ssh';
  return hasDirect ? ['direct', ...SHARED_KEY_MODES] : [...SHARED_KEY_MODES];
}

/** The mode step 2 shows: the picked one when offered, otherwise the first. */
export function resolveConnectMode(picked: string, option: StartOption): ConnectModeId {
  const modes = connectModesFor(option);
  return modes.includes(picked as ConnectModeId) ? (picked as ConnectModeId) : modes[0];
}

export interface StartProgress {
  /** A tool of this kind exists. */
  added: boolean;
  /** A tool of this kind is enabled for agents. */
  wired: boolean;
  /** The tool the example task should name. */
  toolName: string | null;
}

/** Live progress for the chosen option, read straight from broker state. */
export function startProgress(
  option: StartOption,
  connections: ConnectionSummary[],
): StartProgress {
  const entry = option.catalogId ? catalogEntryById(option.catalogId) : undefined;
  const matching = entry ? connectionsForEntry(entry, connections) : [];
  // Prefer showing a tool that is already usable by agents.
  const enabledTool = matching.find((connection) => connection.agent_access.enabled);
  const tool = enabledTool ?? matching[0] ?? null;
  return {
    added: matching.length > 0,
    wired: Boolean(enabledTool),
    toolName: tool ? tool.name : null,
  };
}

/** The example task, with a placeholder while no tool exists yet. */
export function startTask(option: StartOption, progress: StartProgress): string {
  return `Using my Multitool connection "${progress.toolName ?? 'my-tool'}", ${option.taskBody}`;
}

function sshAuthSockAssignment(socket: string): string {
  const quoted = socket.replace(/[\\"`$]/g, '\\$&');
  return `SSH_AUTH_SOCK="${quoted}"`;
}

/** A ready-to-run shell assignment for a persistent SSH agent socket. */
export function sshAuthSockCommand(socket: string): string {
  return `export ${sshAuthSockAssignment(socket)}`;
}

/** The configured SSH invocation, preserving imported aliases and ports. */
export function sshInvocationCommand(
  connection: {
    destination?: string | null;
    user?: string | null;
    host?: string | null;
    port?: number | null;
    target: string;
  },
): string {
  const importedDestination = connection.destination?.trim();
  const destination = importedDestination
    || (connection.user && connection.host ? `${connection.user}@${connection.host}` : connection.target);
  const port = !importedDestination && connection.port && connection.port !== 22
    ? ` -p ${connection.port}`
    : '';
  return `ssh${port} ${destination}`;
}

/** One command that uses the issued signing socket to reach its SSH target. */
export function sshDirectCommand(
  socket: string,
  connection: Parameters<typeof sshInvocationCommand>[0],
): string {
  return `${sshAuthSockAssignment(socket)} ${sshInvocationCommand(connection)}`;
}

/**
 * Resolve an issued endpoint's address. Older brokers omitted SSH's socket
 * path from connection summaries, but its stable location is derivable from
 * the broker socket directory and endpoint id.
 */
export function directEndpointAddress(
  type: ConnectionType,
  endpoint: { endpoint_id: string; dsn?: string | null } | null | undefined,
  brokerSocket: string,
): string | null {
  if (!endpoint) return null;
  if (endpoint.dsn) return endpoint.dsn;
  if (type !== 'ssh') return null;
  const slash = brokerSocket.lastIndexOf('/');
  const socketDir = slash >= 0 ? brokerSocket.slice(0, slash) : '.';
  return `${socketDir}/endpoints/${endpoint.endpoint_id}/agent.sock`;
}

/**
 * Step 3's prompt when the agent connects over the direct endpoint: the
 * lead-in hands the agent the endpoint itself — the full DSN, secret
 * included, or the issued SSH agent socket — instead of naming a broker
 * tool. Falls back to the tool-name prompt while no endpoint is issued.
 */
export function directStartTask(
  option: StartOption,
  progress: StartProgress,
  endpoint: { dsn?: string | null; sshInvocation?: string | null } | null | undefined,
): string {
  if (!endpoint) return startTask(option, progress);
  if (option.connType === 'ssh') {
    const socket = endpoint.dsn
      ? `Use this SSH agent socket: ${sshAuthSockAssignment(endpoint.dsn)}`
      : 'Use the SSH agent socket Multitool issued.';
    const connect = endpoint.sshInvocation
      ? `SSH to the server with ${endpoint.sshInvocation}`
      : 'SSH to the configured server';
    return `${socket}\n${connect}, then ${option.taskBody}`;
  }
  const lead = endpoint.dsn
    ? `Connect to this Postgres DSN: ${endpoint.dsn}`
    : `Connect to the direct endpoint Multitool issued.`;
  return `${lead}\n\nThen ${option.taskBody}`;
}

/**
 * The first ask for a freshly-added tool, keyed by its connection type. The
 * Get started walkthrough (through each option's own task) and the Tools-tab
 * "ready" nudge both resolve their prompt here, so the two can never suggest a
 * different first task for the same kind of tool.
 */
export function firstTaskPrompt(name: string, type: ConnectionType): string {
  const option = START_OPTIONS.find(
    (candidate) => ['postgres', 'ssh'].includes(candidate.id) && candidate.connType === type,
  );
  const body = option
    ? option.taskBody
    // Branded APIs and protocols without a walkthrough use a generic
    // read-only ask rather than borrowing one particular provider's copy.
    : 'make one read-only request and summarize what comes back.';
  return `Using my Multitool connection "${name}", ${body}`;
}
