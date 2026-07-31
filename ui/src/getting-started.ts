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
  /** Connection type this sets up. */
  connType: ConnectionType | null;
  /** Catalog row the Add button opens. */
  catalogId: string | null;
  /** This option is backed by an MCP connection. */
  mcp?: boolean;
  /**
   * What one connection of this kind is, in the words the service itself
   * uses — a Notion *workspace*, a GitHub *account*. Names the object of the
   * repeat action ("Connect another Notion workspace"), which is otherwise
   * the page's most ambiguous word: the tool picker sits directly above, so
   * a bare "another" reads as another service entirely.
   */
  unit: string;
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
    unit: 'Postgres database',
    taskBody: `list the 10 largest tables with their row counts, and flag any foreign key that has no index.`,
  },
  {
    id: 'ssh',
    label: 'SSH',
    icon: 'terminal',
    connType: 'ssh',
    catalogId: 'ssh',
    unit: 'SSH server',
    taskBody: `report disk and memory usage, then show the last 20 lines of any log that contains errors.`,
  },
  {
    id: 'notion',
    label: 'Notion',
    icon: 'notion',
    connType: 'api',
    catalogId: 'notion',
    mcp: true,
    unit: 'Notion workspace',
    taskBody: `summarize the pages I changed this week and list any open action items.`,
  },
  {
    id: 'github',
    label: 'GitHub',
    icon: 'github',
    connType: 'api',
    catalogId: 'github',
    mcp: true,
    unit: 'GitHub account',
    taskBody: `summarize the pull requests and issues that changed this week.`,
  },
  {
    id: 'stripe',
    label: 'Stripe',
    icon: 'stripe',
    connType: 'api',
    catalogId: 'stripe',
    mcp: true,
    unit: 'Stripe account',
    taskBody: `summarize payment activity from the last seven days and flag anything that needs attention.`,
  },
  {
    id: 'sentry',
    label: 'Sentry',
    icon: 'sentry',
    connType: 'api',
    catalogId: 'sentry',
    mcp: true,
    unit: 'Sentry organization',
    taskBody: `summarize the highest-impact unresolved issues from this week.`,
  },
  // The odd ones out sit at the bottom: Slack rides the plain API (its name
  // says so, since rows carry no kind tag), and Custom MCP is the catch-all.
  {
    id: 'slack',
    label: 'Slack API',
    icon: 'slack',
    connType: 'api',
    catalogId: 'slack',
    unit: 'Slack workspace',
    taskBody: `summarize the important conversations from this week and list the decisions that were made.`,
  },
  {
    id: 'mcp',
    label: 'Custom MCP',
    icon: 'plug',
    connType: 'api',
    catalogId: 'mcp',
    mcp: true,
    unit: 'MCP server',
    taskBody: `list the tools it exposes, then use them to summarize what changed this week.`,
  },
];

export function startOptionById(id: string): StartOption {
  return START_OPTIONS.find((option) => option.id === id) ?? START_OPTIONS[0];
}

/**
 * How a sentence names the thing being connected, the way the user thinks of
 * it. Databases and servers are things you point at, so they read as kinds
 * ("this Postgres database"); a service is a name you recognize.
 */
function startSubject(option: StartOption): string {
  return option.connType === 'pg'
    ? 'this Postgres database'
    : option.connType === 'ssh'
    ? 'this SSH server'
    : option.id === 'mcp'
    ? 'your MCP server'
    // "Slack API" names the transport on the picker row, where it sits
    // beside MCP-backed rows; in a sentence it is just Slack.
    : option.id === 'slack'
    ? 'Slack'
    : option.label;
}

/** Step 1's lead before anything exists: what the step is about to do. */
export function startAddLead(option: StartOption): string {
  return `Connect to ${startSubject(option)} via AgentMFA.`;
}

/**
 * Step 1's lead once a tool exists. The imperative no longer applies — the
 * checkmark above it says the step is finished — so the line reports what the
 * step produced, and names the tool, which is the handle step 3's prompt
 * hands the agent. Naming it is also what gives the repeat action below a
 * referent: "another" beside a named connection is plainly a second one.
 *
 * A tool agents may not call is not a finished step, whatever the badge says,
 * so that case says so rather than claiming reach it doesn't have.
 */
export function startAddedLead(option: StartOption, progress: StartProgress): string {
  const named = progress.toolName ? `“${progress.toolName}”` : 'It';
  if (!progress.wired) {
    return `${named} is connected, but agents may not call it yet — turn on`
      + ' agent access from the Tools tab.';
  }
  return `Agents reach ${startSubject(option)} as ${named} through AgentMFA.`;
}

/**
 * The label for step 1's action once a tool exists. Says what a second one
 * would be — a Notion *workspace*, an SSH *server* — because a bare "Connect
 * another" sits a few lines under the picker that swaps the whole service,
 * and reads as though it opens that instead.
 */
export function startAddAnotherLabel(option: StartOption, verb: string): string {
  return `${verb} another ${option.unit}`;
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
  mcp: 'Other MCP',
  cli: 'HTTP/API client',
};

/** How the hero sentence names each mode: “Connect to Postgres from <this>.” */
export const CONNECT_MODE_SENTENCE_LABELS: Record<ConnectModeId, string> = {
  direct: 'any database client',
  'claude-code': 'Claude Code',
  'claude-desktop': 'Claude Desktop',
  codex: 'Codex',
  mcp: 'another MCP client',
  cli: 'any HTTP client',
};

/** Direct endpoints are protocol-specific, so their hero label is too. */
export function connectModeSentenceLabel(
  mode: ConnectModeId,
  option: StartOption,
): string {
  return mode === 'direct' && option.connType === 'ssh'
    ? 'any SSH client'
    : CONNECT_MODE_SENTENCE_LABELS[mode];
}

// Every way an agent can ride the shared key, in display order.
const SHARED_KEY_MODES: ConnectModeId[] =
  ['claude-code', 'claude-desktop', 'codex', 'mcp', 'cli'];

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
  /** This client launches `mfa mcp`, which must be installed separately. */
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

export const CLI_INSTALL_COMMAND = 'npm install -g agentmfa';

/** Connection-guide steps include the CLI prerequisite as its own first step
 * for clients that launch the stdio bridge. */
export function connectGuideSteps(client: ConnectClient, env: ConnectClientEnv): ConnectStep[] {
  const steps = client.steps(env);
  if (!client.requiresCli) return steps;
  return [{
    title: 'Install the AgentMFA CLI',
    detail: 'Install the mfa command globally and keep it available on PATH. Requires Node.js 22 or newer.',
    snippet: CLI_INSTALL_COMMAND,
  }, ...steps];
}

const SNIPPETS: Record<string, (env: ConnectClientEnv) => string> = {
  'claude-code': () => 'claude mcp add agentmfa -- mfa mcp --client claude-code',
  'claude-desktop': () =>
    '{\n'
    + '  "mcpServers": {\n'
    + '    "agentmfa": {\n'
    + '      "command": "mfa",\n'
    + '      "args": [\n'
    + '        "mcp",\n'
    + '        "--client",\n'
    + '        "claude-desktop"\n'
    + '      ]\n'
    + '    }\n'
    + '  }\n'
    + '}',
  codex: () => '[mcp_servers.agentmfa]\ncommand = "mfa"\nargs = ["mcp", "--client", "codex"]',
  mcp: (env: ConnectClientEnv) =>
    `# the MCP URL's port moves with restarts — read mcp_url from the manifest\n`
    + `curl -fsS --unix-socket ${env.socket} http://localhost/.well-known/agent-broker.json\n\n`
    + `# connect your MCP client to mcp_url with this header\n`
    + `Authorization: Bearer $(cat ${env.token})`,
  cli: (env: ConnectClientEnv) =>
    `# discover what's available (and full API docs)\ncurl -fsS --unix-socket ${env.socket} http://localhost/instructions\n\n`
    + `# authenticated calls: one shared key for this machine\nexport AGENTMFA_TOKEN="$(cat ${env.token})"\n`
    + `curl -fsS --unix-socket ${env.socket} \\\n  -H "Authorization: Bearer $AGENTMFA_TOKEN" \\\n  -H "X-AgentMFA-Client: my-harness" \\\n  http://localhost/v1/connections`,
};

export const CONNECT_CLIENTS: ConnectClient[] = [
  {
    id: 'claude-code',
    name: 'Claude Code',
    sub: 'Terminal',
    mark: 'CC',
    icon: 'anthropic',
    labels: ['claude-code'],
    lead: () => 'Install the AgentMFA CLI, then add it to Claude Code:',
    copyLabel: 'Copy',
    snippet: SNIPPETS['claude-code'],
    requiresCli: true,
    inlineCliInstall: true,
    steps: (env) => [
      {
        title: 'Add AgentMFA as an MCP server',
        snippet: SNIPPETS['claude-code'](env),
      },
      {
        title: 'Check for valid tools',
        detail: 'In any Claude Code session, ask it to run agentmfa_status to list your enabled tools.',
      },
    ],
  },
  {
    id: 'claude-desktop',
    name: 'Claude Desktop',
    sub: 'Desktop app',
    mark: 'CD',
    icon: 'anthropic',
    labels: ['claude-desktop'],
    lead: (env) =>
      `Add this to ${CLAUDE_DESKTOP_CONFIG_PATH[env.platform]}, then restart Claude.`,
    copyLabel: 'Copy config',
    snippet: SNIPPETS['claude-desktop'],
    requiresCli: true,
    steps: (env) => [
      {
        title: 'Add AgentMFA to Claude Desktop’s config',
        detail: `Merge this into ${CLAUDE_DESKTOP_CONFIG_PATH[env.platform]}, or copy the whole file if you don’t have one yet.`,
        snippet: SNIPPETS['claude-desktop'](env),
      },
      {
        title: 'Restart Claude Desktop',
        detail: 'AgentMFA appears under the tools icon. Ask Claude to run agentmfa_status to confirm.',
      },
    ],
  },
  {
    id: 'codex',
    name: 'Codex',
    sub: 'Terminal & desktop',
    mark: 'CX',
    icon: 'openai',
    labels: ['codex', 'codex-desktop'],
    lead: () => 'Add this to ~/.codex/config.toml, then restart Codex.',
    copyLabel: 'Copy config',
    snippet: SNIPPETS.codex,
    requiresCli: true,
    steps: (env) => [
      {
        title: 'Register the MCP server',
        detail: 'Add this to ~/.codex/config.toml, then restart Codex.',
        snippet: SNIPPETS.codex(env),
      },
      {
        title: 'Verify from a Codex session',
        detail: 'Ask Codex to call agentmfa_status. Your enabled tools show up as agentmfa_* tools.',
      },
    ],
  },
  {
    id: 'mcp',
    name: 'Other MCP',
    sub: 'Any client',
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
        detail: 'After installing the AgentMFA CLI, clients that launch stdio servers can run mfa mcp directly.',
        snippet: CLI_INSTALL_COMMAND,
      },
    ],
  },
  {
    id: 'cli',
    name: 'HTTP/API client',
    sub: 'Any client',
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
        followup: 'Speaking MCP over HTTP instead? See “Other MCP” above.',
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
  return `Using my AgentMFA connection "${progress.toolName ?? 'my-tool'}", ${option.taskBody}`;
}

function sshAuthSockAssignment(socket: string): string {
  const quoted = socket.replace(/[\\"`$]/g, '\\$&');
  return `SSH_AUTH_SOCK="${quoted}"`;
}

/** A ready-to-run shell assignment for a persistent SSH agent socket. */
export function sshAuthSockCommand(socket: string): string {
  return `export ${sshAuthSockAssignment(socket)}`;
}

/**
 * The `-o` flags every emitted `ssh` invocation carries.
 *
 * `SSH_AUTH_SOCK` alone points the agent at the broker but leaves the default
 * `IdentityFile` list in place, so a working `~/.ssh/id_ed25519` can complete
 * the login with no broker involvement and no activity-log entry — a success
 * that looks brokered and is not. `IdentityFile=none` and `CertificateFile=none`
 * remove that path; the broker's agent identity is still offered, because
 * OpenSSH only filters agent keys against `IdentityFile` under
 * `IdentitiesOnly=yes` — which is why that flag is deliberately absent here
 * despite being the intuitive one to reach for.
 *
 * `ForwardAgent=no` because forwarding is unsupported: the broker refuses a
 * session-bind that admits to being forwarded, but the flag is asserted by the
 * client, so it stops an honest one and not a hostile one.
 *
 * `ControlMaster=no` because a multiplexed connection is authorized once and
 * then reused by later invocations that never contact the agent again — no
 * audit entry, no expiry, nothing to revoke.
 *
 * `ProxyJump=none` because the broker cannot authenticate a jump hop: `-J`
 * spawns a child `ssh -W` that inherits `IdentityAgent` and logs in to the
 * *jump* host, so the agent is asked to bind that host's key — and a tool pins
 * one. Leaving the jump enabled turned that into a refusal reading like a
 * host-key attack; refusing it fails at connect, where the message is about
 * routing. Kept in step with `capability::ssh::SSH_BROKER_OPTIONS` by a test.
 */
export const SSH_BROKER_OPTIONS = [
  'IdentityFile=none',
  'CertificateFile=none',
  'ForwardAgent=no',
  'ControlMaster=no',
  'ProxyJump=none',
] as const;

/** Those flags as a command-line fragment, one `-o` each. */
export function sshBrokerFlags(): string {
  return SSH_BROKER_OPTIONS.map((option) => `-o ${option}`).join(' ');
}

/**
 * The configured SSH invocation, preserving imported aliases and ports.
 *
 * An imported alias keeps its name so ~/.ssh/config still supplies the rest of
 * its settings — ProxyJump excepted, which the flags below disable because the
 * broker cannot authenticate a jump hop — but a non-default port is spelled out
 * rather than left to the alias. The port is the one resolved at import: re-point the alias at a new
 * port and this command keeps overriding it with the old one until the tool
 * is re-imported. That is the lesser surprise — deferring to the alias sends
 * the command to a port the tool was never configured for.
 */
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
  const port = connection.port && connection.port !== 22
    ? ` -p ${connection.port}`
    : '';
  return `ssh${port} ${sshBrokerFlags()} ${destination}`;
}

/** One command that uses the issued signing socket to reach its SSH target. */
export function sshDirectCommand(
  socket: string,
  connection: Parameters<typeof sshInvocationCommand>[0] & { name?: string },
  requireAuth = false,
): string {
  // An authenticated agent socket refuses a client that merely points
  // `SSH_AUTH_SOCK` at it: the ssh-agent protocol gives stock `ssh` nowhere to
  // present the endpoint secret. The forwarder is the command that works, so
  // it is the command shown — an address that cannot be used is worse than no
  // address, because it looks like a working one.
  if (requireAuth) {
    return `mfa ssh-agent ${shellWord(connection.name ?? '')} -- ${sshInvocationCommand(connection)}`;
  }
  return `${sshAuthSockAssignment(socket)} ${sshInvocationCommand(connection)}`;
}

/** One shell word: quoted only when it would otherwise split or expand. */
function shellWord(value: string): string {
  return /^[A-Za-z0-9._@%+:,/-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\''`)}'`;
}

/**
 * Resolve an issued endpoint's address from the connection summary.
 *
 * SSH resolves through `sshSocket` instead: the agent socket's filename is
 * derived from the endpoint secret, so that the path cannot be found by
 * listing the endpoints directory — the ssh-agent protocol has nowhere to
 * present a credential, so whoever opens the socket gets signatures. Only the
 * broker can name it, and a summary is built without touching the vault. The
 * caller reads it back with `get_endpoint` and passes it here; there is
 * deliberately no fallback that reconstructs a path from the endpoint id,
 * because such a path is exactly what must not be guessable.
 */
export function directEndpointAddress(
  type: ConnectionType,
  endpoint: { endpoint_id: string; dsn?: string | null } | null | undefined,
  sshSocket?: string | null,
): string | null {
  if (!endpoint) return null;
  if (endpoint.dsn) return endpoint.dsn;
  return type === 'ssh' ? (sshSocket ?? null) : null;
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
      : 'Use the SSH agent socket AgentMFA issued.';
    const connect = endpoint.sshInvocation
      ? `SSH to the server with ${endpoint.sshInvocation}`
      : 'SSH to the configured server';
    return `${socket}\n${connect}, then ${option.taskBody}`;
  }
  const lead = endpoint.dsn
    ? `Connect to this Postgres DSN: ${endpoint.dsn}`
    : `Connect to the direct endpoint AgentMFA issued.`;
  return `${lead}\n\nThen ${option.taskBody}`;
}

/**
 * The on-screen form of a task that embeds a direct endpoint: the DSN
 * password and the unguessable agent-socket filename become bullets. The
 * Copy button carries the real text — the screen never has to show it.
 */
export function redactedStartTask(task: string): string {
  return task
    .replace(/(:\/\/[^:@/\s]*:)[^@\s]+(?=@)/g, '$1••••••')
    .replace(/(agent-)[0-9a-f]{6,}(\.sock)/gi, '$1••••••$2');
}
