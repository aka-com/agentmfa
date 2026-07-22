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
  /** The first ask — chosen to be immediately useful, not a hello-world. */
  task: (toolName: string) => string;
}

export const START_PROMISE = "Give your agent a whole app's tools — GitHub, Notion, anything with MCP.";

export const START_OPTIONS: StartOption[] = [
  {
    id: 'postgres',
    label: 'Postgres',
    icon: 'postgres',
    connType: 'pg',
    catalogId: 'postgres',
    task: (name) =>
      `Using my Multitool tool "${name}", list the 10 largest tables with their row ` +
      `counts, and flag any foreign key that has no index.`,
  },
  {
    id: 'ssh',
    label: 'SSH',
    icon: 'terminal',
    connType: 'ssh',
    catalogId: 'ssh',
    task: (name) =>
      `Using my Multitool tool "${name}", report disk and memory usage, then show the ` +
      `last 20 lines of any log that contains errors.`,
  },
  {
    id: 'notion',
    label: 'Notion',
    icon: 'notion',
    connType: 'api',
    catalogId: 'notion',
    mcp: true,
    task: (name) =>
      `Using my Multitool tool "${name}", summarize the pages I changed this week and ` +
      `list any open action items.`,
  },
  {
    id: 'github',
    label: 'GitHub',
    icon: 'github',
    connType: 'api',
    catalogId: 'github',
    mcp: true,
    task: (name) =>
      `Using my Multitool tool "${name}", summarize the pull requests and issues that ` +
      `changed this week.`,
  },
  {
    id: 'slack',
    label: 'Slack',
    icon: 'slack',
    connType: 'api',
    catalogId: 'slack',
    task: (name) =>
      `Using my Multitool tool "${name}", summarize the important conversations from ` +
      `this week and list the decisions that were made.`,
  },
  {
    id: 'stripe',
    label: 'Stripe',
    icon: 'stripe',
    connType: 'api',
    catalogId: 'stripe',
    mcp: true,
    task: (name) =>
      `Using my Multitool tool "${name}", summarize payment activity from the last seven ` +
      `days and flag anything that needs attention.`,
  },
  {
    id: 'sentry',
    label: 'Sentry',
    icon: 'sentry',
    connType: 'api',
    catalogId: 'sentry',
    mcp: true,
    task: (name) =>
      `Using my Multitool tool "${name}", summarize the highest-impact unresolved issues ` +
      `from this week.`,
  },
  {
    id: 'vercel',
    label: 'Vercel',
    icon: 'vercel',
    connType: 'api',
    catalogId: 'mcp-vercel',
    mcp: true,
    task: (name) =>
      `Using my Multitool tool "${name}", summarize this week’s deployments and explain ` +
      `any failures.`,
  },
  {
    id: 'mcp',
    label: 'Custom MCP',
    icon: 'plug',
    showPickerLabel: true,
    connType: 'api',
    catalogId: 'mcp',
    mcp: true,
    task: (name) =>
      `Using my Multitool tool "${name}", list the tools it exposes, then use them to ` +
      `summarize what changed this week.`,
  },
];

export function startOptionById(id: string): StartOption {
  return START_OPTIONS.find((option) => option.id === id) ?? START_OPTIONS[0];
}

/**
 * How the agent reaches the broker in step 2. `direct` is the per-tool
 * endpoint (a Postgres DSN or SSH agent socket) and is only offered for
 * kinds that have one; every other mode rides the shared key.
 */
export type ConnectModeId =
  | 'direct' | 'claude-code' | 'claude-desktop' | 'codex' | 'codex-desktop' | 'mcp' | 'cli';

export const CONNECT_MODE_LABELS: Record<ConnectModeId, string> = {
  direct: 'Direct',
  'claude-code': 'Claude Code',
  'claude-desktop': 'Claude Desktop',
  codex: 'Codex',
  'codex-desktop': 'Codex Desktop',
  mcp: 'MCP client',
  cli: 'CLI',
};

const SHARED_KEY_MODES: ConnectModeId[] =
  ['claude-code', 'claude-desktop', 'codex', 'codex-desktop', 'mcp', 'cli'];

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
  /** An agent has fetched the shared key (a pair/whoami has been seen). */
  connected: boolean;
  /** A tool of this kind is enabled for agents. */
  wired: boolean;
  /** The tool the example task should name. */
  toolName: string | null;
}

/** Live progress for the chosen option, read straight from broker state.
 * `agentConnected` is supplied by the caller (there is no agent registry
 * under the shared identity — the signal is activity, not a roster). */
export function startProgress(
  option: StartOption,
  connections: ConnectionSummary[],
  agentConnected: boolean,
): StartProgress {
  const entry = option.catalogId ? catalogEntryById(option.catalogId) : undefined;
  const matching = entry ? connectionsForEntry(entry, connections) : [];
  // Prefer showing a tool that is already usable by agents.
  const enabledTool = matching.find((connection) => connection.agent_access.enabled);
  const tool = enabledTool ?? matching[0] ?? null;
  return {
    added: matching.length > 0,
    connected: agentConnected,
    wired: Boolean(enabledTool),
    toolName: tool ? tool.name : null,
  };
}

/** The example task, with a placeholder while no tool exists yet. */
export function startTask(option: StartOption, progress: StartProgress): string {
  return option.task(progress.toolName ?? 'my-tool');
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
  if (option) return option.task(name);
  // Branded APIs and protocols without a walkthrough use a generic read-only
  // ask rather than borrowing one particular provider's copy.
  return `Using my Multitool tool "${name}", make one read-only request and summarize what comes back.`;
}
