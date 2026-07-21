// The Get started walkthrough: pick what you want your agent to reach, then
// three steps that mirror how the broker actually works — add the tool,
// register the agent, wire them together and ask for something worth having.
//
// The copy lives here (rather than inline in the renderer) so the prompts and
// the progress rules are testable on their own.

import type { AgentSummary, ConnectionSummary, ConnectionType } from './types';

export interface StartOption {
  id: string;
  /** Label on the small picker row. */
  label: string;
  /** Connection type this sets up; null while only MCP can provide it. */
  connType: ConnectionType | null;
  /** Catalog row the Add button opens. */
  catalogId: string | null;
  /**
   * This option is satisfied only by an MCP connection. Both this and the
   * Custom API option store `api` connections, so type alone cannot tell
   * them apart — without this, adding a plain API would tick the MCP
   * option's first step.
   */
  mcp?: boolean;
  /** Why this is worth wiring up, in one line. */
  promise: string;
  /** The first ask — chosen to be immediately useful, not a hello-world. */
  task: (toolName: string) => string;
}

export const START_OPTIONS: StartOption[] = [
  {
    id: 'postgres',
    label: 'Postgres',
    connType: 'pg',
    catalogId: 'postgres',
    promise: 'Let your agent read your database without ever holding the password.',
    task: (name) =>
      `Using my Multitool tool "${name}", list the 10 largest tables with their row ` +
      `counts, and flag any foreign key that has no index.`,
  },
  {
    id: 'ssh',
    label: 'SSH',
    connType: 'ssh',
    catalogId: 'ssh',
    promise: 'Let your agent work on a server while the private key stays in the broker.',
    task: (name) =>
      `Using my Multitool tool "${name}", report disk and memory usage, then show the ` +
      `last 20 lines of any log that contains errors.`,
  },
  {
    id: 'api',
    label: 'Custom API',
    connType: 'api',
    catalogId: 'http',
    promise: 'Let your agent call an API with a key it never gets to read.',
    task: (name) =>
      `Using my Multitool tool "${name}", call a read-only endpoint and summarize the ` +
      `response as a short schema I can keep.`,
  },
  {
    id: 'mcp',
    label: 'MCP server',
    connType: 'api',
    catalogId: 'mcp',
    mcp: true,
    promise: "Give your agent a whole app's tools — GitHub, Notion, anything with an MCP server.",
    task: (name) =>
      `Using my Multitool tool "${name}", list the tools it exposes, then use them to ` +
      `summarize what changed this week.`,
  },
];

export function startOptionById(id: string): StartOption {
  return START_OPTIONS.find((option) => option.id === id) ?? START_OPTIONS[0];
}

export interface StartProgress {
  /** A tool of this kind exists. */
  added: boolean;
  /** At least one agent has registered. */
  connected: boolean;
  /** An agent is wired to a tool of this kind. */
  wired: boolean;
  /** The tool the example task should name. */
  toolName: string | null;
  /** The agent the wiring step should name. */
  agentName: string | null;
}

/** Live progress for the chosen option, read straight from broker state. */
export function startProgress(
  option: StartOption,
  connections: ConnectionSummary[],
  agents: AgentSummary[],
): StartProgress {
  const matching = option.connType
    ? connections.filter(
      (connection) =>
        connection.type === option.connType
        && Boolean(connection.mcp_path) === Boolean(option.mcp),
    )
    : [];
  // Prefer showing a tool that is already usable by an agent.
  const wiredTool = matching.find((connection) => (connection.wired_agents || []).length > 0);
  const tool = wiredTool ?? matching[0] ?? null;
  // Name the agent that actually holds the wiring when one exists — with more
  // than one registered agent, agents[0] need not be the wired one, and the
  // wire step would otherwise name an agent that isn't connected to the tool.
  const wiredAgent = wiredTool ? (wiredTool.wired_agents || [])[0]?.agent : undefined;
  return {
    added: matching.length > 0,
    connected: agents.length > 0,
    wired: Boolean(wiredTool),
    toolName: tool ? tool.name : null,
    agentName: wiredAgent ?? (agents.length ? agents[0].name : null),
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
    (candidate) => candidate.connType === type && !candidate.mcp,
  );
  if (option) return option.task(name);
  // No walkthrough option enumerates this type (only WebSockets today), so
  // fall back to a generic read-only ask rather than borrow another type's copy.
  return `Using my Multitool tool "${name}", make one read-only request and summarize what comes back.`;
}
