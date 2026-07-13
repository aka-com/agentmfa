// Pure rules for the guided-setup workflow (the Agents hero ↔ Services
// panel with breadcrumbs). Kept separate from app.ts so the cross-tab
// navigation, task-targeting, and completion rules can be exercised
// without a browser/Tauri.

export type GuideStep = 'connect' | 'add' | 'task' | 'done';

export const GUIDE_STEPS: Array<[GuideStep, string]> = [
  ['connect', 'Connect agent'],
  ['add', 'Add service'],
  ['task', 'First task'],
  ['done', 'Done'],
];

/** Which pane a breadcrumb lands on: agent work on Agents, the rest on Services. */
export function guideTabForStep(step: GuideStep): 'agents' | 'connections' {
  return step === 'connect' ? 'agents' : 'connections';
}

/**
 * Which walkthrough setting a crumb must re-enable when the user navigates
 * to a step whose panel they had previously hidden — the click asked for it.
 */
export function guideSettingForStep(
  step: GuideStep,
): 'show_agent_walkthrough' | 'show_service_walkthrough' {
  return step === 'connect' ? 'show_agent_walkthrough' : 'show_service_walkthrough';
}

/**
 * Dismissing the walkthrough dismisses the whole workflow: both the
 * Services panel and the Agents hero, or "Back to the beginning" would lead
 * to the start of a supposedly dismissed walkthrough.
 */
export const GUIDE_DISMISS_SETTINGS = [
  'show_service_walkthrough',
  'show_agent_walkthrough',
] as const;

/**
 * The service the First-task step hands to the agent: the most recently
 * saved guided service when it still exists, otherwise the first listed
 * service. Never invents a target.
 */
export function guideTaskTarget<C extends { name: string }>(
  ready: { name: string } | null,
  connections: C[],
): C | null {
  if (ready) {
    const match = connections.find((connection) => connection.name === ready.name);
    if (match) return match;
  }
  return connections.length ? connections[0] : null;
}

/** What the First-task step should show for the current broker state. */
export type GuideTaskStage = 'need-service' | 'need-agent' | 'ready';

export function guideTaskStage(connectionCount: number, agentCount: number): GuideTaskStage {
  if (!connectionCount) return 'need-service';
  if (!agentCount) return 'need-agent';
  return 'ready';
}

/**
 * "Finish setup" appears only when finishing would be true: an agent is
 * connected and the first task has actually been copied.
 */
export function guideCanFinish(agentCount: number, taskCopied: boolean): boolean {
  return agentCount > 0 && taskCopied;
}

/**
 * Whether a saved connection came through the guided panel (quick-setup
 * import) while the walkthrough is visible — only those saves advance the
 * workflow to First task; a plain ＋ Add service never moves it.
 */
export function guideAdvancesOnSave(
  walkthroughVisible: boolean,
  setupSource: string | undefined,
): boolean {
  return walkthroughVisible && setupSource === 'import';
}

/**
 * Whether a save should (re)target the first-task prompt. True for the very
 * first service and for every guided save, so the task step names the
 * service just added rather than an alphabetically earlier one.
 */
export function guideRetargetsReady(
  hadConnections: boolean,
  setupSource: string | undefined,
): boolean {
  return !hadConnections || setupSource === 'import';
}
