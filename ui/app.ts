// AgentMFA frontend. One file drives all Tauri windows (main, tray
// dropdown, and approval), chosen from location.hash.
//
// Every mutation and read goes through the Rust core via Tauri
// commands; the webview never holds a secret value. When run outside
// Tauri (a plain browser), a dev mock stands in for the core so the
// UI is developable standalone.

import { invoke, listen, mode } from '/src/bridge';
import { ICONS, TYPES, esc, escAttr, toast, relTime, absTime } from '/src/util';
import {
  apiOriginFromParts, authTemplate, firstTaskPrompt, parseApiOrigin, parseConnectionImport,
  portForTypeSwitch, quickSetupPlaceholder, shouldResolveSshImport, sshImportFromPreview,
  suggestedSecretName,
} from '/src/connection-input';
import { formErrorKind, formErrorMessage, inlineFormError } from '/src/form-errors';
import type { HostKeyCandidate } from '/src/connection-input';
import type {
  ActivityEntry,
  AgentSummary,
  ApprovalRequest,
  CommandArgs,
  CommandName,
  ConnectionInput,
  ConnectionSummary,
  ConnectionType,
  Decision,
  PermissionSummary,
  SecretSummary,
  SessionSummary,
  Settings,
} from '/src/types';

const EDIT_SECRET_MASK = '••••••••••••';
const ACTIVITY_RENDER_LIMIT = 200;

// The left-nav tabs, in order — also the cycle order for Ctrl-Tab.
const TABS = ['connections', 'access', 'secrets', 'activity'] as const;
type Tab = typeof TABS[number];

interface SheetState {
  kind: 'add-secret' | 'edit-secret' | 'add-conn' | 'edit-conn' | 'settings' | 'clear-activity';
  id?: string;
}

interface ConfirmState {
  kind: string;
  id?: string | number;
  name?: string;
}

interface ConnectionDraft {
  name?: string;
  value?: string;
  importWarnings?: string[];
  origin?: string | null;
  scheme?: string | null;
  host?: string | null;
  port?: string;
  dbname?: string | null;
  user?: string | null;
  hostKeyFingerprint?: string | null;
  proxyJump?: string | null;
  sslmode?: string | null;
  pgCaBundlePath?: string | null;
  url?: string | null;
  template?: string | null;
  secretId?: string | null;
  secretSource?: string;
  newSecretName?: string;
  newSecretValue?: string;
  importedCredential?: string | null;
  identityFile?: string;
  identityFiles?: string[];
  sshImportId?: string;
  destination?: string | null;
  authMode?: string;
  authDetail?: string;
  import?: string;
  setupSource?: 'manual' | 'import';
}

interface ConnectionReadyState {
  name: string;
  type: ConnectionType;
}

interface AppState {
  tab: Tab;
  secrets: SecretSummary[];
  connections: ConnectionSummary[];
  agents: AgentSummary[];
  sessions: SessionSummary[];
  activity: ActivityEntry[];
  queue: ApprovalRequest[];
  agentSetupInstructions: string;
  brokerInstructions: string;
  settings: Settings;
  reveal: Record<string, string>;
  sheet: SheetState | null;
  draft: ConnectionDraft;
  sheetErrors: Record<string, string>;
  sheetBaseline: string | null;
  confirmDiscard: boolean;
  formMenuOpen: string | null;
  connAdvancedOpen: boolean;
  connType: ConnectionType;
  confirm: ConfirmState | null;
  alwaysOpen: boolean;
  reqDetailOpen: boolean | null;
  revokeInheritedRules: boolean;
  approvalRequestId: string | null;
  menuOpen: boolean;
  walkthroughMenuOpen: boolean;
  agentMenuOpen: string | null;
  copied: string | null;
  readyCopied: boolean;
  setupInstructionsOpen: boolean;
  showFullInstructions: boolean;
  quickSetupType: ConnectionType;
  quickSetupSource: string;
  quickSetupError: string | null;
  connectionReady: ConnectionReadyState | null;
  connectionTaskCopied: boolean;
  connTests: Record<string, ConnectionTestState>;
}

interface ConnectionTestState {
  running: boolean;
  ok?: boolean;
  detail?: string;
}

/* ------------------------------ local state ------------------------------ */
const state: AppState = {
  tab: 'connections',
  secrets: [],
  connections: [],
  agents: [],
  sessions: [],
  activity: [],
  queue: [],
  agentSetupInstructions: '', // short paste-ready setup message (lazy-loaded)
  brokerInstructions: '', // full GET /instructions body (lazy-loaded)
  settings: {
    reauth_on_read: true,
    menu_bar_hides_dock: false,
    show_service_walkthrough: true,
    show_agent_walkthrough: true,
  },
  reveal: {},            // secretId -> prefix string (transient)
  // sheet / confirm state
  sheet: null,           // {kind:'add-secret'|'edit-secret'|'add-conn'|'edit-conn'|'settings', ...}
  draft: {},
  sheetErrors: {},       // field key -> inline validation message
  sheetBaseline: null,   // draft signature at sheet open (dirty-close detection)
  confirmDiscard: false, // "Discard this service?" confirm over the conn sheet
  formMenuOpen: null,    // id of the open custom-select listbox in the sheet
  connAdvancedOpen: false, // "Advanced" disclosure in the service sheet
  connType: 'api',
  confirm: null,         // {kind, id/name}
  alwaysOpen: false,
  reqDetailOpen: null,   // approval payload disclosure override
  revokeInheritedRules: false,
  approvalRequestId: null,
  menuOpen: false,       // desktop-mode settings popover (gear) open
  walkthroughMenuOpen: false,
  agentMenuOpen: null,   // agent id whose ⋯ options menu is open (Access tab)
  copied: null,          // secretId whose value was just copied (transient "Copied" flash)
  readyCopied: false,    // transient feedback on the setup-instructions status button
  setupInstructionsOpen: false,
  showFullInstructions: false, // short setup vs full /instructions body
  quickSetupType: 'pg',
  quickSetupSource: '',
  quickSetupError: null,
  connectionReady: null,
  connectionTaskCopied: false,
  connTests: {},         // connectionId -> in-flight/last test result (transient)
};

const root = (): HTMLElement => {
  const element = document.getElementById('root');
  if (!element) throw new Error('Missing #root element');
  return element;
};
let accessExpiryTimer: ReturnType<typeof setTimeout> | null = null;

/* ------------------------------ data loading ----------------------------- */
type RefreshTarget = 'all' | 'secrets' | 'connections' | 'agents' | 'sessions' |
  'activity' | 'queue' | 'settings';
type LoadKey = 'secrets' | 'connections' | 'agents' | 'sessions' | 'activity' | 'queue';

async function refresh(which: RefreshTarget = 'all'): Promise<void> {
  const jobs: Promise<void>[] = [];
  if (which === 'all' || which === 'secrets') jobs.push(load('secrets', 'list_secrets'));
  if (which === 'all' || which === 'connections') jobs.push(load('connections', 'list_connections'));
  if (which === 'all' || which === 'agents') jobs.push(load('agents', 'list_agents'));
  if (which === 'all' || which === 'sessions') jobs.push(load('sessions', 'list_sessions'));
  if (which === 'all' || which === 'activity') {
    jobs.push(load('activity', 'list_activity', { limit: ACTIVITY_RENDER_LIMIT }));
  }
  if (which === 'all' || which === 'queue') jobs.push(load('queue', 'get_queue'));
  if (which === 'all' || which === 'settings') jobs.push(loadSettings());
  await Promise.all(jobs);
  render();
}
async function load<K extends CommandName>(
  key: LoadKey,
  cmd: K,
  args?: CommandArgs<K>,
): Promise<void> {
  try {
    const result: unknown = await invoke(cmd, args);
    switch (key) {
      case 'secrets': state.secrets = result as SecretSummary[]; break;
      case 'connections': state.connections = result as ConnectionSummary[]; break;
      case 'agents': state.agents = result as AgentSummary[]; break;
      case 'sessions': state.sessions = result as SessionSummary[]; break;
      case 'activity': state.activity = result as ActivityEntry[]; break;
      case 'queue': state.queue = result as ApprovalRequest[]; break;
    }
  } catch (error) {
    console.error(cmd, error);
  }
}
async function loadSettings(): Promise<void> {
  try { state.settings = await invoke('get_settings'); } catch (e) { console.error(e); }
}
async function refreshAccessViews(): Promise<void> {
  await Promise.all([
    load('connections', 'list_connections'),
    load('agents', 'list_agents'),
  ]);
  render();
  scheduleAccessExpiryRefresh();
}

function scheduleAccessExpiryRefresh(): void {
  if (accessExpiryTimer !== null) clearTimeout(accessExpiryTimer);
  accessExpiryTimer = null;
  const expiries = state.connections
    .flatMap((connection) => (connection.permissions || [])
      .flatMap((permission) => permission.expires_at
        ? [new Date(permission.expires_at).getTime()]
        : []))
    .filter((expiresAt) => Number.isFinite(expiresAt) && expiresAt > Date.now());
  if (!expiries.length) return;
  const delay = Math.max(0, Math.min(...expiries) - Date.now() + 50);
  accessExpiryTimer = setTimeout(() => {
    accessExpiryTimer = null;
    if (mode !== 'approval') refreshAccessViews();
  }, Math.min(delay, 2_147_483_647));
}

/* --------------------------------- render -------------------------------- */
// Rebuilding #root from scratch would drop anything the DOM holds that state
// doesn't: in-progress sheet input and the focused control. Broker events
// (queue/sessions/activity changes) re-render at arbitrary times, so every
// render first captures open drafts and then puts focus (and any text
// selection) back where it was.
function render(capture = true): void {
  if (capture) captureDrafts();
  const active = document.activeElement instanceof HTMLInputElement ||
    document.activeElement instanceof HTMLTextAreaElement
    ? document.activeElement
    : null;
  const focusId = active && active.id ? active.id : null;
  const sel = active && focusId && typeof active.selectionStart === 'number'
    ? { start: active.selectionStart, end: active.selectionEnd, dir: active.selectionDirection }
    : null;

  if (mode === 'approval') renderApproval();
  else if (mode === 'dropdown') renderDropdown();
  else renderMainWindow();

  if (focusId) {
    const el = document.getElementById(focusId) as HTMLInputElement | HTMLTextAreaElement | null;
    if (el) {
      el.focus();
      if (sel && typeof el.setSelectionRange === 'function') {
        try { el.setSelectionRange(sel.start, sel.end, sel.dir || 'none'); } catch { /* non-text input */ }
      }
    }
  }

  if (state.formMenuOpen) positionFormMenu();

  // First render of a connection sheet: snapshot the draft as the form
  // presents it (defaults included) so cancelling can detect real edits.
  if (state.sheet && (state.sheet.kind === 'add-conn' || state.sheet.kind === 'edit-conn') &&
      state.sheetBaseline === null) {
    captureDrafts();
    state.sheetBaseline = connDraftSignature();
  }
}

function pendingBannerHTML() {
  if (!state.queue.length) return '';
  return `<div class="pending-banner"><span>⏳ ${state.queue.length} request${state.queue.length > 1 ? 's' : ''} waiting</span>
    <button class="btn sm" data-act="open-approval">Review</button></div>`;
}

function setupCurlCommand(instructions: string): string {
  return instructions.split(/\r?\n/).find((line) => line.trimStart().startsWith('curl '))?.trim() || 'Loading…';
}

const QUICK_SETUP_TYPES: Array<[ConnectionType, string]> = [
  ['pg', 'Postgres'],
  ['ssh', 'SSH'],
  ['api', 'HTTP API'],
  ['ws', 'WebSocket'],
];

function firstConnectionSetupHTML(): string {
  const type = state.quickSetupType;
  const types = QUICK_SETUP_TYPES.map(([value, label]) =>
    `<button class="quick-type ${type === value ? 'on' : ''}" aria-pressed="${type === value}" data-act="quick-setup-type" data-type="${value}">${label}</button>`).join('');
  return `<div class="agent-onboarding service-onboarding walkthrough-card">
    <div class="walkthrough-head">
      <div class="onboarding-copy"><b>Add a service for your agent</b>
        ${mode === 'dropdown' ? '' : '<span>Save a database, server, or API.</span>'}</div>
      <button class="icon-btn walkthrough-close" title="Hide this walkthrough" aria-label="Hide Add a service walkthrough" data-act="hide-service-walkthrough">${ICONS.x}</button>
    </div>
    <div class="quick-type-row">
      <div class="quick-types" aria-label="Service type">${types}</div>
    </div>
    <div class="quick-import-row">
      <input id="quick-setup-source" aria-label="Service to import" placeholder="${escAttr(quickSetupPlaceholder(type))}" value="${escAttr(state.quickSetupSource)}">
      <button class="btn primary sm" data-act="quick-setup-review">Continue</button>
    </div>
    ${state.quickSetupError ? `<div class="field-error quick-setup-error">${esc(state.quickSetupError)}</div>` : ''}
  </div>`;
}

function globalSectionsHTML() {
  let out = '';
  let hasOnboarding = false;
  if (state.tab === 'connections' && state.settings.show_service_walkthrough) {
    out += firstConnectionSetupHTML();
    hasOnboarding = true;
  }
  if (state.tab === 'connections' && state.settings.show_agent_walkthrough) {
    hasOnboarding = true;
    const instructionBody = state.showFullInstructions
      ? (state.brokerInstructions || 'Loading…')
      : (state.agentSetupInstructions || 'Loading…');
    out += `<div class="agent-onboarding walkthrough-card">
      <div class="walkthrough-head">
        <div class="onboarding-copy"><b>Connect an agent</b>
          <span>Copy a short setup message into your coding agent. After you paste and run it, your agent will walk you through setup.</span></div>
        <button class="icon-btn walkthrough-close" title="Hide this walkthrough" aria-label="Hide Connect an agent walkthrough" data-act="hide-agent-walkthrough">${ICONS.x}</button>
      </div>
      <div class="onboarding-actions">
        <button class="btn primary sm" data-act="copy-agent-setup">Copy setup instructions</button>
        <button class="setup-toggle" data-act="toggle-setup-instructions"
          aria-expanded="${state.setupInstructionsOpen}">${mode === 'dropdown' ? 'View' : 'View instructions'}<span class="setup-toggle-icon">${ICONS.chevronDown}</span></button>
        ${state.setupInstructionsOpen
          ? `<div class="seg instructions-seg" role="group" aria-label="Instruction detail">
              <button class="seg-btn ${state.showFullInstructions ? '' : 'on'}" data-act="set-instructions-detail" data-full="false" aria-pressed="${!state.showFullInstructions}">Short</button>
              <button class="seg-btn ${state.showFullInstructions ? 'on' : ''}" data-act="set-instructions-detail" data-full="true" aria-pressed="${state.showFullInstructions}">Full</button></div>`
          : ''}
      </div>
      ${state.setupInstructionsOpen
        ? state.showFullInstructions
          ? `<div class="setup-instructions is-full">
              <div class="full-instructions-banner">
                <p>These are the instructions that the agent will see. Tell it to read from:</p>
                <code>${esc(setupCurlCommand(state.agentSetupInstructions))}</code>
              </div>
              <pre class="full-instructions-code"><code>${esc(instructionBody)}</code></pre>
            </div>`
          : `<pre class="setup-instructions"><code>${esc(instructionBody)}</code></pre>`
        : ''}</div>`;
  }
  if (state.sessions.length) {
    out += '<div class="live-head">Active sessions</div>' + state.sessions.map((s) => {
      const t = TYPES[s.type];
      // who holds the session matters as much as what it's connected to
      const who = s.agent ? `${esc(s.agent)} → ${esc(s.connection)}` : esc(s.connection);
      if (state.confirm && state.confirm.kind === 'close-session' && state.confirm.id === s.id) {
        return `<div class="live-row"><span class="badge ${t.cls}">${t.label}</span>
          <div class="live-txt"><div class="c-name">${who}</div>
          <div class="s-sub">Close this session now?</div></div>
          <button class="btn sm" data-act="confirm-cancel">Cancel</button>
          <button class="btn sm danger" data-act="close-session-confirm" data-id="${s.id}">Close</button></div>`;
      }
      return `<div class="live-row"><span class="badge ${t.cls}">${t.label}</span>
        <div class="live-txt"><div class="c-name">${who}</div>
        <div class="s-sub" title="${escAttr(s.detail)}">${esc(s.detail)}</div></div>
        <button class="btn sm" data-act="close-session-ask" data-id="${s.id}">Close</button></div>`;
    }).join('');
  }
  return out ? `<div class="dd-global ${hasOnboarding ? 'onboarding-global' : ''}">${out}</div>` : '';
}

function secretsHTML() {
  if (!state.secrets.length) {
    const detail = mode === 'dropdown' ? '' : `
      <p>Store API keys, connection strings, and other credentials and secrets here.</p>
      <p class="empty-tip">Tip: adding a service can save its credential in one step.</p>
      <button class="btn primary" data-act="open-add-secret">＋ Add secret</button>`;
    return `<div class="empty"><div class="empty-ico">🔐</div><h3>No secrets</h3>${detail}</div>`;
  }
  const rows = state.secrets.map((s) => {
    if (state.confirm && state.confirm.kind === 'del-secret-inuse' && state.confirm.id === s.id) {
      return `<tr class="confirm-row"><td colspan="3"><div class="confirm-inline"><span>Currently used by ${esc(s.used_by_names.join(', '))}. Delete the service first.</span>
          <button class="btn sm" data-act="confirm-cancel">OK</button></div></td></tr>`;
    }
    if (state.confirm && state.confirm.kind === 'del-secret' && state.confirm.id === s.id) {
      return `<tr class="confirm-row"><td colspan="3"><div class="confirm-inline"><span>Delete “${esc(s.name)}” from the macOS Keychain?</span>
          <button class="btn sm" data-act="confirm-cancel">Cancel</button>
          <button class="btn sm danger" data-act="del-secret-confirm" data-id="${s.id}">Delete</button></div></td></tr>`;
    }
    // The eye reveals only a short prefix (the full value never
    // enters the webview).
    const revealed = state.reveal[s.id];
    const copied = state.copied === s.id;
    // the eye toggles reveal ↔ conceal; copy is a ghost button that surfaces on
    // hovering the value (available whether or not the prefix is revealed)
    const eyeBtn = mode === 'dropdown' ? '' : revealed
      ? `<button class="icon-btn eye-btn" title="Hide prefix" aria-label="Hide prefix" data-act="hide-secret" data-id="${s.id}">${ICONS.eyeOff}</button>`
      : `<button class="icon-btn eye-btn" title="Reveal prefix" aria-label="Reveal prefix" data-act="reveal-secret" data-id="${s.id}">${ICONS.eye}</button>`;
    // The copy affordance and the post-copy "Copied" status both overlay the
    // masked value, centered — never beside it (the placeholder dims behind).
    const overlay = copied
      ? `<span class="copied-badge">${ICONS.check}<span>Copied</span></span>`
      : `<button class="ghost-copy" title="Copy value" data-act="copy-secret" data-id="${s.id}">${ICONS.copy}<span>Copy</span></button>`;
    const valText = revealed ? esc(revealed) : '••••••••';
    const sub = `Used by ${s.used_by} service${s.used_by === 1 ? '' : 's'}`;
    return `<tr>
      <td><div><div class="s-name">${esc(s.name)}</div><div class="s-sub secret-usage">${esc(sub)}</div></div></td>
      <td class="val"><span class="val-wrap"><span class="val-slot ${copied ? 'is-copied' : ''}"><code>${valText}</code><span class="val-overlay">${overlay}</span></span></span> ${eyeBtn}</td>
      <td class="rowdel">
        <button class="icon-btn" title="Edit secret" aria-label="Edit secret ${escAttr(s.name)}" data-act="edit-secret" data-id="${s.id}">${ICONS.pencil}</button>
        <button class="icon-btn" title="Delete secret" aria-label="Delete secret ${escAttr(s.name)}" data-act="del-secret-ask" data-id="${s.id}">${ICONS.trash}</button></td></tr>`;
  }).join('');
  return `<table class="sec-table"><tbody>${rows}</tbody></table>`;
}

/* ---- connections tab ---- */
function accessDescription(connection: ConnectionSummary, scope: string): string {
  if (scope === 'read') return 'Can fetch data';
  if (connection.type === 'api') return 'Can make any request';
  return 'Can open and use this service';
}

/* ---- access tab ---- */
// The screen pivots around the broker's core question — what can this agent
// reach right now? One block per paired agent: an identity card on top, then
// one row per service stating the agent's current capability in plain words.
const agentPermissionFor = (a: AgentSummary, c: ConnectionSummary): PermissionSummary | undefined =>
  (c.permissions || []).find((permission) => permission.agent === a.name &&
    (!permission.expires_at || new Date(permission.expires_at).getTime() > Date.now()));

function accessPillHTML(c: ConnectionSummary, permission: PermissionSummary | undefined): string {
  if (!permission) return '<span class="acc-pill">Asks you each time</span>';
  if (permission.expires_at) {
    const minutes = Math.max(1, Math.ceil((new Date(permission.expires_at).getTime() - Date.now()) / 60000));
    return `<span class="acc-pill granted">${esc(accessDescription(c, permission.scope))} · ${minutes} min left</span>`;
  }
  return `<span class="acc-pill rule">${esc(accessDescription(c, permission.scope))} · without asking</span>`;
}

function agentAccessRowHTML(a: AgentSummary, c: ConnectionSummary): string {
  const t = TYPES[c.type];
  const permission = agentPermissionFor(a, c);
  const live = state.sessions.some((s) => s.agent === a.name && s.connection === c.name);
  const action = !permission ? '' : permission.expires_at
    ? `<button class="btn ghost sm" aria-label="End access to ${escAttr(c.name)} for ${escAttr(a.name)} now" data-act="del-permission" data-id="${permission.id}">End now</button>`
    : `<button class="btn ghost sm" aria-label="Require approval again for ${escAttr(a.name)} on ${escAttr(c.name)}" data-act="del-permission" data-id="${permission.id}">Require approval</button>`;
  return `<div class="acc-row">
    <span class="badge ${t.cls}">${t.label}</span>
    <div class="acc-svc"><div class="acc-name">${esc(c.name)}${live ? ' <span class="cc-live">● live</span>' : ''}</div>
      <div class="acc-target" title="${escAttr(c.target)}">${esc(c.target)}</div></div>
    ${accessPillHTML(c, permission)}${action}</div>`;
}

function agentBlockHTML(a: AgentSummary): string {
  const menuOpen = state.agentMenuOpen === a.id;
  const sub = `${a.program} · ${a.verification} · last used ${relTime(a.last_used)}`;
  const rows = state.connections.length
    ? state.connections.map((c) => agentAccessRowHTML(a, c)).join('')
    : `<div class="acc-none">No services yet.${mode === 'dropdown' ? '' : ` Add one to give ${esc(a.name)} somewhere to connect.`}</div>`;
  return `<div class="agent-block">
    <div class="agent-card">
      <span class="agent-avatar" role="img" aria-label="Agent">${ICONS.bot}</span>
      <div class="agent-id"><div class="c-name">${esc(a.name)}</div>
        <div class="s-sub agent-sub" title="${escAttr(a.identity)}">${esc(sub)}</div></div>
      <div class="agent-menu-wrap">
        <button class="icon-btn agent-menu-btn ${menuOpen ? 'on' : ''}" title="Agent options"
          aria-label="Options for ${escAttr(a.name)}" aria-haspopup="menu"
          aria-expanded="${menuOpen}" data-act="toggle-agent-menu" data-id="${a.id}">${ICONS.ellipsis}</button>
        ${menuOpen ? `<div class="agent-menu" role="menu" aria-label="Options for ${escAttr(a.name)}">
          <button class="menu-item" role="menuitem" data-act="copy-agent-setup">${ICONS.copy} Copy setup instructions</button>
          <button class="menu-item danger" role="menuitem" data-act="revoke-ask" data-id="${a.id}">${ICONS.unplug} Disconnect ${esc(a.name)}…</button>
        </div>` : ''}
      </div>
    </div>
    <div class="acc-rows">${rows}</div>
  </div>`;
}

function accessHTML(): string {
  if (!state.agents.length) {
    const detail = mode === 'dropdown' ? '' : `
      <p>Pair a coding agent to see and control what it can reach.</p>
      <p class="empty-tip">Copy the setup instructions into your agent to get started.</p>
      <button class="btn primary" data-act="copy-agent-setup">Copy setup instructions</button>`;
    return `<div class="empty"><div class="empty-ico">🤖</div><h3>No agents connected</h3>${detail}</div>`;
  }
  return state.agents.map(agentBlockHTML).join('');
}
const liveCount = (c: ConnectionSummary): number =>
  state.sessions.filter((s) => s.connection === c.name).length;
const connActionsHTML = (c: ConnectionSummary): string => {
  const test = state.connTests[c.id];
  return `<button class="btn ghost sm cc-test-btn" data-act="test-conn" data-id="${c.id}"
     aria-label="Test service ${escAttr(c.name)}" ${test && test.running ? 'disabled' : ''}>${test && test.running ? 'Testing…' : 'Test'}</button>
   <button class="icon-btn" title="Edit service" aria-label="Edit service ${escAttr(c.name)}" data-act="edit-conn" data-id="${c.id}">${ICONS.pencil}</button>
   <button class="icon-btn" title="Delete service" aria-label="Delete service ${escAttr(c.name)}" data-act="del-conn-ask" data-id="${c.id}">${ICONS.trash}</button>`;
};

const connTestResultHTML = (c: ConnectionSummary): string => {
  const test = state.connTests[c.id];
  if (!test || test.running || test.detail === undefined) return '';
  return `<div class="cc-test ${test.ok ? 'ok' : 'err'}">${test.ok ? ICONS.circleCheck : ICONS.circleX}<span>${esc(test.detail)}</span></div>`;
};

// Card grid, after TablePlus launchers / Keybase device cards: one
// connection = one object with everything about it inside its border.
function connectionsHTML() {
  if (!state.connections.length) {
    const detail = mode === 'dropdown' ? '' : `
      <p>Add APIs, databases, SSH servers, and WebSockets.</p>
      <button class="btn primary" data-act="open-add-conn">＋ Add service</button>`;
    return `<div class="empty"><div class="empty-ico">🔌</div><h3>No services</h3>${detail}</div>`;
  }
  const ready = state.connectionReady;
  const readyPrompt = ready ? firstTaskPrompt(ready.name, ready.type) : '';
  const readyCard = ready && state.agents.length ? `<div class="connection-ready">
    <div class="connection-ready-copy"><b>${esc(ready.name)} is ready</b>
      <span>Ask your agent:</span><code>${esc(readyPrompt)}</code></div>
    <div class="connection-ready-actions">
      <button class="btn sm" data-act="copy-first-task">${state.connectionTaskCopied ? `${ICONS.check} Copied` : 'Copy task'}</button>
      <button class="icon-btn" title="Dismiss" aria-label="Dismiss service ready message" data-act="dismiss-connection-ready">${ICONS.circleX}</button>
    </div></div>` : '';
  return readyCard + `<div class="conn-cards">` + state.connections.map((c) => {
    const t = TYPES[c.type];
    if (state.confirm && state.confirm.kind === 'del-conn' && state.confirm.id === c.id) {
      return `<div class="conn-card confirm-card">
        <div class="cc-top"><span class="badge ${t.cls}">${t.label}</span>
          <span class="c-name" title="${escAttr(c.name)}">${esc(c.name)}</span></div>
        <div class="cc-confirm">Delete this service?${(c.permissions || []).some((permission) => !permission.expires_at) ? ' Affected agents will need approval again.' : ''}</div>
        <div class="cc-foot"><button class="btn sm" data-act="confirm-cancel">Cancel</button>
          <button class="btn sm danger" data-act="del-conn-confirm" data-id="${c.id}">Delete</button></div></div>`;
    }
    const chips = c.secret_names.map((n) => `<span class="key-chip">🔑 ${esc(n)}</span>`).join('');
    return `<div class="conn-card">
      <div class="cc-top"><span class="badge ${t.cls}">${t.label}</span>
        <span class="c-name" title="${escAttr(c.name)}">${esc(c.name)}</span>
        ${liveCount(c) ? '<span class="cc-live">● live</span>' : ''}</div>
      <div class="cc-target" title="${escAttr(c.target)}">${esc(c.target)}</div>
      <div class="cc-chips">${chips}</div>
      ${connTestResultHTML(c)}
      <div class="cc-foot">${connActionsHTML(c)}</div></div>`;
  }).join('') + `</div>`;
}

// Console.app-style rows: a proportional timestamp gutter, restrained
// semantic Lucide icon, then plain primary text with optional detail.
function activityRowHTML(a: ActivityEntry): string {
  const icon = ICONS[a.icon] || '';
  return `<div class="act-row">
    <span class="act-gutter"><span class="act-time" data-tippy-content="${escAttr(absTime(a.at))}" data-tippy-theme="activity-time">${esc(relTime(a.at))}</span></span>
    <span class="act-ico tone-${escAttr(a.tone || 'neutral')}">${icon}</span>
    <span class="act-txt">${esc(a.text)}${a.detail ? `<div class="act-detail">${esc(a.detail)}</div>` : ''}</span></div>`;
}

function activityHTML() {
  if (!state.activity.length) {
    return `<div class="muted-note">No activity yet.${mode === 'dropdown' ? '' : '<br>Requests and broker actions will appear here.'}</div>`;
  }
  return '<div class="act-list">' + state.activity
    .slice(0, ACTIVITY_RENDER_LIMIT)
    .map(activityRowHTML).join('') + '</div>';
}

async function receiveActivity(entry: ActivityEntry | null | undefined): Promise<void> {
  if (!entry || !entry.at || !entry.text) {
    await load('activity', 'list_activity', { limit: ACTIVITY_RENDER_LIMIT });
    if (mode !== 'approval' && state.tab === 'activity' && !state.sheet && !state.menuOpen) render();
    return;
  }

  const duplicate = state.activity.some((item) =>
    item.at === entry.at && item.icon === entry.icon && item.text === entry.text && item.detail === entry.detail);
  if (duplicate) return;
  state.activity = [entry, ...state.activity].slice(0, ACTIVITY_RENDER_LIMIT);

  if (mode === 'approval' || state.tab !== 'activity' || state.sheet || state.menuOpen) return;
  const list = document.querySelector('.act-list');
  if (!list) {
    render();
    return;
  }
  list.insertAdjacentHTML('afterbegin', activityRowHTML(entry));
  while (list.children.length > ACTIVITY_RENDER_LIMIT) list.lastElementChild?.remove();
}

function tabContentHTML() {
  return state.tab === 'secrets' ? secretsHTML()
    : state.tab === 'connections' ? connectionsHTML()
    : state.tab === 'access' ? accessHTML()
    : activityHTML();
}

function brokerReadyHTML() {
  const copied = state.readyCopied;
  return `<button class="dd-sub ready-copy ${copied ? 'is-copied' : ''}"
    data-act="copy-ready-setup" title="${copied ? 'Setup instructions copied' : 'Copy setup instructions'}"
    aria-label="Copy setup instructions"><span class="dot"></span>
    <span class="ready-copy-label" aria-live="polite">${copied ? `${ICONS.check} Copied` : 'Ready'}</span></button>`;
}

function walkthroughMenuHTML(): string {
  const option = (action: string, label: string, checked: boolean): string =>
    `<button class="walkthrough-option" role="menuitemcheckbox" aria-checked="${checked}" data-act="${action}">
      <span class="walkthrough-check">${checked ? ICONS.check : ''}</span><span>${label}</span></button>`;
  return `<div class="walkthrough-menu-wrap">
    <button class="icon-btn walkthrough-menu-icon ${state.walkthroughMenuOpen ? 'on' : ''}"
      title="Choose walkthroughs" aria-label="Choose walkthroughs" aria-haspopup="menu"
      aria-expanded="${state.walkthroughMenuOpen}" data-act="toggle-walkthrough-menu">${ICONS.circleQuestion}</button>
    ${state.walkthroughMenuOpen ? `<div class="walkthrough-menu" role="menu" aria-label="Walkthroughs">
      <div class="walkthrough-menu-title">Walkthroughs</div>
      ${option('toggle-service-walkthrough', 'Add a service for your agent', state.settings.show_service_walkthrough)}
      ${option('toggle-agent-walkthrough', 'Connect an agent', state.settings.show_agent_walkthrough)}
    </div>` : ''}
  </div>`;
}

function renderMainWindow() {
  const navItem = (tab: Tab): string =>
    `<button class="nav-item ${state.tab === tab ? 'on' : ''}" data-act="tab" data-tab="${tab}">${tabLabel(tab)}</button>`;
  const nav = TABS.filter((tab) => tab !== 'activity').map(navItem).join('');
  const activityNav = navItem('activity');
  // One view-specific action, always in the header row next to the title.
  const actionBtn = state.tab === 'connections'
    ? `<div class="dw-head-actions">${walkthroughMenuHTML()}<button class="btn" data-act="open-add-conn">＋ Add service</button></div>`
    : state.tab === 'access'
    ? `<button class="btn" data-act="copy-agent-setup">Copy setup instructions</button>`
    : state.tab === 'secrets'
    ? `<button class="btn" data-act="open-add-secret">＋ Add secret</button>`
    : `<button class="btn" data-act="clear-activity-ask" ${state.activity.length ? '' : 'disabled'}>Clear activity</button>`;
  const menu = state.menuOpen
    ? `<div class="settings-menu">
        <button class="menu-item" data-act="mode-tray">${ICONS.menubar} Minimize to menu bar</button>
        <button class="menu-item" data-act="open-settings">${ICONS.gear} Settings</button>
      </div>` : '';
  root().innerHTML = `<div class="surface">
    <div class="dw-titlebar" data-tauri-drag-region><span class="dw-title">AgentMFA</span></div>
    <div class="dw-body">
      <div class="dw-side">
        <div class="dw-brand"><div class="dd-appicon">🔐</div>
          <div><div class="dd-title">AgentMFA</div>${brokerReadyHTML()}</div></div>
        <div class="dw-nav">${nav}</div>
        <div class="dw-secondary-nav">${activityNav}</div>
        <div class="dw-settings">${menu}
          <button class="nav-item gear-btn ${state.menuOpen ? 'on' : ''}" data-act="toggle-settings-menu" title="Settings" aria-label="Settings">${ICONS.gear}</button>
        </div>
      </div>
      <div class="dw-main">
        <div class="dw-head"><h2>${tabLabel(state.tab)}</h2>${actionBtn}</div>
        ${pendingBannerHTML()}
        ${globalSectionsHTML()}
        <div class="content">${tabContentHTML()}</div>
      </div>
    </div></div>${sheetsHTML()}`;
}

function renderDropdown() {
  const tabs = TABS.map((tb) =>
    `<button class="seg-btn ${state.tab === tb ? 'on' : ''}" data-act="tab" data-tab="${tb}">${tabLabel(tb)}</button>`).join('');
  const footer = state.tab === 'secrets'
    ? '<div class="dd-footer"><button class="btn block" data-act="open-add-secret">＋ Add secret</button></div>'
    : state.tab === 'connections'
    ? '<div class="dd-footer"><button class="btn block" data-act="open-add-conn">＋ Add service</button></div>' : '';
  root().innerHTML = `<div class="surface dropdown-surface">
    <div class="dd-head"><div class="dd-appicon">🔐</div>
      <div class="dd-identity"><div class="dd-title">AgentMFA</div>${brokerReadyHTML()}</div>
      <button class="icon-btn" title="Open as a window" aria-label="Open as a window" data-act="mode-window">${ICONS.expand}</button>
      ${walkthroughMenuHTML()}
      <button class="icon-btn" title="Settings" aria-label="Settings" data-act="open-settings">${ICONS.gear}</button></div>
    ${pendingBannerHTML()}
    <div class="seg">${tabs}</div>
    ${globalSectionsHTML()}
    <div class="content dd-content">${tabContentHTML()}</div>
    ${footer}</div>${sheetsHTML()}`;
}

/* --------------------------------- sheets -------------------------------- */
function sheetsHTML() {
  if (!state.sheet) return '';
  switch (state.sheet.kind) {
    case 'add-secret': return addSecretSheet(false);
    case 'edit-secret': return addSecretSheet(true);
    case 'add-conn': return connSheet(false);
    case 'edit-conn': return connSheet(true);
    case 'settings': return settingsSheet();
    case 'clear-activity': return clearActivitySheet();
    default: return '';
  }
}

function clearActivitySheet() {
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide confirm-sheet" role="dialog" aria-modal="true" aria-labelledby="clear-activity-title">
      <h3 id="clear-activity-title">Clear activity?</h3>
      <p>This permanently removes all activity history from this device.</p>
      <div class="sheet-actions">
        <button class="btn" data-act="sheet-cancel">Cancel</button>
        <button class="btn danger" data-act="clear-activity-confirm">Clear activity</button>
      </div></div>`;
}

// Inline per-field validation: saveSecret/saveConn fill state.sheetErrors
// keyed by field, the sheet renders the message under the offending input,
// and editing the field clears its error (the `input` listener below).
const fieldErr = (key: string): string =>
  state.sheetErrors[key] ? `<div class="field-error">${esc(state.sheetErrors[key])}</div>` : '';
const fieldCls = (key: string): string => (state.sheetErrors[key] ? 'err' : '');
// Custom select shared by every dropdown in the form sheets: a trigger
// button plus a fixed-position listbox (see positionFormMenu). The trigger
// carries the selection as its value so captureDrafts reads it like the
// native select it replaces.
function customSelectHTML(
  id: string,
  options: Array<[string, string]>,
  selectedValue: string | null | undefined,
  errCls = '',
): string {
  const open = state.formMenuOpen === id;
  const selected = options.find(([value]) => value === selectedValue) ?? options[0];
  const rows = options.map(([value, label]) =>
    `<button type="button" class="cred-opt" role="option" data-act="select-pick"
      data-menu="${id}" data-id="${escAttr(value)}" aria-selected="${value === selected[0]}">
      <span class="cred-opt-col"><span class="cred-name">${esc(label)}</span></span>
      ${value === selected[0] ? `<span class="cred-opt-check">${ICONS.check}</span>` : ''}</button>`).join('');
  return `<div class="cred-select">
    <button type="button" id="${id}" class="cred-trigger ${errCls}" value="${escAttr(selected[0])}"
      data-act="select-toggle" data-menu="${id}" aria-haspopup="listbox" aria-expanded="${open}">
      <span class="cred-name">${esc(selected[1])}</span>
      <span class="cred-chevron" aria-hidden="true">${ICONS.chevronDown}</span></button>
    ${open ? `<div class="cred-menu" role="listbox">${rows}</div>` : ''}</div>`;
}

function addSecretSheet(editing: boolean): string {
  const d = state.draft;
  const sheetId = state.sheet?.id;
  const s = editing ? state.secrets.find((x) => x.id === sheetId) : null;
  const title = editing ? 'Edit secret' : 'Add secret';
  const valueLabel = editing ? 'New value (saved to macOS Keychain)' : 'Value';
  const valuePlaceholder = editing ? '' : 'Your secret (saved in Keychain)';
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>${title}</h3>
    <div class="f-row"><label for="f-name">Name</label><input id="f-name" class="${fieldCls('name')}" placeholder="e.g. STRIPE_API_KEY" value="${escAttr(d.name ?? (s ? s.name : ''))}">${fieldErr('name')}</div>
    <div class="f-row"><label for="f-value">${valueLabel}</label><input id="f-value" class="${fieldCls('value')}" type="password" placeholder="${valuePlaceholder}" value="${escAttr(d.value ?? '')}">${fieldErr('value')}</div>
    <div class="sheet-actions">
      <button class="btn" data-act="sheet-cancel">Cancel</button>
      <button class="btn primary" data-act="save-secret">Save</button></div></div>`;
}

// Sentinel option value in the saved-credential select that switches the
// chooser into "create a new credential" mode.
const NEW_CREDENTIAL_OPTION = '__new__';

function credentialNameIsTaken(name: string): boolean {
  const candidate = name.trim();
  return Boolean(candidate) && state.secrets.some((secret) => secret.name === candidate);
}

function serviceNameIsTaken(name: string): boolean {
  const candidate = name.trim();
  return Boolean(candidate) && state.connections.some((connection) => connection.name === candidate);
}

function credentialChooserHTML(
  type: ConnectionType,
  draft: ConnectionDraft,
  allowNew = true,
): string {
  const source = allowNew
    ? (draft.secretSource || (draft.importedCredential || draft.sshImportId || !state.secrets.length ? 'new' : 'existing'))
    : 'existing';
  const secretLabel = type === 'pg' ? 'Database password'
    : type === 'ssh' ? 'SSH private key'
    : 'Token or API key';
  let picker = '';
  if (state.secrets.length) {
    // Usage detail disambiguates similarly named credentials without
    // touching secret values (revealing those is a separate explicit call).
    const usageDetail = (secret: SecretSummary): string => !secret.used_by ? ''
      : secret.used_by === 1 && secret.used_by_names.length ? `used by ${secret.used_by_names[0]}`
      : `used by ${secret.used_by} services`;
    // No default selection: a wrong prefilled secret (a password where a
    // private key belongs, or vice versa) is worse than an explicit choice.
    const selected = source === 'existing'
      ? state.secrets.find((secret) => secret.id === draft.secretId) || null
      : null;
    const keyBadge = `<span class="cred-badge" aria-hidden="true">${ICONS.keyRound}</span>`;
    const plusBadge = `<span class="cred-badge plus" aria-hidden="true">${ICONS.plus}</span>`;
    const triggerContent = selected
      ? `${keyBadge}<span class="cred-name">${esc(selected.name)}</span>
         ${selected.used_by ? `<span class="cred-detail">${esc(usageDetail(selected))}</span>` : ''}`
      : source === 'new'
      ? `${plusBadge}<span class="cred-name">New secret…</span>`
      : `<span class="cred-name cred-placeholder">Choose a secret…</span>`;
    const options = state.secrets.map((secret) => {
      const picked = selected !== null && selected.id === secret.id;
      return `<button type="button" class="cred-opt" role="option" data-act="credential-pick"
        data-id="${escAttr(secret.id)}" aria-selected="${picked}">${keyBadge}
        <span class="cred-opt-col"><span class="cred-name">${esc(secret.name)}</span>
          ${secret.used_by ? `<span class="cred-opt-sub">${esc(usageDetail(secret))}</span>` : ''}</span>
        ${picked ? `<span class="cred-opt-check">${ICONS.check}</span>` : ''}</button>`;
    }).join('');
    const newOption = allowNew
      ? `<div class="cred-menu-divider"></div>
        <button type="button" class="cred-opt" role="option" data-act="credential-pick"
          data-id="${NEW_CREDENTIAL_OPTION}" aria-selected="${source === 'new'}">${plusBadge}
          <span class="cred-opt-col"><span class="cred-name">New secret…</span></span></button>`
      : '';
    const menu = state.formMenuOpen === 'c-secret'
      ? `<div class="cred-menu" role="listbox">${options}${newOption}</div>`
      : '';
    // The trigger carries the selection as its value so captureDrafts and the
    // sheet-open baseline read it exactly like the native select it replaced.
    picker = `<div class="f-row"><label for="c-secret">${secretLabel}</label>
      <div class="cred-select">
        <button type="button" id="c-secret" class="cred-trigger ${fieldCls('secret')}"
          value="${escAttr(selected ? selected.id : source === 'new' ? NEW_CREDENTIAL_OPTION : '')}" data-act="select-toggle" data-menu="c-secret"
          aria-haspopup="listbox" aria-expanded="${state.formMenuOpen === 'c-secret'}">
          ${triggerContent}<span class="cred-chevron" aria-hidden="true">${ICONS.chevronDown}</span></button>
        ${menu}</div>${fieldErr('secret')}</div>`;
  } else if (source === 'new') {
    picker = `<div class="f-row"><label>${secretLabel}</label></div>`;
  }
  if (source === 'existing') {
    return `<div class="credential-group">${picker}</div>`;
  }
  const suggested = suggestedSecretName(draft.name ?? '', type);
  const effectiveName = (draft.newSecretName || suggested).trim();
  const nameTaken = credentialNameIsTaken(effectiveName);
  const nameRow = `<div class="f-row"><label for="c-new-secret-name">Credential name</label><input id="c-new-secret-name" class="${fieldCls('newSecretName')} ${nameTaken ? 'name-conflict-warning' : ''}" aria-describedby="credential-name-warning" placeholder="${escAttr(suggested)}" value="${escAttr(draft.newSecretName ?? '')}">${fieldErr('newSecretName')}<div id="credential-name-warning" class="field-warning" role="status" aria-live="polite"${nameTaken ? '' : ' hidden'}>Name used by an existing credential</div></div>`;
  if (type === 'ssh' && draft.sshImportId && draft.identityFiles && draft.identityFiles.length) {
    const identityOptions = draft.identityFiles.map((path): [string, string] => [path, path]);
    return `<div class="credential-group">${picker}${nameRow}
      <div class="f-row"><label for="c-identity-file">Identity file</label>${customSelectHTML('c-identity-file', identityOptions, draft.identityFile)}${fieldErr('newSecretValue')}
        <div class="rule-note">Saved directly to macOS Keychain</div></div></div>`;
  }
  const valuePlaceholder = type === 'pg' ? 'Paste the database password'
    : type === 'ssh' ? 'Paste the private key'
    : 'Paste the token or API key';
  return `<div class="credential-group">${picker}${nameRow}
    <div class="f-row"><label for="c-new-secret-value">Credential value</label><input id="c-new-secret-value" class="${fieldCls('newSecretValue')}" type="password" placeholder="${valuePlaceholder}" value="${escAttr(draft.newSecretValue ?? draft.importedCredential ?? '')}">${fieldErr('newSecretValue')}</div></div>`;
}

async function connectionDraftFromImport(
  source: string,
  currentDraft: ConnectionDraft = {},
): Promise<{ type: ConnectionType; draft: ConnectionDraft }> {
  const imported = shouldResolveSshImport(source)
    ? sshImportFromPreview(await invoke('inspect_ssh_import', { source }))
    : parseConnectionImport(source);
  const importedFields = imported.fields as ConnectionDraft;
  return {
    type: imported.type,
    draft: {
      ...currentDraft,
      ...importedFields,
      name: currentDraft.name || imported.name,
      importedCredential: imported.credential,
      secretSource: importedFields.sshImportId ? 'new' : currentDraft.secretSource,
      importWarnings: imported.warnings,
      port: importedFields.port == null ? currentDraft.port : String(importedFields.port),
      setupSource: 'import',
    },
  };
}

function connectionTypeLabel(type: ConnectionType): string {
  return QUICK_SETUP_TYPES.find(([value]) => value === type)?.[1] || 'service';
}

// Whether the draft carries a non-default value in one of the fields hidden
// behind the "Advanced" disclosure, so opening the sheet shows what is set.
function draftUsesAdvancedFields(d: ConnectionDraft, t: ConnectionType): boolean {
  if (t === 'ssh') return Boolean((d.hostKeyFingerprint || '').trim());
  if (t === 'pg') {
    return Boolean((d.pgCaBundlePath || '').trim())
      || Boolean(d.sslmode && d.sslmode !== 'verify-full');
  }
  return false;
}

function connSheet(editing: boolean): string {
  const d = state.draft;
  const t = state.connType;
  const sheetId = state.sheet?.id;
  const conn = editing ? state.connections.find((c) => c.id === sheetId) : null;
  const typeBtn = (val: ConnectionType, label: string): string => {
    if (editing) return `<button type="button" class="seg-btn ${t === val ? 'on' : ''}" disabled ${t === val ? '' : 'style="opacity:.35"'}>${label}</button>`;
    return `<button type="button" class="seg-btn ${t === val ? 'on' : ''}" data-act="conn-type" data-type="${val}">${label}</button>`;
  };
  const importWarnings = !editing && d.importWarnings && d.importWarnings.length
    ? `<div class="pair-identity-warning import-warning"><b>Review imported details</b><ul>${d.importWarnings.map((warning) => `<li>${esc(warning)}</li>`).join('')}</ul></div>` : '';
  let sshHostKeyField = '';
  let pgTlsFields = '';
  let fields = importWarnings;
  const nameTaken = !editing && serviceNameIsTaken(d.name ?? '');
  const nameWarning = editing ? ''
    : `<div id="service-name-warning" class="field-warning" role="status" aria-live="polite"${nameTaken ? '' : ' hidden'}>Name used by an existing service</div>`;
  fields += `<div class="f-row"><label for="f-cname">Name</label><input id="f-cname" class="${fieldCls('name')} ${nameTaken ? 'name-conflict-warning' : ''}"${editing ? '' : ' aria-describedby="service-name-warning"'} placeholder="e.g. github" value="${escAttr(d.name ?? '')}">${fieldErr('name')}${nameWarning}</div>
    <div class="f-row"><label>Type${editing ? ': fixed after creation' : ''}</label>
    <div class="seg in-form">${typeBtn('pg', 'Postgres')}${typeBtn('ssh', 'SSH')}${typeBtn('api', 'HTTP API')}${typeBtn('ws', 'WebSocket')}</div></div>`;
  if (t === 'api') {
    const origin = d.origin ?? apiOriginFromParts(d.scheme ?? undefined, d.host ?? undefined, d.port ?? null);
    fields += `<div class="f-row"><label for="f-origin">API root</label><input id="f-origin" class="${fieldCls('origin')}" placeholder="https://api.github.com" value="${escAttr(origin)}">${fieldErr('origin')}</div>`;
  } else if (t === 'ssh') {
    fields += `<div class="f-2col compact-field-row">
      <div class="f-row" style="flex:0 0 90px"><label for="f-user">User</label><input id="f-user" class="${fieldCls('user')}" placeholder="satoshi" value="${escAttr(d.user ?? '')}">${fieldErr('user')}</div>
      <div class="f-row"><label for="f-host">Host</label><input id="f-host" class="${fieldCls('host')}" placeholder="prod.example.com" value="${escAttr(d.host ?? '')}">${fieldErr('host')}</div>
      <div class="f-row" style="flex:0 0 90px"><label for="f-port">Port</label><input id="f-port" class="${fieldCls('port')}" inputmode="numeric" value="${escAttr(d.port ?? '22')}">${fieldErr('port')}</div></div>`;
    fields += d.proxyJump ? `<div class="rule-note">ProxyJump: ${esc(d.proxyJump)}</div>` : '';
    sshHostKeyField = `<div class="f-row"><label for="f-host-key">Host key fingerprint <span class="label-detail">(optional)</span></label>
      <input id="f-host-key" class="${fieldCls('hostKeyFingerprint')}" placeholder="SHA256:…" value="${escAttr(d.hostKeyFingerprint ?? '')}">${fieldErr('hostKeyFingerprint')}
      <div class="rule-note">The server’s identity (host key) is confirmed with you the first time an agent connects.</div></div>`;
  } else if (t === 'pg') {
    const sslmode = d.sslmode || 'verify-full';
    const sslOpts: Array<[string, string]> = [
      ['verify-full', 'Verify full'],
      ['require', 'Require TLS (no certificate verification)'],
      ['verify-ca', 'Verify CA only (no hostname verification)'],
      ['prefer', 'Prefer (TLS optional)'],
      ['disable', 'Disable'],
    ];
    fields += `<div class="f-2col compact-field-row">
      <div class="f-row"><label for="f-host">Host</label><input id="f-host" class="${fieldCls('host')}" placeholder="db.internal.example.com" value="${escAttr(d.host ?? '')}">${fieldErr('host')}</div>
      <div class="f-row" style="flex:0 0 90px"><label for="f-port">Port</label><input id="f-port" class="${fieldCls('port')}" inputmode="numeric" value="${escAttr(d.port ?? '5432')}">${fieldErr('port')}</div></div>
      <div class="f-2col compact-field-row">
      <div class="f-row"><label for="f-db">Database</label><input id="f-db" class="${fieldCls('dbname')}" placeholder="app_production" value="${escAttr(d.dbname ?? '')}">${fieldErr('dbname')}</div>
      <div class="f-row" style="flex:0 0 90px"><label for="f-user">User</label><input id="f-user" class="${fieldCls('user')}" placeholder="app" value="${escAttr(d.user ?? '')}">${fieldErr('user')}</div></div>`;
    pgTlsFields = `<div class="f-row"><label for="f-sslmode">TLS mode</label>${customSelectHTML('f-sslmode', sslOpts, sslmode, fieldCls('sslmode'))}${fieldErr('sslmode')}
        ${sslmode === 'require' ? '<div class="pair-identity-warning">The server certificate will not be verified.</div>' : ''}</div>
      <div class="f-row"><label for="f-pg-ca-bundle">Trusted CA bundle <span class="label-detail">(optional)</span></label>
        <input id="f-pg-ca-bundle" placeholder="/path/to/private-ca.pem" value="${escAttr(d.pgCaBundlePath ?? '')}"></div>`;
  } else {
    fields += `<div class="f-row"><label for="f-url">URL</label><input id="f-url" class="${fieldCls('url')}" placeholder="wss://stream.example.com/feed" value="${escAttr(d.url ?? '')}">${fieldErr('url')}</div>`;
  }
  // Authentication is recipe-driven for new connections. Existing custom
  // templates remain directly editable so the UI round-trips every config.
  if (editing && t === 'api') {
    fields += `<div class="f-row"><label for="c-template">Injection template</label>
      <input id="c-template" class="${fieldCls('template')}" value="${escAttr(d.template ?? '')}">${fieldErr('template')}
      <div class="rule-note">Bearer token + template; references saved credentials by name.</div></div>`;
  } else if (editing) {
    if (t !== 'ws' || !d.template) fields += credentialChooserHTML(t, d, false);
    if (t === 'ws' && d.template) {
      fields += `<details class="set-collapse" ${d.template ? 'open' : ''}><summary>Custom authentication header</summary>
        <div class="set-panel"><div class="f-row"><label for="c-template">Injection template</label>
        <input id="c-template" class="${fieldCls('template')}" placeholder="Authorization: Bearer {{TOKEN_NAME}}" value="${escAttr(d.template ?? '')}">${fieldErr('template')}</div></div></details>`;
    }
  } else if (t === 'api' || t === 'ws') {
    const modeValue = d.authMode || 'bearer';
    const recipes: Array<[string, string]> = [
      ['bearer', 'Bearer token'], ['header', 'Custom header'],
      ...(t === 'api' ? [['query', 'Query parameter'] as [string, string]] : []),
      ['advanced', 'Bearer token + template'],
    ];
    // Decision first: the authentication type governs which detail field and
    // credential inputs appear, so those render beneath the select.
    fields += `<div class="f-row"><label for="c-auth-mode">Authentication type</label>${customSelectHTML('c-auth-mode', recipes, modeValue)}</div>`;
    if (modeValue === 'header') {
      fields += `<div class="f-row"><label for="c-auth-detail">Header name</label><input id="c-auth-detail" class="${fieldCls('authDetail')}" placeholder="X-API-Key" value="${escAttr(d.authDetail ?? '')}">${fieldErr('authDetail')}</div>`;
    } else if (modeValue === 'query') {
      fields += `<div class="f-row"><label for="c-auth-detail">Query parameter</label><input id="c-auth-detail" class="${fieldCls('authDetail')}" placeholder="api_key" value="${escAttr(d.authDetail ?? '')}">${fieldErr('authDetail')}</div>`;
    }
    if (modeValue === 'advanced') {
      fields += `<div class="f-row"><label for="c-template">Injection template</label><input id="c-template" class="${fieldCls('template')}" placeholder="Authorization: Bearer {{TOKEN_NAME}}" value="${escAttr(d.template ?? '')}">${fieldErr('template')}
        <div class="rule-note">References credentials by name using <code>{{ … }}</code>. Use this for Basic auth or composed credentials.</div></div>`;
    } else {
      fields += credentialChooserHTML(t, d);
    }
  } else {
    fields += credentialChooserHTML(t, d);
  }
  const advancedFields = pgTlsFields + sshHostKeyField;
  if (advancedFields) {
    // Force the section open when one of its fields has a validation error,
    // so the inline message (and the focused input) is visible.
    const advancedError = ['hostKeyFingerprint', 'sslmode', 'pgCaBundlePath']
      .some((key) => state.sheetErrors[key]);
    const advOpen = state.connAdvancedOpen || advancedError;
    fields += `<div class="adv-collapse">
      <button type="button" class="adv-toggle" aria-expanded="${advOpen}" data-act="toggle-conn-advanced">
        <span class="adv-toggle-icon" aria-hidden="true">${ICONS.chevronDown}</span>Advanced</button>
      ${advOpen ? advancedFields : ''}</div>`;
  }
  if (editing && conn && (conn.permissions || []).some((permission) => !permission.expires_at)) {
    fields += `<div class="rule-note">Changing the destination makes affected agents ask for approval again.</div>`;
  }
  const title = editing ? 'Edit service'
    : d.setupSource === 'import' ? `Review ${connectionTypeLabel(t)} service`
    : d.setupSource === 'manual' ? `Add ${connectionTypeLabel(t)} service`
    : 'Add service';
  const discardConfirm = state.confirmDiscard ? `
    <div class="sheet-backdrop over-sheet" data-act="discard-keep"></div>
    <div class="sheet wide confirm-sheet discard-confirm" role="dialog" aria-modal="true" aria-labelledby="discard-conn-title">
      <h3 id="discard-conn-title">${editing ? 'Discard changes?' : 'Discard this service?'}</h3>
      <p>You have unsaved changes in this form. Closing it discards them.</p>
      <div class="sheet-actions">
        <button class="btn" data-act="discard-keep">Keep editing</button>
        <button class="btn danger" data-act="discard-confirm">Discard</button>
      </div></div>` : '';
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>${title}</h3>${fields}
    <div class="sheet-actions"><button class="btn" data-act="sheet-cancel">Cancel</button>
      <button class="btn primary" data-act="save-conn">${editing ? 'Save' : 'Add service'}</button></div></div>${discardConfirm}`;
}

function settingsSheet() {
  const s = state.settings;
  const reauthRow = `<div class="set-row"><div class="set-txt"><div class="st-title">Confirm before using saved secrets</div>
      <div class="st-sub">Use OS authentication before showing, copying, or sending a saved credential.</div></div>
      <button class="switch ${s.reauth_on_read ? 'on' : ''}" data-act="toggle-reauth" role="checkbox" aria-checked="${s.reauth_on_read ? 'true' : 'false'}"></button></div>`;
  const dockRow = `<div class="set-row"><div class="set-txt"><div class="st-title">Hide Dock icon in the menu bar</div>
      <div class="st-sub">When minimized to the menu bar, hide the Dock icon until the window is reopened.</div></div>
      <button class="switch ${s.menu_bar_hides_dock ? 'on' : ''}" data-act="toggle-menubar-dock" role="checkbox" aria-checked="${s.menu_bar_hides_dock ? 'true' : 'false'}"></button></div>`;
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>Settings</h3>
    ${reauthRow}${dockRow}
    <div class="sheet-actions"><button class="btn primary" data-act="sheet-cancel">Done</button></div></div>`;
}

/* ----------------------------- approval window --------------------------- */
function durationLabel(seconds: number): string {
  if (seconds % 60 === 0) {
    const minutes = seconds / 60;
    return `${minutes} minute${minutes === 1 ? '' : 's'}`;
  }
  return `${seconds} seconds`;
}

function approvalWindowLabel(req: ApprovalRequest): string {
  const received = new Date(req.received_at).getTime();
  const deadline = new Date(req.deadline).getTime();
  const seconds = Math.max(0, Math.round((deadline - received) / 1000));
  return durationLabel(seconds);
}

function approvalHeading(req: ApprovalRequest): string {
  const name = req.connection ? req.connection.name : 'AgentMFA';
  if (req.kind === 'pair') return `Let ${req.agent} connect to AgentMFA?`;
  if (req.kind === 'http' && req.http && !req.http.mutating) {
    return `${req.agent} wants to fetch data from ${name}`;
  }
  if (req.kind === 'http') return `${req.agent} wants to make a request through ${name}`;
  if (req.kind === 'ssh' && req.ssh) return `Trust the host key for ${name}?`;
  if (req.kind === 'ssh') return `${req.agent} wants to sign in through ${name}`;
  return `${req.agent} wants to connect to ${name}`;
}

function temporaryAccessExplanation(req: ApprovalRequest): { duration: string; text: string } {
  const connection = req.connection ? req.connection.name : 'this service';
  const access = req.temporary_access || { scope: 'full', duration_seconds: 900 };
  const duration = durationLabel(access.duration_seconds);
  if (access.scope === 'read') {
    return {
      duration,
      text: `For ${duration}, ${req.agent} can fetch data from ${connection} without asking again. Requests that may make changes will still ask.`,
    };
  }
  if (req.kind === 'http') {
    return {
      duration,
      text: `For ${duration}, ${req.agent} can make any request through ${connection} without asking again, including changes and deletes.`,
    };
  }
  return {
    duration,
    text: `For ${duration}, ${req.agent} can open and use ${connection} without asking again. Activity inside an active session is not reviewed individually.`,
  };
}

function ongoingAccessExplanation(req: ApprovalRequest): string {
  const connection = req.connection ? req.connection.name : 'this service';
  if (req.temporary_access && req.temporary_access.scope === 'read') {
    return `${req.agent} will be able to fetch data from ${connection} without asking again. Requests that may make changes will still ask.`;
  }
  if (req.kind === 'http') {
    return `${req.agent} will be able to make any request through ${connection} without asking again, including changes and deletes.`;
  }
  return `${req.agent} will be able to open and use ${connection} without asking again. Activity inside an active session is not reviewed individually.`;
}

function renderApproval() {
  const req = state.queue[0];
  const el = root();
  if (!req) {
    el.innerHTML = `<div class="surface approval"><div class="ap-empty">No requests waiting.</div></div>`;
    resizeApprovalToContent();
    return;
  }
  const conn = req.connection;
  const t = conn ? TYPES[conn.type] : null;
  const isPair = req.kind === 'pair';
  const isHostKey = !!req.ssh;
  if (state.approvalRequestId !== req.id) {
    state.approvalRequestId = req.id;
    state.alwaysOpen = false;
    state.reqDetailOpen = null;
    state.revokeInheritedRules = isPair && !!(req.inherited && req.inherited.length);
  }
  if (isHostKey) ensureKnownHostsCheck(req);
  const connCell = conn
    ? (t ? `<span class="badge ${t.cls}">${t.label}</span> ` : '') + `<b>${esc(conn.name)}</b>`
    : '';
  const connectionRow = conn ? `<div class="ap-row"><span>Service</span><span>${connCell}</span></div>` : '';
  const targetRow = conn ? `<div class="ap-row"><span>Target</span><code>${esc(conn.target)}</code></div>` : '';
  const pairIdentity = req.pairing_identity || {
    program: req.identity || 'Unknown program',
    verification: 'Program identity',
    technical: req.identity || 'Unavailable',
    warning: null,
  };
  const identityRows = isPair ? `
      <div class="ap-row"><span>Requested name</span><span><b>${esc(req.agent)}</b> <em class="self-reported">supplied by program</em></span></div>
      <div class="ap-row"><span>Program</span><b>${esc(pairIdentity.program)}</b></div>
      <div class="ap-row"><span>Verification</span><span>${esc(pairIdentity.verification)}</span></div>` : '';

  let inherit = '';
  if (isPair && req.inherited && req.inherited.length) {
    inherit = `<div class="inherit-warn"><span class="iw-head">This name already has access that does not require approval</span>
      <ul>${req.inherited.map((c) => `<li><b>${esc(c.name)}</b> — ${c.type === 'api' ? 'Any request' : 'Open and use this service'}</li>`).join('')}</ul>
      <div class="pair-choice-head">When this program connects:</div>
      <label class="pair-choice"><input type="radio" name="pair-access" data-act="pair-inheritance" data-revoke="true" ${state.revokeInheritedRules ? 'checked' : ''}>
        <span><b>Require approval again</b><small>Recommended</small></span></label>
      <label class="pair-choice"><input type="radio" name="pair-access" data-act="pair-inheritance" data-revoke="false" ${state.revokeInheritedRules ? '' : 'checked'}>
        <span><b>Keep existing access</b><small>The new program inherits everything listed above</small></span></label></div>`;
  }

  const replacement = isPair && req.replaces_existing_agent
    ? `<div class="pair-replace"><b>${esc(req.agent)} is already connected.</b> Connecting again replaces its current sign-in. Other ${esc(req.agent)} processes may need to reload their saved sign-in.</div>` : '';
  const identityWarning = isPair && pairIdentity.warning
    ? `<div class="pair-identity-warning">${esc(pairIdentity.warning)}</div>` : '';
  const identityDetails = isPair
    ? `<details class="pair-tech"><summary>Technical identity</summary><code>${esc(pairIdentity.technical)}</code></details>` : '';

  const detail = requestDetailHTML(req) + sshHostKeyDetailHTML(req);

  // Host-key trust prompts are a yes/no decision: no "don't ask again",
  // no access session (the broker coerces those decisions to a one-time
  // pin anyway).
  let always: { btn: string; box: string } | null = null;
  if (!isPair && !isHostKey) {
    const box = state.alwaysOpen
      ? `<div class="always-box"><div class="f-row"><label>Use without asking</label>
        <div class="rule-note">${esc(ongoingAccessExplanation(req))} You can require approval again from the Access tab.</div></div>
        <button class="btn primary sm" data-act="always-save">Don’t ask again</button></div>` : '';
    always = { btn: `<button class="btn ghost sm" data-act="always-toggle">Don’t ask again…</button>`, box };
  }

  const temporary = temporaryAccessExplanation(req);
  const sessionNote = !isPair && !isHostKey
    ? `<div class="ap-access-summary"><b>If you allow for ${esc(temporary.duration)}</b><p>${esc(temporary.text)}</p></div>` : '';

  el.innerHTML = `<div class="surface approval">
    <div class="ap-head" data-tauri-drag-region><div class="ap-icon" data-tauri-drag-region>🔐</div>
      <div data-tauri-drag-region><div class="ap-title" data-tauri-drag-region>${esc(approvalHeading(req))}</div></div></div>
    <div class="ap-scroll">
    ${isPair ? `<div class="pair-explainer"><p>This program will be able to list services you have added, and request to make outbound connections to them.</p><p>Agents can never read saved secrets.</p></div>` : ''}
    <div class="ap-rows">
      ${isPair ? identityRows : `<div class="ap-row"><span>Agent</span><b>${esc(req.agent)}</b></div>
      ${connectionRow}${targetRow}
      <div class="ap-row"><span>This request</span><code>${esc(req.action)}</code></div>`}
      <div class="ap-row"><span>Approve within</span><span>${esc(approvalWindowLabel(req))}</span></div>
    </div>
    ${identityWarning}${replacement}${inherit}${identityDetails}${detail}
    ${sessionNote}
    ${always ? `<div class="ap-ongoing-action">${always.btn}</div>${always.box}` : ''}
    </div>
    <div class="ap-buttons">
      <button class="btn deny" data-act="decide-deny" data-id="${req.id}">${isPair ? 'Don’t connect' : 'Deny'}</button>
      ${isPair || isHostKey ? '' : `<button class="btn ghost sm" data-act="decide-once" data-id="${req.id}">This request only</button>`}
      <span class="spacer"></span>
      ${isHostKey
        ? `<button class="btn primary" data-act="decide-once" data-id="${req.id}">Trust &amp; allow</button>`
        : `<button class="btn primary" data-act="decide-allow" data-id="${req.id}">${isPair ? 'Connect agent' : `Allow for ${esc(temporary.duration)}`}</button>`}</div>
    ${state.queue.length > 1 ? `<div class="aw-queue">${state.queue.length - 1} more request${state.queue.length > 2 ? 's' : ''} waiting</div>` : ''}
  </div>`;
  resizeApprovalToContent();
}

function resizeApprovalToContent(): void {
  requestAnimationFrame(() => {
    const approval = document.querySelector<HTMLElement>('.surface.approval');
    if (!approval) return;
    const measure = approval.cloneNode(true) as HTMLElement;
    measure.classList.add('approval-measure');
    document.body.appendChild(measure);
    const height = measure.getBoundingClientRect().height;
    measure.remove();
    void invoke('ui_resize_approval', { height }).catch(() => { /* window may be closing */ });
  });
}

function requestDetailHTML(req: ApprovalRequest): string {
  if (req.kind !== 'http' || !req.http) return '';
  const h = req.http;
  const shown = state.reqDetailOpen === null ? h.mutating : state.reqDetailOpen;
  const head = `<div class="req-detail-head"><button class="btn ghost sm" data-act="req-detail-toggle">${shown ? '▾' : '▸'} Technical request details${h.mutating ? `<span class="mut-tag">${esc(h.method)}</span>` : ''}</button></div>`;
  if (!shown) return head;
  const hdrs = h.headers && h.headers.length
    ? h.headers.map(([k, v]) => `<div class="rd-line"><span class="rd-k">${esc(k)}:</span> ${esc(String(v))}</div>`).join('')
    : '<div class="rd-empty">none</div>';
  let bodyBlock;
  if (h.body_preview == null) bodyBlock = '<div class="rd-empty">none</div>';
  else bodyBlock = `<pre class="rd-body">${esc(h.body_preview)}${h.body_truncated ? `\n… +${h.body_len - h.body_preview.length} bytes not shown` : ''}</pre>`;
  return head + `<div class="req-detail">
    <div class="rd-sub">Additional agent headers</div>${hdrs}
    <div class="rd-sub">Body</div>${bodyBlock}</div>`;
}

/* ---- SSH host-key trust prompts ---- */
// known_hosts provenance, fetched once per prompt (keyed by request id) so
// the chip can say whether the observed key matches the user's own records.
type KnownHostsCheck = HostKeyCandidate[] | 'pending' | 'error';
const knownHostsChecks: Record<string, KnownHostsCheck> = {};

function ensureKnownHostsCheck(req: ApprovalRequest): void {
  const ssh = req.ssh;
  if (!ssh || knownHostsChecks[req.id]) return;
  knownHostsChecks[req.id] = 'pending';
  invoke('check_known_hosts', { host: ssh.host, port: ssh.port })
    .then((candidates) => { knownHostsChecks[req.id] = candidates; })
    .catch(() => { knownHostsChecks[req.id] = 'error'; })
    .finally(() => {
      if (mode === 'approval' && state.queue[0] && state.queue[0].id === req.id) render();
    });
}

function knownHostsChipHTML(req: ApprovalRequest): string {
  const ssh = req.ssh;
  if (!ssh) return '';
  const check = knownHostsChecks[req.id];
  if (!check || check === 'pending') return `<span class="hk-chip">Checking known_hosts…</span>`;
  if (check === 'error') return `<span class="hk-chip">Couldn’t check known_hosts</span>`;
  const match = check.find((candidate) => candidate.fingerprint === ssh.observed_fingerprint);
  if (match) {
    return `<span class="hk-chip ok" title="${escAttr(match.source)}">${ICONS.check} Matches your known_hosts</span>`;
  }
  if (!check.length) return `<span class="hk-chip warn">First sighting — verify out-of-band</span>`;
  return `<span class="hk-chip danger">${ICONS.circleX} Conflicts with your known_hosts</span>`;
}

function sshHostKeyDetailHTML(req: ApprovalRequest): string {
  const ssh = req.ssh;
  if (!ssh) return '';
  return `<div class="hk-detail">
    <div class="rd-sub">Server host key (${esc(ssh.algorithm)})</div>
    <code class="hk-fingerprint">${esc(ssh.observed_fingerprint)}</code>
    <div class="hk-provenance">${knownHostsChipHTML(req)}</div>
    <p class="hk-note">First connection to this server. Trusting this key pins it: later connections must present the same key or are refused.</p>
  </div>`;
}

/* --------------------------------- helpers ------------------------------- */
const cap = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);
const tabLabel = (tab: Tab): string => tab === 'connections' ? 'Services' : cap(tab);

// Flash "Copied" in place of the masked value for a moment after a copy.
let copiedTimer: ReturnType<typeof setTimeout> | null = null;
function flashCopied(id: string): void {
  state.copied = id;
  render();
  if (copiedTimer) clearTimeout(copiedTimer);
  copiedTimer = setTimeout(() => { state.copied = null; render(); }, 1400);
}

let readyCopiedTimer: ReturnType<typeof setTimeout> | null = null;
function flashReadyCopied(): void {
  state.readyCopied = true;
  render();
  if (readyCopiedTimer) clearTimeout(readyCopiedTimer);
  readyCopiedTimer = setTimeout(() => { state.readyCopied = false; render(); }, 1400);
}

// Focus a sheet field on open (after the render that creates it).
function focusField(id: string): void {
  setTimeout(() => {
    const el = document.getElementById(id);
    if (el) el.focus();
  }, 0);
}

// Anchor the fixed-position listbox menu to its trigger, flipping above
// when the viewport bottom would cut it off. Runs after every render while
// a menu is open, and again on scroll/resize so it tracks the trigger.
function positionFormMenu(): void {
  const trigger = state.formMenuOpen ? document.getElementById(state.formMenuOpen) : null;
  const menu = document.querySelector<HTMLElement>('.cred-menu');
  if (!trigger || !menu) return;
  // A fixed descendant is still clipped by an ancestor's overflow. Move the
  // listbox out of the scrolling sheet before positioning it so the sheet can
  // keep its scrollbar without cutting the menu off.
  if (menu.parentElement !== root()) root().appendChild(menu);
  const rect = trigger.getBoundingClientRect();
  menu.style.left = `${rect.left}px`;
  menu.style.width = `${rect.width}px`;
  const below = rect.bottom + 5;
  const flip = below + menu.offsetHeight > window.innerHeight - 8 &&
    rect.top - menu.offsetHeight - 5 > 8;
  menu.style.top = flip ? `${rect.top - menu.offsetHeight - 5}px` : `${below}px`;
  menu.style.visibility = 'visible';
}

// Focus the selected option when a listbox menu opens.
function focusMenuOption(): void {
  setTimeout(() => {
    const menu = document.querySelector<HTMLElement>('.cred-menu');
    const option = menu?.querySelector<HTMLElement>('[aria-selected="true"]')
      ?? menu?.querySelector<HTMLElement>('[role="option"]');
    option?.focus();
  }, 0);
}

function focusImportedConnectionDraft(): void {
  const d = state.draft;
  const type = state.connType;
  if (!(d.name || '').trim()) {
    focusField('f-cname');
    return;
  }
  const missing = type === 'pg'
    ? [[d.host, 'f-host'], [d.dbname, 'f-db'], [d.user, 'f-user']]
    : type === 'ssh'
    // The host key fingerprint is optional (trusted at first connection).
    ? [[d.host, 'f-host'], [d.user, 'f-user']]
    : type === 'api'
    ? [[d.origin, 'f-origin']]
    : [[d.url, 'f-url']];
  const firstMissing = missing.find(([value]) => !String(value || '').trim());
  focusField(firstMissing ? String(firstMissing[1]) : 'f-cname');
}

const INPUT_BY_ERROR_FIELD = {
  name: 'f-cname', value: 'f-value', origin: 'f-origin', host: 'f-host', port: 'f-port',
  dbname: 'f-db', user: 'f-user', hostKeyFingerprint: 'f-host-key', sslmode: 'f-sslmode',
  url: 'f-url', template: 'c-template', secret: 'c-secret',
  newSecretName: 'c-new-secret-name', newSecretValue: 'c-new-secret-value',
};

function showFormError(error: unknown): void {
  const inline = inlineFormError(error);
  if (!inline) {
    const prefix = formErrorKind(error) === 'cancelled' ? '' : '⚠ ';
    toast(prefix + formErrorMessage(error));
    return;
  }
  state.sheetErrors = { ...state.sheetErrors, [inline.field]: inline.message };
  render();
  const defaultNameId = state.sheet && state.sheet.kind.includes('secret') ? 'f-name' : 'f-cname';
  const inputId = inline.field === 'name'
    ? defaultNameId
    : INPUT_BY_ERROR_FIELD[inline.field as keyof typeof INPUT_BY_ERROR_FIELD];
  if (inputId) focusField(inputId);
}

function selectEditSecretMask() {
  setTimeout(() => {
    const el = document.getElementById('f-value') as HTMLInputElement | null;
    if (state.sheet && state.sheet.kind === 'edit-secret' && el && el.value === EDIT_SECRET_MASK) {
      el.focus();
      el.select();
    }
  }, 0);
}

function captureDrafts(): void {
  const g = (id: string): string | undefined => {
    const el = document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null;
    return el?.value;
  };
  if (state.sheet && (state.sheet.kind === 'add-secret' || state.sheet.kind === 'edit-secret')) {
    if (g('f-name') !== undefined) state.draft.name = g('f-name');
    if (g('f-value') !== undefined) state.draft.value = g('f-value');
  }
  if (state.sheet && (state.sheet.kind === 'add-conn' || state.sheet.kind === 'edit-conn')) {
    if (g('f-cname') !== undefined) state.draft.name = g('f-cname');
    if (g('f-origin') !== undefined) state.draft.origin = g('f-origin');
    if (g('f-host') !== undefined) state.draft.host = g('f-host');
    if (g('f-port') !== undefined) state.draft.port = g('f-port');
    if (g('f-db') !== undefined) state.draft.dbname = g('f-db');
    if (g('f-user') !== undefined) state.draft.user = g('f-user');
    if (g('f-host-key') !== undefined) state.draft.hostKeyFingerprint = g('f-host-key');
    if (g('f-sslmode') !== undefined) state.draft.sslmode = g('f-sslmode');
    if (g('f-pg-ca-bundle') !== undefined) state.draft.pgCaBundlePath = g('f-pg-ca-bundle');
    if (g('f-url') !== undefined) state.draft.url = g('f-url');
    if (g('c-template') !== undefined) state.draft.template = g('c-template');
    const secretChoice = g('c-secret');
    if (secretChoice !== undefined) {
      if (secretChoice === NEW_CREDENTIAL_OPTION) {
        state.draft.secretSource = 'new';
      } else if (secretChoice) {
        state.draft.secretId = secretChoice;
        state.draft.secretSource = 'existing';
      }
      // An empty value is the unselected placeholder: leave the draft as-is.
    }
    if (g('c-new-secret-name') !== undefined) state.draft.newSecretName = g('c-new-secret-name');
    if (g('c-identity-file') !== undefined) state.draft.identityFile = g('c-identity-file');
    if (g('c-new-secret-value') !== undefined) {
      state.draft.newSecretValue = g('c-new-secret-value');
      delete state.draft.importedCredential;
    }
    if (g('c-auth-mode') !== undefined) state.draft.authMode = g('c-auth-mode');
    if (g('c-auth-detail') !== undefined) state.draft.authDetail = g('c-auth-detail');
  }
}

/* --------------------------------- actions ------------------------------- */
function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function run(fn: () => Promise<unknown>): Promise<boolean> {
  try { await fn(); return true; } catch (error) { toast('⚠ ' + errorMessage(error)); return false; }
}

function isProtectedFormSheet(sheet: SheetState | null = state.sheet): boolean {
  return sheet?.kind === 'add-secret' || sheet?.kind === 'edit-secret'
    || sheet?.kind === 'add-conn' || sheet?.kind === 'edit-conn';
}

async function holdDropdownFormOpen(): Promise<boolean> {
  if (mode !== 'dropdown') return true;
  try {
    await invoke('ui_set_dropdown_form_active', { active: true });
    return true;
  } catch (error) {
    toast('⚠ Couldn’t keep this form open: ' + errorMessage(error));
    return false;
  }
}

function releaseDropdownForm(): void {
  if (mode !== 'dropdown') return;
  void invoke('ui_set_dropdown_form_active', { active: false })
    .catch((error) => toast('⚠ Couldn’t release the menu-bar form: ' + errorMessage(error)));
}

async function saveSecret(): Promise<void> {
  captureDrafts();
  const sheet = state.sheet;
  if (!sheet || (sheet.kind !== 'add-secret' && sheet.kind !== 'edit-secret')) return;
  const name = (state.draft.name || '').trim();
  const value = state.draft.value || '';
  const errs: Record<string, string> = {};
  if (!name) errs.name = 'Name is required';
  if (sheet.kind === 'add-secret' && !value) errs.value = 'Value is required';
  if (Object.keys(errs).length) { state.sheetErrors = errs; render(); return; }
  if (sheet.kind === 'add-secret') {
    try { await invoke('add_secret', { name, value }); }
    catch (error) { showFormError(error); return; }
    toast('🔑 Saved to macOS Keychain');
  } else {
    if (value !== EDIT_SECRET_MASK && (!value || value.includes('•'))) {
      state.sheetErrors = { value: 'Invalid value' };
      render();
      return;
    }
    try {
      await invoke('edit_secret', {
        id: sheet.id ?? '',
        newName: name,
        newValue: value === EDIT_SECRET_MASK ? null : value,
      });
    } catch (error) { showFormError(error); return; }
    toast('✏️ Secret updated');
  }
  closeSheet();
  await refresh('secrets');
}

async function saveConn(): Promise<void> {
  captureDrafts();
  const sheet = state.sheet;
  if (!sheet || (sheet.kind !== 'add-conn' && sheet.kind !== 'edit-conn')) return;
  const d = state.draft;
  const name = (d.name || '').trim();
  const t = state.connType;
  const adding = sheet.kind === 'add-conn';
  const serviceNameTaken = adding && serviceNameIsTaken(name);
  const authMode = d.authMode || 'bearer';
  const errs: Record<string, string> = {};
  if (!name) errs.name = 'Name is required';
  if (t === 'api' || t === 'pg' || t === 'ssh') {
    if (t !== 'api' && !(d.host || '').trim()) errs.host = 'Host is required';
  }
  let port = t === 'ssh' ? 22 : 5432;
  if (t === 'pg' || t === 'ssh') {
    const portStr = (d.port ?? '').trim() || String(port);
    port = Number(portStr);
    if (!/^\d+$/.test(portStr) || !Number.isInteger(port) || port < 1 || port > 65535) {
      errs.port = 'Port must be 1–65535';
    }
    if (t === 'pg' && !(d.dbname || '').trim()) errs.dbname = 'Database is required';
    if (!(d.user || '').trim()) errs.user = 'User is required';
    // The SSH host key fingerprint is optional: empty saves the service
    // unpinned, and the key is confirmed at the first agent connection.
  }
  if (t === 'ws') {
    const url = (d.url || '').trim();
    if (!url) errs.url = 'URL is required';
    else if (!/^wss?:\/\//i.test(url)) errs.url = 'Must start with ws:// or wss://';
  }
  let apiOrigin = null;
  if (t === 'api') {
    try { apiOrigin = parseApiOrigin(d.origin || ''); }
    catch (error) { errs.origin = errorMessage(error); }
  }
  const usesRecipe = adding && (t === 'api' || t === 'ws') && authMode !== 'advanced';
  const needsCredentialChoice = (adding && !((t === 'api' || t === 'ws') && authMode === 'advanced')) ||
    (!adding && t !== 'api');
  const secretSource = adding
    ? (d.secretSource || (d.importedCredential || d.sshImportId || !state.secrets.length ? 'new' : 'existing'))
    : 'existing';
  let selectedSecret: SecretSummary | null = null;
  let newSecretName: string | null = null;
  let newSecretNameTaken = false;
  if (needsCredentialChoice && secretSource === 'existing') {
    selectedSecret = state.secrets.find((secret) => secret.id === d.secretId) || null;
    if (!selectedSecret) errs.secret = 'Choose a saved credential or save a new one';
  } else if (needsCredentialChoice) {
    newSecretName = (d.newSecretName || suggestedSecretName(name, t)).trim();
    const hasImportedIdentity = t === 'ssh' && d.sshImportId && d.identityFile;
    const newSecretValue = d.newSecretValue ?? d.importedCredential ?? '';
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(newSecretName)) {
      errs.newSecretName = 'Use letters, numbers, and underscores; start with a letter or underscore';
    }
    newSecretNameTaken = credentialNameIsTaken(newSecretName);
    if (!newSecretValue && !hasImportedIdentity) errs.newSecretValue = 'Credential value is required';
  }
  const templateSecretName = selectedSecret ? selectedSecret.name : newSecretName;
  let injectionTemplate = (d.template || '').trim();
  if (usesRecipe) {
    try { injectionTemplate = authTemplate(t, authMode, templateSecretName || '', (d.authDetail || '').trim()); }
    catch (error) { errs.authDetail = errorMessage(error); }
  } else if ((t === 'api' || (adding && t === 'ws')) && authMode === 'advanced' && !injectionTemplate) {
    errs.template = 'Injection template is required';
  } else if (!adding && t === 'api' && !injectionTemplate) {
    errs.template = 'Injection template is required';
  }
  if (Object.keys(errs).length || serviceNameTaken || newSecretNameTaken) {
    state.sheetErrors = errs;
    render();
    if (serviceNameTaken) focusField('f-cname');
    else if (newSecretNameTaken) focusField('c-new-secret-name');
    return;
  }
  const input: ConnectionInput = { name, type: t };
  if (adding && needsCredentialChoice && secretSource === 'new') {
    input.new_secret_name = newSecretName;
    if (t === 'ssh' && d.sshImportId && d.identityFile) {
      input.ssh_import_id = d.sshImportId;
      input.identity_file = d.identityFile;
    } else {
      input.new_secret_value = d.newSecretValue ?? d.importedCredential;
    }
  }
  if (t === 'api') {
    input.host = apiOrigin!.host;
    input.scheme = apiOrigin!.scheme;
    input.port = apiOrigin!.port;
    input.template = injectionTemplate;
  } else if (t === 'pg') {
    input.host = (d.host || '').trim();
    input.port = port;
    input.dbname = (d.dbname || '').trim();
    input.user = (d.user || '').trim();
    input.sslmode = d.sslmode || 'verify-full';
    input.trusted_ca_bundle_path = (d.pgCaBundlePath || '').trim() || null;
    if (selectedSecret) input.secret_id = selectedSecret.id;
  } else if (t === 'ssh') {
    input.destination = (d.destination || '').trim() || null;
    input.host = (d.host || '').trim();
    input.port = port;
    input.user = (d.user || '').trim();
    input.host_key_fingerprint = (d.hostKeyFingerprint || '').trim();
    if (selectedSecret) input.secret_id = selectedSecret.id;
  } else {
    input.url = (d.url || '').trim();
    input.template = injectionTemplate || null;
    if (selectedSecret) input.secret_id = selectedSecret.id;
  }
  try {
    if (adding) await invoke('add_connection', { input });
    else await invoke('edit_connection', { id: sheet.id ?? '', input });
    toast(adding ? '🔌 Service saved' : '✏️ Service updated');
    if (adding) {
      if (!state.connections.length) {
        state.connectionReady = { name, type: t };
        state.connectionTaskCopied = false;
      }
      state.quickSetupSource = '';
      state.quickSetupError = null;
    }
    closeSheet();
    await refresh('all');
  } catch (e) {
    showFormError(e);
  }
}

function closeSheet() {
  const releaseDropdown = isProtectedFormSheet();
  state.sheet = null;
  state.draft = {};
  state.sheetErrors = {};
  state.sheetBaseline = null;
  state.confirmDiscard = false;
  state.formMenuOpen = null;
  render();
  if (releaseDropdown) releaseDropdownForm();
}

// Draft fields compared against the sheet-open baseline to decide whether
// cancelling should ask before discarding.
const DIRTY_DRAFT_FIELDS: Array<keyof ConnectionDraft> = [
  'name', 'origin', 'host', 'port', 'dbname', 'user', 'url', 'template',
  'hostKeyFingerprint', 'sslmode', 'pgCaBundlePath', 'secretId', 'secretSource',
  'newSecretName', 'newSecretValue', 'authMode', 'authDetail', 'identityFile',
];

function connDraftSignature(): string {
  // When adding, switching the type auto-fills defaults (port, TLS mode), so
  // exclude the type and those fields — only typed content should count as
  // an edit worth a discard confirmation.
  const adding = state.sheet?.kind === 'add-conn';
  const fields = adding
    ? DIRTY_DRAFT_FIELDS.filter((key) => key !== 'port' && key !== 'sslmode')
    : DIRTY_DRAFT_FIELDS;
  const values = fields.map((key) => {
    const value = state.draft[key];
    return value == null || value === '' ? null : value;
  });
  return (adding ? '' : state.connType) + '|' + JSON.stringify(values);
}

function requestCloseSheet(): void {
  const kind = state.sheet?.kind;
  if ((kind === 'add-conn' || kind === 'edit-conn') && state.sheetBaseline !== null) {
    captureDrafts();
    if (connDraftSignature() !== state.sheetBaseline) {
      state.confirmDiscard = true;
      render(false);
      return;
    }
  }
  closeSheet();
}

/* --------------------------------- events -------------------------------- */
document.addEventListener('click', async (e) => {
  const target = e.target instanceof Element ? e.target : null;
  const btn = target?.closest<HTMLElement>('[data-act]') ?? null;
  // Dismiss the desktop settings popover on any click outside it (its own
  // toggle handles itself; menu-item clicks close it in their handlers).
  if (state.menuOpen && !target?.closest('.settings-menu') &&
      !(btn && btn.dataset.act === 'toggle-settings-menu')) {
    state.menuOpen = false;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.walkthroughMenuOpen && !target?.closest('.walkthrough-menu-wrap')) {
    state.walkthroughMenuOpen = false;
    if (!btn) { render(); return; }
  }
  if (state.agentMenuOpen && !target?.closest('.agent-menu-wrap')) {
    state.agentMenuOpen = null;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.formMenuOpen && !target?.closest('.cred-select') && !target?.closest('.cred-menu')) {
    state.formMenuOpen = null;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (!btn) return;
  const act = btn.dataset.act;
  const id = btn.dataset.id ?? '';
  const name = btn.dataset.name ?? '';
  switch (act) {
    case 'tab': {
      const tab = btn.dataset.tab;
      if (tab && TABS.includes(tab as Tab)) state.tab = tab as Tab;
      state.confirm = null;
      state.walkthroughMenuOpen = false;
      state.agentMenuOpen = null;
      render();
      break;
    }
    case 'mode-tray': state.menuOpen = false; run(() => invoke('ui_set_mode', { mode: 'tray' })); break;
    case 'mode-window': run(() => invoke('ui_set_mode', { mode: 'window' })); break;
    case 'toggle-settings-menu': state.menuOpen = !state.menuOpen; render(); break;
    case 'toggle-walkthrough-menu':
      state.menuOpen = false;
      state.walkthroughMenuOpen = !state.walkthroughMenuOpen;
      render();
      break;
    case 'toggle-agent-menu':
      state.agentMenuOpen = state.agentMenuOpen === id ? null : id;
      render();
      break;
    case 'toggle-service-walkthrough': {
      const on = !state.settings.show_service_walkthrough;
      if (await run(() => invoke('set_service_walkthrough_visible', { on }))) {
        state.settings.show_service_walkthrough = on;
        render();
      }
      break;
    }
    case 'toggle-agent-walkthrough': {
      const on = !state.settings.show_agent_walkthrough;
      if (await run(() => invoke('set_agent_walkthrough_visible', { on }))) {
        state.settings.show_agent_walkthrough = on;
        if (!on) state.setupInstructionsOpen = false;
        render();
      }
      break;
    }
    case 'hide-service-walkthrough':
      if (await run(() => invoke('set_service_walkthrough_visible', { on: false }))) {
        state.settings.show_service_walkthrough = false;
        render();
      }
      break;
    case 'hide-agent-walkthrough':
      if (await run(() => invoke('set_agent_walkthrough_visible', { on: false }))) {
        state.settings.show_agent_walkthrough = false;
        state.setupInstructionsOpen = false;
        render();
      }
      break;
    case 'open-settings': state.menuOpen = false; state.sheet = { kind: 'settings' }; render(); break;
    case 'copy-agent-setup':
      if (state.agentMenuOpen) { state.agentMenuOpen = null; render(); }
      if (await run(() => invoke('copy_agent_setup'))) toast('📋 Setup instructions copied');
      break;
    case 'toggle-setup-instructions':
      state.setupInstructionsOpen = !state.setupInstructionsOpen;
      if (state.setupInstructionsOpen) {
        render();
        if (!state.showFullInstructions && !state.agentSetupInstructions) {
          await run(async () => {
            state.agentSetupInstructions = await invoke('get_agent_setup');
          });
        } else if (state.showFullInstructions && !state.brokerInstructions) {
          const ok = await run(async () => {
            state.brokerInstructions = await invoke('get_broker_instructions');
          });
          if (!ok) state.showFullInstructions = false;
        }
      }
      render();
      break;
    case 'set-instructions-detail': {
      if (!state.setupInstructionsOpen) break;
      const full = btn.dataset.full === 'true';
      if (full === state.showFullInstructions) break;
      state.showFullInstructions = full;
      if (full && !state.brokerInstructions) {
        render();
        const ok = await run(async () => {
          state.brokerInstructions = await invoke('get_broker_instructions');
        });
        if (!ok) state.showFullInstructions = false;
      } else if (!full && !state.agentSetupInstructions) {
        render();
        await run(async () => {
          state.agentSetupInstructions = await invoke('get_agent_setup');
        });
      }
      render();
      break;
    }
    case 'copy-ready-setup':
      if (await run(() => invoke('copy_agent_setup'))) flashReadyCopied();
      break;
    case 'clear-activity-ask':
      state.sheet = { kind: 'clear-activity' };
      render();
      break;
    case 'clear-activity-confirm':
      if (await run(() => invoke('clear_activity'))) {
        state.activity = [];
        closeSheet();
        toast('Activity cleared');
      }
      break;

    case 'reveal-secret':
      await run(async () => { state.reveal[id] = await invoke('reveal_secret_prefix', { id }); render(); });
      break;
    case 'hide-secret':
      delete state.reveal[id]; render(); break;
    case 'copy-secret':
      if (await run(() => invoke('copy_secret', { id }))) {
        toast('📋 Copied for 30s');
        flashCopied(id);
      }
      break;
    case 'del-secret-ask': {
      const s = state.secrets.find((x) => x.id === id);
      state.confirm = { kind: s && s.used_by ? 'del-secret-inuse' : 'del-secret', id };
      render();
      break;
    }
    case 'del-secret-confirm':
      if (await run(() => invoke('delete_secret', { id }))) {
        state.confirm = null; toast('🗑 Removed from macOS Keychain'); await refresh('secrets');
      }
      break;
    case 'edit-secret':
      if (!await holdDropdownFormOpen()) break;
      state.sheet = { kind: 'edit-secret', id };
      state.draft = { value: EDIT_SECRET_MASK };
      state.sheetErrors = {};
      render();
      selectEditSecretMask();
      break;
    case 'open-add-secret':
      if (!await holdDropdownFormOpen()) break;
      state.sheet = { kind: 'add-secret' }; state.draft = {}; state.sheetErrors = {};
      render(); focusField('f-name'); break;
    case 'save-secret': await saveSecret(); break;

    case 'quick-setup-type': {
      const type = btn.dataset.type as ConnectionType | undefined;
      if (type && QUICK_SETUP_TYPES.some(([value]) => value === type)) {
        state.quickSetupType = type;
        state.quickSetupError = null;
        render();
        focusField('quick-setup-source');
      }
      break;
    }
    case 'quick-setup-review': {
      try {
        const imported = await connectionDraftFromImport(state.quickSetupSource);
        if (!await holdDropdownFormOpen()) break;
        state.quickSetupType = imported.type;
        state.quickSetupError = null;
        state.sheet = { kind: 'add-conn' };
        state.connType = imported.type;
        state.draft = imported.draft;
        state.sheetErrors = {};
        state.sheetBaseline = null;
        state.connAdvancedOpen = draftUsesAdvancedFields(state.draft, state.connType);
        render();
        focusImportedConnectionDraft();
      } catch (error) {
        state.quickSetupError = errorMessage(error);
        render();
        focusField('quick-setup-source');
      }
      break;
    }
    case 'copy-first-task': {
      const ready = state.connectionReady;
      if (!ready) break;
      try {
        await navigator.clipboard.writeText(firstTaskPrompt(ready.name, ready.type));
        state.connectionTaskCopied = true;
        render();
        setTimeout(() => { state.connectionTaskCopied = false; render(); }, 1400);
      } catch {
        toast('⚠ Could not copy the task');
      }
      break;
    }
    case 'dismiss-connection-ready':
      state.connectionReady = null;
      state.connectionTaskCopied = false;
      render();
      break;
    case 'open-add-conn':
      if (!await holdDropdownFormOpen()) break;
      state.sheet = { kind: 'add-conn' }; state.connType = 'api'; state.draft = {};
      state.sheetErrors = {}; state.sheetBaseline = null; state.connAdvancedOpen = false;
      render(); focusField('f-cname'); break;
    case 'edit-conn': {
      const c = state.connections.find((x) => x.id === id);
      if (!c) break;
      if (!await holdDropdownFormOpen()) break;
      state.sheet = { kind: 'edit-conn', id }; state.connType = c.type;
      state.sheetErrors = {};
      state.sheetBaseline = null;
      state.draft = { name: c.name, host: c.host, scheme: c.scheme,
        origin: c.type === 'api'
          ? apiOriginFromParts(c.scheme ?? undefined, c.host ?? undefined, c.port)
          : null,
        port: c.port ? String(c.port) : (c.type === 'ssh' ? '22' : '5432'),
        dbname: c.dbname, user: c.user, url: c.url, template: c.template,
        destination: c.destination,
        hostKeyFingerprint: c.host_key_fingerprint,
        sslmode: c.sslmode || 'verify-full', pgCaBundlePath: c.trusted_ca_bundle_path,
        secretId: null };
      // best-effort: prefill single-secret binding by name→id
      if (c.type !== 'api' && c.secret_names.length) {
        const s = state.secrets.find((s) => s.name === c.secret_names[0]);
        if (s) state.draft.secretId = s.id;
      }
      state.connAdvancedOpen = draftUsesAdvancedFields(state.draft, state.connType);
      render(); focusField('f-cname'); break;
    }
    case 'conn-type': {
      captureDrafts();
      const nextType = btn.dataset.type;
      if (!nextType || !['api', 'pg', 'ws', 'ssh'].includes(nextType)) break;
      const typedNextType = nextType as ConnectionType;
      state.draft.port = portForTypeSwitch(
        state.connType,
        typedNextType,
        state.draft.port ?? null,
      );
      state.connType = typedNextType;
      state.sheetErrors = {};
      state.formMenuOpen = null;
      render(false);
      break;
    }
    case 'toggle-conn-advanced':
      captureDrafts();
      state.connAdvancedOpen = !state.connAdvancedOpen;
      render(false);
      break;
    case 'select-toggle': {
      const menuId = btn.dataset.menu ?? '';
      captureDrafts();
      state.formMenuOpen = state.formMenuOpen === menuId ? null : menuId;
      render(false);
      if (state.formMenuOpen) focusMenuOption();
      else focusField(menuId);
      break;
    }
    case 'select-pick': {
      const menuId = btn.dataset.menu ?? '';
      captureDrafts();
      state.formMenuOpen = null;
      const errKey = ERR_KEY_BY_INPUT[menuId as keyof typeof ERR_KEY_BY_INPUT];
      if (errKey) delete state.sheetErrors[errKey];
      if (menuId === 'c-auth-mode') state.draft.authMode = id;
      else if (menuId === 'f-sslmode') state.draft.sslmode = id;
      else if (menuId === 'c-identity-file') state.draft.identityFile = id;
      render(false);
      focusField(menuId);
      break;
    }
    case 'credential-pick':
      captureDrafts();
      state.formMenuOpen = null;
      delete state.sheetErrors.secret;
      if (id === NEW_CREDENTIAL_OPTION) {
        state.draft.secretSource = 'new';
      } else {
        state.draft.secretSource = 'existing';
        state.draft.secretId = id;
      }
      render(false);
      focusField(id === NEW_CREDENTIAL_OPTION ? 'c-new-secret-name' : 'c-secret');
      break;
    case 'save-conn': await saveConn(); break;
    case 'del-conn-ask': state.confirm = { kind: 'del-conn', id }; render(); break;
    case 'del-conn-confirm':
      if (await run(() => invoke('delete_connection', { id }))) {
        state.confirm = null;
        delete state.connTests[id];
        toast('🗑 Service removed');
        await refresh('all');
      }
      break;
    case 'test-conn': {
      if (state.connTests[id] && state.connTests[id].running) break;
      state.connTests[id] = { running: true };
      render();
      try {
        const report = await invoke('test_connection', { id });
        state.connTests[id] = { running: false, ok: report.ok, detail: report.detail };
      } catch (error) {
        state.connTests[id] = { running: false, ok: false, detail: errorMessage(error) };
      }
      render();
      break;
    }
    case 'del-permission':
      await run(() => invoke('remove_permission', { id }));
      toast('🔒 Approval will be required again'); await refresh('all');
      break;

    case 'revoke-ask': {
      if (state.agentMenuOpen) { state.agentMenuOpen = null; render(); }
      let confirmed = false;
      if (!await run(async () => { confirmed = await invoke('confirm_agent_disconnect'); }) || !confirmed) break;
      if (await run(() => invoke('revoke_agent', { id }))) {
        toast('🔒 Agent disconnected'); await refresh('all');
      }
      break;
    }
    case 'close-session-ask': state.confirm = { kind: 'close-session', id: Number(id) }; render(); break;
    case 'close-session-confirm':
      if (await run(() => invoke('close_session', { id: Number(id) }))) {
        state.confirm = null; toast('⏹ Connection closed'); await refresh('sessions');
      }
      break;
    case 'confirm-cancel': state.confirm = null; render(); break;

    case 'sheet-cancel': requestCloseSheet(); break;
    case 'discard-keep': state.confirmDiscard = false; render(false); break;
    case 'discard-confirm': closeSheet(); break;
    case 'toggle-reauth':
      {
        const on = !state.settings.reauth_on_read;
        await run(() => invoke('set_reauth_on_read', { on }));
        toast(on ? '💳 Confirmation required before using saved secrets' : '💳 Extra confirmation removed');
      }
      await refresh('settings');
      break;
    case 'toggle-menubar-dock':
      {
        const on = !state.settings.menu_bar_hides_dock;
        await run(() => invoke('set_menu_bar_hides_dock', { on }));
        toast(on ? '🚢 Dock icon hidden in the menu bar' : '🚢 Dock icon kept in the menu bar');
      }
      await refresh('settings');
      break;
    // Approval window
    case 'req-detail-toggle': {
      const req = state.queue[0];
      const shownNow = state.reqDetailOpen === null ? (req.http && req.http.mutating) : state.reqDetailOpen;
      state.reqDetailOpen = !shownNow; render(); break;
    }
    case 'pair-inheritance': state.revokeInheritedRules = btn.dataset.revoke === 'true'; render(); break;
    case 'always-toggle': state.alwaysOpen = !state.alwaysOpen; render(); break;

    case 'decide-deny': await decide(id, 'deny'); break;
    case 'decide-allow': await decide(id, mode === 'approval' && state.queue[0] && state.queue[0].kind !== 'pair' ? 'allow_session' : 'allow_once'); break;
    case 'decide-once': await decide(id, 'allow_once'); break;
    case 'always-save': await decide(id, 'always_allow'); break;
    case 'open-approval': run(() => invoke('ui_show_approval')); break;
    default: break;
  }
});

async function decide(id: string, decision: Decision): Promise<void> {
  try {
    const req = state.queue[0];
    const revokeInheritedRules =
      decision === 'allow_once' && req && req.kind === 'pair' && !!state.revokeInheritedRules;
    await invoke('decide', { id, decision, revokeInheritedRules });
    state.alwaysOpen = false;
    state.reqDetailOpen = null;
    state.revokeInheritedRules = false;
  } catch (error) {
    // OS authentication cancelled or failed: keep the request pending.
    toast('🔒 ' + errorMessage(error));
  }
  await refresh('queue');
}

document.addEventListener('keydown', (e) => {
  // Ctrl-Tab / Ctrl-Shift-Tab cycle the left-nav tabs when the main window is
  // open (the approval window has no tabs; a modal sheet keeps focus).
  if (e.key === 'Enter' && e.target instanceof HTMLInputElement && e.target.id === 'quick-setup-source') {
    e.preventDefault();
    document.querySelector<HTMLElement>('[data-act="quick-setup-review"]')?.click();
    return;
  }
  if (e.key === 'Tab' && e.ctrlKey && mode !== 'approval' && !state.sheet) {
    e.preventDefault();
    const i = TABS.indexOf(state.tab);
    const n = TABS.length;
    state.tab = TABS[(i + (e.shiftKey ? -1 : 1) + n) % n];
    state.menuOpen = false;
    render();
    return;
  }
  if (e.key === 'Escape') {
    if (state.walkthroughMenuOpen) { state.walkthroughMenuOpen = false; render(); return; }
    if (state.agentMenuOpen) { state.agentMenuOpen = null; render(); return; }
    if (state.menuOpen) { state.menuOpen = false; render(); return; }
    if (state.formMenuOpen) {
      const menuId = state.formMenuOpen;
      state.formMenuOpen = null;
      render(false);
      focusField(menuId);
      return;
    }
    if (state.confirmDiscard) { state.confirmDiscard = false; render(false); return; }
    if (state.sheet) { requestCloseSheet(); return; }
    if (state.confirm) { state.confirm = null; render(); return; }
    if (mode === 'dropdown') invoke('ui_hide_dropdown');
  } else if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && state.sheet &&
      (state.formMenuOpen ||
        (e.key === 'ArrowDown' && document.activeElement?.classList.contains('cred-trigger')))) {
    // Native-select keyboard behavior for the listboxes: ArrowDown on a
    // closed trigger opens it; arrows move between options once open.
    e.preventDefault();
    if (!state.formMenuOpen) {
      state.formMenuOpen = (document.activeElement as HTMLElement).id;
      render(false);
      focusMenuOption();
      return;
    }
    const options = Array.from(
      document.querySelectorAll<HTMLElement>('.cred-menu [role="option"]'));
    if (!options.length) return;
    const index = options.indexOf(document.activeElement as HTMLElement);
    const next = index === -1
      ? (e.key === 'ArrowDown' ? 0 : options.length - 1)
      : Math.min(Math.max(index + (e.key === 'ArrowDown' ? 1 : -1), 0), options.length - 1);
    options[next].focus();
  } else if (e.key === 'Enter' && e.target instanceof Element && e.target.tagName === 'INPUT') {
    if (state.confirmDiscard) return;
    if (state.sheet && (state.sheet.kind === 'add-secret' || state.sheet.kind === 'edit-secret')) { e.preventDefault(); saveSecret(); }
    else if (state.sheet && (state.sheet.kind === 'add-conn' || state.sheet.kind === 'edit-conn')) { e.preventDefault(); saveConn(); }
  } else if (e.key === 'Tab' && state.sheet) {
    // Keep keyboard focus inside the modal sheet, wrapping at either end.
    // The discard confirm stacks over the form sheet and takes the trap.
    const sheet = document.querySelector<HTMLElement>('.sheet.discard-confirm')
      ?? document.querySelector<HTMLElement>('.sheet');
    if (!sheet) return;
    const focusables = sheet.querySelectorAll<HTMLElement>(
      'button:not([disabled]), input:not([disabled]), select:not([disabled]), summary');
    if (!focusables.length) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const inside = sheet.contains(document.activeElement);
    if (e.shiftKey && (!inside || document.activeElement === first)) {
      e.preventDefault(); last.focus();
    } else if (!e.shiftKey && (!inside || document.activeElement === last)) {
      e.preventDefault(); first.focus();
    }
  }
});

// Editing a field clears its inline validation error.
const ERR_KEY_BY_INPUT = {
  'f-name': 'name', 'f-value': 'value',
  'f-cname': 'name', 'f-origin': 'origin', 'f-host': 'host', 'f-port': 'port',
  'f-db': 'dbname', 'f-user': 'user', 'f-host-key': 'hostKeyFingerprint',
  'f-url': 'url', 'f-sslmode': 'sslmode', 'c-template': 'template', 'c-secret': 'secret',
  'c-new-secret-name': 'newSecretName', 'c-new-secret-value': 'newSecretValue',
  'c-auth-detail': 'authDetail',
};

function updateCredentialNamePlaceholder(connectionName: string): void {
  const input = document.getElementById('c-new-secret-name') as HTMLInputElement | null;
  if (input) input.placeholder = suggestedSecretName(connectionName, state.connType);
}

function updateCredentialNameWarning(): void {
  const input = document.getElementById('c-new-secret-name') as HTMLInputElement | null;
  const hint = document.getElementById('credential-name-warning');
  if (!input || !hint) return;
  const connectionName = (document.getElementById('f-cname') as HTMLInputElement | null)?.value
    ?? state.draft.name
    ?? '';
  const effectiveName = (input.value || suggestedSecretName(connectionName, state.connType)).trim();
  const nameTaken = credentialNameIsTaken(effectiveName);
  input.classList.toggle('name-conflict-warning', nameTaken);
  hint.hidden = !nameTaken;
}

function updateServiceNameWarning(): void {
  const input = document.getElementById('f-cname') as HTMLInputElement | null;
  const hint = document.getElementById('service-name-warning');
  if (!input || !hint) return;
  const nameTaken = serviceNameIsTaken(input.value);
  input.classList.toggle('name-conflict-warning', nameTaken);
  hint.hidden = !nameTaken;
}

document.addEventListener('input', (e) => {
  const target = e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement
    ? e.target
    : null;
  const key = target
    ? ERR_KEY_BY_INPUT[target.id as keyof typeof ERR_KEY_BY_INPUT]
    : undefined;
  if (target?.id === 'quick-setup-source') {
    state.quickSetupSource = target.value;
    state.quickSetupError = null;
  }
  if (target?.id === 'f-cname') {
    updateCredentialNamePlaceholder(target.value);
    updateCredentialNameWarning();
    updateServiceNameWarning();
  }
  if (target?.id === 'c-new-secret-name') updateCredentialNameWarning();
  if (key && state.sheetErrors[key]) {
    delete state.sheetErrors[key];
    render();
  }
});

document.addEventListener('focusout', (e) => {
  const target = e.target instanceof HTMLInputElement ? e.target : null;
  if (target?.id === 'f-cname') {
    // Internal spaces are valid service-name characters, but edge whitespace
    // is not part of the stored name. Reflect the submitted value as soon as
    // the field is left instead of waiting for Save to trim it invisibly.
    target.value = target.value.trim();
    state.draft.name = target.value;
    updateCredentialNamePlaceholder(target.value);
  }
});

// Keep an open fixed-position listbox glued to its trigger while the sheet
// scrolls or the window resizes.
document.addEventListener('scroll', () => {
  if (state.formMenuOpen) positionFormMenu();
}, true);
window.addEventListener('resize', () => {
  if (state.formMenuOpen) positionFormMenu();
});

/* --------------------------------- boot ---------------------------------- */
async function boot() {
  // A webview reload must not leave a stale native lock behind. Forms acquire
  // it again before they are shown.
  if (mode === 'dropdown') await invoke('ui_set_dropdown_form_active', { active: false });
  await refresh(mode === 'approval' ? 'queue' : 'all');
  if (mode !== 'approval') scheduleAccessExpiryRefresh();
  // Hover tooltips (absolute timestamps on activity rows, etc.). Delegated
  // from #root so they survive re-renders; content is each element's
  // data-tippy-content. Vendored Tippy.js (self-hosted for the 'self' CSP).
  if (window.tippy) {
    window.tippy.delegate('#root', {
      target: '[data-tippy-content]',
      delay: [250, 0],
      duration: [120, 80],
    });
  }
  // Relative timestamps drift; re-render the activity view every minute so
  // "just now" becomes "1m", etc., while that tab is open.
  setInterval(() => {
    if (mode !== 'approval' && state.tab === 'activity' && !state.sheet && !state.menuOpen) render();
  }, 60000);
  // Access sessions are in-memory and expire without a persisted state
  // change. Refresh access rows and agent summaries so expiry disappears
  // promptly everywhere it is presented.
  setInterval(() => {
    if (mode !== 'approval' && !state.sheet && !state.menuOpen) refreshAccessViews();
  }, 30000);
  // Live updates from the core.
  await listen('amfa://queue-changed', (ev) => { state.queue = ev.payload || []; render(); });
  await listen('amfa://sessions-changed', () => refresh('sessions'));
  await listen('amfa://agents-changed', async () => {
    const before = new Map(state.agents.map((agent) => [agent.name, agent.paired_at]));
    await load('agents', 'list_agents');
    render();
    const connected = state.agents.find((agent) =>
      !before.has(agent.name) || before.get(agent.name) !== agent.paired_at);
    if (connected) toast(`🔗 ${connected.name} is connected and can now ask to use your services`);
  });
  await listen('amfa://rules-changed', () => {
    if (mode !== 'approval') refreshAccessViews();
  });
  // A core-side connection change (a trust-on-first-use host-key pin) has no
  // originating UI command to refresh after; reload the services list.
  await listen('amfa://connections-changed', () => {
    if (mode !== 'approval') refresh('connections');
  });
  await listen('amfa://activity-appended', (ev) => receiveActivity(ev.payload));
  await listen('amfa://activity-changed', () => refresh('activity'));
  await listen('amfa://open-settings', () => {
    if (isProtectedFormSheet()) return;
    state.sheet = { kind: 'settings' };
    state.draft = {};
    state.sheetErrors = {};
    render();
  });
  await listen('amfa://dropdown-shown', () => {
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
  });
  await listen('amfa://dropdown-hidden', () => {
    releaseDropdownForm();
    state.reveal = {};
    state.sheet = null;
    state.draft = {};
    state.sheetErrors = {};
    state.sheetBaseline = null;
    state.confirmDiscard = false;
    state.confirm = null;
    state.walkthroughMenuOpen = false;
    state.agentMenuOpen = null;
    render();
  });
}
boot();
