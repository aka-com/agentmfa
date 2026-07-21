// Multitool frontend. One file drives all Tauri windows (main, tray
// and dropdown), chosen from location.hash.
//
// Every mutation and read goes through the Rust core via Tauri
// commands; the webview never holds a secret value. When run outside
// Tauri (a plain browser), a dev mock stands in for the core so the
// UI is developable standalone.

import { invoke, listen, mode } from '/src/bridge';
import {
  CATALOG, CATALOG_SECTIONS, catalogNameForType, connectionsForEntry, entryForConnection,
  mcpTemplateForConnection,
  visibleCatalog,
} from '/src/catalog';
import type { ConnectionPreset } from '/src/catalog';
import {
  START_OPTIONS, firstTaskPrompt, startOptionById, startProgress, startTask,
} from '/src/getting-started';
import type { CatalogEntry } from '/src/catalog';
import { ICONS, TYPES, esc, escAttr, toast, relTime, absTime } from '/src/util';
import {
  apiOriginFromParts, authTemplate, parseApiOrigin, parseConnectionImport,
  parseMcpServerUrl,
  quickSetupPlaceholder, shouldResolveSshImport, sshImportFromPreview, suggestedSecretName,
} from '/src/connection-input';
import { formErrorKind, formErrorMessage, inlineFormError } from '/src/form-errors';
import type { HostKeyCandidate } from '/src/connection-input';
import type {
  ActivityEntry,
  AgentSummary,
  CommandArgs,
  CommandName,
  ConnectionInput,
  ConnectionSummary,
  ConnectionType,
  ElicitationRequest,
  McpAuthDraft,
  McpAuthState,
  McpStatusReport,
  McpToolInfo,
  WiringSummary,
  SecretSummary,
  SessionSummary,
  Settings,
} from '/src/types';

const EDIT_SECRET_MASK = '••••••••••••';
const ACTIVITY_RENDER_LIMIT = 200;

// The left-nav tabs, in order — also the cycle order for Ctrl-Tab.
const TABS = ['start', 'connections', 'agents', 'activity'] as const;
// The tray dropdown is a quick-access panel; onboarding belongs in the window.
const DROPDOWN_TABS = TABS.filter((tab) => tab !== 'start');
type Tab = typeof TABS[number];


interface SheetState {
  kind: 'add-secret' | 'edit-secret' | 'add-conn' | 'edit-conn' | 'settings' | 'clear-activity'
    | 'elicitation' | 'mcp-auth' | 'wiring-tools';
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
  /** This draft is an MCP server, so the origin field is a full server URL. */
  isMcp?: boolean;
  /** Catalog row that opened the sheet (template lookup for MCP rows). */
  entryId?: string;
  mcpPath?: string | null;
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
  elicitations: ElicitationRequest[];
  agentSetupInstructions: string;
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
  /** The catalog row that opened the add sheet; names the dialog. */
  connEntryName: string | null;
  /** The branded row's prefill (docs pointer, credential hint) while adding. */
  connPreset: ConnectionPreset | null;
  confirm: ConfirmState | null;
  toolSearch: string;
  toolOpen: string | null;
  startOption: string;
  connImportSource: string;
  connImportError: string | null;
  menuOpen: boolean;
  agentMenuOpen: string | null;
  connMenuOpen: string | null;
  copied: string | null;
  readyCopied: boolean;
  connectionReady: ConnectionReadyState | null;
  connectionTaskCopied: boolean;
  connTests: Record<string, ConnectionTestState>;
  /** Live MCP sign-in session shown by the mcp-auth sheet. */
  mcpAuth: McpAuthState | null;
  /** The submitted draft, kept for Try again. */
  mcpAuthDraft: McpAuthDraft | null;
  /** Authorization URL already auto-opened, so re-renders don't re-open. */
  mcpAuthOpenedUrl: string | null;
  /** connectionId -> in-flight/last MCP status check (transient). */
  mcpStatus: Record<string, McpStatusState>;
  /** The open per-wiring tool picker (agent x MCP connection). */
  wiringTools: WiringToolsState | null;
}

interface WiringToolsState {
  agentId: string;
  agentName: string;
  connectionId: string;
  connectionName: string;
  loading: boolean;
  error?: string;
  tools?: McpToolInfo[];
  /** Checked tool names; null means "all tools" (no curation). */
  selected: string[] | null;
  saving: boolean;
}

interface McpStatusState {
  running: boolean;
  report?: McpStatusReport;
  error?: string;
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
  elicitations: [],      // paused upstream tool calls awaiting the user (SEP-2322)
  agentSetupInstructions: '', // short paste-ready setup message (lazy-loaded)
  settings: {
    reauth_on_read: true,
    show_websockets: false,
    menu_bar_hides_dock: false,
  },
  reveal: {},            // secretId -> prefix string (transient)
  // sheet / confirm state
  sheet: null,           // {kind:'add-secret'|'edit-secret'|'add-conn'|'edit-conn'|'settings', ...}
  draft: {},
  sheetErrors: {},       // field key -> inline validation message
  sheetBaseline: null,   // draft signature at sheet open (dirty-close detection)
  confirmDiscard: false, // "Discard this tool?" confirm over the conn sheet
  formMenuOpen: null,    // id of the open custom-select listbox in the sheet
  connAdvancedOpen: false, // "Advanced" disclosure in the tool sheet
  connType: 'api',
  connEntryName: null,
  connPreset: null,      // branded-row prefill for the open add sheet
  confirm: null,         // {kind, id/name}
  toolSearch: '',        // Add-tools catalog search query
  toolOpen: null,        // catalog entry id whose connections are expanded
  startOption: 'postgres', // which walkthrough the Get started tab shows
  connImportSource: '',  // paste-to-prefill field in the add sheet
  connImportError: null,
  menuOpen: false,       // desktop-mode settings popover (gear) open
  agentMenuOpen: null,   // agent id whose ⋯ options menu is open (Agents tab)
  connMenuOpen: null,    // connection id whose ⋯ options menu is open (Tools tab)
  copied: null,          // secretId whose value was just copied (transient "Copied" flash)
  readyCopied: false,    // transient feedback on the setup-instructions status button
  connectionReady: null,
  connectionTaskCopied: false,
  connTests: {},         // connectionId -> in-flight/last test result (transient)
  mcpAuth: null,
  mcpAuthDraft: null,
  mcpAuthOpenedUrl: null,
  mcpStatus: {},
  wiringTools: null,
};

// Re-rendering replaces #root wholesale, which would drop the scroll
// position of the scrolling panes — expanding a catalog row would jump you
// back to the top. Snapshot and restore them around every render.
const SCROLLERS = ['.content', '.dd-global'];
function captureScroll(): Array<[string, number]> {
  return SCROLLERS.flatMap((sel): Array<[string, number]> => {
    const el = document.querySelector(sel);
    return el && el.scrollTop ? [[sel, el.scrollTop]] : [];
  });
}
function restoreScroll(saved: Array<[string, number]>): void {
  for (const [sel, top] of saved) {
    const el = document.querySelector(sel);
    if (el) el.scrollTop = top;
  }
}
/** Switching tabs should start at the top, not inherit the old offset. */
function resetScroll(): void {
  for (const sel of SCROLLERS) {
    const el = document.querySelector(sel);
    if (el) el.scrollTop = 0;
  }
}

const root = (): HTMLElement => {
  const element = document.getElementById('root');
  if (!element) throw new Error('Missing #root element');
  return element;
};
/* ------------------------------ data loading ----------------------------- */
type RefreshTarget = 'all' | 'secrets' | 'connections' | 'agents' | 'sessions' |
  'activity' | 'settings' | 'elicitations';
type LoadKey = 'secrets' | 'connections' | 'agents' | 'sessions' | 'activity' |
  'elicitations';

async function refresh(which: RefreshTarget = 'all'): Promise<void> {
  const jobs: Promise<void>[] = [];
  if (which === 'all' || which === 'secrets') jobs.push(load('secrets', 'list_secrets'));
  if (which === 'all' || which === 'connections') jobs.push(load('connections', 'list_connections'));
  if (which === 'all' || which === 'agents') jobs.push(load('agents', 'list_agents'));
  if (which === 'all' || which === 'sessions') jobs.push(load('sessions', 'list_sessions'));
  if (which === 'all' || which === 'elicitations') jobs.push(load('elicitations', 'list_elicitations'));
  if (which === 'all' || which === 'activity') {
    jobs.push(load('activity', 'list_activity', { limit: ACTIVITY_RENDER_LIMIT }));
  }
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
      case 'elicitations': state.elicitations = result as ElicitationRequest[]; break;
    }
  } catch (error) {
    console.error(cmd, error);
  }
}
async function loadSettings(): Promise<void> {
  try { state.settings = await invoke('get_settings'); } catch (e) { console.error(e); }
}
async function refreshAgentsView(): Promise<void> {
  await Promise.all([
    load('connections', 'list_connections'),
    load('agents', 'list_agents'),
  ]);
  render();
}

/* --------------------------------- render -------------------------------- */
// Rebuilding #root from scratch would drop anything the DOM holds that state
// doesn't: in-progress sheet input and the focused control. Broker events
// (sessions/activity changes) re-render at arbitrary times, so every
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
  const scroll = captureScroll();

  if (mode === 'dropdown') renderDropdown();
  else renderMainWindow();

  restoreScroll(scroll);

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

/**
 * A paused upstream tool call asking the user for input (SEP-2322).
 *
 * DESIGN MOCK — see ELICITATION.md. This is the trusted surface the plan's
 * "approval routing" risk demands: the upstream's prompt is answered here,
 * in the app, and never through the agent. The queue shows a one-line
 * notification; the question itself is asked in a dialog (`elicitationSheet`).
 */
function elicitationNoteHTML(request: ElicitationRequest): string {
  return `<button class="elicit-note" data-act="elicit-open" data-id="${escAttr(request.id)}"
    aria-label="Answer the input request from ${escAttr(request.connection)}">
    <span class="elicit-ico">${ICONS.bell}</span>
    <span class="elicit-note-txt"><b>${esc(request.connection)}</b> asked for input —
      ${esc(request.agent)} is paused</span>
    <span class="elicit-when" data-tippy-content="${escAttr(absTime(request.requested_at))}">${esc(relTime(request.requested_at))}</span>
    <span class="elicit-note-cta">Answer…</span>
  </button>`;
}

function globalSectionsHTML() {
  let out = '';
  const hasOnboarding = false;
  // Pending input requests outrank everything: an agent is paused on them.
  // They show on every tab, in both the window and the dropdown.
  if (state.elicitations.length) {
    out += '<div class="live-head">Waiting on you</div>'
      + state.elicitations.map(elicitationNoteHTML).join('');
  }
  // Live sessions answer "what is my agent doing right now?", so they sit
  // with the agents rather than above every screen.
  if (state.tab === 'agents' && state.sessions.length) {
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

function secretsTableHTML() {
  const rows = state.secrets.map((s) => {
    if (state.confirm && state.confirm.kind === 'del-secret-inuse' && state.confirm.id === s.id) {
      return `<tr class="confirm-row"><td colspan="3"><div class="confirm-inline"><span>Currently used by ${esc(s.used_by_names.join(', '))}. Delete the tool first.</span>
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
    const sub = `Used by ${s.used_by} tool${s.used_by === 1 ? '' : 's'}`;
    return `<tr>
      <td><div><div class="s-name">${esc(s.name)}</div><div class="s-sub secret-usage">${esc(sub)}</div></div></td>
      <td class="val"><span class="val-wrap"><span class="val-slot ${copied ? 'is-copied' : ''}"><code>${valText}</code><span class="val-overlay">${overlay}</span></span></span> ${eyeBtn}</td>
      <td class="rowdel">
        <button class="icon-btn" title="Edit secret" aria-label="Edit secret ${escAttr(s.name)}" data-act="edit-secret" data-id="${s.id}">${ICONS.pencil}</button>
        <button class="icon-btn" title="Delete secret" aria-label="Delete secret ${escAttr(s.name)}" data-act="del-secret-ask" data-id="${s.id}">${ICONS.trash}</button></td></tr>`;
  }).join('');
  return `<table class="sec-table"><tbody>${rows}</tbody></table>`;
}

/* ---- agents tab ---- */
// The screen pivots around the core question — what can this agent reach?
// One block per registered agent: an identity card on top, then one row per
// service with a wire/unwire toggle. Wired = the agent uses the service
// without prompting; unwired = refused.
const agentWiringFor = (a: AgentSummary, c: ConnectionSummary): WiringSummary | undefined =>
  (c.wired_agents || []).find((wiring) => wiring.agent_id === a.id);

function agentToolRowHTML(a: AgentSummary, c: ConnectionSummary): string {
  const t = TYPES[c.type];
  const wiring = agentWiringFor(a, c);
  const wired = !!wiring;
  const live = state.sessions.some((s) => s.agent === a.name && s.connection === c.name);
  const pill = wired
    ? '<span class="acc-pill granted">Wired</span>'
    : '<span class="acc-pill">Not wired</span>';
  // A wired MCP connection can be narrowed to a curated tool subset; the
  // chip names the current scope and opens the picker.
  const toolsChip = wired && c.mcp_path
    ? `<button class="btn ghost sm" data-act="wiring-tools" data-id="${a.id}" data-conn="${c.id}"
        aria-label="Choose which tools ${escAttr(a.name)} may call on ${escAttr(c.name)}"
        title="Choose which of this server’s tools ${escAttr(a.name)} may call">${
          wiring?.allowed_tools
            ? `${wiring.allowed_tools.length} tool${wiring.allowed_tools.length === 1 ? '' : 's'}`
            : 'All tools'}</button>`
    : '';
  const action = wired
    ? `<button class="btn ghost sm" aria-label="Unwire ${escAttr(a.name)} from ${escAttr(c.name)}" data-act="unwire" data-id="${a.id}" data-conn="${c.id}">Unwire</button>`
    : `<button class="btn ghost sm" aria-label="Wire ${escAttr(a.name)} to ${escAttr(c.name)}" data-act="wire" data-id="${a.id}" data-conn="${c.id}">Wire up</button>`;
  return `<div class="acc-row">
    <span class="badge ${t.cls}">${t.label}</span>
    <div class="acc-svc"><div class="acc-name">${esc(c.name)}${live ? ' <span class="cc-live">● live</span>' : ''}</div>
      <div class="acc-target" title="${escAttr(c.target)}">${esc(c.target)}</div></div>
    ${pill}${toolsChip}${action}</div>`;
}

function agentBlockHTML(a: AgentSummary): string {
  const menuOpen = state.agentMenuOpen === a.id;
  // Wired tools first — with many tools the interesting rows would
  // otherwise be scattered through the list.
  const ordered = [...state.connections].sort((x, y) => {
    const wired = Number(!!agentWiringFor(a, y)) - Number(!!agentWiringFor(a, x));
    return wired || x.name.localeCompare(y.name);
  });
  const wiredCount = ordered.filter((c) => agentWiringFor(a, c)).length;
  const sub = state.connections.length
    ? `Connected to ${wiredCount} of ${state.connections.length} tool${state.connections.length === 1 ? '' : 's'} · last used ${relTime(a.last_used)}`
    : `last used ${relTime(a.last_used)}`;
  const rows = ordered.length
    ? ordered.map((c) => agentToolRowHTML(a, c)).join('')
    : `<div class="acc-none">No tools yet.${mode === 'dropdown' ? '' : ` Add one to give ${esc(a.name)} somewhere to connect.`}</div>`;
  return `<div class="agent-block">
    <div class="agent-card">
      <span class="agent-avatar" role="img" aria-label="Agent">${ICONS.bot}</span>
      <div class="agent-id"><div class="c-name">${esc(a.name)}</div>
        <div class="s-sub agent-sub">${esc(sub)}</div></div>
      <div class="agent-menu-wrap">
        <button class="icon-btn agent-menu-btn ${menuOpen ? 'on' : ''}" title="Agent options"
          aria-label="Options for ${escAttr(a.name)}" aria-haspopup="menu"
          aria-expanded="${menuOpen}" data-act="toggle-agent-menu" data-id="${a.id}">${ICONS.ellipsis}</button>
        ${menuOpen ? `<div class="agent-menu" role="menu" aria-label="Options for ${escAttr(a.name)}">
          <button class="menu-item danger" role="menuitem" data-act="revoke-ask" data-id="${a.id}">${ICONS.unplug} Disconnect ${esc(a.name)}…</button>
        </div>` : ''}
      </div>
    </div>
    <div class="acc-rows">${rows}</div>
  </div>`;
}

// With no agent registered there is nothing to wire. Get started owns the
// onboarding narrative — how an agent self-registers (POST /v1/pair) and gets
// wired — so this is a plain empty state that points there rather than a
// second copy of the walkthrough.
function agentsEmptyHTML(): string {
  const pointer = mode === 'dropdown'
    ? 'Open the window and follow Get started.'
    : 'Follow Get started to connect your first agent.';
  return `<div class="empty"><div class="empty-ico">${ICONS.botMessageSquare}</div>
    <h3>No agents connected</h3>
    <p>${pointer}</p></div>`;
}

function agentsHTML(): string {
  if (!state.agents.length) return agentsEmptyHTML();
  return state.agents.map(agentBlockHTML).join('');
}
const liveCount = (c: ConnectionSummary): number =>
  state.sessions.filter((s) => s.connection === c.name).length;
const connTestResultHTML = (c: ConnectionSummary): string => {
  const test = state.connTests[c.id];
  if (!test) return '';
  if (test.running) return '<div class="cc-test running">Testing…</div>';
  if (test.detail === undefined) return '';
  return `<div class="cc-test ${test.ok ? 'ok' : 'err'}">${test.ok ? ICONS.circleCheck : ICONS.circleX}<span>${esc(test.detail)}</span></div>`;
};


// What a connection actually lets an agent do, in plain words — the
// expansion has to answer "what is this for?" without opening the editor.
function connectionPurpose(c: ConnectionSummary): string {
  if (c.type === 'api' && c.mcp_path) return 'Exposes this MCP server’s tools to wired agents';
  if (c.type === 'pg') return `Runs SQL against ${c.dbname || 'the database'}`;
  if (c.type === 'ssh') return `Shell, git, and file transfer as ${c.user || 'the pinned user'}`;
  if (c.type === 'ws') return 'Streams WebSocket messages';
  return 'Makes HTTP requests to this origin';
}

/** The credential the broker injects; never its value. */
function connectionCredential(c: ConnectionSummary): string {
  const names = c.secret_names || [];
  if (!names.length) return 'No credential bound';
  return `Uses ${names.join(' + ')}`;
}

/** Who may use it — the wiring is the whole authorization model. */
function connectionWiring(c: ConnectionSummary): { text: string; wired: boolean } {
  const names = (c.wired_agents || []).map((w) => w.agent);
  return names.length
    ? { text: `Wired to ${names.join(', ')}`, wired: true }
    : { text: 'Not wired to any agent', wired: false };
}

// One row inside an expanded catalog entry. It spans the full card width and
// carries enough to identify the connection without opening it: name, where
// it points, what it does, which credential it injects, and who is wired.
function catalogConnRowHTML(c: ConnectionSummary): string {
  if (state.confirm && state.confirm.kind === 'del-conn' && state.confirm.id === c.id) {
    return `<div class="cat-conn confirm-conn">
      <div class="cat-conn-tx"><b>${esc(c.name)}</b>
        <span class="cat-conn-danger">Delete this tool?${(c.wired_agents || []).length ? ' Wired agents will lose access.' : ''}</span></div>
      <button class="btn sm" data-act="confirm-cancel">Cancel</button>
      <button class="btn sm danger" data-act="del-conn-confirm" data-id="${c.id}">Delete</button></div>`;
  }
  const test = state.connTests[c.id];
  const menuOpen = state.connMenuOpen === c.id;
  const live = liveCount(c);
  const wiring = connectionWiring(c);
  const mcpStatus = c.mcp_path ? state.mcpStatus[c.id] : undefined;
  const account = c.mcp_path && c.account
    ? `<span class="cat-meta-account" title="Verified by the status check">${esc(`Connected as ${c.account}`)}</span>`
    : '';
  const statusBtn = c.mcp_path
    ? `<button class="icon-btn mcp-status-btn" title="Check server & account"
        aria-label="Check status of ${escAttr(c.name)}" data-act="mcp-status" data-id="${c.id}"
        ${mcpStatus && mcpStatus.running ? 'disabled' : ''}>${ICONS.refresh}</button>`
    : '';
  const reconnectItem = c.mcp_path
    ? `<button class="menu-item" role="menuitem" data-act="reconnect-mcp" data-id="${c.id}">${ICONS.logIn} Reconnect (sign in again)…</button>`
    : '';
  // Only call out TLS when it is weaker than the default.
  const tls = c.type === 'pg' && c.sslmode && c.sslmode !== 'verify-full'
    ? `<span class="cat-meta-warn">TLS ${esc(c.sslmode)}</span>` : '';
  const hostKey = c.type === 'ssh' && !c.host_key_fingerprint
    ? '<span class="cat-meta-warn">Host key not pinned yet</span>' : '';
  // Passive health: brokered agent calls and background token renewals
  // record a rejected credential without anyone pressing Test. The badge
  // carries the fix: sign in again for MCP connections, re-test otherwise.
  const needsReconnect = c.last_status === 'needs_reconnect'
    ? `<span class="cat-meta-warn" title="${escAttr(c.last_detail || '')}">Needs reconnect</span>
       ${c.mcp_path
         ? `<button class="btn ghost sm cat-meta-fix" data-act="reconnect-mcp" data-id="${c.id}">Reconnect…</button>`
         : `<button class="btn ghost sm cat-meta-fix" data-act="test-conn" data-id="${c.id}">Test again</button>`}`
    : '';
  return `<div class="cat-conn">
    <div class="cat-conn-tx">
      <div class="cat-conn-head"><b>${esc(c.name)}</b>${live ? ` <span class="cc-live">● ${live} live</span>` : ''}</div>
      <code title="${escAttr(c.target)}">${esc(c.target)}</code>
      <div class="cat-conn-meta">
        <span>${esc(connectionPurpose(c))}</span>
        <span>${esc(connectionCredential(c))}</span>
        <span class="${wiring.wired ? '' : 'cat-meta-idle'}">${esc(wiring.text)}</span>
        ${account}${tls}${hostKey}${needsReconnect}
      </div>${connTestResultHTML(c)}${mcpStatusHTML(c)}</div>
    ${statusBtn}<div class="tile-menu-wrap">
      <button class="icon-btn tile-menu-btn ${menuOpen ? 'on' : ''}" title="Tool options"
        aria-label="Options for ${escAttr(c.name)}" aria-haspopup="menu"
        aria-expanded="${menuOpen}" data-act="toggle-conn-menu" data-id="${c.id}">${ICONS.ellipsis}</button>
      ${menuOpen ? `<div class="tile-menu" role="menu" aria-label="Options for ${escAttr(c.name)}">
        <button class="menu-item" role="menuitem" data-act="test-conn" data-id="${c.id}" ${test && test.running ? 'disabled' : ''}>${ICONS.flaskConical} ${test && test.running ? 'Testing…' : 'Test connection'}</button>
        ${reconnectItem}
        <button class="menu-item" role="menuitem" data-act="edit-conn" data-id="${c.id}">${ICONS.pencil} Edit…</button>
        <button class="menu-item danger" role="menuitem" data-act="del-conn-ask" data-id="${c.id}">${ICONS.trash} Delete…</button>
      </div>` : ''}
    </div></div>`;
}

// The status check's result, rendered under the MCP connection it belongs
// to — reachability and account first, then the server's resources the
// same way credentials and wirings are listed.
function mcpStatusHTML(c: ConnectionSummary): string {
  if (!c.mcp_path) return '';
  const status = state.mcpStatus[c.id];
  if (!status) return '';
  if (status.running) return '<div class="cc-test running">Checking the server…</div>';
  if (status.error) {
    return `<div class="cc-test err">${ICONS.circleX}<span>${esc(status.error)}</span></div>`;
  }
  const report = status.report;
  if (!report) return '';
  const head = `<div class="cc-test ${report.ok ? 'ok' : 'err'}">${report.ok ? ICONS.circleCheck : ICONS.circleX}<span>${esc(report.detail)}</span></div>`;
  if (!report.ok) return head;
  const missing = report.missing_tools.length
    ? `<div class="mcp-missing">${ICONS.circleQuestion}<span>Expected tools not advertised: ${esc(report.missing_tools.join(', '))}</span></div>`
    : '';
  let resources = '';
  if (report.resources_supported) {
    const shown = report.resources.slice(0, 8);
    const rows = shown.map((resource) =>
      `<div class="mcp-res"><b>${esc(resource.name)}</b><code title="${escAttr(resource.uri)}">${esc(resource.uri)}</code></div>`).join('');
    const more = report.resources.length > shown.length
      ? `<div class="mcp-res-more">+ ${report.resources.length - shown.length} more</div>` : '';
    resources = `<div class="mcp-res-head">Resources (${report.resources.length})</div>
      ${rows || '<div class="mcp-res-more">None listed by the server.</div>'}${more}`;
  }
  return `${head}${missing}${resources}`;
}

// The built-in credentials store, expanded inline: the same secrets table
// the standalone tab used to own.
function credentialsExpansionHTML(): string {
  const body = state.secrets.length
    ? secretsTableHTML()
    : '<div class="muted-note">No saved credentials yet.</div>';
  return `<div class="cat-conns">${body}
    <button class="btn ghost sm cat-add-another" data-act="open-add-secret">＋ Add credential</button></div>`;
}

// One catalog row: icon chip, name, one-line description, and a trailing
// action — Add for addable tools, a dimmed "Soon" chip for MCP-backed ones,
// or a count badge that expands the row into what is configured.
function catalogRowHTML(entry: CatalogEntry): string {
  const builtin = entry.via === 'builtin';
  const count = builtin ? state.secrets.length : connectionsForEntry(entry, state.connections).length;
  const open = state.toolOpen === entry.id && (builtin || count > 0);
  const label = builtin
    ? `${count} saved credential${count === 1 ? '' : 's'}`
    : `${count} configured connection${count === 1 ? '' : 's'}`;
  const action = count || builtin
    ? `<button class="cat-count ${open ? 'on' : ''}" data-act="catalog-toggle" data-id="${entry.id}"
        aria-expanded="${open}" title="${escAttr(label)}">${builtin ? ICONS.fileKey : ICONS.plug} ${count}<span class="cat-chev">${ICONS.chevronDown}</span></button>`
    : entry.via === 'connection'
    ? `<button class="btn cat-add" data-act="catalog-add" data-id="${entry.id}">Add</button>`
    : `<span class="cat-soon" title="Arrives with the MCP layer">Soon</span>`;
  const expansion = !open ? ''
    : builtin ? credentialsExpansionHTML()
    : `<div class="cat-conns">
      <div class="cat-conn-list">${connectionsForEntry(entry, state.connections).map(catalogConnRowHTML).join('')}</div>
      <button class="btn ghost sm cat-add-another" data-act="catalog-add" data-id="${entry.id}">＋ Add another ${esc(entry.name)}</button>
    </div>`;
  return `<div class="cat-row-wrap ${open ? 'open' : ''}">
    <div class="cat-row">
      <span class="cat-ico" aria-hidden="true">${ICONS[entry.icon] || ''}</span>
      <div class="cat-tx"><b>${esc(entry.name)}</b><span>${esc(entry.description)}</span></div>
      ${action}
    </div>${expansion}</div>`;
}

/** Whether a draft is being edited as an MCP server rather than a raw API. */
function isMcpDraft(draft: { isMcp?: boolean; mcpPath?: string | null }): boolean {
  return Boolean(draft.isMcp || draft.mcpPath);
}

function connectionsHTML() {
  const ready = state.connectionReady;
  const readyPrompt = ready ? firstTaskPrompt(ready.name, ready.type) : '';
  const readyCard = ready && state.agents.length ? `<div class="connection-ready">
    <div class="connection-ready-copy"><b>${esc(ready.name)} is ready</b>
      <span>Ask your agent:</span><code>${esc(readyPrompt)}</code></div>
    <div class="connection-ready-actions">
      <button class="btn sm" data-act="copy-first-task">${state.connectionTaskCopied ? `${ICONS.check} Copied` : 'Copy task'}</button>
      <button class="icon-btn" title="Dismiss" aria-label="Dismiss tool ready message" data-act="dismiss-connection-ready">${ICONS.circleX}</button>
    </div></div>` : '';
  const entries = visibleCatalog(state.toolSearch, {
    showWebsockets: state.settings.show_websockets,
    connections: state.connections,
  });
  const sections = CATALOG_SECTIONS.map((section) => {
    const rows = entries.filter((entry) => entry.section === section);
    if (!rows.length) return '';
    return `<div class="cat-section"><div class="cat-section-h">${section.toUpperCase()}</div>
      <div class="cat-rows">${rows.map(catalogRowHTML).join('')}</div></div>`;
  }).join('');
  const search = mode === 'dropdown'
    ? `<input id="tool-search" class="cat-search" type="search" placeholder="Search tools…"
        aria-label="Search tools" value="${escAttr(state.toolSearch)}">`
    : '';
  return readyCard + `<div class="catalog">${search}
    ${sections || '<div class="muted-note">No tools match your search.</div>'}
  </div>`;
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
    if (state.tab === 'activity' && !state.sheet && !state.menuOpen) render();
    return;
  }

  const duplicate = state.activity.some((item) =>
    item.at === entry.at && item.icon === entry.icon && item.text === entry.text && item.detail === entry.detail);
  if (duplicate) return;
  state.activity = [entry, ...state.activity].slice(0, ACTIVITY_RENDER_LIMIT);

  if (state.tab !== 'activity' || state.sheet || state.menuOpen) return;
  const list = document.querySelector('.act-list');
  if (!list) {
    render();
    return;
  }
  list.insertAdjacentHTML('afterbegin', activityRowHTML(entry));
  while (list.children.length > ACTIVITY_RENDER_LIMIT) list.lastElementChild?.remove();
}

function startHTML(): string {
  const option = startOptionById(state.startOption);
  const progress = startProgress(option, state.connections, state.agents);

  const picker = START_OPTIONS.map((candidate) =>
    `<button class="start-pick ${candidate.id === option.id ? 'on' : ''}"
      aria-pressed="${candidate.id === option.id}"
      data-act="start-option" data-id="${candidate.id}">${esc(candidate.label)}</button>`).join('');

  const step = (n: number, title: string, done: boolean, body: string): string =>
    `<li class="start-step ${done ? 'done' : ''}">
      <span class="start-num" aria-hidden="true">${done ? ICONS.check : n}</span>
      <div class="start-body"><b>${esc(title)}</b>${body}</div></li>`;

  const addBody = `<p>Save the destination and its credential. The credential goes to your Keychain;
        agents can use it but never read it.</p>
      <div class="start-actions">
        <button class="btn primary sm" data-act="catalog-add" data-id="${option.catalogId}">Add ${esc(option.label)}</button>
        ${progress.added && progress.toolName
          ? `<span class="start-note">${esc(progress.toolName)} is saved.</span>` : ''}
      </div>`;

  const connectBody = `<p>Paste this into your coding agent. It registers itself and shows up on
      the Agents tab — with no access to anything yet.</p>
    <pre class="setup-instructions"><code>${esc(state.agentSetupInstructions || 'Loading…')}</code></pre>
    <div class="start-actions">
      <button class="btn primary sm" data-act="copy-agent-setup">Copy setup instructions</button>
      ${progress.connected && progress.agentName
        ? `<span class="start-note">${esc(progress.agentName)} is connected.</span>` : ''}
    </div>`;

  const task = startTask(option, progress);
  const wireWhat = `wire ${progress.agentName ? `<b>${esc(progress.agentName)}</b>` : 'your agent'} `
    + `to ${progress.toolName ? `<b>${esc(progress.toolName)}</b>` : 'the tool'}`;
  const wireBody = `<p>On the Agents tab, ${wireWhat}. Wiring is the whole permission model:
      a wired tool works with no prompt, everything else is refused.</p>
    <pre class="start-task"><code>${esc(task)}</code></pre>
    <div class="start-actions">
      <button class="btn sm" data-act="copy-text" data-text="${escAttr(task)}">Copy this task</button>
      <button class="btn ghost sm" data-act="tab" data-tab="agents">Open Agents</button>
    </div>`;

  return `<div class="start">
    <div class="start-hero">
      <h3>Connect your agent to everything</h3>
      <div class="start-picker" role="group" aria-label="What to set up first">${picker}</div>
      <p class="start-promise">${esc(option.promise)}</p>
    </div>
    <ol class="start-steps">
      ${step(1, option.connType ? `Add the ${option.label} tool` : `Add an ${option.label}`, progress.added, addBody)}
      ${step(2, 'Connect your agent', progress.connected, connectBody)}
      ${step(3, 'Wire them together, then ask for something useful', progress.wired, wireBody)}
    </ol>
  </div>`;
}

function tabContentHTML() {
  return state.tab === 'start' ? startHTML()
    : state.tab === 'connections' ? connectionsHTML()
    : state.tab === 'agents' ? agentsHTML()
    : activityHTML();
}

function brokerReadyHTML() {
  const copied = state.readyCopied;
  return `<button class="dd-sub ready-copy ${copied ? 'is-copied' : ''}"
    data-act="copy-ready-setup" title="${copied ? 'Setup instructions copied' : 'Copy setup instructions'}"
    aria-label="Copy setup instructions"><span class="dot"></span>
    <span class="ready-copy-label" aria-live="polite">${copied ? `${ICONS.check} Copied` : 'Ready'}</span></button>`;
}

function renderMainWindow() {
  const navItem = (tab: Tab): string =>
    `<button class="nav-item ${state.tab === tab ? 'on' : ''}" data-act="tab" data-tab="${tab}">${tabLabel(tab)}</button>`;
  const nav = TABS.filter((tab) => tab !== 'activity').map(navItem).join('');
  const activityNav = navItem('activity');
  // One view-specific action, always in the header row next to the title.
  const actionBtn = state.tab === 'start'
    ? ''
    : state.tab === 'connections'
    ? `<div class="dw-head-actions">
        <input id="tool-search" class="cat-search" type="search" placeholder="Search tools…"
          aria-label="Search tools" value="${escAttr(state.toolSearch)}"></div>`
    : state.tab === 'agents'
    ? ''
    : `<button class="btn" data-act="clear-activity-ask" ${state.activity.length ? '' : 'disabled'}>Clear activity</button>`;
  const menu = state.menuOpen
    ? `<div class="settings-menu">
        <button class="menu-item" data-act="mode-tray">${ICONS.menubar} Minimize to menu bar</button>
        <button class="menu-item" data-act="open-settings">${ICONS.gear} Settings</button>
      </div>` : '';
  root().innerHTML = `<div class="surface">
    <div class="dw-titlebar" data-tauri-drag-region><span class="dw-title">Multitool</span></div>
    <div class="dw-body">
      <div class="dw-side">
        <div class="dw-brand"><div class="dd-appicon">${ICONS.blocks}</div>
          <div><div class="dd-title">Multitool</div>${brokerReadyHTML()}</div></div>
        <div class="dw-nav">${nav}</div>
        <div class="dw-secondary-nav">${activityNav}</div>
        <div class="dw-settings">${menu}
          <button class="nav-item gear-btn ${state.menuOpen ? 'on' : ''}" data-act="toggle-settings-menu" title="Settings" aria-label="Settings">${ICONS.gear}</button>
        </div>
      </div>
      <div class="dw-main">
        <div class="dw-head"><h2>${state.tab === 'connections' ? 'Add tools' : tabLabel(state.tab)}</h2>${actionBtn}</div>
        ${globalSectionsHTML()}
        <div class="content">${tabContentHTML()}</div>
      </div>
    </div></div>${sheetsHTML()}`;
}

function renderDropdown() {
  if (state.tab === 'start') state.tab = 'connections';
  const tabs = DROPDOWN_TABS.map((tb) =>
    `<button class="seg-btn ${state.tab === tb ? 'on' : ''}" data-act="tab" data-tab="${tb}">${tabLabel(tb)}</button>`).join('');
  const footer = '';
  root().innerHTML = `<div class="surface dropdown-surface">
    <div class="dd-head"><div class="dd-appicon">${ICONS.blocks}</div>
      <div class="dd-identity"><div class="dd-title">Multitool</div>${brokerReadyHTML()}</div>
      <button class="icon-btn" title="Open as a window" aria-label="Open as a window" data-act="mode-window">${ICONS.expand}</button>
      <button class="icon-btn" title="Settings" aria-label="Settings" data-act="open-settings">${ICONS.gear}</button></div>
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
    case 'elicitation': return elicitationSheet();
    case 'mcp-auth': return mcpAuthSheet();
    case 'wiring-tools': return wiringToolsSheet();
    default: return '';
  }
}

/**
 * The elicitation dialog (SEP-2322 design mock, see ELICITATION.md).
 *
 * Shaped like a native macOS alert: symbol on top, a bold one-line message
 * naming who is asking, then the upstream's own question as the quiet
 * informative text, the fields, and a right-aligned button row with the
 * default action last. The prompt is third-party text: rendered verbatim
 * and inert, and the chrome (title, not prompt) is what says who is asking.
 */
function elicitationSheet(): string {
  const request = state.elicitations.find((r) => r.id === state.sheet?.id);
  if (!request) {
    return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
      <div class="sheet elicit-sheet" role="alertdialog" aria-modal="true" aria-labelledby="elicit-title">
        <div class="elicit-dlg-ico">${ICONS.bell}</div>
        <h3 id="elicit-title" class="elicit-dlg-title">This request is gone</h3>
        <div class="elicit-dlg-context">It was answered somewhere else or expired.</div>
        <div class="sheet-actions elicit-dlg-actions">
          <button class="btn primary" data-act="sheet-cancel">OK</button>
        </div></div>`;
  }
  const fields = request.fields.map((field) => `
    <label class="elicit-field">
      <span>${esc(field.label)}</span>
      <input id="elicit-${escAttr(request.id)}-${escAttr(field.name)}"
        type="${field.secret ? 'password' : 'text'}"
        autocomplete="off" spellcheck="false">
    </label>`).join('');
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet elicit-sheet" role="alertdialog" aria-modal="true" aria-labelledby="elicit-title">
      <div class="elicit-dlg-ico">${ICONS.bell}</div>
      <h3 id="elicit-title" class="elicit-dlg-title">${esc(request.connection)} asked for input</h3>
      <div class="elicit-dlg-question">${esc(request.prompt)}</div>
      <div class="elicit-dlg-fields">${fields}</div>
      <div class="sheet-actions elicit-dlg-actions">
        <button class="btn elicit-refuse-btn" data-act="elicit-refuse" data-id="${escAttr(request.id)}">Refuse</button>
        <span class="elicit-dlg-spacer"></span>
        <button class="btn" data-act="sheet-cancel">Cancel</button>
        <button class="btn primary" data-act="elicit-send" data-id="${escAttr(request.id)}">Send to ${esc(request.connection)}</button>
      </div>
    </div>`;
}

/**
 * Per-wiring tool picker: which of an MCP server's tools one agent may
 * call. "All tools" is the default and the reset; a curated subset is
 * enforced broker-side on every tools/call, and the sidecar lists only
 * what is callable.
 */
function wiringToolsSheet(): string {
  const wt = state.wiringTools;
  if (!wt) return '';
  const title = `Tools for ${wt.agentName} on ${wt.connectionName}`;
  let body = '';
  if (wt.loading) {
    body = '<div class="cc-test running">Asking the server for its tools…</div>';
  } else if (wt.error) {
    body = `<div class="cc-test err">${ICONS.circleX}<span>${esc(wt.error)}</span></div>`;
  } else {
    const tools = wt.tools || [];
    const allChecked = wt.selected === null;
    const isChecked = (name: string): boolean => allChecked || (wt.selected || []).includes(name);
    const rows = tools.map((tool) => `<label class="wt-row">
        <input type="checkbox" data-act="wt-toggle" data-tool="${escAttr(tool.name)}"
          ${isChecked(tool.name) ? 'checked' : ''}>
        <span class="wt-name"><code>${esc(tool.name)}</code>
          ${tool.description ? `<span class="wt-desc">${esc(tool.description)}</span>` : ''}</span>
      </label>`).join('');
    // A curated subset may name tools the server no longer advertises;
    // keep them visible so unchecking them is possible.
    const stale = (wt.selected || []).filter((name) => !tools.some((tool) => tool.name === name));
    const staleRows = stale.map((name) => `<label class="wt-row wt-stale">
        <input type="checkbox" data-act="wt-toggle" data-tool="${escAttr(name)}" checked>
        <span class="wt-name"><code>${esc(name)}</code>
          <span class="wt-desc">No longer advertised by the server</span></span>
      </label>`).join('');
    body = `<label class="wt-row wt-all">
        <input type="checkbox" data-act="wt-all" ${allChecked ? 'checked' : ''}>
        <span class="wt-name"><b>All tools</b>
          <span class="wt-desc">New tools the server adds later are callable too</span></span>
      </label>
      <div class="wt-list ${allChecked ? 'wt-dim' : ''}">${rows}${staleRows}</div>`;
  }
  const count = wt.selected === null
    ? 'every tool'
    : `${wt.selected.length} tool${wt.selected.length === 1 ? '' : 's'}`;
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide" role="dialog" aria-modal="true" aria-labelledby="wt-title">
      <h3 id="wt-title">${esc(title)}</h3>
      <p class="wt-sub">${esc(wt.agentName)} can call ${esc(count)} on this server. Everything
        unchecked is refused by the broker and hidden from the agent's tool list.</p>
      ${body}
      <div class="sheet-actions">
        <button class="btn" data-act="sheet-cancel">Cancel</button>
        <button class="btn primary" data-act="wt-save" ${wt.loading || wt.saving ? 'disabled' : ''}>
          ${wt.saving ? 'Saving…' : 'Save'}</button>
      </div></div>`;
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

function toolNameIsTaken(name: string): boolean {
  const candidate = name.trim();
  return Boolean(candidate) && state.connections.some((connection) => connection.name === candidate);
}

function credentialChooserHTML(
  type: ConnectionType,
  draft: ConnectionDraft,
  allowNew = true,
  valueHint?: string,
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
      : `used by ${secret.used_by} tools`;
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
  const valuePlaceholder = valueHint ? `Paste your key (${valueHint})`
    : type === 'pg' ? 'Paste the database password'
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
  const importWarnings = !editing && d.importWarnings && d.importWarnings.length
    ? `<div class="pair-identity-warning import-warning"><b>Review imported details</b><ul>${d.importWarnings.map((warning) => `<li>${esc(warning)}</li>`).join('')}</ul></div>` : '';
  // Paste-to-prefill: a DSN, URL, or `ssh` command fills the form below
  // instead of making the user retype what they already have.
  const importRow = editing ? '' : `<div class="f-row sheet-import">
      <label for="conn-import">Paste a connection string <span class="label-detail">(optional)</span></label>
      <div class="sheet-import-row">
        <input id="conn-import" class="${state.connImportError ? 'field-invalid' : ''}" type="text"
          spellcheck="false" autocapitalize="off" autocorrect="off"
          placeholder="${escAttr(quickSetupPlaceholder(t))}" value="${escAttr(state.connImportSource)}">
        <button class="btn" data-act="conn-import" ${state.connImportSource.trim() ? '' : 'disabled'}>Prefill</button></div>
      ${state.connImportError ? `<div class="field-error">${esc(state.connImportError)}</div>` : ''}</div>`;
  const importDivider = !editing && (t === 'pg' || t === 'ssh')
    ? '<hr class="sheet-import-divider">'
    : '';
  let sshHostKeyField = '';
  let pgTlsFields = '';
  let fields = importRow + importDivider + importWarnings;
  const nameTaken = !editing && toolNameIsTaken(d.name ?? '');
  const nameWarning = editing ? ''
    : `<div id="tool-name-warning" class="field-warning" role="status" aria-live="polite"${nameTaken ? '' : ' hidden'}>Name used by an existing tool</div>`;
  fields += `<div class="f-row"><label for="f-cname">Name</label><input id="f-cname" class="${fieldCls('name')} ${nameTaken ? 'name-conflict-warning' : ''}"${editing ? '' : ' aria-describedby="tool-name-warning"'} placeholder="e.g. github" value="${escAttr(d.name ?? '')}">${fieldErr('name')}${nameWarning}</div>`;
  if (t === 'api' && isMcpDraft(d)) {
    const url = d.origin
      ?? (d.host
        ? `${apiOriginFromParts(d.scheme ?? undefined, d.host, d.port ?? null)}${d.mcpPath ?? ''}`
        : '');
    const entry = d.entryId ? CATALOG.find((candidate) => candidate.id === d.entryId) : undefined;
    const hint = entry?.mcpTemplate?.urlHint
      ?? 'The URL your provider gave you. Its tools appear to wired agents automatically; the credential below is injected on the way out and never reaches the agent.';
    fields += `<div class="f-row"><label for="f-origin">MCP server URL</label>
      <input id="f-origin" class="${fieldCls('origin')}" placeholder="https://mcp.example.com/mcp" value="${escAttr(url)}">${fieldErr('origin')}
      <div class="rule-note">${esc(hint)}</div></div>`;
  } else if (t === 'api') {
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
    const mcpAdd = t === 'api' && isMcpDraft(d);
    const modeValue = d.authMode || (mcpAdd ? 'oauth' : 'bearer');
    const recipes: Array<[string, string]> = [
      // MCP servers advertise their own sign-in flow; the browser dance is
      // the default and a pasted token stays one select away.
      ...(mcpAdd ? [['oauth', 'Sign in with your account (OAuth)'] as [string, string]] : []),
      ['bearer', 'Bearer token'], ['header', 'Custom header'],
      ...(t === 'api' ? [['query', 'Query parameter'] as [string, string]] : []),
      ['advanced', 'Bearer token + template'],
    ];
    // Decision first: the authentication type governs which detail field and
    // credential inputs appear, so those render beneath the select.
    fields += `<div class="f-row"><label for="c-auth-mode">Authentication type</label>${customSelectHTML('c-auth-mode', recipes, modeValue)}</div>`;
    if (modeValue === 'oauth') {
      fields += `<div class="rule-note oauth-note">You’ll approve access in your browser. The token is saved
        to your Keychain and injected by the broker — agents never see it. Run this again to connect
        a second account.</div>`;
    } else if (modeValue === 'header') {
      fields += `<div class="f-row"><label for="c-auth-detail">Header name</label><input id="c-auth-detail" class="${fieldCls('authDetail')}" placeholder="X-API-Key" value="${escAttr(d.authDetail ?? '')}">${fieldErr('authDetail')}</div>`;
    } else if (modeValue === 'query') {
      fields += `<div class="f-row"><label for="c-auth-detail">Query parameter</label><input id="c-auth-detail" class="${fieldCls('authDetail')}" placeholder="api_key" value="${escAttr(d.authDetail ?? '')}">${fieldErr('authDetail')}</div>`;
    }
    if (modeValue === 'advanced') {
      fields += `<div class="f-row"><label for="c-template">Injection template</label><input id="c-template" class="${fieldCls('template')}" placeholder="Authorization: Bearer {{TOKEN_NAME}}" value="${escAttr(d.template ?? '')}">${fieldErr('template')}
        <div class="rule-note">References credentials by name using <code>{{ … }}</code>. Use this for Basic auth or composed credentials.</div></div>`;
    } else if (modeValue !== 'oauth') {
      fields += credentialChooserHTML(t, d, true, state.connPreset?.credentialHint);
    }
    // Branded rows say where the credential comes from — the equivalent of a
    // provider's "get your API key" page, as plain text (no live links here).
    if (state.connPreset?.docsUrl && modeValue !== 'oauth') {
      fields += `<div class="rule-note">Create or find your ${esc(state.connEntryName || 'API')} key at <code>${esc(state.connPreset.docsUrl)}</code></div>`;
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
  if (editing && conn && (conn.wired_agents || []).length) {
    fields += `<div class="rule-note">Changing the destination unwires affected agents.</div>`;
  }
  const label = (!editing && state.connEntryName) || catalogNameForType(t);
  const oauthSelected = !editing && t === 'api' && isMcpDraft(d)
    && (d.authMode || 'oauth') === 'oauth';
  const title = `${editing ? 'Edit' : oauthSelected ? 'Connect' : 'Add'} ${label}`;
  const discardConfirm = state.confirmDiscard ? `
    <div class="sheet-backdrop over-sheet" data-act="discard-keep"></div>
    <div class="sheet wide confirm-sheet discard-confirm" role="dialog" aria-modal="true" aria-labelledby="discard-conn-title">
      <h3 id="discard-conn-title">${editing ? 'Discard changes?' : 'Discard this tool?'}</h3>
      <p>You have unsaved changes in this form. Closing it discards them.</p>
      <div class="sheet-actions">
        <button class="btn" data-act="discard-keep">Keep editing</button>
        <button class="btn danger" data-act="discard-confirm">Discard</button>
      </div></div>` : '';
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>${title}</h3>${fields}
    <div class="sheet-actions"><button class="btn" data-act="sheet-cancel">Cancel</button>
      <button class="btn primary" data-act="save-conn">${editing ? 'Save' : oauthSelected ? 'Sign in & connect' : `Add ${label}`}</button></div></div>${discardConfirm}`;
}

/* ------------------------- MCP sign-in sheet ------------------------------ */

const AUTH_STEPS: Array<[string, string]> = [
  ['probing', 'Contacting the server'],
  ['discovering', 'Reading how to sign in'],
  ['registering', 'Registering Multitool'],
  ['awaiting_authorization', 'Approving in your browser'],
  ['exchanging', 'Finishing sign-in'],
  ['verifying', 'Confirming the account'],
];

function isTerminalAuth(auth: McpAuthState): boolean {
  return auth.phase === 'succeeded' || auth.phase === 'failed' || auth.phase === 'cancelled';
}

// Every intermediate state of the sign-in flow, live: the step list shows
// where the dance is, and the terminal states (connected / failed /
// cancelled) each carry their own actions.
function mcpAuthSheet(): string {
  const auth = state.mcpAuth;
  if (!auth) return '';
  const stepIndex = AUTH_STEPS.findIndex(([phase]) => phase === auth.phase);
  const succeeded = auth.phase === 'succeeded';
  const steps = AUTH_STEPS.map(([, label], index) => {
    const done = succeeded || (stepIndex > index);
    const current = !isTerminalAuth(auth) && stepIndex === index;
    return `<li class="auth-step ${done ? 'done' : ''} ${current ? 'current' : ''}">
      <span class="auth-step-mark" aria-hidden="true">${done ? ICONS.check : current ? '<span class="auth-spinner"></span>' : ''}</span>
      <span>${esc(label)}</span></li>`;
  }).join('');

  let body = '';
  let actions = `<button class="btn" data-act="mcp-auth-cancel">Cancel</button>`;
  if (auth.phase === 'awaiting_authorization') {
    body = `<div class="auth-note">Your browser should have opened. Approve the request there,
        then come back — this dialog follows along by itself.</div>
      <div class="auth-url"><code title="${escAttr(auth.authorization_url)}">${esc(auth.authorization_url)}</code></div>`;
    actions = `<button class="btn" data-act="mcp-auth-cancel">Cancel</button>
      <button class="btn primary" data-act="mcp-open-browser" data-url="${escAttr(auth.authorization_url)}">Open browser again</button>`;
  } else if (auth.phase === 'succeeded') {
    body = `<div class="auth-done">${ICONS.circleCheck}
      <div><b>${esc(auth.connection_name)} is connected${auth.account ? ` as ${esc(auth.account)}` : ''}.</b>
      ${auth.warning
        ? `<div class="auth-warning">Token saved, but verification did not complete: ${esc(auth.warning)}</div>`
        : '<div class="auth-sub">Use the status button on the tool any time to re-check the server and account.</div>'}
      </div></div>`;
    actions = `<button class="btn primary" data-act="mcp-auth-done">Done</button>`;
  } else if (auth.phase === 'failed') {
    body = `<div class="auth-failed">${ICONS.circleX}
      <div><b>${esc(auth.message)}</b>
      ${auth.hint ? `<div class="auth-sub">${esc(auth.hint)}</div>` : ''}</div></div>`;
    actions = `${state.mcpAuthDraft && !state.mcpAuthDraft.reauth_connection_id
        ? '<button class="btn" data-act="mcp-auth-token">Use a token instead</button>'
        : '<button class="btn" data-act="sheet-cancel">Close</button>'}
      ${state.mcpAuthDraft ? '<button class="btn primary" data-act="mcp-auth-retry">Try again</button>' : ''}`;
  } else if (auth.phase === 'cancelled') {
    body = '<div class="auth-note">Sign-in cancelled. Nothing was saved.</div>';
    actions = `<button class="btn" data-act="sheet-cancel">Close</button>
      ${state.mcpAuthDraft ? '<button class="btn primary" data-act="mcp-auth-retry">Try again</button>' : ''}`;
  }
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide auth-sheet" role="dialog" aria-modal="true" aria-labelledby="mcp-auth-title">
      <h3 id="mcp-auth-title">Connect ${esc(auth.name)}</h3>
      <div class="auth-target"><code>${esc(auth.target)}</code></div>
      <ol class="auth-steps">${steps}</ol>
      ${body}
      <div class="sheet-actions">${actions}</div></div>`;
}

/** Kick off (or restart) a sign-in and switch to the progress sheet. */
async function startMcpAuth(draft: McpAuthDraft): Promise<boolean> {
  try {
    const auth = await invoke('start_mcp_auth', { input: draft });
    state.mcpAuthDraft = draft;
    state.mcpAuth = auth;
    state.mcpAuthOpenedUrl = null;
    state.sheet = { kind: 'mcp-auth' };
    state.sheetErrors = {};
    state.confirmDiscard = false;
    state.formMenuOpen = null;
    render();
    return true;
  } catch (error) {
    showFormError(error);
    return false;
  }
}

function receiveMcpAuth(auth: McpAuthState): void {
  if (!state.mcpAuth || state.mcpAuth.id !== auth.id) return;
  state.mcpAuth = auth;
  // First arrival in the browser step opens the system browser once;
  // "Open browser again" covers the blocked-popup / closed-tab cases.
  if (auth.phase === 'awaiting_authorization'
      && state.mcpAuthOpenedUrl !== auth.authorization_url) {
    state.mcpAuthOpenedUrl = auth.authorization_url;
    void invoke('open_url', { url: auth.authorization_url })
      .catch(() => toast('⚠ Could not open the browser — use the button in the dialog'));
  }
  if (state.sheet && state.sheet.kind === 'mcp-auth') render();
}

function settingsSheet() {
  const s = state.settings;
  const reauthRow = `<div class="set-row"><div class="set-txt"><div class="st-title">Confirm before using saved secrets</div>
      <div class="st-sub">Use OS authentication before showing, copying, or sending a saved credential.</div></div>
      <button class="switch ${s.reauth_on_read ? 'on' : ''}" data-act="toggle-reauth" role="checkbox" aria-checked="${s.reauth_on_read ? 'true' : 'false'}"></button></div>`;
  const dockRow = `<div class="set-row"><div class="set-txt"><div class="st-title">Hide Dock icon in the menu bar</div>
      <div class="st-sub">When minimized to the menu bar, hide the Dock icon until the window is reopened.</div></div>
      <button class="switch ${s.menu_bar_hides_dock ? 'on' : ''}" data-act="toggle-menubar-dock" role="checkbox" aria-checked="${s.menu_bar_hides_dock ? 'true' : 'false'}"></button></div>`;
  const websocketRow = `<div class="set-row"><div class="set-txt"><div class="st-title">Show WebSockets</div>
      <div class="st-sub">Adds Custom WebSocket to the tool catalog. Tools you already have stay visible either way.</div></div>
      <button class="switch ${s.show_websockets ? 'on' : ''}" data-act="toggle-websockets" role="checkbox" aria-checked="${s.show_websockets ? 'true' : 'false'}"></button></div>`;
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>Settings</h3>
    ${reauthRow}${websocketRow}${dockRow}
    <div class="sheet-actions"><button class="btn primary" data-act="sheet-cancel">Done</button></div></div>`;
}

/* --------------------------------- helpers ------------------------------- */
const cap = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);
const tabLabel = (tab: Tab): string =>
  tab === 'connections' ? 'Tools' : tab === 'start' ? 'Get started' : cap(tab);

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
    || sheet?.kind === 'add-conn' || sheet?.kind === 'edit-conn'
    || sheet?.kind === 'mcp-auth';
}

// Test a connection broker-side and pin the result to its catalog row.
// Shared by the row's ⋯ menu and the automatic post-save health check.
async function runConnectionTest(id: string): Promise<void> {
  if (!id || state.connTests[id]?.running) return;
  state.connTests[id] = { running: true };
  render();
  try {
    const report = await invoke('test_connection', { id });
    state.connTests[id] = { running: false, ok: report.ok, detail: report.detail };
  } catch (error) {
    state.connTests[id] = { running: false, ok: false, detail: errorMessage(error) };
  }
  render();
}

async function loadWiringTools(connectionId: string): Promise<void> {
  try {
    const tools = await invoke('list_mcp_tools', { id: connectionId });
    const wt = state.wiringTools;
    if (!wt || wt.connectionId !== connectionId) return;
    wt.loading = false;
    wt.tools = tools;
  } catch (error) {
    const wt = state.wiringTools;
    if (!wt || wt.connectionId !== connectionId) return;
    wt.loading = false;
    wt.error = errorMessage(error);
  }
  render(false);
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
  const toolNameTaken = adding && toolNameIsTaken(name);
  const mcpAdd = adding && t === 'api' && isMcpDraft(d);
  const authMode = d.authMode || (mcpAdd ? 'oauth' : 'bearer');
  const usesOauth = mcpAdd && authMode === 'oauth';
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
  let apiOrigin: { scheme: string; host: string; port: number | null } | null = null;
  let mcpPath: string | null = null;
  if (t === 'api' && isMcpDraft(d)) {
    try {
      const server = parseMcpServerUrl(d.origin || '');
      apiOrigin = { scheme: server.scheme, host: server.host, port: server.port };
      mcpPath = server.mcpPath;
    } catch (error) { errs.origin = errorMessage(error); }
  } else if (t === 'api') {
    try { apiOrigin = parseApiOrigin(d.origin || ''); }
    catch (error) { errs.origin = errorMessage(error); }
  }
  const usesRecipe = adding && (t === 'api' || t === 'ws')
    && authMode !== 'advanced' && !usesOauth;
  const needsCredentialChoice = !usesOauth && (
    (adding && !((t === 'api' || t === 'ws') && authMode === 'advanced')) ||
    (!adding && t !== 'api'));
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
  if (Object.keys(errs).length || toolNameTaken || newSecretNameTaken) {
    state.sheetErrors = errs;
    render();
    if (toolNameTaken) focusField('f-cname');
    else if (newSecretNameTaken) focusField('c-new-secret-name');
    return;
  }
  if (usesOauth) {
    // No credential to collect: the sign-in flow mints the token, stores
    // it, and creates the connection only once authentication completed.
    const entry = d.entryId ? CATALOG.find((candidate) => candidate.id === d.entryId) : undefined;
    const template = entry?.mcpTemplate;
    await startMcpAuth({
      name,
      scheme: apiOrigin!.scheme,
      host: apiOrigin!.host,
      port: apiOrigin!.port,
      mcp_path: mcpPath!,
      whoami_tool: template?.whoamiTool ?? null,
      expected_tools: template?.expectedTools ?? [],
    });
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
    input.mcp_path = mcpPath;
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
    toast(adding ? '🔌 Tool saved' : '✏️ Tool updated');
    if (adding) {
      // The first-task prompt names the service just saved — the very first
      // one, and every guided save after it — never an older neighbor.
      const hadConnections = state.connections.length > 0;
      // The first tool added gets the "ready — ask your agent" nudge.
      if (!hadConnections) {
        state.connectionReady = { name, type: t };
        state.connectionTaskCopied = false;
      }
    }
    closeSheet();
    await refresh('all');
    // Answer "did that actually work?" immediately: test the saved tool and
    // show the result on its row (expanded into view when it was just added).
    if (adding) {
      const saved = state.connections.find((c) => c.name === name);
      if (saved) {
        const entry = entryForConnection(saved);
        if (entry) state.toolOpen = entry.id;
        render();
        void runConnectionTest(saved.id);
      }
    } else {
      void runConnectionTest(sheet.id ?? '');
    }
  } catch (e) {
    showFormError(e);
  }
}

function closeSheet() {
  const releaseDropdown = isProtectedFormSheet();
  // Closing the sign-in sheet mid-flow aborts the flow: no listener stays
  // behind waiting for a browser approval the user walked away from.
  if (state.sheet?.kind === 'mcp-auth' && state.mcpAuth && !isTerminalAuth(state.mcpAuth)) {
    const id = state.mcpAuth.id;
    void invoke('cancel_mcp_auth', { id }).catch(() => {});
  }
  state.mcpAuth = null;
  state.wiringTools = null;
  state.sheet = null;
  state.draft = {};
  state.sheetErrors = {};
  state.sheetBaseline = null;
  state.confirmDiscard = false;
  state.formMenuOpen = null;
  state.connPreset = null;
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
// Opportunistic re-check: coming back to the app re-tests anything the
// broker last saw unhealthy, so a fixed credential clears its badge
// without a manual test. Throttled so window-switching stays free.
let lastFocusRecheck = 0;
window.addEventListener('focus', () => {
  if (Date.now() - lastFocusRecheck < 60_000) return;
  lastFocusRecheck = Date.now();
  for (const connection of state.connections) {
    if ((connection.last_status === 'needs_reconnect' || connection.last_status === 'failed')
      && !state.connTests[connection.id]?.running) {
      void runConnectionTest(connection.id);
    }
  }
});

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
  if (state.agentMenuOpen && !target?.closest('.agent-menu-wrap')) {
    state.agentMenuOpen = null;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.connMenuOpen && !target?.closest('.tile-menu-wrap')) {
    state.connMenuOpen = null;
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
      state.agentMenuOpen = null;
      state.connMenuOpen = null;
      render();
      resetScroll();
      break;
    }
    case 'mode-tray': state.menuOpen = false; run(() => invoke('ui_set_mode', { mode: 'tray' })); break;
    case 'mode-window': run(() => invoke('ui_set_mode', { mode: 'window' })); break;
    case 'toggle-settings-menu': state.menuOpen = !state.menuOpen; render(); break;
    case 'toggle-agent-menu':
      state.agentMenuOpen = state.agentMenuOpen === id ? null : id;
      render();
      break;
    case 'toggle-conn-menu':
      state.connMenuOpen = state.connMenuOpen === id ? null : id;
      render();
      break;
    case 'open-settings': state.menuOpen = false; state.sheet = { kind: 'settings' }; render(); break;
    case 'copy-agent-setup':
      if (state.agentMenuOpen) { state.agentMenuOpen = null; render(); }
      if (await run(() => invoke('copy_agent_setup'))) toast('📋 Setup instructions copied');
      break;
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

    case 'conn-import': {
      const source = (document.getElementById('conn-import') as HTMLInputElement | null)?.value
        ?? state.connImportSource;
      if (!source.trim()) break;
      try {
        const imported = await connectionDraftFromImport(source, state.draft);
        if (imported.type !== state.connType) {
          // The row you opened decided the type; a mismatched paste belongs
          // to a different tool rather than silently switching this one.
          state.connImportError =
            `That looks like a ${catalogNameForType(imported.type)} connection — add it from the ${catalogNameForType(imported.type)} row.`;
          render();
          focusField('conn-import');
          break;
        }
        state.draft = imported.draft;
        state.connImportError = null;
        state.sheetErrors = {};
        state.connAdvancedOpen = draftUsesAdvancedFields(state.draft, state.connType);
        render();
        focusImportedConnectionDraft();
      } catch (error) {
        state.connImportError = errorMessage(error);
        render();
        focusField('conn-import');
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
    case 'start-option':
      if (id && START_OPTIONS.some((option) => option.id === id)) {
        state.startOption = id;
        render();
      }
      break;
    case 'copy-text': {
      const text = btn.dataset.text ?? '';
      if (!text) break;
      try {
        await navigator.clipboard.writeText(text);
        toast('📋 Copied');
      } catch {
        toast('⚠ Could not copy');
      }
      break;
    }
    case 'catalog-toggle':
      state.toolOpen = state.toolOpen === id ? null : id;
      render(); break;
    case 'catalog-add': {
      const entry = CATALOG.find((candidate) => candidate.id === id);
      if (!entry || entry.via !== 'connection' || !entry.connType) break;
      if (!await holdDropdownFormOpen()) break;
      state.sheet = { kind: 'add-conn' };
      state.connType = entry.connType;
      state.draft = {};
      // An MCP row stores an API connection, but the form asks for a
      // server URL rather than an API root — and the dialog is named after
      // the row the user clicked, not the protocol underneath it.
      state.connEntryName = entry.name;
      state.connPreset = entry.preset ?? null;
      if (entry.mcp) {
        state.draft.isMcp = true;
        state.draft.entryId = entry.id;
        // Sign-in first; a pasted token stays one select away. The
        // template's published URL prefills the field but stays editable.
        state.draft.authMode = 'oauth';
        if (entry.mcpTemplate?.serverUrl) state.draft.origin = entry.mcpTemplate.serverUrl;
      }
      // A branded row prefills everything but the credential: the documented
      // API root, the vendor's auth recipe, and a suggested name — all into
      // ordinary, editable form fields.
      if (entry.preset) {
        state.draft.name = entry.preset.name;
        state.draft.origin = entry.preset.origin;
        state.draft.authMode = entry.preset.authMode;
        state.draft.authDetail = entry.preset.authDetail;
      }
      if (entry.connType === 'pg') state.draft.port = '5432';
      if (entry.connType === 'ssh') state.draft.port = '22';
      state.sheetErrors = {}; state.sheetBaseline = null; state.connAdvancedOpen = false;
      state.connImportSource = ''; state.connImportError = null;
      render();
      // With a preset the only thing left to supply is the credential.
      focusField(!entry.preset ? 'f-cname' : state.secrets.length ? 'c-secret' : 'c-new-secret-value');
      break;
    }
    case 'edit-conn': {
      const c = state.connections.find((x) => x.id === id);
      if (!c) break;
      state.connMenuOpen = null;
      if (!await holdDropdownFormOpen()) break;
      state.sheet = { kind: 'edit-conn', id }; state.connType = c.type;
      state.connEntryName = null;
      state.connPreset = null;
      state.sheetErrors = {};
      state.sheetBaseline = null;
      state.draft = { name: c.name, host: c.host, scheme: c.scheme,
        origin: c.type === 'api'
          // An MCP connection round-trips as the full server URL it was
          // entered as, so editing shows what was typed rather than a
          // stripped origin.
          ? apiOriginFromParts(c.scheme ?? undefined, c.host ?? undefined, c.port)
            + (c.mcp_path ?? '')
          : null,
        isMcp: Boolean(c.mcp_path),
        mcpPath: c.mcp_path ?? null,
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
    case 'del-conn-ask': state.connMenuOpen = null; state.confirm = { kind: 'del-conn', id }; render(); break;
    case 'del-conn-confirm':
      if (await run(() => invoke('delete_connection', { id }))) {
        state.confirm = null;
        delete state.connTests[id];
        delete state.mcpStatus[id];
        toast('🗑 Tool removed');
        await refresh('all');
      }
      break;
    case 'test-conn':
      state.connMenuOpen = null;
      void runConnectionTest(id);
      break;
    case 'mcp-status': {
      if (state.mcpStatus[id] && state.mcpStatus[id].running) break;
      state.connMenuOpen = null;
      const connection = state.connections.find((x) => x.id === id);
      if (!connection) break;
      state.mcpStatus[id] = { running: true };
      render();
      const template = mcpTemplateForConnection(connection);
      try {
        const report = await invoke('mcp_status', {
          id,
          options: {
            whoami_tool: template?.whoamiTool ?? null,
            expected_tools: template?.expectedTools ?? [],
          },
        });
        state.mcpStatus[id] = { running: false, report };
      } catch (error) {
        state.mcpStatus[id] = { running: false, error: errorMessage(error) };
      }
      // The check can update the stored account acknowledgment.
      await load('connections', 'list_connections');
      render();
      break;
    }
    case 'reconnect-mcp': {
      const connection = state.connections.find((x) => x.id === id);
      if (!connection || !connection.mcp_path) break;
      state.connMenuOpen = null;
      if (!await holdDropdownFormOpen()) break;
      const template = mcpTemplateForConnection(connection);
      await startMcpAuth({
        name: connection.name,
        scheme: connection.scheme || 'https',
        host: connection.host || '',
        port: connection.port ?? null,
        mcp_path: connection.mcp_path,
        reauth_connection_id: connection.id,
        whoami_tool: template?.whoamiTool ?? null,
        expected_tools: template?.expectedTools ?? [],
      });
      break;
    }
    case 'wiring-tools': {
      const agent = state.agents.find((x) => x.id === id);
      const connection = state.connections.find((x) => x.id === btn.dataset.conn);
      if (!agent || !connection) break;
      const wiring = (connection.wired_agents || []).find((w) => w.agent_id === agent.id);
      state.sheet = { kind: 'wiring-tools' };
      state.wiringTools = {
        agentId: agent.id,
        agentName: agent.name,
        connectionId: connection.id,
        connectionName: connection.name,
        loading: true,
        selected: wiring?.allowed_tools ? [...wiring.allowed_tools] : null,
        saving: false,
      };
      render();
      void loadWiringTools(connection.id);
      break;
    }
    case 'wt-all': {
      const wt = state.wiringTools;
      if (!wt) break;
      // Checking "All tools" clears curation; unchecking starts a subset
      // from everything currently advertised.
      wt.selected = wt.selected === null ? (wt.tools || []).map((t) => t.name) : null;
      render(false);
      break;
    }
    case 'wt-toggle': {
      const wt = state.wiringTools;
      if (!wt) break;
      const tool = btn.dataset.tool || '';
      if (wt.selected === null) {
        // Unchecking one tool from "all" starts a subset of the rest.
        wt.selected = (wt.tools || []).map((t) => t.name).filter((name) => name !== tool);
      } else if (wt.selected.includes(tool)) {
        wt.selected = wt.selected.filter((name) => name !== tool);
      } else {
        wt.selected = [...wt.selected, tool];
      }
      render(false);
      break;
    }
    case 'wt-save': {
      const wt = state.wiringTools;
      if (!wt || wt.saving) break;
      wt.saving = true;
      render(false);
      if (await run(() => invoke('set_wiring_tools', {
        agentId: wt.agentId, connectionId: wt.connectionId, tools: wt.selected,
      }))) {
        toast(wt.selected === null
          ? '🔧 All tools allowed'
          : `🔧 ${wt.selected.length} tool${wt.selected.length === 1 ? '' : 's'} allowed`);
        closeSheet();
        await refresh('all');
      } else {
        wt.saving = false;
        render(false);
      }
      break;
    }
    case 'mcp-open-browser':
      await run(() => invoke('open_url', { url: btn.dataset.url || '' }));
      break;
    case 'mcp-auth-cancel': {
      const auth = state.mcpAuth;
      if (!auth || isTerminalAuth(auth)) { closeSheet(); break; }
      // The resulting mcp-auth-changed event flips the sheet to Cancelled.
      await run(() => invoke('cancel_mcp_auth', { id: auth.id }));
      break;
    }
    case 'mcp-auth-retry':
      if (state.mcpAuthDraft) await startMcpAuth(state.mcpAuthDraft);
      break;
    case 'mcp-auth-token':
      // Back to the add form with the same draft, token mode selected.
      state.mcpAuth = null;
      state.sheet = { kind: 'add-conn' };
      state.draft.authMode = 'bearer';
      state.sheetErrors = {};
      state.sheetBaseline = null;
      render();
      focusField('f-origin');
      break;
    case 'mcp-auth-done':
      toast('🔌 Connected');
      closeSheet();
      await refresh('all');
      break;
    case 'wire':
      await run(() => invoke('set_wiring', { agentId: id, connectionId: btn.dataset.conn || '', wired: true }));
      await refresh('all');
      break;
    case 'unwire':
      await run(() => invoke('set_wiring', { agentId: id, connectionId: btn.dataset.conn || '', wired: false }));
      toast('🔌 Unwired'); await refresh('all');
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

    // SEP-2322 elicitation (DESIGN MOCK, see ELICITATION.md): the queue row
    // opens the dialog; answering or refusing there resumes the paused
    // upstream call broker-side. Values are read from the DOM at click time
    // and handed straight to the command — they are never mirrored into
    // state, so a re-render cannot repaint them.
    case 'elicit-open': {
      state.sheet = { kind: 'elicitation', id };
      render();
      const request = state.elicitations.find((r) => r.id === id);
      if (request?.fields[0]) focusField(`elicit-${id}-${request.fields[0].name}`);
      break;
    }
    case 'elicit-send': {
      const request = state.elicitations.find((r) => r.id === id);
      if (!request) break;
      const values: Record<string, string> = {};
      let missing = false;
      for (const field of request.fields) {
        const input = document.getElementById(`elicit-${id}-${field.name}`) as HTMLInputElement | null;
        const value = input?.value.trim() ?? '';
        if (!value) { missing = true; input?.focus(); break; }
        values[field.name] = value;
      }
      if (missing) break;
      if (await run(() => invoke('respond_elicitation', { id, approved: true, values }))) {
        toast(`📨 Sent to ${request.connection} — ${request.agent} resumes`);
        closeSheet();
        await refresh('elicitations');
      }
      break;
    }
    case 'elicit-refuse': {
      const request = state.elicitations.find((r) => r.id === id);
      if (await run(() => invoke('respond_elicitation', { id, approved: false }))) {
        toast(`🚫 Refused — ${request?.agent ?? 'the agent'} is told no, without your reasons`);
        closeSheet();
        await refresh('elicitations');
      }
      break;
    }

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
    case 'toggle-websockets':
      {
        const on = !state.settings.show_websockets;
        if (await run(() => invoke('set_show_websockets', { on }))) {
          state.settings.show_websockets = on;
          toast(on ? '🔌 WebSockets shown in the catalog' : '🔌 WebSockets hidden');
        }
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
    default: break;
  }
});

document.addEventListener('keydown', (e) => {
  // Ctrl-Tab / Ctrl-Shift-Tab cycle the left-nav tabs when the main window is
  // open (a modal sheet keeps focus).
  if (e.key === 'Tab' && e.ctrlKey && !state.sheet) {
    e.preventDefault();
    const i = TABS.indexOf(state.tab);
    const n = TABS.length;
    state.tab = TABS[(i + (e.shiftKey ? -1 : 1) + n) % n];
    state.menuOpen = false;
    render();
    return;
  }
  if (e.key === 'Escape') {
    if (state.agentMenuOpen) { state.agentMenuOpen = null; render(); return; }
    if (state.connMenuOpen) { state.connMenuOpen = null; render(); return; }
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

function updateToolNameWarning(): void {
  const input = document.getElementById('f-cname') as HTMLInputElement | null;
  const hint = document.getElementById('tool-name-warning');
  if (!input || !hint) return;
  const nameTaken = toolNameIsTaken(input.value);
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
  if (target?.id === 'conn-import') {
    state.connImportSource = target.value;
    state.connImportError = null;
    // Toggle the button in place: a full re-render per keystroke would be
    // wasteful, and leaving it stale would make Prefill permanently dead.
    document.querySelector('[data-act="conn-import"]')
      ?.toggleAttribute('disabled', !target.value.trim());
  }
  if (target?.id === 'tool-search') {
    state.toolSearch = target.value;
    state.toolOpen = null;
    render();
    return;
  }
  if (target?.id === 'f-cname') {
    updateCredentialNamePlaceholder(target.value);
    updateCredentialNameWarning();
    updateToolNameWarning();
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
  // Choose the landing tab before the first paint: nothing configured yet
  // means the walkthrough is the useful screen.
  await Promise.all([
    load('connections', 'list_connections'),
    load('agents', 'list_agents'),
  ]);
  if (mode !== 'dropdown' && !state.connections.length && !state.agents.length) {
    state.tab = 'start';
  }
  await refresh('all');
  // The setup card always shows the paste-ready message.
  try { state.agentSetupInstructions = await invoke('get_agent_setup'); render(); }
  catch (error) { console.error('get_agent_setup', error); }
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
    if (state.tab === 'activity' && !state.sheet && !state.menuOpen) render();
  }, 60000);
  // Live updates from the core.
  await listen('aka://sessions-changed', () => refresh('sessions'));
  await listen('aka://elicitations-changed', async () => {
    await refresh('elicitations');
    // The open dialog's request may have been answered elsewhere or
    // expired; the sheet re-renders as "gone" via elicitationSheet, which
    // is correct — nothing to close here, the user dismisses it informed.
  });
  await listen('aka://agents-changed', async () => {
    const before = new Map(state.agents.map((agent) => [agent.name, agent.paired_at]));
    await load('agents', 'list_agents');
    render();
    const connected = state.agents.find((agent) =>
      !before.has(agent.name) || before.get(agent.name) !== agent.paired_at);
    if (connected) toast(`🔗 ${connected.name} is connected — wire it to your tools from the Agents tab`);
  });
  await listen('aka://wirings-changed', () => refreshAgentsView());
  // A core-side connection change (a trust-on-first-use host-key pin) has no
  // originating UI command to refresh after; reload the services list.
  await listen('aka://connections-changed', () => refresh('connections'));
  await listen('aka://activity-appended', (ev) => receiveActivity(ev.payload));
  await listen('aka://mcp-auth-changed', (ev) => receiveMcpAuth(ev.payload));
  await listen('aka://activity-changed', () => refresh('activity'));
  await listen('aka://open-settings', () => {
    if (isProtectedFormSheet()) return;
    state.sheet = { kind: 'settings' };
    state.draft = {};
    state.sheetErrors = {};
    render();
  });
  await listen('aka://dropdown-shown', () => {
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
  });
  await listen('aka://dropdown-hidden', () => {
    releaseDropdownForm();
    state.reveal = {};
    state.sheet = null;
    state.draft = {};
    state.sheetErrors = {};
    state.sheetBaseline = null;
    state.confirmDiscard = false;
    state.confirm = null;
    state.agentMenuOpen = null;
    state.connMenuOpen = null;
    render();
  });
}
boot();
