// Multitool frontend. One file drives all Tauri windows (main, tray
// and dropdown), chosen from location.hash.
//
// Every mutation and read goes through the Rust core via Tauri
// commands; the webview never holds a secret value. When run outside
// Tauri (a plain browser), a dev mock stands in for the core so the
// UI is developable standalone.

import { invoke, listen, mode } from '/src/bridge';
import {
  CATALOG, CATALOG_SECTIONS, catalogNameForType, connectionsForEntry, filterCatalog,
} from '/src/catalog';
import {
  START_OPTIONS, startOptionById, startProgress, startTask,
} from '/src/getting-started';
import type { CatalogEntry } from '/src/catalog';
import { ICONS, TYPES, esc, escAttr, toast, relTime, absTime } from '/src/util';
import {
  apiOriginFromParts, authTemplate, firstTaskPrompt, parseApiOrigin, parseConnectionImport,
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
  agentSetupInstructions: '', // short paste-ready setup message (lazy-loaded)
  settings: {
    reauth_on_read: true,
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
  'activity' | 'settings';
type LoadKey = 'secrets' | 'connections' | 'agents' | 'sessions' | 'activity';

async function refresh(which: RefreshTarget = 'all'): Promise<void> {
  const jobs: Promise<void>[] = [];
  if (which === 'all' || which === 'secrets') jobs.push(load('secrets', 'list_secrets'));
  if (which === 'all' || which === 'connections') jobs.push(load('connections', 'list_connections'));
  if (which === 'all' || which === 'agents') jobs.push(load('agents', 'list_agents'));
  if (which === 'all' || which === 'sessions') jobs.push(load('sessions', 'list_sessions'));
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

function globalSectionsHTML() {
  let out = '';
  const hasOnboarding = false;
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
  const wired = !!agentWiringFor(a, c);
  const live = state.sessions.some((s) => s.agent === a.name && s.connection === c.name);
  const pill = wired
    ? '<span class="acc-pill granted">Wired</span>'
    : '<span class="acc-pill">Not wired</span>';
  const action = wired
    ? `<button class="btn ghost sm" aria-label="Unwire ${escAttr(a.name)} from ${escAttr(c.name)}" data-act="unwire" data-id="${a.id}" data-conn="${c.id}">Unwire</button>`
    : `<button class="btn ghost sm" aria-label="Wire ${escAttr(a.name)} to ${escAttr(c.name)}" data-act="wire" data-id="${a.id}" data-conn="${c.id}">Wire up</button>`;
  return `<div class="acc-row">
    <span class="badge ${t.cls}">${t.label}</span>
    <div class="acc-svc"><div class="acc-name">${esc(c.name)}${live ? ' <span class="cc-live">● live</span>' : ''}</div>
      <div class="acc-target" title="${escAttr(c.target)}">${esc(c.target)}</div></div>
    ${pill}${action}</div>`;
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

// With no agent registered there is nothing to wire, so the tab explains how
// an agent connects instead of showing an empty shelf. The steps mirror what
// the broker actually does: the agent calls POST /v1/pair itself, appears
// here immediately, and starts with no access until it is wired.
function connectAgentWalkthroughHTML(): string {
  if (mode === 'dropdown') {
    return `<div class="empty"><div class="empty-ico">${ICONS.botMessageSquare}</div>
      <h3>No agents connected</h3>
      <p>Open the window and follow Get started.</p></div>`;
  }
  const step = (n: number, title: string, body: string): string =>
    `<li class="start-step">
      <span class="start-num" aria-hidden="true">${n}</span>
      <div class="start-body"><b>${esc(title)}</b>${body}</div></li>`;
  const hasTools = state.connections.length > 0;
  return `<div class="start connect-walkthrough">
    <div class="start-hero">
      <div class="empty-ico">${ICONS.botMessageSquare}</div>
      <h3>No agents connected yet</h3>
      <p>An agent registers itself — you never copy a token by hand.</p>
    </div>
    <ol class="start-steps">
      ${step(1, 'Give your agent the setup message', `<p>Paste this into the coding agent you want to
        use. It tells the agent where the broker's socket is and how to read its instructions.</p>
        <pre class="setup-instructions"><code>${esc(state.agentSetupInstructions || 'Loading…')}</code></pre>
        <div class="start-actions">
          <button class="btn primary sm" data-act="copy-agent-setup">Copy setup instructions</button>
        </div>`)}
      ${step(2, 'Let it register itself', `<p>The agent calls the broker once and is registered on the
        spot — no approval prompt, no pasted token. It appears on this tab within a second or two,
        able to list your tools but not to use any of them.</p>`)}
      ${step(3, 'Wire it to the tools it should reach', `<p>Each agent starts with no access. Wiring is
        the permission model: a wired tool works with no prompt, and everything else is refused.
        ${hasTools
          ? 'Your tools will appear under the agent here, each with a Wire up button.'
          : 'Add a tool first — there is nothing to wire an agent to yet.'}</p>
        <div class="start-actions">
          <button class="btn ${hasTools ? 'ghost' : 'primary'} sm" data-act="tab" data-tab="${hasTools ? 'start' : 'connections'}">${hasTools ? 'Open Get started' : 'Add your first tool'}</button>
        </div>`)}
    </ol>
  </div>`;
}

function agentsHTML(): string {
  if (!state.agents.length) return connectAgentWalkthroughHTML();
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
  // Only call out TLS when it is weaker than the default.
  const tls = c.type === 'pg' && c.sslmode && c.sslmode !== 'verify-full'
    ? `<span class="cat-meta-warn">TLS ${esc(c.sslmode)}</span>` : '';
  const hostKey = c.type === 'ssh' && !c.host_key_fingerprint
    ? '<span class="cat-meta-warn">Host key not pinned yet</span>' : '';
  return `<div class="cat-conn">
    <div class="cat-conn-tx">
      <div class="cat-conn-head"><b>${esc(c.name)}</b>${live ? ` <span class="cc-live">● ${live} live</span>` : ''}</div>
      <code title="${escAttr(c.target)}">${esc(c.target)}</code>
      <div class="cat-conn-meta">
        <span>${esc(connectionPurpose(c))}</span>
        <span>${esc(connectionCredential(c))}</span>
        <span class="${wiring.wired ? '' : 'cat-meta-idle'}">${esc(wiring.text)}</span>
        ${tls}${hostKey}
      </div>${connTestResultHTML(c)}</div>
    <div class="tile-menu-wrap">
      <button class="icon-btn tile-menu-btn ${menuOpen ? 'on' : ''}" title="Tool options"
        aria-label="Options for ${escAttr(c.name)}" aria-haspopup="menu"
        aria-expanded="${menuOpen}" data-act="toggle-conn-menu" data-id="${c.id}">${ICONS.ellipsis}</button>
      ${menuOpen ? `<div class="tile-menu" role="menu" aria-label="Options for ${escAttr(c.name)}">
        <button class="menu-item" role="menuitem" data-act="test-conn" data-id="${c.id}" ${test && test.running ? 'disabled' : ''}>${ICONS.flaskConical} ${test && test.running ? 'Testing…' : 'Test connection'}</button>
        <button class="menu-item" role="menuitem" data-act="edit-conn" data-id="${c.id}">${ICONS.pencil} Edit…</button>
        <button class="menu-item danger" role="menuitem" data-act="del-conn-ask" data-id="${c.id}">${ICONS.trash} Delete…</button>
      </div>` : ''}
    </div></div>`;
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
  return `<div class="cat-row-wrap ${open ? 'open' : ''} ${entry.via === 'mcp' ? 'is-soon' : ''}">
    <div class="cat-row">
      <span class="cat-ico" aria-hidden="true">${ICONS[entry.icon] || ''}</span>
      <div class="cat-tx"><b>${esc(entry.name)}</b><span>${esc(entry.description)}</span></div>
      ${action}
    </div>${expansion}</div>`;
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
  const entries = filterCatalog(state.toolSearch);
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
  const unavailable = !option.connType;

  const picker = START_OPTIONS.map((candidate) =>
    `<button class="start-pick ${candidate.id === option.id ? 'on' : ''}"
      aria-pressed="${candidate.id === option.id}"
      data-act="start-option" data-id="${candidate.id}">${esc(candidate.label)}</button>`).join('');

  const step = (n: number, title: string, done: boolean, body: string): string =>
    `<li class="start-step ${done ? 'done' : ''}">
      <span class="start-num" aria-hidden="true">${done ? ICONS.check : n}</span>
      <div class="start-body"><b>${esc(title)}</b>${body}</div></li>`;

  const addBody = unavailable
    ? `<p>The MCP layer is not built yet, so there is nothing to add here. Everything below
        already works — set up Postgres, SSH, or a custom API and an agent wired to one of
        those behaves exactly the same way.</p>`
    : `<p>Save the destination and its credential. The credential goes to your Keychain;
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
      <h3>Give your agent a real tool</h3>
      <p>Three steps. Your credentials stay in the Keychain the whole way.</p>
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

function toolNameIsTaken(name: string): boolean {
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
  let sshHostKeyField = '';
  let pgTlsFields = '';
  let fields = importRow + importWarnings;
  const nameTaken = !editing && toolNameIsTaken(d.name ?? '');
  const nameWarning = editing ? ''
    : `<div id="tool-name-warning" class="field-warning" role="status" aria-live="polite"${nameTaken ? '' : ' hidden'}>Name used by an existing tool</div>`;
  fields += `<div class="f-row"><label for="f-cname">Name</label><input id="f-cname" class="${fieldCls('name')} ${nameTaken ? 'name-conflict-warning' : ''}"${editing ? '' : ' aria-describedby="tool-name-warning"'} placeholder="e.g. github" value="${escAttr(d.name ?? '')}">${fieldErr('name')}${nameWarning}</div>`;
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
  if (editing && conn && (conn.wired_agents || []).length) {
    fields += `<div class="rule-note">Changing the destination unwires affected agents.</div>`;
  }
  const title = `${editing ? 'Edit' : 'Add'} ${catalogNameForType(t)}`;
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
      <button class="btn primary" data-act="save-conn">${editing ? 'Save' : `Add ${catalogNameForType(t)}`}</button></div></div>${discardConfirm}`;
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
  const toolNameTaken = adding && toolNameIsTaken(name);
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
  if (Object.keys(errs).length || toolNameTaken || newSecretNameTaken) {
    state.sheetErrors = errs;
    render();
    if (toolNameTaken) focusField('f-cname');
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
      if (entry.connType === 'pg') state.draft.port = '5432';
      if (entry.connType === 'ssh') state.draft.port = '22';
      state.sheetErrors = {}; state.sheetBaseline = null; state.connAdvancedOpen = false;
      state.connImportSource = ''; state.connImportError = null;
      render(); focusField('f-cname'); break;
    }
    case 'edit-conn': {
      const c = state.connections.find((x) => x.id === id);
      if (!c) break;
      state.connMenuOpen = null;
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
        toast('🗑 Tool removed');
        await refresh('all');
      }
      break;
    case 'test-conn': {
      if (state.connTests[id] && state.connTests[id].running) break;
      state.connMenuOpen = null;
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
