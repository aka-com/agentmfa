// Multitool frontend. One file drives all Tauri windows (main, tray
// and dropdown), chosen from location.hash.
//
// Every mutation and read goes through the Rust core via Tauri
// commands; the webview never holds a secret value. When run outside
// Tauri (a plain browser), a dev mock stands in for the core so the
// UI is developable standalone.

import { invoke, listen, mode } from '/src/bridge';
import {
  CATALOG_SECTIONS, canQuickConnectMcp, catalogEntryById, catalogNameForType,
  collapsedCatalogGroup, connectedCatalogFirst, connectionsForEntry, entryForConnection,
  mcpTemplateForConnection, visibleCatalog,
} from '/src/catalog';
import type { ConnectionPreset } from '/src/catalog';
import {
  CONNECT_CLIENTS, CONNECT_MODE_LABELS, START_OPTIONS, START_PROMISE, clientMatchesLabel,
  connectClientById, connectModesFor, firstTaskPrompt, resolveConnectMode, startOptionById,
  startProgress, startTask,
} from '/src/getting-started';
import type {
  ConnectClient, ConnectClientEnv, ConnectModeId, ConnectStep, Platform, StartOption,
  StartProgress,
} from '/src/getting-started';
import type { CatalogEntry } from '/src/catalog';
import { ICONS, TYPES, esc, escAttr, toast, relTime, absTime } from '/src/util';
import {
  apiOriginFromParts, authTemplate, defaultConnectionName, parseApiOrigin, parseConnectionImport,
  isLoopbackHost, parseMcpServerUrl,
  quickSetupPlaceholder, shouldResolveSshImport, sshImportFromPreview, suggestedSecretName,
} from '/src/connection-input';
import { formErrorKind, formErrorMessage, inlineFormError } from '/src/form-errors';
import {
  LOCAL_BROKER, brokerLabel, brokerTakeover, brokerTone, remoteEndpointCaution,
} from '/src/broker';
import type { HostKeyCandidate } from '/src/connection-input';
import type {
  ActivityEntry,
  BrokerProfile,
  CommandArgs,
  CommandName,
  ConnectionInput,
  ConnectionSummary,
  ConnectionType,
  ElicitationRequest,
  IdentityInfo,
  McpAuthDraft,
  McpAuthState,
  McpStatusReport,
  McpToolInfo,
  IssuedEndpoint,
  SecretSummary,
  SessionSummary,
  Settings,
} from '/src/types';

const EDIT_SECRET_MASK = '••••••••••••';
const ACTIVITY_RENDER_LIMIT = 200;

// The left-nav tabs, in order — also the cycle order for Ctrl-Tab.
const TABS = ['start', 'connections', 'secrets', 'activity'] as const;
// The tray dropdown is a quick-access panel; onboarding belongs in the window.
const DROPDOWN_TABS = TABS.filter((tab) => tab !== 'start');
type Tab = typeof TABS[number];

// The two Get started views: the intro walkthrough and the per-client
// connection guides (formerly the Connect tab).
const START_VIEWS = ['walkthrough', 'guides'] as const;
type StartView = typeof START_VIEWS[number];


interface SheetState {
  kind: 'add-secret' | 'edit-secret' | 'add-conn' | 'edit-conn' | 'settings' | 'clear-activity'
    | 'elicitation' | 'mcp-auth' | 'wiring-tools' | 'endpoint-issued';
  id?: string;
  /** The issue result, for the 'endpoint-issued' sheet. */
  endpoint?: IssuedEndpoint;
}

interface ConfirmState {
  kind: string;
  id?: string | number;
  name?: string;
}

interface ConnectionDraft {
  name?: string;
  /** The form may keep deriving the name until the user edits it directly. */
  nameIsAutomatic?: boolean;
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
  /** True while sslmode was set from a loopback host rather than picked, so
   * a host change may keep adjusting it; false once the user picks one. */
  sslmodeIsAutomatic?: boolean;
  pgCaBundlePath?: string | null;
  url?: string | null;
  template?: string | null;
  secretId?: string | null;
  secretSource?: 'existing' | 'new' | 'none';
  newSecretName?: string;
  newSecretValue?: string;
  importedCredential?: string | null;
  identityFile?: string;
  identityFiles?: string[];
  sshImportId?: string;
  destination?: string | null;
  authMode?: string;
  // BYO-app OAuth (plain REST rows).
  oauthClientId?: string;
  oauthClientSecret?: string;
  oauthAuthUrl?: string;
  oauthTokenUrl?: string;
  /** Checked scopes; undefined means "preset defaults, all on". */
  oauthScopes?: string[];
  authDetail?: string;
  import?: string;
  setupSource?: 'manual' | 'import';
}

interface ConnectionReadyState {
  name: string;
  type: ConnectionType;
}

/** The remote-broker configuration form's transient state. */
interface RemoteSetupState {
  open: boolean;
  advancedOpen: boolean;
  url: string;
  token: string;
  busy: boolean;
  error: string | null;
}

interface AppState {
  tab: Tab;
  /** Which broker the app manages and its link state. */
  broker: BrokerProfile;
  /** The header's broker-switcher menu is open. */
  brokerMenuOpen: boolean;
  /** The remote-broker configuration form (a full-pane takeover). */
  remoteSetup: RemoteSetupState;
  localUsername: string;
  secrets: SecretSummary[];
  connections: ConnectionSummary[];
  /** The shared broker identity ("this computer's key"); null until loaded. */
  identity: IdentityInfo | null;
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
  secretSearch: string;
  /** Catalog entry ids whose connections are expanded. */
  toolsOpen: string[];
  catalogActionMenuOpen: string | null;
  /** Collapsible catalog sections currently showing all of their rows. */
  sectionsExpanded: string[];
  startOption: string;
  /** Which view the Get started tab shows: the walkthrough or the guides. */
  startView: StartView;
  /** Which connect mode step 2 of the walkthrough shows. */
  connectMode: string;
  connImportSource: string;
  connImportError: string | null;
  menuOpen: boolean;
  /** Which connection-guide card is expanded. */
  connectOpen: string | null;
  agentMenuOpen: string | null;
  connMenuOpen: string | null;
  /** Tools tab: the catalog "add" view is open (the flat list otherwise). */
  addToolOpen: boolean;
  copied: string | null;
  readyCopied: boolean;
  connectionReady: ConnectionReadyState | null;
  connectionTaskCopied: boolean;
  connTests: Record<string, ConnectionTestState>;
  /** Verdict of testing the add-form draft; null when no test has run. */
  draftTest: ConnectionTestState | null;
  /** Armed by a failed draft test: the next Add saves without re-testing.
   * Any edit to the form disarms it, so changed details test again. */
  draftTestOverride: boolean;
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
  /** Activity tab filters (transient; cleared on tab switch is deliberate NOT done — keep across renders). */
  activityQuery: string;
  activityAgent: string | null;
  activityIssuesOnly: boolean;
}

interface WiringToolsState {
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
  broker: LOCAL_BROKER,
  brokerMenuOpen: false,
  remoteSetup: { open: false, advancedOpen: false, url: '', token: '', busy: false, error: null },
  localUsername: '',
  secrets: [],
  connections: [],
  identity: null,
  sessions: [],
  activity: [],
  elicitations: [],      // paused upstream tool calls awaiting the user (SEP-2322)
  agentSetupInstructions: '', // short paste-ready setup message (lazy-loaded)
  settings: {
    reauth_on_read: true,
    show_websockets: false,
    menu_bar_hides_dock: false,
    presence_window_secs: 15 * 60,
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
  secretSearch: '',      // Secrets catalog search query
  toolsOpen: [],         // catalog entry ids whose connections are expanded
  catalogActionMenuOpen: null, // catalog id whose quick-connect chevron menu is open
  sectionsExpanded: [],  // sections showing beyond their connected/minimum rows
  startOption: 'postgres', // which walkthrough the Get started tab shows
  startView: 'walkthrough' as StartView, // walkthrough vs connection guides (kept across tab switches)
  connectMode: 'direct', // step 2's connect-mode chip (falls back per option)
  connImportSource: '',  // paste-to-prefill field in the add sheet
  connImportError: null,
  menuOpen: false,       // desktop-mode settings popover (gear) open
  connectOpen: 'claude-code', // connection-guide card that starts expanded
  agentMenuOpen: null,   // 'identity' while the key card's ⋯ menu is open
  connMenuOpen: null,    // connection id whose ⋯ options menu is open (Tools tab)
  addToolOpen: false,    // Tools tab: catalog add-view open (flat list otherwise)

  copied: null,          // secretId whose value was just copied (transient "Copied" flash)
  readyCopied: false,    // transient feedback on the setup-instructions status button
  connectionReady: null,
  connectionTaskCopied: false,
  connTests: {},         // connectionId -> in-flight/last test result (transient)
  draftTest: null,
  draftTestOverride: false,
  mcpAuth: null,
  mcpAuthDraft: null,
  mcpAuthOpenedUrl: null,
  mcpStatus: {},
  wiringTools: null,
  activityQuery: '',
  activityAgent: null,
  activityIssuesOnly: false,
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
type RefreshTarget = 'all' | 'secrets' | 'connections' | 'identity' | 'sessions' |
  'activity' | 'settings' | 'elicitations';
type LoadKey = 'secrets' | 'connections' | 'sessions' | 'activity' |
  'elicitations';

async function refresh(which: RefreshTarget = 'all'): Promise<void> {
  const jobs: Promise<void>[] = [];
  if (which === 'all' || which === 'secrets') jobs.push(load('secrets', 'list_secrets'));
  if (which === 'all' || which === 'connections') jobs.push(load('connections', 'list_connections'));
  if (which === 'all' || which === 'identity') jobs.push(loadIdentity());
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
async function loadLocalUsername(): Promise<void> {
  try { state.localUsername = await invoke('get_local_username'); }
  catch (e) { console.error('get_local_username', e); }
}
async function loadIdentity(): Promise<void> {
  try { state.identity = await invoke('get_identity'); }
  catch (e) { console.error('get_identity', e); }
}
async function refreshAgentsView(): Promise<void> {
  await Promise.all([
    load('connections', 'list_connections'),
    loadIdentity(),
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
  // with the connection guides rather than above every screen.
  if (state.tab === 'start' && state.startView === 'guides' && state.sessions.length) {
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

function secretsTableHTML(query = '') {
  const needle = query.trim().toLowerCase();
  const rows = state.secrets.filter((secret) => !needle
    || secret.name.toLowerCase().includes(needle)
    || secret.used_by_names.some((name) => name.toLowerCase().includes(needle))).map((s) => {
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
    return `<tr>
      <td><div class="s-name">${esc(s.name)}</div></td>
      <td class="val"><span class="val-wrap"><span class="val-slot ${copied ? 'is-copied' : ''}"><code>${valText}</code><span class="val-overlay">${overlay}</span></span></span> ${eyeBtn}</td>
      <td class="rowdel">
        <button class="icon-btn" title="Edit secret" aria-label="Edit secret ${escAttr(s.name)}" data-act="edit-secret" data-id="${s.id}">${ICONS.pencil}</button>
        <button class="icon-btn" title="Delete secret" aria-label="Delete secret ${escAttr(s.name)}" data-act="del-secret-ask" data-id="${s.id}">${ICONS.trash}</button></td></tr>`;
  }).join('');
  return `<table class="sec-table"><tbody>${rows}</tbody></table>`;
}

/* ---- connection guides (Get started > guides view) ---- */
// One shared identity covers every local agent, so the screen pivots around
// the core question — what may agents reach? A key card on top (this
// computer's key: where it lives, and Rotate), then one row per tool with an
// enable/disable toggle. Enabled = agents use the tool without prompting;
// disabled = refused.

// Kinds that can be issued a stable direct endpoint (a pasteable
// DSN/socket/URL an unmodified tool uses). WebSocket lands later.
const ENDPOINTABLE: Record<ConnectionType, boolean> = { pg: true, ssh: true, api: true, ws: false };

/**
 * The on-screen form of an issued endpoint address: scheme, a masked
 * password slot, host, and path. The embedded token and any query (the
 * socket-path form of a local DSN) stay off the screen — the full address
 * only lands on the clipboard.
 */
function briefEndpointAddress(dsn: string): string {
  try {
    const url = new URL(dsn);
    const auth = url.username
      ? `${url.username}${url.password ? ':…' : ''}@`
      : url.password ? '…@' : '';
    return `${url.protocol}//${auth}${url.host}${url.pathname === '/' ? '' : url.pathname}`;
  } catch {
    // Unparseable DSNs must never fall through with a credential in them:
    // drop everything between the username and the `@` before showing it.
    return dsn.replace(/\/\/([^/@:]*)(:[^@]*)?@/, '//$1@');
  }
}

// The direct-endpoint lifecycle strip on an enabled Postgres/SSH/HTTP row:
// a hairline footer that owns issue → live badge → reissue/revoke. The
// address shown is never the capability itself — SSH's socket path (which is
// the whole capability) appears only in the one-time issue sheet.
function endpointStripHTML(c: ConnectionSummary): string {
  if (!c.agent_access.enabled || !ENDPOINTABLE[c.type]) return '';
  const endpoint = c.agent_access.endpoint ?? null;
  if (!endpoint) {
    return `<div class="ep-strip">
      <button class="btn primary sm" data-act="issue-endpoint" data-conn="${c.id}"
        title="A pasteable address for an unmodified tool">Issue direct endpoint…</button>
    </div>`;
  }
  // The address itself is the copy affordance — clicking it copies, with the
  // same dim-and-overlay effect as copying a secret value.
  const copied = state.copied === `ep:${c.id}`;
  const address = endpoint.dsn
    ? `<button class="ep-addr-wrap ${copied ? 'is-copied' : ''}" title="Copy the full endpoint address"
        aria-label="Copy endpoint address for ${escAttr(c.name)}" data-act="copy-endpoint-dsn" data-conn="${c.id}">
        <code class="ep-addr">${esc(briefEndpointAddress(endpoint.dsn))}</code>
        <span class="val-overlay">${copied
          ? `<span class="copied-badge">${ICONS.check}<span>Copied</span></span>`
          : `<span class="ghost-copy">${ICONS.copy}<span>Copy</span></span>`}</span>
      </button>`
    : '<span class="ep-addr ep-addr-hidden">Agent socket — shown at issue</span>';
  // The strip is plug + address + copy, nothing more: reissue/revoke live
  // in the row's one options menu.
  return `<div class="ep-strip">
    <span class="ep-ico" title="Direct endpoint">${ICONS.plugSm}</span>
    ${address}
  </div>`;
}

/** The agents on/off switch a connection row carries — the row's primary
 * control, pinned to its right edge. */
function connToggleHTML(c: ConnectionSummary): string {
  const enabled = c.agent_access.enabled;
  return `<button class="switch ${enabled ? 'on' : ''}" role="switch" aria-checked="${enabled}"
    title="${enabled ? 'Agents may use this tool' : 'Agents may not use this tool'}"
    aria-label="${enabled ? 'Disable' : 'Enable'} ${escAttr(c.name)} for agents"
    data-act="${enabled ? 'disable-tool' : 'enable-tool'}" data-conn="${c.id}"></button>`;
}

/* ---- connection guides ---- */
// The guides' job is no longer to manage identities the broker stores —
// there is exactly one, this computer's key — but to get the user's own
// agents talking to Multitool: a key card, one guide card per client from
// the shared CONNECT_CLIENTS definitions (the same ones step 2 of the
// walkthrough renders), and a cosmetic recently-seen list built from
// activity labels. Per-tool access lives on the Tools tab.

// Tauri gives the webview the host OS's UA; Claude Desktop's config path
// is the only per-platform copy today.
function detectPlatform(): Platform {
  const ua = navigator.userAgent;
  if (ua.includes('Win')) return 'windows';
  if (ua.includes('Mac')) return 'macos';
  return 'linux';
}

/** The broker facts client snippets interpolate, with pre-identity fallbacks. */
function connectClientEnv(): ConnectClientEnv {
  return {
    socket: state.identity?.socket_path ?? '~/.aka/broker.sock',
    token: state.identity?.token_path ?? '~/.aka/token',
    platform: detectPlatform(),
  };
}

/** Activity labels seen recently, newest first: the cosmetic replacement
 * for the old agent roster. */
function recentClients(): Array<{ name: string; at: string }> {
  const latest = new Map<string, string>();
  for (const entry of state.activity) {
    if (!entry.agent || entry.agent === 'endpoint') continue;
    if (!latest.has(entry.agent)) latest.set(entry.agent, entry.at);
  }
  return [...latest.entries()]
    .map(([name, at]) => ({ name, at }))
    .slice(0, 6);
}

function connectKeyCardHTML(identity: IdentityInfo): string {
  const menuOpen = state.agentMenuOpen === 'identity';
  const copied = state.copied === 'shared-key';
  return `<div class="agent-block">
    <div class="agent-card">
      <span class="agent-avatar" role="img" aria-label="This computer's key">${ICONS.fileKey}</span>
      <div class="agent-id"><div class="c-name">This computer’s key</div>
        <div class="s-sub agent-sub">${esc(identity.token_path)}${identity.legacy_aliases
          ? ` · ${identity.legacy_aliases} legacy token${identity.legacy_aliases === 1 ? '' : 's'} still accepted`
          : ''}</div></div>
      <button class="btn sm" data-act="copy-key">${copied ? `${ICONS.check} Copied` : 'Copy key'}</button>
      <div class="agent-menu-wrap">
        <button class="icon-btn agent-menu-btn ${menuOpen ? 'on' : ''}" title="Key options"
          aria-label="Key options" aria-haspopup="menu"
          aria-expanded="${menuOpen}" data-act="toggle-agent-menu" data-id="identity">${ICONS.ellipsis}</button>
        ${menuOpen ? `<div class="agent-menu" role="menu" aria-label="Key options">
          <button class="menu-item danger" role="menuitem" data-act="rotate-key-ask">${ICONS.unplug} Rotate key…</button>
        </div>` : ''}
      </div>
    </div>
    <div class="connect-keynote">One shared key for everything that runs as you on this computer.
      Rotating it disconnects every agent at once.</div>
  </div>`;
}

function connectStepHTML(step: ConnectStep, n: number): string {
  const snippet = step.snippet
    ? `<div class="connect-snip"><pre><code>${esc(step.snippet)}</code></pre>
        <button class="btn sm connect-copy" data-act="copy-text" data-text="${escAttr(step.snippet)}">Copy</button></div>`
    : '';
  return `<div class="connect-step">
    <span class="connect-step-n" aria-hidden="true">${n}</span>
    <div class="connect-step-bd"><b>${esc(step.title)}</b>
      <div class="connect-step-d">${esc(step.detail)}</div>${snippet}</div>
  </div>`;
}

function connectCardHTML(client: ConnectClient, env: ConnectClientEnv): string {
  const open = state.connectOpen === client.id;
  const seen = recentClients().find((recent) => clientMatchesLabel(client, recent.name));
  const seenChip = seen
    ? `<span class="connect-seen" title="An agent using this label reached the broker">● seen ${relTime(seen.at)}</span>`
    : '';
  const steps = open
    ? `<div class="connect-steps">${client.steps(env).map((step, i) => connectStepHTML(step, i + 1)).join('')}
        ${client.note ? `<div class="connect-note">${esc(client.note)}</div>` : ''}</div>`
    : '';
  return `<div class="agent-block connect-card ${open ? 'open' : ''}">
    <button class="connect-row" data-act="connect-toggle" data-id="${client.id}" aria-expanded="${open}">
      <span class="connect-mark ${client.id}" aria-hidden="true">${client.icon ? ICONS[client.icon] || esc(client.mark) : esc(client.mark)}</span>
      <span class="connect-tx"><b>${esc(client.name)}</b><span>${esc(client.sub)}</span></span>
      ${seenChip}
      <span class="cat-chev ${open ? 'open' : ''}">${ICONS.chevronDown}</span>
    </button>
    ${steps}
  </div>`;
}

function recentClientsHTML(): string {
  const clients = recentClients();
  if (!clients.length) return '';
  const rows = clients.map((client) => `<div class="connect-recent-row">
      <code>${esc(client.name)}</code><span class="grow"></span>
      <span class="s-sub">${relTime(client.at)}</span>
    </div>`).join('');
  return `<div class="connect-sec-lbl">Recently seen</div>
    <div class="agent-block"><div class="connect-recent">${rows}</div>
    <div class="connect-keynote">Names are labels agents report about themselves for the
      activity log — they aren’t identities, and access doesn’t depend on them.</div></div>`;
}

function connectGuidesHTML(): string {
  const identity = state.identity;
  if (!identity) return '';
  const env = connectClientEnv();
  const guides = CONNECT_CLIENTS.map((client) => connectCardHTML(client, env)).join('');
  return `${connectKeyCardHTML(identity)}
    <div class="connect-sec-lbl">Connect an agent</div>
    ${guides}
    ${recentClientsHTML()}`;
}
const liveCount = (c: ConnectionSummary): number =>
  state.sessions.filter((s) => s.connection === c.name).length;
const connTestResultHTML = (c: ConnectionSummary): string => {
  const test = state.connTests[c.id];
  if (!test) return '';
  if (test.running) return '<div class="cc-test running">Testing…</div>';
  // Failures are health, not feedback: they render through the row's
  // issue list (connectionIssues), never as a line under a green verdict.
  if (test.detail === undefined || !test.ok) return '';
  return `<div class="cc-test ok">${ICONS.circleCheck}<span>${esc(test.detail)}</span></div>`;
};


/** The coarse kind a connection belongs to. Drives the muted per-kind
 * icon tint so a mixed list sorts itself visually without being
 * grouped. */
type ConnKind = 'mcp' | 'db' | 'ssh' | 'ws' | 'api';

function connectionKind(c: ConnectionSummary): ConnKind {
  if (c.type === 'pg') return 'db';
  if (c.type === 'ssh') return 'ssh';
  if (c.type === 'ws') return 'ws';
  return c.mcp_path ? 'mcp' : 'api';
}



/** The credential the broker injects; never its value. */
function connectionCredential(c: ConnectionSummary): string | null {
  // Inside the connected block, connectedness is the precondition — the
  // chip names the mechanism, it doesn't re-announce the state.
  if (c.oauth || c.oauth_spec) return 'OAuth';
  const names = c.secret_names || [];
  if (!names.length) return null;
  return names.join(' + ');
}

// One row inside an expanded catalog entry. It spans the full card width and
// carries enough to identify the connection without opening it: who is signed
// in (accounts differ between connections; the server rarely does), where it
// points, which tools agents get, and which credential the broker injects.
/** Everything wrong with a connection, folded into the one list the
 * health indicator owns. TLS weaker than the default, an unpinned host
 * key, a passively recorded rejected credential (brokered calls and
 * background token renewals set needs_reconnect without anyone pressing
 * Test), and the most recent failed test or MCP check each become one
 * line in the expansion, with the fix action beside it. One verdict per
 * row: a failed check moves the indicator, it never sits beside a green
 * one. */
function connectionIssues(c: ConnectionSummary): Array<{ text: string; fix?: string }> {
  const issues: Array<{ text: string; fix?: string }> = [];
  if (c.type === 'pg' && c.sslmode && c.sslmode !== 'verify-full' && !isLoopbackHost(c.host)) {
    issues.push({
      text: c.sslmode === 'disable'
        ? 'TLS is disabled for this connection.'
        : `TLS is relaxed to ${c.sslmode}.`,
      fix: `<button class="btn ghost sm cat-meta-fix" data-act="edit-conn" data-id="${c.id}">Edit…</button>`,
    });
  }
  if (c.type === 'ssh' && !c.host_key_fingerprint) {
    issues.push({ text: 'Host key not pinned yet — pins on the first connection.' });
  }
  if (c.last_status === 'needs_reconnect') {
    issues.push({
      text: c.last_detail || 'The credential was rejected; reconnect to refresh it.',
      fix: c.mcp_path
        ? `<button class="btn ghost sm cat-meta-fix" data-act="reconnect-mcp" data-id="${c.id}">Reconnect…</button>`
        : c.oauth_spec
        ? `<button class="btn ghost sm cat-meta-fix" data-act="oauth-reconnect" data-id="${c.id}">Reconnect…</button>`
        : `<button class="btn ghost sm cat-meta-fix" data-act="test-conn" data-id="${c.id}">Test again</button>`,
    });
  }
  const test = state.connTests[c.id];
  if (test && !test.running && test.detail !== undefined && !test.ok
      && test.detail !== c.last_detail) {
    issues.push({
      text: test.detail,
      fix: `<button class="btn ghost sm cat-meta-fix" data-act="test-conn" data-id="${c.id}">Test again</button>`,
    });
  }
  const mcpStatus = c.mcp_path ? state.mcpStatus[c.id] : undefined;
  if (mcpStatus && !mcpStatus.running) {
    const detail = mcpStatus.error
      ?? (mcpStatus.report && !mcpStatus.report.ok ? mcpStatus.report.detail : null);
    if (detail && detail !== c.last_detail) {
      issues.push({
        text: detail,
        fix: `<button class="btn ghost sm cat-meta-fix" data-act="mcp-status" data-id="${c.id}">Check again</button>`,
      });
    }
  }
  return issues;
}

/** Account-first display title: the signed-in identity is what tells two
 * connections to the same server apart. A parenthetical that just
 * restates the target ("Postgres (dev@localhost:5433)") drops away — the
 * target is printed beside it anyway. The full name stays on hover. */
function connectionTitle(c: ConnectionSummary): string {
  const paren = /^(.*\S)\s*\((.+)\)$/.exec(c.name);
  return c.mcp_path && c.account
    ? c.account
    : paren && c.target.includes(paren[2])
    ? paren[1]
    : c.name;
}

/** The per-server tool filter chip an enabled MCP connection carries. */
function connectionToolsChipHTML(c: ConnectionSummary): string {
  if (!c.agent_access.enabled || !c.mcp_path) return '';
  return `<button class="cat-meta-tools" data-act="wiring-tools" data-conn="${c.id}"
      aria-label="Choose which tools agents may call on ${escAttr(c.name)}"
      title="Choose which of this server’s tools agents may call">${ICONS.filter}<span>${
        c.agent_access.allowed_tools
          ? `${c.agent_access.allowed_tools.length} tool${c.agent_access.allowed_tools.length === 1 ? '' : 's'}`
          : 'All tools'}</span></button>`;
}

// The always-visible strip under a connected row: just the direct
// endpoint and the row's one options menu. Everything identifying lives
// on the row above; issues and test results render as lines beneath.
function connPanelHTML(c: ConnectionSummary): string {
  const test = state.connTests[c.id];
  const menuOpen = state.connMenuOpen === c.id;
  const enabled = c.agent_access.enabled;
  const mcpStatus = c.mcp_path ? state.mcpStatus[c.id] : undefined;
  const running = c.mcp_path
    ? Boolean(mcpStatus && mcpStatus.running)
    : Boolean(test && test.running);
  // One name and one icon for the one action, whatever the protocol —
  // MCP rows still run the server & account check underneath.
  const connectionCheckItem = `<button class="menu-item" role="menuitem"
      data-act="${c.mcp_path ? 'mcp-status' : 'test-conn'}" data-id="${c.id}"
      ${running ? 'disabled' : ''}>${ICONS.flaskConical} ${running ? 'Testing…' : 'Test connection'}</button>`;
  const endpointItems = enabled && c.agent_access.endpoint
    ? `<button class="menu-item" role="menuitem" data-act="reissue-endpoint-ask" data-conn="${c.id}">${ICONS.refresh} Reissue endpoint…</button>
        <button class="menu-item danger" role="menuitem" data-act="revoke-endpoint-ask" data-conn="${c.id}">${ICONS.x} Revoke endpoint…</button>`
    : '';
  const issues = connectionIssues(c);
  const issuesBlock = enabled && issues.length
    ? `<div class="cc-issues">${issues.map((issue) =>
        `<div class="cc-issue"><span>${esc(issue.text)}</span>${issue.fix ?? ''}</div>`).join('')}</div>`
    : '';
  return `<div class="conn-panel">
    <div class="conn-panel-main">
      ${endpointStripHTML(c)}
      <span class="grow"></span>
      <div class="tile-menu-wrap">
        <button class="icon-btn tile-menu-btn ${menuOpen ? 'on' : ''}" title="Tool options"
          aria-label="Options for ${escAttr(c.name)}" aria-haspopup="menu"
          aria-expanded="${menuOpen}" data-act="toggle-conn-menu" data-id="${c.id}">${ICONS.ellipsis}</button>
        ${menuOpen ? `<div class="tile-menu" role="menu" aria-label="Options for ${escAttr(c.name)}">
          ${connectionCheckItem}
          ${endpointItems}
        </div>` : ''}
      </div>
    </div>
    ${issuesBlock}${connTestResultHTML(c)}${mcpStatusHTML(c)}
  </div>`;
}

// The status check's result, rendered under the MCP connection it belongs
// to — reachability and account first, then the server's resources the
// same way credentials and wirings are listed.
function mcpStatusHTML(c: ConnectionSummary): string {
  if (!c.mcp_path) return '';
  const status = state.mcpStatus[c.id];
  if (!status) return '';
  if (status.running) return '<div class="cc-test running">Checking the server…</div>';
  // Errors and failed reports surface through the row's issue list
  // (connectionIssues); only a healthy report renders here.
  if (status.error) return '';
  const report = status.report;
  if (!report || !report.ok) return '';
  const head = `<div class="cc-test ok">${ICONS.circleCheck}<span>${esc(report.detail)}</span></div>`;
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
  return `${head}${resources}`;
}

// The built-in credentials store, expanded inline: the same secrets table
// the standalone tab used to own.
function credentialsExpansionHTML(): string {
  const query = state.tab === 'secrets' ? state.secretSearch : '';
  const matching = state.secrets.filter((secret) => !query.trim()
    || secret.name.toLowerCase().includes(query.trim().toLowerCase())
    || secret.used_by_names.some((name) => name.toLowerCase().includes(query.trim().toLowerCase())));
  const body = matching.length
    ? secretsTableHTML(query)
    : `<div class="muted-note">${state.secrets.length ? 'No saved credentials match your search.' : 'No saved credentials yet.'}</div>`;
  return `<div class="cat-conns credentials-expansion">${body}
    <button class="cat-more cat-add-secret" data-act="open-add-secret">＋ Add credential</button></div>`;
}

// One catalog row: icon chip, name, one-line description, and a trailing
// action — Add for addable tools, a dimmed "Soon" chip for MCP-backed ones,
// or a count badge that expands the row into what is configured.
// `forceAdd` renders a connected generic row as still-addable: its
// connections already live in the flat list above, so the catalog offers
// only the add action instead of a second representation of them.
function catalogRowHTML(entry: CatalogEntry, forceAdd = false): string {
  // A grayed-out placeholder: visible, not yet addable.
  if (entry.disabled) {
    return `<div class="cat-row-wrap is-soon">
      <div class="cat-row">
        <span class="cat-ico" aria-hidden="true">${ICONS[entry.icon] || ''}</span>
        <div class="cat-tx"><b>${esc(entry.name)}</b><span>${esc(entry.description)}</span></div>
        <span class="cat-soon" title="Not available yet">Soon</span>
      </div></div>`;
  }
  const builtin = entry.via === 'builtin';
  const count = builtin
    ? state.secrets.length
    : forceAdd ? 0 : connectionsForEntry(entry, state.connections).length;
  // The credentials store renders fully expanded, always — its table is
  // the content of the Secrets tab, not a disclosure.
  const open = builtin || (count > 0 && state.toolsOpen.includes(entry.id));
  const quickConnect = canQuickConnectMcp(entry);
  const actionMenuOpen = state.catalogActionMenuOpen === entry.id;
  const label = builtin
    ? `${count} saved credential${count === 1 ? '' : 's'}`
    : `${count} configured connection${count === 1 ? '' : 's'}`;
  // Call out rows that need provider-side setup; generic MCP and HTTP rows
  // still use Configure because the user supplies their endpoint.
  const addLabel = entry.requiresSetup
    ? 'Setup'
    : ['mcp', 'http'].includes(entry.id)
    ? 'Configure'
    : entry.preset
    ? 'Configure'
    : entry.mcp && !entry.mcpTemplate?.serverUrl
    ? 'Add custom app'
    : entry.mcp
    ? 'Connect now'
    : 'Add';
  const quickConnectAction = `<div class="cat-connect-wrap ${actionMenuOpen ? 'open' : ''}">
      <div class="cat-connect-buttons">
        <button class="btn cat-add cat-connect-primary" data-act="catalog-connect-oauth"
          data-id="${entry.id}">Connect</button>
        <button class="btn cat-add cat-connect-menu-btn" data-act="toggle-catalog-connect-menu"
          data-id="${entry.id}" title="More ways to connect ${escAttr(entry.name)}"
          aria-label="More ways to connect ${escAttr(entry.name)}" aria-haspopup="menu"
          aria-expanded="${actionMenuOpen}">${ICONS.chevronDown}</button>
      </div>
      ${actionMenuOpen ? `<div class="cat-connect-menu" role="menu" aria-label="Connect ${escAttr(entry.name)}">
        <button class="menu-item" role="menuitem" data-act="catalog-connect-oauth" data-id="${entry.id}">Connect</button>
        <button class="menu-item" role="menuitem" data-act="catalog-connect-manual" data-id="${entry.id}">Connect via custom URL</button>
        ${entry.preset ? `<button class="menu-item" role="menuitem" data-act="catalog-connect-api" data-id="${entry.id}">Connect custom API</button>` : ''}
      </div>` : ''}
    </div>`;
  // Connected rows split like the quick-connect control: the count half
  // toggles the row open, the chevron half opens the add-another menu.
  // Quick-connect rows keep both connect paths in that menu.
  const connectedMenuItems = quickConnect
    ? `<button class="menu-item" role="menuitem" data-act="catalog-connect-oauth" data-id="${entry.id}">Add another connection</button>
        <button class="menu-item" role="menuitem" data-act="catalog-connect-manual" data-id="${entry.id}">Add another connection (custom)</button>`
    : `<button class="menu-item" role="menuitem" data-act="catalog-add" data-id="${entry.id}">Add another connection</button>`;
  const connectedAction = `<div class="cat-connect-wrap ${actionMenuOpen ? 'open' : ''}">
      <div class="cat-connect-buttons">
        <button class="cat-count cat-connect-primary ${open ? 'on' : ''}" data-act="catalog-toggle"
          data-id="${entry.id}" aria-expanded="${open}" aria-label="${escAttr(label)}"
          title="${escAttr(label)}">${count}</button>
        <button class="cat-count cat-connect-menu-btn" data-act="toggle-catalog-connect-menu"
          data-id="${entry.id}" title="Add another ${escAttr(entry.name)} connection"
          aria-label="Add another ${escAttr(entry.name)} connection" aria-haspopup="menu"
          aria-expanded="${actionMenuOpen}">${ICONS.chevronDown}</button>
      </div>
      ${actionMenuOpen ? `<div class="cat-connect-menu" role="menu" aria-label="Add another ${escAttr(entry.name)} connection">${connectedMenuItems}</div>` : ''}
    </div>`;
  const action = builtin
    ? `<span class="cat-count is-static" title="${escAttr(label)}">${ICONS.fileKey} ${count}</span>`
    : count
    ? connectedAction
    : quickConnect
    ? quickConnectAction
    : entry.via === 'connection'
    ? `<button class="btn cat-add" data-act="catalog-add" data-id="${entry.id}">${addLabel}</button>`
    : `<span class="cat-soon" title="Arrives with the MCP layer">Soon</span>`;
  // Only the credentials store expands here: connected tools live in the
  // flat list above the catalog, never inside catalog rows.
  const expansion = open && builtin ? credentialsExpansionHTML() : '';
  const rowToggle = count && !builtin
    ? ` data-act="catalog-toggle" data-id="${entry.id}"`
    : '';
  return `<div class="cat-row-wrap ${open ? 'open' : ''} ${actionMenuOpen ? 'menu-open' : ''}">
    <div class="cat-row ${rowToggle ? 'is-toggle' : ''} ${count ? 'is-configured' : ''}"${rowToggle}>
      <span class="cat-ico" aria-hidden="true">${ICONS[entry.icon] || ''}</span>
      <div class="cat-tx"><b>${esc(entry.name)}</b><span>${esc(entry.description)}</span></div>
      ${entry.limitedSupport ? `<span class="cat-limited" tabindex="0" data-tippy-content="${escAttr(entry.name)} only accepts OAuth sign-ins from pre-approved clients. Use the API connector, or contact your representative at the company for support.">Limited support</span>` : ''}
      ${action}
    </div>${expansion}</div>`;
}

/* ---- flat tools list (steady state) ----------------------------------- */
// The Tools tab's steady state answers one question: what can agents
// reach right now, and is it healthy? One row per connection; the whole
// catalog waits behind "+ Add tool". Anything wrong is one banner above
// the list — never red text inside it.

/** Flat rows are named after the tool, not the signed-in account — the
 * account is a detail fact. (connectionTitle keeps account-first naming
 * for sibling rows inside the add view's groups, where it's what tells
 * two connections to the same server apart.) */
function connectionRowName(c: ConnectionSummary): string {
  const paren = /^(.*\S)\s*\((.+)\)$/.exec(c.name);
  return paren && c.target.includes(paren[2]) ? paren[1] : c.name;
}

/** The row's second line: destination, then the credential the broker
 * injects (never its value). */
function connectionSublineHTML(c: ConnectionSummary): string {
  const credential = connectionCredential(c);
  const filter = connectionToolsChipHTML(c);
  const key = credential
    ? `<span class="flat-cred" tabindex="0" data-tippy-content="Using ${escAttr(
        credential === 'OAuth' ? 'OAuth sign-in' : credential)}">${ICONS.keyRound}</span>`
    : '';
  return `<span class="flat-dest" title="${escAttr(c.target)}">${esc(c.target)}</span>${
    filter ? ` · ${filter}` : ''}${key ? ` · ${key}` : ''}`;
}

/** The flat row's health glyph. Not a control: the row itself opens the
 * detail, which is where issues are read and fixed. */
function flatHealthHTML(c: ConnectionSummary): string {
  if (!c.agent_access.enabled) {
    return '<span class="cc-dot off" role="img" title="Off" aria-label="Off — agents may not use this tool"></span>';
  }
  const issues = connectionIssues(c);
  if (!issues.length) return '<span class="cc-dot ok" role="img" title="Ready" aria-label="Ready"></span>';
  return `<span class="cc-health attn" title="${escAttr(issues.map((issue) => issue.text).join(' '))}">
      <span class="cc-dot warn"></span><span>${issues.length} issue${issues.length === 1 ? '' : 's'}</span></span>`;
}

function attentionBannerHTML(): string {
  const attn = state.connections.filter(
    (c) => c.agent_access.enabled && connectionIssues(c).length,
  );
  if (!attn.length) return '';
  const first = attn[0];
  const firstIssue = connectionIssues(first)[0];
  const more = attn.length > 1 ? ` · +${attn.length - 1} more` : '';
  return `<div class="attn-banner">${ICONS.triangleAlert}
    <span><b>${attn.length === 1 ? '1 tool needs' : `${attn.length} tools need`} attention</b>
      — ${esc(connectionTitle(first))}: ${esc(firstIssue.text)}${more}</span></div>`;
}

function flatConnRowHTML(c: ConnectionSummary): string {
  const kind = connectionKind(c);
  const live = liveCount(c);
  const entry = entryForConnection(c);
  return `<div class="flat-conn-wrap">
    <div class="flat-conn-row">
      <span class="cat-ico kind-${kind}" aria-hidden="true">${entry ? ICONS[entry.icon] || '' : ''}</span>
      <div class="flat-tx"><b title="${escAttr(c.name)}">${esc(connectionRowName(c))}</b>
        <span>${connectionSublineHTML(c)}</span></div>
      ${live ? `<span class="cc-live">● ${live} live</span>` : ''}
      <div class="cat-conn-status">${flatHealthHTML(c)}</div>
      ${connToggleHTML(c)}
      <button class="icon-btn conn-edit-btn" title="Edit ${escAttr(connectionRowName(c))}"
        aria-label="Edit ${escAttr(c.name)}" data-act="edit-conn" data-id="${c.id}">${ICONS.squarePen}</button>
    </div>${connPanelHTML(c)}</div>`;
}


/** Whether a draft is being edited as an MCP server rather than a raw API. */
function isMcpDraft(draft: { isMcp?: boolean; mcpPath?: string | null }): boolean {
  return Boolean(draft.isMcp || draft.mcpPath);
}

// Sections that collapse to their connected/minimum rows behind a "More
// tools" disclosure. API Apps holds few rows today but is expected
// to grow, so it collapses the same way as the larger sections.
const COLLAPSIBLE_SECTIONS: string[] = ['MCP Apps', 'API Apps'];

function connectionsHTML() {
  const ready = state.connectionReady;
  const readyPrompt = ready ? firstTaskPrompt(ready.name, ready.type) : '';
  const readyCard = ready ? `<div class="connection-ready">
    <div class="connection-ready-copy"><b>${esc(ready.name)} is ready</b>
      <span>Ask your agent:</span><code>${esc(readyPrompt)}</code></div>
    <div class="connection-ready-actions">
      <button class="btn sm" data-act="copy-first-task">${state.connectionTaskCopied ? `${ICONS.check} Copied` : 'Copy task'}</button>
      <button class="icon-btn" title="Dismiss" aria-label="Dismiss tool ready message" data-act="dismiss-connection-ready">${ICONS.circleX}</button>
    </div></div>` : '';
  // One view, no navigation: the connected tools stay at the top as flat
  // rows, and an "Add a tool" row at the bottom of the list expands the
  // catalog of everything not yet connected, in place, beneath it.
  const entries = visibleCatalog(state.toolSearch, {
    showWebsockets: state.settings.show_websockets,
    connections: state.connections,
  });
  const isConnected = (entry: CatalogEntry): boolean =>
    connectionsForEntry(entry, state.connections).length > 0;
  const needle = state.toolSearch.trim().toLowerCase();
  const matching = state.connections.filter((c) => !needle
    || c.name.toLowerCase().includes(needle)
    || c.target.toLowerCase().includes(needle)
    || (c.account || '').toLowerCase().includes(needle));
  const connectedList = state.connections.length
    ? `<div class="cat-section"><div class="cat-section-h">TOOLS</div>
      <div class="cat-rows">${matching.length
        ? matching.map(flatConnRowHTML).join('')
        : '<div class="muted-note">No tools match your search.</div>'}</div></div>`
    : '';
  // With nothing connected, adding is the only thing to do — the catalog
  // starts open.
  const addOpen = state.addToolOpen || !state.connections.length;
  const addRow = `<div class="cat-section"><div class="cat-rows">
      <div class="cat-row is-toggle add-tools-row" role="button" tabindex="0"
        data-act="toggle-add-tools" aria-expanded="${addOpen}"
        aria-label="${addOpen ? 'Hide' : 'Show'} tools that can be added">
        <span class="cat-ico" aria-hidden="true">${ICONS.plus}</span>
        <div class="cat-tx"><b>Add a tool</b></div>
        <span class="cat-chev group-chev ${addOpen ? 'open' : ''}" aria-hidden="true">${ICONS.chevronDown}</span>
      </div></div></div>`;
  // Generic rows are tool types, not accounts: they stay addable even
  // while connected, or there would be no way to add a second database.
  const alwaysAddable = (entry: CatalogEntry): boolean =>
    entry.section === 'Infrastructure' || ['http', 'mcp'].includes(entry.id);
  // Infrastructure leads; every other section (Secrets aside) follows as
  // its own group, offering what isn't connected yet plus the generics.
  const ADD_SECTIONS = [
    'Infrastructure',
    ...CATALOG_SECTIONS.filter((section) => section !== 'Infrastructure' && section !== 'Secrets'),
  ];
  const sections = !addOpen ? '' : ADD_SECTIONS.map((section) => {
    const sectionEntries = entries.filter(
      (entry) => entry.section === section
        && (!isConnected(entry) || alwaysAddable(entry)),
    );
    if (!sectionEntries.length) return '';
    const ordered = connectedCatalogFirst(sectionEntries, state.connections);
    const collapsible = COLLAPSIBLE_SECTIONS.includes(section) && !state.toolSearch.trim();
    const expanded = state.sectionsExpanded.includes(section);
    const collapsed = collapsible
      ? collapsedCatalogGroup(sectionEntries, state.connections)
      : { visible: ordered, hiddenCount: 0 };
    const rows = collapsible && !expanded ? collapsed.visible : ordered;
    const disclosure = collapsible && collapsed.hiddenCount > 0
      ? `<button class="cat-more" data-act="toggle-section-expanded" data-id="${escAttr(section)}"
          aria-expanded="${expanded}">
          <span>${expanded ? 'Show fewer tools' : 'Show more tools'}</span>
          <span class="cat-more-chev ${expanded ? 'open' : ''}" aria-hidden="true">${ICONS.chevronDown}</span>
        </button>`
      : '';
    return `<div class="cat-section add-section"><div class="cat-section-h">${section.toUpperCase()}</div>
      <div class="cat-rows">${rows.map((entry) => catalogRowHTML(entry, isConnected(entry))).join('')}${disclosure}</div></div>`;
  }).join('');
  const search = mode === 'dropdown'
    ? `<input id="tool-search" class="cat-search" type="search" placeholder="Search tools…"
        aria-label="Search tools" value="${escAttr(state.toolSearch)}">`
    : '';
  return readyCard + `<div class="catalog">${search}${attentionBannerHTML()}
    ${connectedList}${addRow}${addOpen && !sections ? '<div class="muted-note">No tools match your search.</div>' : sections}
  </div>`;
}

function secretsHTML(): string {
  const allEntries = visibleCatalog('', {
    showWebsockets: state.settings.show_websockets,
    connections: state.connections,
  }).filter((entry) => entry.section === 'Secrets');
  const needle = state.secretSearch.trim().toLowerCase();
  const entries = allEntries.filter((entry) => {
    const entryMatch = !needle
      || entry.name.toLowerCase().includes(needle)
      || entry.description.toLowerCase().includes(needle)
      || (entry.keywords || []).some((keyword) => keyword.toLowerCase().includes(needle));
    const savedSecretMatch = entry.id === 'credentials' && state.secrets.some((secret) =>
      secret.name.toLowerCase().includes(needle)
      || secret.used_by_names.some((name) => name.toLowerCase().includes(needle)));
    return entryMatch || savedSecretMatch;
  });
  const rows = connectedCatalogFirst(entries, state.connections);
  const search = mode === 'dropdown'
    ? `<input id="secret-search" class="cat-search" type="search" placeholder="Search secrets…"
        aria-label="Search secrets" value="${escAttr(state.secretSearch)}">`
    : '';
  const section = rows.length
    ? `<div class="cat-section"><div class="cat-section-h">SECRETS</div>
        <div class="cat-rows">${rows.map((entry) => catalogRowHTML(entry)).join('')}</div></div>`
    : '<div class="muted-note">No secrets match your search.</div>';
  return `<div class="catalog">${search}${section}
  </div>`;
}

// Console.app-style rows: a proportional timestamp gutter, restrained
// semantic Lucide icon, then plain primary text with optional detail.
function activityRowHTML(a: ActivityEntry): string {
  const icon = ICONS[a.icon] || '';
  // Attribution and timing stay under the message. The tool gets its own
  // right-side column so it can be scanned independently across rows.
  const chips = [
    a.agent ? `<span class="act-chip" title="Agent">${esc(a.agent)}</span>` : '',
    typeof a.duration_ms === 'number'
      ? `<span class="act-chip act-chip-time" title="Duration">${a.duration_ms} ms</span>` : '',
    // A hosted broker authorizes gated actions by manage-token possession;
    // mark those so the trail reads honestly next to Touch-ID-confirmed rows.
    a.confirmation === 'management_token'
      ? `<span class="act-chip act-chip-manage" title="Authorized by the management token">via manage token</span>` : '',
  ].join('');
  const tool = a.connection
    ? `<span class="act-chip act-tool" title="Tool: ${escAttr(a.connection)}">${esc(a.connection)}</span>`
    : '';
  return `<div class="act-row">
    <span class="act-gutter"><span class="act-time" data-tippy-content="${escAttr(absTime(a.at))}" data-tippy-theme="activity-time">${esc(relTime(a.at))}</span></span>
    <span class="act-ico tone-${escAttr(a.tone || 'neutral')}">${icon}</span>
    <span class="act-txt">${esc(a.text)}${a.detail ? `<div class="act-detail">${esc(a.detail)}</div>` : ''}${chips ? `<div class="act-chips">${chips}</div>` : ''}</span>
    ${tool}</div>`;
}

/** The activity entries the current filters keep. */
function filteredActivity(): ActivityEntry[] {
  const needle = state.activityQuery.trim().toLowerCase();
  return state.activity.filter((entry) => {
    if (state.activityIssuesOnly && entry.tone !== 'danger' && entry.tone !== 'warning') {
      return false;
    }
    if (state.activityAgent && entry.agent !== state.activityAgent) return false;
    if (!needle) return true;
    return entry.text.toLowerCase().includes(needle)
      || (entry.detail || '').toLowerCase().includes(needle)
      || (entry.agent || '').toLowerCase().includes(needle)
      || (entry.connection || '').toLowerCase().includes(needle);
  });
}

function activityHTML() {
  if (!state.activity.length) {
    return `<div class="muted-note">No activity yet.${mode === 'dropdown' ? '' : '<br>Requests and broker actions will appear here.'}</div>`;
  }
  // Agents seen in the loaded window; chips beat a dropdown at this scale.
  const agents = [...new Set(state.activity.map((entry) => entry.agent).filter(Boolean))] as string[];
  const chip = (label: string, act: string, on: boolean, value = ''): string =>
    `<button class="seg-btn act-filter ${on ? 'on' : ''}" data-act="${act}"
      ${value ? `data-value="${escAttr(value)}"` : ''}>${esc(label)}</button>`;
  const filterBar = `<div class="act-filters">
    <input id="activity-search" class="cat-search act-search" type="search"
      placeholder="Filter activity…" aria-label="Filter activity"
      value="${escAttr(state.activityQuery)}">
    ${chip('Issues', 'act-filter-issues', state.activityIssuesOnly)}
    ${agents.map((agent) =>
      chip(agent, 'act-filter-agent', state.activityAgent === agent, agent)).join('')}
  </div>`;
  const entries = filteredActivity().slice(0, ACTIVITY_RENDER_LIMIT);
  const list = entries.length
    ? '<div class="act-list">' + entries.map(activityRowHTML).join('') + '</div>'
    : '<div class="muted-note">Nothing matches these filters.</div>';
  return filterBar + list;
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
  // With filters active the cheap prepend would bypass them; re-render.
  if (state.activityQuery || state.activityAgent || state.activityIssuesOnly) {
    render();
    return;
  }
  const list = document.querySelector('.act-list');
  if (!list) {
    render();
    return;
  }
  list.insertAdjacentHTML('afterbegin', activityRowHTML(entry));
  while (list.children.length > ACTIVITY_RENDER_LIMIT) list.lastElementChild?.remove();
}

/** The right-aligned status on a step-2 pane. One vocabulary for every mode:
 * "Connected · <when>" once the broker has seen a call, "Waiting for first
 * call" before that, and "No endpoint yet" for a direct pane pre-issue. */
function startModeStatusHTML(mode: ConnectModeId, conn: ConnectionSummary | null): string {
  const idle = (text: string) =>
    `<span class="start-status idle"><span class="start-status-dot"></span>${text}</span>`;
  let seenAt: string | undefined;
  if (mode === 'direct') {
    if (!conn?.agent_access.endpoint) return idle('No endpoint yet');
    seenAt = state.activity.find(
      (entry) => entry.agent === 'endpoint' && entry.connection === conn.name)?.at;
  } else {
    // Each client claims its own activity labels; self-named clients (Other
    // MCP client, HTTP API harnesses) match any label no branded client claims.
    const client = connectClientById(mode);
    seenAt = client
      ? recentClients().find((recent) => clientMatchesLabel(client, recent.name))?.at
      : undefined;
  }
  return seenAt
    ? `<span class="start-status"><span class="start-status-dot"></span>Connected · ${esc(relTime(seenAt))}</span>`
    : idle('Waiting for first call');
}

/** Step 2's pane for one connect mode: a one-line lead, the snippet, and an
 * actions row with the status pinned right. */
function startConnectPaneHTML(mode: ConnectModeId, option: StartOption, progress: StartProgress): string {
  const conn = progress.toolName
    ? state.connections.find((candidate) => candidate.name === progress.toolName) ?? null
    : null;
  const status = startModeStatusHTML(mode, conn);
  const snip = (text: string) => `<pre class="setup-instructions"><code>${esc(text)}</code></pre>`;
  const copyBtn = (text: string, label: string) =>
    `<button class="btn primary sm" data-act="copy-text" data-text="${escAttr(text)}">${label}</button>`;
  const actions = (inner: string) => `<div class="start-actions">${inner}${status}</div>`;

  switch (mode) {
    case 'direct': {
      if (!conn) {
        return `<p>Direct endpoints are issued per tool — add the ${esc(option.label)} tool above first.</p>
          ${actions('<button class="btn primary sm" disabled>Issue direct endpoint</button>')}`;
      }
      const endpoint = conn.agent_access.endpoint ?? null;
      const lead = endpoint
        ? `A direct endpoint is issued for “${esc(conn.name)}”. ${conn.type === 'pg'
            ? 'Copy its address (secret included) from the tool’s row anytime — reissue to rotate the secret.'
            : 'Its socket path was shown at issue — reissue to get a new one.'}`
        : conn.type === 'pg'
        ? `Issue a local DSN for “${esc(conn.name)}” that any unmodified Postgres client can use —
            psql, drivers, ORMs.`
        : `Issue a signing-agent socket for “${esc(conn.name)}”. Plain ssh, git, and rsync work
            unmodified; the private key never leaves this machine.`;
      const label = !endpoint ? 'Issue direct endpoint'
        : conn.type === 'pg' ? 'Reissue (new secret)' : 'Reissue';
      return `<p>${lead}</p>
        ${actions(`<button class="btn primary sm" data-act="issue-endpoint" data-conn="${conn.id}">${label}</button>`)}`;
    }
  }

  // Every other mode renders straight from its shared client definition.
  const client = connectClientById(mode);
  if (!client) return '';
  const env = connectClientEnv();
  if (client.paneSource === 'agent-setup') {
    return `<p>${esc(client.lead(env))}</p>
      <pre class="setup-instructions"><code>${esc(state.agentSetupInstructions || 'Loading…')}</code></pre>
      ${actions(`<button class="btn primary sm" data-act="copy-agent-setup">${client.copyLabel}</button>`)}`;
  }
  const snippet = client.snippet(env);
  return `<p>${esc(client.lead(env))}</p>
    ${snip(snippet)}${actions(copyBtn(snippet, client.copyLabel))}`;
}

// The centered walkthrough/guides switch at the top of the Get started tab.
function startViewToggleHTML(): string {
  const btn = (view: StartView, label: string) =>
    `<button class="seg-btn ${state.startView === view ? 'on' : ''}"
      aria-pressed="${state.startView === view}" data-act="start-view" data-id="${view}">${label}</button>`;
  return `<div class="start-view-toggle"><div class="seg" role="group" aria-label="Get started view">
    ${btn('walkthrough', 'Quick start')}${btn('guides', 'Connection guides')}</div></div>`;
}

function startHTML(): string {
  const body = state.startView === 'guides'
    ? connectGuidesHTML()
    : startWalkthroughHTML();
  return `<div class="start">${startViewToggleHTML()}${body}</div>`;
}

function startWalkthroughHTML(): string {
  const option = startOptionById(state.startOption);
  const catalogEntry = option.catalogId ? catalogEntryById(option.catalogId) : undefined;
  const agentConnected = state.activity.some((entry) => entry.text.startsWith('Agent connected'));
  const progress = startProgress(option, state.connections, agentConnected);

  const picker = START_OPTIONS.map((candidate) => {
    const visibleLabel = candidate.showPickerLabel
      ? `<span class="start-pick-label">${esc(candidate.label)}</span>` : '';
    return `<button class="start-pick ${candidate.showPickerLabel ? 'has-label' : ''} ${candidate.id === option.id ? 'on' : ''}"
      aria-pressed="${candidate.id === option.id}"
      aria-label="${escAttr(candidate.label)}" title="${escAttr(candidate.label)}"
      data-act="start-option" data-id="${candidate.id}">
      <span class="start-pick-icon" aria-hidden="true">${ICONS[candidate.icon] || ''}</span>${visibleLabel}</button>`;
  }).join('');

  const step = (n: number, title: string, done: boolean, body: string): string =>
    `<li class="start-step ${done ? 'done' : ''}">
      <span class="start-num" aria-hidden="true">${n}</span>
      <div class="start-body"><b>${esc(title)}</b>${body}</div></li>`;

  const addAction = catalogEntry && canQuickConnectMcp(catalogEntry)
    ? 'catalog-connect-oauth' : 'catalog-add';
  const addLabel = progress.added ? `${option.label} Connected` : `Add ${option.label}`;
  const addBody = `<p>Save the destination and its credential. The credential goes to your Keychain;
        agents can use it but never read it.</p>
      <div class="start-picker" role="group" aria-label="What to connect">${picker}</div>
      <div class="start-actions">
        <button class="btn primary sm" data-act="${addAction}" data-id="${option.catalogId}"
          ${progress.added ? 'disabled' : ''}>${esc(addLabel)}</button>
      </div>`;

  const connectMode = resolveConnectMode(state.connectMode, option);
  const modePicker = connectModesFor(option).map((candidate) =>
    `<button class="start-pick has-label ${candidate === connectMode ? 'on' : ''}"
      aria-pressed="${candidate === connectMode}" data-act="start-mode" data-id="${candidate}">
      <span class="start-pick-label">${esc(CONNECT_MODE_LABELS[candidate])}</span></button>`).join('');
  const connectBody = `
    <div class="start-picker" role="group" aria-label="How your agent connects">${modePicker}</div>
    ${startConnectPaneHTML(connectMode, option, progress)}`;

  const task = startTask(option, progress);
  const wireBody = `<p>Tools are enabled for all agents when you add them.</p>
    <pre class="setup-instructions"><code>${esc(task)}</code></pre>
    <div class="start-actions">
      <button class="btn primary sm" data-act="copy-text" data-text="${escAttr(task)}">Copy this task</button>
      <button class="btn ghost sm" data-act="open-connect-guides">Open connection guides</button>
    </div>`;

  return `<div class="start-hero">
      <h3>Connect your agent to everything</h3>
      <p class="start-promise">${esc(START_PROMISE)}</p>
    </div>
    <ol class="start-steps">
      ${step(1, option.connType ? `Add the ${option.label} tool` : `Add an ${option.label}`, progress.added, addBody)}
      ${step(2, 'Connect your agent', progress.connected, connectBody)}
      ${step(3, 'Ask for something useful', progress.wired, wireBody)}
    </ol>`;
}

function tabContentHTML() {
  return state.tab === 'start' ? startHTML()
    : state.tab === 'connections' ? connectionsHTML()
    : state.tab === 'secrets' ? secretsHTML()
    : activityHTML();
}

function brokerReadyHTML() {
  const copied = state.readyCopied;
  // The badge tracks the *managed* broker: a remote link that is down must
  // not sit under a green "Ready".
  const tone = brokerTone(state.broker);
  const label = tone === 'error' ? 'Unreachable' : tone === 'pending' ? 'Connecting…' : 'Ready';
  return `<button class="dd-sub ready-copy ${copied ? 'is-copied' : ''}"
    data-act="copy-ready-setup" title="${copied ? 'Setup instructions copied' : 'Copy setup instructions'}"
    aria-label="Copy setup instructions"><span class="dot dot-${tone}"></span>
    <span class="ready-copy-label" aria-live="polite">${copied ? `${ICONS.check} Copied` : label}</span></button>`;
}

/* --------------------------- broker switcher ------------------------------ */

/** The header's custom local/remote dropdown (right-justified). */
function brokerSwitchHTML(): string {
  const tone = brokerTone(state.broker);
  const label = brokerLabel(state.broker);
  const menu = state.brokerMenuOpen
    ? `<div class="broker-menu" role="menu">
        <button class="menu-item" role="menuitem" data-act="broker-pick-local">
          <span class="broker-check">${state.broker.mode === 'local' ? '✓' : ''}</span> Local</button>
        <button class="menu-item" role="menuitem" data-act="broker-pick-remote">
          <span class="broker-check">${state.broker.mode === 'remote' ? '✓' : ''}</span> Connect hosted instance…</button>
      </div>`
    : '';
  return `<div class="broker-switch-wrap">
    <button class="broker-btn ${state.brokerMenuOpen ? 'on' : ''}" data-act="broker-menu"
      aria-haspopup="menu" aria-expanded="${state.brokerMenuOpen}" title="Which broker this app manages">
      <span class="broker-dot ${tone}"></span><span class="broker-label">${esc(label)}</span>
      <span class="broker-caret" aria-hidden="true">${ICONS.chevronDown}</span>
    </button>${menu}</div>`;
}

/** The full-content-pane takeover while a remote link is not usable. */
function brokerPaneHTML(): string {
  const kind = brokerTakeover(state.broker, state.remoteSetup.open);
  if (!kind) return '';
  if (kind === 'setup') {
    const setup = state.remoteSetup;
    const hasSaved = state.broker.has_saved_token
      && (setup.url.trim() === '' || setup.url.trim().replace(/\/+$/, '') === (state.broker.url ?? ''));
    const cancelBtn = state.broker.mode === 'remote' && !state.broker.connected
      ? `<button class="btn ghost" data-act="broker-pick-local">Use this Mac instead</button>`
      : `<button class="btn ghost" data-act="broker-setup-cancel">Cancel</button>`;
    return `<div class="broker-pane" role="form" aria-label="Connect to hosted Multitool">
      <div class="bp-icon">${ICONS.blocks}</div>
      <h2>Connect to hosted Multitool</h2>
      <p class="bp-lead">Connect to a remote Multitool server with a management token.</p>
      <div class="adv-collapse">
        <button type="button" class="adv-toggle" aria-expanded="${setup.advancedOpen}"
          data-act="toggle-remote-advanced">
          <span class="adv-toggle-icon" aria-hidden="true">${ICONS.chevronDown}</span>Advanced</button>
        ${setup.advancedOpen ? `<pre class="setup-instructions bp-setup-code"><code># To start a remote instance, run this behind a TLS proxy or tunnel:
aka serve --listen 0.0.0.0:4780
aka manage token</code></pre>` : ''}
      </div>
      <div class="f-row"><label for="rb-url">Hosted instance URL</label>
        <input id="rb-url" placeholder="https://multitool.aka.com" value="${escAttr(setup.url)}"
          autocomplete="off" spellcheck="false"></div>
      <div class="f-row"><label for="rb-token">Management token</label>
        <input id="rb-token" type="password" placeholder="${hasSaved ? 'Using the saved token (paste to replace)' : 'akamgr_…'}"
          value="${escAttr(setup.token)}" autocomplete="off"></div>
      ${setup.error ? `<div class="inline-error" role="alert">${esc(setup.error)}</div>` : ''}
      <div class="bp-actions">
        <button class="btn primary" data-act="broker-connect-submit" ${setup.busy ? 'disabled' : ''}>
          ${setup.busy ? 'Connecting…' : 'Connect'}</button>
        ${cancelBtn}
      </div>
    </div>`;
  }
  if (kind === 'connecting') {
    return `<div class="broker-pane" role="status">
      <span class="app-loading-spinner"></span>
      <h2>Connecting to the remote broker</h2>
      <p class="bp-lead"><code>${esc(state.broker.url ?? '')}</code></p>
      <div class="bp-actions">
        <button class="btn ghost" data-act="broker-pick-local">Use this Mac instead</button>
      </div>
    </div>`;
  }
  return `<div class="broker-pane broker-pane-error" role="alert">
    <div class="bp-icon bp-icon-error">${ICONS.circleX}</div>
    <h2>Can’t reach the remote broker</h2>
    <p class="bp-lead"><code>${esc(state.broker.url ?? '')}</code></p>
    ${state.broker.error ? `<p class="bp-detail">${esc(state.broker.error)}</p>` : ''}
    <div class="bp-actions">
      <button class="btn primary" data-act="broker-retry">Retry</button>
      <button class="btn" data-act="broker-edit">Edit connection…</button>
      <button class="btn ghost" data-act="broker-pick-local">Use this Mac</button>
    </div>
  </div>`;
}

function renderMainWindow() {
  const takeover = brokerPaneHTML();
  const navItem = (tab: Tab): string =>
    `<button class="nav-item ${state.tab === tab ? 'on' : ''}" data-act="tab" data-tab="${tab}"
      ${takeover ? 'disabled' : ''}>${tabLabel(tab)}</button>`;
  const nav = TABS.map(navItem).join('');
  // One view-specific action, always in the header row next to the title.
  const actionBtn = state.tab === 'connections'
    ? `<div class="dw-head-actions">
        <input id="tool-search" class="cat-search" type="search" placeholder="Search tools…"
          aria-label="Search tools" value="${escAttr(state.toolSearch)}"></div>`
    : state.tab === 'secrets'
    ? `<div class="dw-head-actions">
        <input id="secret-search" class="cat-search" type="search" placeholder="Search secrets…"
          aria-label="Search secrets" value="${escAttr(state.secretSearch)}"></div>`
    : state.tab === 'activity'
    ? `<button class="btn" data-act="clear-activity-ask" ${state.activity.length ? '' : 'disabled'}>Clear activity</button>`
    : '';
  const pageTitle = state.tab === 'connections' ? 'Manage tools'
    : state.tab === 'secrets' ? 'Manage secrets'
    : tabLabel(state.tab);
  const pageHead = state.tab === 'start' ? ''
    : `<div class="dw-head"><h2>${pageTitle}</h2>${actionBtn}</div>`;
  const menu = state.menuOpen
    ? `<div class="settings-menu">
        <button class="menu-item" data-act="mode-tray">${ICONS.menubar} Minimize to menu bar</button>
        <button class="menu-item" data-act="open-settings">${ICONS.gear} Settings</button>
      </div>` : '';
  root().innerHTML = `<div class="surface">
    <div class="dw-titlebar" data-tauri-drag-region>
      <span class="dw-title dw-title-center">Multitool</span>
      ${brokerSwitchHTML()}
    </div>
    <div class="dw-body">
      <div class="dw-side ${takeover ? 'disabled' : ''}">
        <div class="dw-brand"><div class="dd-appicon">${ICONS.blocks}</div>
          <div><div class="dd-title">Multitool</div>${brokerReadyHTML()}</div></div>
        <div class="dw-nav">${nav}</div>
        <div class="dw-settings">${takeover ? '' : menu}
          <button class="nav-item gear-btn ${state.menuOpen ? 'on' : ''}" data-act="toggle-settings-menu"
            title="Settings" aria-label="Settings" ${takeover ? 'disabled' : ''}>${ICONS.gear}</button>
        </div>
      </div>
      <div class="dw-main">
        ${takeover ? `<div class="content broker-takeover">${takeover}</div>` : `${pageHead}
        ${globalSectionsHTML()}
        <div class="content">${tabContentHTML()}</div>`}
      </div>
    </div></div>${takeover ? '' : sheetsHTML() + endpointConfirmHTML() + deleteConnConfirmHTML()}`;
}

function renderDropdown() {
  if (state.tab === 'start') state.tab = 'connections';
  const takeover = brokerPaneHTML();
  if (takeover) {
    root().innerHTML = `<div class="surface dropdown-surface">
      <div class="dd-head"><div class="dd-appicon">${ICONS.blocks}</div>
        <div class="dd-identity"><div class="dd-title">Multitool</div></div>
        <button class="icon-btn" title="Open as a window" aria-label="Open as a window" data-act="mode-window">${ICONS.expand}</button></div>
      <div class="content dd-content broker-takeover">${takeover}</div></div>`;
    return;
  }
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
    ${footer}</div>${sheetsHTML()}${endpointConfirmHTML()}${deleteConnConfirmHTML()}`;
}

/* --------------------------------- sheets -------------------------------- */
// Shown right after issuing a direct endpoint: the pasteable address (with
// the secret riding in it), a ready-to-run example, and the secret itself.
// The secret is retained on the endpoint, so the row's chip keeps carrying
// it — losing this sheet loses nothing. Copy buttons write to the
// clipboard; the text is also selectable as a fallback.
function endpointIssuedSheet(): string {
  const info = state.sheet?.endpoint;
  if (!info) return '';
  const addressLabel = info.type === 'ssh' ? 'Agent socket' : info.type === 'pg' ? 'DSN' : 'Base URL';
  const field = (label: string, value: string, fieldKey: string, note = ''): string =>
    `<div class="ep-field"><div class="ep-label">${label}${note ? ` <span class="ep-note">${note}</span>` : ''}</div>
      <div class="ep-row"><code class="ep-code">${esc(value)}</code>
      <button class="btn ghost sm" data-act="copy-endpoint" data-field="${fieldKey}" aria-label="Copy ${label}">Copy</button></div></div>`;
  const secretField = info.secret
    ? field('Secret', info.secret, 'secret')
    : '<div class="ep-note">SSH endpoints present no secret — the socket path is the whole capability.</div>';
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet" role="dialog" aria-modal="true" aria-labelledby="ep-title">
      <h3 id="ep-title">Direct endpoint issued</h3>
      <p class="sheet-sub">Paste this into your tool's config. You can copy it again anytime from the tool's row.</p>
      ${field(addressLabel, info.dsn, 'dsn')}
      ${secretField}
      ${field('Example', info.example, 'example')}
      ${remoteEndpointCaution(state.broker, info.type)
        ? `<div class="rule-note ep-remote-note">${esc(remoteEndpointCaution(state.broker, info.type) ?? '')}</div>`
        : ''}
      <div class="sheet-actions"><button class="btn" data-act="sheet-cancel">Done</button></div>
    </div>`;
}

// Reissue/revoke endpoint asks: a centered confirm dialog with the same
// chrome as the other confirm sheets, instead of an inline row swap.
function endpointConfirmHTML(): string {
  const confirm = state.confirm;
  if (!confirm || (confirm.kind !== 'reissue-endpoint' && confirm.kind !== 'revoke-endpoint')) return '';
  const conn = state.connections.find((candidate) => candidate.id === confirm.id);
  const name = conn ? conn.name : 'this tool';
  const reissue = confirm.kind === 'reissue-endpoint';
  return `<div class="sheet-backdrop" data-act="confirm-cancel"></div>
    <div class="sheet wide confirm-sheet" role="dialog" aria-modal="true" aria-labelledby="ep-confirm-title">
      <h3 id="ep-confirm-title">${reissue ? 'Reissue this endpoint?' : 'Revoke this endpoint?'}</h3>
      <p>${reissue
        ? 'You’ll get a new secret to paste into your tools. The current secret stops working the moment you reissue.'
        : `Tools using ${esc(name)}’s direct address lose access immediately.`}</p>
      <div class="sheet-actions">
        <button class="btn" data-act="confirm-cancel">Cancel</button>
        ${reissue
          ? `<button class="btn primary" data-act="reissue-endpoint-confirm" data-conn="${escAttr(String(confirm.id ?? ''))}">Reissue</button>`
          : `<button class="btn danger" data-act="revoke-endpoint-confirm" data-conn="${escAttr(String(confirm.id ?? ''))}">Revoke</button>`}
      </div></div>`;
}

// Deleting a tool asks in the same centered dialog as the other
// destructive confirms, instead of an inline row swap.
function deleteConnConfirmHTML(): string {
  const confirm = state.confirm;
  if (!confirm || confirm.kind !== 'del-conn') return '';
  const conn = state.connections.find((candidate) => candidate.id === confirm.id);
  const name = conn ? conn.name : 'this tool';
  const enabled = Boolean(conn && conn.agent_access.enabled);
  return `<div class="sheet-backdrop" data-act="confirm-cancel"></div>
    <div class="sheet wide confirm-sheet" role="dialog" aria-modal="true" aria-labelledby="del-conn-title">
      <h3 id="del-conn-title">Delete ${esc(name)}?</h3>
      <p>The connection and its settings are removed.${enabled ? ' Agents lose access immediately.' : ''}</p>
      <div class="sheet-actions">
        <button class="btn" data-act="confirm-cancel">Cancel</button>
        <button class="btn danger" data-act="del-conn-confirm" data-id="${escAttr(String(confirm.id ?? ''))}">Delete</button>
      </div></div>`;
}

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
    case 'endpoint-issued': return endpointIssuedSheet();
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
  const title = `Tools agents may call on ${wt.connectionName}`;
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
      <p class="wt-sub">Agents can call ${esc(count)} on this server. Everything
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
const NO_CREDENTIAL_OPTION = '__none__';

/** Types that may be connected without any stored credential. MCP servers
 *  are stored as `api` connections, so this covers them too. */
function secretAllowsNone(type: ConnectionType): boolean {
  return type === 'pg' || type === 'ssh' || type === 'api';
}

/** The credential source to assume when the draft has not chosen one yet.
 *  Defaults to "none" wherever None is offered; an imported credential still
 *  forces "new". Kept in one place so the chooser and validation agree. */
function defaultSecretSource(
  type: ConnectionType,
  draft: ConnectionDraft,
  allowNew: boolean,
): 'existing' | 'new' | 'none' {
  if (draft.secretSource) return draft.secretSource;
  if (draft.importedCredential || draft.sshImportId) return 'new';
  if (secretAllowsNone(type)) return 'none';
  return allowNew && !state.secrets.length ? 'new' : 'existing';
}

function credentialNameIsTaken(name: string): boolean {
  const candidate = name.trim();
  return Boolean(candidate) && state.secrets.some((secret) => secret.name === candidate);
}

function toolNameIsTaken(name: string): boolean {
  const candidate = name.trim();
  return Boolean(candidate) && state.connections.some((connection) => connection.name === candidate);
}

function automaticConnectionName(draft: ConnectionDraft = state.draft): string {
  return defaultConnectionName(
    state.connType,
    state.connEntryName || catalogNameForType(state.connType),
    { user: draft.user, host: draft.host, port: draft.port },
  );
}

function credentialChooserHTML(
  type: ConnectionType,
  draft: ConnectionDraft,
  allowNew = true,
  valueHint?: string,
): string {
  const allowNone = secretAllowsNone(type);
  const source = defaultSecretSource(type, draft, allowNew);
  const secretLabel = type === 'pg' ? 'Database password'
    : type === 'ssh' ? 'SSH private key'
    : 'Token or API key';
  let picker = '';
  if (state.secrets.length || allowNew || allowNone) {
    // No default selection: a wrong prefilled secret (a password where a
    // private key belongs, or vice versa) is worse than an explicit choice.
    const selected = source === 'existing'
      ? state.secrets.find((secret) => secret.id === draft.secretId) || null
      : null;
    const keyBadge = `<span class="cred-badge" aria-hidden="true">${ICONS.keyRound}</span>`;
    const plusBadge = `<span class="cred-badge plus" aria-hidden="true">${ICONS.plus}</span>`;
    const noneBadge = `<span class="cred-badge none" aria-hidden="true">${ICONS.circleSlash}</span>`;
    const triggerContent = selected
      ? `${keyBadge}<span class="cred-name">${esc(selected.name)}</span>`
      : source === 'new'
      ? `${plusBadge}<span class="cred-name">New secret…</span>`
      : source === 'none'
      ? `${noneBadge}<span class="cred-name">None</span>`
      : `<span class="cred-name cred-placeholder">Choose a secret…</span>`;
    const options = state.secrets.map((secret) => {
      const picked = selected !== null && selected.id === secret.id;
      return `<button type="button" class="cred-opt" role="option" data-act="credential-pick"
        data-id="${escAttr(secret.id)}" aria-selected="${picked}">${keyBadge}
        <span class="cred-opt-col"><span class="cred-name">${esc(secret.name)}</span></span>
        ${picked ? `<span class="cred-opt-check">${ICONS.check}</span>` : ''}</button>`;
    }).join('');
    const newOption = allowNew
      ? `${state.secrets.length ? '<div class="cred-menu-divider"></div>' : ''}
        <button type="button" class="cred-opt" role="option" data-act="credential-pick"
          data-id="${NEW_CREDENTIAL_OPTION}" aria-selected="${source === 'new'}">${plusBadge}
          <span class="cred-opt-col"><span class="cred-name">New secret…</span></span></button>`
      : '';
    const noneOption = allowNone
      ? `${allowNew || !state.secrets.length ? '' : '<div class="cred-menu-divider"></div>'}
        <button type="button" class="cred-opt" role="option" data-act="credential-pick"
          data-id="${NO_CREDENTIAL_OPTION}" aria-selected="${source === 'none'}">${noneBadge}
          <span class="cred-opt-col"><span class="cred-name">None</span></span>
          ${source === 'none' ? `<span class="cred-opt-check">${ICONS.check}</span>` : ''}</button>`
      : '';
    const menu = state.formMenuOpen === 'c-secret'
      ? `<div class="cred-menu" role="listbox">${options}${newOption}${noneOption}</div>`
      : '';
    // The trigger carries the selection as its value so captureDrafts and the
    // sheet-open baseline read it exactly like the native select it replaced.
    picker = `<div class="f-row"><label for="c-secret">${secretLabel}</label>
      <div class="cred-select">
        <button type="button" id="c-secret" class="cred-trigger ${fieldCls('secret')}"
          value="${escAttr(selected ? selected.id : source === 'new' ? NEW_CREDENTIAL_OPTION : source === 'none' ? NO_CREDENTIAL_OPTION : '')}" data-act="select-toggle" data-menu="c-secret"
          aria-haspopup="listbox" aria-expanded="${state.formMenuOpen === 'c-secret'}">
          ${triggerContent}<span class="cred-chevron" aria-hidden="true">${ICONS.chevronDown}</span></button>
        ${menu}</div>${fieldErr('secret')}</div>`;
  } else if (source === 'new') {
    picker = `<div class="f-row"><label>${secretLabel}</label></div>`;
  }
  if (source !== 'new') {
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
  if (t === 'pg') return Boolean((d.pgCaBundlePath || '').trim());
  return false;
}

const PG_SSL_OPTIONS: Array<[string, string]> = [
  ['verify-full', 'Verify full'],
  ['require', 'Require TLS (no certificate verification)'],
  ['verify-ca', 'Verify CA only (no hostname verification)'],
  ['prefer', 'Prefer (TLS optional)'],
  ['disable', 'Disable'],
];

/** Keep sslmode tracking a loopback host until the user picks one: default →
 * disable when the host goes loopback, and back when it stops being one.
 * Returns whether the draft changed so callers can sync the rendered field. */
function applyLoopbackTlsPrefill(d: ConnectionDraft): boolean {
  if (d.sslmodeIsAutomatic === false) return false;
  const loopback = isLoopbackHost(d.host);
  if (loopback && (d.sslmode ?? 'verify-full') === 'verify-full') {
    d.sslmode = 'disable';
    d.sslmodeIsAutomatic = true;
    return true;
  }
  if (!loopback && d.sslmodeIsAutomatic && d.sslmode === 'disable') {
    d.sslmode = 'verify-full';
    return true;
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
  // Paste-to-prefill: a Postgres DSN or `ssh` command fills the form below
  // instead of making the user retype what they already have.
  const canImport = !editing && (t === 'pg' || t === 'ssh');
  const importRow = !canImport ? '' : `<div class="f-row sheet-import">
      <label for="conn-import">Connection string</label>
      <div class="sheet-import-row">
        <input id="conn-import" class="${state.connImportError ? 'field-invalid' : ''}" type="text"
          spellcheck="false" autocapitalize="off" autocorrect="off"
          placeholder="${escAttr(quickSetupPlaceholder(t))}" value="${escAttr(state.connImportSource)}">
        <button class="btn" data-act="conn-import" ${state.connImportSource.trim() ? '' : 'disabled'}>Prefill</button></div>
      ${state.connImportError ? `<div class="field-error">${esc(state.connImportError)}</div>` : ''}</div>`;
  const importDivider = canImport
    ? '<div class="sheet-import-divider"><span>or</span></div>'
    : '';
  let sshHostKeyField = '';
  let pgTlsFields = '';
  let fields = importRow + importDivider + importWarnings;
  const nameTaken = !editing && toolNameIsTaken(d.name ?? '');
  const nameWarning = editing ? ''
    : `<div id="tool-name-warning" class="field-warning" role="status" aria-live="polite"${nameTaken ? '' : ' hidden'}>Name used by an existing tool</div>`;
  const namePlaceholder = (!editing && state.connEntryName) || catalogNameForType(t);
  fields += `<div class="f-row"><label for="f-cname">Name</label><input id="f-cname" class="${fieldCls('name')} ${nameTaken ? 'name-conflict-warning' : ''}"${editing ? '' : ' aria-describedby="tool-name-warning"'} placeholder="${escAttr(namePlaceholder)}" value="${escAttr(d.name ?? '')}">${fieldErr('name')}${nameWarning}</div>`;
  if (t === 'api' && isMcpDraft(d)) {
    const url = d.origin
      ?? (d.host
        ? `${apiOriginFromParts(d.scheme ?? undefined, d.host, d.port ?? null)}${d.mcpPath ?? ''}`
        : '');
    const entry = d.entryId ? catalogEntryById(d.entryId) : undefined;
    const hint = entry?.mcpTemplate?.urlHint;
    fields += `<div class="f-row"><label for="f-origin">MCP server URL</label>
      <input id="f-origin" class="${fieldCls('origin')}" placeholder="https://mcp.example.com/mcp" value="${escAttr(url)}">${fieldErr('origin')}
      ${hint ? `<div class="rule-note">${esc(hint)}</div>` : ''}</div>`;
  } else if (t === 'api') {
    const origin = d.origin ?? apiOriginFromParts(d.scheme ?? undefined, d.host ?? undefined, d.port ?? null);
    fields += `<div class="f-row"><label for="f-origin">API root</label><input id="f-origin" class="${fieldCls('origin')}" placeholder="https://api.github.com" value="${escAttr(origin)}">${fieldErr('origin')}</div>`;
  } else if (t === 'ssh') {
    fields += `<div class="f-2col compact-field-row">
      <div class="f-row" style="flex:0 0 90px"><label for="f-user">User</label><input id="f-user" class="${fieldCls('user')}" placeholder="${escAttr(state.localUsername)}" value="${escAttr(d.user ?? '')}">${fieldErr('user')}</div>
      <div class="f-row"><label for="f-host">Host</label><input id="f-host" class="${fieldCls('host')}" placeholder="prod.example.com" value="${escAttr(d.host ?? '')}">${fieldErr('host')}</div>
      <div class="f-row" style="flex:0 0 90px"><label for="f-port">Port</label><input id="f-port" class="${fieldCls('port')}" inputmode="numeric" value="${escAttr(d.port ?? '22')}">${fieldErr('port')}</div></div>`;
    fields += d.proxyJump ? `<div class="rule-note">ProxyJump: ${esc(d.proxyJump)}</div>` : '';
    sshHostKeyField = `<div class="f-row"><label for="f-host-key">Host key fingerprint <span class="label-detail">(optional)</span></label>
      <input id="f-host-key" class="${fieldCls('hostKeyFingerprint')}" placeholder="SHA256:…" value="${escAttr(d.hostKeyFingerprint ?? '')}">${fieldErr('hostKeyFingerprint')}
      <div class="rule-note">The server’s identity (host key) is confirmed with you the first time an agent connects.</div></div>`;
  } else if (t === 'pg') {
    const sslmode = d.sslmode || 'verify-full';
    fields += `<div class="f-2col compact-field-row">
      <div class="f-row"><label for="f-host">Host</label><input id="f-host" class="${fieldCls('host')}" placeholder="db.internal.example.com" value="${escAttr(d.host ?? '')}">${fieldErr('host')}</div>
      <div class="f-row" style="flex:0 0 90px"><label for="f-port">Port</label><input id="f-port" class="${fieldCls('port')}" inputmode="numeric" value="${escAttr(d.port ?? '5432')}">${fieldErr('port')}</div></div>
      <div class="f-2col compact-field-row">
      <div class="f-row"><label for="f-db">Database</label><input id="f-db" class="${fieldCls('dbname')}" placeholder="app_production" value="${escAttr(d.dbname ?? '')}">${fieldErr('dbname')}</div>
      <div class="f-row" style="flex:0 0 90px"><label for="f-user">User</label><input id="f-user" class="${fieldCls('user')}" placeholder="${escAttr(state.localUsername)}" value="${escAttr(d.user ?? '')}">${fieldErr('user')}</div></div>
      <div class="f-row"><label for="f-sslmode">TLS mode</label>${customSelectHTML('f-sslmode', PG_SSL_OPTIONS, sslmode, fieldCls('sslmode'))}${fieldErr('sslmode')}
        ${sslmode === 'require' ? '<div class="pair-identity-warning">The server certificate will not be verified.</div>' : ''}</div>`;
    pgTlsFields = `<div class="f-row"><label for="f-pg-ca-bundle">Trusted CA bundle <span class="label-detail">(optional)</span></label>
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
    const oauthPreset = !mcpAdd && t === 'api' && d.entryId
      ? catalogEntryById(d.entryId)?.oauthPreset : undefined;
    const modeValue = d.authMode || (mcpAdd ? 'oauth' : 'bearer');
    const recipes: Array<[string, string]> = [
      // MCP servers advertise their own sign-in flow; the browser dance is
      // the default and a pasted token stays one select away.
      ...(mcpAdd ? [['oauth', 'Sign in with your account (OAuth)'] as [string, string]] : []),
      ['bearer', 'Bearer token'], ['header', 'Custom header'],
      ...(t === 'api' ? [['query', 'Query parameter'] as [string, string]] : []),
      // Plain REST rows with documented OAuth endpoints offer a browser
      // sign-in against the user's own OAuth app (BYO-app, loopback PKCE).
      ...(oauthPreset ? [['oauth', 'Sign in with your browser (your OAuth app)'] as [string, string]] : []),
      ['advanced', 'Bearer token + template'],
    ];
    // Decision first: the authentication type governs which detail field and
    // credential inputs appear, so those render beneath the select.
    fields += `<div class="f-row"><label for="c-auth-mode">Authentication type</label>${customSelectHTML('c-auth-mode', recipes, modeValue)}</div>`;
    if (modeValue === 'oauth' && oauthPreset) {
      const checked = d.oauthScopes ?? oauthPreset.scopes;
      const scopeBoxes = oauthPreset.scopes.map((scope) => `<label class="wt-row">
          <input type="checkbox" data-act="oauth-scope-toggle" data-scope="${escAttr(scope)}"
            ${checked.includes(scope) ? 'checked' : ''}>
          <span class="wt-name"><code>${esc(scope)}</code></span>
        </label>`).join('');
      fields += `<div class="rule-note oauth-note">Uses your own OAuth app: create one at
          <code>${esc(oauthPreset.appDocsUrl || 'the provider')}</code>, allow a
          <code>http://127.0.0.1</code> redirect, and paste its client ID. You’ll approve access in
          your browser; tokens live in your Keychain and refresh automatically.</div>
        <div class="f-row"><label for="c-oauth-client-id">Client ID</label>
          <input id="c-oauth-client-id" class="${fieldCls('oauthClientId')}" value="${escAttr(d.oauthClientId ?? '')}">${fieldErr('oauthClientId')}</div>
        <div class="f-row"><label for="c-oauth-client-secret">Client secret <span class="label-detail">(only if your provider requires one)</span></label>
          <input id="c-oauth-client-secret" type="password" value="${escAttr(d.oauthClientSecret ?? '')}"></div>
        <div class="f-row"><label>Scopes</label><div class="wt-list">${scopeBoxes}</div></div>
        <div class="adv-collapse"><details class="set-collapse"><summary>OAuth endpoints</summary>
          <div class="set-panel">
          <div class="f-row"><label for="c-oauth-auth-url">Authorization URL</label>
            <input id="c-oauth-auth-url" class="${fieldCls('oauthAuthUrl')}" value="${escAttr(d.oauthAuthUrl ?? oauthPreset.authUrl)}">${fieldErr('oauthAuthUrl')}</div>
          <div class="f-row"><label for="c-oauth-token-url">Token URL</label>
            <input id="c-oauth-token-url" class="${fieldCls('oauthTokenUrl')}" value="${escAttr(d.oauthTokenUrl ?? oauthPreset.tokenUrl)}">${fieldErr('oauthTokenUrl')}</div>
          </div></details></div>`;
    } else if (modeValue === 'oauth') {
      fields += `<div class="rule-note oauth-note">You’ll approve access in your browser. The token is saved
        to your Keychain and injected into the connection. You can connect multiple accounts.</div>`;
      // Vendors without automatic client registration (Google Workspace)
      // need a one-time OAuth client the user creates with the provider.
      const oauthApp = mcpAdd && d.entryId
        ? catalogEntryById(d.entryId)?.mcpTemplate?.oauthApp : undefined;
      if (oauthApp) {
        fields += `<div class="rule-note oauth-note">This provider has no automatic client registration:
            create an OAuth client at <code>${esc(oauthApp.docsUrl || 'the provider')}</code> and paste
            its ID here. It is used once per sign-in and stored with the connection.</div>
          <div class="f-row"><label for="c-oauth-client-id">Client ID</label>
            <input id="c-oauth-client-id" class="${fieldCls('oauthClientId')}" value="${escAttr(d.oauthClientId ?? '')}">${fieldErr('oauthClientId')}</div>
          <div class="f-row"><label for="c-oauth-client-secret">Client secret <span class="label-detail">(only if your provider issued one)</span></label>
            <input id="c-oauth-client-secret" type="password" value="${escAttr(d.oauthClientSecret ?? '')}"></div>`;
      }
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
    // provider's "get your API key" page, opened outside the app.
    if (state.connPreset?.docsUrl && modeValue !== 'oauth') {
      const docsLabel = state.connPreset.docsUrl;
      const docsUrl = /^https?:\/\//i.test(docsLabel) ? docsLabel : `https://${docsLabel}`;
      fields += `<div class="rule-note">Create or find your ${esc(state.connEntryName || 'API')} key at
        <code><a class="external-doc-link" href="${escAttr(docsUrl)}" data-act="open-external-url"
          data-url="${escAttr(docsUrl)}">${esc(docsLabel)}</a></code></div>`;
    }
  } else {
    fields += credentialChooserHTML(t, d);
  }
  const advancedFields = pgTlsFields + sshHostKeyField;
  if (advancedFields) {
    // Force the section open when one of its fields has a validation error,
    // so the inline message (and the focused input) is visible.
    const advancedError = ['hostKeyFingerprint', 'pgCaBundlePath']
      .some((key) => state.sheetErrors[key]);
    const advOpen = state.connAdvancedOpen || advancedError;
    fields += `<div class="adv-collapse">
      <button type="button" class="adv-toggle" aria-expanded="${advOpen}" data-act="toggle-conn-advanced">
        <span class="adv-toggle-icon" aria-hidden="true">${ICONS.chevronDown}</span>Advanced</button>
      ${advOpen ? advancedFields : ''}</div>`;
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
  // The draft-test verdict sits between the fields (below the Advanced
  // toggle) and the action row: the failure, a TLS-shaped fix when the
  // detail identifies one, and the promise that Add now saves anyway.
  const dt = !editing ? state.draftTest : null;
  const tlsDeclined = Boolean(dt?.detail && /declined TLS/i.test(dt.detail));
  const certFailed = Boolean(dt?.detail && /certificate/i.test(dt.detail));
  const draftTestHTML = !dt ? ''
    : dt.running
    ? '<div class="draft-test running">Testing the connection…</div>'
    : `<div class="draft-test err">${ICONS.circleX}<div>
        <b>Connection test failed.</b> ${esc(dt.detail || '')}
        ${tlsDeclined ? `<div class="draft-test-fix"><button type="button" class="btn sm" data-act="draft-test-disable-tls">Set TLS mode to Disable</button></div>` : ''}
        ${certFailed && t === 'pg' ? '<div class="draft-test-hint">Trust the server’s CA under Advanced → Trusted CA bundle, or pick a different TLS mode.</div>' : ''}
        <div class="draft-test-hint">Press “Add ${esc(label)}” again to save it without a passing test.</div>
      </div></div>`;
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>${title}</h3>${fields}${draftTestHTML}
    <div class="sheet-actions">${editing && conn
      ? `<button class="btn danger conn-delete-btn" data-act="del-conn-from-edit" data-id="${conn.id}">Delete…</button>${
          conn.mcp_path || conn.oauth_spec
          ? `<div class="tile-menu-wrap sheet-conn-menu">
              <button class="icon-btn tile-menu-btn ${state.connMenuOpen === `sheet:${conn.id}` ? 'on' : ''}"
                title="More options" aria-label="More options for ${escAttr(conn.name)}" aria-haspopup="menu"
                aria-expanded="${state.connMenuOpen === `sheet:${conn.id}`}"
                data-act="toggle-conn-menu" data-id="sheet:${conn.id}">${ICONS.ellipsis}</button>
              ${state.connMenuOpen === `sheet:${conn.id}` ? `<div class="tile-menu" role="menu" aria-label="More options for ${escAttr(conn.name)}">
                <button class="menu-item" role="menuitem" data-act="${conn.mcp_path ? 'reconnect-mcp' : 'oauth-reconnect'}"
                  data-id="${conn.id}">${ICONS.refresh} Reconnect (sign in again)</button>
              </div>` : ''}
            </div>`
          : ''}`
      : ''}<button class="btn" data-act="sheet-cancel">Cancel</button>
      <button class="btn primary" data-act="save-conn" ${dt?.running ? 'disabled' : ''}>${editing ? 'Save' : oauthSelected ? 'Sign in & connect' : `Add ${label}`}</button></div></div>${discardConfirm}`;
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
      <div><b>${esc(cap(auth.message))}</b>
      ${auth.hint ? `<div class="auth-sub">${esc(auth.hint)}</div>` : ''}</div></div>`;
    actions = `<button class="btn" data-act="mcp-open-browser" data-url="${escAttr(auth.target)}">Open in browser</button>
      ${state.mcpAuthDraft && !state.mcpAuthDraft.reauth_connection_id
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
  const windowBtn = (secs: number, label: string): string =>
    `<button class="seg-btn ${s.presence_window_secs === secs ? 'on' : ''}" data-act="set-presence-window"
      data-id="${secs}" role="radio" aria-checked="${s.presence_window_secs === secs}">${label}</button>`;
  const presenceRow = s.reauth_on_read
    ? `<div class="set-row"><div class="set-txt"><div class="st-title">Stay unlocked after confirming</div>
      <div class="st-sub">Confirming access allows actions for this long. An agent requesting new access will always ask again.</div></div>
      <div class="seg in-form" role="radiogroup" aria-label="Stay unlocked for">
      ${windowBtn(15 * 60, '15 min')}${windowBtn(60 * 60, '1 hr')}${windowBtn(2 * 60 * 60, '2 hrs')}</div></div>`
    : '';
  // Window chrome is a this-machine concern: in remote mode the toggle
  // would patch the *remote* broker's setting, which this app's chrome
  // deliberately never reads (windows.rs) — and could silently reconfigure
  // a desktop app running on the broker host. Local mode only.
  const dockRow = state.broker.mode === 'local'
    ? `<div class="set-row"><div class="set-txt"><div class="st-title">Hide Dock icon in the menu bar</div>
      <div class="st-sub">When minimized to the menu bar, hide the Dock icon.</div></div>
      <button class="switch ${s.menu_bar_hides_dock ? 'on' : ''}" data-act="toggle-menubar-dock" role="checkbox" aria-checked="${s.menu_bar_hides_dock ? 'true' : 'false'}"></button></div>`
    : '';
  const websocketRow = `<div class="set-row"><div class="set-txt"><div class="st-title">Show WebSockets</div>
      <div class="st-sub">Adds Custom WebSocket to the tool catalog.</div></div>
      <button class="switch ${s.show_websockets ? 'on' : ''}" data-act="toggle-websockets" role="checkbox" aria-checked="${s.show_websockets ? 'true' : 'false'}"></button></div>`;
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>Settings</h3>
    ${reauthRow}${presenceRow}${websocketRow}${dockRow}
    <div class="sheet-actions"><button class="btn primary" data-act="sheet-cancel">Done</button></div></div>`;
}

/* --------------------------------- helpers ------------------------------- */
const cap = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);
const tabLabel = (tab: Tab): string =>
  tab === 'connections' ? 'Tools'
  : tab === 'start' ? 'Get started'
  : tab === 'activity' ? 'Activity Log'
  : cap(tab);

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
  // Capture the remote-broker form only while state still shows it: after a
  // successful connect resets the form, the old inputs are in the DOM until
  // the next paint, and capturing then would copy the deliberately cleared
  // token back into JS state.
  if (brokerTakeover(state.broker, state.remoteSetup.open) === 'setup') {
    if (g('rb-url') !== undefined) state.remoteSetup.url = g('rb-url') ?? '';
    if (g('rb-token') !== undefined) state.remoteSetup.token = g('rb-token') ?? '';
  }
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
      } else if (secretChoice === NO_CREDENTIAL_OPTION) {
        state.draft.secretSource = 'none';
        state.draft.secretId = null;
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
    if (g('c-oauth-client-id') !== undefined) state.draft.oauthClientId = g('c-oauth-client-id');
    if (g('c-oauth-client-secret') !== undefined) state.draft.oauthClientSecret = g('c-oauth-client-secret');
    if (g('c-oauth-auth-url') !== undefined) state.draft.oauthAuthUrl = g('c-oauth-auth-url');
    if (g('c-oauth-token-url') !== undefined) state.draft.oauthTokenUrl = g('c-oauth-token-url');
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

function initializeCatalogConnectionDraft(
  entry: CatalogEntry,
  mcpAuthMode: 'oauth' | 'bearer' = 'oauth',
  asApi = false,
): void {
  state.connType = entry.connType!;
  state.connEntryName = entry.name;
  state.connPreset = entry.preset ?? null;
  state.draft = { nameIsAutomatic: true };
  if (entry.mcp && !asApi) {
    state.draft.isMcp = true;
    state.draft.entryId = entry.id;
    state.draft.authMode = mcpAuthMode;
    if (entry.mcpTemplate?.serverUrl) state.draft.origin = entry.mcpTemplate.serverUrl;
  }
  // On a dual-mode row (MCP template + API preset) the MCP draft wins;
  // the preset applies only when adding the row as a plain API.
  if (entry.preset && !state.draft.isMcp) {
    state.draft.origin = entry.preset.origin;
    state.draft.authMode = entry.preset.authMode;
    state.draft.authDetail = entry.preset.authDetail;
  }
  if (entry.connType === 'pg') state.draft.port = '5432';
  if (entry.connType === 'ssh') state.draft.port = '22';
  state.draft.name = automaticConnectionName();
  state.sheetErrors = {};
  state.sheetBaseline = null;
  state.connAdvancedOpen = false;
  state.connImportSource = '';
  state.connImportError = null;
}

function credentialFocusTarget(draft: ConnectionDraft = state.draft): string {
  const source = draft.secretSource
    || (draft.importedCredential || draft.sshImportId || !state.secrets.length ? 'new' : 'existing');
  return source === 'new' ? 'c-new-secret-value' : 'c-secret';
}

function initialCatalogConnectionFocusTarget(entry: CatalogEntry): string {
  const prefilledApiRoot = entry.connType === 'api' && Boolean(state.draft.origin?.trim());
  if (prefilledApiRoot && state.draft.authMode !== 'oauth') return credentialFocusTarget();
  if (entry.connType === 'api' && (state.draft.name || '').trim()) return 'f-origin';
  if (!entry.preset) return 'f-cname';
  return credentialFocusTarget();
}

async function openCatalogConnectionForm(
  entry: CatalogEntry,
  mcpAuthMode: 'oauth' | 'bearer' = 'oauth',
  asApi = false,
): Promise<void> {
  if (!entry.connType || !await holdDropdownFormOpen()) return;
  state.sheet = { kind: 'add-conn' };
  initializeCatalogConnectionDraft(entry, mcpAuthMode, asApi);
  if (entry.connType === 'pg') applyLoopbackTlsPrefill(state.draft);
  render();
  focusField(initialCatalogConnectionFocusTarget(entry));
}

function availableConnectionName(base: string): string {
  if (!toolNameIsTaken(base)) return base;
  let suffix = 2;
  while (toolNameIsTaken(`${base} ${suffix}`)) suffix += 1;
  return `${base} ${suffix}`;
}

async function quickConnectCatalogMcp(entry: CatalogEntry): Promise<void> {
  const serverUrl = entry.mcpTemplate?.serverUrl;
  if (!entry.connType || !canQuickConnectMcp(entry) || !serverUrl) return;
  if (!await holdDropdownFormOpen()) return;
  initializeCatalogConnectionDraft(entry, 'oauth');
  state.draft.name = availableConnectionName(state.draft.name || entry.name);
  try {
    const server = parseMcpServerUrl(serverUrl);
    await startMcpAuth({
      name: state.draft.name,
      scheme: server.scheme,
      host: server.host,
      port: server.port,
      mcp_path: server.mcpPath,
      whoami_tool: entry.mcpTemplate?.whoamiTool ?? null,
    });
  } catch (error) {
    toast('⚠ ' + errorMessage(error));
  }
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
  if (state.draftTest?.running) return;
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
  const oauthPreset = adding && t === 'api' && !mcpAdd && d.entryId
    ? catalogEntryById(d.entryId)?.oauthPreset : undefined;
  const byoOauth = !!oauthPreset && authMode === 'oauth';
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
  const mcpOauthApp = usesOauth && d.entryId
    ? catalogEntryById(d.entryId)?.mcpTemplate?.oauthApp : undefined;
  if (mcpOauthApp && !(d.oauthClientId || '').trim()) {
    errs.oauthClientId = 'The OAuth client ID is required';
  }
  if (byoOauth) {
    if (!(d.oauthClientId || '').trim()) errs.oauthClientId = 'The OAuth client ID is required';
    for (const [key, value] of [
      ['oauthAuthUrl', d.oauthAuthUrl ?? oauthPreset!.authUrl],
      ['oauthTokenUrl', d.oauthTokenUrl ?? oauthPreset!.tokenUrl],
    ] as const) {
      if (!/^https:\/\//.test((value || '').trim())) errs[key] = 'Must be a complete https:// URL';
    }
  }
  const usesRecipe = adding && (t === 'api' || t === 'ws')
    && authMode !== 'advanced' && !usesOauth && !byoOauth;
  const needsCredentialChoice = !usesOauth && !byoOauth && (
    (adding && !((t === 'api' || t === 'ws') && authMode === 'advanced')) ||
    (!adding && t !== 'api'));
  const secretSource = adding
    ? defaultSecretSource(t, d, true)
    : (d.secretSource || 'existing');
  let selectedSecret: SecretSummary | null = null;
  let newSecretName: string | null = null;
  let newSecretNameTaken = false;
  if (needsCredentialChoice && secretSource === 'existing') {
    selectedSecret = state.secrets.find((secret) => secret.id === d.secretId) || null;
    if (!selectedSecret) errs.secret = 'Choose a saved credential or save a new one';
  } else if (needsCredentialChoice && secretSource === 'new') {
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
  if (usesRecipe && secretSource !== 'none') {
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
    const entry = d.entryId ? catalogEntryById(d.entryId) : undefined;
    const template = entry?.mcpTemplate;
    await startMcpAuth({
      name,
      scheme: apiOrigin!.scheme,
      host: apiOrigin!.host,
      port: apiOrigin!.port,
      mcp_path: mcpPath!,
      whoami_tool: template?.whoamiTool ?? null,
      ...(mcpOauthApp ? {
        oauth_client_id: (d.oauthClientId || '').trim(),
        oauth_client_secret: (d.oauthClientSecret || '').trim() || null,
        oauth_scope: mcpOauthApp.scopes?.join(' ') || null,
        extra_auth_params: mcpOauthApp.extraAuthParams ?? [],
      } : {}),
    });
    return;
  }
  if (byoOauth) {
    // The token is minted by the browser dance; the broker stores it and
    // creates the connection only once authentication completed.
    const scopes = d.oauthScopes ?? oauthPreset!.scopes;
    const input: ConnectionInput = {
      name,
      type: t,
      host: apiOrigin!.host,
      scheme: apiOrigin!.scheme,
      port: apiOrigin!.port,
      oauth_auth_url: (d.oauthAuthUrl ?? oauthPreset!.authUrl).trim(),
      oauth_token_url: (d.oauthTokenUrl ?? oauthPreset!.tokenUrl).trim(),
      oauth_client_id: (d.oauthClientId || '').trim(),
      oauth_scopes: scopes,
      oauth_extra_params: oauthPreset!.extraAuthParams ?? [],
    };
    toast('🌐 Approve access in your browser…');
    if (await run(() => invoke('oauth_connect', {
      input, clientSecret: (d.oauthClientSecret || '').trim() || null,
    }))) {
      toast('🔌 Connected');
      closeSheet();
      await refresh('all');
    }
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
  // Adding a Postgres/SSH tool dials it first, so a wrong TLS mode (or an
  // unreachable host) surfaces while the form is still open. A failed test
  // is advice, not a wall: it arms the override and the next Add saves
  // as-entered.
  if (adding && (t === 'pg' || t === 'ssh') && !state.draftTestOverride) {
    state.draftTest = { running: true };
    render();
    let report: { ok: boolean; detail: string };
    try {
      report = await invoke('test_connection_draft', { input });
    } catch (error) {
      report = { ok: false, detail: formErrorMessage(error) };
    }
    if (!report.ok) {
      state.draftTest = { running: false, ok: false, detail: report.detail };
      state.draftTestOverride = true;
      render();
      return;
    }
    state.draftTest = null;
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
        // A finished add lands back on the flat list, where the new tool is.
        state.addToolOpen = false;
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
        if (entry && !state.toolsOpen.includes(entry.id)) state.toolsOpen.push(entry.id);
        render();
        void runConnectionTest(saved.id);
        // Endpointable kinds get their direct endpoint issued on creation —
        // the one-time sheet still has to show, since the secret (or SSH
        // socket path) leaves the broker only at issue.
        if (ENDPOINTABLE[saved.type] && saved.agent_access.enabled && !saved.agent_access.endpoint) {
          try {
            const info = await invoke('issue_endpoint', { connectionId: saved.id });
            state.sheet = { kind: 'endpoint-issued', endpoint: info };
            await refresh('all');
          } catch {
            // The row still offers "Issue direct endpoint…" as the fallback.
          }
          render();
        }
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
  state.draftTest = null;
  state.draftTestOverride = false;
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
  if (btn?.dataset.act === 'open-external-url') e.preventDefault();
  // The checkbox is presentational; stop the browser toggling it so the
  // rendered state stays authoritative.
  // Dismiss the desktop settings popover on any click outside it (its own
  // toggle handles itself; menu-item clicks close it in their handlers).
  if (state.menuOpen && !target?.closest('.settings-menu') &&
      !(btn && btn.dataset.act === 'toggle-settings-menu')) {
    state.menuOpen = false;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.brokerMenuOpen && !target?.closest('.broker-switch-wrap')) {
    state.brokerMenuOpen = false;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.agentMenuOpen && !target?.closest('.agent-menu-wrap')) {
    state.agentMenuOpen = null;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.catalogActionMenuOpen && !target?.closest('.cat-connect-wrap')) {
    state.catalogActionMenuOpen = null;
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
      state.catalogActionMenuOpen = null;
      state.connMenuOpen = null;
      render();
      resetScroll();
      break;
    }
    case 'broker-menu': state.brokerMenuOpen = !state.brokerMenuOpen; render(); break;
    case 'broker-pick-local': {
      state.brokerMenuOpen = false;
      state.remoteSetup.open = false;
      state.remoteSetup.error = null;
      if (state.broker.mode === 'local') { render(); break; }
      try {
        state.broker = await invoke('switch_broker_local');
        await refresh('all');
        try { state.agentSetupInstructions = await invoke('get_agent_setup'); } catch { /* pane shows loading */ }
        toast('Managing this Mac’s broker');
      } catch (error) {
        toast(`Couldn’t start the local broker: ${String(error)}`);
      }
      render();
      break;
    }
    case 'broker-pick-remote': {
      state.brokerMenuOpen = false;
      state.remoteSetup = {
        open: true,
        advancedOpen: false,
        url: state.broker.url ?? state.remoteSetup.url,
        token: '',
        busy: false,
        error: null,
      };
      render();
      break;
    }
    case 'toggle-remote-advanced':
      captureDrafts();
      state.remoteSetup.advancedOpen = !state.remoteSetup.advancedOpen;
      render();
      break;
    case 'broker-setup-cancel':
      state.remoteSetup.open = false;
      state.remoteSetup.error = null;
      render();
      break;
    case 'broker-edit':
      state.remoteSetup = {
        open: true,
        advancedOpen: false,
        url: state.broker.url ?? '',
        token: '',
        busy: false,
        error: null,
      };
      render();
      break;
    case 'broker-connect-submit': {
      captureDrafts();
      const url = state.remoteSetup.url.trim();
      const token = state.remoteSetup.token.trim();
      state.remoteSetup.busy = true;
      state.remoteSetup.error = null;
      render();
      try {
        state.broker = await invoke('connect_remote_broker', { url, token: token || null });
        state.remoteSetup = {
          open: false, advancedOpen: false, url: '', token: '', busy: false, error: null,
        };
        await refresh('all');
        try { state.agentSetupInstructions = await invoke('get_agent_setup'); } catch { /* pane shows loading */ }
        toast(`Managing ${brokerLabel(state.broker)}`);
      } catch (error) {
        state.remoteSetup.busy = false;
        state.remoteSetup.error = String(error);
      }
      render();
      break;
    }
    case 'broker-retry': {
      try {
        state.broker = await invoke('retry_remote_broker');
        await refresh('all');
      } catch {
        // The profile event carries the failure; nothing else to do.
      }
      render();
      break;
    }
    case 'mode-tray': state.menuOpen = false; run(() => invoke('ui_set_mode', { mode: 'tray' })); break;
    case 'mode-window': run(() => invoke('ui_set_mode', { mode: 'window' })); break;
    case 'toggle-settings-menu': state.menuOpen = !state.menuOpen; render(); break;
    case 'connect-toggle':
      state.connectOpen = state.connectOpen === id ? null : id;
      render();
      break;
    case 'copy-key':
      if (await run(() => invoke('copy_key'))) flashCopied('shared-key');
      break;
    case 'toggle-agent-menu':
      state.agentMenuOpen = state.agentMenuOpen === id ? null : id;
      render();
      break;
    case 'toggle-conn-menu':
      state.connMenuOpen = state.connMenuOpen === id ? null : id;
      render();
      break;
    case 'issue-endpoint':
    case 'reissue-endpoint-confirm': {
      const connectionId = btn.dataset.conn || '';
      state.confirm = null;
      // Not via run(): we need the one-time result to show its secret.
      try {
        const info = await invoke('issue_endpoint', { connectionId });
        state.sheet = { kind: 'endpoint-issued', endpoint: info };
        await refresh('all');
      } catch (error) {
        toast('⚠ ' + errorMessage(error));
        render();
      }
      break;
    }
    case 'reissue-endpoint-ask':
      state.connMenuOpen = null;
      state.confirm = { kind: 'reissue-endpoint', id: btn.dataset.conn || '' };
      render();
      break;
    case 'revoke-endpoint-ask':
      state.connMenuOpen = null;
      state.confirm = { kind: 'revoke-endpoint', id: btn.dataset.conn || '' };
      render();
      break;
    case 'revoke-endpoint-confirm': {
      const conn = state.connections.find((candidate) => candidate.id === btn.dataset.conn);
      const endpointId = conn?.agent_access.endpoint?.endpoint_id || '';
      state.confirm = null;
      if (endpointId && await run(() => invoke('revoke_endpoint', { endpointId }))) {
        toast('Endpoint revoked');
        await refresh('all');
      } else {
        render();
      }
      break;
    }
    case 'copy-endpoint-dsn': {
      const conn = state.connections.find((candidate) => candidate.id === btn.dataset.conn);
      const dsn = conn?.agent_access.endpoint?.dsn;
      if (conn && dsn) {
        try {
          await navigator.clipboard.writeText(dsn);
          flashCopied(`ep:${conn.id}`);
        } catch {
          toast('⚠ Copy failed — select the text and copy it manually');
        }
      }
      break;
    }
    case 'copy-endpoint': {
      const info = state.sheet?.endpoint;
      const key = btn.dataset.field;
      if (info) {
        const text = key === 'secret' ? info.secret : key === 'dsn' ? info.dsn : info.example;
        try {
          await navigator.clipboard.writeText(text);
          toast('📋 Copied');
        } catch {
          toast('⚠ Copy failed — select the text and copy it manually');
        }
      }
      break;
    }
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
        if (state.draft.nameIsAutomatic) state.draft.name = automaticConnectionName();
        // A pasted DSN that says nothing about TLS gets the same loopback
        // prefill as a typed host; an explicit sslmode= is the user's call.
        if (state.connType === 'pg' && !/sslmode=/i.test(source)) {
          applyLoopbackTlsPrefill(state.draft);
        }
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
    case 'start-mode':
      if (id) {
        state.connectMode = id;
        render();
      }
      break;
    case 'start-view':
      if (START_VIEWS.includes(id as StartView)) {
        state.startView = id as StartView;
        render();
      }
      break;
    case 'open-connect-guides':
      state.tab = 'start';
      state.startView = 'guides';
      render();
      resetScroll();
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
      if (state.toolsOpen.includes(id)) {
        state.toolsOpen = state.toolsOpen.filter((openId) => openId !== id);
      } else {
        state.toolsOpen = [...state.toolsOpen, id];
      }
      render(); break;
    case 'toggle-add-tools':
      state.addToolOpen = !state.addToolOpen;
      render();
      break;
    case 'toggle-section-expanded':
      state.sectionsExpanded = state.sectionsExpanded.includes(id)
        ? state.sectionsExpanded.filter((section) => section !== id)
        : [...state.sectionsExpanded, id];
      render();
      break;
    case 'toggle-catalog-connect-menu':
      state.catalogActionMenuOpen = state.catalogActionMenuOpen === id ? null : id;
      render();
      break;
    case 'catalog-connect-oauth': {
      const entry = catalogEntryById(id);
      state.catalogActionMenuOpen = null;
      render(false);
      if (entry) await quickConnectCatalogMcp(entry);
      break;
    }
    case 'catalog-connect-manual': {
      const entry = catalogEntryById(id);
      state.catalogActionMenuOpen = null;
      if (entry) await openCatalogConnectionForm(entry, 'bearer');
      break;
    }
    case 'catalog-connect-api': {
      // The dual-mode escape hatch: add a branded row as a plain
      // credentialed API instead of its hosted MCP server.
      const entry = catalogEntryById(id);
      state.catalogActionMenuOpen = null;
      if (entry) await openCatalogConnectionForm(entry, 'bearer', true);
      break;
    }
    case 'catalog-add': {
      const entry = catalogEntryById(id);
      if (!entry || entry.via !== 'connection' || !entry.connType) break;
      // "Add another" on a dual-mode row should match what is already
      // there: if every existing connection under it is a plain API
      // (no MCP path), open the API form rather than jumping to MCP.
      const existing = connectionsForEntry(entry, state.connections);
      const asApi = Boolean(entry.mcp && entry.preset && existing.length > 0
        && existing.every((connection) => !connection.mcp_path));
      await openCatalogConnectionForm(entry, asApi ? 'bearer' : 'oauth', asApi);
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
        secretId: null,
        secretSource: c.type !== 'api' && !c.secret_names.length ? 'none' : 'existing' };
      // best-effort: prefill single-secret binding by name→id
      if (c.type !== 'api' && c.secret_names.length) {
        const s = state.secrets.find((s) => s.name === c.secret_names[0]);
        if (s) state.draft.secretId = s.id;
      }
      state.connAdvancedOpen = draftUsesAdvancedFields(state.draft, state.connType);
      render(); focusField('f-cname'); break;
    }
    case 'draft-test-disable-tls':
      captureDrafts();
      state.draft.sslmode = 'disable';
      state.draft.sslmodeIsAutomatic = false;
      state.draftTest = null;
      state.draftTestOverride = false;
      render();
      break;
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
      else if (menuId === 'f-sslmode') {
        state.draft.sslmode = id;
        state.draft.sslmodeIsAutomatic = false;
        // A changed TLS mode voids the failed verdict: the next Add re-tests.
        state.draftTest = null;
        state.draftTestOverride = false;
      }
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
      } else if (id === NO_CREDENTIAL_OPTION) {
        state.draft.secretSource = 'none';
        state.draft.secretId = null;
      } else {
        state.draft.secretSource = 'existing';
        state.draft.secretId = id;
      }
      render(false);
      focusField(id === NEW_CREDENTIAL_OPTION ? 'c-new-secret-name' : 'c-secret');
      break;
    case 'save-conn': await saveConn(); break;
    case 'del-conn-ask': state.connMenuOpen = null; state.confirm = { kind: 'del-conn', id }; render(); break;
    case 'del-conn-from-edit':
      closeSheet();
      state.confirm = { kind: 'del-conn', id };
      render();
      break;
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
        // An oauthApp template's scope override and authorize params must
        // ride reauth too, or the retry asks for every advertised scope
        // and (for Google) comes back without a refresh token. The client
        // ID itself is recovered broker-side from the stored grant.
        ...(template?.oauthApp ? {
          oauth_scope: template.oauthApp.scopes?.join(' ') || null,
          extra_auth_params: template.oauthApp.extraAuthParams ?? [],
        } : {}),
      });
      break;
    }
    case 'act-filter-issues':
      state.activityIssuesOnly = !state.activityIssuesOnly;
      render(false);
      break;
    case 'act-filter-agent': {
      const value = btn.dataset.value || '';
      state.activityAgent = state.activityAgent === value ? null : value;
      render(false);
      break;
    }
    case 'oauth-scope-toggle': {
      captureDrafts();
      const entry = state.draft.entryId ? catalogEntryById(state.draft.entryId) : undefined;
      const preset = entry?.oauthPreset;
      if (!preset) break;
      const scope = btn.dataset.scope || '';
      const current = state.draft.oauthScopes ?? preset.scopes;
      state.draft.oauthScopes = current.includes(scope)
        ? current.filter((candidate) => candidate !== scope)
        : [...current, scope];
      render(false);
      break;
    }
    case 'oauth-reconnect': {
      state.connMenuOpen = null;
      toast('🌐 Approve access in your browser…');
      if (await run(() => invoke('oauth_reconnect', { id }))) {
        toast('🔌 Reconnected');
        await refresh('all');
      }
      break;
    }
    case 'wiring-tools': {
      const connection = state.connections.find((x) => x.id === btn.dataset.conn);
      if (!connection) break;
      state.sheet = { kind: 'wiring-tools' };
      state.wiringTools = {
        connectionId: connection.id,
        connectionName: connection.name,
        loading: true,
        selected: connection.agent_access.allowed_tools
          ? [...connection.agent_access.allowed_tools] : null,
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
      if (await run(() => invoke('set_allowed_tools', {
        connectionId: wt.connectionId, tools: wt.selected,
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
    case 'open-external-url':
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
      focusField(state.draft.origin?.trim() ? credentialFocusTarget() : 'f-origin');
      break;
    case 'mcp-auth-done':
      toast('🔌 Connected');
      closeSheet();
      await refresh('all');
      break;
    case 'enable-tool':
      await run(() => invoke('set_tool_access', { connectionId: btn.dataset.conn || '', enabled: true }));
      await refresh('all');
      break;
    case 'disable-tool':
      await run(() => invoke('set_tool_access', { connectionId: btn.dataset.conn || '', enabled: false }));
      toast('🔌 Disabled for agents'); await refresh('all');
      break;

    case 'rotate-key-ask': {
      if (state.agentMenuOpen) { state.agentMenuOpen = null; render(); }
      // The OS authentication sheet is both the warning and the gate: its
      // reason text carries the consequences, so nothing precedes it.
      if (await run(() => invoke('rotate_key'))) {
        toast('🔑 Key rotated — agents reconnect from the token file'); await refresh('all');
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
    case 'set-presence-window':
      {
        const secs = Number(id);
        if (secs !== state.settings.presence_window_secs
            && await run(() => invoke('set_presence_window', { secs }))) {
          state.settings.presence_window_secs = secs;
          const label = secs === 15 * 60 ? '15 minutes' : secs === 60 * 60 ? '1 hour' : '2 hours';
          toast(`🔓 Stays unlocked for ${label} after confirming`);
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
    resetScroll();
    return;
  }
  if (e.key === 'Escape') {
    if (state.catalogActionMenuOpen) { state.catalogActionMenuOpen = null; render(); return; }
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

/** Sync the rendered TLS-mode select with the draft without a re-render
 * (the host field keeps focus while the prefill tracks it). */
function updateSslmodeField(): void {
  const trigger = document.getElementById('f-sslmode') as HTMLButtonElement | null;
  if (!trigger) return;
  const sslmode = state.draft.sslmode || 'verify-full';
  trigger.value = sslmode;
  const label = trigger.querySelector('.cred-name');
  const option = PG_SSL_OPTIONS.find(([value]) => value === sslmode);
  if (label && option) label.textContent = option[1];
}

function updateAutomaticConnectionName(): void {
  if (state.sheet?.kind !== 'add-conn' || !state.draft.nameIsAutomatic) return;
  const input = document.getElementById('f-cname') as HTMLInputElement | null;
  if (!input) return;
  const name = automaticConnectionName();
  state.draft.name = name;
  input.value = name;
  updateCredentialNamePlaceholder(name);
  updateCredentialNameWarning();
  updateToolNameWarning();
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
    state.toolsOpen = [];
    render();
    return;
  }
  if (target?.id === 'secret-search') {
    state.secretSearch = target.value;
    state.toolsOpen = [];
    render();
    return;
  }
  if (target?.id === 'activity-search') {
    state.activityQuery = target.value;
    render();
    return;
  }
  if (target?.id === 'f-cname') {
    state.draft.name = target.value;
    state.draft.nameIsAutomatic = false;
    updateCredentialNamePlaceholder(target.value);
    updateCredentialNameWarning();
    updateToolNameWarning();
  }
  if (target?.id === 'f-user') {
    state.draft.user = target.value;
    updateAutomaticConnectionName();
  }
  if (target?.id === 'f-host') {
    state.draft.host = target.value;
    updateAutomaticConnectionName();
    if (state.sheet?.kind === 'add-conn' && state.connType === 'pg'
        && applyLoopbackTlsPrefill(state.draft)) {
      updateSslmodeField();
    }
  }
  if (target?.id === 'f-port') {
    state.draft.port = target.value;
    updateAutomaticConnectionName();
  }
  if (target?.id === 'c-new-secret-name') updateCredentialNameWarning();
  // Any edit to the add form disarms a failed draft test's override: the
  // details changed, so the next Add tests the new details instead of
  // saving unverified. The stale verdict stays visible until then.
  if (target && state.sheet?.kind === 'add-conn' && state.draftTestOverride) {
    state.draftTestOverride = false;
  }
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
  // Which broker this app manages decides everything else about boot.
  try { state.broker = await invoke('get_broker_profile'); } catch (e) { console.error(e); }
  // Choose the landing tab before the first paint: nothing configured yet
  // means the walkthrough is the useful screen.
  await Promise.all([
    loadLocalUsername(),
    load('connections', 'list_connections'),
    loadIdentity(),
  ]);
  if (mode !== 'dropdown' && !state.connections.length) {
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
  await listen('aka://broker-changed', async (ev) => {
    // "Same broker" means mode AND url: a switch from connected remote A to
    // connected remote B must refetch, not keep A's data labeled as B.
    const wasConnected = state.broker.connected
      && state.broker.mode === ev.payload.mode
      && state.broker.url === ev.payload.url;
    state.broker = ev.payload;
    // A link that just came (back) up: refetch everything rather than
    // trusting whatever was on screen for the previous broker.
    if (ev.payload.connected && !wasConnected) {
      await refresh('all');
      try { state.agentSetupInstructions = await invoke('get_agent_setup'); } catch { /* pane shows loading */ }
    }
    render();
  });
  // The boot fetches above ran before that listener existed, and events are
  // not queued for later listeners: a saved-remote probe finishing inside
  // that window (either way) was silently dropped, which would pin the
  // "Connecting…" takeover forever. Re-fetch the profile now that changes
  // are observed — unless an event already delivered a fresher one.
  {
    const bootProfile = state.broker;
    try {
      const profile = await invoke('get_broker_profile');
      if (state.broker === bootProfile) {
        const cameUp = profile.connected
          && !(bootProfile.connected && bootProfile.mode === profile.mode && bootProfile.url === profile.url);
        state.broker = profile;
        if (cameUp) {
          await refresh('all');
          try { state.agentSetupInstructions = await invoke('get_agent_setup'); } catch { /* pane shows loading */ }
        }
        render();
      }
    } catch (e) { console.error(e); }
  }
  await listen('aka://sessions-changed', () => refresh('sessions'));
  await listen('aka://elicitations-changed', async () => {
    await refresh('elicitations');
    // The open dialog's request may have been answered elsewhere or
    // expired; the sheet re-renders as "gone" via elicitationSheet, which
    // is correct — nothing to close here, the user dismisses it informed.
  });
  await listen('aka://agents-changed', async () => {
    // Fires when an agent fetches the shared key (compat pair) or the key
    // rotates; the Paired audit entry carries the who.
    await loadIdentity();
    render();
  });
  await listen('aka://wirings-changed', () => refreshAgentsView());
  // A core-side connection change (a trust-on-first-use host-key pin) has no
  // originating UI command to refresh after; reload the services list.
  await listen('aka://connections-changed', () => refresh('connections'));
  await listen('aka://activity-appended', (ev) => receiveActivity(ev.payload));
  await listen('aka://mcp-auth-changed', (ev) => receiveMcpAuth(ev.payload));
  await listen('aka://connect-requested', (ev) => {
    // An agent asked for a tool that isn't configured: land the user on
    // the catalog with the ask prefilled. A request only — adding and
    // wiring stays entirely in the user's hands.
    const { agent, service } = ev.payload;
    state.tab = 'connections';
    state.toolSearch = service;
    state.toolsOpen = [];
    toast(`🤖 ${agent} asked to connect “${service}”`);
    render();
  });
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
    state.catalogActionMenuOpen = null;
    state.agentMenuOpen = null;
    state.connMenuOpen = null;
    render();
  });
}
boot();
