// AgentMFA React frontend. One file drives all Tauri windows (main, tray
// and dropdown), chosen from location.hash.
//
// Every mutation and read goes through the Rust core via Tauri
// commands; the webview never holds a secret value. When run outside
// Tauri (a plain browser), a dev mock stands in for the core so the
// UI is developable standalone.

import { invoke, listen, mode } from '/src/bridge';
import { QueryClientProvider } from '@tanstack/react-query';
import DOMPurify from 'dompurify';
import parse, { attributesToProps, domToReact, Element as ParsedElement } from 'html-react-parser';
import type { DOMNode, HTMLReactParserOptions } from 'html-react-parser';
import {
  createElement, StrictMode, useEffect, useLayoutEffect, useMemo, useRef, useState,
} from 'react';
import type { ReactNode } from 'react';
import { createPortal, flushSync } from 'react-dom';
import { createRoot } from 'react-dom/client';
import {
  CATALOG_SECTIONS, canQuickConnectMcp, catalogEntryById, catalogNameForType,
  collapsedCatalogGroup, connectedCatalogFirst, connectionEditPresentation,
  connectionsForEntry, entryForConnection, mcpTemplateForConnection, visibleCatalog,
} from '/src/catalog';
import type { ConnectionPreset } from '/src/catalog';
import {
  CLI_INSTALL_COMMAND, CONNECT_CLIENTS, CONNECT_MODE_LABELS, START_OPTIONS, clientMatchesLabel,
  connectClientById, connectModesFor, directEndpointAddress, directStartTask,
  resolveConnectMode,
  connectGuideSteps, sshDirectCommand, sshInvocationCommand, startKindLabel,
  startOptionById, startProgress, startTask,
} from '/src/getting-started';
import type {
  ConnectClient, ConnectClientEnv, ConnectModeId, ConnectStep, Platform, StartOption,
  StartProgress,
} from '/src/getting-started';
import type { CatalogEntry } from '/src/catalog';
import {
  ICONS, TYPES, esc, escAttr, toast, relTime, absTime, timeLeft, clockTime,
} from '/src/util';
import {
  apiOriginFromParts, authTemplate, defaultConnectionName, parseApiOrigin, parseConnectionImport,
  insecureNonLoopbackHttp, isLoopbackHost, parseMcpServerUrl,
  quickSetupPlaceholder, shouldResolveSshImport, sshImportFromPreview, suggestedSecretName,
} from '/src/connection-input';
import { ENDPOINT_FORMATS } from '/src/endpoint-formats';
import {
  formErrorCode, formErrorDetail, formErrorKind, formErrorMessage, formErrorToast, inlineFormError,
  sentenceCase,
} from '/src/form-errors';
import {
  LOCAL_BROKER, brokerLabel, brokerTakeover, brokerTone, remoteEndpointCaution,
} from '/src/broker';
import { sameBrokerScope } from '/src/broker-scope';
import { activityIdentity } from '/src/activity';
import { activeRequestCount, activeRequests, anchorExpiry, recentRequests } from '/src/requests';
import { APP_VERSION } from '/src/version';
import { virtualListWindow } from '/src/virtual-list';
import type { HostKeyCandidate } from '/src/connection-input';
import type {
  ActivityEntry,
  Approval,
  ApprovalDecision,
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
  NotificationSettings,
  RequestRecord,
  IssuedEndpoint,
  SecretSummary,
  SessionSummary,
  Settings,
  TestErrorKind,
} from '/src/types';
import { queryClient, refetchBrokerQuery, removeBrokerQueries } from '/src/query-client';
import { UiStore, useUiRevision } from '/src/ui-store';

const EDIT_SECRET_MASK = '••••••••••••';
/** How much of the log a view read asks the broker for. Matches the broker's
 * own ceiling (ACTIVITY_VIEW_LIMIT), which clamps anything larger. The list
 * windows its rows, so this bounds the read and the filter scope rather than
 * how many rows are mounted. */
const ACTIVITY_RENDER_LIMIT = 500;
/** Rows kept mounted past each edge of the activity window. Enough that a
 * flick of the wheel, or a row that turns out taller than its estimate, never
 * exposes a blank strip before the next frame. */
const ACTIVITY_OVERSCAN = 8;
/** Viewport assumed for the one render that precedes the first measurement.
 * Generously tall: over-mounting for a single pre-paint frame is invisible,
 * under-mounting would show a short list until the scroller is measured. */
const ACTIVITY_PREPAINT_VIEWPORT = 1200;

// The left-nav tabs, in order — also the cycle order for Ctrl-Tab.
const TABS = ['start', 'inbox', 'connections', 'secrets', 'activity'] as const;
// The tray dropdown is a quick-access panel; onboarding belongs in the window.
const DROPDOWN_TABS = TABS.filter((tab) => tab !== 'start');
type Tab = typeof TABS[number];

// The two Get started views: the intro walkthrough and the per-client
// connection guides (formerly the Connect tab).
const START_VIEWS = ['walkthrough', 'guides'] as const;
type StartView = typeof START_VIEWS[number];


interface SheetState {
  kind: 'add-secret' | 'edit-secret' | 'add-conn' | 'edit-conn' | 'settings' | 'clear-activity'
    | 'elicitation' | 'approval' | 'mcp-auth' | 'wiring-tools' | 'endpoint-issued';
  id?: string;
  /** Version of the connection whose values seeded an edit draft. */
  expectedUpdatedAt?: string;
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
  hostKeyCandidates?: HostKeyCandidate[];
  hostKeyCheckMessage?: string;
  hostKeyChecking?: boolean;
  /** The fingerprint was filled from a known_hosts lookup (not typed), so a
   * host/port change invalidates it along with the candidate list. */
  hostKeyAutoPinned?: boolean;
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
  /**
   * Passphrase for an encrypted SSH private key. Revealed only once the backend
   * says the offered key needs one, spent on the save that follows, and never
   * kept in the draft afterwards — it decrypts the key at import and has no
   * further role, because the vault is what protects a stored key.
   */
  keyPassphrase?: string;
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

interface ConnMenuPoint {
  x: number;
  y: number;
}

type LoadKey = 'secrets' | 'connections' | 'identity' | 'sessions' | 'activity' |
  'settings' | 'elicitations' | 'approvals' | 'requests';
interface LoadStatus {
  status: 'idle' | 'loading' | 'ready' | 'error';
  error?: string;
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
  /** The open elicitation dialog's field values, keyed by field name. */
  elicitValues: Record<string, string>;
  /** Agent traffic parked on a decision: it moves only once answered. */
  approvals: Approval[];
  /** Broker-owned request decision lifecycle history. */
  requests: RequestRecord[];
  /** One approval response in flight; prevents duplicate native prompts/actions. */
  approvalAnswering: string | null;
  agentSetupInstructions: string;
  settings: Settings;
  /** Native request notifications for this desktop shell, not the broker. */
  notificationSettings: NotificationSettings;
  /** Per-resource read health. Failed reads must never masquerade as empty data. */
  loadStatus: Record<LoadKey, LoadStatus>;
  reveal: Record<string, string>;
  /** Direct-endpoint fields expanded from their masked one-liner, by connection id. */
  epExpanded: Record<string, boolean>;
  /**
   * An issued SSH endpoint's agent socket path, by connection id.
   *
   * Connection summaries do not carry it. The filename is derived from the
   * endpoint secret precisely so the socket cannot be found by listing a
   * directory — the ssh-agent protocol has nowhere to present a credential, so
   * whoever opens the socket gets signatures — which means only the broker,
   * holding the vault, can name it. Read back per connection and cached here.
   */
  sshSockets: Record<string, string>;
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
  /** Pointer anchor for a row's right-click menu. Null means the same menu
   * is anchored to the detail panel's ellipsis button instead. */
  connMenuPoint: ConnMenuPoint | null;
  /** Tools tab: the catalog "add" view is open (the flat list otherwise). */
  addToolOpen: boolean;
  /** Tools tab: the connection whose detail panel is shown (null falls
   * back to the first row that needs attention, then the first row). */
  selectedConn: string | null;
  /** Narrow layout only: the detail panel is open as a slide-over. */
  connDetailOpen: boolean;
  copied: string | null;
  readyCopied: boolean;
  connectionReady: ConnectionReadyState | null;
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
  /** Request-history filters and expanded rows, local to this broker view. */
  requestQuery: string;
  requestAgent: string | null;
  requestIssuesOnly: boolean;
  expandedRequests: string[];
}

interface WiringToolsState {
  connectionId: string;
  connectionName: string;
  loading: boolean;
  error?: string;
  tools?: McpToolInfo[];
  stale?: boolean;
  fetchedAt?: string;
  cacheAgeSeconds?: number;
  truncated?: boolean;
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
  kind?: TestErrorKind;
}

/* ------------------------------ local state ------------------------------ */
const DEFAULT_SETTINGS: Settings = {
  reauth_on_read: true,
  menu_bar_hides_dock: false,
  presence_window_secs: 15 * 60,
};
const DEFAULT_NOTIFICATION_SETTINGS: NotificationSettings = {
  mode: 'when_hidden',
  showContext: false,
  available: true,
  canOpenSystemSettings: false,
};
const DEFAULT_LOAD_STATUS = (): Record<LoadKey, LoadStatus> => ({
  secrets: { status: 'idle' },
  connections: { status: 'idle' },
  identity: { status: 'idle' },
  sessions: { status: 'idle' },
  activity: { status: 'idle' },
  settings: { status: 'idle' },
  elicitations: { status: 'idle' },
  approvals: { status: 'idle' },
  requests: { status: 'idle' },
});

const initialState: AppState = {
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
  elicitValues: {},      // open elicitation dialog's field values (transient)
  approvals: [],         // agent traffic parked on the user's confirmation
  requests: [],          // bounded request history, including terminal records
  approvalAnswering: null,
  agentSetupInstructions: '', // short paste-ready setup message (lazy-loaded)
  settings: { ...DEFAULT_SETTINGS },
  notificationSettings: { ...DEFAULT_NOTIFICATION_SETTINGS },
  loadStatus: DEFAULT_LOAD_STATUS(),
  reveal: {},            // secretId -> prefix string (transient)
  epExpanded: {},        // connId -> endpoint field expanded (transient)
  sshSockets: {},        // connId -> issued SSH agent socket path (read back)
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
  connMenuPoint: null,   // right-click pointer anchor; null uses the ⋯ button
  addToolOpen: false,    // Tools tab: catalog add-view open (flat list otherwise)
  selectedConn: null,    // Tools tab: detail-panel selection (null = automatic)
  connDetailOpen: false, // narrow layout: detail panel open as a slide-over

  copied: null,          // secretId whose value was just copied (transient "Copied" flash)
  readyCopied: false,    // transient feedback on the setup-instructions status button
  connectionReady: null,
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
  requestQuery: '',
  requestAgent: null,
  requestIssuesOnly: false,
  expandedRequests: [],
};

const uiStore = new UiStore(initialState);
const state = uiStore.state;
let reactMounted = false;
let renderPublication = 0;
/** Cancels the one pending post-render fix-up, if any. */
let cancelPendingFinish: (() => void) | null = null;
/** Scroll snapshot awaiting restore; `resetScroll` clears it so a deferred
 * restore cannot undo an explicit scroll-to-top. */
let pendingScroll: Array<[string, Element, number]> | null = null;
/** Changes only when broker identity changes. Async work captures this value
 * so a result from an earlier backend cannot update the current broker's UI.
 * Link-state changes within that scope do not invalidate useful reads. */
let brokerEpoch = 0;
/** Changes whenever another webview saves this desktop's notification
 * preferences. It prevents an older in-flight read from overwriting the
 * event's newer value. */
let notificationSettingsEpoch = 0;
/** A dropdown form holds a renewable native lease. The native side also
 * expires it, so a webview crash or reload cannot strand the panel. */
let dropdownFormHeartbeat: number | null = null;
/** Pointer-drag preview state. The connection rows render this order through
 * React; drag handlers never move React-owned DOM nodes themselves. */
let dragConnId: string | null = null;
let dragConnOrder: string[] | null = null;
let connectionReorderGeneration = 0;
/** False until boot() has loaded the first broker data; AppRoot keeps
 * showing the loading splash instead of painting an empty window. */
let booted = false;

function brokerEpochIsCurrent(epoch: number): boolean {
  return epoch === brokerEpoch;
}

function clearBrokerOwnedState(): void {
  if (state.sheet) releaseDropdownForm();
  state.secrets = [];
  state.connections = [];
  state.identity = null;
  state.sessions = [];
  state.activity = [];
  state.elicitations = [];
  state.elicitValues = {};
  state.approvals = [];
  state.requests = [];
  state.approvalAnswering = null;
  state.agentSetupInstructions = '';
  state.settings = { ...DEFAULT_SETTINGS };
  state.loadStatus = DEFAULT_LOAD_STATUS();
  state.reveal = {};
  state.epExpanded = {};
  state.sshSockets = {};
  setSheet(null);
  state.draft = {};
  state.sheetErrors = {};
  state.sheetBaseline = null;
  state.confirmDiscard = false;
  state.formMenuOpen = null;
  state.confirm = null;
  state.connPreset = null;
  state.connEntryName = null;
  state.selectedConn = null;
  state.connMenuOpen = null;
  state.connMenuPoint = null;
  state.connectionReady = null;
  state.connTests = {};
  state.draftTest = null;
  state.draftTestOverride = false;
  state.mcpAuth = null;
  state.mcpAuthDraft = null;
  state.mcpAuthOpenedUrl = null;
  state.mcpStatus = {};
  state.wiringTools = null;
  // View-local filters and panel state also describe the old broker's data:
  // an agent filter from broker A would silently empty broker B's activity.
  state.activityQuery = '';
  state.activityAgent = null;
  state.activityIssuesOnly = false;
  state.requestQuery = '';
  state.requestAgent = null;
  state.requestIssuesOnly = false;
  state.expandedRequests = [];
  state.toolSearch = '';
  state.secretSearch = '';
  state.sectionsExpanded = [];
  state.connDetailOpen = false;
  dragConnId = null;
  dragConnOrder = null;
}

/** The one place sheet transitions happen, so a future cross-cutting
 * concern (analytics, focus policy) has a single seam. */
function setSheet(sheet: SheetState | null): void {
  state.sheet = sheet;
}

/** Change broker identity without ever showing the previous broker's data under it. */
function setBrokerProfile(profile: BrokerProfile): void {
  const scopeChanged = !sameBrokerScope(state.broker, profile);
  if (scopeChanged) brokerEpoch += 1;
  if (scopeChanged) {
    removeBrokerQueries(state.broker);
    clearBrokerOwnedState();
  }
  state.broker = profile;
}

// With in-place reconciliation, scroll positions and focus normally survive
// a render because the DOM nodes themselves survive. The snapshots below are
// a safety net for the cases where React did replace a node (a key change,
// a subtree swap): restore compares element identity and only touches what
// was actually replaced.
const SCROLLERS = ['.content', '.dd-global', '.conn-detail-pane'];
function captureScroll(): Array<[string, Element, number]> {
  return SCROLLERS.flatMap((sel): Array<[string, Element, number]> => {
    const el = document.querySelector(sel);
    return el && el.scrollTop ? [[sel, el, el.scrollTop]] : [];
  });
}
function restoreScroll(saved: Array<[string, Element, number]>): void {
  for (const [sel, el, top] of saved) {
    const now = document.querySelector(sel);
    if (now && now !== el) now.scrollTop = top;
  }
}
/** Switching tabs should start at the top, not inherit the old offset. */
function resetScroll(): void {
  // A deferred restore from the render this reset follows must not re-apply
  // the pre-switch offset onto the new view's scroller.
  pendingScroll = null;
  for (const sel of SCROLLERS) {
    const el = document.querySelector(sel);
    if (el) el.scrollTop = 0;
  }
}

function clearSensitivePresentation(): boolean {
  const changed = Object.keys(state.reveal).length > 0 || Object.keys(state.epExpanded).length > 0;
  state.reveal = {};
  state.epExpanded = {};
  return changed;
}

function showRequestInbox(): void {
  clearSensitivePresentation();
  state.tab = 'inbox';
  state.confirm = null;
  state.menuOpen = false;
  state.agentMenuOpen = null;
  state.catalogActionMenuOpen = null;
  state.connMenuOpen = null;
  state.connMenuPoint = null;
  state.connDetailOpen = false;
  render();
  resetScroll();
}

async function consumePendingOpenRequests(): Promise<void> {
  if (state.sheet) return;
  try {
    if (await invoke('ui_take_open_requests')) showRequestInbox();
  } catch (error) {
    console.error('ui_take_open_requests', error);
  }
}

const root = (): HTMLElement => {
  const element = document.getElementById('root');
  if (!element) throw new Error('Missing #root element');
  return element;
};
/** Portal target for fixed-position overlays (the credential listbox).
 * A sibling of #root, so React-managed children and manually positioned
 * DOM never share a container. */
const overlays = (): HTMLElement => {
  const element = document.getElementById('overlays');
  if (!element) throw new Error('Missing #overlays element');
  return element;
};
/* ------------------------------ data loading ----------------------------- */
type RefreshTarget = 'all' | 'secrets' | 'connections' | 'identity' | 'sessions' |
  'activity' | 'settings' | 'elicitations' | 'approvals' | 'requests';

function markLocalBrokerUnavailable(): void {
  if (state.broker.mode !== 'local') return;
  setBrokerProfile({
    ...state.broker,
    connected: false,
    error: 'The local broker did not answer. Your stored data has not been replaced or cleared.',
  });
}

async function refresh(which: RefreshTarget = 'all'): Promise<boolean> {
  const jobs: Promise<boolean>[] = [];
  if (which === 'all' || which === 'secrets') jobs.push(load('secrets', 'list_secrets'));
  if (which === 'all' || which === 'connections') jobs.push(load('connections', 'list_connections'));
  if (which === 'all' || which === 'identity') jobs.push(loadIdentity());
  if (which === 'all' || which === 'sessions') jobs.push(load('sessions', 'list_sessions'));
  if (which === 'all' || which === 'elicitations') jobs.push(load('elicitations', 'list_elicitations'));
  if (which === 'all' || which === 'approvals') jobs.push(load('approvals', 'list_approvals'));
  if (which === 'all' || which === 'requests') jobs.push(load('requests', 'list_requests'));
  if (which === 'all' || which === 'activity') {
    jobs.push(load('activity', 'list_activity', { limit: ACTIVITY_RENDER_LIMIT }));
  }
  if (which === 'all' || which === 'settings') jobs.push(loadSettings());
  const succeeded = (await Promise.all(jobs)).every(Boolean);
  // Connections is the local broker's liveness signal. A peripheral read can
  // fail independently and already has a per-view error band; it must not
  // blank the whole app or prevent recovery from the takeover screen.
  const touchedConnections = which === 'all' || which === 'connections';
  if (
    touchedConnections
    && state.broker.mode === 'local'
    && !state.broker.connected
    && state.loadStatus.connections.status === 'ready'
  ) {
    setBrokerProfile({ ...state.broker, connected: true, error: null });
  }
  render();
  return succeeded;
}
async function load<K extends CommandName>(
  key: LoadKey,
  cmd: K,
  args?: CommandArgs<K>,
): Promise<boolean> {
  const broker = state.broker;
  const epoch = brokerEpoch;
  state.loadStatus[key] = { status: 'loading' };
  try {
    const result: unknown = await refetchBrokerQuery(broker, cmd, args);
    if (!brokerEpochIsCurrent(epoch)) return false;
    switch (key) {
      case 'secrets': state.secrets = result as SecretSummary[]; break;
      case 'connections':
        state.connections = result as ConnectionSummary[];
        // Not awaited: the list paints immediately and the SSH addresses fill
        // in behind it. Each is a vault read, so this must not gate a refresh.
        void resolveSshEndpointSockets(broker, epoch);
        break;
      case 'sessions': state.sessions = result as SessionSummary[]; break;
      case 'activity': state.activity = result as ActivityEntry[]; break;
      // Deadlines are re-anchored to this machine's clock at receipt, so a
      // remote broker's clock offset cannot distort the countdowns.
      case 'elicitations':
        state.elicitations = anchorExpiry(result as ElicitationRequest[]);
        break;
      case 'approvals': state.approvals = anchorExpiry(result as Approval[]); break;
      case 'requests': state.requests = anchorExpiry(result as RequestRecord[]); break;
    }
    state.loadStatus[key] = { status: 'ready' };
    return true;
  } catch (error) {
    console.error(cmd, error);
    if (!brokerEpochIsCurrent(epoch)) return false;
    state.loadStatus[key] = { status: 'error', error: errorMessage(error) };
    if (key === 'connections') markLocalBrokerUnavailable();
    return false;
  }
}
/**
 * Fill `state.sshSockets` for every SSH connection with an issued endpoint.
 *
 * The socket's filename is derived from the endpoint secret so that the path
 * cannot be found by listing `~/.aka/endpoints`, which means the connection
 * list — built without touching the vault — cannot carry it. `get_endpoint`
 * can: it is the ungated display read (no native sheet, no audit entry), so
 * running it in the background on every list refresh is safe — the gate and
 * the "copied" audit live on the separate copy path the Copy buttons take.
 * Cached because the path is stable until the endpoint is reissued, and
 * re-read on every list refresh so a reissue lands.
 */
async function resolveSshEndpointSockets(broker: BrokerProfile, epoch: number): Promise<void> {
  const wanted = state.connections.filter((c) => c.type === 'ssh' && c.agent_access.endpoint);
  if (!wanted.length) {
    if (Object.keys(state.sshSockets).length) {
      state.sshSockets = {};
      render();
    }
    return;
  }
  const resolved: Record<string, string> = {};
  for (const conn of wanted) {
    try {
      const issued = await refetchBrokerQuery(broker, 'get_endpoint', { connectionId: conn.id });
      if (!brokerEpochIsCurrent(epoch)) return;
      if (issued?.dsn) resolved[conn.id] = issued.dsn;
    } catch (error) {
      console.error('get_endpoint', error);
    }
  }
  if (!brokerEpochIsCurrent(epoch)) return;
  const changed = Object.keys(resolved).length !== Object.keys(state.sshSockets).length
    || Object.entries(resolved).some(([id, sock]) => state.sshSockets[id] !== sock);
  if (!changed) return;
  state.sshSockets = resolved;
  render();
}
/**
 * The issued SSH agent socket for `conn`, reading it back if the cache is cold.
 *
 * The cached copy arrives a beat after the connection list, so a click that
 * lands in that window would otherwise find nothing to copy. The read is the
 * same one `resolveSshEndpointSockets` makes; it populates the cache too.
 */
async function sshEndpointSocket(conn: ConnectionSummary): Promise<string | null> {
  const cached = state.sshSockets[conn.id];
  if (cached) return cached;
  if (!conn.agent_access.endpoint) return null;
  try {
    const issued = await invoke('get_endpoint', { connectionId: conn.id });
    if (!issued?.dsn) return null;
    state.sshSockets = { ...state.sshSockets, [conn.id]: issued.dsn };
    return issued.dsn;
  } catch (error) {
    console.error('get_endpoint', error);
    return null;
  }
}
async function loadSettings(): Promise<boolean> {
  const broker = state.broker;
  const epoch = brokerEpoch;
  state.loadStatus.settings = { status: 'loading' };
  try {
    const settings = await refetchBrokerQuery(broker, 'get_settings');
    if (!brokerEpochIsCurrent(epoch)) return false;
    state.settings = settings;
    state.loadStatus.settings = { status: 'ready' };
    return true;
  } catch (error) {
    console.error(error);
    if (!brokerEpochIsCurrent(epoch)) return false;
    state.loadStatus.settings = { status: 'error', error: errorMessage(error) };
    return false;
  }
}
async function loadNotificationSettings(): Promise<void> {
  const epoch = notificationSettingsEpoch;
  try {
    const settings = await invoke('get_notification_settings');
    if (epoch === notificationSettingsEpoch) state.notificationSettings = settings;
  }
  catch (e) { console.error('get_notification_settings', e); }
}
async function loadLocalUsername(): Promise<void> {
  try { state.localUsername = await invoke('get_local_username'); }
  catch (e) { console.error('get_local_username', e); }
}
async function loadIdentity(): Promise<boolean> {
  const broker = state.broker;
  const epoch = brokerEpoch;
  state.loadStatus.identity = { status: 'loading' };
  try {
    const identity = await refetchBrokerQuery(broker, 'get_identity');
    if (!brokerEpochIsCurrent(epoch)) return false;
    state.identity = identity;
    state.loadStatus.identity = { status: 'ready' };
    return true;
  } catch (error) {
    console.error('get_identity', error);
    if (!brokerEpochIsCurrent(epoch)) return false;
    state.loadStatus.identity = { status: 'error', error: errorMessage(error) };
    return false;
  }
}
async function loadAgentSetup(): Promise<void> {
  const broker = state.broker;
  const epoch = brokerEpoch;
  const instructions = await refetchBrokerQuery(broker, 'get_agent_setup');
  if (brokerEpochIsCurrent(epoch)) state.agentSetupInstructions = instructions;
}
async function refreshAgentsView(): Promise<void> {
  await Promise.all([
    load('connections', 'list_connections'),
    loadIdentity(),
  ]);
  render();
}

/* --------------------------------- render -------------------------------- */
// The action layer publishes one external-store revision per logical update.
// React owns #root and reconciles in place; form fields are controlled, so
// focus, selection, and scroll normally survive a render untouched. The
// snapshots here are a safety net for transitions that replace the focused
// control with another instance carrying the same id; restore runs only when
// that actually happened.
function render(): void {
  const active = document.activeElement instanceof HTMLInputElement ||
    document.activeElement instanceof HTMLTextAreaElement
    ? document.activeElement
    : null;
  const focusId = active && active.id ? active.id : null;
  const sel = active && focusId && typeof active.selectionStart === 'number'
    ? { start: active.selectionStart, end: active.selectionEnd, dir: active.selectionDirection }
    : null;
  const scroll = captureScroll();

  if (reactMounted) {
    // Ordinary external-store publications stay on React's scheduler. The
    // initial root mount below remains synchronous so startup never flashes
    // an empty shell. Exactly one deferred fix-up is pending at a time —
    // the superseded one is cancelled, not left to accumulate (the hidden
    // dropdown renders on every broker event, and an animation frame never
    // fires while the document is hidden, so uncancelled callbacks would
    // pile up retaining detached DOM). While hidden, a zero timeout stands
    // in for the frame that will not come.
    const publication = ++renderPublication;
    uiStore.publish();
    cancelPendingFinish?.();
    pendingScroll = scroll;
    const finish = () => {
      cancelPendingFinish = null;
      if (publication !== renderPublication) return;
      finishRender(active, focusId, sel, pendingScroll ?? []);
      pendingScroll = null;
    };
    if (document.hidden) {
      const handle = setTimeout(finish, 0);
      cancelPendingFinish = () => clearTimeout(handle);
    } else {
      const handle = requestAnimationFrame(finish);
      cancelPendingFinish = () => cancelAnimationFrame(handle);
    }
    return;
  }

  finishRender(active, focusId, sel, scroll);
}

function finishRender(
  active: HTMLInputElement | HTMLTextAreaElement | null,
  focusId: string | null,
  sel: { start: number; end: number | null; dir: 'forward' | 'backward' | 'none' | null } | null,
  scroll: Array<[string, Element, number]>,
): void {
  restoreScroll(scroll);

  // The focused control survived (still focused): leave it alone. Restore
  // only when React replaced it — the old node lost focus, but its
  // same-id successor should carry on as if it hadn't.
  if (focusId && document.activeElement !== active) {
    const el = document.getElementById(focusId) as HTMLInputElement | HTMLTextAreaElement | null;
    if (el) {
      el.focus();
      if (sel && typeof el.setSelectionRange === 'function') {
        try { el.setSelectionRange(sel.start, sel.end, sel.dir || 'none'); } catch { /* non-text input */ }
      }
    }
  }

  if (state.formMenuOpen) positionFormMenu();
  if (state.connMenuPoint) positionConnContextMenu();

  // First render of a connection sheet: snapshot the draft so cancelling
  // can detect real edits.
  if (state.sheet && (state.sheet.kind === 'add-conn' || state.sheet.kind === 'edit-conn') &&
      state.sheetBaseline === null) {
    state.sheetBaseline = connDraftSignature();
  }
}

/**
 * What one prompt is asking about, in the words of the connection's own
 * plane. Postgres cannot be confirmed per statement — the proxy splices
 * bytes once connected — so it asks per session, and saying so is what
 * makes "Approve" mean something specific.
 */
function approvalUnit(approval: Approval): string {
  if (approval.unit === 'session' || approval.type === 'pg') {
    return 'wants to open a database session';
  }
  if (approval.unit === 'login' || approval.type === 'ssh') {
    return 'wants to log in over SSH';
  }
  if (approval.unit === 'tool') return 'wants to call a tool';
  if (approval.unit === 'request') return 'wants to send a request';
  // Compatibility with brokers from before the explicit unit was added:
  // "request" remains true even for a tool call, while guessing from the
  // connection would mislabel generic HTTP traffic on an MCP connection.
  return 'wants to send a request';
}

/**
 * Attribution for a prompt or history row. The broker's direct-endpoint
 * planes report the literal agent label `endpoint` — an audit-stable wire
 * value, not prose — so spell that one out instead of rendering
 * "endpoint wants to send a request". Every other label is the agent's
 * self-reported name, shown as sent.
 */
function agentLabel(agent: string): string {
  return agent === 'endpoint'
    ? 'A direct endpoint client'
    : `Agent reported as “${agent}”`;
}

/** A broker that predates the `required` flag omits it entirely, and the UI
 * it shipped against required every field — so absence stays required, and
 * only an explicit `false` marks a field optional. */
const elicitFieldRequired = (field: { required?: boolean }): boolean => field.required !== false;

function requestOutcome(record: RequestRecord): {
  label: string;
  detail: string;
  icon: string;
  tone: string;
} {
  const minutes = Math.max(1, Math.round((record.window_secs ?? 900) / 60));
  switch (record.resolution) {
    case 'approved_for_window':
      return {
        label: 'Approved',
        detail: `Allowed for ${minutes} minute${minutes === 1 ? '' : 's'}`,
        icon: ICONS.circleCheck,
        tone: 'success',
      };
    case 'approved_all':
    case 'confirmation_disabled':
      return {
        label: 'Approved',
        detail: 'Allowed and traffic confirmation turned off',
        icon: ICONS.circleCheck,
        tone: 'success',
      };
    case 'denied':
      return {
        label: 'Denied',
        detail: 'Refused by the user',
        icon: ICONS.circleX,
        tone: 'danger',
      };
    case 'timed_out':
      return {
        label: 'Expired',
        detail: 'No answer before the deadline',
        icon: ICONS.clockAlert,
        tone: 'muted',
      };
    case 'policy_changed':
      return {
        label: 'Revoked',
        detail: 'Access, destination, or broker authority changed',
        icon: ICONS.circleX,
        tone: 'danger',
      };
    case 'no_surface':
      return {
        label: 'Unavailable',
        detail: 'No connected surface could ask',
        icon: ICONS.clockAlert,
        tone: 'muted',
      };
    case 'waived':
      return {
        label: 'Approved',
        detail: 'Allowed by the attached confirmation surface',
        icon: ICONS.circleCheck,
        tone: 'success',
      };
    case 'caller_disconnected':
      return {
        label: 'Abandoned',
        detail: 'The caller disconnected before an answer',
        icon: ICONS.clockAlert,
        tone: 'muted',
      };
    case 'input_provided':
      return {
        label: 'Provided',
        detail: 'Input provided; the paused call resumed',
        icon: ICONS.circleCheck,
        tone: 'success',
      };
    case 'input_refused':
      return {
        label: 'Refused',
        detail: 'Input refused; the paused call was told no',
        icon: ICONS.circleX,
        tone: 'danger',
      };
    default: {
      const fallback = ({
        approved: ['Approved', ICONS.circleCheck, 'success'],
        denied: ['Denied', ICONS.circleX, 'danger'],
        expired: ['Expired', ICONS.clockAlert, 'muted'],
        revoked: ['Revoked', ICONS.circleX, 'danger'],
        unavailable: ['Unavailable', ICONS.clockAlert, 'muted'],
        abandoned: ['Abandoned', ICONS.clockAlert, 'muted'],
        pending: ['Pending', ICONS.clockAlert, 'muted'],
      } as Record<string, [string, string, string]>)[record.status]
        ?? ['Completed', ICONS.circleCheck, 'muted'];
      return {
        label: fallback[0],
        detail: fallback[0],
        icon: fallback[1],
        tone: fallback[2],
      };
    }
  }
}

function liveSessionsHTML(extraClass = ''): string {
  const sessions = state.sessions.map((session) => {
    const type = TYPES[session.type];
    const who = session.agent
      ? `${esc(session.agent)} → ${esc(session.connection)}`
      : esc(session.connection);
    if (state.confirm?.kind === 'close-session' && state.confirm.id === session.id) {
      return `<div class="live-row"><span class="badge ${type.cls}">${type.label}</span>
        <div class="live-txt"><div class="c-name">${who}</div>
        <div class="s-sub">Close this session now?</div></div>
        <button class="btn sm" data-act="confirm-cancel">Cancel</button>
        <button class="btn sm danger" data-act="close-session-confirm"
          data-id="${session.id}">Close</button></div>`;
    }
    return `<div class="live-row"><span class="badge ${type.cls}">${type.label}</span>
      <div class="live-txt"><div class="c-name">${who}</div>
      <div class="s-sub" title="${escAttr(session.detail)}">${esc(session.detail)}</div></div>
      <button class="btn sm" data-act="close-session-ask"
        data-id="${session.id}">Close</button></div>`;
  }).join('');
  return `<section class="live-sessions ${extraClass}" aria-label="Active sessions">
    <div class="live-head">Active sessions</div>
    <div class="live-list">${sessions}</div></section>`;
}

function globalSectionsHTML(embeddedInStart = false) {
  let out = '';
  const hasOnboarding = false;
  const requestCount = activeRequestCount(state.approvals, state.elicitations);
  const hasLiveSessions = state.tab === 'start'
    && state.startView === 'guides'
    && state.sessions.length > 0;
  // Requests keep a compact, persistent route from every other screen. Their
  // details and actions now live in the Inbox instead of being duplicated
  // above every tab.
  if (requestCount && state.tab !== 'inbox') {
    const requests = activeRequests(state.approvals, state.elicitations);
    const next = requests[0];
    const label = requestCount === 1 ? '1 request needs attention'
      : `${requestCount} requests need attention`;
    const kinds = [
      state.approvals.length
        ? `${state.approvals.length} approval${state.approvals.length === 1 ? '' : 's'}`
        : '',
      state.elicitations.length
        ? `${state.elicitations.length} input request${state.elicitations.length === 1 ? '' : 's'}`
        : '',
    ].filter(Boolean).join(' · ');
    out += `<button class="request-banner" data-act="open-inbox"
      aria-label="${escAttr(label)}. Open the Request Inbox.">
      <span class="request-banner-ico">${state.approvals.length ? ICONS.shieldAlert : ICONS.bell}</span>
      <span class="request-banner-copy"><b>${esc(label)}</b>
        <span>${esc(kinds)} · next expires ${esc(timeLeft(next.expiresAt))}</span></span>
      <span class="request-banner-cta">Open Inbox</span>
    </button>`;
  }
  // Live sessions answer "what is my agent doing right now?", so they sit
  // with the connection guides rather than above every screen.
  if (hasLiveSessions) {
    out += liveSessionsHTML();
  }
  const requestRouteOnly = requestCount > 0
    && state.tab !== 'inbox'
    && !hasLiveSessions
    && !hasOnboarding;
  return out
    ? `<div class="dd-global ${embeddedInStart ? 'start-global ' : ''}${
      hasOnboarding ? 'onboarding-global' : ''
    }${
      requestRouteOnly ? ' request-route-only' : ''
    }">${out}</div>`
    : '';
}

function RequestInbox(): ReactNode {
  const active = activeRequests(state.approvals, state.elicitations);
  const activeIds = new Set(active.map((request) => request.id));
  const allRecent = recentRequests(state.requests, activeIds);
  const requestAgents = [...new Set(allRecent.map((record) => record.agent).filter(Boolean))];
  const needle = state.requestQuery.trim().toLowerCase();
  const recent = allRecent.filter((record) => {
    if (state.requestAgent && record.agent !== state.requestAgent) return false;
    if (state.requestIssuesOnly && requestOutcome(record).tone === 'success') return false;
    if (!needle) return true;
    return record.summary.toLowerCase().includes(needle)
      || (record.detail || '').toLowerCase().includes(needle)
      || record.agent.toLowerCase().includes(needle)
      || record.connection.toLowerCase().includes(needle)
      || (record.target || '').toLowerCase().includes(needle);
  });
  const count = active.length;
  const empty = count === 0 && allRecent.length === 0;
  const unavailableRefusals = state.activity.filter((entry) =>
    entry.text.startsWith('Refused (nobody could confirm):')).length;
  return (
    <div className="request-inbox">
      {unavailableRefusals > 0
        ? <div className="request-surface-warning" role="status">
            <b>{unavailableRefusals} traffic confirmation
              {unavailableRefusals === 1 ? ' was' : 's were'} refused</b>
            <span>
              No approval surface was attached. This durable count comes from the Activity Log.
            </span>
          </div>
        : null}
      {empty
        ? <div className="empty request-empty">
            <div className="empty-ico"><Icon markup={ICONS.bell} /></div>
            <h3>No requests yet</h3>
            <p>Requests that need attention and outcomes from this broker session will appear here.</p>
          </div>
        : <>
            <section className="request-section" aria-labelledby="request-active-title">
              <div className="request-section-head">
                <h3 id="request-active-title">Needs attention</h3>
                <span className={`request-total ${count ? 'has-requests' : ''}`}>{count}</span>
              </div>
              {count === 0
                ? <div className="request-section-empty">Nothing is waiting on you.</div>
                : <div className="request-list">
                    {active.map((item) => {
                      if (item.kind === 'approval') {
                        const approval = item.approval;
                        const riders = approval.waiting > 1
                          ? `${approval.waiting} calls are waiting on this answer`
                          : '1 call is waiting on this answer';
                        return (
                          <button key={`approval:${approval.id}`}
                            className="request-card request-card-approval"
                            data-act="approval-open" data-id={approval.id}>
                            <span className="request-card-ico"><Icon markup={ICONS.shieldAlert} /></span>
                            <span className="request-card-body">
                              <span className="request-card-top">
                                <span className="request-kind">Approval</span>
                              </span>
                              <b className="untrusted-identity" dir="auto">
                                {agentLabel(approval.agent)} {approvalUnit(approval)}
                              </b>
                              <span className="request-context untrusted-identity" dir="auto">
                                {approval.connection} · {approval.target}
                              </span>
                              <code className="request-summary untrusted-identity" dir="auto">
                                {approval.summary}
                              </code>
                              <span className="request-foot">{riders}</span>
                            </span>
                            <span className="request-card-side">
                              <span className="request-when" title={absTime(approval.requested_at)}>
                                {relTime(approval.requested_at)} · expires in {timeLeft(approval.expires_at)}
                              </span>
                              <span className="request-card-action">Review</span>
                            </span>
                          </button>
                        );
                      }
                      const request = item.elicitation;
                      return (
                        <button key={`elicitation:${request.id}`}
                          className="request-card request-card-elicitation"
                          data-act="elicit-open" data-id={request.id}>
                          <span className="request-card-ico"><Icon markup={ICONS.bell} /></span>
                          <span className="request-card-body">
                            <span className="request-card-top">
                              <span className="request-kind">Input request</span>
                            </span>
                            <b className="untrusted-identity" dir="auto">
                              {agentLabel(request.agent)} says {request.connection} asked for input
                            </b>
                            <span className="request-context untrusted-identity" dir="auto">
                              {request.agent} is paused · {request.tool}
                            </span>
                            <span className="request-prompt untrusted-identity" dir="auto">
                              {request.prompt}
                            </span>
                          </span>
                          <span className="request-card-side">
                            <span className="request-when" title={absTime(request.requested_at)}>
                              {relTime(request.requested_at)} · expires in {timeLeft(request.expires_at)}
                            </span>
                            <span className="request-card-action">Answer</span>
                          </span>
                        </button>
                      );
                    })}
                  </div>}
            </section>
            <section className="request-section" aria-labelledby="request-recent-title">
              <div className="request-section-head">
                <h3 id="request-recent-title">Recent (this broker session)</h3>
                <span className="request-total">{allRecent.length}</span>
              </div>
              {allRecent.length > 0
                ? <div className="act-filters request-filters">
                    <input id="request-search" className="cat-search act-search" type="search"
                      placeholder="Filter requests…" aria-label="Filter request history"
                      value={state.requestQuery}
                      onChange={(e) => { state.requestQuery = e.currentTarget.value; render(); }} />
                    <button className={`seg-btn act-filter ${state.requestIssuesOnly ? 'on' : ''}`}
                      data-act="request-filter-issues">Issues</button>
                    {requestAgents.map((agent) => (
                      <button key={agent} dir="auto"
                        className={`seg-btn act-filter untrusted-identity ${
                          state.requestAgent === agent ? 'on' : ''}`}
                        data-act="request-filter-agent" data-value={agent}>{agent}</button>
                    ))}
                  </div>
                : null}
              {recent.length === 0
                ? <div className="request-section-empty">
                    {allRecent.length
                      ? 'Nothing matches these filters.'
                      : 'Resolved requests from this broker session will appear here.'}
                  </div>
                : <div className="request-list request-history-list">
                    {recent.map((record) => {
                      const outcome = requestOutcome(record);
                      const at = record.resolved_at ?? record.requested_at;
                      const key = `${record.kind}:${record.id}`;
                      const expanded = state.expandedRequests.includes(key);
                      const connectionAvailable = record.connection_id
                        && state.connections.some((connection) => connection.id === record.connection_id);
                      const context = [
                        agentLabel(record.agent),
                        record.connection,
                        record.target,
                      ].filter(Boolean).join(' · ');
                      return (
                        <article key={`${record.kind}:${record.id}`}
                          className={`request-card request-card-history ${outcome.tone}`}>
                          <button className="request-history-toggle"
                            data-act="request-history-toggle" data-id={key}
                            aria-expanded={expanded}>
                            <span className="request-card-ico"><Icon markup={outcome.icon} /></span>
                            <span className="request-card-body">
                              <span className="request-card-top">
                                <span className="request-kind">
                                  {record.kind === 'elicitation' ? 'Input request'
                                    : record.kind === 'approval' ? 'Approval' : 'Request'}
                                </span>
                                <span className="request-outcome">{outcome.label}</span>
                              </span>
                              <b>{outcome.detail}</b>
                              <span className="request-context untrusted-identity" dir="auto">
                                {context}
                              </span>
                              <code className="request-summary untrusted-identity" dir="auto">
                                {record.summary}
                              </code>
                              {record.waiting > 1
                                ? <span className="request-foot">
                                    {record.waiting} calls shared this decision
                                  </span>
                                : null}
                            </span>
                            <span className="request-card-side">
                              <span className="request-when" title={absTime(at)}>{relTime(at)}</span>
                              <span className="request-card-action">
                                {expanded ? 'Hide details' : 'Details'}
                              </span>
                            </span>
                          </button>
                          {expanded
                            ? <div className="request-history-detail">
                                <pre className="approval-detail untrusted-identity" dir="auto">
                                  {record.detail || record.summary}
                                </pre>
                                {connectionAvailable
                                  ? <button className="btn sm" data-act="request-open-connection"
                                      data-id={record.connection_id}>Open tool</button>
                                  : null}
                              </div>
                            : null}
                        </article>
                      );
                    })}
                  </div>}
            </section>
          </>}
    </div>
  );
}

function secretsTableHTML(query = '') {
  const needle = query.trim().toLowerCase();
  const rows = state.secrets.filter((secret) => !needle
    || secret.name.toLowerCase().includes(needle)
    || secret.used_by_names.some((name) => name.toLowerCase().includes(needle))).map((s) => {
    if (state.confirm && state.confirm.kind === 'del-secret-inuse' && state.confirm.id === s.id) {
      const deleteButtons = s.used_by_names.map((name) => {
        const connection = state.connections.find((candidate) => candidate.name === name);
        return connection
          ? `<button class="btn sm danger" data-act="delete-using-connection"
              data-id="${escAttr(connection.id)}">Delete ${esc(name)}…</button>`
          : '';
      }).join('');
      return `<tr class="confirm-row"><td colspan="4"><div class="confirm-inline"><span>Currently used by ${esc(s.used_by_names.join(', '))}. Delete the tool first.</span>
          ${deleteButtons}
          <button class="btn sm" data-act="confirm-cancel">OK</button></div></td></tr>`;
    }
    if (state.confirm && state.confirm.kind === 'del-secret' && state.confirm.id === s.id) {
      return `<tr class="confirm-row"><td colspan="4"><div class="confirm-inline"><span>Delete “${esc(s.name)}” from the macOS Keychain?</span>
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
    const usedBy = s.used_by_names.length
      ? `<div class="used-by-links">${s.used_by_names.map((name) => {
          const connection = state.connections.find((candidate) => candidate.name === name);
          return connection
            ? `<button class="used-by-link" data-act="show-connection"
                data-id="${escAttr(connection.id)}">${esc(name)}</button>`
            : `<span>${esc(name)}</span>`;
        }).join('')}</div>`
      : '<span class="s-sub">Not in use</span>';
    return `<tr>
      <td><div class="s-name">${esc(s.name)}</div></td>
      <td>${usedBy}</td>
      <td class="val"><span class="val-wrap"><span class="val-slot ${copied ? 'is-copied' : ''}"><code>${valText}</code><span class="val-overlay">${overlay}</span></span></span> ${eyeBtn}</td>
      <td class="rowdel">
        <button class="icon-btn" title="Edit secret" aria-label="Edit secret ${escAttr(s.name)}" data-act="edit-secret" data-id="${s.id}">${ICONS.pencil}</button>
        <button class="icon-btn" title="Delete secret" aria-label="Delete secret ${escAttr(s.name)}" data-act="del-secret-ask" data-id="${s.id}">${ICONS.trash}</button></td></tr>`;
  }).join('');
  return `<table class="sec-table"><thead><tr><th>Credential</th><th>Used by</th><th>Value</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>${rows}</tbody></table>`;
}

/* ---- connection guides (Get started > guides view) ---- */
// One shared identity covers every local agent, so the screen pivots around
// the core question — what may agents reach? A key card on top (this
// computer's key: where it lives, and Rotate), then one row per tool with an
// enable/disable toggle. Enabled = agents use the tool without prompting;
// disabled = refused.

// Kinds that can be issued a stable direct endpoint (a pasteable
// DSN/socket an unmodified tool uses).
const ENDPOINTABLE: Record<ConnectionType, boolean> = { pg: true, ssh: true, api: true };

// Below this width the Tools tab's detail panel is a slide-over rather
// than a second column. Must match the styles.css breakpoint.
const NARROW_LAYOUT = '(max-width: 720px)';

/** The address with its embedded credential replaced by bullets — the
 * collapsed field's display text. Addresses without an inline password
 * (SSH socket commands, plain URLs) pass through unchanged. */
function maskedEndpoint(address: string): string {
  return address.replace(/(:\/\/[^:@/\s]*:)[^@\s]+(?=@)/, '$1******');
}

/** The full address as markup with soft break opportunities after its own
 * punctuation — so a long address wraps at "/", "@", or ":" instead of
 * mid-identifier. Runs of separators stay whole ("://" never splits), and
 * each segment is escaped individually so the injected tags survive. */
function breakableAddress(address: string): string {
  return address.split(/(?<=[/?&@:=])(?![/?&@:=])/).map(esc).join('<wbr>');
}

// The direct-endpoint lifecycle strip on an enabled Postgres/SSH/HTTP row:
// a hairline footer that owns issue → live badge → reissue/revoke. The
// SSH renders the socket assignment together with its configured `ssh`
// invocation so the copied value connects immediately.
function endpointStripHTML(c: ConnectionSummary, withFormats = false): string {
  if (!c.agent_access.enabled || !ENDPOINTABLE[c.type]) return '';
  const endpoint = c.agent_access.endpoint ?? null;
  if (!endpoint) {
    return `<div class="ep-strip">
      <button class="btn primary sm" data-act="issue-endpoint" data-conn="${c.id}"
        title="A pasteable address for an unmodified tool">Get connection address…</button>
    </div>`;
  }
  // The address rides in a field with its Copy button showing — copying is
  // what everyone does with this string, so the affordance is explicit, not
  // a hover reveal. The field and the button use the same complete DSN,
  // including its issued credential and any socket-path query.
  //
  // In the detail pane the field starts as a masked one-liner (credential
  // replaced with asterisks, address ellipsized) — Copy still carries the complete DSN;
  // clicking the line expands it. Losing focus or leaving the tab collapses
  // the full capability again.
  const copied = state.copied === `ep:${c.id}`;
  const expanded = Boolean(state.epExpanded[c.id]);
  const endpointAddress = directEndpointAddress(c.type, endpoint, state.sshSockets[c.id]);
  const endpointText = endpointAddress
    ? c.type === 'ssh'
      ? sshDirectCommand(endpointAddress, c)
      : endpointAddress
    : null;
  const copyTitle = c.type === 'ssh'
    ? 'Copy the SSH command'
    : 'Copy the connection command';
  const copyBtn = endpointText
    ? `<button class="btn sm ep-copy" title="${copyTitle}"
        aria-label="${copyTitle} for ${escAttr(c.name)}" data-act="copy-endpoint-dsn"
        data-conn="${c.id}">${
        copied ? `${ICONS.check} Copied` : `${ICONS.copy} Copy`}</button>`
    : '';
  const address = endpointText
    ? expanded
      ? `<div class="ep-field">
          <code class="ep-addr">${breakableAddress(endpointText)}</code>
          ${copyBtn}
        </div>`
      : `<div class="ep-field collapsed">
          <button class="ep-addr ep-addr-masked" title="Show the full address"
            aria-label="Show the full connection address for ${escAttr(c.name)}"
            aria-expanded="false" data-act="expand-endpoint" data-conn="${c.id}">${
            esc(maskedEndpoint(endpointText))}</button>
          ${copyBtn}
        </div>`
    : '<span class="ep-addr ep-addr-hidden">Connection address unavailable</span>';
  // The strip is the field, nothing more: reissue/revoke live in the row's
  // one options menu. The detail pane adds the per-application copy row
  // beneath it; the guides keep just the address they narrate.
  const formats = withFormats && endpointText && endpointAddress
    ? endpointFormatRowHTML(c, endpointAddress)
    : '';
  return `<div class="ep-strip">${address}</div>${formats}`;
}

// One button per common client rendering of the issued endpoint (psql,
// libpq keywords, .env, ssh config, …). Each copies a string derived from
// the same summary + address the field shows. The click invokes a native
// command that reads the retained endpoint and renders the selected format
// without putting the credential-bearing copy text in a DOM attribute.
function endpointFormatRowHTML(c: ConnectionSummary, address: string): string {
  const buttons = ENDPOINT_FORMATS[c.type]
    .filter(
      (format) =>
        format.needsSecret || format.needsAltAddress || format.build(c, address) != null,
    )
    .map((format) => {
      const copied = state.copied === `epf:${c.id}:${format.key}`;
      return `<button class="btn sm ep-fmt ${copied ? 'is-copied' : ''}" title="${escAttr(format.title)}"
        aria-label="${escAttr(`${copied ? 'Copied. ' : ''}${format.title} for ${c.name}`)}"
        data-act="copy-endpoint-format" data-conn="${c.id}" data-format="${format.key}">${
        `<span class="ep-fmt-label">${esc(format.label)}</span>${
          copied ? `<span class="ep-fmt-check" aria-hidden="true">${ICONS.check}</span>` : ''}`}</button>`;
    })
    .join('');
  if (!buttons) return '';
  return `<div class="ep-formats" role="group" aria-label="Copy the connection for other applications">
    <span class="ep-formats-lbl">Copy for</span>${buttons}</div>`;
}

/** The agents on/off switch, in the detail panel's header — the tool's one
 * primary control. Its state is written out in the title's subline
 * ("Enabled" / "Off"), so the switch itself stays unlabeled and the header
 * keeps its width for the name. The list rows carry only the health dot
 * (gray = off). */
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
// agents talking to AgentMFA: a key card, one guide card per client from
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
          ? ` · ${identity.legacy_aliases} older key${identity.legacy_aliases === 1 ? '' : 's'} still accepted briefly`
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
      ${step.detail ? `<div class="connect-step-d">${esc(step.detail)}</div>` : ''}
      ${snippet}
      ${step.followup ? `<div class="connect-step-d connect-step-followup">${esc(step.followup)}</div>` : ''}</div>
  </div>`;
}

function connectCardHTML(client: ConnectClient, env: ConnectClientEnv): string {
  const open = state.connectOpen === client.id;
  const seen = recentClients().find((recent) => clientMatchesLabel(client, recent.name));
  const seenChip = seen
    ? `<span class="connect-seen" title="An agent using this label reached the broker">● seen ${relTime(seen.at)}</span>`
    : '';
  const steps = open
    ? `<div class="connect-steps">${connectGuideSteps(client, env).map((step, i) => connectStepHTML(step, i + 1)).join('')}
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
  // While running, the status row's pill already says Testing…
  if (test.running) return '';
  // Failures are health, not feedback: they render through the row's
  // issue list (connectionIssues), never as a line under a green verdict.
  if (test.detail === undefined || !test.ok) return '';
  return `<div class="cc-test ok">${ICONS.circleCheck}<span>${esc(test.detail)}</span></div>`;
};


/** The coarse kind a connection belongs to. Drives the muted per-kind
 * icon tint so a mixed list sorts itself visually without being
 * grouped. */
type ConnKind = 'mcp' | 'db' | 'ssh' | 'api';

function connectionKind(c: ConnectionSummary): ConnKind {
  if (c.type === 'pg') return 'db';
  if (c.type === 'ssh') return 'ssh';
  return c.mcp_path ? 'mcp' : 'api';
}

// The fix affordances an issue row can carry: compact buttons stacked under
// the issue text. A fix names the action ("Fix settings", "Reconnect…"),
// never the remedy in prose — the message stays diagnosis-only so it reads
// the same in the banner, the tooltip, and the panel.
const fixBtn = (act: string, id: string, label: string, primary = false): string =>
  `<button class="btn ${primary ? 'primary' : 'outline'} sm cat-meta-fix" data-act="${act}" data-id="${id}">${label}</button>`;
/** Open the connection editor — the fix for a TLS/cert mismatch. */
const editFix = (c: ConnectionSummary): string => fixBtn('edit-conn', c.id, 'Fix settings', true);

// One row inside an expanded catalog entry. It spans the full card width and
// carries enough to identify the connection without opening it: who is signed
// in (accounts differ between connections; the server rarely does), where it
// points, which tools agents get, and which credential the broker injects.
/** Everything wrong with a connection, folded into the one list the
 * health indicator owns. TLS weaker than the default, an unpinned host
 * key, a passively recorded rejected credential (brokered calls and
 * background token renewals set needs_reconnect without anyone pressing
 * Test), and the most recent failed test or MCP check each become one
 * line in the expansion, with its fix actions stacked below it. One verdict per
 * row: a failed check moves the indicator, it never sits beside a green
 * one. */
function connectionIssues(
  c: ConnectionSummary,
): Array<{ text: string; detail?: string; fix?: string; tone?: 'info' }> {
  const issues: Array<{ text: string; detail?: string; fix?: string; tone?: 'info' }> = [];
  if (c.type === 'pg' && c.sslmode && c.sslmode !== 'verify-full' && !isLoopbackHost(c.host)) {
    issues.push({
      text: c.sslmode === 'disable'
        ? 'TLS is disabled for this connection.'
        : c.sslmode === 'prefer'
          ? 'TLS prefers encryption but may fall back to plaintext; the server identity is not verified.'
          : c.sslmode === 'require'
            ? 'TLS encrypts this connection, but the server identity is not verified.'
            : `TLS is relaxed to ${c.sslmode}.`,
      fix: editFix(c),
    });
  }
  if (c.type === 'ssh' && !c.host_key_fingerprint) {
    issues.push({
      text: 'Host key not pinned yet — pins on the first connection.',
      tone: 'info',
    });
  }
  if (c.last_status === 'needs_reconnect') {
    issues.push({
      text: c.last_detail || 'The credential was rejected; reconnect to refresh it.',
      fix: c.mcp_path
        ? fixBtn('reconnect-mcp', c.id, 'Reconnect…')
        : c.oauth_spec
        ? fixBtn('oauth-reconnect', c.id, 'Reconnect…')
        : '',
    });
  }
  // A test or check finished this session supersedes the broker's
  // recorded verdict: a fresh failure surfaces even when its message
  // matches the stored one, and a fresh success retires a stale recorded
  // failure. Either way the row carries at most one failure line, so the
  // only dedupe left is against lines already in the list.
  const test = state.connTests[c.id];
  const mcpStatus = c.mcp_path ? state.mcpStatus[c.id] : undefined;
  const fresh = c.mcp_path
    ? mcpStatus && !mcpStatus.running && (mcpStatus.error || mcpStatus.report)
      ? { ok: !mcpStatus.error && Boolean(mcpStatus.report?.ok),
          detail: mcpStatus.error ?? mcpStatus.report?.detail }
      : null
    : test && !test.running && test.detail !== undefined
    ? { ok: test.ok, detail: test.detail, kind: test.kind }
    : null;
  const rawFailure = fresh
    ? fresh.ok ? null : fresh.detail
    : c.last_status === 'failed'
    ? c.last_detail || 'The last connection check failed.'
    : null;
  const failure = rawFailure ? sentenceCase(rawFailure) : null;
  if (failure && !issues.some((issue) => issue.text === failure)) {
    // A fresh test carries a failure kind; when it's one the connection
    // editor could plausibly fix — a wrong host, port, credential, or TLS
    // expectation — the card leads with Fix settings. 'other' and the
    // passively-recorded (kindless) verdict carry no targeted fix of their
    // own; testing remains available from the panel's options menu.
    const kind = fresh && !fresh.ok ? fresh.kind : undefined;
    const fixable = !c.mcp_path && kind !== undefined && kind !== 'other';
    // The TLS refusal gets a short headline with the protocol-speak
    // ("refused to start TLS", the sslmode by name) demoted to a detail
    // line. The stored broker verdict carries no kind, so the raw message
    // is recognized by its text.
    const tlsDeclined = kind === 'tls_declined' || /refused to start TLS/i.test(failure);
    issues.push(tlsDeclined
      ? {
          text: 'TLS handshake failed',
          detail: `The server refused TLS; this connection requires ${
            c.sslmode ? `"${c.sslmode}"` : 'it'}.`,
          fix: fixable ? editFix(c) : '',
        }
      : { text: failure, fix: fixable ? editFix(c) : '' });
  }
  return issues;
}

/** A parenthetical that just restates the target ("Postgres
 * (dev@localhost:5433)") drops away — the target prints beside the name
 * wherever it appears. */
function stripTargetParen(name: string, target: string): string {
  const paren = /^(.*\S)\s*\((.+)\)$/.exec(name);
  return paren && target.includes(paren[2]) ? paren[1] : name;
}

/** Account-first display title, used where a connection is named without
 * its subline (the attention banner): the signed-in identity is what
 * tells two connections to the same server apart. */
function connectionTitle(c: ConnectionSummary): string {
  return c.mcp_path && c.account ? c.account : stripTargetParen(c.name, c.target);
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

/** The shared contents of a tool's options menu. Both the detail-panel
 * ellipsis and a right-click on its master row open these exact actions. */
function connectionMenuItemsHTML(c: ConnectionSummary): string {
  const test = state.connTests[c.id];
  const mcpStatus = c.mcp_path ? state.mcpStatus[c.id] : undefined;
  const running = c.mcp_path
    ? Boolean(mcpStatus && mcpStatus.running)
    : Boolean(test && test.running);
  const endpointItems = c.agent_access.enabled && c.agent_access.endpoint
    ? `<div class="menu-divider" role="separator"></div>
        <button class="menu-item" role="menuitem" data-act="reissue-endpoint-ask" data-conn="${c.id}">${ICONS.refresh} Rotate connection address</button>
        <button class="menu-item danger" role="menuitem" data-act="revoke-endpoint-ask" data-conn="${c.id}">${ICONS.x} Revoke connection address</button>`
    : '';
  return `<button class="menu-item" role="menuitem" data-act="${c.mcp_path ? 'mcp-status' : 'test-conn'}"
      data-id="${c.id}" ${running ? 'disabled' : ''}>${ICONS.flaskConical} ${running ? 'Testing…' : 'Test connection'}</button>
    <button class="menu-item" role="menuitem" data-act="edit-conn" data-id="${c.id}">${ICONS.pencil} Edit tool</button>
    <button class="menu-item danger" role="menuitem" data-act="del-conn-ask" data-id="${c.id}">${ICONS.trash} Delete tool</button>
    ${endpointItems}`;
}

/** What the switch promises to ask about, in this tool's own terms. */
function confirmUnitLabel(c: ConnectionSummary): string {
  if (c.type === 'pg') return 'Ask before database sessions';
  if (c.type === 'ssh') return 'Ask before SSH logins';
  return c.mcp_path ? 'Ask before tool calls' : 'Ask before requests';
}

/**
 * The limit of what a kind's switch can promise, where that differs from
 * what the label implies. Both planes confirm something coarser than a
 * single operation, and the row says which — a switch that quietly means
 * less than it reads is worse than no switch.
 */
function confirmScopeNote(c: ConnectionSummary): string {
  if (c.type === 'ssh') {
    return 'Each login is confirmed. Commands in the session that follows are not — '
      + 'AgentMFA signs the login and is then out of the connection.';
  }
  if (c.type === 'pg') {
    return 'Each session is confirmed. Statements within it are not: one approval covers '
      + 'every query the client sends.';
  }
  return '';
}

/**
 * The traffic-confirmation switch, in the detail panel under the tool's
 * connect section. Off by default: turning it on is the user asking to be
 * interrupted, and it belongs next to the access switch it narrows rather
 * than in global Settings, because the answer differs per tool.
 */
function confirmSectionHTML(c: ConnectionSummary): string {
  if (!c.agent_access.enabled) return '';
  const on = Boolean(c.agent_access.confirm);
  const until = c.agent_access.confirm_window_until;
  // An approval covers the agent the prompt named, not the connection, so
  // the line names it. "Approved until 14:32" on its own would read as the
  // tool being open to everything, which is the opposite of what it means.
  const windowAgents = c.agent_access.confirm_window_agents ?? [];
  const covered = windowAgents.length === 1
    ? `for ${esc(windowAgents[0])}`
    : windowAgents.length > 1
      ? `for ${windowAgents.length} agents`
      : '';
  const window = on && until && new Date(until).getTime() > Date.now()
    ? `<div class="cd-confirm-window">${ICONS.timer}<span>Approved ${covered} until
        ${esc(clockTime(until))} — not asking ${windowAgents.length === 1 ? 'again' : 'them again'}
        until then. Other agents are still asked.</span></div>`
    : '';
  // The mirror image of the window: after a Deny, retries are refused
  // without a fresh prompt for a short cooldown. Without this line that
  // refusal is invisible, and a mis-clicked Deny reads as a broken tool.
  const cooldownUntil = c.agent_access.confirm_cooldown_until;
  const cooldown = on && cooldownUntil && new Date(cooldownUntil).getTime() > Date.now()
    ? `<div class="cd-confirm-window cd-confirm-cooldown">${ICONS.clockAlert}<span>Denied —
        retries are refused without asking for ${esc(timeLeft(cooldownUntil))}. Turning
        confirmation off and back on clears it.</span></div>`
    : '';
  // Shown whether the switch is on or off: what it can promise is part of
  // deciding whether to turn it on at all.
  const scope = confirmScopeNote(c);
  return `<div class="cd-sec cd-confirm">
      <div class="cd-confirm-row">
        <div class="cd-confirm-txt">
          <div class="cd-confirm-lbl">${esc(confirmUnitLabel(c))}</div>
          ${scope ? `<div class="cd-confirm-sub">${esc(scope)}</div>` : ''}
        </div>
        <button class="switch ${on ? 'on' : ''}" role="switch" aria-checked="${on}"
          title="${on ? 'Traffic is confirmed with you first' : 'Traffic goes without asking'}"
          aria-label="${on ? 'Stop confirming' : 'Confirm'} traffic on ${escAttr(c.name)}"
          data-act="${on ? 'confirm-off' : 'confirm-on'}" data-conn="${c.id}"></button>
      </div>
      ${window}
      ${cooldown}
      ${on ? `<div class="cd-confirm-note">With no AgentMFA approval surface attached,
        this tool’s traffic is refused rather than carried.</div>` : ''}
    </div>`;
}

// The Tools tab's detail panel: everything about connecting to the
// selected tool that the compact rows no longer carry — its connection
// endpoints, issues with their fixes, and the row's one options menu.
// Beside the list when the window is wide; a slide-over when it isn't.
function connDetailHTML(c: ConnectionSummary): string {
  const menuOpen = state.connMenuOpen === c.id && !state.connMenuPoint;
  const enabled = c.agent_access.enabled;
  const entry = entryForConnection(c);
  const mcpStatus = c.mcp_path ? state.mcpStatus[c.id] : undefined;
  const issues = connectionIssues(c);
  const issuesBlock = enabled && issues.length
    ? `<div class="cc-issues">${issues.map((issue) =>
        `<div class="cc-issue ${issue.tone ?? ''}">${
          issue.tone === 'info' ? ICONS.info : ICONS.triangleAlert}<div class="cc-issue-body">
          <span class="cc-issue-headline">${esc(issue.text)}</span>${
          issue.detail ? `<span class="cc-issue-detail">${esc(issue.detail)}</span>` : ''}${
          issue.fix
            ? `<div class="cc-issue-fixes">${issue.fix}</div>`
            : ''}</div></div>`).join('')}</div>`
    : '';
  // The connect section is addressed to the user, not the machinery: a
  // sentence-case invitation naming what they're connecting to, where the
  // panel's other sections keep the tracked-caps label.
  const connectTitle = ((): string => {
    switch (connectionKind(c)) {
      case 'db': return 'Connect to this database';
      case 'ssh': return 'Connect to this server';
      default: return 'Connect to this service';
    }
  })();
  const endpointSection = enabled && ENDPOINTABLE[c.type] && !c.mcp_path
    ? `<div class="cd-sec"><div class="cd-connect-lbl"><span>${connectTitle}</span></div>
        ${endpointStripHTML(c, true)}
      </div>`
    : '';
  // MCP tools combine their filter and direct endpoint into one section:
  // both describe how agents reach and constrain this tool. The label
  // speaks in the connect headline's sentence-case register — the panel
  // has one voice, no tracked-caps machinery labels.
  const mcpSection = enabled && c.mcp_path
    ? `<div class="cd-sec"><div class="cd-connect-lbl"><span>AgentMFA MCP</span><span class="cd-lbl-aside">${connectionToolsChipHTML(c)}</span></div>
        ${ENDPOINTABLE[c.type] ? endpointStripHTML(c) : ''}</div>`
    : '';
  const offNote = enabled
    ? ''
    : '<div class="cd-help cd-off-note">This tool is disabled.</div>';
  // The tool's facts, unpacked. The row keeps the terse machine target;
  // this card is where its parts are readable — only facts
  // the summary actually carries render, so every kind contributes what it
  // has. The live-session line surfaces what the list's "N live" badge
  // counts and links it to the log that explains it.
  const factRows = ((): Array<[string, string]> => {
    const rows: Array<[string, string]> = [];
    if (c.mcp_path) {
      if (c.host) rows.push(['Server', `${c.host}${c.mcp_path === '/' ? '' : c.mcp_path}`]);
      if (c.account) rows.push(['Signs in as', c.account]);
    } else if (c.type === 'pg') {
      if (c.host) rows.push(['Host', c.host]);
      if (c.port != null) rows.push(['Port', String(c.port)]);
      if (c.dbname) rows.push(['Database', c.dbname]);
      if (c.user) rows.push(['Signs in as', c.user]);
      if (c.sslmode) rows.push(['TLS', c.sslmode]);
    } else if (c.type === 'ssh') {
      if (c.destination) rows.push(['Destination', c.destination]);
      if (c.host) rows.push(['Host', c.host]);
      if (c.port != null) rows.push(['Port', String(c.port)]);
      if (c.user) rows.push(['User', c.user]);
      rows.push(['Host key', c.host_key_fingerprint ? 'Pinned' : 'Not pinned yet']);
    } else if (c.host) {
      rows.push(['Server', `${c.scheme ? `${c.scheme}://` : ''}${c.host}`]);
    }
    if (c.secret_names.length) rows.push(['Credential', c.secret_names.join(', ')]);
    else if (c.oauth) rows.push(['Credential', 'OAuth, renewed by AgentMFA']);
    return rows;
  })();
  const live = liveCount(c);
  const confirmSection = confirmSectionHTML(c);
  const detailsSection = factRows.length
    ? `<div class="cd-sec"><div class="cd-connect-lbl"><span>Details</span></div>
        <div class="cd-facts">${factRows.map(([key, value]) =>
          `<div class="cd-fact"><span class="cd-fact-k">${esc(key)}</span><code class="cd-fact-v">${esc(value)}</code></div>`).join('')}</div>
        ${live ? `<div class="cd-live">${live} live session${live === 1 ? '' : 's'} ·
          <button class="cd-live-link" data-act="tab" data-tab="activity">View in Activity Log</button></div>` : ''}
      </div>`
    : '';
  return `<div class="cd-head">
      <span class="cat-ico kind-${connectionKind(c)}" aria-hidden="true">${entry ? ICONS[entry.icon] || '' : ''}</span>
      <div class="cd-title"><b title="${escAttr(c.name)}">${esc(connectionRowName(c))}</b>
        <span>${enabled ? 'Enabled' : 'Off'}</span></div>
      <div class="cd-actions">
        ${connToggleHTML(c)}
        <div class="tile-menu-wrap">
          <button class="icon-btn tile-menu-btn ${menuOpen ? 'on' : ''}" title="Tool options"
            aria-label="Options for ${escAttr(c.name)}" aria-haspopup="menu"
            aria-expanded="${menuOpen}" data-act="toggle-conn-menu" data-id="${c.id}">${ICONS.ellipsis}</button>
          ${menuOpen ? `<div class="tile-menu" role="menu" aria-label="Options for ${escAttr(c.name)}">
            ${connectionMenuItemsHTML(c)}
          </div>` : ''}
        </div>
      </div>
    </div>
    ${offNote}${issuesBlock}${connTestResultHTML(c)}${c.mcp_path
      ? mcpSection + endpointSection
      : endpointSection + mcpSection}${confirmSection}${detailsSection}${mcpStatusHTML(c)}`;
}

// The status check's result, rendered under the MCP connection it belongs
// to — reachability and account first, then the server's resources the
// same way credentials and wirings are listed.
function mcpStatusHTML(c: ConnectionSummary): string {
  if (!c.mcp_path) return '';
  const status = state.mcpStatus[c.id];
  if (!status) return '';
  // While running, the options-menu action already says Testing…
  if (status.running) return '';
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
      `<div class="mcp-res"><b title="${escAttr(resource.name)}">${esc(resource.name)}</b><code title="${escAttr(resource.uri)}">${esc(resource.uri)}</code></div>`).join('');
    const more = report.resources.length > shown.length
      ? `<div class="mcp-res-more">+ ${report.resources.length - shown.length} more</div>` : '';
    resources = `<div class="mcp-res-head">Resources (${report.resources.length})</div>
      ${rows || '<div class="mcp-res-more">None listed by the server.</div>'}${more}`;
  }
  const truncated = report.truncated
    ? '<div class="mcp-res-more">Catalog results were capped; more items are available upstream.</div>'
    : '';
  return `${head}${resources}${truncated}`;
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
// Connections live in the flat list above the catalog, so a catalog row
// only ever offers its add action — connected generic entries included.
function catalogRowHTML(entry: CatalogEntry): string {
  // A grayed-out placeholder: visible, not yet addable.
  if (entry.disabled) {
    return `<div class="cat-row-wrap is-soon">
      <div class="cat-row">
        <span class="cat-ico" aria-hidden="true">${ICONS[entry.icon] || ''}</span>
        <div class="cat-tx"><b>${esc(entry.name)}</b></div>
        <span class="cat-soon" title="Not available yet">Coming soon</span>
      </div></div>`;
  }
  const builtin = entry.via === 'builtin';
  const quickConnect = canQuickConnectMcp(entry);
  const actionMenuOpen = state.catalogActionMenuOpen === entry.id;
  // Rows that need provider-side setup (Slack, Gmail) and generic custom
  // connection rows all say Configure: the user supplies something before
  // the connection can be made.
  const addLabel = entry.requiresSetup
    ? 'Configure'
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
  // The credentials store renders its table right below (always expanded),
  // so the row itself carries no trailing badge — the table is the count.
  const action = builtin
    ? ''
    : quickConnect
    ? quickConnectAction
    : entry.via === 'connection'
    ? `<button class="btn cat-add" data-act="catalog-add" data-id="${entry.id}">${addLabel}</button>`
    : `<span class="cat-soon" title="Arrives with the MCP layer">Soon</span>`;
  // Only the credentials store expands here, and it renders expanded
  // always — its table is the content of the Secrets tab, not a
  // disclosure. Connected tools live in the flat list, never in here.
  const expansion = builtin ? credentialsExpansionHTML() : '';
  return `<div class="cat-row-wrap ${builtin ? 'open' : ''} ${actionMenuOpen ? 'menu-open' : ''}">
    <div class="cat-row">
      <span class="cat-ico" aria-hidden="true">${ICONS[entry.icon] || ''}</span>
      <div class="cat-tx"><b>${esc(entry.name)}</b></div>
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
 * account is a detail fact, and the subline carries the target. */
function connectionRowName(c: ConnectionSummary): string {
  return stripTargetParen(c.name, c.target);
}

/** The master row's second line carries only the destination. Tool filtering
 * and credential details live in the detail pane. */
function connectionSublineHTML(c: ConnectionSummary): string {
  return `<span class="flat-dest" title="${escAttr(c.target)}">${esc(c.target)}</span>`;
}

/** The flat row's health glyph. Not a control: the row itself opens the
 * detail, which is where issues are read and fixed. */
function flatHealthHTML(c: ConnectionSummary): string {
  if (!c.agent_access.enabled) {
    return '<span class="cc-dot off" role="img" title="Off" aria-label="Off — agents may not use this tool"></span>';
  }
  const issues = connectionIssues(c).filter((issue) => issue.tone !== 'info');
  if (!issues.length) return '<span class="cc-dot ok" role="img" title="Ready" aria-label="Ready"></span>';
  // A dot, not a badge: the count and the issues themselves are read in
  // the detail panel the row opens.
  return `<span class="cc-dot warn" role="img" title="${escAttr(issues.map((issue) => issue.text).join(' '))}"
      aria-label="${issues.length} issue${issues.length === 1 ? '' : 's'}"></span>`;
}

/** The connection the detail panel shows: the explicit selection while it
 * still exists, else the first row that needs attention, else the first
 * row — the panel never opens empty. */
function selectedConnection(): ConnectionSummary | null {
  if (!state.connections.length) return null;
  const chosen = state.connections.find((c) => c.id === state.selectedConn);
  if (chosen) return chosen;
  const attn = state.connections.find(
    (c) => c.agent_access.enabled
      && connectionIssues(c).some((issue) => issue.tone !== 'info'),
  );
  return attn ?? state.connections[0];
}

function flatConnRowHTML(c: ConnectionSummary, reorderable = false): string {
  const kind = connectionKind(c);
  const live = liveCount(c);
  const entry = entryForConnection(c);
  const selected = selectedConnection()?.id === c.id;
  // The row is the detail panel's opener; the on/off switch lives in the
  // detail header, so the health dot alone carries state here (gray = off).
  return `<div class="flat-conn-wrap ${selected ? 'sel' : ''}${reorderable ? ' reorderable' : ''}${dragConnId === c.id ? ' dragging' : ''}"
    data-conn-row="${c.id}"${reorderable ? ' draggable="true"' : ''}>
    <div class="flat-conn-row" role="button" tabindex="0" data-act="select-conn" data-id="${c.id}"
      aria-expanded="${selected}" aria-label="Show details for ${escAttr(connectionRowName(c))}"${
        reorderable ? ' aria-keyshortcuts="Alt+ArrowUp Alt+ArrowDown"' : ''}>
      <span class="cat-ico kind-${kind}" aria-hidden="true">${entry ? ICONS[entry.icon] || '' : ''}</span>
      <div class="flat-tx"><b title="${escAttr(c.name)}">${esc(connectionRowName(c))}</b>
        <span>${connectionSublineHTML(c)}</span></div>
      ${live ? `<span class="cc-live">${live} live</span>` : ''}
      <div class="cat-conn-status">${flatHealthHTML(c)}</div>
    </div></div>`;
}


/** Whether a draft is being edited as an MCP server rather than a raw API. */
function isMcpDraft(draft: { isMcp?: boolean; mcpPath?: string | null }): boolean {
  return Boolean(draft.isMcp || draft.mcpPath);
}

// Sections that collapse to their connected/minimum rows behind a "More
// tools" disclosure. API Apps holds few rows today but is expected
// to grow, so it collapses the same way as the larger sections.
const COLLAPSIBLE_SECTIONS: string[] = ['MCP Apps', 'API Apps'];

// The compact success banner shown after adding a tool. Rendered by
// connectionsHTML in the wide window; the dropdown hoists it above its
// inline search (see TabContent), so it keeps topping the tab either way.
function connectionReadyCardHTML(): string {
  const ready = state.connectionReady;
  if (!ready) return '';
  return `<div class="connection-ready">
    <b>${esc(ready.name)} successfully added</b>
    <button class="icon-btn" title="Dismiss" aria-label="Dismiss success message"
      data-act="dismiss-connection-ready">${ICONS.circleX}</button>
  </div>`;
}

function connectionsHTML(withReadyCard = true) {
  const readyCard = withReadyCard ? connectionReadyCardHTML() : '';
  const byId = new Map(state.connections.map((connection) => [connection.id, connection] as const));
  const previewOrder = dragConnOrder;
  const orderedConnections = previewOrder
    ? [
        ...previewOrder.map((id) => byId.get(id)).filter(
          (connection): connection is ConnectionSummary => Boolean(connection),
        ),
        ...state.connections.filter((connection) => !previewOrder.includes(connection.id)),
      ]
    : state.connections;
  // One view, no navigation: the connected tools stay at the top as flat
  // rows, and an "Add a tool" row at the bottom of the list expands the
  // catalog of everything not yet connected, in place, beneath it.
  const entries = visibleCatalog(state.toolSearch);
  const isConnected = (entry: CatalogEntry): boolean =>
    connectionsForEntry(entry, state.connections).length > 0;
  const needle = state.toolSearch.trim().toLowerCase();
  // A connected row also answers to what the tool *is* — its catalog
  // entry's name, description, and keywords — not just what the user
  // named it, so "postgres" still finds a row called "Analytics DB".
  const entryMatches = (c: ConnectionSummary): boolean => {
    const entry = entryForConnection(c);
    return Boolean(entry) && [entry!.name, entry!.description, ...(entry!.keywords || [])]
      .some((text) => text.toLowerCase().includes(needle));
  };
  const matching = orderedConnections.filter((c) => !needle
    || c.name.toLowerCase().includes(needle)
    || c.target.toLowerCase().includes(needle)
    || (c.account || '').toLowerCase().includes(needle)
    || entryMatches(c));
  // Reordering persists the full list order, so it is only offered when the
  // whole list is on screen: no active search filter, and more than one tool.
  const reorderable = !needle && matching.length > 1;
  const connectedList = state.connections.length
    ? `<div class="cat-section"><div class="cat-rows${reorderable ? ' reorderable' : ''}${dragConnId ? ' drag-active' : ''}"
        data-conn-list${reorderable ? '="on"' : ''}>${matching.length
        ? matching.map((c) => flatConnRowHTML(c, reorderable)).join('')
        : '<div class="muted-note">No tools match your search.</div>'}</div></div>`
    : '';
  // With nothing connected, adding is the only thing to do — the catalog
  // starts open.
  const addOpen = state.addToolOpen || !state.connections.length;
  const addRow = state.connections.length
    ? `<div class="cat-section"><div class="cat-rows">
        <div class="cat-row is-toggle add-tools-row" role="button" tabindex="0"
          data-act="toggle-add-tools" aria-expanded="${addOpen}"
          aria-label="${addOpen ? 'Hide' : 'Show'} tools that can be added">
          <span class="cat-ico" aria-hidden="true">${ICONS.plus}</span>
          <div class="cat-tx"><b>Add a tool</b></div>
          <span class="cat-chev group-chev ${addOpen ? 'open' : ''}" aria-hidden="true">${ICONS.chevronDown}</span>
        </div></div></div>`
    : '';
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
      <div class="cat-rows">${rows.map(catalogRowHTML).join('')}${disclosure}</div></div>`;
  }).join('');
  // Master–detail: the rows keep only what identifies a tool; everything
  // about connecting to it lives in the panel beside the list. Narrow
  // windows get the same panel as a slide-over instead (see styles).
  const detail = selectedConnection();
  const detailPane = detail
    ? `<aside class="conn-detail-pane" aria-label="Connection details">${connDetailHTML(detail)}</aside>`
    : '';
  const backdrop = detail && state.connDetailOpen
    ? '<button class="conn-detail-backdrop" data-act="close-conn-detail" aria-label="Close connection details" tabindex="-1"></button>'
    : '';
  return readyCard + `<div class="catalog ${state.connDetailOpen ? 'detail-open' : ''}">
    <div class="tools-split"><div class="tools-list">
      ${connectedList}${addRow}${addOpen && !sections ? '<div class="muted-note">No tools match your search.</div>' : sections}
    </div>${detailPane}</div>${backdrop}
  </div>`;
}

function secretsHTML(): string {
  const allEntries = visibleCatalog('').filter((entry) => entry.section === 'Secrets');
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
  // Each store renders as its own card so the Keychain credentials and the
  // 1Password placeholder read as separate groups, not rows of one list.
  const sections = rows.length
    ? rows.map((entry) =>
      `<div class="cat-section"><div class="cat-rows">${catalogRowHTML(entry)}</div></div>`).join('')
    : '<div class="muted-note">No secrets match your search.</div>';
  return `<div class="catalog">${sections}
  </div>`;
}

// Console.app-style rows: a proportional timestamp gutter, restrained
// semantic Lucide icon, then plain primary text with optional detail.
function ActivityRow({ entry }: { entry: ActivityEntry }): ReactNode {
  // Attribution and timing stay under the message. The tool gets its own
  // right-side column so it can be scanned independently across rows.
  const remotePeer = entry.surface === 'remote' ? (entry.approver || 'local socket') : null;
  const hasChips = Boolean(entry.agent) || typeof entry.duration_ms === 'number'
    || entry.confirmation === 'management_token' || Boolean(remotePeer);
  return (
    <div className="act-row">
      <span className="act-gutter">
        <span className="act-time" data-tippy-content={absTime(entry.at)}
          data-tippy-theme="activity-time">{relTime(entry.at)}</span>
      </span>
      <span className={`act-ico tone-${entry.tone || 'neutral'}`}>
        <Icon markup={ICONS[entry.icon] || ''} />
      </span>
      <div className="act-txt">
        {entry.text}
        {entry.detail ? <div className="act-detail">{entry.detail}</div> : null}
        {hasChips && (
          <div className="act-chips">
            {entry.agent
              ? <span className="act-chip untrusted-identity" dir="auto"
                  title="Self-reported agent label">reported as “{entry.agent}”</span>
              : null}
            {typeof entry.duration_ms === 'number'
              ? <span className="act-chip act-chip-time" title="Duration">{entry.duration_ms} ms</span> : null}
            {/* A hosted broker authorizes gated actions by manage-token
                possession; mark those so the trail reads honestly next to
                Touch-ID-confirmed rows. */}
            {entry.confirmation === 'management_token'
              ? <span className="act-chip act-chip-manage" title="Authorized by the management token">via manage token</span> : null}
            {remotePeer
              ? <span className="act-chip" title="Direct socket peer; not an authenticated human identity">remote: {remotePeer}</span> : null}
          </div>
        )}
      </div>
      {entry.connection
        ? <span className="act-chip act-tool" title={`Tool: ${entry.connection}`}>{entry.connection}</span>
        : null}
    </div>
  );
}

/** A stable row identity: entries carry no broker id, so key on content and
 * disambiguate identical repeats by occurrence. Prepends then move rows
 * instead of rewriting every position. */
function activityKey(entry: ActivityEntry, seen: Map<string, number>): string {
  const base = activityIdentity(entry);
  const n = seen.get(base) ?? 0;
  seen.set(base, n + 1);
  return n ? `${base}#${n}` : base;
}

/**
 * A row's height before anything has been measured.
 *
 * Shaped by the entry rather than a single constant: rows are one 18px line of
 * text inside 16px of padding, and grow by a detail line and a chip row when
 * the entry carries them (see `.act-row` in styles.css). A guess that tracks
 * content lands within a few pixels, so the scrollbar barely moves as real
 * measurements arrive — one flat estimate would visibly resize it while
 * scrolling through a run of detailed rows.
 */
function activityRowEstimate(entry: ActivityEntry): number {
  let height = 34;
  if (entry.detail) height += 19;
  if (entry.agent || typeof entry.duration_ms === 'number'
    || entry.confirmation === 'management_token'
    || entry.surface === 'remote') height += 21;
  return height;
}

/** Measured row heights, keyed by row identity so a live prepend keeps every
 * height already known. Invalidated when the scroller's width changes, since
 * width is what decides how the text these heights came from wraps. */
const activityRowHeights = new Map<string, number>();
let activityRowHeightsWidth = 0;
/** Enough for several full logs; the cache outlives filter changes, so bound
 * it rather than letting stale identities accumulate for the session. */
const ACTIVITY_HEIGHT_CACHE_MAX = 2_000;

/** What the activity list needs from its scroller to place the window. */
interface ScrollMetrics {
  scrollTop: number;
  viewport: number;
  /** The list's top edge in the scroller's content coordinates. */
  listTop: number;
  /** Cached heights only describe the width they were measured at. */
  width: number;
}

const PREPAINT_METRICS: ScrollMetrics = {
  scrollTop: 0, viewport: ACTIVITY_PREPAINT_VIEWPORT, listTop: 0, width: 0,
};

/** Whole pixels: sub-pixel scroll and layout noise would otherwise re-render
 * the window without ever moving it. */
function readScrollMetrics(scroller: Element, list: Element): ScrollMetrics {
  const scrollTop = scroller.scrollTop;
  return {
    scrollTop: Math.round(scrollTop),
    viewport: Math.round(scroller.clientHeight),
    listTop: Math.round(
      list.getBoundingClientRect().top - scroller.getBoundingClientRect().top + scrollTop,
    ),
    width: Math.round(scroller.clientWidth),
  };
}

function sameMetrics(a: ScrollMetrics, b: ScrollMetrics): boolean {
  return a.scrollTop === b.scrollTop && a.viewport === b.viewport
    && a.listTop === b.listTop && a.width === b.width;
}

/**
 * The activity rows, windowed.
 *
 * Only the rows near the viewport are mounted; spacer divs stand in for the
 * rest so the scrollbar still describes the whole log. This matters less for
 * the initial paint than for the re-renders: every live event and the
 * once-a-minute relative-timestamp refresh reconcile this list, and windowing
 * keeps that proportional to the viewport instead of the log.
 *
 * Rows are variable height and the list has no scroller of its own — it
 * scrolls with `.content` — so the window is computed against that ancestor,
 * and heights come from measuring the mounted rows before paint.
 *
 * The trade windowing makes: find-in-page and screen readers see the mounted
 * window, not the whole log. The filter field above is the way to reach a row
 * that isn't mounted.
 */
function ActivityList({ entries }: { entries: ActivityEntry[] }): ReactNode {
  const seen = new Map<string, number>();
  const keys = entries.map((entry) => activityKey(entry, seen));

  const listRef = useRef<HTMLDivElement | null>(null);
  const [metrics, setMetrics] = useState<ScrollMetrics>(PREPAINT_METRICS);
  const [, countMeasurements] = useState(0);

  const view = virtualListWindow({
    heights: entries.map((entry, i) =>
      activityRowHeights.get(keys[i]) ?? activityRowEstimate(entry)),
    listTop: metrics.listTop,
    scrollTop: metrics.scrollTop,
    viewport: metrics.viewport,
    overscan: ACTIVITY_OVERSCAN,
  });

  // Scrolling and resizing move the window without any store revision, so
  // this listener — not render() — is what drives those updates.
  useEffect(() => {
    const list = listRef.current;
    const scroller = list?.closest('.content');
    if (!list || !scroller) return;
    const sync = (): void => {
      const next = readScrollMetrics(scroller, list);
      setMetrics((prev) => (sameMetrics(prev, next) ? prev : next));
    };
    sync();
    scroller.addEventListener('scroll', sync, { passive: true });
    const resize = new ResizeObserver(sync);
    resize.observe(scroller);
    return () => {
      scroller.removeEventListener('scroll', sync);
      resize.disconnect();
    };
  }, []);

  // Runs after every render, before paint: the mounted rows just changed, and
  // the filter chips above may have re-wrapped and moved the list. Both state
  // updates bail when nothing moved, so this settles in at most one extra pass.
  useLayoutEffect(() => {
    const list = listRef.current;
    if (!list) return;
    const scroller = list.closest('.content');
    if (scroller) {
      const next = readScrollMetrics(scroller, list);
      setMetrics((prev) => (sameMetrics(prev, next) ? prev : next));
      if (next.width && next.width !== activityRowHeightsWidth) {
        activityRowHeightsWidth = next.width;
        activityRowHeights.clear();
      }
    }
    if (activityRowHeights.size > ACTIVITY_HEIGHT_CACHE_MAX) activityRowHeights.clear();
    // Document order, so the nth mounted row is the nth key from the window.
    const mounted = list.querySelectorAll<HTMLElement>(':scope > .act-row');
    let changed = false;
    mounted.forEach((el, i) => {
      const key = keys[view.start + i];
      if (key === undefined) return;
      const height = el.getBoundingClientRect().height;
      const known = activityRowHeights.get(key);
      // Half a pixel of slack: fractional line boxes must not measure, differ,
      // re-render and measure again forever.
      if (height > 0 && (known === undefined || Math.abs(known - height) > 0.5)) {
        activityRowHeights.set(key, height);
        changed = true;
      }
    });
    if (changed) countMeasurements((n) => n + 1);
  });

  return (
    <div className="act-list" ref={listRef}>
      {view.padTop > 0
        ? <div className="act-pad" style={{ height: view.padTop }} aria-hidden="true" />
        : null}
      {entries.slice(view.start, view.end).map((entry, i) => (
        <ActivityRow key={keys[view.start + i]} entry={entry} />
      ))}
      {view.padBottom > 0
        ? <div className="act-pad" style={{ height: view.padBottom }} aria-hidden="true" />
        : null}
    </div>
  );
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

function ActivityView(): ReactNode {
  const liveSessions = state.sessions.length
    ? <SafeMarkup markup={liveSessionsHTML('activity-live-sessions')} />
    : null;
  if (!state.activity.length) {
    return (
      <>
        {liveSessions}
        <div className="muted-note">
          No activity yet.
          {mode === 'dropdown' ? null : <><br />Requests and broker actions will appear here.</>}
        </div>
      </>
    );
  }
  // Agents seen in the loaded window; chips beat a dropdown at this scale.
  const agents = [...new Set(state.activity.map((entry) => entry.agent).filter(Boolean))] as string[];
  const entries = filteredActivity().slice(0, ACTIVITY_RENDER_LIMIT);
  return (
    <>
      {liveSessions}
      <div className="act-filters">
        <input id="activity-search" className="cat-search act-search" type="search"
          placeholder="Filter activity…" aria-label="Filter activity"
          value={state.activityQuery}
          onChange={(e) => { state.activityQuery = e.currentTarget.value; render(); }} />
        <button className={`seg-btn act-filter ${state.activityIssuesOnly ? 'on' : ''}`}
          data-act="act-filter-issues">Issues</button>
        {agents.map((agent) => (
          <button key={agent} className={`seg-btn act-filter ${state.activityAgent === agent ? 'on' : ''}`}
            data-act="act-filter-agent" data-value={agent}>{agent}</button>
        ))}
      </div>
      {entries.length
        ? <ActivityList entries={entries} />
        : <div className="muted-note">Nothing matches these filters.</div>}
    </>
  );
}

async function receiveActivity(entry: ActivityEntry | null | undefined): Promise<void> {
  if (!entry || !entry.at || !entry.text) {
    await load('activity', 'list_activity', { limit: ACTIVITY_RENDER_LIMIT });
    if (state.tab === 'activity' && !state.sheet && !state.menuOpen) render();
    return;
  }

  const identity = activityIdentity(entry);
  const duplicate = state.activity.some((item) => activityIdentity(item) === identity);
  if (duplicate) return;
  state.activity = [entry, ...state.activity].slice(0, ACTIVITY_RENDER_LIMIT);

  if (state.tab !== 'activity' || state.sheet || state.menuOpen) return;
  // With filters active the cheap prepend would bypass them; re-render.
  if (state.activityQuery || state.activityAgent || state.activityIssuesOnly) {
    render();
    return;
  }
  render();
}

/** Step 2's pane for one connect mode: a one-line lead, the snippet, and its
 * action row. */
function startConnectPaneHTML(mode: ConnectModeId, option: StartOption, progress: StartProgress): string {
  const conn = progress.toolName
    ? state.connections.find((candidate) => candidate.name === progress.toolName) ?? null
    : null;
  const snip = (text: string) => `<pre class="setup-instructions"><code>${esc(text)}</code></pre>`;
  const copyBtn = (text: string, label: string) =>
    `<button class="btn primary sm" data-act="copy-text" data-text="${escAttr(text)}">${label}</button>`;
  const actions = (inner: string) => `<div class="start-actions">${inner}</div>`;

  switch (mode) {
    case 'direct': {
      if (!conn) {
        const prerequisite = option.connType === 'pg'
          ? 'Add a Postgres database first.'
          : option.connType === 'ssh'
          ? 'Add an SSH server first.'
          : `Add a ${esc(option.label)} tool first.`;
        return `<p>${prerequisite}</p>
          <div class="start-actions"><button class="btn primary sm" disabled>Get connection address</button></div>`;
      }
      const endpoint = conn.agent_access.endpoint ?? null;
      if (!endpoint) {
        const lead = conn.type === 'pg'
          ? `Get a local DSN for “${esc(conn.name)}” that any unmodified Postgres client can use —
              psql, drivers, ORMs.`
          : `Get a signing-agent socket for “${esc(conn.name)}”. Plain ssh, git, and rsync work
              unmodified; the private key never leaves this machine.`;
        return `<p>${lead}</p>
          <div class="start-actions"><button class="btn primary sm" data-act="issue-endpoint"
            data-conn="${conn.id}">Get connection address</button></div>`;
      }
      // The address itself is the deliverable: the same field as the
      // tool's row. Getting a new one / revoking stay in that row's ⋯ menu.
      const lead = conn.type === 'pg'
        ? 'Tell your agent to connect directly to this database.'
        : 'Tell your agent to connect directly to this server.';
      return `<p>${lead}</p>${endpointStripHTML(conn)}`;
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
  const clientSnippet = client.snippet(env);
  if (client.requiresCli && !client.inlineCliInstall) {
    return `<p>Install the AgentMFA CLI:</p>
      ${snip(CLI_INSTALL_COMMAND)}
      <p class="start-pane-next">${esc(client.lead(env))}</p>
      ${snip(clientSnippet)}
      ${actions(copyBtn(clientSnippet, client.copyLabel))}`;
  }
  const snippet = client.inlineCliInstall
    ? `${CLI_INSTALL_COMMAND}\n${clientSnippet}`
    : clientSnippet;
  return `<p>${esc(client.lead(env))}</p>
    ${snip(snippet)}${actions(copyBtn(snippet, client.copyLabel))}`;
}

// The centered walkthrough/guides switch directly under the page heading.
function startViewToggleHTML(): string {
  const btn = (view: StartView, label: string) =>
    `<button class="seg-btn ${state.startView === view ? 'on' : ''}"
      aria-pressed="${state.startView === view}" data-act="start-view" data-id="${view}">${label}</button>`;
  return `<div class="start-view-toggle"><div class="seg" role="group" aria-label="Get started view">
    ${btn('walkthrough', 'Quick start')}${btn('guides', 'Agent guides')}</div></div>`;
}

function startHTML(): string {
  const body = state.startView === 'guides'
    ? connectGuidesHTML()
    : startWalkthroughHTML();
  return `<div class="start">
    <div class="start-hero"><h3>Connect your agent to tools and services</h3></div>
    ${startViewToggleHTML()}
    ${globalSectionsHTML(true)}
    <div class="start-view-body">${body}</div>
  </div>`;
}

function startWalkthroughHTML(): string {
  const option = startOptionById(state.startOption);
  const catalogEntry = option.catalogId ? catalogEntryById(option.catalogId) : undefined;
  const progress = startProgress(option, state.connections);

  const picker = START_OPTIONS.map((candidate) => {
    const candidateEntry = candidate.catalogId ? catalogEntryById(candidate.catalogId) : undefined;
    const visibleLabel = candidate.showPickerLabel
      ? `<span class="start-pick-label">${esc(candidate.label)}</span>` : '';
    const limited = candidateEntry?.limitedSupport
      ? '<span class="start-pick-limited">Limited</span>' : '';
    const kind = startKindLabel(candidate);
    const fullLabel = kind ? `${candidate.label} ${kind}` : candidate.label;
    return `<button class="start-pick ${candidate.showPickerLabel ? 'has-label' : ''} ${candidate.id === option.id ? 'on' : ''}"
      aria-pressed="${candidate.id === option.id}"
      aria-label="${escAttr(fullLabel)}" title="${escAttr(fullLabel)}"
      data-act="start-option" data-id="${candidate.id}">
      <span class="start-pick-icon" aria-hidden="true">${ICONS[candidate.icon] || ''}</span>${visibleLabel}${limited}</button>`;
  }).join('');

  const step = (n: number, title: string, done: boolean, body: string): string =>
    `<li class="start-step ${done ? 'done' : ''}">
      <span class="start-num" aria-hidden="true">${n}</span>
      <div class="start-body"><b>${esc(title)}</b>${body}</div></li>`;

  const addAction = catalogEntry && canQuickConnectMcp(catalogEntry)
    ? 'catalog-connect-oauth' : 'catalog-add';
  const optionKind = startKindLabel(option);
  const optionName = optionKind ? `${option.label} ${optionKind}` : option.label;
  const addLabel = progress.added ? `${optionName} Connected` : `Add ${optionName}`;
  const addBody = `<p>AgentMFA supports databases, SSH, APIs, and MCPs.</p>
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

  // Over the direct endpoint the agent talks straight to the DSN/socket, so
  // the task leads with that endpoint (secret included) instead of the tool.
  const directConn = progress.toolName
    ? state.connections.find((candidate) => candidate.name === progress.toolName) ?? null
    : null;
  const directEndpoint = directConn?.agent_access.endpoint ?? null;
  const directAddress = directConn && directEndpoint
    ? directEndpointAddress(directConn.type, directEndpoint, state.sshSockets[directConn.id])
    : null;
  const task = connectMode === 'direct'
    ? directStartTask(
        option,
        progress,
        directEndpoint
          ? {
              ...directEndpoint,
              dsn: directAddress,
              sshInvocation: directConn?.type === 'ssh'
                ? sshInvocationCommand(directConn)
                : null,
            }
          : null,
      )
    : startTask(option, progress);
  const wireBody = `<pre class="setup-instructions"><code>${esc(task)}</code></pre>
    <div class="start-actions">
      <button class="btn primary sm" data-act="copy-text" data-text="${escAttr(task)}">Copy</button>
    </div>`;

  return `<ol class="start-steps">
      ${step(1, 'Select a tool to connect', progress.added, addBody)}
      ${step(2, 'Connect your agent', recentClients().length > 0, connectBody)}
      ${step(3, 'Ask for something useful', progress.wired, wireBody)}
    </ol>`;
}

/** The active tab's content: TSX for converted views, legacy markup for the
 * rest (crossing the SafeMarkup boundary). */
/** The dropdown's inline catalog search (the main window's lives in its
 * header). Controlled, so it needs no delegated handler; the legacy catalog
 * markup it sits above stays read-only. */
function DropdownCatalogSearch({ kind }: { kind: 'tool' | 'secret' }): ReactNode {
  const isTool = kind === 'tool';
  return (
    <input className="cat-search dd-cat-search" type="search"
      placeholder={isTool ? 'Search tools…' : 'Search secrets…'}
      aria-label={isTool ? 'Search tools' : 'Search secrets'}
      value={isTool ? state.toolSearch : state.secretSearch}
      onChange={(e) => {
        if (isTool) state.toolSearch = e.currentTarget.value;
        else state.secretSearch = e.currentTarget.value;
        render();
      }} />
  );
}

function TabContent(): ReactNode {
  if (state.tab === 'inbox') return <RequestInbox />;
  if (state.tab === 'activity') return <ActivityView />;
  // The dropdown puts its catalog search inline above the list; the wide
  // window has it in the header instead (see MainWindow). The ready card
  // stays above the search, where the one-markup-blob layout had it.
  if (mode === 'dropdown' && (state.tab === 'connections' || state.tab === 'secrets')) {
    const isTools = state.tab === 'connections';
    return (
      <>
        {isTools && <SafeMarkup markup={connectionReadyCardHTML()} />}
        <DropdownCatalogSearch kind={isTools ? 'tool' : 'secret'} />
        <SafeMarkup markup={isTools ? connectionsHTML(false) : secretsHTML()} />
      </>
    );
  }
  const markup = state.tab === 'start' ? startHTML()
    : state.tab === 'connections' ? connectionsHTML()
    : secretsHTML();
  return <SafeMarkup markup={markup} />;
}

function brokerReadyHTML() {
  const copied = state.readyCopied;
  // The badge tracks the *managed* broker: a remote link that is down must
  // not sit under a green "Ready".
  const tone = brokerTone(state.broker);
  const label = tone === 'error' ? 'Unreachable' : tone === 'pending' ? 'Connecting…' : 'Ready';
  return `<div class="dd-sub ready-status">
    <span class="ready-state" role="status"><span class="dot dot-${tone}" aria-hidden="true"></span>
      <span>${label}</span></span>
    <button class="ready-copy ${copied ? 'is-copied' : ''}"
      data-act="copy-ready-setup"
      title="${copied ? 'Setup instructions copied' : 'Copy setup instructions'}"
      aria-label="${copied ? 'Setup instructions copied' : 'Copy setup instructions'}">
      <span class="ready-copy-label" aria-live="polite">${copied ? `${ICONS.check} Copied` : 'Copy'}</span>
    </button></div>`;
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
          <span class="broker-check">${state.broker.mode === 'remote' ? '✓' : ''}</span> Connect remote…</button>
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
/** The full-pane broker takeover: the remote-setup form (controlled),
 * the connecting spinner, or the unreachable-broker error. */
function BrokerPane({ kind }: { kind: 'setup' | 'connecting' | 'error' }): ReactNode {
  if (kind === 'setup') {
    const setup = state.remoteSetup;
    const setupInstructions =
      '# To start a remote instance, run this behind a TLS proxy or tunnel:\n'
      + 'mfa serve --listen 0.0.0.0:4780\nmfa manage token';
    const hasSaved = state.broker.has_saved_token
      && (setup.url.trim() === '' || setup.url.trim().replace(/\/+$/, '') === (state.broker.url ?? ''));
    const insecureRemote = insecureNonLoopbackHttp(setup.url);
    return (
      <div className="broker-pane" role="form" aria-label="Connect to hosted AgentMFA">
        <div className="bp-icon"><Icon markup={ICONS.blocks} /></div>
        <h2>Connect to hosted AgentMFA</h2>
        <p className="bp-lead">Connect to a remote AgentMFA server with a management token.</p>
        <div className="adv-collapse">
          <button type="button" className="adv-toggle" aria-expanded={setup.advancedOpen}
            data-act="toggle-remote-advanced">
            <span className="adv-toggle-icon" aria-hidden="true"><Icon markup={ICONS.chevronDown} /></span>Advanced</button>
          {setup.advancedOpen && (
            <div className="bp-setup-wrap">
              <pre className="setup-instructions bp-setup-code"><code>{setupInstructions}</code></pre>
              <button className="btn sm" data-act="copy-text"
                data-text={setupInstructions}>Copy</button>
            </div>
          )}
        </div>
        <div className="f-row">
          <label htmlFor="rb-url">Hosted instance URL</label>
          <input id="rb-url" placeholder="https://agentmfa.aka.com" value={setup.url}
            autoComplete="off" spellCheck={false}
            onChange={(e) => { setup.url = e.currentTarget.value; render(); }} />
          {insecureRemote
            ? <div className="field-warning" role="alert">
                This sends the management token over unencrypted HTTP. Use HTTPS or a loopback URL.
              </div>
            : null}
        </div>
        <div className="f-row">
          <label htmlFor="rb-token">Management token</label>
          <input id="rb-token" type="password" value={setup.token} autoComplete="off"
            placeholder={hasSaved ? 'Using the saved token (paste to replace)' : 'akamgr_…'}
            onChange={(e) => { setup.token = e.currentTarget.value; render(); }} />
        </div>
        {setup.error && <div className="inline-error" role="alert">{setup.error}</div>}
        <div className="bp-actions">
          <button className="btn primary" data-act="broker-connect-submit" disabled={setup.busy}>
            {setup.busy ? 'Connecting…' : 'Connect'}</button>
          {state.broker.mode === 'remote' && !state.broker.connected
            ? <button className="btn ghost" data-act="broker-pick-local">Use this Mac instead</button>
            : <button className="btn ghost" data-act="broker-setup-cancel">Cancel</button>}
        </div>
      </div>
    );
  }
  if (kind === 'connecting') {
    return (
      <div className="broker-pane" role="status">
        <span className="app-loading-spinner"></span>
        <h2>Connecting to the remote broker</h2>
        <p className="bp-lead"><code>{state.broker.url ?? ''}</code></p>
        <div className="bp-actions">
          <button className="btn ghost" data-act="broker-pick-local">Use this Mac instead</button>
        </div>
      </div>
    );
  }
  const local = state.broker.mode === 'local';
  return (
    <div className="broker-pane broker-pane-error" role="alert">
      <div className="bp-icon bp-icon-error"><Icon markup={ICONS.circleX} /></div>
      <h2>{local ? 'The local broker isn’t responding' : 'Can’t reach the remote broker'}</h2>
      {!local && <p className="bp-lead"><code>{state.broker.url ?? ''}</code></p>}
      {state.broker.error && <p className="bp-detail">{state.broker.error}</p>}
      <div className="bp-actions">
        <button className="btn primary" data-act={local ? 'local-broker-retry' : 'broker-retry'}>
          Retry</button>
        {!local && <button className="btn" data-act="broker-edit">Edit connection…</button>}
        {!local && <button className="btn ghost" data-act="broker-pick-local">Use this Mac</button>}
      </div>
    </div>
  );
}

/** The effective appearance, as theme.js stamped it on <html> pre-paint. */
function currentTheme(): 'light' | 'dark' {
  return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light';
}

function Icon({ markup }: { markup: string }): ReactNode {
  return <SafeMarkup markup={markup} />;
}

/** The appearance toggle riding beside the settings gear, in both chromes. */
function ThemeButton({ className }: { className: string }): ReactNode {
  const dark = currentTheme() === 'dark';
  const label = `Switch to ${dark ? 'light' : 'dark'} appearance`;
  return (
    <button className={className} data-act="toggle-theme" title={label} aria-label={label}>
      <Icon markup={dark ? ICONS.sun : ICONS.moon} />
    </button>
  );
}

function viewLoadKeys(tab: Tab): LoadKey[] {
  switch (tab) {
    case 'start': return ['connections', 'identity', 'settings'];
    case 'connections': return ['connections'];
    case 'secrets': return ['secrets'];
    case 'activity': return ['activity', 'sessions'];
    case 'inbox': return ['approvals', 'elicitations', 'requests'];
  }
}

function LoadFailureBand(): ReactNode {
  const failures = viewLoadKeys(state.tab)
    .map((key) => [key, state.loadStatus[key]] as const)
    .filter(([, status]) => status.status === 'error');
  if (!failures.length) return null;
  const detail = failures.map(([, status]) => status.error).filter(Boolean).join(' · ');
  return (
    <div className="load-failure" role="alert">
      <div><b>Couldn’t load this view.</b>{detail ? <span>{detail}</span> : null}</div>
      <button className="btn sm" data-act="retry-view-loads">Retry</button>
    </div>
  );
}

function MainWindow(): ReactNode {
  const takeover = brokerTakeover(state.broker, state.remoteSetup.open);
  const requestCount = activeRequestCount(state.approvals, state.elicitations);
  const pageTitle = state.tab === 'connections' ? 'Connect tools'
    : state.tab === 'secrets' ? 'Manage secrets'
    : state.tab === 'inbox' ? 'Request inbox'
    // The sidebar keeps the tab's title-case label; the page header speaks
    // sentence case.
    : state.tab === 'activity' ? 'Activity log'
    : tabLabel(state.tab);

  const pageAction = state.tab === 'connections'
    ? <div className="dw-head-actions">
        <input id="tool-search" className="cat-search" type="search" placeholder="Search tools…"
          aria-label="Search tools" value={state.toolSearch}
          onChange={(e) => { state.toolSearch = e.currentTarget.value; render(); }} />
      </div>
    : state.tab === 'secrets'
      ? <div className="dw-head-actions">
          <input id="secret-search" className="cat-search" type="search" placeholder="Search secrets…"
            aria-label="Search secrets" value={state.secretSearch}
            onChange={(e) => { state.secretSearch = e.currentTarget.value; render(); }} />
        </div>
      : state.tab === 'activity'
        ? <button className="btn" data-act="clear-activity-ask"
            disabled={!state.activity.length}>Clear activity</button>
        : null;

  return (
    <>
      <div className="surface">
        <div className="dw-titlebar" data-tauri-drag-region="">
          <span className="dw-title dw-title-center">AgentMFA</span>
          <SafeMarkup markup={brokerSwitchHTML()} />
        </div>
        <div className="dw-body">
          <div className={`dw-side ${takeover ? 'disabled' : ''}`}>
            <div className="dw-brand">
              <div className="dd-appicon"><Icon markup={ICONS.blocks} /></div>
              <div><div className="dd-title">AgentMFA</div><SafeMarkup markup={brokerReadyHTML()} /></div>
            </div>
            <div className="dw-nav">
              {TABS.map((tab) => (
                <button key={tab} className={`nav-item ${state.tab === tab ? 'on' : ''}`}
                  data-act="tab" data-tab={tab} disabled={Boolean(takeover)}>
                  <span className="nav-tab-label">{tabLabel(tab)}</span>
                  {tab === 'inbox' && requestCount > 0
                    ? <span className="nav-count" aria-label={`${requestCount} pending requests`}>
                        {requestCount}
                      </span>
                    : null}
                </button>
              ))}
            </div>
            <div className="dw-settings">
              {!takeover && state.menuOpen && (
                <div className="settings-menu">
                  <div className="menu-version">Version {APP_VERSION}</div>
                  <button className="menu-item" data-act="mode-tray">
                    <Icon markup={ICONS.menubar} /> Minimize to menu bar
                  </button>
                  <button className="menu-item" data-act="open-settings">
                    <Icon markup={ICONS.gear} /> Settings
                  </button>
                </div>
              )}
              <button className={`nav-item gear-btn ${state.menuOpen ? 'on' : ''}`}
                data-act="toggle-settings-menu" title="Settings" aria-label="Settings"
                disabled={Boolean(takeover)}>
                <Icon markup={ICONS.gear} />
              </button>
              <ThemeButton className="nav-item theme-btn" />
            </div>
          </div>
          <div className="dw-main">
            {takeover
              ? <div className="content broker-takeover"><BrokerPane kind={takeover} /></div>
              : <>
                  {state.tab !== 'start' && (
                    <div className="dw-head">
                      <div className="dw-head-title">
                        <h2>{pageTitle}</h2>
                        {state.tab === 'inbox'
                          ? <span className={`request-total ${requestCount ? 'has-requests' : ''}`}
                              aria-live="polite">
                              {requestCount} pending
                            </span>
                          : null}
                      </div>
                      {pageAction}
                    </div>
                  )}
                  <SafeMarkup markup={state.tab === 'start' ? '' : globalSectionsHTML()} />
                  <LoadFailureBand />
                  <div className="content"><TabContent /></div>
                </>}
          </div>
        </div>
      </div>
      {!takeover && (
        <><Sheets /><SafeMarkup markup={endpointConfirmHTML() + deleteConnConfirmHTML()} /></>
      )}
    </>
  );
}

function DropdownWindow(): ReactNode {
  const takeover = brokerTakeover(state.broker, state.remoteSetup.open);
  const requestCount = activeRequestCount(state.approvals, state.elicitations);
  if (takeover) {
    return (
      <div className="surface dropdown-surface">
        <div className="dd-head">
          <div className="dd-appicon"><Icon markup={ICONS.blocks} /></div>
          <div className="dd-identity"><div className="dd-title">AgentMFA</div></div>
          <button className="icon-btn" title="Open as a window" aria-label="Open as a window"
            data-act="mode-window"><Icon markup={ICONS.expand} /></button>
        </div>
        <div className="content dd-content broker-takeover"><BrokerPane kind={takeover} /></div>
      </div>
    );
  }
  return (
    <>
      <div className="surface dropdown-surface">
        <div className="dd-head">
          <div className="dd-appicon"><Icon markup={ICONS.blocks} /></div>
          <div className="dd-identity">
            <div className="dd-title">AgentMFA</div><SafeMarkup markup={brokerReadyHTML()} />
          </div>
          <button className="icon-btn" title="Open as a window" aria-label="Open as a window"
            data-act="mode-window"><Icon markup={ICONS.expand} /></button>
          <ThemeButton className="icon-btn" />
          <button className="icon-btn" title="Settings" aria-label="Settings"
            data-act="open-settings"><Icon markup={ICONS.gear} /></button>
        </div>
        <div className="seg">
          {DROPDOWN_TABS.map((tab) => (
            <button key={tab} className={`seg-btn ${state.tab === tab ? 'on' : ''}`}
              data-act="tab" data-tab={tab}>
              <span>{tabLabel(tab)}</span>
              {tab === 'inbox' && requestCount > 0
                ? <span className="seg-count">{requestCount}</span>
                : null}
            </button>
          ))}
        </div>
        <SafeMarkup markup={state.tab === 'start' ? '' : globalSectionsHTML()} />
        <LoadFailureBand />
        <div className="content dd-content"><TabContent /></div>
      </div>
      <><Sheets /><SafeMarkup markup={endpointConfirmHTML() + deleteConnConfirmHTML()} /></>
    </>
  );
}

/**
 * Compatibility boundary for the remaining read-mostly view functions.
 *
 * The returned HTML is sanitized, parsed into React elements, and reconciled
 * in place by React—never assigned to innerHTML, never remounted wholesale.
 * Forms live in controlled TSX components, not here; no form inputs cross
 * this boundary today (the input/textarea branch below is a safety net that
 * keeps any future one uncontrolled). Elements carrying an id or data-id are keyed
 * on it, so list reorders move DOM instead of re-pairing it positionally.
 * New screens should be ordinary TSX components.
 */
function SafeMarkup({ markup }: { markup: string }): ReactNode {
  const clean = useMemo(() => {
    const out = String(DOMPurify.sanitize(markup, {
      USE_PROFILES: { html: true, svg: true, svgFilters: true },
      // focusable is the SVG a11y attribute keeping icons out of tab order;
      // the profiles don't know it and would silently strip it.
      ADD_ATTR: ['data-tauri-drag-region', 'focusable'],
    }));
    // The sanitizer drops anything outside its profiles silently; a legacy
    // helper using a new tag or attribute would just lose it. Surface that
    // in dev so the fix (ADD_ATTR/ADD_TAGS above) is a warning away.
    if (import.meta.env.DEV && DOMPurify.removed.length) {
      console.warn('SafeMarkup: sanitizer dropped markup', DOMPurify.removed);
    }
    return out;
  }, [markup]);

  const nodes = useMemo(() => {
    const options: HTMLReactParserOptions = {
      replace(node) {
        if (!(node instanceof ParsedElement)) return;
        if (node.name === 'input' || node.name === 'textarea') {
          const props = attributesToProps(node.attribs) as Record<string, unknown>;
          if ('value' in props) {
            props.defaultValue = props.value;
            delete props.value;
          }
          if ('checked' in props) {
            props.defaultChecked = props.checked;
            delete props.checked;
          }
          // A textarea's text children are its default value; passing both
          // them and defaultValue trips React's invariant and would take the
          // whole window down.
          if (node.name === 'textarea' && node.children.length) delete props.defaultValue;
          const identity = node.attribs.id ?? node.attribs.name;
          if (identity) props.key = identity;
          return createElement(
            node.name,
            props,
            node.name === 'textarea'
              ? domToReact(node.children as DOMNode[], options)
              : undefined,
          );
        }

        // Parsed nodes otherwise reconcile positionally; give rows and other
        // identified elements a stable key so reorders move DOM nodes
        // instead of rewriting each position's contents.
        const rowKey = node.attribs['data-id'] ?? node.attribs.id;
        if (rowKey) {
          // Sibling action buttons can share one data-id (one row's Connect
          // and its ⋯ menu); the act name keeps their keys distinct.
          const act = node.attribs['data-act'];
          return createElement(
            node.name,
            { ...attributesToProps(node.attribs), key: `${node.name}:${act ?? ''}:${rowKey}` },
            node.children.length
              ? domToReact(node.children as DOMNode[], options)
              : undefined,
          );
        }
        return;
      },
    };
    return parse(clean, options);
  }, [clean]);

  return nodes;
}

/** A row's right-click menu lives at the document root so no scroll pane or
 * rounded card can clip it. render() measures this portal and clamps its
 * pointer anchor to all four viewport edges. */
function ConnectionContextMenu(): ReactNode {
  const connection = state.connMenuPoint && state.connMenuOpen
    ? state.connections.find((candidate) => candidate.id === state.connMenuOpen)
    : null;
  if (!connection) return null;
  return createPortal(
    <div className="tile-menu-wrap conn-context-menu-wrap">
      <SafeMarkup markup={`<div class="tile-menu" role="menu"
        aria-label="Options for ${escAttr(connection.name)}">
        ${connectionMenuItemsHTML(connection)}
      </div>`} />
    </div>,
    document.body,
  );
}

function AppRoot(): ReactNode {
  // Subscribes this root to store publications; the revision itself is not
  // used as a key — the windows reconcile in place rather than remounting.
  useUiRevision(uiStore);
  const inboxVisible = booted && state.tab === 'inbox'
    && !brokerTakeover(state.broker, state.remoteSetup.open);
  useEffect(() => {
    void invoke('ui_set_request_inbox_visible', { visible: inboxVisible });
  }, [inboxVisible]);
  if (!booted) {
    // Mounting React replaced index.html's placeholder; keep the same
    // splash up until boot() has real data, instead of flashing a fully
    // chromed but empty window that snaps to the landing tab a beat later.
    return (
      <div className="app-loading" role="status" aria-label="Loading AgentMFA">
        <span className="app-loading-spinner" />
      </div>
    );
  }
  return (
    <>
      <RequestLiveRegion />
      {mode === 'dropdown' ? <DropdownWindow /> : <MainWindow />}
      <ConnectionContextMenu />
    </>
  );
}

function RequestLiveRegion(): ReactNode {
  const active = activeRequests(state.approvals, state.elicitations);
  const previousCount = useRef(0);
  const [announcement, setAnnouncement] = useState('');
  const count = active.length;
  const nextExpiry = active
    .map((request) => request.kind === 'approval'
      ? request.approval.expires_at
      : request.elicitation.expires_at)
    .sort()[0];
  useEffect(() => {
    if (count > previousCount.current) {
      const expiry = nextExpiry ? ` Next request expires in ${timeLeft(nextExpiry)}.` : '';
      setAnnouncement(
        `${count} request${count === 1 ? '' : 's'} waiting for your attention.${expiry}`,
      );
    }
    previousCount.current = count;
  }, [count, nextExpiry]);
  return <div className="sr-only" role="status" aria-live="assertive"
    aria-atomic="true">{announcement}</div>;
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
    `<div class="issued-ep-field">
      <div class="ep-label">${label}${note ? ` <span class="ep-note">${note}</span>` : ''}</div>
      <code class="ep-code">${esc(value)}</code>
      <button class="btn ghost sm" data-act="copy-endpoint" data-field="${fieldKey}" aria-label="Copy ${label}">Copy</button>
    </div>`;
  const secretField = info.secret
    ? field('Secret', info.secret, 'secret')
    : '';
  const sheetSubtitle = info.type === 'ssh'
    ? "Paste this into your tool's config. Note: SSH addresses have no separate secret; the socket path is the whole capability. You can copy it again anytime from the tool's details."
    : "Paste this into your tool's config. You can copy it again anytime from the tool's details.";
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet endpoint-issued-sheet" role="dialog" aria-modal="true" aria-labelledby="ep-title">
      <h3 id="ep-title">Your connection address</h3>
      <p class="sheet-sub">${sheetSubtitle}</p>
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
      <h3 id="ep-confirm-title">${reissue ? 'Get a new address?' : 'Revoke this address?'}</h3>
      <p>${reissue
        ? 'You’ll get a new address to paste into your tools. The current address stops working the moment the new one is issued.'
        : `Tools using ${esc(name)}’s address lose access immediately.`}</p>
      <div class="sheet-actions">
        <button class="btn" data-act="confirm-cancel">Cancel</button>
        ${reissue
          ? `<button class="btn primary" data-act="reissue-endpoint-confirm" data-conn="${escAttr(String(confirm.id ?? ''))}">Get new address</button>`
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
      <p>The connection and its settings will be removed.${enabled ? ' Agents will lose access immediately.' : ''}</p>
      <div class="sheet-actions">
        <button class="btn" data-act="confirm-cancel">Cancel</button>
        <button class="btn danger" data-act="del-conn-confirm" data-id="${escAttr(String(confirm.id ?? ''))}">Delete</button>
      </div></div>`;
}

/** The open sheet: converted forms render as controlled TSX, the rest as
 * legacy markup across the SafeMarkup boundary. */
function Sheets(): ReactNode {
  if (!state.sheet) return null;
  switch (state.sheet.kind) {
    case 'add-secret': return <SecretSheet editing={false} />;
    case 'edit-secret': return <SecretSheet editing />;
    case 'add-conn': return <ConnSheet editing={false} />;
    case 'edit-conn': return <ConnSheet editing />;
    case 'wiring-tools': return <WiringToolsSheet />;
    case 'settings': return <SafeMarkup markup={settingsSheet()} />;
    case 'clear-activity': return <SafeMarkup markup={clearActivitySheet()} />;
    case 'elicitation': return <ElicitationSheet />;
    case 'approval': return <ApprovalSheet />;
    case 'mcp-auth': return <SafeMarkup markup={mcpAuthSheet()} />;
    case 'endpoint-issued': return <SafeMarkup markup={endpointIssuedSheet()} />;
    default: return null;
  }
}

/**
 * The elicitation dialog for an upstream SEP-2322 input request.
 *
 * Shaped like a native macOS alert: symbol on top, a bold one-line message
 * naming who is asking, then the upstream's own question as the quiet
 * informative text, the fields, and a right-aligned button row with the
 * default action last. The prompt is third-party text: rendered verbatim
 * and inert, and the chrome (title, not prompt) is what says who is asking.
 */
function ElicitationSheet(): ReactNode {
  const request = state.elicitations.find((r) => r.id === state.sheet?.id);
  if (!request) {
    return (
      <>
        <div className="sheet-backdrop" data-act="sheet-cancel"></div>
        <div className="sheet elicit-sheet" role="alertdialog" aria-modal="true" aria-labelledby="elicit-title">
          <div className="elicit-dlg-ico"><Icon markup={ICONS.bell} /></div>
          <h3 id="elicit-title" className="elicit-dlg-title">This request is gone</h3>
          <div className="elicit-dlg-context">It was answered somewhere else or expired.</div>
          <div className="sheet-actions elicit-dlg-actions">
            <button className="btn primary" data-act="sheet-cancel">OK</button>
          </div>
        </div>
      </>
    );
  }
  return (
    <>
      <div className="sheet-backdrop" data-act="sheet-cancel"></div>
      <div className="sheet elicit-sheet" role="alertdialog" aria-modal="true" aria-labelledby="elicit-title">
        <div className="elicit-dlg-ico"><Icon markup={ICONS.bell} /></div>
        <h3 id="elicit-title" className="elicit-dlg-title untrusted-identity" dir="auto">
          {agentLabel(request.agent)} says {request.connection} asked for input
        </h3>
        {/* Third-party text: rendered verbatim and inert. */}
        <div className="elicit-dlg-question untrusted-identity" dir="auto">{request.prompt}</div>
        {/* The upstream asked for something credential-shaped. It still gets
            its form — the match is a guess about prose, and refusing on it
            broke ordinary fields whose names merely read like secrets — but
            the user gets told, in our voice, what this channel is not for. */}
        {request.credential_warning
          ? (
            <div className="elicit-credential-warn">
              <Icon markup={ICONS.shieldAlert} />
              <span>
                Don’t enter a password, API key, or other credential here.
                This form is a round trip to {request.connection} over MCP: whatever you type is
                sent back to it as ordinary text, and AgentMFA neither masks nor stores it.
                Credentials belong in <strong>Secrets</strong>, where they stay in the Keychain and
                are attached to traffic without passing through a prompt.
              </span>
            </div>
          )
          : null}
        <div className="elicit-dlg-fields">
          {request.fields.map((field, index) => {
            const required = elicitFieldRequired(field);
            return (
            <label className="elicit-field" key={field.name}>
              <span className="untrusted-identity" dir="auto">
                {field.label} {required ? <b aria-hidden="true">*</b>
                  : <span className="label-detail">(optional)</span>}
              </span>
              {field.boolean ? (
                // A yes/no field: a checkbox whose value is stored as the
                // string 'true'/'false' (the broker coerces it to a real JSON
                // boolean before it rides upstream).
                <input id={`elicit-${request.id}-${field.name}`} type="checkbox"
                  className="elicit-toggle"
                  aria-required={required}
                  checked={state.elicitValues[field.name] === 'true'}
                  onChange={(e) => {
                    state.elicitValues[field.name] = e.currentTarget.checked ? 'true' : 'false';
                    delete state.sheetErrors[`elicit:${field.name}`];
                    render();
                  }} />
              ) : field.options?.length ? (
                // A fixed choice set: the shared form dropdown, keyed by the
                // field's index so an arbitrary upstream field name cannot
                // produce an invalid DOM id. select-pick writes elicitValues.
                <CustomSelect id={`elicit-sel-${index}`}
                  options={[
                    ...(required ? [] : [['', 'Not provided'] as [string, string]]),
                    ...field.options.map((opt): [string, string] => [opt, opt]),
                  ]}
                  ariaRequired={required}
                  selectedValue={state.elicitValues[field.name]
                    ?? (required ? field.options[0] : '')} />
              ) : (
                // Always plain text, whatever the schema declared. A masked
                // field is the affordance that says "this is a credential,
                // type it here", which is the one claim this prompt must
                // never make. The password-manager opt-outs are part of the
                // same point: an autofill offer is that affordance too, just
                // drawn by the browser instead of by us.
                <input id={`elicit-${request.id}-${field.name}`}
                  type="text" autoComplete="off" spellCheck={false}
                  aria-required={required}
                  autoCapitalize="off" autoCorrect="off"
                  data-1p-ignore="true" data-lpignore="true" data-bwignore="true"
                  data-form-type="other"
                  value={state.elicitValues[field.name] ?? ''}
                  onChange={(e) => {
                    state.elicitValues[field.name] = e.currentTarget.value;
                    delete state.sheetErrors[`elicit:${field.name}`];
                    render();
                  }} />
              )}
              <FieldError k={`elicit:${field.name}`} />
            </label>
            );
          })}
        </div>
        <div className="sheet-actions elicit-dlg-actions">
          <button className="btn elicit-refuse-btn" data-act="elicit-refuse" data-id={request.id}>Refuse</button>
          <span className="elicit-dlg-spacer"></span>
          <button className="btn" data-act="sheet-cancel">Cancel</button>
          <button className="btn primary" data-act="elicit-send" data-id={request.id}>Send to {request.connection}</button>
        </div>
      </div>
    </>
  );
}

/**
 * The traffic-confirmation dialog.
 *
 * Same alert shape as the elicitation sheet, and deliberately so — but the
 * question is the opposite one. There, the upstream asks the user for
 * input; here, AgentMFA asks whether the traffic should happen at all, and
 * the answer is a decision about access rather than a value to forward.
 *
 * The three answers are the whole point of the switch: let this through for
 * a while, stop asking altogether, or refuse. "Stop asking" turns the
 * connection's confirmation off, which the broker treats as removing a
 * gate — it runs its own native authentication before applying it, so a
 * stray click cannot silently disarm the switch.
 */
function ApprovalSheet(): ReactNode {
  const approval = state.approvals.find((a) => a.id === state.sheet?.id);
  if (!approval) {
    return (
      <>
        <div className="sheet-backdrop" data-act="sheet-cancel"></div>
        <div className="sheet elicit-sheet" role="alertdialog" aria-modal="true" aria-labelledby="approval-title">
          <div className="elicit-dlg-ico"><Icon markup={ICONS.shieldAlert} /></div>
          <h3 id="approval-title" className="elicit-dlg-title">This request is gone</h3>
          <div className="elicit-dlg-context">
            It was answered elsewhere, or nobody answered in time and the call was refused.
          </div>
          <div className="sheet-actions elicit-dlg-actions">
            <button className="btn primary" data-act="sheet-cancel">OK</button>
          </div>
        </div>
      </>
    );
  }
  const minutes = Math.max(1, Math.round(approval.window_secs / 60));
  const answering = state.approvalAnswering !== null;
  return (
    <>
      <div className="sheet-backdrop" data-act="sheet-cancel"></div>
      <div className="sheet elicit-sheet" role="alertdialog" aria-modal="true" aria-labelledby="approval-title">
        <div className="elicit-dlg-ico"><Icon markup={ICONS.shieldAlert} /></div>
        <h3 id="approval-title" className="elicit-dlg-title untrusted-identity" dir="auto">
          {agentLabel(approval.agent)} {approvalUnit(approval)}
        </h3>
        <div className="elicit-dlg-context untrusted-identity" dir="auto">
          {approval.connection} · {approval.target}
        </div>
        {/* The call itself, verbatim and inert: it is the agent's text. */}
        <div className="approval-call">
          <div className="approval-summary untrusted-identity" dir="auto">{approval.summary}</div>
          {approval.detail
            ? <pre className="approval-detail untrusted-identity" dir="auto">{approval.detail}</pre>
            : null}
        </div>
        {/* What Approve actually hands over. Outside the block above on
            purpose: that is the agent's text, this is ours, and the whole
            point is that it cannot be reworded by the thing being approved. */}
        {approval.consequence
          ? (
            <div className="approval-consequence">
              <Icon markup={ICONS.shieldAlert} />
              <span>{approval.consequence}</span>
            </div>
          )
          : null}
        <div className="elicit-dlg-context approval-meta">
          {approval.waiting > 1
            ? `${approval.waiting} calls are waiting on this answer · `
            : ''}
          Refused automatically in {timeLeft(approval.expires_at)}
        </div>
        <div className="sheet-actions elicit-dlg-actions approval-actions">
          <button className="btn elicit-refuse-btn" data-act="approval-deny"
            data-id={approval.id} disabled={answering}>Deny</button>
          <span className="elicit-dlg-spacer"></span>
          <button className="btn" data-act="approval-approve-all"
            data-id={approval.id} disabled={answering}
            title="Allow this call and turn traffic confirmation off for this tool">Stop asking</button>
          <button className="btn primary" data-act="approval-approve-window"
            data-id={approval.id} disabled={answering}>
            {answering ? 'Answering…' : `Approve ${minutes}m`}
          </button>
        </div>
      </div>
    </>
  );
}

/**
 * Per-wiring tool picker: which of an MCP server's tools one agent may
 * call. "All tools" is the default and the reset; a curated subset is
 * enforced broker-side on every tools/call, and the sidecar lists only
 * what is callable.
 */
function WiringToolsSheet(): ReactNode {
  const wt = state.wiringTools;
  if (!wt) return null;
  const allChecked = wt.selected === null;
  const isChecked = (name: string): boolean => allChecked || (wt.selected || []).includes(name);
  const tools = wt.tools || [];
  const toggleTool = (tool: string): void => {
    if (wt.selected === null) {
      // Unchecking one tool from "all" starts a subset of the rest.
      wt.selected = tools.map((t) => t.name).filter((name) => name !== tool);
    } else if (wt.selected.includes(tool)) {
      wt.selected = wt.selected.filter((name) => name !== tool);
    } else {
      wt.selected = [...wt.selected, tool];
    }
    render();
  };
  const toggleAll = (): void => {
    // Checking "All tools" clears curation; unchecking starts a subset
    // from everything currently advertised.
    wt.selected = wt.selected === null ? tools.map((t) => t.name) : null;
    render();
  };
  let body: ReactNode;
  if (wt.loading) {
    body = <div className="cc-test running">Asking the server for its tools…</div>;
  } else {
    // A curated subset may name tools the live list doesn't include — the
    // server stopped advertising them, or the list couldn't be fetched at
    // all (a lapsed sign-in). Keep them visible and editable so the subset
    // can still be trimmed and saved without reconnecting first.
    const stale = (wt.selected || []).filter((name) => !tools.some((tool) => tool.name === name));
    const staleNote = wt.error ? 'Saved earlier — reconnect to confirm it still exists'
      : 'No longer advertised by the server';
    body = (
      <>
        {/* When the live list is unavailable, the picker still works off the
            saved selection: keep or trim it and save, no sign-in required. */}
        {wt.error && (
          <div className="cc-test warn"><Icon markup={ICONS.circleX} />
            <span>Couldn’t refresh the tool list from the server — showing your saved selection.
              Reconnect the tool to see every tool.</span></div>
        )}
        {wt.stale && (
          <div className="cc-test warn"><Icon markup={ICONS.circleX} />
            <span>Showing the last successful tool list from{' '}
              {wt.fetchedAt ? new Date(wt.fetchedAt).toLocaleString() : 'an earlier check'}
              {wt.cacheAgeSeconds ? ` (${wt.cacheAgeSeconds}s old)` : ''}.</span></div>
        )}
        {wt.truncated && (
          <div className="cc-test warn"><span>The server’s tool catalog was capped at{' '}
            {tools.length} entries. Narrow the upstream catalog to curate tools beyond this list.</span></div>
        )}
        <label className="wt-row wt-all">
          <input type="checkbox" checked={allChecked} onChange={toggleAll} />
          <span className="wt-name"><b>All tools</b>
            <span className="wt-desc">New tools the server adds later are callable too</span></span>
        </label>
        <div className={`wt-list ${allChecked ? 'wt-dim' : ''}`}>
          {tools.map((tool) => (
            <label key={tool.name} className="wt-row">
              <input type="checkbox" checked={isChecked(tool.name)}
                onChange={() => toggleTool(tool.name)} />
              <span className="wt-name"><code>{tool.display_name || tool.name}</code>
                {tool.description ? <span className="wt-desc">{tool.description}</span> : null}</span>
            </label>
          ))}
          {stale.map((name) => (
            <label key={`stale:${name}`} className="wt-row wt-stale">
              <input type="checkbox" checked onChange={() => toggleTool(name)} />
              <span className="wt-name"><code>{name}</code>
                <span className="wt-desc">{staleNote}</span></span>
            </label>
          ))}
        </div>
      </>
    );
  }
  const count = wt.selected === null
    ? 'every tool'
    : `${wt.selected.length} tool${wt.selected.length === 1 ? '' : 's'}`;
  return (
    <>
      <div className="sheet-backdrop" data-act="sheet-cancel"></div>
      <div className="sheet wide" role="dialog" aria-modal="true" aria-labelledby="wt-title">
        <h3 id="wt-title">Tools agents may call on {wt.connectionName}</h3>
        <p className="wt-sub">Agents can call {count} on this server. Everything
          unchecked is refused by the broker and hidden from the agent's tool list.</p>
        {body}
        <div className="sheet-actions">
          <button className="btn" data-act="sheet-cancel">Cancel</button>
          <button className="btn primary" data-act="wt-save" disabled={wt.loading || wt.saving}>
            {wt.saving ? 'Saving…' : 'Save'}</button>
        </div>
      </div>
    </>
  );
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
const fieldCls = (key: string): string => (state.sheetErrors[key] ? 'err' : '');
/** Custom select shared by every dropdown in the form sheets: a trigger
 * button plus a fixed-position listbox portaled under #overlays so the
 * scrolling sheet cannot clip it (see positionFormMenu). Selection is
 * applied by the delegated select-pick handler writing the draft. */
function CustomSelect({ id, options, selectedValue, errCls = '', ariaRequired }: {
  id: string;
  options: Array<[string, string]>;
  selectedValue: string | null | undefined;
  errCls?: string;
  ariaRequired?: boolean;
}): ReactNode {
  const open = state.formMenuOpen === id;
  const selected = options.find(([value]) => value === selectedValue) ?? options[0];
  return (
    <div className="cred-select">
      <button type="button" id={id} className={`cred-trigger ${errCls}`} value={selected[0]}
        data-act="select-toggle" data-menu={id} aria-haspopup="listbox" aria-expanded={open}
        aria-required={ariaRequired}>
        <span className="cred-name">{selected[1]}</span>
        <span className="cred-chevron" aria-hidden="true"><Icon markup={ICONS.chevronDown} /></span>
      </button>
      {open && createPortal(
        <div className="cred-menu" role="listbox">
          {options.map(([value, label]) => (
            <button type="button" key={value} className="cred-opt" role="option" data-act="select-pick"
              data-menu={id} data-id={value} aria-selected={value === selected[0]}>
              <span className="cred-opt-col"><span className="cred-name">{label}</span></span>
              {value === selected[0]
                ? <span className="cred-opt-check"><Icon markup={ICONS.check} /></span> : null}
            </button>
          ))}
        </div>,
        overlays(),
        `select:${id}`,
      )}
    </div>
  );
}

/** Inline validation message under a controlled field. */
function FieldError({ k }: { k: string }): ReactNode {
  return state.sheetErrors[k] ? <div className="field-error">{state.sheetErrors[k]}</div> : null;
}

function FormGlobalError(): ReactNode {
  const message = state.sheetErrors._global;
  if (!message) return null;
  return (
    <div className="form-global-error" role="alert">
      <b>{message}</b>
      {state.sheetErrors._detail ? <span>{state.sheetErrors._detail}</span> : null}
    </div>
  );
}

/** Any add-form edit makes the last failed connection test stale. */
function disarmDraftTestOverride(): void {
  if (state.sheet?.kind === 'add-conn' && state.draftTestOverride) {
    state.draftTestOverride = false;
  }
}

/** Controlled-field write: update the draft, clear the field's stale
 * validation error (matching the old delegated-input behavior), and any
 * add-form edit disarms a failed draft test's save-anyway override. */
function setDraftField(key: keyof ConnectionDraft & string, errKey: string, value: string): void {
  (state.draft as Record<string, unknown>)[key] = value;
  // A hand-edited fingerprint is the user's own claim, not the lookup's; it
  // must survive later host/port corrections.
  if (key === 'hostKeyFingerprint') state.draft.hostKeyAutoPinned = undefined;
  if (state.sheetErrors[errKey]) delete state.sheetErrors[errKey];
  delete state.sheetErrors._global;
  delete state.sheetErrors._detail;
  disarmDraftTestOverride();
  render();
}

function SecretSheet({ editing }: { editing: boolean }): ReactNode {
  const d = state.draft;
  return (
    <>
      <div className="sheet-backdrop" data-act="sheet-cancel"></div>
      <div className="sheet wide">
        <h3>{editing ? 'Edit secret' : 'Add secret'}</h3>
        <div className="f-row">
          <label htmlFor="f-name">Name</label>
          <input id="f-name" className={fieldCls('name')} placeholder="e.g. STRIPE_API_KEY"
            value={d.name ?? ''}
            onChange={(e) => setDraftField('name', 'name', e.currentTarget.value)} />
          <FieldError k="name" />
        </div>
        <div className="f-row">
          <label htmlFor="f-value">{editing ? 'New value (saved to macOS Keychain)' : 'Value'}</label>
          <input id="f-value" className={fieldCls('value')} type="password"
            placeholder={editing ? '' : 'Your secret (saved in Keychain)'}
            value={d.value ?? ''}
            onChange={(e) => setDraftField('value', 'value', e.currentTarget.value)} />
          <FieldError k="value" />
        </div>
        <FormGlobalError />
        <div className="sheet-actions">
          <button className="btn" data-act="sheet-cancel">Cancel</button>
          <button className="btn primary" data-act="save-secret">Save</button>
        </div>
      </div>
    </>
  );
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

function automaticConnectionName(): string {
  return defaultConnectionName(
    state.connType,
    state.connEntryName || catalogNameForType(state.connType),
    state.connections.map((connection) => connection.name),
  );
}

function CredentialChooser({ type, allowNew = true, valueHint }: {
  type: ConnectionType;
  allowNew?: boolean;
  valueHint?: string;
}): ReactNode {
  const draft = state.draft;
  const allowNone = secretAllowsNone(type);
  const source = defaultSecretSource(type, draft, allowNew);
  const secretLabel = type === 'pg' ? 'Database password'
    : type === 'ssh' ? 'SSH private key'
    : 'Token or API key';
  const keyBadge = <span className="cred-badge" aria-hidden="true"><Icon markup={ICONS.keyRound} /></span>;
  const plusBadge = <span className="cred-badge plus" aria-hidden="true"><Icon markup={ICONS.plus} /></span>;
  const noneBadge = <span className="cred-badge none" aria-hidden="true"><Icon markup={ICONS.circleSlash} /></span>;
  let picker: ReactNode = null;
  if (state.secrets.length || allowNew || allowNone) {
    // No default selection: a wrong prefilled secret (a password where a
    // private key belongs, or vice versa) is worse than an explicit choice.
    const selected = source === 'existing'
      ? state.secrets.find((secret) => secret.id === draft.secretId) || null
      : null;
    const open = state.formMenuOpen === 'c-secret';
    const triggerContent = selected
      ? <>{keyBadge}<span className="cred-name">{selected.name}</span></>
      : source === 'new'
      ? <>{plusBadge}<span className="cred-name">New secret…</span></>
      : source === 'none'
      ? <>{noneBadge}<span className="cred-name">None</span></>
      : <span className="cred-name cred-placeholder">Choose a secret…</span>;
    picker = (
      <div className="f-row">
        <label htmlFor="c-secret">{secretLabel}</label>
        <div className="cred-select">
          {/* The trigger carries the selection as its value so the sheet-open
              baseline reads it exactly like the native select it replaced. */}
          <button type="button" id="c-secret" className={`cred-trigger ${fieldCls('secret')}`}
            value={selected ? selected.id
              : source === 'new' ? NEW_CREDENTIAL_OPTION
              : source === 'none' ? NO_CREDENTIAL_OPTION : ''}
            data-act="select-toggle" data-menu="c-secret"
            aria-haspopup="listbox" aria-expanded={open}>
            {triggerContent}
            <span className="cred-chevron" aria-hidden="true"><Icon markup={ICONS.chevronDown} /></span>
          </button>
          {open && createPortal(
            <div className="cred-menu" role="listbox">
              {state.secrets.map((secret) => {
                const picked = selected !== null && selected.id === secret.id;
                return (
                  <button type="button" key={secret.id} className="cred-opt" role="option"
                    data-act="credential-pick" data-id={secret.id} aria-selected={picked}>
                    {keyBadge}
                    <span className="cred-opt-col"><span className="cred-name">{secret.name}</span></span>
                    {picked ? <span className="cred-opt-check"><Icon markup={ICONS.check} /></span> : null}
                  </button>
                );
              })}
              {allowNew && (
                <>
                  {state.secrets.length ? <div className="cred-menu-divider"></div> : null}
                  <button type="button" className="cred-opt" role="option" data-act="credential-pick"
                    data-id={NEW_CREDENTIAL_OPTION} aria-selected={source === 'new'}>
                    {plusBadge}
                    <span className="cred-opt-col"><span className="cred-name">New secret…</span></span>
                  </button>
                </>
              )}
              {allowNone && (
                <>
                  {allowNew || !state.secrets.length ? null : <div className="cred-menu-divider"></div>}
                  <button type="button" className="cred-opt" role="option" data-act="credential-pick"
                    data-id={NO_CREDENTIAL_OPTION} aria-selected={source === 'none'}>
                    {noneBadge}
                    <span className="cred-opt-col"><span className="cred-name">None</span></span>
                    {source === 'none'
                      ? <span className="cred-opt-check"><Icon markup={ICONS.check} /></span> : null}
                  </button>
                </>
              )}
            </div>,
            overlays(),
            'select:c-secret',
          )}
        </div>
        <FieldError k="secret" />
      </div>
    );
  } else if (source === 'new') {
    picker = <div className="f-row"><label>{secretLabel}</label></div>;
  }
  if (source !== 'new') {
    return <div className="credential-group">{picker}</div>;
  }
  const suggested = suggestedSecretName(draft.name ?? '', type);
  const effectiveName = (draft.newSecretName || suggested).trim();
  const nameTaken = credentialNameIsTaken(effectiveName);
  const nameRow = (
    <div className="f-row">
      <label htmlFor="c-new-secret-name">Credential name</label>
      <input id="c-new-secret-name"
        className={`${fieldCls('newSecretName')} ${nameTaken ? 'name-conflict-warning' : ''}`}
        aria-describedby="credential-name-warning" placeholder={suggested}
        value={draft.newSecretName ?? ''}
        onChange={(e) => setDraftField('newSecretName', 'newSecretName', e.currentTarget.value)} />
      <FieldError k="newSecretName" />
      <div id="credential-name-warning" className="field-warning" role="status" aria-live="polite"
        hidden={!nameTaken}>Name used by an existing credential</div>
    </div>
  );
  // Shown only after the backend reports the key is encrypted: a passphrase
  // field on every SSH form would imply one is expected, and most are not. The
  // passphrase decrypts the key once, here; what the vault seals is the
  // cleartext OpenSSH form, and the vault is the protection boundary for it.
  const passphraseRow = type === 'ssh' && state.sheetErrors.keyPassphrase !== undefined
    ? (
      <div className="f-row" key="key-passphrase">
        <label htmlFor="c-key-passphrase">Key passphrase</label>
        <input id="c-key-passphrase" className={fieldCls('keyPassphrase')} type="password"
          placeholder="Passphrase for this private key"
          value={draft.keyPassphrase ?? ''}
          onChange={(e) => setDraftField('keyPassphrase', 'keyPassphrase', e.currentTarget.value)} />
        <FieldError k="keyPassphrase" />
        <div className="rule-note">
          Used once, to unlock the key. AgentMFA stores the unlocked key in the
          system keychain and never keeps the passphrase.
        </div>
      </div>
    )
    : null;
  if (type === 'ssh' && draft.sshImportId && draft.identityFiles && draft.identityFiles.length) {
    const identityOptions = draft.identityFiles.map((path): [string, string] => [path, path]);
    return (
      <div className="credential-group">
        {picker}{nameRow}
        <div className="f-row">
          <label htmlFor="c-identity-file">Identity file</label>
          <CustomSelect id="c-identity-file" options={identityOptions} selectedValue={draft.identityFile} />
          <FieldError k="newSecretValue" />
          <div className="rule-note">Saved directly to macOS Keychain</div>
        </div>
        {passphraseRow}
      </div>
    );
  }
  const valuePlaceholder = valueHint ? `Paste your key (${valueHint})`
    : type === 'pg' ? 'Paste the database password'
    : type === 'ssh' ? 'Paste the private key'
    : 'Paste the token or API key';
  return (
    <div className="credential-group">
      {picker}{nameRow}
      <div className="f-row">
        <label htmlFor="c-new-secret-value">Credential value</label>
        <input id="c-new-secret-value" className={fieldCls('newSecretValue')} type="password"
          placeholder={valuePlaceholder}
          value={draft.newSecretValue ?? draft.importedCredential ?? ''}
          onChange={(e) => setDraftField('newSecretValue', 'newSecretValue', e.currentTarget.value)} />
        <FieldError k="newSecretValue" />
      </div>
      {passphraseRow}
    </div>
  );
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
  if (t === 'pg' || t === 'api') return Boolean((d.pgCaBundlePath || '').trim());
  return false;
}

const PG_SSL_OPTIONS: Array<[string, string]> = [
  ['verify-full', 'Require TLS (verify certificate)'],
  ['require', 'Require TLS (server not verified)'],
  ['prefer', 'Prefer TLS (may use plaintext; server not verified)'],
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

function ConnSheet({ editing }: { editing: boolean }): ReactNode {
  const d = state.draft;
  const t = state.connType;
  const sheetId = state.sheet?.id;
  const conn = editing ? state.connections.find((c) => c.id === sheetId) : null;
  const editPresentation = conn ? connectionEditPresentation(conn) : null;
  const managedMcpOAuth = Boolean(editPresentation?.managedMcpOAuth);
  // Identity fields keep deriving the automatic name until the user edits
  // the name directly; a pg host may keep adjusting the TLS prefill.
  const onIdentityField = (key: 'user' | 'host' | 'port', errKey: string) =>
    (e: { currentTarget: HTMLInputElement }) => {
      d[key] = e.currentTarget.value;
      if (state.sheetErrors[errKey]) delete state.sheetErrors[errKey];
      disarmDraftTestOverride();
      if (state.sheet?.kind === 'add-conn' && d.nameIsAutomatic) {
        d.name = automaticConnectionName();
      }
      if (key === 'host' && state.sheet?.kind === 'add-conn' && t === 'pg') {
        applyLoopbackTlsPrefill(d);
      }
      if (t === 'ssh' && (key === 'host' || key === 'port')) {
        d.hostKeyCandidates = undefined;
        d.hostKeyCheckMessage = undefined;
        // A fingerprint filled from the lookup was learned for the old
        // destination; keeping it would pin the wrong host's key. Typed
        // values are the user's own claim and survive.
        if (d.hostKeyAutoPinned) {
          d.hostKeyFingerprint = null;
          d.hostKeyAutoPinned = undefined;
        }
      }
      render();
    };
  const importWarnings = !editing && d.importWarnings && d.importWarnings.length
    ? <div className="pair-identity-warning import-warning" key="import-warnings"><b>Review imported details</b>
        <ul>{d.importWarnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></div>
    : null;
  // Paste-to-prefill: a Postgres DSN or `ssh` command fills the form below
  // instead of making the user retype what they already have.
  const canImport = !editing && (t === 'pg' || t === 'ssh');
  const importRow = canImport && (
    <div className="f-row sheet-import" key="import">
      <label htmlFor="conn-import">Connection string</label>
      <div className="sheet-import-row">
        <input id="conn-import" className={state.connImportError ? 'field-invalid' : ''} type="text"
          spellCheck={false} autoCapitalize="off" autoCorrect="off"
          placeholder={quickSetupPlaceholder(t)} value={state.connImportSource}
          onChange={(e) => {
            state.connImportSource = e.currentTarget.value;
            state.connImportError = null;
            if (state.draftTestOverride) state.draftTestOverride = false;
            render();
          }} />
        <button className="btn" data-act="conn-import"
          disabled={!state.connImportSource.trim()}>Prefill</button>
      </div>
      {state.connImportError && <div className="field-error">{state.connImportError}</div>}
    </div>
  );
  const importDivider = canImport && <div className="sheet-import-divider" key="import-divider"><span>or</span></div>;
  const fields: ReactNode[] = [importRow, importDivider, importWarnings];
  const nameTaken = !editing && toolNameIsTaken(d.name ?? '');
  const namePlaceholder = (!editing && state.connEntryName) || catalogNameForType(t);
  fields.push(
    <div className="f-row" key="name">
      <label htmlFor="f-cname">Name</label>
      <input id="f-cname" className={`${fieldCls('name')} ${nameTaken ? 'name-conflict-warning' : ''}`}
        aria-describedby={editing ? undefined : 'tool-name-warning'}
        placeholder={namePlaceholder} value={d.name ?? ''}
        onChange={(e) => {
          d.nameIsAutomatic = false;
          setDraftField('name', 'name', e.currentTarget.value);
        }}
        onBlur={(e) => {
          // Internal spaces are valid service-name characters, but edge
          // whitespace is not part of the stored name. Reflect the submitted
          // value as soon as the field is left instead of trimming invisibly.
          const trimmed = e.currentTarget.value.trim();
          if (trimmed !== d.name) { d.name = trimmed; render(); }
        }} />
      <FieldError k="name" />
      {!editing && (
        <div id="tool-name-warning" className="field-warning" role="status" aria-live="polite"
          hidden={!nameTaken}>Name used by an existing tool</div>
      )}
    </div>,
  );
  let sshHostKeyField: ReactNode = null;
  let pgTlsFields: ReactNode = null;
  let apiTlsFields: ReactNode = null;
  if (t === 'api' && isMcpDraft(d)) {
    const url = d.origin
      ?? (d.host
        ? `${apiOriginFromParts(d.scheme ?? undefined, d.host, d.port ?? null)}${d.mcpPath ?? ''}`
        : '');
    const entry = d.entryId ? catalogEntryById(d.entryId) : undefined;
    const hint = entry?.mcpTemplate?.urlHint;
    fields.push(
      <div className="f-row" key="origin">
        <label htmlFor="f-origin">MCP server URL</label>
        <input id="f-origin" className={fieldCls('origin')} placeholder="https://mcp.example.com/mcp"
          value={url} readOnly={managedMcpOAuth}
          aria-readonly={managedMcpOAuth ? 'true' : undefined}
          onChange={(e) => setDraftField('origin', 'origin', e.currentTarget.value)} />
        <FieldError k="origin" />
        {managedMcpOAuth
          ? <div className="rule-note">This OAuth connection is pinned to its MCP server. Add another MCP server to use a different URL.</div>
          : hint ? <div className="rule-note">{hint}</div> : null}
      </div>,
    );
  } else if (t === 'api') {
    const origin = d.origin ?? apiOriginFromParts(d.scheme ?? undefined, d.host ?? undefined, d.port ?? null);
    fields.push(
      <div className="f-row" key="origin">
        <label htmlFor="f-origin">API root</label>
        <input id="f-origin" className={fieldCls('origin')} placeholder="https://api.github.com"
          value={origin}
          onChange={(e) => setDraftField('origin', 'origin', e.currentTarget.value)} />
        <FieldError k="origin" />
      </div>,
    );
  } else if (t === 'ssh') {
    fields.push(
      <div className="f-2col compact-field-row" key="ssh-identity">
        <div className="f-row" style={{ flex: '0 0 90px' }}>
          <label htmlFor="f-user">User</label>
          <input id="f-user" className={fieldCls('user')} placeholder={state.localUsername}
            value={d.user ?? ''} onChange={onIdentityField('user', 'user')} />
          <FieldError k="user" />
        </div>
        <div className="f-row">
          <label htmlFor="f-host">Host</label>
          <input id="f-host" className={fieldCls('host')} placeholder="prod.example.com"
            value={d.host ?? ''} onChange={onIdentityField('host', 'host')} />
          <FieldError k="host" />
        </div>
        <div className="f-row" style={{ flex: '0 0 90px' }}>
          <label htmlFor="f-port">Port</label>
          <input id="f-port" className={fieldCls('port')} inputMode="numeric"
            value={d.port ?? '22'} onChange={onIdentityField('port', 'port')} />
          <FieldError k="port" />
        </div>
      </div>,
      d.proxyJump ? <div className="rule-note" key="proxyjump">ProxyJump: {d.proxyJump}</div> : null,
    );
    sshHostKeyField = (
      <div className="f-row" key="host-key">
        <label htmlFor="f-host-key">Host key fingerprint <span className="label-detail">(optional)</span></label>
        <input id="f-host-key" className={fieldCls('hostKeyFingerprint')} placeholder="SHA256:…"
          value={d.hostKeyFingerprint ?? ''}
          onChange={(e) => setDraftField('hostKeyFingerprint', 'hostKeyFingerprint', e.currentTarget.value)} />
        <FieldError k="hostKeyFingerprint" />
        <div className="host-key-check">
          <button type="button" className="btn sm" data-act="check-known-hosts"
            disabled={!d.host?.trim() || d.hostKeyChecking}>
            {d.hostKeyChecking ? 'Checking…' : 'Check known_hosts'}
          </button>
          {d.hostKeyCheckMessage
            ? <span className="rule-note" role="status">{d.hostKeyCheckMessage}</span>
            : null}
        </div>
        {d.hostKeyCandidates && d.hostKeyCandidates.length > 1
          ? <div className="host-key-candidates" aria-label="Matching known host keys">
              {d.hostKeyCandidates.map((candidate) => (
                <button type="button" className="btn sm" key={candidate.fingerprint}
                  data-act="pick-host-key" data-id={candidate.fingerprint}>
                  {candidate.algorithm} · {candidate.fingerprint}
                </button>
              ))}
            </div>
          : null}
        <div className="rule-note">The server’s identity (host key) is confirmed with you the first time an agent connects.</div>
      </div>
    );
  } else if (t === 'pg') {
    const sslmode = d.sslmode || 'verify-full';
    fields.push(
      <div className="f-2col compact-field-row" key="pg-host">
        <div className="f-row">
          <label htmlFor="f-host">Host</label>
          <input id="f-host" className={fieldCls('host')} placeholder="db.internal.example.com"
            value={d.host ?? ''} onChange={onIdentityField('host', 'host')} />
          <FieldError k="host" />
        </div>
        <div className="f-row" style={{ flex: '0 0 90px' }}>
          <label htmlFor="f-port">Port</label>
          <input id="f-port" className={fieldCls('port')} inputMode="numeric"
            value={d.port ?? '5432'} onChange={onIdentityField('port', 'port')} />
          <FieldError k="port" />
        </div>
      </div>,
      <div className="f-2col compact-field-row" key="pg-db">
        <div className="f-row">
          <label htmlFor="f-db">Database</label>
          <input id="f-db" className={fieldCls('dbname')} placeholder="app_production"
            value={d.dbname ?? ''}
            onChange={(e) => setDraftField('dbname', 'dbname', e.currentTarget.value)} />
          <FieldError k="dbname" />
        </div>
        <div className="f-row" style={{ flex: '0 0 90px' }}>
          <label htmlFor="f-user">User</label>
          <input id="f-user" className={fieldCls('user')} placeholder={state.localUsername}
            value={d.user ?? ''} onChange={onIdentityField('user', 'user')} />
          <FieldError k="user" />
        </div>
      </div>,
      <div className="f-row" key="pg-tls">
        <label htmlFor="f-sslmode">TLS mode</label>
        <CustomSelect id="f-sslmode" options={PG_SSL_OPTIONS} selectedValue={sslmode}
          errCls={fieldCls('sslmode')} />
        <FieldError k="sslmode" />
      </div>,
    );
    pgTlsFields = (
      <div className="f-row" key="ca-bundle">
        <label htmlFor="f-pg-ca-bundle">Trusted CA bundle <span className="label-detail">(optional)</span></label>
        <input id="f-pg-ca-bundle" placeholder="/path/to/private-ca.pem"
          value={d.pgCaBundlePath ?? ''}
          onChange={(e) => setDraftField('pgCaBundlePath', 'pgCaBundlePath', e.currentTarget.value)} />
      </div>
    );
  }
  if (t === 'api') {
    apiTlsFields = (
      <div className="f-row" key="api-ca-bundle">
        <label htmlFor="f-api-ca-bundle">Trusted CA bundle <span className="label-detail">(optional)</span></label>
        <input id="f-api-ca-bundle" placeholder="/path/to/private-ca.pem"
          value={d.pgCaBundlePath ?? ''}
          onChange={(e) => setDraftField('pgCaBundlePath', 'pgCaBundlePath', e.currentTarget.value)} />
        <div className="rule-note">Replaces public certificate authorities for this API connection.</div>
      </div>
    );
  }
  const templateField = (placeholder?: string, note?: ReactNode): ReactNode => (
    <div className="f-row">
      <label htmlFor="c-template">Credential template</label>
      <input id="c-template" className={fieldCls('template')} placeholder={placeholder}
        value={d.template ?? ''}
        onChange={(e) => setDraftField('template', 'template', e.currentTarget.value)} />
      <FieldError k="template" />
      {note}
    </div>
  );
  // OAuth-managed MCP authentication belongs to the sign-in flow. Keep its
  // generated secret name and injection template out of the ordinary editor:
  // reconnect is the only supported way to replace that grant.
  if (managedMcpOAuth) {
    fields.push(
      <div className="f-row" key="auth">
        <label>Authentication</label>
        <input value="OAuth (managed by AgentMFA)" readOnly aria-readonly="true" />
        <div className="rule-note">{conn?.account ? `Connected account: ${conn.account}. ` : ''}Tokens are stored securely, refreshed automatically, and sent only to this MCP server.</div>
      </div>,
    );
  // Existing manual API authentication still round-trips every config, but
  // the implementation template belongs behind an explicit advanced
  // disclosure rather than defining the connection's product identity.
  } else if (editing && t === 'api') {
    const credentialNames = conn?.secret_names.join(', ') || '';
    fields.push(
      <div className="f-row" key="auth">
        <label>Authentication</label>
        <input value={credentialNames ? 'Saved credential' : 'No credential'} readOnly aria-readonly="true" />
        {credentialNames
          ? <div className="rule-note">Uses {credentialNames}. Advanced authentication can change the saved credential reference.</div>
          : null}
      </div>,
      <details className="set-collapse" open={Boolean(state.sheetErrors.template)} key="auth-template">
        <summary>Custom authentication</summary>
        <div className="set-panel">
          {templateField(undefined,
            <div className="rule-note">References saved credentials by name using <code>{'{{ … }}'}</code>.</div>)}
        </div>
      </details>,
    );
  } else if (editing) {
    fields.push(<CredentialChooser type={t} allowNew={false} key="chooser" />);
  } else if (t === 'api') {
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
    const clientIdField = (detail: string): ReactNode => (
      <>
        <div className="f-row">
          <label htmlFor="c-oauth-client-id">Client ID</label>
          <input id="c-oauth-client-id" className={fieldCls('oauthClientId')}
            value={d.oauthClientId ?? ''}
            onChange={(e) => setDraftField('oauthClientId', 'oauthClientId', e.currentTarget.value)} />
          <FieldError k="oauthClientId" />
        </div>
        <div className="f-row">
          <label htmlFor="c-oauth-client-secret">Client secret <span className="label-detail">({detail})</span></label>
          <input id="c-oauth-client-secret" type="password" value={d.oauthClientSecret ?? ''}
            onChange={(e) => setDraftField('oauthClientSecret', 'oauthClientSecret', e.currentTarget.value)} />
        </div>
      </>
    );
    // Decision first: the authentication type governs which detail field and
    // credential inputs appear, so those render beneath the select.
    fields.push(
      <div className="f-row" key="auth-mode">
        <label htmlFor="c-auth-mode">Authentication type</label>
        <CustomSelect id="c-auth-mode" options={recipes} selectedValue={modeValue} />
      </div>,
    );
    if (modeValue === 'oauth' && oauthPreset) {
      const checked = d.oauthScopes ?? oauthPreset.scopes;
      fields.push(
        <div className="rule-note oauth-note" key="oauth-note">Uses your own OAuth app: create one at{' '}
          <code>{oauthPreset.appDocsUrl || 'the provider'}</code>, allow a{' '}
          <code>http://127.0.0.1</code> redirect, and paste its client ID. You’ll approve access in
          your browser; tokens live in your Keychain and refresh automatically.</div>,
        <div key="oauth-client">{clientIdField('only if your provider requires one')}</div>,
        <div className="f-row" key="oauth-scopes">
          <label>Scopes</label>
          <div className="wt-list">
            {oauthPreset.scopes.map((scope) => (
              <label key={scope} className="wt-row">
                <input type="checkbox" checked={checked.includes(scope)}
                  onChange={() => {
                    const current = d.oauthScopes ?? oauthPreset.scopes;
                    d.oauthScopes = current.includes(scope)
                      ? current.filter((candidate) => candidate !== scope)
                      : [...current, scope];
                    render();
                  }} />
                <span className="wt-name"><code>{scope}</code></span>
              </label>
            ))}
          </div>
        </div>,
        <div className="adv-collapse" key="oauth-endpoints">
          <details className="set-collapse">
            <summary>OAuth endpoints</summary>
            <div className="set-panel">
              <div className="f-row">
                <label htmlFor="c-oauth-auth-url">Authorization URL</label>
                <input id="c-oauth-auth-url" className={fieldCls('oauthAuthUrl')}
                  value={d.oauthAuthUrl ?? oauthPreset.authUrl}
                  onChange={(e) => setDraftField('oauthAuthUrl', 'oauthAuthUrl', e.currentTarget.value)} />
                <FieldError k="oauthAuthUrl" />
              </div>
              <div className="f-row">
                <label htmlFor="c-oauth-token-url">Token URL</label>
                <input id="c-oauth-token-url" className={fieldCls('oauthTokenUrl')}
                  value={d.oauthTokenUrl ?? oauthPreset.tokenUrl}
                  onChange={(e) => setDraftField('oauthTokenUrl', 'oauthTokenUrl', e.currentTarget.value)} />
                <FieldError k="oauthTokenUrl" />
              </div>
            </div>
          </details>
        </div>,
      );
    } else if (modeValue === 'oauth') {
      fields.push(
        <div className="rule-note oauth-note" key="oauth-note">You’ll approve access in your browser. The token is saved
          to your Keychain and injected into the connection. You can connect multiple accounts.</div>,
      );
      // Vendors without automatic client registration (Google Workspace)
      // need a one-time OAuth client the user creates with the provider.
      const oauthApp = mcpAdd && d.entryId
        ? catalogEntryById(d.entryId)?.mcpTemplate?.oauthApp : undefined;
      if (oauthApp) {
        fields.push(
          <div className="rule-note oauth-note" key="oauth-app-note">This provider has no automatic client registration:
            create an OAuth client at <code>{oauthApp.docsUrl || 'the provider'}</code> and paste
            its ID here. It is used once per sign-in and stored with the connection.</div>,
          <div key="oauth-client">{clientIdField('only if your provider issued one')}</div>,
        );
      }
    } else if (modeValue === 'header' || modeValue === 'query') {
      fields.push(
        <div className="f-row" key="auth-detail">
          <label htmlFor="c-auth-detail">{modeValue === 'header' ? 'Header name' : 'Query parameter'}</label>
          <input id="c-auth-detail" className={fieldCls('authDetail')}
            placeholder={modeValue === 'header' ? 'X-API-Key' : 'api_key'}
            value={d.authDetail ?? ''}
            onChange={(e) => setDraftField('authDetail', 'authDetail', e.currentTarget.value)} />
          <FieldError k="authDetail" />
        </div>,
      );
    }
    if (modeValue === 'advanced') {
      fields.push(
        <div key="auth-template">{templateField('Authorization: Bearer {{TOKEN_NAME}}',
          <div className="rule-note">References credentials by name using <code>{'{{ … }}'}</code>. Use this for Basic auth or composed credentials.</div>)}</div>,
      );
    } else if (modeValue !== 'oauth') {
      fields.push(
        <CredentialChooser type={t} valueHint={state.connPreset?.credentialHint} key="chooser" />,
      );
    }
    // Branded rows say where the credential comes from — the equivalent of a
    // provider's "get your API key" page, opened outside the app.
    if (state.connPreset?.docsUrl && modeValue !== 'oauth') {
      const docsLabel = state.connPreset.docsUrl;
      const docsUrl = /^https?:\/\//i.test(docsLabel) ? docsLabel : `https://${docsLabel}`;
      fields.push(
        <div className="rule-note" key="docs">Create or find your {state.connEntryName || 'API'} key at{' '}
          <code><a className="external-doc-link" href={docsUrl} data-act="open-external-url"
            data-url={docsUrl}>{docsLabel}</a></code></div>,
      );
    }
  } else {
    fields.push(<CredentialChooser type={t} key="chooser" />);
  }
  if (apiTlsFields || pgTlsFields || sshHostKeyField) {
    // Force the section open when one of its fields has a validation error,
    // so the inline message (and the focused input) is visible.
    const advancedError = ['hostKeyFingerprint', 'pgCaBundlePath']
      .some((key) => state.sheetErrors[key]);
    const advOpen = state.connAdvancedOpen || advancedError;
    fields.push(
      <div className="adv-collapse" key="advanced">
        <button type="button" className="adv-toggle" aria-expanded={advOpen} data-act="toggle-conn-advanced">
          <span className="adv-toggle-icon" aria-hidden="true"><Icon markup={ICONS.chevronDown} /></span>Advanced</button>
        {advOpen ? <>{apiTlsFields}{pgTlsFields}{sshHostKeyField}</> : null}
      </div>,
    );
  }
  const label = editing
    ? editPresentation?.label ?? catalogNameForType(t)
    : state.connEntryName || catalogNameForType(t);
  const oauthSelected = !editing && t === 'api' && isMcpDraft(d)
    && (d.authMode || 'oauth') === 'oauth';
  const title = `${editing ? 'Edit' : oauthSelected ? 'Connect' : 'Add'} ${label}`;
  // The draft-test verdict sits between the fields (below the Advanced
  // toggle) and the action row: the failure, a TLS-shaped fix when the
  // detail identifies one, and the promise that Add now saves anyway.
  const dt = !editing ? state.draftTest : null;
  const draftTest = !dt ? null
    : dt.running
    ? <div className="draft-test running">Testing the connection…</div>
    : (
      <div className="draft-test err">
        <Icon markup={ICONS.circleX} />
        <div>
          <b>Connection test failed.</b> {dt.detail || ''}
          {dt.kind === 'tls_declined' && (
            <div className="draft-test-fix">
              <button type="button" className="btn sm" data-act="draft-test-disable-tls">Set TLS mode to Disable</button>
            </div>
          )}
          {dt.kind === 'cert_unverified' && t === 'pg' && (
            <div className="draft-test-hint">Trust the server’s CA under Advanced → Trusted CA bundle, or pick a different TLS mode.</div>
          )}
          <div className="draft-test-hint">Press “Add {label}” again to save it without a passing test.</div>
        </div>
      </div>
    );
  const menuOpen = conn ? state.connMenuOpen === `sheet:${conn.id}` : false;
  return (
    <>
      <div className="sheet-backdrop" data-act="sheet-cancel"></div>
      <div className="sheet wide">
        <h3>{title}</h3>
        {fields}
        <FormGlobalError />
        {draftTest}
        <div className="sheet-actions">
          {editing && conn && (
            <>
              <button className="btn danger conn-delete-btn" data-act="del-conn-from-edit"
                data-id={conn.id}>Delete…</button>
              {managedMcpOAuth
                ? <button className="btn" data-act="reconnect-mcp" data-id={conn.id}>Reconnect…</button>
                : conn.mcp_path || conn.oauth_spec
                ? <div className="tile-menu-wrap sheet-conn-menu">
                    <button className={`icon-btn tile-menu-btn ${menuOpen ? 'on' : ''}`}
                      title="More options" aria-label={`More options for ${conn.name}`}
                      aria-haspopup="menu" aria-expanded={menuOpen}
                      data-act="toggle-conn-menu" data-id={`sheet:${conn.id}`}>
                      <Icon markup={ICONS.ellipsis} /></button>
                    {menuOpen && (
                      <div className="tile-menu" role="menu" aria-label={`More options for ${conn.name}`}>
                        <button className="menu-item" role="menuitem"
                          data-act={conn.mcp_path ? 'reconnect-mcp' : 'oauth-reconnect'}
                          data-id={conn.id}>
                          <Icon markup={ICONS.refresh} /> Reconnect (sign in again)</button>
                      </div>
                    )}
                  </div>
                : null}
            </>
          )}
          <button className="btn" data-act="sheet-cancel">Cancel</button>
          <button className="btn primary" data-act="save-conn" disabled={dt?.running}>
            {editing ? 'Save' : oauthSelected ? 'Sign in & connect' : `Add ${label}`}</button>
        </div>
      </div>
      {state.confirmDiscard && (
        <>
          <div className="sheet-backdrop over-sheet" data-act="discard-keep"></div>
          <div className="sheet wide confirm-sheet discard-confirm" role="dialog" aria-modal="true"
            aria-labelledby="discard-conn-title">
            <h3 id="discard-conn-title">{editing ? 'Discard changes?' : 'Discard this tool?'}</h3>
            <p>You have unsaved changes in this form. Closing it discards them.</p>
            <div className="sheet-actions">
              <button className="btn" data-act="discard-keep">Keep editing</button>
              <button className="btn danger" data-act="discard-confirm">Discard</button>
            </div>
          </div>
        </>
      )}
    </>
  );
}

/* ------------------------- MCP sign-in sheet ------------------------------ */

const AUTH_STEPS: Array<[string, string]> = [
  ['probing', 'Contacting the server'],
  ['discovering', 'Reading how to sign in'],
  ['registering', 'Registering AgentMFA'],
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
        ? `<div class="auth-warning">Token saved, but verification did not complete: ${esc(sentenceCase(auth.warning))}</div>`
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
  const epoch = brokerEpoch;
  try {
    const auth = await invoke('start_mcp_auth', { input: draft });
    if (!brokerEpochIsCurrent(epoch)) return false;
    state.mcpAuthDraft = draft;
    state.mcpAuth = auth;
    state.mcpAuthOpenedUrl = null;
    setSheet({ kind: 'mcp-auth' });
    state.sheetErrors = {};
    state.confirmDiscard = false;
    state.formMenuOpen = null;
    render();
    return true;
  } catch (error) {
    if (!brokerEpochIsCurrent(epoch)) return false;
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
  const notifications = state.notificationSettings;
  const notificationModeBtn = (
    value: NotificationSettings['mode'],
    label: string,
  ): string =>
    `<button class="seg-btn ${notifications.mode === value ? 'on' : ''}"
      data-act="set-notification-mode" data-id="${value}" role="radio"
      aria-checked="${notifications.mode === value}">${label}</button>`;
  const notificationRow = `<div class="set-row notification-setting"><div class="set-txt">
      <div class="st-title">Request notifications</div>
      <div class="st-sub">Native notifications are delivered by this computer and never include request details.</div></div>
      <div class="seg in-form notification-modes" role="radiogroup" aria-label="Request notifications">
        ${notificationModeBtn('off', 'Off')}
        ${notificationModeBtn('when_hidden', 'When away')}
        ${notificationModeBtn('always', 'Always')}
      </div></div>`;
  const notificationWarning = notifications.available ? ''
    : `<div class="notification-warning" role="status">
      <b>Native notifications are unavailable.</b>
      <span>${esc(notifications.unavailableReason || 'Use the Request Inbox for waiting requests.')}</span>
      ${notifications.canOpenSystemSettings
        ? '<button class="cd-live-link" data-act="open-notification-settings">Open notification settings</button>'
        : ''}
    </div>`;
  const notificationPreviewRow = notifications.mode === 'off' ? ''
    : `<div class="set-row"><div class="set-txt"><div class="st-title">Show agent and tool names</div>
      <div class="st-sub">Include only those names in notifications. Targets, summaries, and arguments always stay in the Inbox.</div></div>
      <button class="switch ${notifications.showContext ? 'on' : ''}"
        data-act="toggle-notification-context" role="checkbox"
        aria-label="Show agent and tool names in notifications"
        aria-checked="${notifications.showContext}"></button></div>`;
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
  const authenticationRows = state.broker.native_authentication
    ? `${reauthRow}${presenceRow}`
    : state.broker.mode === 'remote'
      ? `<div class="set-row"><div class="set-txt">
          <div class="st-title">Authorized by management token on ${esc(brokerLabel(state.broker))}</div>
          <div class="st-sub">This broker does not advertise native OS authentication. Sensitive settings are authorized by the management token instead.</div>
        </div></div>`
      : `<div class="set-row"><div class="set-txt">
          <div class="st-title">Native OS authentication unavailable</div>
          <div class="st-sub">This broker shell does not advertise an operating-system authentication prompt.</div>
        </div></div>`;
  // Window chrome is a this-machine concern: in remote mode the toggle
  // would patch the *remote* broker's setting, which this app's chrome
  // deliberately never reads (windows.rs) — and could silently reconfigure
  // a desktop app running on the broker host. Local mode only.
  const dockRow = state.broker.mode === 'local'
    ? `<div class="set-row"><div class="set-txt"><div class="st-title">Hide Dock icon in the menu bar</div>
      <div class="st-sub">When minimized to the menu bar, hide the Dock icon.</div></div>
      <button class="switch ${s.menu_bar_hides_dock ? 'on' : ''}" data-act="toggle-menubar-dock" role="checkbox" aria-checked="${s.menu_bar_hides_dock ? 'true' : 'false'}"></button></div>`
    : '';
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>Settings</h3>
    ${notificationRow}${notificationWarning}${notificationPreviewRow}${authenticationRows}${dockRow}
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
  // The custom selects portal their fixed listbox under #overlays, outside
  // the scrolling sheet that would otherwise clip it; anchor it here.
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

const SHEET_FOCUSABLE_SELECTOR =
  'button:not([disabled]), input:not([disabled]), select:not([disabled]), summary';

function sheetFocusables(sheet: HTMLElement): HTMLElement[] {
  return Array.from(sheet.querySelectorAll<HTMLElement>(SHEET_FOCUSABLE_SELECTOR));
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
  keyPassphrase: 'c-key-passphrase',
};

function showFormError(error: unknown): void {
  const inline = inlineFormError(error);
  if (!inline) {
    const prefix = formErrorKind(error) === 'cancelled' ? '' : '⚠ ';
    const detail = formErrorDetail(error);
    if (state.sheet) {
      state.sheetErrors = {
        ...state.sheetErrors,
        _global: formErrorMessage(error),
        _detail: detail ?? '',
      };
      render();
    }
    toast(prefix + formErrorToast(error));
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
    if (state.sheet?.kind === 'edit-secret' && state.draft.value === EDIT_SECRET_MASK && el) {
      el.focus();
      el.select();
    }
  }, 0);
}


/* --------------------------------- actions ------------------------------- */
function errorMessage(error: unknown): string {
  return formErrorToast(error);
}

async function run(fn: () => Promise<unknown>): Promise<boolean> {
  const epoch = brokerEpoch;
  try {
    await fn();
    return brokerEpochIsCurrent(epoch);
  } catch (error) {
    if (brokerEpochIsCurrent(epoch) && formErrorKind(error) !== 'cancelled') {
      toast('⚠ ' + errorMessage(error));
    }
    return false;
  }
}

async function answerElicitation(
  id: string,
  approved: boolean,
  values?: Record<string, string>,
): Promise<boolean> {
  let answered = false;
  const ok = await run(async () => {
    answered = await invoke('respond_elicitation', { id, approved, values });
  });
  if (!ok) return false;
  if (!answered) {
    toast('This input request was already answered or expired');
    closeSheet();
    await Promise.all([
      load('elicitations', 'list_elicitations'),
      load('requests', 'list_requests'),
    ]);
    render();
    return false;
  }
  return true;
}

/**
 * Answer a waiting prompt and close its dialog.
 *
 * The broker reports whether a prompt was still there to answer: one that
 * lapsed (or that another window answered) while this dialog sat open is
 * gone, and saying "approved" then would be a lie about traffic that was
 * already refused.
 */
async function answerApproval(
  id: string,
  decision: ApprovalDecision,
  success: string,
): Promise<void> {
  if (state.approvalAnswering) return;
  // "Stop asking" runs the broker's native authentication, whose sheet
  // takes focus. In the menu-bar dropdown that focus loss would hide the
  // chrome and dismiss this dialog mid-answer, so hold it open the way
  // credential forms do.
  if (decision === 'approve_all' && !await holdDropdownFormOpen()) return;
  state.approvalAnswering = id;
  render();
  let answered = false;
  const ok = await run(async () => {
    answered = await invoke('respond_approval', { id, decision });
  });
  if (state.approvalAnswering === id) state.approvalAnswering = null;
  if (!ok) {
    render();
    return;
  }
  toast(answered ? success : '⏳ That request is gone — it lapsed or was answered elsewhere');
  closeSheet();
  await Promise.all([
    load('approvals', 'list_approvals'),
    load('requests', 'list_requests'),
    load('connections', 'list_connections'),
  ]);
  render();
}

function isProtectedFormSheet(sheet: SheetState | null = state.sheet): boolean {
  return sheet?.kind === 'add-secret' || sheet?.kind === 'edit-secret'
    || sheet?.kind === 'add-conn' || sheet?.kind === 'edit-conn'
    || sheet?.kind === 'mcp-auth' || sheet?.kind === 'approval'
    || sheet?.kind === 'elicitation';
}

// Test a connection broker-side and pin the result to its catalog row.
// Shared by the panel's status row and the automatic post-save health check.
async function runConnectionTest(id: string): Promise<void> {
  if (!id || state.connTests[id]?.running) return;
  const epoch = brokerEpoch;
  state.connTests[id] = { running: true };
  render();
  try {
    const report = await invoke('test_connection', { id });
    if (!brokerEpochIsCurrent(epoch)) return;
    state.connTests[id] = { running: false, ok: report.ok, detail: report.detail, kind: report.kind };
  } catch (error) {
    if (!brokerEpochIsCurrent(epoch)) return;
    state.connTests[id] = { running: false, ok: false, detail: errorMessage(error) };
  }
  render();
}

async function loadWiringTools(connectionId: string): Promise<void> {
  const broker = state.broker;
  const epoch = brokerEpoch;
  try {
    const catalog = await refetchBrokerQuery(broker, 'list_mcp_tools', { id: connectionId });
    if (!brokerEpochIsCurrent(epoch)) return;
    const wt = state.wiringTools;
    if (!wt || wt.connectionId !== connectionId) return;
    wt.loading = false;
    wt.tools = catalog.tools;
    wt.stale = catalog.stale;
    wt.fetchedAt = catalog.fetched_at;
    wt.cacheAgeSeconds = catalog.cache_age_seconds;
    wt.truncated = catalog.truncated;
  } catch (error) {
    if (!brokerEpochIsCurrent(epoch)) return;
    const wt = state.wiringTools;
    if (!wt || wt.connectionId !== connectionId) return;
    wt.loading = false;
    wt.error = errorMessage(error);
  }
  render();
}

async function holdDropdownFormOpen(): Promise<boolean> {
  if (mode !== 'dropdown') return true;
  try {
    await invoke('ui_set_dropdown_form_active', { active: true });
    if (dropdownFormHeartbeat === null) {
      dropdownFormHeartbeat = window.setInterval(() => {
        void invoke('ui_set_dropdown_form_active', { active: true })
          .catch((error) => {
            console.error('could not renew menu-bar form lease', error);
            if (dropdownFormHeartbeat !== null) {
              window.clearInterval(dropdownFormHeartbeat);
              dropdownFormHeartbeat = null;
            }
          });
      }, 30_000);
    }
    return true;
  } catch (error) {
    toast('⚠ Couldn’t keep this form open: ' + errorMessage(error));
    return false;
  }
}

function releaseDropdownForm(): void {
  if (mode !== 'dropdown') return;
  if (dropdownFormHeartbeat !== null) {
    window.clearInterval(dropdownFormHeartbeat);
    dropdownFormHeartbeat = null;
  }
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
  setSheet({ kind: 'add-conn' });
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
  const sheet = state.sheet;
  if (!sheet || (sheet.kind !== 'add-secret' && sheet.kind !== 'edit-secret')) return;
  const epoch = brokerEpoch;
  const name = (state.draft.name || '').trim();
  const value = state.draft.value || '';
  let dependentConnectionIds: string[] = [];
  const errs: Record<string, string> = {};
  if (!name) errs.name = 'Name is required';
  if (sheet.kind === 'add-secret' && !value) errs.value = 'Value is required';
  if (Object.keys(errs).length) { state.sheetErrors = errs; render(); return; }
  if (sheet.kind === 'add-secret') {
    try { await invoke('add_secret', { name, value }); }
    catch (error) {
      if (brokerEpochIsCurrent(epoch)) showFormError(error);
      return;
    }
    if (!brokerEpochIsCurrent(epoch)) return;
    toast('🔑 Saved to macOS Keychain');
  } else {
    if (value !== EDIT_SECRET_MASK && (!value || value.includes('•'))) {
      state.sheetErrors = { value: 'Invalid value' };
      render();
      return;
    }
    const usedBy = state.secrets.find((secret) => secret.id === sheet.id)?.used_by_names ?? [];
    dependentConnectionIds = state.connections
      .filter((connection) => usedBy.includes(connection.name))
      .map((connection) => connection.id);
    try {
      await invoke('edit_secret', {
        id: sheet.id ?? '',
        newName: name,
        newValue: value === EDIT_SECRET_MASK ? null : value,
      });
    } catch (error) {
      if (brokerEpochIsCurrent(epoch)) showFormError(error);
      return;
    }
    if (!brokerEpochIsCurrent(epoch)) return;
    toast('✏️ Secret updated');
  }
  closeSheet();
  await refresh('secrets');
  if (!brokerEpochIsCurrent(epoch)) return;
  for (const connectionId of dependentConnectionIds) {
    void runConnectionTest(connectionId);
  }
}

async function saveConn(): Promise<void> {
  if (state.draftTest?.running) return;
  const sheet = state.sheet;
  if (!sheet || (sheet.kind !== 'add-conn' && sheet.kind !== 'edit-conn')) return;
  const epoch = brokerEpoch;
  const d = state.draft;
  const name = (d.name || '').trim();
  const t = state.connType;
  const usesLocalUser = t === 'pg' || t === 'ssh';
  const user = usesLocalUser
    ? (d.user || '').trim() || state.localUsername.trim()
    : '';
  // The local account is shown as the username placeholder, so submitting an
  // untouched field should accept that visible default. Materialize it in the
  // draft too, so another validation error leaves the form showing exactly
  // what the next submission will save.
  if (usesLocalUser && !(d.user || '').trim() && user) d.user = user;
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
    if (!user) errs.user = 'User is required';
    // The SSH host key fingerprint is optional: empty saves the service
    // unpinned, and the key is confirmed at the first agent connection.
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
  const usesRecipe = adding && t === 'api'
    && authMode !== 'advanced' && !usesOauth && !byoOauth;
  const needsCredentialChoice = !usesOauth && !byoOauth && (
    (adding && !(t === 'api' && authMode === 'advanced')) ||
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
  } else if (t === 'api' && authMode === 'advanced' && !injectionTemplate) {
    errs.template = 'Credential template is required';
  } else if (!adding && t === 'api' && !injectionTemplate) {
    errs.template = 'Credential template is required';
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
      trusted_ca_bundle_path: (d.pgCaBundlePath || '').trim() || null,
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
      trusted_ca_bundle_path: (d.pgCaBundlePath || '').trim() || null,
    };
    toast('🌐 Approve access in your browser…');
    if (await run(() => invoke('oauth_connect', {
      input, clientSecret: (d.oauthClientSecret || '').trim() || null,
    }))) {
      if (!brokerEpochIsCurrent(epoch)) return;
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
    // Sent only when the user filled it, and never retained: the backend
    // decrypts the key with it and stores the unlocked form.
    if (t === 'ssh' && (d.keyPassphrase || '').length) input.key_passphrase = d.keyPassphrase;
  }
  if (t === 'api') {
    input.host = apiOrigin!.host;
    input.scheme = apiOrigin!.scheme;
    input.port = apiOrigin!.port;
    input.template = injectionTemplate;
    input.mcp_path = mcpPath;
    input.trusted_ca_bundle_path = (d.pgCaBundlePath || '').trim() || null;
  } else if (t === 'pg') {
    input.host = (d.host || '').trim();
    input.port = port;
    input.dbname = (d.dbname || '').trim();
    input.user = user;
    input.sslmode = d.sslmode || 'verify-full';
    input.trusted_ca_bundle_path = (d.pgCaBundlePath || '').trim() || null;
    if (selectedSecret) input.secret_id = selectedSecret.id;
  } else if (t === 'ssh') {
    input.destination = (d.destination || '').trim() || null;
    input.host = (d.host || '').trim();
    input.port = port;
    input.user = user;
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
    let report: { ok: boolean; detail: string; kind?: TestErrorKind };
    try {
      report = await invoke('test_connection_draft', { input });
    } catch (error) {
      if (!brokerEpochIsCurrent(epoch)) return;
      report = { ok: false, detail: formErrorMessage(error) };
    }
    if (!brokerEpochIsCurrent(epoch)) return;
    if (!report.ok) {
      state.draftTest = { running: false, ok: false, detail: report.detail, kind: report.kind };
      state.draftTestOverride = true;
      render();
      return;
    }
    state.draftTest = null;
  }
  if (!brokerEpochIsCurrent(epoch)) return;
  const createdCredential = adding && newSecretName !== null;
  try {
    if (adding) await invoke('add_connection', { input });
    else {
      await invoke('edit_connection', {
        id: sheet.id ?? '',
        expectedUpdatedAt: sheet.expectedUpdatedAt ?? '',
        input,
      });
    }
    if (!brokerEpochIsCurrent(epoch)) return;
    toast(adding ? '🔌 Tool saved' : '✏️ Tool updated');
    if (adding) {
      // The first-task prompt names the service just saved — the very first
      // one, and every guided save after it — never an older neighbor.
      const hadConnections = state.connections.length > 0;
      // The first tool added gets a compact success message.
      if (!hadConnections) {
        state.connectionReady = { name };
        // A finished add lands back on the flat list, where the new tool is.
        state.addToolOpen = false;
      }
    }
    closeSheet();
    await refresh('all');
    if (!brokerEpochIsCurrent(epoch)) return;
    // Answer "did that actually work?" immediately: test the saved tool and
    // show the result on its row in the flat list.
    if (adding) {
      const saved = state.connections.find((c) => c.name === name);
      if (saved) {
        render();
        void runConnectionTest(saved.id);
        // Keep the new-credential flow confirmation-free. A direct endpoint
        // grants standing access and has its own native gate, so leave that
        // explicit action on the saved row instead of folding its prompt into
        // credential creation.
        if (!createdCredential
            && ENDPOINTABLE[saved.type]
            && saved.agent_access.enabled
            && !saved.agent_access.endpoint) {
          try {
            const info = await invoke('issue_endpoint', { connectionId: saved.id });
            if (!brokerEpochIsCurrent(epoch)) return;
            setSheet({ kind: 'endpoint-issued', id: saved.id, endpoint: info });
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
    if (!brokerEpochIsCurrent(epoch)) return;
    // A version conflict means this sheet's token is stale. Re-read the
    // list so the current row (and its fresh token) is there the moment
    // the sheet is reopened — recovery must not depend on the
    // connections-changed event stream being up.
    if (formErrorCode(e) === 'connection_changed') void refresh('connections');
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
  setSheet(null);
  state.draft = {};
  // The elicitation dialog's answers may include secrets; they must not
  // outlive the dialog that collected them.
  state.elicitValues = {};
  state.sheetErrors = {};
  state.sheetBaseline = null;
  state.confirmDiscard = false;
  state.draftTest = null;
  state.draftTestOverride = false;
  state.formMenuOpen = null;
  state.connPreset = null;
  render();
  if (releaseDropdown) releaseDropdownForm();
  void consumePendingOpenRequests();
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
    if (connDraftSignature() !== state.sheetBaseline) {
      state.confirmDiscard = true;
      render();
      return;
    }
  }
  closeSheet();
}

/* --------------------------------- events -------------------------------- */
/** Keep the pointer-anchored tool menu wholly inside the current viewport.
 * Measuring the rendered menu handles both the short base menu and the
 * taller variant with direct-connection actions. */
function positionConnContextMenu(): void {
  const point = state.connMenuPoint;
  const wrap = document.querySelector<HTMLElement>('.conn-context-menu-wrap');
  if (!point || !wrap) return;
  const inset = 8;
  const box = wrap.getBoundingClientRect();
  const maxLeft = Math.max(inset, window.innerWidth - box.width - inset);
  const maxTop = Math.max(inset, window.innerHeight - box.height - inset);
  wrap.style.left = `${Math.min(Math.max(inset, point.x), maxLeft)}px`;
  wrap.style.top = `${Math.min(Math.max(inset, point.y), maxTop)}px`;
  wrap.style.visibility = 'visible';
}

// Opportunistic re-check: coming back to the app re-tests anything the
// broker last saw unhealthy, so a fixed credential clears its badge
// without a manual test. Throttled so window-switching stays free.
let lastFocusRecheck = 0;
window.addEventListener('blur', () => {
  if (clearSensitivePresentation()) render();
});
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

document.addEventListener('contextmenu', (e) => {
  const target = e.target instanceof Element ? e.target : null;
  const row = target?.closest<HTMLElement>('.flat-conn-wrap');
  const id = row?.dataset.connRow;
  if (!id) return;
  e.preventDefault();
  state.selectedConn = id;
  state.connMenuOpen = id;
  state.connMenuPoint = { x: e.clientX, y: e.clientY };
  state.catalogActionMenuOpen = null;
  state.agentMenuOpen = null;
  render();
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
    state.connMenuPoint = null;
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
      clearSensitivePresentation();
      if (tab && TABS.includes(tab as Tab)) state.tab = tab as Tab;
      state.confirm = null;
      state.agentMenuOpen = null;
      state.catalogActionMenuOpen = null;
      state.connMenuOpen = null;
      state.connMenuPoint = null;
      // The slide-over is a transient view; coming back to Tools starts
      // at the list, not with the panel already over it.
      state.connDetailOpen = false;
      render();
      resetScroll();
      break;
    }
    case 'retry-view-loads':
      await refresh('all');
      break;
    case 'open-inbox':
      showRequestInbox();
      break;
    case 'broker-menu': state.brokerMenuOpen = !state.brokerMenuOpen; render(); break;
    case 'broker-pick-local': {
      state.brokerMenuOpen = false;
      state.remoteSetup.open = false;
      state.remoteSetup.error = null;
      if (state.broker.mode === 'local') { render(); break; }
      try {
        setBrokerProfile(await invoke('switch_broker_local'));
        await refresh('all');
        try { await loadAgentSetup(); } catch { /* pane shows loading */ }
        toast('Managing this Mac’s broker');
      } catch (error) {
        toast(`Couldn’t start the local broker: ${String(error)}`);
      }
      render();
      break;
    }
    case 'local-broker-retry': {
      await refresh('all');
      if (state.broker.connected) {
        try { await loadAgentSetup(); } catch { /* view remains usable */ }
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
      const url = state.remoteSetup.url.trim();
      const token = state.remoteSetup.token.trim();
      state.remoteSetup.busy = true;
      state.remoteSetup.error = null;
      render();
      try {
        setBrokerProfile(await invoke('connect_remote_broker', { url, token: token || null }));
        state.remoteSetup = {
          open: false, advancedOpen: false, url: '', token: '', busy: false, error: null,
        };
        await refresh('all');
        try { await loadAgentSetup(); } catch { /* pane shows loading */ }
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
        setBrokerProfile(await invoke('retry_remote_broker'));
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
    case 'toggle-theme': {
      const next = currentTheme() === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      // Storage can be unavailable (private contexts); the switch still
      // applies for this window, the choice just won't stick.
      try { localStorage.setItem('theme', next); } catch { /* see above */ }
      render();
      break;
    }
    case 'connect-toggle':
      state.connectOpen = state.connectOpen === id ? null : id;
      render();
      break;
    case 'copy-key':
      if (await run(() => invoke('copy_key'))) {
        toast('📋 Copied for 30s');
        flashCopied('shared-key');
      }
      break;
    case 'toggle-agent-menu':
      state.agentMenuOpen = state.agentMenuOpen === id ? null : id;
      render();
      break;
    case 'toggle-conn-menu':
      state.connMenuPoint = null;
      state.connMenuOpen = state.connMenuOpen === id ? null : id;
      render();
      break;
    case 'issue-endpoint':
    case 'reissue-endpoint-confirm': {
      const epoch = brokerEpoch;
      const connectionId = btn.dataset.conn || '';
      state.confirm = null;
      // Not via run(): we need the one-time result to show its secret.
      try {
        const info = await invoke('issue_endpoint', { connectionId });
        if (!brokerEpochIsCurrent(epoch)) break;
        setSheet({ kind: 'endpoint-issued', id: connectionId, endpoint: info });
        await refresh('all');
      } catch (error) {
        if (!brokerEpochIsCurrent(epoch)) break;
        toast('⚠ ' + errorMessage(error));
        render();
      }
      break;
    }
    case 'reissue-endpoint-ask':
      state.connMenuOpen = null;
      state.connMenuPoint = null;
      state.confirm = { kind: 'reissue-endpoint', id: btn.dataset.conn || '' };
      render();
      break;
    case 'revoke-endpoint-ask':
      state.connMenuOpen = null;
      state.connMenuPoint = null;
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
    case 'expand-endpoint': {
      const id = btn.dataset.conn;
      if (id) { state.epExpanded[id] = true; render(); }
      break;
    }
    case 'copy-endpoint-dsn': {
      const conn = state.connections.find((candidate) => candidate.id === btn.dataset.conn);
      if (conn && await run(() => invoke('copy_endpoint_text', {
        connectionId: conn.id,
        format: 'direct',
      }))) {
        toast('📋 Copied for 30s');
        flashCopied(`ep:${conn.id}`);
      }
      break;
    }
    case 'copy-endpoint-format': {
      const conn = state.connections.find((candidate) => candidate.id === btn.dataset.conn);
      const format = btn.dataset.format ?? '';
      if (conn && format && await run(() => invoke('copy_endpoint_text', {
        connectionId: conn.id,
        format,
      }))) {
        toast('📋 Copied for 30s');
        flashCopied(`epf:${conn.id}:${format}`);
      }
      break;
    }
    case 'copy-endpoint': {
      const connectionId = state.sheet?.id;
      const format = btn.dataset.field ?? '';
      if (connectionId && format && await run(() => invoke('copy_endpoint_text', {
        connectionId,
        format,
      }))) {
        toast('📋 Copied for 30s');
      }
      break;
    }
    case 'open-settings': state.menuOpen = false; setSheet({ kind: 'settings' }); render(); break;
    case 'copy-agent-setup':
      if (state.agentMenuOpen) { state.agentMenuOpen = null; render(); }
      if (await run(() => invoke('copy_agent_setup'))) toast('📋 Setup instructions copied');
      break;
    case 'copy-ready-setup':
      if (await run(() => invoke('copy_agent_setup'))) flashReadyCopied();
      break;
    case 'clear-activity-ask':
      setSheet({ kind: 'clear-activity' });
      render();
      break;
    case 'clear-activity-confirm':
      if (await run(() => invoke('clear_activity'))) {
        state.activity = [];
        closeSheet();
        toast('Activity cleared');
      }
      break;

    case 'reveal-secret': {
      const epoch = brokerEpoch;
      try {
        const prefix = await invoke('reveal_secret_prefix', { id });
        if (!brokerEpochIsCurrent(epoch)) break;
        state.reveal[id] = prefix;
        render();
      } catch (error) {
        if (brokerEpochIsCurrent(epoch)) toast('⚠ ' + errorMessage(error));
      }
      break;
    }
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
    case 'show-connection':
      state.tab = 'connections';
      state.addToolOpen = false;
      state.selectedConn = id;
      state.connDetailOpen = true;
      state.confirm = null;
      render();
      break;
    case 'delete-using-connection':
      state.tab = 'connections';
      state.addToolOpen = false;
      state.selectedConn = id;
      state.connDetailOpen = true;
      state.confirm = { kind: 'del-conn', id };
      render();
      break;
    case 'edit-secret':
      if (!await holdDropdownFormOpen()) break;
      setSheet({ kind: 'edit-secret', id });
      // Controlled fields read the draft, so seed it with what the form
      // shows: the current name and the masked value.
      state.draft = {
        name: state.secrets.find((s) => s.id === id)?.name ?? '',
        value: EDIT_SECRET_MASK,
      };
      state.sheetErrors = {};
      render();
      selectEditSecretMask();
      break;
    case 'open-add-secret':
      if (!await holdDropdownFormOpen()) break;
      setSheet({ kind: 'add-secret' }); state.draft = {}; state.sheetErrors = {};
      render(); focusField('f-name'); break;
    case 'save-secret': await saveSecret(); break;

    case 'conn-import': {
      const epoch = brokerEpoch;
      const source = state.connImportSource;
      if (!source.trim()) break;
      try {
        const imported = await connectionDraftFromImport(source, state.draft);
        if (!brokerEpochIsCurrent(epoch)) break;
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
        if (!brokerEpochIsCurrent(epoch)) break;
        state.connImportError = errorMessage(error);
        render();
        focusField('conn-import');
      }
      break;
    }
    case 'dismiss-connection-ready':
      state.connectionReady = null;
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
    case 'select-conn':
      state.selectedConn = id;
      // In the wide layout the panel is always on screen and this flag is
      // inert; in the narrow layout it opens the slide-over.
      state.connDetailOpen = true;
      render();
      break;
    case 'close-conn-detail':
      state.connDetailOpen = false;
      render();
      break;
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
      render();
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
      const entry = entryForConnection(c);
      state.connMenuOpen = null;
      state.connMenuPoint = null;
      if (!await holdDropdownFormOpen()) break;
      setSheet({ kind: 'edit-conn', id, expectedUpdatedAt: c.updated_at }); state.connType = c.type;
      state.connEntryName = entry?.name ?? null;
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
        entryId: entry?.id,
        mcpPath: c.mcp_path ?? null,
        port: c.port ? String(c.port) : (c.type === 'ssh' ? '22' : '5432'),
        dbname: c.dbname, user: c.user, template: c.template,
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
      state.draft.sslmode = 'disable';
      state.draft.sslmodeIsAutomatic = false;
      state.draftTest = null;
      state.draftTestOverride = false;
      render();
      break;
    case 'toggle-conn-advanced':
      state.connAdvancedOpen = !state.connAdvancedOpen;
      render();
      break;
    case 'check-known-hosts': {
      const host = state.draft.host?.trim() ?? '';
      if (!host || state.draft.hostKeyChecking) break;
      const port = Number.parseInt(state.draft.port || '22', 10);
      const epoch = brokerEpoch;
      const draft = state.draft;
      draft.hostKeyChecking = true;
      draft.hostKeyCheckMessage = undefined;
      render();
      try {
        const candidates = await invoke('check_known_hosts', {
          host,
          port: Number.isInteger(port) && port > 0 ? port : 22,
        });
        if (!brokerEpochIsCurrent(epoch) || state.draft !== draft) break;
        draft.hostKeyCandidates = candidates;
        if (candidates.length === 1) {
          draft.hostKeyFingerprint = candidates[0].fingerprint;
          draft.hostKeyAutoPinned = true;
          draft.hostKeyCheckMessage =
            `Pinned ${candidates[0].algorithm} from ${candidates[0].source}.`;
        } else if (candidates.length > 1) {
          draft.hostKeyCheckMessage = 'Choose the host key this tool should pin.';
        } else {
          draft.hostKeyCheckMessage = 'No matching key was found in known_hosts.';
        }
      } catch (error) {
        if (!brokerEpochIsCurrent(epoch) || state.draft !== draft) break;
        draft.hostKeyCandidates = [];
        draft.hostKeyCheckMessage = errorMessage(error);
      } finally {
        if (brokerEpochIsCurrent(epoch) && state.draft === draft) {
          draft.hostKeyChecking = false;
          render();
        }
      }
      break;
    }
    case 'pick-host-key': {
      const candidate = state.draft.hostKeyCandidates
        ?.find((item) => item.fingerprint === id);
      if (!candidate) break;
      state.draft.hostKeyFingerprint = candidate.fingerprint;
      state.draft.hostKeyAutoPinned = true;
      state.draft.hostKeyCheckMessage = `Pinned ${candidate.algorithm} from ${candidate.source}.`;
      delete state.sheetErrors.hostKeyFingerprint;
      render();
      break;
    }
    case 'select-toggle': {
      const menuId = btn.dataset.menu ?? '';
      state.formMenuOpen = state.formMenuOpen === menuId ? null : menuId;
      render();
      if (state.formMenuOpen) focusMenuOption();
      else focusField(menuId);
      break;
    }
    case 'select-pick': {
      const menuId = btn.dataset.menu ?? '';
      state.formMenuOpen = null;
      // An elicitation enum dropdown, keyed `elicit-sel-<index>`: write the
      // picked value into the field's elicit value rather than the draft.
      if (menuId.startsWith('elicit-sel-')) {
        const index = Number(menuId.slice('elicit-sel-'.length));
        const request = state.elicitations.find((r) => r.id === state.sheet?.id);
        const field = request?.fields[index];
        if (field) {
          state.elicitValues[field.name] = id;
          delete state.sheetErrors[`elicit:${field.name}`];
        }
        render();
        focusField(menuId);
        break;
      }
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
      disarmDraftTestOverride();
      render();
      focusField(menuId);
      break;
    }
    case 'credential-pick':
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
      disarmDraftTestOverride();
      render();
      focusField(id === NEW_CREDENTIAL_OPTION ? 'c-new-secret-name' : 'c-secret');
      break;
    case 'save-conn': await saveConn(); break;
    case 'del-conn-ask':
      state.connMenuOpen = null;
      state.connMenuPoint = null;
      state.confirm = { kind: 'del-conn', id };
      render();
      break;
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
      state.connMenuPoint = null;
      void runConnectionTest(id);
      break;
    case 'mcp-status': {
      if (state.mcpStatus[id] && state.mcpStatus[id].running) break;
      const epoch = brokerEpoch;
      state.connMenuOpen = null;
      state.connMenuPoint = null;
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
        if (!brokerEpochIsCurrent(epoch)) break;
        state.mcpStatus[id] = { running: false, report };
      } catch (error) {
        if (!brokerEpochIsCurrent(epoch)) break;
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
      state.connMenuPoint = null;
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
      render();
      break;
    case 'act-filter-agent': {
      const value = btn.dataset.value || '';
      state.activityAgent = state.activityAgent === value ? null : value;
      render();
      break;
    }
    case 'request-filter-issues':
      state.requestIssuesOnly = !state.requestIssuesOnly;
      render();
      break;
    case 'request-filter-agent': {
      const value = btn.dataset.value || '';
      state.requestAgent = state.requestAgent === value ? null : value;
      render();
      break;
    }
    case 'request-history-toggle':
      state.expandedRequests = state.expandedRequests.includes(id)
        ? state.expandedRequests.filter((request) => request !== id)
        : [...state.expandedRequests, id];
      render();
      break;
    case 'request-open-connection':
      state.tab = 'connections';
      state.addToolOpen = false;
      state.selectedConn = id;
      state.connDetailOpen = true;
      render();
      break;
    case 'oauth-reconnect': {
      state.connMenuOpen = null;
      state.connMenuPoint = null;
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
      setSheet({ kind: 'wiring-tools' });
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
    // wt-all / wt-toggle live on WiringToolsSheet's controlled checkboxes.
    case 'wt-save': {
      const wt = state.wiringTools;
      if (!wt || wt.saving) break;
      wt.saving = true;
      render();
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
        render();
      }
      break;
    }
    case 'mcp-open-browser':
      await run(() => invoke('open_url', { url: btn.dataset.url || '' }));
      break;
    case 'open-external-url':
      await run(() => invoke('open_url', { url: btn.dataset.url || '' }));
      break;
    case 'open-notification-settings':
      await run(() => invoke('open_notification_settings'));
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
      setSheet({ kind: 'add-conn' });
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
    case 'confirm-on':
      if (await run(() => invoke('set_confirm_mode', { connectionId: btn.dataset.conn || '', on: true }))) {
        toast('🛡️ Traffic will be confirmed with you first');
      }
      await refresh('connections');
      break;
    case 'confirm-off':
      // Removing a gate the user put up: the broker authenticates before it
      // applies, so a refused sheet leaves the switch on. That native sheet
      // takes focus, so the menu-bar dropdown must hold itself open the way
      // credential forms do.
      if (!await holdDropdownFormOpen()) break;
      if (await run(() => invoke('set_confirm_mode', { connectionId: btn.dataset.conn || '', on: false }))) {
        toast('🔕 No longer asking about this tool’s traffic');
      }
      releaseDropdownForm();
      await refresh('connections');
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

    // SEP-2322 elicitation: the queue row opens the dialog; answering or
    // refusing there resumes the paused upstream call broker-side. The
    // dialog's fields are controlled, held in
    // state.elicitValues for the dialog's lifetime only — seeded empty here,
    // cleared again by closeSheet so answers (possibly secrets) don't
    // outlive the dialog.
    case 'elicit-open': {
      if (!await holdDropdownFormOpen()) break;
      state.elicitValues = {};
      state.sheetErrors = {};
      const request = state.elicitations.find((r) => r.id === id);
      // A required dropdown shows its first choice selected; seed that value
      // so an untouched enum sends what the user sees. Optional fields start
      // absent and stay out of the upstream answer until the user fills them.
      for (const field of request?.fields ?? []) {
        if (!elicitFieldRequired(field)) continue;
        if (field.boolean) state.elicitValues[field.name] = 'false';
        else if (field.options?.length) {
          state.elicitValues[field.name] = field.options[0];
        }
      }
      setSheet({ kind: 'elicitation', id });
      render();
      if (request?.fields[0] && !request.fields[0].options?.length) {
        focusField(`elicit-${id}-${request.fields[0].name}`);
      }
      break;
    }
    case 'elicit-send': {
      const request = state.elicitations.find((r) => r.id === id);
      if (!request) break;
      const values: Record<string, string> = {};
      state.sheetErrors = {};
      let missingIndex: number | null = null;
      for (const [index, field] of request.fields.entries()) {
        const value = (state.elicitValues[field.name] ?? '').trim();
        if (!value && elicitFieldRequired(field)) {
          state.sheetErrors[`elicit:${field.name}`] = 'This field is required';
          missingIndex = index;
          break;
        }
        if (value) values[field.name] = value;
      }
      if (missingIndex !== null) {
        render();
        const field = request.fields[missingIndex];
        focusField(field.options?.length
          ? `elicit-sel-${missingIndex}`
          : `elicit-${id}-${field.name}`);
        break;
      }
      if (await answerElicitation(id, true, values)) {
        toast(`📨 Sent to ${request.connection} — ${request.agent} resumes`);
        closeSheet();
        await Promise.all([
          load('elicitations', 'list_elicitations'),
          load('requests', 'list_requests'),
        ]);
        render();
      }
      break;
    }
    // Traffic confirmation: the queue row opens the dialog, and the answer
    // releases (or refuses) the parked call broker-side. "Approve all" runs
    // the broker's native authentication on the way through, because it
    // turns the tool's switch off.
    case 'approval-open': {
      if (!await holdDropdownFormOpen()) break;
      setSheet({ kind: 'approval', id });
      render();
      // The triggering queue row disappears behind a modal. Put keyboard
      // focus on the safest answer instead of leaving it on a hidden node.
      setTimeout(() => {
        document.querySelector<HTMLElement>('[data-act="approval-deny"]')?.focus();
      }, 0);
      break;
    }
    case 'approval-approve-window': {
      const approval = state.approvals.find((a) => a.id === id);
      const minutes = Math.max(1, Math.round((approval?.window_secs ?? 900) / 60));
      await answerApproval(id, 'approve_window',
        `✅ Approved — not asking again on ${approval?.connection ?? 'this tool'} for ${minutes}m`);
      break;
    }
    case 'approval-approve-all': {
      const approval = state.approvals.find((a) => a.id === id);
      await answerApproval(id, 'approve_all',
        `✅ Approved — ${approval?.connection ?? 'this tool'} no longer asks`);
      break;
    }
    case 'approval-deny': {
      const approval = state.approvals.find((a) => a.id === id);
      await answerApproval(id, 'deny',
        `🚫 Refused — ${approval?.agent ?? 'the agent'} is told the call was denied`);
      break;
    }

    case 'elicit-refuse': {
      const request = state.elicitations.find((r) => r.id === id);
      if (await answerElicitation(id, false)) {
        toast(`🚫 Refused — ${request?.agent ?? 'the agent'} is told no, without your reasons`);
        closeSheet();
        await Promise.all([
          load('elicitations', 'list_elicitations'),
          load('requests', 'list_requests'),
        ]);
        render();
      }
      break;
    }

    case 'sheet-cancel': requestCloseSheet(); break;
    case 'discard-keep': state.confirmDiscard = false; render(); break;
    case 'discard-confirm': closeSheet(); break;
    case 'set-notification-mode': {
      if (id !== 'off' && id !== 'when_hidden' && id !== 'always') break;
      const settings: NotificationSettings = {
        ...state.notificationSettings,
        mode: id,
      };
      const settingsEpoch = notificationSettingsEpoch;
      try {
        const saved = await invoke('set_notification_settings', { settings });
        if (settingsEpoch === notificationSettingsEpoch) state.notificationSettings = saved;
        const label = id === 'off' ? 'off' : id === 'always' ? 'always on' : 'on when you’re away';
        toast(`🔔 Request notifications ${label}`);
      } catch (error) {
        toast('⚠ ' + errorMessage(error));
      }
      render();
      break;
    }
    case 'toggle-notification-context': {
      const settings: NotificationSettings = {
        ...state.notificationSettings,
        showContext: !state.notificationSettings.showContext,
      };
      const settingsEpoch = notificationSettingsEpoch;
      try {
        const saved = await invoke('set_notification_settings', { settings });
        if (settingsEpoch === notificationSettingsEpoch) state.notificationSettings = saved;
        toast(settings.showContext
          ? '🔔 Notifications show agent and tool names'
          : '🔔 Notification previews are private');
      } catch (error) {
        toast('⚠ ' + errorMessage(error));
      }
      render();
      break;
    }
    case 'toggle-reauth':
      {
        const on = !state.settings.reauth_on_read;
        await run(() => invoke('set_reauth_on_read', { on }));
        toast(on ? '💳 Confirmation required before using saved secrets' : '💳 Extra confirmation removed');
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

/* ---------------------- Tools list drag reordering ----------------------- */
// The connected-tools list on the Tools tab can be reordered by dragging a
// row (or, for keyboard users, focusing it and pressing Alt+Up/Down). The
// chosen order is persisted on the broker via
// `reorder_connections`; the broker echoes `connections-changed`, which
// refreshes every window back to the stored order.

// The row a dropped item should land *before*: the first whose vertical
// midpoint sits below the pointer. `null` means append at the end.
function connRowAfter(list: HTMLElement, y: number): string | null {
  const rows = [...list.querySelectorAll<HTMLElement>('.flat-conn-wrap:not(.dragging)')];
  for (const row of rows) {
    const box = row.getBoundingClientRect();
    if (y < box.top + box.height / 2) return row.dataset.connRow ?? null;
  }
  return null;
}

function moveConnectionBefore(ids: string[], movedId: string, beforeId: string | null): string[] {
  const next = ids.filter((id) => id !== movedId);
  const before = beforeId === null ? next.length : next.indexOf(beforeId);
  next.splice(before < 0 ? next.length : before, 0, movedId);
  return next;
}

async function persistConnOrder(
  orderedIds: string[],
  previous: ConnectionSummary[],
  generation: number,
): Promise<void> {
  if (!await run(() => invoke('reorder_connections', { orderedIds }))
      && generation === connectionReorderGeneration) {
    state.connections = previous;
    render();
  }
}

// Commit the React-rendered preview order and persist it.
function commitConnDrag(): void {
  if (!dragConnId) return;
  const ids = dragConnOrder ?? state.connections.map((connection) => connection.id);
  const previous = state.connections.slice();
  dragConnId = null;
  dragConnOrder = null;
  const byId = new Map(state.connections.map((c) => [c.id, c] as const));
  const next = ids.map((id) => byId.get(id)).filter((c): c is ConnectionSummary => Boolean(c));
  // Preserve any connection not represented in the DOM (a filtered-out row
  // cannot happen while reordering is enabled, but stay total to be safe).
  for (const c of state.connections) if (!ids.includes(c.id)) next.push(c);
  const changed = next.some((c, i) => c.id !== state.connections[i]?.id);
  if (changed) state.connections = next;
  render();
  if (!changed) return;
  const generation = ++connectionReorderGeneration;
  void persistConnOrder(next.map((c) => c.id), previous, generation);
}

// Move one connection up (-1) or down (+1) by keyboard, optimistically
// re-rendering and keeping the moved row focused, then persisting.
function moveConnByKeyboard(id: string, delta: number): void {
  const previous = state.connections.slice();
  const ids = state.connections.map((c) => c.id);
  const from = ids.indexOf(id);
  if (from === -1) return;
  const to = from + delta;
  if (to < 0 || to >= ids.length) return;
  ids.splice(to, 0, ids.splice(from, 1)[0]);
  const byId = new Map(state.connections.map((c) => [c.id, c] as const));
  state.connections = ids.map((cid) => byId.get(cid)!)
    .filter((c): c is ConnectionSummary => Boolean(c));
  render();
  document.querySelector<HTMLElement>(
    `[data-conn-row="${CSS.escape(id)}"] .flat-conn-row`,
  )?.focus();
  const generation = ++connectionReorderGeneration;
  void persistConnOrder(ids, previous, generation);
}

document.addEventListener('dragstart', (e) => {
  const wrap = (e.target instanceof Element ? e.target : null)
    ?.closest<HTMLElement>('.flat-conn-wrap.reorderable');
  if (!wrap) return;
  dragConnId = wrap.dataset.connRow ?? null;
  if (!dragConnId) return;
  dragConnOrder = state.connections.map((connection) => connection.id);
  if (e.dataTransfer) {
    e.dataTransfer.effectAllowed = 'move';
    // Firefox refuses to start a drag unless some data is attached.
    e.dataTransfer.setData('text/plain', dragConnId);
    // Drag the whole row, not just the little grip.
    e.dataTransfer.setDragImage(wrap, 24, wrap.offsetHeight / 2);
  }
  render();
});

document.addEventListener('dragover', (e) => {
  if (!dragConnId) return;
  const list = (e.target instanceof Element ? e.target : null)?.closest<HTMLElement>('[data-conn-list="on"]');
  if (!list) return;
  e.preventDefault(); // mark this a valid drop target
  if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
  const beforeId = connRowAfter(list, e.clientY);
  const current = dragConnOrder ?? state.connections.map((connection) => connection.id);
  const next = moveConnectionBefore(current, dragConnId, beforeId);
  if (next.every((id, index) => id === current[index])) return;
  dragConnOrder = next;
  render();
});

document.addEventListener('drop', (e) => {
  if (!dragConnId) return;
  if ((e.target instanceof Element ? e.target : null)?.closest('[data-conn-list="on"]')) {
    e.preventDefault();
  }
  commitConnDrag();
});

// Fires after every drag, including one cancelled outside the list; it is the
// backstop that clears the dragging state and commits the final order.
document.addEventListener('dragend', () => commitConnDrag());

document.addEventListener('keydown', (e) => {
  // A focused row moves with Alt+Up/Down — the keyboard-accessible
  // equivalent of dragging it.
  if (e.altKey && (e.key === 'ArrowUp' || e.key === 'ArrowDown')
      && e.target instanceof HTMLElement) {
    const row = e.target.closest<HTMLElement>('.flat-conn-row');
    const wrap = row?.closest<HTMLElement>('.flat-conn-wrap.reorderable');
    if (wrap?.dataset.connRow) {
      e.preventDefault();
      moveConnByKeyboard(wrap.dataset.connRow, e.key === 'ArrowDown' ? 1 : -1);
      return;
    }
  }
  // Divs acting as buttons (connection rows, the add-tools row) activate
  // from the keyboard like the real thing.
  if ((e.key === 'Enter' || e.key === ' ') && e.target instanceof HTMLElement
      && e.target.getAttribute('role') === 'button' && e.target.dataset.act) {
    e.preventDefault();
    e.target.click();
    return;
  }
  // Ctrl-Tab / Ctrl-Shift-Tab cycle the left-nav tabs when the main window is
  // open (a modal sheet keeps focus).
  if (e.key === 'Tab' && e.ctrlKey && !state.sheet) {
    e.preventDefault();
    // The dropdown has no Get started tab; cycle only the tabs it shows.
    const ring: readonly Tab[] = mode === 'dropdown' ? DROPDOWN_TABS : TABS;
    const i = ring.indexOf(state.tab);
    const n = ring.length;
    state.tab = ring[(i + (e.shiftKey ? -1 : 1) + n) % n];
    state.menuOpen = false;
    state.connDetailOpen = false;
    render();
    resetScroll();
    return;
  }
  if (e.key === 'Escape') {
    if (state.catalogActionMenuOpen) { state.catalogActionMenuOpen = null; render(); return; }
    if (state.agentMenuOpen) { state.agentMenuOpen = null; render(); return; }
    if (state.connMenuOpen) {
      state.connMenuOpen = null;
      state.connMenuPoint = null;
      render();
      return;
    }
    // The detail slide-over only exists in the narrow layout; in the wide
    // layout the flag is inert and Escape passes through.
    if (state.connDetailOpen && window.matchMedia(NARROW_LAYOUT).matches) {
      state.connDetailOpen = false; render(); return;
    }
    if (state.menuOpen) { state.menuOpen = false; render(); return; }
    if (state.formMenuOpen) {
      const menuId = state.formMenuOpen;
      state.formMenuOpen = null;
      render();
      focusField(menuId);
      return;
    }
    if (state.confirmDiscard) { state.confirmDiscard = false; render(); return; }
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
      render();
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
  } else if (e.key === 'Tab' && state.formMenuOpen && e.target instanceof Element
      && e.target.closest('.cred-menu')) {
    // The listbox is portaled outside .sheet, so close it and move relative
    // to its trigger before the modal trap mistakes the option for escaped
    // focus and wraps all the way to an edge.
    e.preventDefault();
    const menuId = state.formMenuOpen;
    state.formMenuOpen = null;
    render();
    const sheet = document.querySelector<HTMLElement>('.sheet');
    if (!sheet) return;
    const focusables = sheetFocusables(sheet);
    const trigger = document.getElementById(menuId);
    const triggerIndex = trigger instanceof HTMLElement ? focusables.indexOf(trigger) : -1;
    if (triggerIndex === -1 || !focusables.length) return;
    const offset = e.shiftKey ? -1 : 1;
    focusables[(triggerIndex + offset + focusables.length) % focusables.length].focus();
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
    const focusables = sheetFocusables(sheet);
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

// Custom-select triggers map to the draft field whose inline validation
// error a new pick clears (text fields clear their own via setDraftField).
const ERR_KEY_BY_INPUT = {
  'f-sslmode': 'sslmode', 'c-secret': 'secret', 'c-auth-mode': 'authMode',
  'c-identity-file': 'newSecretValue',
};

// Form fields are controlled React inputs; their onChange handlers own
// draft updates, error clearing, and the draft-test-override disarm.

// Keep an open fixed-position listbox glued to its trigger while the sheet
// scrolls or the window resizes.
document.addEventListener('scroll', () => {
  if (state.formMenuOpen) positionFormMenu();
}, true);
window.addEventListener('resize', () => {
  if (state.formMenuOpen) positionFormMenu();
  if (state.connMenuPoint) positionConnContextMenu();
});

/* --------------------------------- boot ---------------------------------- */
let requestRefreshTimer: ReturnType<typeof setTimeout> | null = null;

function scheduleRequestRefresh(): void {
  if (requestRefreshTimer) clearTimeout(requestRefreshTimer);
  requestRefreshTimer = setTimeout(async () => {
    requestRefreshTimer = null;
    await Promise.all([
      load('elicitations', 'list_elicitations'),
      load('approvals', 'list_approvals'),
      load('requests', 'list_requests'),
      load('connections', 'list_connections'),
    ]);
    render();
  }, 250);
}

async function boot() {
  if (mode === 'dropdown' && state.tab === 'start') state.tab = 'connections';
  // A webview reload must not leave a stale native lock behind. Forms acquire
  // it again before they are shown.
  if (mode === 'dropdown') await invoke('ui_set_dropdown_form_active', { active: false });
  // This desktop setting can be edited from either webview. Subscribe before
  // the initial read so a concurrent save cannot be lost during boot.
  await listen('aka://notification-settings-changed', (event) => {
    notificationSettingsEpoch += 1;
    state.notificationSettings = event.payload;
    if (booted) render();
  });
  await listen('aka://settings-changed', () => {
    void refresh('settings');
  });
  // Which broker this app manages decides everything else about boot.
  try {
    setBrokerProfile(await invoke('get_broker_profile'));
  } catch (error) {
    console.error('get_broker_profile', error);
    setBrokerProfile({
      ...LOCAL_BROKER,
      connected: false,
      error: `Couldn’t read local broker status: ${errorMessage(error)}`,
    });
  }
  // Choose the landing tab before the first paint: nothing configured yet
  // means the walkthrough is the useful screen.
  await Promise.all([
    loadLocalUsername(),
    loadNotificationSettings(),
    load('connections', 'list_connections'),
    loadIdentity(),
  ]);
  if (mode !== 'dropdown'
      && state.loadStatus.connections.status === 'ready'
      && !state.connections.length) {
    state.tab = 'start';
  }
  // The landing tab is decided; the next render is the first real paint.
  booted = true;
  await refresh('all');
  // The setup card always shows the paste-ready message.
  try { await loadAgentSetup(); render(); }
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
  // Relative timestamps and approval-window horizons drift; refresh their
  // rendered state every minute while the relevant tab is open.
  setInterval(() => {
    if ((state.tab === 'activity' || state.tab === 'connections' || state.tab === 'inbox')
        && !state.sheet && !state.menuOpen) render();
  }, 60000);
  // Approval deadlines are measured in seconds; keep the visible countdown
  // honest while the dialog is open instead of freezing at its first paint.
  // The Inbox's active cards render the same countdowns, so it ticks too
  // while something is waiting; its terminal history only needs the minute
  // interval above.
  setInterval(() => {
    if (state.sheet?.kind === 'approval'
        || (state.tab === 'inbox' && !state.sheet && !state.menuOpen
          && activeRequestCount(state.approvals, state.elicitations) > 0)) render();
  }, 1000);
  // Live updates from the core.
  await listen('aka://broker-changed', async (ev) => {
    // "Same broker" means mode AND url: a switch from connected remote A to
    // connected remote B must refetch, not keep A's data labeled as B.
    const wasConnected = state.broker.connected
      && state.broker.mode === ev.payload.mode
      && state.broker.url === ev.payload.url;
    setBrokerProfile(ev.payload);
    // A link that just came (back) up: refetch everything rather than
    // trusting whatever was on screen for the previous broker.
    if (ev.payload.connected && !wasConnected) {
      await refresh('all');
      try { await loadAgentSetup(); } catch { /* pane shows loading */ }
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
        setBrokerProfile(profile);
        if (cameUp) {
          await refresh('all');
          try { await loadAgentSetup(); } catch { /* pane shows loading */ }
        }
        render();
      }
    } catch (e) { console.error(e); }
  }
  await listen('aka://sessions-changed', () => refresh('sessions'));
  await listen('aka://elicitations-changed', () => {
    scheduleRequestRefresh();
    // The open dialog's request may have been answered elsewhere or
    // expired; the sheet re-renders as "gone" via ElicitationSheet, which
    // is correct — nothing to close here, the user dismisses it informed.
  });
  await listen('aka://approvals-changed', () => {
    // The queue drives a modal, so it must not lag: a prompt that was
    // answered elsewhere (or lapsed) re-renders the open dialog as gone.
    // Connection rows ride the same refresh so an opened/closed approval
    // window never leaves its status card stale.
    scheduleRequestRefresh();
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
    toast(`🤖 ${agent} asked to connect “${service}”`);
    render();
  });
  await listen('aka://activity-changed', () => refresh('activity'));
  await listen('aka://open-settings', () => {
    if (isProtectedFormSheet()) return;
    setSheet({ kind: 'settings' });
    state.draft = {};
    state.sheetErrors = {};
    render();
  });
  await listen('aka://open-requests', () => {
    void consumePendingOpenRequests();
  });
  // A tray click may have preceded this listener or waited behind a
  // protected dropdown form.
  await consumePendingOpenRequests();
  await listen('aka://dropdown-shown', () => {
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
  });
  await listen('aka://dropdown-hidden', () => {
    releaseDropdownForm();
    state.reveal = {};
    state.epExpanded = {};
    setSheet(null);
    state.draft = {};
    state.sheetErrors = {};
    state.sheetBaseline = null;
    state.confirmDiscard = false;
    state.confirm = null;
    state.catalogActionMenuOpen = null;
    state.agentMenuOpen = null;
    state.connMenuOpen = null;
    state.connMenuPoint = null;
    render();
  });
}

const reactRoot = createRoot(root());
flushSync(() => {
  reactRoot.render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <AppRoot />
      </QueryClientProvider>
    </StrictMode>,
  );
});
reactMounted = true;
void boot();
