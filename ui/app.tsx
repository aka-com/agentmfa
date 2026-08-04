// Multitool React frontend. One file drives all Tauri windows (main, tray
// and dropdown), chosen from location.hash.
//
// Every mutation and read goes through the Rust core via Tauri
// commands; the webview holds a secret value only while the user has
// a reveal open on it. When run outside Tauri (a plain browser), a dev
// mock stands in for the core so the UI is developable standalone.

import { invoke, listen, mode } from '/src/bridge';
import { QueryClientProvider } from '@tanstack/react-query';
import {
  StrictMode, useEffect, useLayoutEffect, useRef, useState,
} from 'react';
import type {
  DragEvent as ReactDragEvent,
  MouseEvent as ReactMouseEvent,
  ReactNode,
} from 'react';
import { createPortal, flushSync } from 'react-dom';
import { createRoot } from 'react-dom/client';
import {
  CATALOG_SECTIONS, canQuickConnectMcp, catalogEntryById, catalogNameForType,
  collapsedCatalogGroup, connectedCatalogFirst, connectionEditPresentation,
  connectionsForEntry, entryForConnection, mcpTemplateForConnection, visibleCatalog,
} from '/src/catalog';
import {
  DROPDOWN_TABS,
  TABS,
  defaultLoadStatus,
  state,
  uiStore,
} from '/src/app-state';
import type {
  ConnectionDraft,
  ConnMenuPoint,
  LoadKey,
  SecretCategory,
  SheetState,
  Tab,
} from '/src/app-state';
import { START_OPTIONS } from '/src/connect-agents';
import type { CatalogEntry } from '/src/catalog';
import {
  ICONS, TYPES, toast, relTime, absTime, timeLeft, clockTime,
} from '/src/util';
import {
  apiOriginFromParts, authTemplate, defaultConnectionName, parseApiOrigin, parseConnectionImport,
  rebindApiCredentialTemplate,
  insecureNonLoopbackHttp, initialSecretSource, isLoopbackHost, parseMcpServerUrl,
  quickSetupPlaceholder, shouldResolveSshImport, sshImportFromPreview, suggestedSecretName,
} from '/src/connection-input';
import {
  formErrorCode, formErrorDetail, formErrorKind, formErrorMessage, formErrorToast, inlineFormError,
  sentenceCase,
} from '/src/form-errors';
import {
  retargetsIssuedEndpoint,
  normalizedSitePreview,
  validateConnectionForm,
  validatePasswordForm,
  validateSecretForm,
} from '/src/form-validation';
import {
  LOCAL_BROKER, brokerLabel, brokerTakeover, brokerTone, remoteEndpointCaution,
  supportsOnePassword, supportsTypedCredentials,
} from '/src/broker';
import { sameBrokerScope } from '/src/broker-scope';
import {
  SAMPLE_TOOLS, persistSamplesDismissed, sampleConnection, sampleToolById,
} from '/src/samples';
import type { SampleTool } from '/src/samples';
import { activityIdentity } from '/src/activity';
import {
  onePasswordAliasError,
  onePasswordAllVaultsOption,
  onePasswordFieldIsUnsupported,
  onePasswordFieldTypeLabel,
  ONEPASSWORD_ALL_VAULTS_ID,
  onePasswordSelectionKey,
  suggestedOnePasswordAlias,
} from '/src/onepassword';
import { ACTIVITY_PAGE_LIMIT, refreshActivityPages } from '/src/activity-refresh';
import { activeRequestCount, activeRequests, anchorExpiry, recentRequests } from '/src/requests';
import { anchorEndpointExpiries } from '/src/endpoint-expiry';
import { APP_VERSION } from '/src/version';
import { virtualListWindow } from '/src/virtual-list';
import { placeAnchoredMenu } from '/src/menu-position';
import type {
  ActivityEntry,
  ActivityPage,
  Approval,
  ApprovalDecision,
  BrokerProfile,
  CommandArgs,
  CommandName,
  ConnectionInput,
  ConnectionSummary,
  ConnectionType,
  ElicitationRequest,
  McpAuthDraft,
  LockState,
  McpAuthState,
  NotificationSettings,
  RequestRecord,
  SecretKind,
  SecretSummary,
  TotpCode,
  OnePasswordIntegration,
  TestErrorKind,
} from '/src/types';
import {
  queryClient,
  refetchBrokerQuery,
  removeBrokerQueries,
  useBrokerQueryRevision,
} from '/src/query-client';
import { useUiRevision } from '/src/ui-store';
import { AppIcon } from '/src/icon';
import type { IconDefinition } from '/src/icon';
import {
  ConnectionToggle,
  ENDPOINTABLE,
  EndpointAuthRow,
  EndpointExpiryRow,
  EndpointOptionsMenu,
  EndpointStrip,
} from '/src/features/endpoint-view';
import { ConnectedToolsList } from '/src/features/connected-tools-list';
import { CredentialRowsList } from '/src/features/credential-rows';
import { StartViewPage, startBlankId } from '/src/features/connect-agents-view';
import { Sheet } from '/src/sheet';

const EDIT_SECRET_MASK = '••••••••••••';

type PasswordGenerationFormat = NonNullable<ConnectionDraft['passwordGenerationFormat']>;
const PASSWORD_GENERATION_FORMATS: ReadonlyArray<{
  id: PasswordGenerationFormat;
  label: string;
}> = [
  { id: 'strong', label: 'Strong Password' },
  { id: 'no-special', label: 'Without Special Characters' },
  { id: 'easy-to-type', label: 'Easy to Type' },
];

/** Draw uniformly from an alphabet without modulo bias. */
function randomCharacters(alphabet: string, count: number): string {
  const limit = 256 - (256 % alphabet.length);
  const chars: string[] = [];
  while (chars.length < count) {
    const bytes = new Uint8Array(Math.max(32, count - chars.length));
    crypto.getRandomValues(bytes);
    for (const byte of bytes) {
      if (byte < limit && chars.length < count) chars.push(alphabet[byte % alphabet.length]);
    }
  }
  return chars.join('');
}

/** Generate familiar Passwords-style recipes locally. The default preserves
 * the existing four grouped chunks; the alternatives trade punctuation or
 * raw entropy for compatibility and ease of transcription. */
function generatedPassword(format: PasswordGenerationFormat = 'strong'): string {
  const alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  if (format === 'no-special') return randomCharacters(alphabet, 20);
  if (format === 'easy-to-type') {
    const consonants = 'bcdfghjkmnpqrstvwxyz';
    const vowels = 'aeiou';
    const chars = Array.from({ length: 20 }, (_, index) =>
      randomCharacters(index % 2 === 0 ? consonants : vowels, 1));
    return [0, 1, 2, 3]
      .map((group) => chars.slice(group * 5, group * 5 + 5).join(''))
      .join('-');
  }
  const chars = randomCharacters(alphabet, 20);
  return [0, 1, 2, 3]
    .map((group) => chars.slice(group * 5, group * 5 + 5))
    .join('-');
}
/** Rows kept mounted past each edge of the activity window. Enough that a
 * flick of the wheel, or a row that turns out taller than its estimate, never
 * exposes a blank strip before the next frame. */
const ACTIVITY_OVERSCAN = 8;
/** Viewport assumed for the one render that precedes the first measurement.
 * Generously tall: over-mounting for a single pre-paint frame is invisible,
 * under-mounting would show a short list until the scroller is measured. */
const ACTIVITY_PREPAINT_VIEWPORT = 1200;

let reactMounted = false;
let renderPublication = 0;
/** Invalidates an in-flight reveal when navigation or window blur has asked
 * the UI to drop sensitive presentation. */
let sensitivePresentationEpoch = 0;
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
/** Kept in the virtual window across one keyboard-reorder render. */
let keyboardReorderConnId: string | null = null;
let keyboardReorderFocusGeneration = 0;
/** False until boot() has loaded the first broker data; AppRoot keeps
 * showing the loading splash instead of painting an empty window. */
let booted = false;

function brokerEpochIsCurrent(epoch: number): boolean {
  return epoch === brokerEpoch;
}

function clearBrokerOwnedState(): void {
  if (state.sheet) releaseDropdownForm();
  state.activity = [];
  state.activityNextBefore = null;
  state.activityLoadingOlder = false;
  state.activityOlderError = null;
  state.elicitValues = {};
  state.approvalAnswering = null;
  state.approvalHostKeyProvenance = null;
  state.agentSetupInstructions = '';
  state.loadStatus = defaultLoadStatus();
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
  state.secretMenuOpen = null;
  state.secretMenuPoint = null;
  state.secretCategory = 'all';
  state.selectedSecret = null;
  state.secretDetailOpen = false;
  state.totpVisible = null;
  state.dropdownSecretOpen = null;
  state.connectionReady = null;
  state.connTests = {};
  state.draftTest = null;
  state.draftTestOverride = false;
  state.mcpAuth = null;
  state.mcpAuthDraft = null;
  state.mcpAuthOpenedUrl = null;
  state.mcpStatus = {};
  state.wiringTools = null;
  state.onepasswordIntegrations = [];
  state.onepasswordFlow = null;
  closeVaultsPanel();
  // View-local filters and panel state also describe the old broker's data:
  // an agent filter from broker A would silently empty broker B's activity.
  state.activityQuery = '';
  state.activityAgent = null;
  state.activityAgentMenuOpen = false;
  state.activityAlertsOnly = false;
  state.requestQuery = '';
  state.requestAgent = null;
  state.requestAlertsOnly = false;
  state.expandedRequests = [];
  state.toolSearch = '';
  state.secretSearch = '';
  state.sectionsExpanded = [];
  state.connDetailOpen = false;
  dragConnId = null;
  dragConnOrder = null;
  keyboardReorderConnId = null;
  keyboardReorderFocusGeneration += 1;
}

/** The one place sheet transitions happen, so a future cross-cutting
 * concern (analytics, focus policy) has a single seam. */
function setSheet(sheet: SheetState | null): void {
  state.sheet = sheet;
}

/** Change broker identity without ever showing the previous broker's data under it. */
function setBrokerProfile(profile: BrokerProfile): void {
  const scopeChanged = !sameBrokerScope(state.broker, profile);
  const lostOnePassword = supportsOnePassword(state.broker) && !supportsOnePassword(profile);
  if (scopeChanged) brokerEpoch += 1;
  if (scopeChanged) {
    removeBrokerQueries(state.broker);
    clearBrokerOwnedState();
  }
  state.broker = profile;
  if (lostOnePassword) {
    state.onepasswordIntegrations = [];
    if (state.sheet?.kind === 'onepassword') closeSheet();
  }
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
  sensitivePresentationEpoch += 1;
  let changed = Object.keys(state.reveal).length > 0
    || Object.keys(state.epExpanded).length > 0
    || state.secretMenuOpen !== null
    || state.totpVisible !== null;
  if (state.sheet?.kind === 'edit-secret' && state.draft.showCredentialValue) {
    changed = true;
    state.draft.showCredentialValue = false;
    // Values fetched from the broker are never retained behind a re-masked
    // edit field. A replacement the user typed remains, but is hidden.
    if (!state.draft.secretValueModified) state.draft.value = '';
  }
  state.reveal = {};
  state.epExpanded = {};
  state.totpVisible = null;
  // The menu names the reveal state it was opened over; dropping the reveals
  // without it would leave "Unreveal secret" pointing at a hidden value.
  state.secretMenuOpen = null;
  state.secretMenuPoint = null;
  return changed;
}

function showRequestInbox(): void {
  clearSensitivePresentation();
  state.tab = 'inbox';
  state.confirm = null;
  state.menuOpen = false;
  state.startMenuOpen = null;
  state.addPalette = null;
  state.catalogActionMenuOpen = null;
  closeVaultsPanel();
  state.activityAgentMenuOpen = false;
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
/** Portal target for fixed-position overlays that must escape scrolling or
 * clipping application surfaces. */
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
  if (which === 'all' && supportsOnePassword(state.broker)) jobs.push(loadOnePasswordIntegrations());
  if (which === 'all' || which === 'connections') jobs.push(load('connections', 'list_connections'));
  if (which === 'all' || which === 'identity') jobs.push(loadIdentity());
  if (which === 'all' || which === 'sessions') jobs.push(load('sessions', 'list_sessions'));
  if (which === 'all' || which === 'elicitations') jobs.push(load('elicitations', 'list_elicitations'));
  if (which === 'all' || which === 'approvals') jobs.push(load('approvals', 'list_approvals'));
  if (which === 'all' || which === 'requests') jobs.push(load('requests', 'list_requests'));
  if (which === 'all' || which === 'activity') jobs.push(loadActivity(true));
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

async function loadOnePasswordIntegrations(): Promise<boolean> {
  const broker = state.broker;
  const epoch = brokerEpoch;
  if (!supportsOnePassword(broker)) {
    state.onepasswordIntegrations = [];
    return true;
  }
  try {
    const integrations = await refetchBrokerQuery(broker, 'list_onepassword_integrations');
    if (!brokerEpochIsCurrent(epoch)) return false;
    state.onepasswordIntegrations = integrations;
    return true;
  } catch (error) {
    console.error('list_onepassword_integrations', error);
    // A transient provider/management read must not make already-configured
    // connections disappear. Broker scope changes clear this state first.
    return false;
  }
}

async function loadActivity(preserveDepth: boolean): Promise<boolean> {
  const broker = state.broker;
  const epoch = brokerEpoch;
  state.loadStatus.activity = { status: 'loading' };
  try {
    const page = await refreshActivityPages(
      state.activity.length,
      preserveDepth,
      (before, limit) => refetchBrokerQuery(
        broker,
        'list_activity',
        before != null ? { before, limit } : { limit },
      ),
    );
    if (!brokerEpochIsCurrent(epoch)) return false;
    state.activity = page.entries;
    state.activityNextBefore = page.next_before ?? null;
    state.activityLoadingOlder = false;
    state.activityOlderError = null;
    state.loadStatus.activity = { status: 'ready' };
    return true;
  } catch (error) {
    console.error('list_activity', error);
    if (!brokerEpochIsCurrent(epoch)) return false;
    state.loadStatus.activity = { status: 'error', error: errorMessage(error) };
    return false;
  }
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
      case 'secrets': break;
      case 'connections':
        state.connections = anchorEndpointExpiries(result as ConnectionSummary[]);
        // Not awaited: the list paints immediately and the SSH addresses fill
        // in behind it. Each is a vault read, so this must not gate a refresh.
        void resolveSshEndpointSockets(broker, epoch);
        break;
      case 'sessions': break;
      case 'activity': {
        const page = result as ActivityPage;
        state.activity = page.entries;
        state.activityNextBefore = page.next_before ?? null;
        state.activityLoadingOlder = false;
        state.activityOlderError = null;
        break;
      }
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
async function loadSettings(): Promise<boolean> {
  const broker = state.broker;
  const epoch = brokerEpoch;
  state.loadStatus.settings = { status: 'loading' };
  try {
    await refetchBrokerQuery(broker, 'get_settings');
    if (!brokerEpochIsCurrent(epoch)) return false;
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
  const [settings, launchAtLogin] = await Promise.allSettled([
    invoke('get_notification_settings'),
    invoke('get_autostart'),
  ]);
  if (settings.status === 'fulfilled' && epoch === notificationSettingsEpoch) {
    state.notificationSettings = settings.value;
  } else if (settings.status === 'rejected') {
    console.error('get_notification_settings', settings.reason);
  }
  if (launchAtLogin.status === 'fulfilled') {
    state.launchAtLogin = launchAtLogin.value;
  } else {
    console.error('get_autostart', launchAtLogin.reason);
  }
}
/** The lock's saved settings and current state. A failure leaves the
 * defaults, which is "no lock" — the gate is enforced in Rust regardless, so
 * a webview that fails this read cannot talk its way past it. */
async function loadLockState(): Promise<void> {
  try {
    state.lock = await invoke('get_lock_state');
  } catch (error) {
    console.error('get_lock_state', error);
  }
}

/** "5 min" / "1 hr" for the auto-lock toast. */
function relLockDelay(secs: number): string {
  if (secs >= 3600) return `${secs / 3600} hr`;
  return `${secs / 60} min`;
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
    await refetchBrokerQuery(broker, 'get_identity');
    if (!brokerEpochIsCurrent(epoch)) return false;
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

  positionOpenMenus();

  // First render of a connection sheet: snapshot the draft so cancelling
  // can detect real edits.
  if (state.sheet && (state.sheet.kind === 'add-conn' || state.sheet.kind === 'edit-conn') &&
      state.sheetBaseline === null) {
    state.sheetBaseline = connDraftSignature();
  }
}

/** Re-anchor every open portaled menu after layout (render, scroll, resize). */
function positionOpenMenus(): void {
  if (state.formMenuOpen) positionFormMenu();
  if (state.connMenuPoint) positionConnContextMenu();
  else if (state.connMenuOpen) positionConnActionMenu();
  if (state.secretMenuPoint) positionSecretContextMenu();
  if (state.epMenuOpen) positionEpCopyMenu();
  if (state.epOptsMenuOpen) positionEpOptsMenu();
  if (state.catalogActionMenuOpen) positionCatalogConnectMenu();
  if (state.vaultMenuOpen) positionVaultMenu();
  if (state.startMenuOpen) positionStartMenu();
  if (state.activityAgentMenuOpen) positionActivityAgentMenu();
}

/**
 * What one prompt is asking about, in the words of the connection's own
 * plane. Postgres cannot be confirmed per statement — the proxy splices
 * bytes once connected — so it asks per session, and saying so is what
 * makes "Approve" mean something specific.
 */
function approvalUnit(approval: Approval): string {
  if (approval.unit === 'host_key') return 'is asking you to trust an SSH host key';
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
  icon: IconDefinition;
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
      } as Record<string, [string, IconDefinition, string]>)[record.status]
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

function LiveSessions({ extraClass = '' }: { extraClass?: string }): ReactNode {
  return (
    <section className={`live-sessions ${extraClass}`} aria-label="Active sessions">
      <div className="live-head">Active sessions</div>
      <div className="live-list">
        {state.sessions.map((session) => {
          const type = TYPES[session.type];
          const who = session.agent
            ? `${session.agent} → ${session.connection}`
            : session.connection;
          return (
            <div key={session.id} className="live-row">
              <span className={`badge ${type.cls}`}>{type.label}</span>
              <div className="live-txt"><div className="c-name">{who}</div>
                <div className="s-sub" title={session.detail}>{session.detail}</div>
              </div>
              <button className="btn sm" data-act="close-session-ask"
                data-id={session.id}>Close</button>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function GlobalSections({ embeddedInStart = false }: { embeddedInStart?: boolean }): ReactNode {
  const requestCount = activeRequestCount(state.approvals, state.elicitations);
  const showRequests = requestCount > 0 && state.tab !== 'inbox';
  if (!showRequests) return null;
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
  return (
    <div className={`dd-global ${embeddedInStart ? 'start-global' : ''}${
      !embeddedInStart && state.tab === 'secrets' ? ' is-wide' : ''} request-route-only`}>
      <button className="request-banner" data-act="open-inbox"
        aria-label={`${label}. Open the Request Inbox.`}>
        <span className="request-banner-ico">
          <Icon markup={state.approvals.length ? ICONS.shieldAlert : ICONS.bell} />
        </span>
        <span className="request-banner-copy"><b>{label}</b>
          <span>{kinds} · next expires {timeLeft(next.expiresAt)}</span></span>
        <span className="request-banner-cta">Open Inbox</span>
      </button>
    </div>
  );
}

function RequestInbox(): ReactNode {
  const active = activeRequests(state.approvals, state.elicitations);
  const activeIds = new Set(active.map((request) => request.id));
  const allRecent = recentRequests(state.requests, activeIds);
  const requestAgentCounts = countAgents(allRecent.map((record) => record.agent));
  const needle = state.requestQuery.trim().toLowerCase();
  const recent = allRecent.filter((record) => {
    if (state.requestAgent && record.agent !== state.requestAgent) return false;
    if (state.requestAlertsOnly && requestOutcome(record).tone === 'success') return false;
    if (!needle) return true;
    return record.summary.toLowerCase().includes(needle)
      || (record.detail || '').toLowerCase().includes(needle)
      || (record.credential_names || []).some((name) => name.toLowerCase().includes(needle))
      || (record.method || '').toLowerCase().includes(needle)
      || (record.path || '').toLowerCase().includes(needle)
      || (record.host_key_fingerprint || '').toLowerCase().includes(needle)
      || record.agent.toLowerCase().includes(needle)
      || record.connection.toLowerCase().includes(needle)
      || (record.target || '').toLowerCase().includes(needle);
  });
  const count = active.length;
  const empty = count === 0 && allRecent.length === 0;
  const unavailableRefusals = state.requests.filter((record) =>
    record.kind === 'approval'
    && (record.status === 'unavailable' || record.resolution === 'unavailable')).length;
  return (
    <div className="request-inbox">
      {unavailableRefusals > 0
        ? <div className="request-surface-warning" role="status">
            <b>{unavailableRefusals} traffic confirmation
              {unavailableRefusals === 1 ? ' was' : 's were'} refused</b>
            <span>
              No approval surface was attached. This count comes from structured request outcomes.
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
                    <button className={`seg-btn act-filter ${state.requestAlertsOnly ? 'on' : ''}`}
                      data-act="request-filter-alerts" aria-pressed={state.requestAlertsOnly}
                      title="Only show requests that were denied, failed, or expired">Alerts</button>
                    <AgentFilterChips counts={requestAgentCounts} selected={state.requestAgent}
                      act="request-filter-agent" noun="requests"
                      onSelect={(agent) => { state.requestAgent = agent; render(); }} />
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
                                {record.kind === 'approval'
                                  ? <dl className="approval-facts">
                                      <div>
                                        <dt>{record.credential_names?.length === 1
                                          ? 'Credential' : 'Credentials'}</dt>
                                        <dd className="untrusted-identity" dir="auto">
                                          {record.credential_names?.length
                                            ? record.credential_names.join(', ') : 'None'}
                                        </dd>
                                      </div>
                                      {record.method
                                        ? <div><dt>Method</dt><dd><code>{record.method}</code></dd></div>
                                        : null}
                                      {record.path
                                        ? <div><dt>Path</dt><dd><code>{record.path}</code></dd></div>
                                        : null}
                                      {record.host_key_fingerprint
                                        ? <div><dt>Host key</dt>
                                            <dd><code>{record.host_key_fingerprint}</code></dd></div>
                                        : null}
                                    </dl>
                                  : null}
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

/** Whether a credential row matches the Credentials page search. */
function secretMatches(secret: SecretSummary, needle: string): boolean {
  return !needle
    || secret.name.toLowerCase().includes(needle)
    || (secret.site ?? '').toLowerCase().includes(needle)
    || (secret.username ?? '').toLowerCase().includes(needle)
    || secret.used_by_names.some((name) => name.toLowerCase().includes(needle));
}

/** Password names are durable wiring identifiers, not presentation. Keep
 * those generated PASSWORD_* names out of user-facing labels and dialogs. */
function credentialDisplayName(secret: SecretSummary): string {
  if (secret.kind === 'password') return secret.site?.trim() || 'this password';
  return secret.name;
}

function credentialNoun(secret: SecretSummary): 'password' | 'secret' {
  return secret.kind === 'password' ? 'password' : 'secret';
}

// StrictMode mounts effects twice in development. Share an in-flight code
// request so that does not issue (and audit) the same TOTP twice.
const liveTotpRequests = new Map<string, Promise<TotpCode>>();

function requestLiveTotp(scope: string, id: string): Promise<TotpCode> {
  const key = `${scope}:${id}`;
  const pending = liveTotpRequests.get(key);
  if (pending) return pending;
  const request = invoke('get_secret_totp', { id }).finally(() => {
    if (liveTotpRequests.get(key) === request) liveTotpRequests.delete(key);
  });
  liveTotpRequests.set(key, request);
  return request;
}

/** A usable current code belongs only in the full desktop window. It is
 * dropped on blur and refreshed at the broker-provided rollover boundary. */
function LiveTotpCode({ id, site }: { id: string; site: string }): ReactNode {
  const [live, setLive] = useState<{ code: string; expiresAt: number } | null>(null);
  const [now, setNow] = useState(Date.now());
  const scope = `${state.broker.mode}:${state.broker.url ?? ''}`;
  useEffect(() => {
    let mounted = true;
    let focused = true;
    let requestGeneration = 0;
    let refreshTimer: ReturnType<typeof setTimeout> | null = null;
    const load = async () => {
      if (!focused) return;
      const generation = ++requestGeneration;
      try {
        const next = await requestLiveTotp(scope, id);
        if (!mounted || !focused || generation !== requestGeneration) return;
        const receivedAt = Date.now();
        setNow(receivedAt);
        setLive({ code: next.code, expiresAt: receivedAt + next.seconds_remaining * 1000 });
        if (refreshTimer) clearTimeout(refreshTimer);
        refreshTimer = setTimeout(() => { void load(); }, next.seconds_remaining * 1000 + 150);
      } catch (error) {
        if (mounted && focused && generation === requestGeneration) {
          console.error('get_secret_totp', error);
          setLive(null);
        }
      }
    };
    const pause = () => {
      focused = false;
      requestGeneration += 1;
      if (refreshTimer) clearTimeout(refreshTimer);
      refreshTimer = null;
      setLive(null);
    };
    const resume = () => {
      if (focused) return;
      focused = true;
      void load();
    };
    const tick = setInterval(() => setNow(Date.now()), 1000);
    window.addEventListener('blur', pause);
    window.addEventListener('focus', resume);
    void load();
    return () => {
      mounted = false;
      requestGeneration += 1;
      if (refreshTimer) clearTimeout(refreshTimer);
      clearInterval(tick);
      window.removeEventListener('blur', pause);
      window.removeEventListener('focus', resume);
    };
  }, [id, scope]);
  if (!live) return <span className="totp-live totp-live-loading" aria-label="Loading 2FA code">
    <span className="totp-code">––– –––</span>
  </span>;
  const seconds = Math.max(0, Math.ceil((live.expiresAt - now) / 1000));
  const code = live.code.replace(/(\d{3})(?=\d)/g, '$1 ');
  return <button className="totp-live" data-act="copy-totp" data-id={id}
    title="Copy the current 2FA code" aria-label={`Copy the current 2FA code for ${site}`}>
    <span className="totp-code">{code}</span>
    <span className="totp-countdown" aria-label={`${seconds} seconds remaining`}>{seconds}s</span>
  </button>;
}

/** Which category tile a credential sorts under (kind, factor, source). */
function secretInCategory(secret: SecretSummary, category: SecretCategory): boolean {
  switch (category) {
    case 'all': return true;
    case 'passwords': return secret.kind === 'password';
    case 'secrets': return secret.kind !== 'password';
    case 'codes': return Boolean(secret.totp);
    case 'onepassword': return secret.source?.kind === 'one_password';
  }
}

/** The monogram tile beside a row or atop the inspector: the site or name
 * initial, Passwords-style. */
function credentialInitial(secret: SecretSummary): string {
  const label = secret.kind === 'password' ? secret.site ?? '' : secret.name;
  return label.trim().charAt(0).toUpperCase() || '•';
}

/** A row's one-line description under its title. */
function credentialSubtitle(secret: SecretSummary): string {
  if (secret.kind === 'password') return secret.username || 'No username';
  return secret.used_by_names.length
    ? `Used by ${secret.used_by_names.join(', ')}`
    : 'Not in use';
}

/** The masked-value copy affordance shared by the inspector and the tray
 * expansion: the copy button and the post-copy "Copied" status both overlay
 * the mask, centered — never beside it (the placeholder dims behind). */
function MaskedValueCopy({ secret }: { secret: SecretSummary }): ReactNode {
  const copied = state.copied === secret.id;
  return (
    <span className="val-wrap"><span className={`val-slot ${copied ? 'is-copied' : ''}`}>
      <code>••••••••</code>
      <span className="val-overlay">{copied
        ? <span className="copied-badge"><Icon markup={ICONS.check} /><span>Copied</span></span>
        : <button className="ghost-copy" title="Copy value" data-act="copy-secret"
            data-id={secret.id}><Icon markup={ICONS.copy} /><span>Copy</span></button>}</span>
    </span></span>
  );
}

/** A user name is public metadata; it copies from the webview directly and
 * shows its hover affordance beside the visible text. */
function UsernameCopy({ secret }: { secret: SecretSummary }): ReactNode {
  if (!secret.username) return <span className="used-by-empty">No username</span>;
  const copied = state.copied === `user:${secret.id}`;
  return (
    <span className="val-wrap">
      <span dir="auto">{secret.username}</span>
      {copied
        ? <span className="copied-badge"><Icon markup={ICONS.check} /><span>Copied</span></span>
        : <button className="ghost-copy" title="Copy user name" data-act="copy-user"
            data-id={secret.id} data-text={secret.username}>
            <Icon markup={ICONS.copy} /><span>Copy</span>
          </button>}
    </span>
  );
}

function UsedByLinks({ secret }: { secret: SecretSummary }): ReactNode {
  if (!secret.used_by_names.length) return <span className="used-by-empty">Not in use</span>;
  return (
    <div className="used-by-links">{secret.used_by_names.map((name) => {
      const connection = state.connections.find((candidate) => candidate.name === name);
      return connection
        ? <button key={connection.id} className="used-by-link" data-act="show-connection"
            data-id={connection.id}>{name}</button>
        : <span key={name}>{name}</span>;
    })}</div>
  );
}

function CredentialRow({ secret, selected }: {
  secret: SecretSummary;
  selected: boolean;
}): ReactNode {
  const password = secret.kind === 'password';
  const displayName = credentialDisplayName(secret);
  return (
    // data-secret-row is what the right-click handler reads; the whole row
    // is the target, so the reveal menu opens wherever it is pressed.
    <button className={`cred-row ${selected ? 'on' : ''}`} id={`cred-row-${secret.id}`}
      data-act="select-secret" data-id={secret.id} data-secret-row={secret.id}
      aria-current={selected ? 'true' : undefined}>
      <span className="cred-mono" aria-hidden="true">{credentialInitial(secret)}</span>
      <span className="cred-row-tx">
        <b className={password ? 'site-host' : 's-name'} title={displayName}>{displayName}</b>
        <small dir="auto">{credentialSubtitle(secret)}</small>
      </span>
      <span className="cred-row-badges">
        {secret.totp ? <span className="cred-chip" title="Has a 2FA code">2FA</span> : null}
        {secret.source?.kind === 'one_password'
          ? <span className="s-source-icon" title={`Stored in ${secret.source.integration_label}`}
              aria-label={`Stored in ${secret.source.integration_label}`}>
              <Icon markup={ICONS.onepassword} />
            </span>
          : null}
      </span>
    </button>
  );
}

/** The inspector: identity on top, then grouped rows — the Passwords-app
 * shape. Values stay write-only; the mask copies, and a reveal (asked for
 * by name through the right-click menu, confirmed there) lands on its own
 * full-width line under the mask. */
function CredentialDetail({ secret }: { secret: SecretSummary }): ReactNode {
  const password = secret.kind === 'password';
  const displayName = credentialDisplayName(secret);
  const noun = credentialNoun(secret);
  const revealed = state.reveal[secret.id];
  const linked = secret.source?.kind === 'one_password' ? secret.source : null;
  return (
    <div className="cdet" data-secret-row={secret.id}>
      <div className="cdet-toolbar">
        <button className="btn sm cdet-back" data-act="close-cred-detail">
          <Icon markup={ICONS.chevronLeft} /> Back
        </button>
        <button className="btn sm" data-act="edit-secret" data-id={secret.id}
          aria-label={`Edit ${noun} ${displayName}`}>Edit</button>
        <button className="btn sm" data-act="del-secret-ask" data-id={secret.id}
          aria-label={`Delete ${noun} ${displayName}`}>Delete</button>
      </div>
      <div className="cdet-hero">
        <span className="cdet-mono" aria-hidden="true">{credentialInitial(secret)}</span>
        <h3 className={`cdet-title ${password ? '' : 'is-mono'}`}>{displayName}</h3>
      </div>
      <div className="cdet-card">
        {password
          ? <div className="cdet-row"><span className="cdet-lbl">User name</span>
              <span className="cdet-val"><UsernameCopy secret={secret} /></span></div>
          : null}
        <div className="cdet-row"><span className="cdet-lbl">{password ? 'Password' : 'Value'}</span>
          <span className="cdet-val"><MaskedValueCopy secret={secret} /></span></div>
        {revealed === undefined
          ? null
          : <div className="cdet-reveal"><code className="sec-reveal-value">{revealed}</code></div>}
      </div>
      {secret.totp
        ? <div className="cdet-card"><div className="cdet-row">
            <span className="cdet-lbl">Verification code</span>
            {/* Codes are issued (and audited) on request, not by browsing:
                the live code mounts only after Show code asks for it. */}
            <span className="cdet-val">{state.totpVisible === secret.id
              ? <LiveTotpCode id={secret.id} site={displayName} />
              : <button className="btn sm" data-act="show-totp" data-id={secret.id}
                  aria-label={`Show the current 2FA code for ${displayName}`}>
                  Show code
                </button>}</span>
          </div></div>
        : null}
      <div className="cdet-card">
        {password && secret.site
          ? <div className="cdet-row"><span className="cdet-lbl">Website</span>
              <span className="cdet-val">{secret.site}</span></div>
          : null}
        <div className="cdet-row"><span className="cdet-lbl">Used by</span>
          <span className="cdet-val"><UsedByLinks secret={secret} /></span></div>
        <div className="cdet-row"><span className="cdet-lbl">Modified</span>
          <span className="cdet-val cdet-muted" title={absTime(secret.updated_at)}>
            {relTime(secret.updated_at)}</span></div>
      </div>
      {linked
        ? <div className="cdet-card"><div className="cdet-source">
            <span className="cdet-source-icon" aria-hidden="true">
              <Icon markup={ICONS.onepassword} /></span>
            <span className="cdet-source-tx"><b>Stored in 1Password</b>
              <small>{linked.integration_label} › {linked.vault_label} › {linked.item_label} › {linked.field_label}</small></span>
          </div></div>
        : null}
    </div>
  );
}

/** A tray row expands in place to its copy actions — the dropdown keeps
 * find-and-copy fast and hands everything else to the main window. The 2FA
 * code copies without ever rendering (codes display only on the desktop). */
function DropdownCredentialRow({ secret }: { secret: SecretSummary }): ReactNode {
  const open = state.dropdownSecretOpen === secret.id;
  const password = secret.kind === 'password';
  const displayName = credentialDisplayName(secret);
  const noun = credentialNoun(secret);
  const revealed = state.reveal[secret.id];
  return (
    <div className={`dd-cred ${open ? 'open' : ''}`} data-secret-row={secret.id}>
      <button className="cred-row dd-cred-toggle" data-act="toggle-dd-secret" data-id={secret.id}
        aria-expanded={open} aria-label={`${open ? 'Collapse' : 'Expand'} ${noun} ${displayName}`}>
        <span className="cred-mono" aria-hidden="true">{credentialInitial(secret)}</span>
        <span className="cred-row-tx">
          <b className={password ? 'site-host' : 's-name'} title={displayName}>{displayName}</b>
          <small dir="auto">{credentialSubtitle(secret)}</small>
        </span>
        <span className="cred-row-badges">
          {secret.totp ? <span className="cred-chip" title="Has a 2FA code">2FA</span> : null}
          {secret.source?.kind === 'one_password'
            ? <span className="s-source-icon" title={`Stored in ${secret.source.integration_label}`}>
                <Icon markup={ICONS.onepassword} />
              </span>
            : null}
          <span className="dd-cred-chev" aria-hidden="true"><Icon markup={ICONS.chevronDown} /></span>
        </span>
      </button>
      {open
        ? <div className="dd-cred-exp">
            {password
              ? <div className="cdet-row"><span className="cdet-lbl">User name</span>
                  <span className="cdet-val"><UsernameCopy secret={secret} /></span></div>
              : null}
            <div className="cdet-row"><span className="cdet-lbl">{password ? 'Password' : 'Value'}</span>
              <span className="cdet-val"><MaskedValueCopy secret={secret} /></span></div>
            {revealed === undefined
              ? null
              : <div className="cdet-reveal"><code className="sec-reveal-value">{revealed}</code></div>}
            {secret.totp
              ? <div className="cdet-row"><span className="cdet-lbl">2FA code</span>
                  <span className="cdet-val"><button className="totp-chip" data-act="copy-totp"
                    data-id={secret.id} title="Copy the current 2FA code"
                    aria-label={`Copy the current 2FA code for ${displayName}`}>Copy code</button>
                  </span></div>
              : null}
            <div className="dd-cred-actions">
              <button className="btn sm" data-act="edit-secret" data-id={secret.id}
                aria-label={`Edit ${noun} ${displayName}`}>Edit</button>
              <button className="btn sm" data-act="del-secret-ask" data-id={secret.id}
                aria-label={`Delete ${noun} ${displayName}`}>Delete</button>
            </div>
          </div>
        : null}
    </div>
  );
}

/* ---- connection guides (Connect agents > guides view) ---- */
// One shared identity covers every local agent, so the screen pivots around
// the core question — what may agents reach? A key card on top (this
// computer's key: where it lives, and Rotate), then one row per tool with an
// enable/disable toggle. Enabled = agents use the tool without prompting;
// disabled = refused.

// Below this width the Tools tab's detail panel is a slide-over rather
// than a second column. Must match the styles.css breakpoint.
const NARROW_LAYOUT = '(max-width: 720px)';

/** The agents on/off switch, in the detail panel's header — the tool's one
 * primary control. Its state is written out in the title's subline
 * ("Enabled" / "Off"), so the switch itself stays unlabeled and the header
 * keeps its width for the name. The list rows carry only the health dot
 * (gray = off). */
/* ---- connection guides ---- */
// The guides' job is no longer to manage identities the broker stores —
// there is exactly one, this computer's key — but to get the user's own
// agents talking to Multitool: a key card, one guide card per client from
// the shared CONNECT_CLIENTS definitions (the same ones step 2 of the
// walkthrough renders), and a cosmetic recently-seen list built from
// activity labels. Per-tool access lives on the Tools tab.

// Tauri gives the webview the host OS's UA; Claude Desktop's config path
// is the only per-platform copy today.
const liveCount = (c: ConnectionSummary): number =>
  state.sessions.filter((s) => s.connection === c.name).length;
/** The coarse kind a connection belongs to. Drives the muted per-kind
 * icon tint so a mixed list sorts itself visually without being
 * grouped. */
type ConnKind = 'mcp' | 'db' | 'ssh' | 'api';

function connectionKind(c: ConnectionSummary): ConnKind {
  if (c.type === 'pg') return 'db';
  if (c.type === 'ssh') return 'ssh';
  return c.mcp_path ? 'mcp' : 'api';
}

/** The kind spoken to the user, beside the enabled state in the panel head. */
function kindLabel(c: ConnectionSummary): string {
  switch (connectionKind(c)) {
    case 'db': return 'PostgreSQL';
    case 'ssh': return 'SSH';
    case 'mcp': return 'MCP server';
    case 'api': return 'HTTP API';
  }
}

// The fix affordances an issue row can carry: compact buttons stacked under
// the issue text. A fix names the action ("Fix settings", "Reconnect…"),
// never the remedy in prose — the message stays diagnosis-only so it reads
// the same in the banner, the tooltip, and the panel.
interface IssueFix {
  action: string;
  id: string;
  label: string;
  primary: boolean;
}
interface ConnectionIssue {
  text: string;
  detail?: string;
  fixes?: IssueFix[];
  tone?: 'info';
}
const fixBtn = (action: string, id: string, label: string, primary = false): IssueFix =>
  ({ action, id, label, primary });
/** Open the connection editor — the fix for a TLS/cert mismatch. */
const editFix = (c: ConnectionSummary): IssueFix =>
  fixBtn('edit-conn', c.id, 'Fix settings', true);

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
): ConnectionIssue[] {
  const issues: ConnectionIssue[] = [];
  if (c.type === 'pg' && c.sslmode && c.sslmode !== 'verify-full' && !isLoopbackHost(c.host)) {
    issues.push({
      text: c.sslmode === 'disable'
        ? 'TLS is disabled for this connection.'
        : c.sslmode === 'prefer'
          ? 'TLS prefers encryption but may fall back to plaintext; the server identity is not verified.'
          : c.sslmode === 'require'
            ? 'TLS encrypts this connection, but the server identity is not verified.'
            : `TLS is relaxed to ${c.sslmode}.`,
      fixes: [editFix(c)],
    });
  }
  if (c.type === 'ssh' && !c.host_key_fingerprint) {
    issues.push({
      text: 'Multitool has not connected to this tool yet. The SSH host key will be pinned on first connection.',
      tone: 'info',
    });
  }
  if (c.last_status === 'needs_reconnect') {
    issues.push({
      text: c.last_detail || 'The credential was rejected; reconnect to refresh it.',
      fixes: c.mcp_path
        ? [fixBtn('reconnect-mcp', c.id, 'Reconnect…')]
        : c.oauth_spec
        ? [fixBtn('oauth-reconnect', c.id, 'Reconnect…')]
        : undefined,
    });
  }
  if (c.last_status === 'warning') {
    issues.push({
      text: c.last_detail || 'The last connection check completed with a warning.',
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
    // own. Every failure card carries Test again, so retrying never means
    // hunting through the panel's options menu.
    const kind = fresh && !fresh.ok ? fresh.kind : undefined;
    const fixable = !c.mcp_path && kind !== undefined && kind !== 'other';
    const retry = fixBtn(c.mcp_path ? 'mcp-status' : 'test-conn', c.id, 'Test again');
    const fixes = fixable ? [editFix(c), retry] : [retry];
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
          fixes,
        }
      : { text: failure, fixes });
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

/** The per-server tool filter chip an enabled MCP connection carries. */
function confirmUnitLabel(c: ConnectionSummary): string {
  if (c.type === 'pg') return 'Ask before database sessions';
  if (c.type === 'ssh') return 'Ask before SSH logins';
  return c.mcp_path ? 'Confirm tool calls before sending' : 'Confirm requests before sending';
}

/** The caption under the switch's label, where the unit needs saying. */
function confirmScopeNote(c: ConnectionSummary): string {
  if (c.type === 'ssh' || c.type === 'pg') {
    return 'Agents will confirm before logging into each new session.';
  }
  return c.mcp_path
    ? 'Agents will confirm each tool call with you before it’s sent.'
    : 'Agents will confirm each request with you before it’s sent.';
}

/**
 * The traffic-confirmation switch, in the detail panel under the tool's
 * connect section. Off by default: turning it on is the user asking to be
 * interrupted, and it belongs next to the access switch it narrows rather
 * than in global Settings, because the answer differs per tool.
 */
/** The primary action label a catalog entry carries wherever it can be added. */
function catalogAddLabel(entry: CatalogEntry): string {
  return entry.requiresSetup || ['mcp', 'http', 'postgres', 'ssh'].includes(entry.id) || entry.preset
    ? 'Configure'
    : entry.mcp && !entry.mcpTemplate?.serverUrl
    ? 'Add custom app'
    : entry.mcp
    ? 'Connect now'
    : 'Add';
}

/** Open the right add form for a catalog row — the shared behavior behind
 * the catalog Add button and the palette's Enter. */
async function addCatalogEntry(entry: CatalogEntry): Promise<void> {
  if (entry.via !== 'connection' || !entry.connType) return;
  // "Add another" on a dual-mode row should match what is already
  // there: if every existing connection under it is a plain API
  // (no MCP path), open the API form rather than jumping to MCP.
  const existing = connectionsForEntry(entry, state.connections);
  const asApi = Boolean(entry.mcp && entry.preset && existing.length > 0
    && existing.every((connection) => !connection.mcp_path));
  await openCatalogConnectionForm(entry, asApi ? 'bearer' : 'oauth', asApi);
}

function onePasswordMethodLabel(method: OnePasswordIntegration['kind']): string {
  if (method === 'desktop_app') return '1Password app';
  if (method === 'service_account') return 'Service account';
  return 'Connect server';
}

/** Any vault action leaves the popover behind — the sheet or confirm it
 * opens replaces it, and the bar is still there when that closes. */
function closeVaultsPanel(): void {
  state.vaultsPanelOpen = false;
  state.vaultMenuOpen = null;
}

async function openOnePasswordFlow(
  integration?: OnePasswordIntegration,
  intent: 'create' | 'browse' | 'update' = integration ? 'browse' : 'create',
): Promise<void> {
  if (!supportsOnePassword(state.broker)) return;
  if (!await holdDropdownFormOpen()) return;
  const method = integration?.kind ?? (state.broker.mode === 'local' ? 'desktop_app' : 'service_account');
  state.onepasswordFlow = {
    intent,
    step: intent === 'browse' ? 2 : 1,
    method,
    label: integration?.label ?? '1Password',
    account: integration?.account ?? '',
    connectUrl: integration?.connect_url ?? '',
    token: '',
    integration: integration ?? null,
    vaults: [],
    vault: null,
    items: [],
    item: null,
    fields: [],
    selections: {},
    busy: false,
    error: null,
  };
  setSheet({ kind: 'onepassword', id: integration?.id });
  render();
  if (intent === 'browse') await loadOnePasswordVaults();
}

async function connectOnePassword(): Promise<void> {
  const flow = state.onepasswordFlow;
  if (!flow || flow.busy) return;
  const updating = flow.intent === 'update' && flow.integration !== null;
  const label = flow.label.trim();
  const account = flow.account.trim();
  const connectUrl = flow.connectUrl.trim();
  const token = flow.token.trim();
  if (updating && flow.method === 'desktop_app') flow.error = 'The 1Password app reconnects when you browse.';
  else if (!label) flow.error = 'Enter a connection name.';
  else if (flow.method === 'desktop_app' && !account) flow.error = 'Enter your 1Password account.';
  else if (flow.method === 'connect' && !connectUrl) flow.error = 'Enter the Connect server URL.';
  else if (flow.method !== 'desktop_app' && !token) flow.error = 'Enter a 1Password access token.';
  else flow.error = null;
  if (flow.error) { render(); return; }
  const epoch = brokerEpoch;
  flow.busy = true;
  // Access tokens are write-only form values. Drop the UI copy as soon as
  // the request is formed; the native/remote broker owns persistence.
  flow.token = '';
  render();
  try {
    if (updating) {
      const integration = await invoke('replace_onepassword_token', {
        id: flow.integration!.id,
        token,
      });
      if (!brokerEpochIsCurrent(epoch) || state.onepasswordFlow !== flow) return;
      state.onepasswordIntegrations = state.onepasswordIntegrations.map((candidate) =>
        candidate.id === integration.id ? integration : candidate);
      closeSheet();
      toast('1Password credential updated');
      return;
    }
    const integration = await invoke('add_onepassword_integration', {
      label,
      method: flow.method,
      account: flow.method === 'desktop_app' ? account : null,
      connectUrl: flow.method === 'connect' ? connectUrl : null,
      token: flow.method === 'desktop_app' ? null : token,
    });
    if (!brokerEpochIsCurrent(epoch) || state.onepasswordFlow !== flow) return;
    flow.integration = integration;
    flow.step = 2;
    state.onepasswordIntegrations = [
      ...state.onepasswordIntegrations.filter((candidate) => candidate.id !== integration.id),
      integration,
    ];
    await loadOnePasswordVaults();
  } catch (error) {
    if (!brokerEpochIsCurrent(epoch) || state.onepasswordFlow !== flow) return;
    flow.busy = false;
    flow.error = errorMessage(error);
    render();
  }
}

async function loadOnePasswordVaults(): Promise<boolean> {
  const flow = state.onepasswordFlow;
  const integration = flow?.integration;
  if (!flow || !integration) return false;
  const epoch = brokerEpoch;
  flow.busy = true;
  flow.error = null;
  render();
  try {
    const vaults = await invoke('list_onepassword_vaults', { id: integration.id });
    if (!brokerEpochIsCurrent(epoch) || state.onepasswordFlow !== flow) return false;
    flow.vaults = vaults;
    flow.busy = false;
    render();
    return true;
  } catch (error) {
    if (!brokerEpochIsCurrent(epoch) || state.onepasswordFlow !== flow) return false;
    flow.busy = false;
    flow.error = errorMessage(error);
    render();
    return false;
  }
}

async function chooseOnePasswordVault(id: string): Promise<void> {
  const flow = state.onepasswordFlow;
  const integration = flow?.integration;
  const allVaults = flow ? onePasswordAllVaultsOption(flow.vaults) : null;
  const vault = id === ONEPASSWORD_ALL_VAULTS_ID
    ? allVaults
    : flow?.vaults.find((candidate) => candidate.id === id);
  if (!flow || !integration || !vault || flow.busy) return;
  const epoch = brokerEpoch;
  flow.vault = vault;
  flow.item = null;
  flow.items = [];
  flow.fields = [];
  flow.busy = true;
  flow.error = null;
  render();
  try {
    const items = vault.id === ONEPASSWORD_ALL_VAULTS_ID
      ? (await Promise.all(flow.vaults.map(async (sourceVault) => {
          const sourceItems = await invoke('list_onepassword_items', {
            id: integration.id,
            vaultId: sourceVault.id,
          });
          return sourceItems.map((item) => ({
            ...item,
            vault_id: sourceVault.id,
            vault_title: sourceVault.title,
          }));
        }))).flat().sort((left, right) => left.title.localeCompare(right.title)
          || (left.vault_title ?? '').localeCompare(right.vault_title ?? ''))
      : await invoke('list_onepassword_items', { id: integration.id, vaultId: vault.id });
    if (!brokerEpochIsCurrent(epoch) || state.onepasswordFlow !== flow || flow.vault?.id !== vault.id) return;
    flow.items = items;
    flow.busy = false;
    render();
  } catch (error) {
    if (!brokerEpochIsCurrent(epoch) || state.onepasswordFlow !== flow) return;
    flow.busy = false;
    flow.error = errorMessage(error);
    render();
  }
}

async function chooseOnePasswordItem(id: string, vaultId?: string): Promise<void> {
  const flow = state.onepasswordFlow;
  const integration = flow?.integration;
  const item = flow?.items.find((candidate) => candidate.id === id
    && (!vaultId || candidate.vault_id === vaultId));
  const vault = item?.vault_id
    ? flow?.vaults.find((candidate) => candidate.id === item.vault_id)
    : flow?.vault;
  if (!flow || !integration || !vault || !item || flow.busy) return;
  const epoch = brokerEpoch;
  flow.item = item;
  flow.fields = [];
  flow.busy = true;
  flow.error = null;
  render();
  try {
    const fields = await invoke('list_onepassword_fields', {
      id: integration.id, vaultId: vault.id, itemId: item.id,
    });
    if (!brokerEpochIsCurrent(epoch) || state.onepasswordFlow !== flow
      || flow.item?.id !== item.id || flow.item?.vault_id !== item.vault_id) return;
    flow.fields = fields;
    flow.busy = false;
    render();
  } catch (error) {
    if (!brokerEpochIsCurrent(epoch) || state.onepasswordFlow !== flow) return;
    flow.busy = false;
    flow.error = errorMessage(error);
    render();
  }
}

function onePasswordSelectionErrors(): Map<string, string> {
  const flow = state.onepasswordFlow;
  if (!flow) return new Map();
  const selections = Object.values(flow.selections);
  const errors = new Map<string, string>();
  for (const selection of selections) {
    const unavailable = [
      ...state.secrets.map((secret) => secret.name),
      ...selections.filter((candidate) => candidate.key !== selection.key)
        .map((candidate) => candidate.alias),
    ];
    const error = onePasswordAliasError(selection.alias, unavailable);
    if (error) errors.set(selection.key, error);
  }
  return errors;
}

function toggleOnePasswordField(fieldId: string): void {
  const flow = state.onepasswordFlow;
  const item = flow?.item;
  const vault = item?.vault_id
    ? flow?.vaults.find((candidate) => candidate.id === item.vault_id)
    : flow?.vault;
  const field = flow?.fields.find((candidate) => candidate.id === fieldId);
  if (!flow || !vault || !item || !field) return;
  const key = onePasswordSelectionKey(vault, item, field);
  if (onePasswordFieldIsUnsupported(field)) {
    delete flow.selections[key];
    render();
    return;
  }
  if (flow.selections[key]) delete flow.selections[key];
  else {
    const unavailable = [
      ...state.secrets.map((secret) => secret.name),
      ...Object.values(flow.selections).map((selection) => selection.alias),
    ];
    flow.selections[key] = {
      key, vault, item, field,
      alias: suggestedOnePasswordAlias(item, field, unavailable),
    };
  }
  flow.error = null;
  render();
}

async function saveOnePasswordSelections(): Promise<void> {
  const flow = state.onepasswordFlow;
  const integration = flow?.integration;
  if (!flow || !integration || flow.busy) return;
  const selections = Object.values(flow.selections);
  if (!selections.length || onePasswordSelectionErrors().size) return;
  const epoch = brokerEpoch;
  flow.busy = true;
  flow.error = null;
  render();
  for (const selection of selections) {
    try {
      await invoke('add_onepassword_secret', {
        name: selection.alias.trim(),
        integrationId: integration.id,
        vaultId: selection.vault.id,
        vaultLabel: selection.vault.title,
        itemId: selection.item.id,
        itemLabel: selection.item.title,
        sectionId: selection.field.section_id ?? null,
        // Unnamed 1Password sections use an empty title; send null, not "".
        sectionLabel: selection.field.section_title?.trim() || null,
        fieldId: selection.field.id,
        fieldLabel: selection.field.title,
        fieldType: selection.field.field_type,
      });
      if (!brokerEpochIsCurrent(epoch) || state.onepasswordFlow !== flow) return;
      delete flow.selections[selection.key];
    } catch (error) {
      if (!brokerEpochIsCurrent(epoch) || state.onepasswordFlow !== flow) return;
      flow.busy = false;
      flow.error = `Couldn’t save ${selection.alias}: ${errorMessage(error)}`;
      await refresh('secrets');
      render();
      return;
    }
  }
  if (!brokerEpochIsCurrent(epoch) || state.onepasswordFlow !== flow) return;
  const count = selections.length;
  closeSheet();
  await refresh('secrets');
  toast(`Linked ${count} 1Password ${count === 1 ? 'credential' : 'credentials'}`);
}

function OnePasswordStepper({ step }: { step: 1 | 2 | 3 }): ReactNode {
  return <ol className="onepassword-steps" aria-label="Connection progress">
    {['Connect', 'Choose fields', 'Review'].map((label, index) => {
      const number = index + 1;
      return <li key={label} className={number === step ? 'current' : number < step ? 'done' : ''}>
        <span>{number < step ? <Icon markup={ICONS.check} /> : number}</span>{label}
      </li>;
    })}
  </ol>;
}

function OnePasswordMethodOptions(): ReactNode {
  const flow = state.onepasswordFlow;
  if (!flow) return null;
  const methods = [
    { id: 'desktop_app' as const, icon: 'onepasswordApp', title: '1Password app',
      description: 'Authorize with the 1Password app on this Mac.' },
    { id: 'service_account' as const, icon: 'onepasswordService', title: 'Service account',
      description: 'Use a dedicated 1Password service account token.' },
    { id: 'connect' as const, icon: 'onepasswordConnect', title: 'Connect server',
      description: 'Connect through your 1Password Connect server.' },
  ].filter((method) => state.broker.mode === 'local' || method.id !== 'desktop_app');
  return <div className="onepassword-methods" role="radiogroup" aria-label="Connection method">
    {methods.map((method) => <button key={method.id} type="button" role="radio"
      aria-checked={flow.method === method.id}
      className={`onepassword-method ${flow.method === method.id ? 'selected' : ''}`}
      data-act="onepassword-method" data-method={method.id}>
      <span className="onepassword-method-icon"><Icon markup={ICONS[method.icon]} /></span>
      <span><b>{method.title}</b><small>{method.description}</small></span>
    </button>)}
  </div>;
}

function OnePasswordAccountGuide(): ReactNode {
  return <aside className="onepassword-account-guide" aria-hidden="true">
    <div className="onepassword-account-preview">
      <div className="onepassword-account-preview-titlebar">
        <span /><span /><span />
      </div>
      <div className="onepassword-account-preview-body">
        <div className="onepassword-account-preview-account">
          <span className="onepassword-account-preview-avatar" />
          <span className="onepassword-account-preview-name">Wendy Appleseed</span>
          <span className="onepassword-account-preview-chevron" />
        </div>
        <div className="onepassword-account-preview-nav">
          <span>Profile</span>
        </div>
      </div>
    </div>
  </aside>;
}

function OnePasswordConnectStep(): ReactNode {
  const flow = state.onepasswordFlow;
  if (!flow) return null;
  const local = state.broker.mode === 'local';
  const updating = flow.intent === 'update';
  const desktopGuide = flow.method === 'desktop_app';
  return <>
    {updating ? <div className="onepassword-update-summary">
      <span className="onepassword-integration-icon" aria-hidden="true">
        <Icon markup={ICONS.onepassword} />
      </span>
      <span><b>{flow.label}</b><small>{flow.connectUrl || onePasswordMethodLabel(flow.method)}</small></span>
    </div> : <OnePasswordMethodOptions />}
    <div className={`onepassword-form${desktopGuide ? ' onepassword-form--with-guide' : ''}`}>
      <div className="onepassword-form-main">
        {!updating ? <div className="f-row">
          <label htmlFor="op-label">Connection name</label>
          <input id="op-label" value={flow.label} placeholder="e.g. Work 1Password"
            onChange={(event) => { flow.label = event.currentTarget.value; flow.error = null; render(); }} />
        </div> : null}
        {flow.method === 'desktop_app' ? <>
          <div className="f-row">
            <label htmlFor="op-account">Account</label>
            <input id="op-account" value={flow.account} placeholder="Account name or UUID"
              onChange={(event) => { flow.account = event.currentTarget.value; flow.error = null; render(); }} />
          </div>
          <p className="onepassword-method-hint">
            Use the name at the top of the 1Password sidebar, or account UUID.
          </p>
        </> : null}
        {flow.method === 'service_account' ? <>
          <div className="f-row">
            <label htmlFor="op-token">Service account token</label>
            <input id="op-token" type="password" autoComplete="off" value={flow.token}
              placeholder="ops_..."
              onChange={(event) => { flow.token = event.currentTarget.value; flow.error = null; render(); }} />
          </div>
          <p className="onepassword-method-hint">{local
            ? "Credentials are stored in this Mac’s Keychain."
            : "Credentials are stored in the remote broker’s secure vault. Uses a dedicated read-only account that can't access Personal and Private vaults."}</p>
        </> : null}
        {flow.method === 'connect' ? <>
          {!updating ? <div className="f-row">
            <label htmlFor="op-url">Connect server URL</label>
            <input id="op-url" type="url" value={flow.connectUrl} placeholder="https://connect.example.com"
              onChange={(event) => { flow.connectUrl = event.currentTarget.value; flow.error = null; render(); }} />
          </div> : null}
          <div className="f-row">
            <label htmlFor="op-token">Connect access token</label>
            <input id="op-token" type="password" autoComplete="off" value={flow.token}
              placeholder="Example: eyJ..."
              onChange={(event) => { flow.token = event.currentTarget.value; flow.error = null; render(); }} />
          </div>
          <p className="onepassword-method-hint">
            You must be running a 1Password Connect server over https:// or on this computer.
          </p>
        </> : null}
      </div>
      {desktopGuide ? <OnePasswordAccountGuide /> : null}
    </div>
    {flow.error ? <div className="form-global-error" role="alert">{flow.error}</div> : null}
    <div className="sheet-actions onepassword-actions">
      <button className="btn" data-act="sheet-cancel" disabled={flow.busy}>Cancel</button>
      <button className="btn primary" data-act="onepassword-connect" disabled={flow.busy}>
        {flow.busy ? (updating ? 'Updating…' : 'Connecting…')
          : updating ? 'Update connection' : 'Continue'}
      </button>
    </div>
  </>;
}

function OnePasswordBreadcrumb(): ReactNode {
  const flow = state.onepasswordFlow;
  if (!flow?.integration) return null;
  return <nav className="onepassword-breadcrumb" aria-label="1Password location">
    <span className="onepassword-breadcrumb-logo"><Icon markup={ICONS.onepassword} /></span>
    {flow.vault
      ? <button data-act="onepassword-show-vaults">{flow.integration.label}</button>
      : <span>{flow.integration.label}</span>}
    {!flow.vault && flow.method === 'service_account' ? <>
      <span className="onepassword-delimiter" aria-hidden="true">›</span>
      <span className="onepassword-breadcrumb-placeholder">Select a vault…</span>
    </> : null}
    {flow.vault ? <><span className="onepassword-delimiter" aria-hidden="true">›</span>
      {flow.item
        ? <button data-act="onepassword-show-items">{flow.vault.title}</button>
        : <span>{flow.vault.title}</span>}</> : null}
    {flow.item ? <><span className="onepassword-delimiter" aria-hidden="true">›</span>
      <span>{flow.item.title}</span></> : null}
  </nav>;
}

function OnePasswordChooseStep(): ReactNode {
  const flow = state.onepasswordFlow;
  if (!flow) return null;
  const selections = Object.values(flow.selections);
  const errors = onePasswordSelectionErrors();
  const allVaults = onePasswordAllVaultsOption(flow.vaults);
  const vaultOptions = allVaults ? [allVaults, ...flow.vaults] : flow.vaults;
  return <>
    <OnePasswordBreadcrumb />
    <div className="onepassword-browser">
      <section className="onepassword-browser-list">
        <h4>{flow.vault ? 'Items' : 'Vaults'}</h4>
        {flow.busy && !flow.item ? <div className="onepassword-loading">Loading…</div>
          : flow.vault
          ? <>{flow.items.length
              ? flow.items.map((item) => <button key={`${item.vault_id ?? ''}:${item.id}`}
                className={flow.item?.id === item.id && flow.item?.vault_id === item.vault_id
                  ? 'selected' : ''}
                data-act="onepassword-item" data-id={item.id} data-vault-id={item.vault_id}>
                <span>{item.title}</span><small>{item.vault_title
                  ? `${item.vault_title} · ${item.category ?? 'Item'}`
                  : item.category ?? 'Item'}</small>
              </button>)
              : <div className="onepassword-list-empty">No items</div>}
            <button className="onepassword-list-back" data-act="onepassword-show-vaults">
              <Icon markup={ICONS.chevronLeft} /> Back
            </button></>
          : vaultOptions.map((vault) => <button key={vault.id}
              data-act="onepassword-vault" data-id={vault.id}>
              <span>{vault.title}{' '}
                <span className="onepassword-vault-count">({vault.item_count})</span>
              </span>
              <Icon markup={ICONS.chevronRight} />
            </button>)}
      </section>
      <section className="onepassword-fields">
        <div className="onepassword-fields-head"><h4>Fields</h4><h4>Stored as</h4></div>
        {!flow.item ? <div className="onepassword-fields-empty">Choose an item to see its fields.</div>
          : flow.busy ? <div className="onepassword-fields-empty">Loading fields…</div>
          : flow.fields.map((field) => {
              const sourceVault = flow.item?.vault_id
                ? flow.vaults.find((vault) => vault.id === flow.item?.vault_id)
                : flow.vault;
              const key = sourceVault && flow.item
                ? onePasswordSelectionKey(sourceVault, flow.item, field) : '';
              const selection = flow.selections[key];
              const unsupported = onePasswordFieldIsUnsupported(field);
              return <div className={`onepassword-field${selection ? ' selected' : ''}${unsupported ? ' unsupported' : ''}`}
                key={key}>
                <label className="onepassword-field-check"
                  title={unsupported ? 'This 1Password field type is not available to Multitool.' : undefined}>
                  <input type="checkbox" checked={Boolean(selection)}
                    disabled={unsupported}
                    onChange={() => toggleOnePasswordField(field.id)} />
                  <span><b>{field.title}</b>
                    <small>{unsupported
                      ? 'Unsupported'
                      : field.section_title || onePasswordFieldTypeLabel(field.field_type)}</small></span>
                </label>
                <div className="onepassword-alias">
                  {selection ? <>
                    <input aria-label={`Stored name for ${field.title}`} value={selection.alias}
                      className={errors.has(key) ? 'err' : ''}
                      onChange={(event) => {
                        selection.alias = event.currentTarget.value;
                        flow.error = null;
                        render();
                      }} />
                    {errors.get(key) ? <span className="field-error">{errors.get(key)}</span> : null}
                  </> : <span>—</span>}
                </div>
              </div>;
            })}
      </section>
    </div>
    {flow.error ? <div className="form-global-error" role="alert">
      <b>Couldn’t load 1Password</b><span>{flow.error}</span>
      <span className="onepassword-error-actions">
        <button className="btn sm" data-act="onepassword-retry">Retry</button>
        {flow.integration && flow.integration.kind !== 'desktop_app'
          ? <button className="btn sm" data-act="onepassword-update"
              data-id={flow.integration?.id}>Update connection</button>
          : null}
        <button className="btn sm danger" data-act="onepassword-delete-ask"
          data-id={flow.integration?.id}>Remove connection</button>
      </span>
    </div> : null}
    <div className="sheet-actions onepassword-actions">
      <button className="btn" data-act="sheet-cancel">Cancel</button>
      <button className="btn primary" data-act="onepassword-review"
        disabled={!selections.length || errors.size > 0 || flow.busy}>Continue</button>
    </div>
  </>;
}

function OnePasswordReviewStep(): ReactNode {
  const flow = state.onepasswordFlow;
  if (!flow) return null;
  const selections = Object.values(flow.selections);
  return <>
    <div className="onepassword-review-list">
      {selections.map((selection) => <article key={selection.key} className="onepassword-review-row">
        <span className="onepassword-review-icon"><Icon markup={ICONS.onepassword} /></span>
        <span className="onepassword-review-copy">
          <b>{selection.alias}</b>
          <span>{selection.vault.title} <i>›</i> {selection.item.title} <i>›</i>
            {selection.field.section_title ? ` ${selection.field.section_title} › ` : ' '}
            {selection.field.title}</span>
        </span>
        <span className="onepassword-retrieved">Retrieved on use</span>
      </article>)}
    </div>
    {flow.error ? <div className="form-global-error" role="alert">{flow.error}</div> : null}
    <div className="sheet-actions onepassword-actions">
      <button className="btn" data-act="onepassword-back" disabled={flow.busy}>Back</button>
      <button className="btn primary" data-act="onepassword-save" disabled={flow.busy || !selections.length}>
        {flow.busy ? 'Saving…' : `Save ${selections.length} linked ${selections.length === 1 ? 'credential' : 'credentials'}`}
      </button>
    </div>
  </>;
}

function OnePasswordSheet(): ReactNode {
  const flow = state.onepasswordFlow;
  if (!flow) return null;
  const updating = flow.intent === 'update';
  return <>
    <header className="onepassword-sheet-head">
      <span className="onepassword-sheet-logo"><Icon markup={ICONS.onepassword} /></span>
      <h3 id="onepassword-sheet-title">{updating ? 'Update 1Password credential' : 'Connect 1Password'}</h3>
    </header>
    {!updating ? <OnePasswordStepper step={flow.step} /> : null}
    {flow.step === 1 ? <OnePasswordConnectStep />
      : flow.step === 2 ? <OnePasswordChooseStep />
      : <OnePasswordReviewStep />}
  </>;
}

function CatalogRow({ entry }: { entry: CatalogEntry }): ReactNode {
  if (entry.disabled) {
    return (
      <div className="cat-row-wrap is-soon">
        <div className="cat-row">
          <span className="cat-ico" aria-hidden="true"><Icon markup={ICONS[entry.icon] || ''} /></span>
          <div className="cat-tx"><b>{entry.name}</b>
            <span>{entry.description}</span></div>
          <span className="cat-soon" title="Not available yet">Coming soon</span>
        </div>
      </div>
    );
  }
  const quickConnect = canQuickConnectMcp(entry);
  const actionMenuOpen = state.catalogActionMenuOpen === entry.id;
  const addLabel = catalogAddLabel(entry);
  let action: ReactNode = null;
  if (quickConnect) {
    action = (
      <div className={`cat-connect-wrap ${actionMenuOpen ? 'open' : ''}`}>
        <div className="cat-connect-buttons">
          <button className="btn cat-add cat-connect-primary" data-act="catalog-connect-oauth"
            data-id={entry.id}>Connect</button>
          <button className="btn cat-add cat-connect-menu-btn"
            data-act="toggle-catalog-connect-menu" data-id={entry.id}
            title={`More ways to connect ${entry.name}`} aria-label={`More ways to connect ${entry.name}`}
            aria-expanded={actionMenuOpen}>
            <Icon markup={ICONS.chevronDown} />
          </button>
        </div>
        {actionMenuOpen
          ? createPortal(
              <div className="anchored-menu-portal cat-connect-menu-wrap"
                data-catalog-menu-portal={entry.id}>
                <div className="cat-connect-menu" aria-label={`Connect ${entry.name}`}>
                  <button className="menu-item" data-act="catalog-connect-oauth"
                    data-id={entry.id}>Connect</button>
                  <button className="menu-item" data-act="catalog-connect-manual"
                    data-id={entry.id}>Connect via custom URL</button>
                  {entry.preset
                    ? <button className="menu-item" data-act="catalog-connect-api"
                        data-id={entry.id}>Connect custom API</button>
                    : null}
                </div>
              </div>,
              overlays(),
            )
          : null}
      </div>
    );
  } else if (entry.via === 'connection') {
    action = <button className="btn cat-add" data-act="catalog-add"
      data-id={entry.id}>{addLabel}</button>;
  } else {
    action = <span className="cat-soon" title="Arrives with the MCP layer">Soon</span>;
  }
  return (
    <div className={`cat-row-wrap ${actionMenuOpen ? 'menu-open' : ''}`}>
      <div className="cat-row">
        <span className="cat-ico" aria-hidden="true"><Icon markup={ICONS[entry.icon] || ''} /></span>
        <div className="cat-tx"><b>{entry.name}</b>
          <span>{entry.description}</span></div>
        {entry.mcp
          ? <span className="cat-mech"
              title="Added by connecting to the vendor’s MCP server">MCP</span>
          : null}
        {action}
      </div>
    </div>
  );
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



/** Whether a draft is being edited as an MCP server rather than a raw API. */
function isMcpDraft(draft: { isMcp?: boolean; mcpPath?: string | null }): boolean {
  return Boolean(draft.isMcp || draft.mcpPath);
}

// Sections that collapse to their connected/minimum rows behind a "More
// tools" disclosure: every app domain. Infrastructure and the custom
// endpoints stay fully expanded — they are the short, load-bearing rows.
const COLLAPSIBLE_SECTIONS: string[] =
  ['Developer Tools', 'AI Models', 'Productivity', 'Communication', 'Business'];

/** Whether a test or MCP check finished this session and passed. The verdict
 * surfaces as a plain-words success alert — the technical transcript ("GET …
 * answered HTTP 200 OK") stays out of the success path, since a pass needs no
 * diagnostics. */
function freshTestPassed(c: ConnectionSummary): boolean {
  if (c.mcp_path) {
    const status = state.mcpStatus[c.id];
    return Boolean(status && !status.running && !status.error && status.report?.ok);
  }
  const test = state.connTests[c.id];
  return Boolean(test && !test.running && test.ok && test.detail !== undefined);
}

/** The attention layer above the details pane: the fresh test verdict and
 * every issue, pulled out of the pane so a tool's health reads before its
 * plumbing. */
function ConnectionAlerts({ connection: c }: { connection: ConnectionSummary }): ReactNode {
  if (!c.agent_access.enabled) return null;
  const issues = connectionIssues(c);
  const passed = freshTestPassed(c);
  if (!issues.length && !passed) return null;
  return <div className="cc-issues cd-alerts">
    {passed
      ? <div className="cc-issue ok" role="status">
          <Icon markup={ICONS.circleCheck} />
          <div className="cc-issue-body">
            <span className="cc-issue-headline">
              Connection test passed — {connectionRowName(c)} is responding.
            </span>
          </div>
        </div>
      : null}
    {issues.map((issue, index) =>
      <div key={`${issue.text}:${index}`} className={`cc-issue ${issue.tone ?? ''}`}>
        <Icon markup={issue.tone === 'info' ? ICONS.info : ICONS.triangleAlert} />
        <div className="cc-issue-body">
          <span className="cc-issue-headline">{issue.text}</span>
          {issue.detail ? <span className="cc-issue-detail">{issue.detail}</span> : null}
          {issue.fixes?.length
            ? <div className="cc-issue-fixes">
                {issue.fixes.map((fix) => (
                  <button key={fix.action} className={`btn sm ${fix.primary ? 'primary' : ''}`}
                    data-act={fix.action} data-id={fix.id}>{fix.label}</button>
                ))}
              </div>
            : null}
        </div>
      </div>)}
  </div>;
}

function ConnectionToolsChip({ connection: c }: {
  connection: ConnectionSummary;
}): ReactNode {
  if (!c.agent_access.enabled || !c.mcp_path) return null;
  const count = c.agent_access.allowed_tools?.length;
  return <button className="cat-meta-tools" data-act="wiring-tools" data-conn={c.id}
    aria-label={`Choose which tools agents may call on ${c.name}`}
    title="Choose which of this server’s tools agents may call">
    <Icon markup={ICONS.filter} />
    <span>{count == null ? 'All tools' : `${count} tool${count === 1 ? '' : 's'}`}</span>
  </button>;
}

function ConnectionMenuItems({ connection: c }: {
  connection: ConnectionSummary;
}): ReactNode {
  const test = state.connTests[c.id];
  const mcpStatus = c.mcp_path ? state.mcpStatus[c.id] : undefined;
  const running = c.mcp_path ? Boolean(mcpStatus?.running) : Boolean(test?.running);
  // Renew / rotate / revoke live on the Connect section's ⋯ menu, next to
  // the address they manage — not on the tool's general options menu.
  return <>
    <button className="menu-item"
      data-act={c.mcp_path ? 'mcp-status' : 'test-conn'} data-id={c.id} disabled={running}>
      <Icon markup={ICONS.flaskConical} /> {running ? 'Testing…' : 'Test connection'}
    </button>
    <button className="menu-item" data-act="edit-conn" data-id={c.id}>
      <Icon markup={ICONS.pencil} /> Edit tool
    </button>
    <button className="menu-item danger" data-act="del-conn-ask" data-id={c.id}>
      <Icon markup={ICONS.trash} /> Delete tool
    </button>
  </>;
}

function ConfirmationSection({ connection: c }: {
  connection: ConnectionSummary;
}): ReactNode {
  if (!c.agent_access.enabled) return null;
  const on = Boolean(c.agent_access.confirm);
  const until = c.agent_access.confirm_window_until;
  const windowAgents = c.agent_access.confirm_window_agents ?? [];
  const covered = windowAgents.length === 1
    ? `for ${windowAgents[0]}`
    : windowAgents.length > 1
    ? `for ${windowAgents.length} agents`
    : '';
  const windowActive = Boolean(on && until && new Date(until).getTime() > Date.now());
  const cooldownUntil = c.agent_access.confirm_cooldown_until;
  const cooldownActive = Boolean(
    on && cooldownUntil && new Date(cooldownUntil).getTime() > Date.now(),
  );
  const scope = confirmScopeNote(c);
  return <div className="cd-sec cd-confirm">
    <div className="cd-confirm-row">
      <div className="cd-confirm-txt">
        <div className="cd-confirm-lbl">{confirmUnitLabel(c)}</div>
        {scope ? <div className="cd-confirm-sub">{scope}</div> : null}
      </div>
      <button className={`switch ${on ? 'on' : ''}`} role="switch" aria-checked={on}
        title={on ? 'Traffic is confirmed with you first' : 'Traffic goes without asking'}
        aria-label={`${on ? 'Stop confirming' : 'Confirm'} traffic on ${c.name}`}
        data-act={on ? 'confirm-off' : 'confirm-on'} data-conn={c.id}></button>
    </div>
    {windowActive && until
      ? <div className="cd-confirm-window"><Icon markup={ICONS.timer} /><span>
          Approved {covered} until {clockTime(until)} — not asking{' '}
          {windowAgents.length === 1 ? 'again' : 'them again'} until then. Other agents are
          still asked.
        </span></div>
      : null}
    {cooldownActive && cooldownUntil
      ? <div className="cd-confirm-window cd-confirm-cooldown">
          <Icon markup={ICONS.clockAlert} /><span>Denied — retries are refused without asking
            for {timeLeft(cooldownUntil)}. Turning confirmation off and back on clears it.</span>
        </div>
      : null}
    {on
      ? <div className="cd-confirm-note">With no Multitool approval surface attached,
          this tool’s traffic is refused rather than carried.</div>
      : null}
  </div>;
}

/**
 * Upstream cookies and authentication challenges can grant authority beyond
 * the broker's configured request credential. HTTP tools return them by
 * default; Advanced lets the user contain them at the broker boundary.
 */
function ResponseCredentialRelay({ connection: c }: {
  connection: ConnectionSummary;
}): ReactNode {
  if (c.type !== 'api') return null;
  const on = Boolean(c.agent_access.expose_response_credentials);
  return <div className="cd-confirm-row cd-response-credentials">
    <div className="cd-confirm-txt">
      <div className="cd-confirm-lbl">Return upstream credentials to agents</div>
      <div className="cd-confirm-sub">
        {on
          ? 'Set-Cookie and authentication challenge/info headers are returned to control-plane and direct-endpoint callers.'
          : 'Cookies and authentication challenge/info headers stay inside the upstream boundary.'}
      </div>
    </div>
    <button className={`switch ${on ? 'on' : ''}`} role="switch" aria-checked={on}
      title={on ? 'Upstream response credentials are exposed' : 'Upstream response credentials are contained'}
      aria-label={`${on ? 'Contain' : 'Return'} upstream response credentials for ${c.name}`}
      data-act={on ? 'response-credentials-off' : 'response-credentials-on'}
      data-conn={c.id}></button>
  </div>;
}

/**
 * Whether this database's statement text is kept in Activity.
 *
 * Postgres only, under Advanced. One approval covers every statement in the
 * session, so this decides whether those statements are retained afterward.
 * Off by default — SQL literals carry passwords and personal data, and that is
 * a retention choice per database rather than per machine.
 */
function StatementRecording({ connection: c }: { connection: ConnectionSummary }): ReactNode {
  if (c.type !== 'pg') return null;
  const on = Boolean(c.agent_access.audit_statements_effective);
  const overridden = c.agent_access.audit_statements != null;
  return <div className="cd-confirm-row cd-statements">
    <div className="cd-confirm-txt">
      <div className="cd-confirm-lbl">Record statements in Activity</div>
      <div className="cd-confirm-sub">
        {on
          ? 'The SQL of each statement is written to the activity log, where it can '
            + 'carry credentials and personal data.'
          : 'Only records the number of statements per session.'}
        {overridden ? ' Set on this tool.' : null}
      </div>
    </div>
    <button className={`switch ${on ? 'on' : ''}`} role="switch" aria-checked={on}
      title={on ? 'Statement text is recorded' : 'Statement text is not recorded'}
      aria-label={`${on ? 'Stop recording' : 'Record'} statement text for ${c.name}`}
      data-act={on ? 'statements-off' : 'statements-on'} data-conn={c.id}></button>
  </div>;
}

function ConnectionToolScope({ connection: c }: {
  connection: ConnectionSummary;
}): ReactNode {
  if (!c.mcp_path) return null;
  const count = c.agent_access.allowed_tools?.length;
  return <div className="cd-confirm-row cd-tool-scope">
    <div className="cd-confirm-txt">
      <div className="cd-confirm-lbl">Tools agents may call</div>
      <div className="cd-confirm-sub">
        {count == null
          ? 'Every tool this MCP server advertises is available to agents.'
          : `${count} selected tool${count === 1 ? ' is' : 's are'} available to agents.`}
      </div>
    </div>
    <ConnectionToolsChip connection={c} />
  </div>;
}

function ConnectionAdvancedSection({ connection: c }: {
  connection: ConnectionSummary;
}): ReactNode {
  if (!c.agent_access.enabled) return null;
  const hasEndpointAuth = c.type === 'ssh' && Boolean(c.agent_access.endpoint);
  const hasOptions = Boolean(c.mcp_path)
    || c.type === 'api'
    || c.type === 'pg'
    || hasEndpointAuth;
  if (!hasOptions) return null;
  const open = state.connDetailAdvancedOpen === c.id;
  return <div className="cd-sec cd-advanced">
    <button className="adv-toggle" data-act="toggle-connection-advanced"
      data-id={c.id} aria-expanded={open} aria-controls={`connection-advanced-${c.id}`}>
      <span className="adv-toggle-icon" aria-hidden="true">
        <Icon markup={ICONS.chevronDown} />
      </span>
      Advanced
    </button>
    {open
      ? <div className="cd-advanced-options" id={`connection-advanced-${c.id}`}>
          <ConnectionToolScope connection={c} />
          <ResponseCredentialRelay connection={c} />
          <StatementRecording connection={c} />
          <EndpointExpiryRow connection={c} />
          <EndpointAuthRow connection={c} />
        </div>
      : null}
  </div>;
}

/** Fact rows for the selected tool (host, user, credential, …). Same
 * disclosure pattern as Advanced so the pane stays short by default. */
function ConnectionDetailsSection({ connection: c }: {
  connection: ConnectionSummary;
}): ReactNode {
  const factRows = connectionFactRows(c);
  if (!factRows.length) return null;
  const open = state.connDetailDetailsOpen === c.id;
  const live = liveCount(c);
  return <div className="cd-sec cd-details">
    <button className="adv-toggle" data-act="toggle-connection-details"
      data-id={c.id} aria-expanded={open} aria-controls={`connection-details-${c.id}`}>
      <span className="adv-toggle-icon" aria-hidden="true">
        <Icon markup={ICONS.chevronDown} />
      </span>
      Details
    </button>
    {open
      ? <div className="cd-details-body" id={`connection-details-${c.id}`}>
          <div className="cd-facts">{factRows.map(([key, value]) =>
            <div key={key} className="cd-fact">
              <span className="cd-fact-k">{key}</span><code className="cd-fact-v">{value}</code>
            </div>)}
          </div>
          {live
            ? <div className="cd-live">{live} live session{live === 1 ? '' : 's'} ·{' '}
                <button className="cd-live-link" data-act="tab" data-tab="activity">
                  View in Activity Log
                </button>
              </div>
            : null}
        </div>
      : null}
  </div>;
}

function McpStatus({ connection: c }: { connection: ConnectionSummary }): ReactNode {
  const status = c.mcp_path ? state.mcpStatus[c.id] : undefined;
  const report = status && !status.running && !status.error ? status.report : undefined;
  if (!report?.ok) return null;
  const shown = report.resources.slice(0, 8);
  return <>
    {report.resources_supported
      ? <>
          <div className="mcp-res-head">Resources ({report.resources.length})</div>
          {shown.length
            ? shown.map((resource) => <div key={`${resource.uri}:${resource.name}`} className="mcp-res">
                <b title={resource.name}>{resource.name}</b>
                <code title={resource.uri}>{resource.uri}</code>
              </div>)
            : <div className="mcp-res-more">None listed by the server.</div>}
          {report.resources.length > shown.length
            ? <div className="mcp-res-more">+ {report.resources.length - shown.length} more</div>
            : null}
        </>
      : null}
    {report.truncated
      ? <div className="mcp-res-more">
          Catalog results were capped; more items are available upstream.
        </div>
      : null}
  </>;
}

function connectionFactRows(c: ConnectionSummary): Array<[string, string]> {
  const rows: Array<[string, string]> = [];
  if (c.mcp_path) {
    // target is the full pinned origin — scheme and non-default port
    // included — so a local server never shows a truncated address here.
    if (c.host) rows.push(['Upstream', `${c.target}${c.mcp_path === '/' ? '' : c.mcp_path}`]);
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
    rows.push(['Upstream', c.target]);
  }
  if (c.signer?.algorithm === 'gcp_service_account') {
    rows.push(['Credential',
      `GCP service account (${c.signer.scope ?? ''}), minted from ${
        c.secret_names.length ? c.secret_names.join(', ') : 'the vaulted key'}`]);
  } else if (c.signer) {
    rows.push(['Credential',
      `AWS SigV4 (${c.signer.region} · ${c.signer.service}), signs with ${
        c.secret_names.length ? c.secret_names.join(', ') : 'vault credentials'}`]);
  } else if (c.secret_names.length) rows.push(['Credential', c.secret_names.join(', ')]);
  else if (c.oauth) rows.push(['Credential', 'OAuth, renewed by Multitool']);
  if (c.client_cert_path) rows.push(['Client certificate', c.client_cert_path]);
  return rows;
}

function ConnectionDetail({ connection: c }: {
  connection: ConnectionSummary;
}): ReactNode {
  const menuOpen = state.connMenuOpen === c.id && !state.connMenuPoint;
  const enabled = c.agent_access.enabled;
  const entry = entryForConnection(c);
  const connectTitle = connectionKind(c) === 'db'
    ? 'Connect to this database'
    : connectionKind(c) === 'ssh'
    ? 'Connect to this server'
    : 'Connect to this service';
  const endpointSection = enabled && ENDPOINTABLE[c.type] && !c.mcp_path
    ? <div className="cd-sec cd-connect">
        <div className="cd-connect-lbl">
          <span>{connectTitle}</span>
          <EndpointOptionsMenu connection={c} />
        </div>
        <EndpointStrip connection={c} withFormats />
      </div>
    : null;
  const mcpSection = enabled && c.mcp_path
    ? <div className="cd-sec cd-connect">
        <div className="cd-connect-lbl">
          <span>Connect to Multitool MCP</span>
          {ENDPOINTABLE[c.type] ? <EndpointOptionsMenu connection={c} /> : null}
        </div>
        {ENDPOINTABLE[c.type] ? <EndpointStrip connection={c} /> : null}
      </div>
    : null;
  return <>
    <div className="cd-head">
      <span className={`cat-ico kind-${connectionKind(c)}`} aria-hidden="true">
        {entry ? <Icon markup={ICONS[entry.icon] || ''} /> : null}
      </span>
      <div className="cd-title"><b title={c.name}>{connectionRowName(c)}</b>
        <span>{kindLabel(c)}</span>
      </div>
      <div className="cd-actions">
        <div className="tile-menu-wrap">
          <button className={`icon-btn tile-menu-btn ${menuOpen ? 'on' : ''}`}
            title="Tool options" aria-label={`Options for ${c.name}`}
            aria-expanded={menuOpen} data-act="toggle-conn-menu" data-id={c.id}
            data-conn-menu-trigger={c.id}>
            <Icon markup={ICONS.ellipsis} />
          </button>
        </div>
        <ConnectionToggle connection={c} />
      </div>
    </div>
    {!enabled ? <div className="cd-help cd-off-note">This tool is disabled.</div> : null}
    {c.mcp_path ? <>{mcpSection}{endpointSection}</> : <>{endpointSection}{mcpSection}</>}
    <ConfirmationSection connection={c} />
    <ConnectionAdvancedSection connection={c} />
    <ConnectionDetailsSection connection={c} />
    <McpStatus connection={c} />
  </>;
}

function FlatConnectionRow({ connection: c, reorderable = false }: {
  connection: ConnectionSummary;
  reorderable?: boolean;
}): ReactNode {
  const kind = connectionKind(c);
  const live = liveCount(c);
  const entry = entryForConnection(c);
  const selected = selectedConnection()?.id === c.id;
  const issues = connectionIssues(c).filter((issue) => issue.tone !== 'info');
  // The status is a word, never a bare dot: Off / Connected, or the worst
  // problem by name so the list answers "what's wrong" without a click.
  const health = !c.agent_access.enabled
    ? <span className="cc-pill off" title="Agents may not use this tool">Off</span>
    : !issues.length
    ? <span className="cc-pill ok" title="Ready">Connected</span>
    : <span className={`cc-pill ${c.last_status === 'failed' ? 'err' : 'warn'}`}
        title={issues.map((issue) => issue.text).join(' ')}
        aria-label={`${issues.length} issue${issues.length === 1 ? '' : 's'}`}>
        {c.last_status === 'failed'
          ? 'Unreachable'
          : c.last_status === 'needs_reconnect'
          ? 'Reconnect'
          : 'Warning'}
      </span>;
  return <div
    className={`flat-conn-wrap ${selected ? 'sel' : ''}${reorderable ? ' reorderable' : ''}${dragConnId === c.id ? ' dragging' : ''}`}
    data-conn-row={c.id} draggable={reorderable || undefined}>
    <div className="flat-conn-row" role="button" tabIndex={0} data-act="select-conn"
      data-id={c.id} aria-expanded={selected}
      aria-label={`Show details for ${connectionRowName(c)}`}
      aria-keyshortcuts={reorderable ? 'Alt+ArrowUp Alt+ArrowDown' : undefined}>
      <span className={`cat-ico kind-${kind}`} aria-hidden="true">
        {entry ? <Icon markup={ICONS[entry.icon] || ''} /> : null}
      </span>
      <div className="flat-tx"><b title={c.name}>{connectionRowName(c)}</b>
        <span><span className="flat-dest" title={c.target}>{c.target}</span></span>
      </div>
      {live ? <span className="cc-live">{live} live</span> : null}
      <div className="cat-conn-status">{health}</div>
    </div>
  </div>;
}

function ConnectionReadyCard(): ReactNode {
  const ready = state.connectionReady;
  if (!ready) return null;
  return <div className="connection-ready">
    <b>{ready.name} successfully added</b>
    <button className="icon-btn" title="Dismiss" aria-label="Dismiss success message"
      data-act="dismiss-connection-ready"><Icon markup={ICONS.circleX} /></button>
  </div>;
}

/* ---- Add-a-tool palette -------------------------------------------------- */
// Adding a tool is a search, not a place: the catalog never renders inline
// once a tool exists. One button opens this palette, typing filters the
// full catalog, ↑↓ selects, Enter adds. The empty state is the exception —
// with nothing connected yet, the directory is the page (see ConnectionsView).

const PALETTE_SECTIONS = [
  'Infrastructure',
  ...CATALOG_SECTIONS.filter((section) => section !== 'Infrastructure' && section !== 'Secrets'),
];

interface PaletteGroup { section: string; entries: CatalogEntry[]; }

/** The palette's result groups: every addable catalog row matching the
 * query, in the catalog's section order. Connected rows drop out unless
 * the kind supports several (databases, servers, custom endpoints). */
function paletteGroups(query: string): PaletteGroup[] {
  const entries = visibleCatalog(query);
  const isConnected = (entry: CatalogEntry): boolean =>
    connectionsForEntry(entry, state.connections).length > 0;
  const alwaysAddable = (entry: CatalogEntry): boolean =>
    entry.connType === 'pg' || entry.connType === 'ssh' || ['http', 'mcp'].includes(entry.id);
  return PALETTE_SECTIONS.flatMap((section) => {
    const rows = entries.filter((entry) => entry.section === section
      && !entry.disabled
      && entry.via === 'connection'
      && (!isConnected(entry) || alwaysAddable(entry)));
    return rows.length ? [{ section, entries: rows }] : [];
  });
}

/** The palette's add: OAuth-capable rows connect immediately, everything
 * else opens the same form the catalog's Add button would. */
async function activatePaletteEntry(entryId: string): Promise<void> {
  const entry = catalogEntryById(entryId);
  state.addPalette = null;
  render();
  if (!entry) return;
  if (canQuickConnectMcp(entry)) {
    await quickConnectCatalogMcp(entry);
    return;
  }
  await addCatalogEntry(entry);
}

function AddToolPalette(): ReactNode {
  const palette = state.addPalette;
  if (!palette) return null;
  const groups = paletteGroups(palette.query);
  const flat = groups.flatMap((group) => group.entries);
  const index = Math.max(0, Math.min(palette.index, flat.length - 1));
  const move = (delta: number): void => {
    if (!flat.length) return;
    palette.index = (index + delta + flat.length) % flat.length;
    const targetId = `palette-row-${flat[palette.index].id}`;
    render();
    requestAnimationFrame(() => {
      document.getElementById(targetId)?.scrollIntoView({ block: 'nearest' });
    });
  };
  let flatIndex = -1;
  return (
    <div className="palette-layer">
      <button className="palette-backdrop" data-act="close-add-palette" tabIndex={-1}
        aria-label="Close the tool palette"></button>
      <div className="add-palette" role="dialog" aria-modal="true" aria-label="Add a tool">
        <div className="palette-search">
          <span className="palette-search-ico" aria-hidden="true">
            <Icon markup={ICONS.scanSearch} />
          </span>
          <input id="add-palette-input" type="text" placeholder="Search tools to add…"
            role="combobox" aria-expanded="true" aria-controls="palette-listbox"
            aria-activedescendant={flat[index] ? `palette-row-${flat[index].id}` : undefined}
            autoComplete="off" spellCheck={false}
            value={palette.query}
            onChange={(e) => {
              palette.query = e.currentTarget.value;
              palette.index = 0;
              render();
            }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
              else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
              else if (e.key === 'Enter' && flat[index]) {
                e.preventDefault();
                void activatePaletteEntry(flat[index].id);
              } else if (e.key === 'Escape') {
                e.preventDefault();
                e.stopPropagation();
                state.addPalette = null;
                render();
              }
            }} />
        </div>
        <div className="palette-list" role="listbox" id="palette-listbox"
          aria-label="Tools that can be added">
          {groups.map((group) => (
            <div key={group.section} className="palette-group">
              <div className="palette-sec" aria-hidden="true">{group.section.toUpperCase()}</div>
              {group.entries.map((entry) => {
                flatIndex += 1;
                const selected = flatIndex === index;
                return (
                  <button key={entry.id} id={`palette-row-${entry.id}`} role="option"
                    aria-selected={selected}
                    className={`palette-row ${selected ? 'sel' : ''}`}
                    data-act="palette-add" data-id={entry.id}>
                    <span className="cat-ico" aria-hidden="true">
                      <Icon markup={ICONS[entry.icon] || ''} />
                    </span>
                    <span className="palette-tx"><b>{entry.name}</b>
                      <span className="palette-desc">{entry.description}</span></span>
                    <span className="palette-verb">
                      {canQuickConnectMcp(entry) ? 'Connect' : catalogAddLabel(entry)}
                    </span>
                  </button>
                );
              })}
            </div>
          ))}
          {!flat.length ? <div className="muted-note">No tools match your search.</div> : null}
        </div>
        <div className="palette-hints" aria-hidden="true">
          <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
          <span><kbd>↵</kbd> add</span>
          <span><kbd>esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}

/* ---- sample tools ------------------------------------------------------- */
// The spotlight card above the tools list: two keyless public APIs whose
// Connect is genuinely zero-step (see src/samples.ts). Only the tinted
// surface is new — the rows, icon chips, and pills are the standard catalog
// components, so the card reads as tools, not an announcement. It stays
// pinned through first run and steady state until its ✕ dismisses it for
// good; a connected sample flips its button to a Connected badge and the
// card keeps offering the other one.

function SampleRow({ sample }: { sample: SampleTool }): ReactNode {
  const connected = Boolean(sampleConnection(sample, state.connections));
  const connecting = state.sampleConnecting === sample.id;
  return (
    <div className="cat-row">
      <span className={`cat-ico brand-${sample.icon}`} aria-hidden="true">
        <Icon markup={ICONS[sample.icon]} />
      </span>
      <div className="cat-tx">
        <b>{sample.name}</b>
        <span>{sample.description}</span>
      </div>
      {connected
        ? <span className="sample-connected"><Icon markup={ICONS.check} /> Connected</span>
        : <button className="btn primary cat-add" data-act="connect-sample"
            data-id={sample.id} disabled={connecting}>
            {connecting ? 'Connecting…' : 'Connect'}
          </button>}
    </div>
  );
}

function SamplesCard(): ReactNode {
  if (state.samplesDismissed) return null;
  return (
    <div className="cat-section">
      <div className="samples-card">
        <div className="samples-head">
          <span className="samples-spark" aria-hidden="true"><Icon markup={ICONS.sparkles} /></span>
          <div className="samples-title">
            <b>Try a sample tool</b>
            <span>Live public APIs you can test against, with zero setup.</span>
          </div>
          <button className="icon-btn samples-dismiss" data-act="dismiss-samples"
            title="Hide sample tools" aria-label="Hide sample tools">
            <Icon markup={ICONS.x} />
          </button>
        </div>
        {SAMPLE_TOOLS.map((sample) => <SampleRow key={sample.id} sample={sample} />)}
      </div>
    </div>
  );
}

function ConnectionsView({ withReadyCard = true }: { withReadyCard?: boolean }): ReactNode {
  const byId = new Map(state.connections.map((connection) => [connection.id, connection] as const));
  const orderedConnections = dragConnOrder
    ? [
        ...dragConnOrder.map((id) => byId.get(id)).filter(
          (connection): connection is ConnectionSummary => Boolean(connection),
        ),
        ...state.connections.filter((connection) => !dragConnOrder!.includes(connection.id)),
      ]
    : state.connections;
  const entries = visibleCatalog(state.toolSearch);
  const isConnected = (entry: CatalogEntry): boolean =>
    connectionsForEntry(entry, state.connections).length > 0;
  const needle = state.toolSearch.trim().toLowerCase();
  const matching = orderedConnections.filter((c) => {
    const entry = entryForConnection(c);
    const entryMatches = Boolean(entry) && [
      entry!.name, entry!.description, ...(entry!.keywords || []),
    ].some((text) => text.toLowerCase().includes(needle));
    return !needle
      || c.name.toLowerCase().includes(needle)
      || c.target.toLowerCase().includes(needle)
      || (c.account || '').toLowerCase().includes(needle)
      || entryMatches;
  });
  const reorderable = !needle && matching.length > 1;
  // The directory renders inline only while nothing is connected — with
  // nothing to manage, browsing is the page. Once a tool exists, adding
  // moves to the palette and the list shows only what agents can reach.
  const showDirectory = !state.connections.length;
  const alwaysAddable = (entry: CatalogEntry): boolean =>
    entry.connType === 'pg' || entry.connType === 'ssh' || ['http', 'mcp'].includes(entry.id);
  const sections = !showDirectory ? [] : PALETTE_SECTIONS.flatMap((section) => {
    const sectionEntries = entries.filter(
      (entry) => entry.section === section && (!isConnected(entry) || alwaysAddable(entry)),
    );
    if (!sectionEntries.length) return [];
    const ordered = connectedCatalogFirst(sectionEntries, state.connections);
    const collapsible = COLLAPSIBLE_SECTIONS.includes(section) && !state.toolSearch.trim();
    const expanded = state.sectionsExpanded.includes(section);
    const collapsed = collapsible
      ? collapsedCatalogGroup(sectionEntries, state.connections)
      : { visible: ordered, hiddenCount: 0 };
    return [{
      section,
      rows: collapsible && !expanded ? collapsed.visible : ordered,
      expanded,
      hiddenCount: collapsed.hiddenCount,
    }];
  });
  const detail = selectedConnection();
  return <>
    {withReadyCard ? <ConnectionReadyCard /> : null}
    <div className={`catalog ${state.connDetailOpen ? 'detail-open' : ''}`}>
      <div className="tools-split">
        <div className="tools-list">
          {mode !== 'dropdown' ? <SamplesCard /> : null}
          {state.connections.length
            ? <div className="cat-section">
                {matching.length
                  ? <ConnectedToolsList items={matching} reorderable={reorderable}
                      dragging={Boolean(dragConnId)}
                      keepMountedId={keyboardReorderConnId}
                      renderItem={(connection) =>
                        <FlatConnectionRow key={connection.id} connection={connection}
                          reorderable={reorderable} />} />
                  : <div className="cat-rows">
                      <div className="muted-note">No tools match your search.</div>
                    </div>}
              </div>
            : null}
          {mode === 'dropdown' && state.connections.length
            ? <div className="cat-section"><div className="cat-rows">
                <div className="cat-row is-toggle add-tools-row" role="button" tabIndex={0}
                  data-act="open-add-palette" aria-haspopup="dialog"
                  aria-label="Add a tool">
                  <span className="cat-ico" aria-hidden="true"><Icon markup={ICONS.plus} /></span>
                  <div className="cat-tx"><b>Add a tool</b></div>
                </div>
              </div></div>
            : null}
          {showDirectory && !sections.length
            ? <div className="muted-note">No tools match your search.</div>
            : sections.map(({ section, rows, expanded, hiddenCount }) =>
                <div key={section} className="cat-section add-section">
                  <div className="cat-section-h">{section.toUpperCase()}</div>
                  <div className="cat-rows">
                    {rows.map((entry) => <CatalogRow key={entry.id} entry={entry} />)}
                    {hiddenCount > 0
                      ? <button className="cat-more" data-act="toggle-section-expanded"
                          data-id={section} aria-expanded={expanded}>
                          <span>{expanded ? 'Show fewer tools' : 'Show more tools'}</span>
                          <span className={`cat-more-chev ${expanded ? 'open' : ''}`}
                            aria-hidden="true"><Icon markup={ICONS.chevronDown} /></span>
                        </button>
                      : null}
                  </div>
                </div>)}
        </div>
        {detail
          ? <div className="conn-detail-col">
              <ConnectionAlerts connection={detail} />
              <aside className="conn-detail-pane" aria-label="Connection details">
                <ConnectionDetail connection={detail} />
              </aside>
            </div>
          : null}
      </div>
      {detail && state.connDetailOpen
        ? <button className="conn-detail-backdrop" data-act="close-conn-detail"
            aria-label="Close connection details" tabIndex={-1}></button>
        : null}
    </div>
  </>;
}

// The credential library always advertises both typed groups. Each heading
// owns its quiet, right-aligned add link, preselecting that credential kind.
// Legacy remote brokers retain their single untyped table.
const SECRET_CATEGORY_TILES: ReadonlyArray<{
  id: SecretCategory;
  label: string;
  icon: IconDefinition;
}> = [
  { id: 'all', label: 'All', icon: ICONS.key },
  { id: 'passwords', label: 'Passwords', icon: ICONS.globe },
  { id: 'secrets', label: 'Secrets', icon: ICONS.fileKey },
  { id: 'codes', label: 'Codes', icon: ICONS.timer },
  { id: 'onepassword', label: '1Password', icon: ICONS.onepassword },
];

// Apple's Passwords app spends a third column on these; Multitool's left
// edge already belongs to app navigation, so the categories compress into
// the tile grid Passwords itself uses at compact widths.
function CredentialCategoryTiles(): ReactNode {
  const counts = new Map<SecretCategory, number>(SECRET_CATEGORY_TILES.map((tile) =>
    [tile.id, state.secrets.filter((secret) => secretInCategory(secret, tile.id)).length]));
  // The 1Password scope earns its tile once the integration is in play.
  const showOnePassword = (counts.get('onepassword') ?? 0) > 0
    || state.onepasswordIntegrations.length > 0;
  const tiles = SECRET_CATEGORY_TILES.filter((tile) =>
    tile.id !== 'onepassword' || showOnePassword);
  // Roving tabindex: one tab stop for the whole group. If the checked tile
  // just disappeared (1Password unlinked), the first tile keeps the stop.
  const stop = tiles.some((tile) => tile.id === state.secretCategory)
    ? state.secretCategory : tiles[0]?.id;
  return (
    <div className="cred-tiles" role="radiogroup" aria-label="Credential categories"
      onKeyDown={(e) => {
        if (!['ArrowRight', 'ArrowDown', 'ArrowLeft', 'ArrowUp'].includes(e.key)) return;
        e.preventDefault();
        const at = tiles.findIndex((tile) => tile.id === state.secretCategory);
        const delta = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : -1;
        const next = tiles[(at + delta + tiles.length) % tiles.length];
        if (!next) return;
        // Radio semantics: moving the focus moves the selection with it.
        state.secretCategory = next.id;
        state.secretDetailOpen = false;
        render();
        focusField(`cred-tile-${next.id}`);
      }}>
      {tiles.map((tile) => {
        const on = (state.secretCategory === tile.id);
        return (
          <button key={tile.id} className={`cred-tile is-${tile.id} ${on ? 'on' : ''}`}
            id={`cred-tile-${tile.id}`} tabIndex={tile.id === stop ? 0 : -1}
            role="radio" aria-checked={on} data-act="secret-category" data-id={tile.id}>
            <span className="cred-tile-ico" aria-hidden="true"><Icon markup={tile.icon} /></span>
            <span className="cred-tile-label">{tile.label}</span>
            <span className="cred-tile-count">{counts.get(tile.id)}</span>
          </button>
        );
      })}
    </div>
  );
}

// The Credentials page is a master–detail split, Passwords-style: category
// tiles over a monogram list on the left, the selected credential's
// inspector on the right. The dropdown compresses the same inventory into
// expandable tray rows. Legacy untyped brokers keep the split but drop the
// tiles and grouping — everything they hold is a secret.
function SecretsView(): ReactNode {
  const needle = state.secretSearch.trim().toLowerCase();
  const typed = supportsTypedCredentials(state.broker);
  const matching = state.secrets.filter((secret) => secretMatches(secret, needle));
  if (mode === 'dropdown') {
    const ordered = [
      ...matching.filter((secret) => secret.kind === 'password'),
      ...matching.filter((secret) => secret.kind !== 'password'),
    ];
    return (
      <div className="dd-creds">
        {ordered.length
          ? <CredentialRowsList className="dd-cred-list" secrets={ordered} rowEstimate={40}
              keepMountedId={state.dropdownSecretOpen}
              renderRow={(secret) => <DropdownCredentialRow key={secret.id} secret={secret} />} />
          : <div className="muted-note">
              {state.secrets.length
                ? 'No saved credentials match your search.'
                : 'No saved credentials yet.'}
            </div>}
        <button className="credential-group-add" data-act="open-add-secret">＋ Add credential</button>
      </div>
    );
  }
  const category: SecretCategory = typed ? state.secretCategory : 'all';
  const inCategory = matching.filter((secret) => secretInCategory(secret, category));
  const passwords = inCategory.filter((secret) => secret.kind === 'password');
  const secrets = inCategory.filter((secret) => secret.kind !== 'password');
  const grouped = typed && category === 'all';
  const ordered = grouped ? [...passwords, ...secrets] : inCategory;
  // The inspector always has a subject: an explicit selection when it is
  // still visible under the active tile and search, else the first row.
  const selected = ordered.find((secret) => secret.id === state.selectedSecret)
    ?? ordered[0] ?? null;
  // Each card windows its rows against the page scroller; the selected row
  // stays mounted so keyboard focus and the current-row semantics hold.
  const rowCard = (list: SecretSummary[]): ReactNode => (
    <CredentialRowsList className="cred-rows" secrets={list} rowEstimate={44}
      keepMountedId={selected?.id}
      renderRow={(secret) => <CredentialRow key={secret.id} secret={secret}
        selected={secret.id === selected?.id} />} />
  );
  const filteredEmptyNote = category === 'codes' ? 'No credentials have a 2FA code yet.'
    : category === 'onepassword' ? 'No credentials are linked from 1Password yet.'
    : category === 'passwords' ? 'No passwords yet.'
    : category === 'secrets' ? 'No secrets yet.'
    : 'No saved credentials yet.';
  // Passwords lead the page unlabelled — they are the page. The secrets
  // group gets one page-register header; the tray keeps its flat list.
  const listBody = grouped
    ? <>
        {passwords.length
          ? rowCard(passwords)
          : <div className="cred-rows"><div className="muted-note">
              {state.secrets.some((secret) => secret.kind === 'password')
                ? 'No passwords match your search.' : 'No passwords yet.'}
            </div></div>}
        <h2 className="creds-sec-h">Secrets</h2>
        {secrets.length
          ? rowCard(secrets)
          : <div className="cred-rows"><div className="muted-note">
              {state.secrets.some((secret) => secret.kind !== 'password')
                ? 'No secrets match your search.' : 'No secrets yet.'}
            </div></div>}
      </>
    : ordered.length
      ? rowCard(ordered)
      : <div className="cred-rows"><div className="muted-note">
          {needle ? 'No credentials match your search.' : filteredEmptyNote}
        </div></div>;
  return (
    <div className={`creds ${selected && state.secretDetailOpen ? 'detail-open' : ''}`}>
      <div className="creds-split">
        <div className="creds-list-col"
          onKeyDown={(e) => {
            if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
            // The tiles above the list own their radiogroup arrow keys.
            if (e.target instanceof Element && e.target.closest('.cred-tiles')) return;
            e.preventDefault();
            const at = ordered.findIndex((secret) => secret.id === selected?.id);
            const next = ordered[at + (e.key === 'ArrowDown' ? 1 : -1)];
            if (!next) return;
            state.selectedSecret = next.id;
            render();
            focusField(`cred-row-${next.id}`);
          }}>
          {typed ? <CredentialCategoryTiles /> : null}
          {listBody}
        </div>
        {selected
          ? <div className="cred-detail-col">
              <aside className="cred-detail-pane"
                aria-label={`Details for ${credentialDisplayName(selected)}`}>
                <CredentialDetail secret={selected} />
              </aside>
            </div>
          // An empty scope keeps the split's shape: the inspector column
          // stays, carrying the inbox-style placeholder, instead of the
          // list stretching across the whole page.
          : <div className="cred-detail-col">
              <aside className="cred-detail-pane" aria-label="No credentials in this view">
                <div className="empty">
                  <div className="empty-ico"><Icon markup={ICONS.key} /></div>
                  <h3>No credentials here</h3>
                  <p>{needle
                    ? 'Nothing in this view matches your search.'
                    : 'Credentials in this category will appear here.'}</p>
                </div>
              </aside>
            </div>}
      </div>
      {selected && state.secretDetailOpen
        ? <button className="cred-detail-backdrop" data-act="close-cred-detail"
            aria-label="Close credential details" tabIndex={-1}></button>
        : null}
    </div>
  );
}

/* ---- secrets status bar ------------------------------------------------ */
// Vault state compresses into a status bar flush with the window bottom:
// the left side is a live inventory, the right side manages 1Password
// connections from an upward-anchored popover, so toggling it never
// reflows the table above.

function VaultRow({ integration }: { integration: OnePasswordIntegration }): ReactNode {
  const linked = state.secrets.filter((secret) => secret.source?.kind === 'one_password'
    && secret.source.integration_id === integration.id).length;
  const method = integration.account || integration.connect_url
    || onePasswordMethodLabel(integration.kind);
  const menuOpen = state.vaultMenuOpen === integration.id;
  return (
    <div className="onepassword-integration-row vault-row">
      <span className="onepassword-integration-copy">
        <b>{integration.label}</b>
        <span>{method}</span>
        <span>{linked} linked {linked === 1 ? 'credential' : 'credentials'}</span>
      </span>
      <span className="onepassword-integration-actions">
        <button className="btn sm" data-act="onepassword-browse"
          data-id={integration.id}>Link credentials</button>
        <button className={`btn sm vault-menu-btn ${menuOpen ? 'on' : ''}`}
          data-act="toggle-vault-menu" data-id={integration.id}
          title={`Options for ${integration.label}`}
          aria-label={`Options for ${integration.label}`}
          aria-expanded={menuOpen} aria-haspopup="true">
          <Icon markup={ICONS.ellipsis} />
        </button>
        {menuOpen
          ? createPortal(
              <div className="anchored-menu-portal vault-menu-wrap">
                <div className="tile-menu" aria-label={`Options for ${integration.label}`}>
                  {integration.kind !== 'desktop_app'
                    ? <button className="menu-item" data-act="onepassword-update"
                        data-id={integration.id}>Edit connection method…</button>
                    : null}
                  <button className="menu-item danger" data-act="onepassword-delete-ask"
                    data-id={integration.id}>Remove…</button>
                </div>
              </div>,
              overlays(),
            )
          : null}
      </span>
    </div>
  );
}

function SecretsStatusBar(): ReactNode {
  const available = supportsOnePassword(state.broker);
  const integrations = state.onepasswordIntegrations;
  const linked = state.secrets.filter((secret) => secret.source?.kind === 'one_password').length;
  const credentialCount = state.secrets.length;
  const open = state.vaultsPanelOpen && integrations.length > 0;
  const inventory = `${credentialCount} ${credentialCount === 1 ? 'credential' : 'credentials'}`;
  return (
    <footer className="secrets-statusbar">
      <span className="sb-count">
        {inventory}
        {linked ? ` · ${linked} linked from 1Password` : ''}
      </span>
      <span className="sb-spacer"></span>
      {integrations.length
        ? <button className={`sb-vaults ${open ? 'on' : ''}`} data-act="toggle-vaults-panel"
            aria-expanded={open} aria-haspopup="true" title="Manage 1Password vaults">
            <span className="sb-1p" aria-hidden="true"><Icon markup={ICONS.onepassword} /></span>
            Connected {integrations.length} {integrations.length === 1 ? 'vault' : 'vaults'}
            <span className={`sb-chev ${open ? 'open' : ''}`} aria-hidden="true">
              <Icon markup={ICONS.chevronDown} /></span>
          </button>
        : <button className="sb-vaults" data-act="onepassword-open" disabled={!available}
            title={available ? undefined : 'Update this remote broker to use 1Password'}>
            <span className="sb-1p" aria-hidden="true"><Icon markup={ICONS.onepassword} /></span>
            {available ? 'Connect 1Password' : 'Unavailable'}
          </button>}
      {open
        ? <div className="vaults-panel" role="group" aria-label="1Password vaults">
            {integrations.map((integration) =>
              <VaultRow key={integration.id} integration={integration} />)}
            <button className="vaults-connect-more" data-act="onepassword-open">
              ＋ Connect another vault
            </button>
          </div>
        : null}
    </footer>
  );
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

/* Agent filter chips overflow into a select past this many agents. */
const AGENT_CHIP_LIMIT = 5;

/** How often each agent appears in the loaded window; drives which chips
 * stay visible when the row overflows. */
function countAgents(agents: Array<string | null | undefined>): Map<string, number> {
  const counts = new Map<string, number>();
  for (const agent of agents) {
    if (agent) counts.set(agent, (counts.get(agent) ?? 0) + 1);
  }
  return counts;
}

/** One filter chip per agent, most active first. Chips beat a dropdown at
 * small scale, but the row must not grow unbounded: past AGENT_CHIP_LIMIT
 * the tail collapses into a native "+N more" select, and an agent chosen
 * there is promoted to a visible pressed chip on the next render. */
function AgentFilterChips({ counts, selected, act, noun, onSelect }: {
  counts: Map<string, number>;
  selected: string | null;
  act: string;
  noun: 'activity' | 'requests';
  onSelect: (agent: string) => void;
}): ReactNode {
  const agents = [...counts.keys()].sort((a, b) =>
    ((counts.get(b) ?? 0) - (counts.get(a) ?? 0)) || a.localeCompare(b));
  let visible = agents;
  let overflow: string[] = [];
  if (agents.length > AGENT_CHIP_LIMIT) {
    visible = agents.slice(0, AGENT_CHIP_LIMIT);
    if (selected && !visible.includes(selected)) visible = [...visible, selected];
    overflow = agents.filter((agent) => !visible.includes(agent));
  }
  return (
    <>
      {visible.map((agent) => (
        <button key={agent} className={`seg-btn act-filter ${selected === agent ? 'on' : ''}`}
          data-act={act} data-value={agent}
          aria-pressed={selected === agent}
          title={`Only show ${noun} from agent “${agent}” (self-reported label)`}>
          <span className="act-filter-key">agent:</span>
          <span className="untrusted-identity" dir="auto">{agent}</span>
        </button>
      ))}
      {overflow.length > 0
        ? <select className="act-filter-more" value=""
            aria-label={`Filter ${noun} by another agent`}
            onChange={(e) => { if (e.currentTarget.value) onSelect(e.currentTarget.value); }}>
            <option value="" disabled>+{overflow.length} more…</option>
            {overflow.map((agent) => (
              <option key={agent} value={agent} dir="auto">{agent}</option>
            ))}
          </select>
        : null}
    </>
  );
}

/** The activity entries the current filters keep. */
function filteredActivity(): ActivityEntry[] {
  const needle = state.activityQuery.trim().toLowerCase();
  return state.activity.filter((entry) => {
    if (state.activityAlertsOnly && entry.tone !== 'danger' && entry.tone !== 'warning') {
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

async function loadOlderActivity(): Promise<void> {
  const before = state.activityNextBefore;
  if (before === null || state.activityLoadingOlder) return;
  const broker = state.broker;
  const epoch = brokerEpoch;
  state.activityLoadingOlder = true;
  state.activityOlderError = null;
  render();
  try {
    const page = await refetchBrokerQuery(
      broker,
      'list_activity',
      { limit: ACTIVITY_PAGE_LIMIT, before },
    );
    if (!brokerEpochIsCurrent(epoch) || state.activityNextBefore !== before) return;
    // The broker cursor is a stable file boundary, so pages do not overlap
    // even when new entries arrive. Preserve genuinely identical audit rows.
    state.activity = [...state.activity, ...page.entries];
    state.activityNextBefore = page.next_before ?? null;
  } catch (error) {
    console.error('list_activity older page', error);
    if (brokerEpochIsCurrent(epoch) && state.activityNextBefore === before) {
      state.activityOlderError = errorMessage(error);
    }
  } finally {
    if (brokerEpochIsCurrent(epoch)) {
      state.activityLoadingOlder = false;
      render();
    }
  }
}

/** The agent filter: one agent at a time, or "All agents" — a pill-shaped
 * menu rather than a chip per agent, which grew past the filter row as soon
 * as a few agents had connected. The names are self-reported, so they stay
 * in the untrusted-identity treatment wherever they appear. */
function ActivityAgentFilter({ agents }: { agents: string[] }): ReactNode {
  const open = state.activityAgentMenuOpen;
  const selected = state.activityAgent;
  return (
    <div className={`act-filter-select ${open ? 'open' : ''}`}>
      <button className={`seg-btn act-filter act-filter-trigger ${selected ? 'on' : ''}`}
        data-act="act-filter-agent-menu" aria-haspopup="listbox" aria-expanded={open}
        title="Only show activity from one agent (self-reported label)">
        <span className="act-filter-key">Agent:</span>
        {selected
          ? <span className="untrusted-identity" dir="auto">{selected}</span>
          : <span>All</span>}
        <span className="act-filter-chev" aria-hidden="true">
          <Icon markup={ICONS.chevronDown} />
        </span>
      </button>
      {open
        ? createPortal(
            <div className="anchored-menu-portal act-filter-menu-wrap">
              <div className="act-filter-menu" role="listbox" aria-label="Filter activity by agent">
                <button className={`menu-item ${selected ? '' : 'on'}`} role="option"
                  aria-selected={!selected} data-act="act-filter-agent" data-value="">
                  All agents
                </button>
                {agents.map((agent) => (
                  <button key={agent} className={`menu-item ${selected === agent ? 'on' : ''}`}
                    role="option" aria-selected={selected === agent}
                    data-act="act-filter-agent" data-value={agent}>
                    <span className="untrusted-identity" dir="auto">{agent}</span>
                  </button>
                ))}
              </div>
            </div>,
            overlays(),
          )
        : null}
    </div>
  );
}

function ActivityView(): ReactNode {
  const liveSessions = state.sessions.length
    ? <LiveSessions extraClass="activity-live-sessions" />
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
  // Agents seen in the loaded window, offered one at a time in the picker.
  const agents = [...new Set(state.activity.map((entry) => entry.agent).filter(Boolean))] as string[];
  const entries = filteredActivity();
  const hasOlder = state.activityNextBefore !== null;
  return (
    <>
      {liveSessions}
      <div className="act-filters">
        <input id="activity-search" className="cat-search act-search" type="search"
          placeholder="Filter activity…" aria-label="Filter activity"
          value={state.activityQuery}
          onChange={(e) => { state.activityQuery = e.currentTarget.value; render(); }} />
        <button className={`seg-btn act-filter ${state.activityAlertsOnly ? 'on' : ''}`}
          data-act="act-filter-alerts" aria-pressed={state.activityAlertsOnly}
          title="Only show warnings and errors">Alerts</button>
        {agents.length ? <ActivityAgentFilter agents={agents} /> : null}
      </div>
      {entries.length
        ? <ActivityList entries={entries} />
        : <div className="muted-note">Nothing matches these filters.</div>}
      <div className="activity-page-footer">
        {hasOlder
          ? <span>
              Filters currently cover {state.activity.length.toLocaleString()} loaded entries.
            </span>
          : <span>All {state.activity.length.toLocaleString()} retained entries are loaded.</span>}
        {state.activityOlderError
          ? <span className="activity-page-error" role="alert">{state.activityOlderError}</span>
          : null}
        {hasOlder
          ? <button className="btn sm" data-act="activity-load-older"
              disabled={state.activityLoadingOlder}>
              {state.activityLoadingOlder ? 'Loading…' : 'Load older activity'}
            </button>
          : null}
      </div>
    </>
  );
}

async function receiveActivity(entry: ActivityEntry | null | undefined): Promise<void> {
  if (!entry || !entry.at || !entry.text) {
    await loadActivity(true);
    if (state.tab === 'activity' && !state.sheet && !state.menuOpen) render();
    return;
  }

  const identity = activityIdentity(entry);
  const duplicate = state.activity.some((item) => activityIdentity(item) === identity);
  if (duplicate) return;
  state.activity = [entry, ...state.activity];

  if (state.tab !== 'activity' || state.sheet || state.menuOpen) return;
  // With filters active the cheap prepend would bypass them; re-render.
  if (state.activityQuery || state.activityAgent || state.activityAlertsOnly) {
    render();
    return;
  }
  render();
}

/** Step 2's pane for one connect mode: a one-line lead, the snippet, and its
 * action row. */
function DropdownCatalogSearch({ kind }: { kind: 'tool' | 'secret' }): ReactNode {
  const isTool = kind === 'tool';
  return (
    <input className="cat-search dd-cat-search" type="search"
      placeholder={isTool ? 'Search tools…' : 'Search credentials…'}
      aria-label={isTool ? 'Search tools' : 'Search credentials'}
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
  if (state.tab === 'start') {
    return <StartViewPage globalSections={<GlobalSections embeddedInStart />} />;
  }
  // The dropdown puts its catalog search inline above the list; the wide
  // window has it in the header instead (see MainWindow). The ready card
  // stays above the search, where the one-markup-blob layout had it.
  if (mode === 'dropdown' && (state.tab === 'connections' || state.tab === 'secrets')) {
    const isTools = state.tab === 'connections';
    return (
      <>
        {isTools && <ConnectionReadyCard />}
        <DropdownCatalogSearch kind={isTools ? 'tool' : 'secret'} />
        {isTools ? <ConnectionsView withReadyCard={false} /> : <SecretsView />}
      </>
    );
  }
  if (state.tab === 'secrets') return <SecretsView />;
  return <ConnectionsView />;
}

function BrokerReady(): ReactNode {
  // The badge tracks the *managed* broker: a remote link that is down must
  // not sit under a green "Ready".
  const tone = brokerTone(state.broker);
  const label = tone === 'error' ? 'Unreachable' : tone === 'pending' ? 'Connecting…' : 'Ready';
  return <div className="dd-sub ready-status">
    <span className="ready-state" role="status"><span className={`dot dot-${tone}`} aria-hidden="true"></span>
      <span>{label}</span></span>
  </div>;
}

/* --------------------------- broker switcher ------------------------------ */

/** The header's custom local/remote dropdown (right-justified). */
function BrokerSwitch(): ReactNode {
  const tone = brokerTone(state.broker);
  const label = brokerLabel(state.broker);
  return (
    <div className="broker-switch-wrap">
      <button className={`broker-btn ${state.brokerMenuOpen ? 'on' : ''}`} data-act="broker-menu"
        aria-expanded={state.brokerMenuOpen} title="Which broker this app manages">
        <span className={`broker-dot ${tone}`}></span><span className="broker-label">{label}</span>
        <span className="broker-caret" aria-hidden="true"><Icon markup={ICONS.chevronDown} /></span>
      </button>
      {state.brokerMenuOpen
        ? <div className="broker-menu">
            <button className="menu-item" data-act="broker-pick-local">
              <span className="broker-check">{state.broker.mode === 'local' ? '✓' : ''}</span> Local
            </button>
            <button className="menu-item" data-act="broker-pick-remote">
              <span className="broker-check">{state.broker.mode === 'remote' ? '✓' : ''}</span> Connect remote…
            </button>
          </div>
        : null}
    </div>
  );
}

/** The full-content-pane takeover while a remote link is not usable. */
/** The full-pane broker takeover: the remote-setup form (controlled),
 * the connecting spinner, or the unreachable-broker error. */
function BrokerPane({ kind }: { kind: 'setup' | 'connecting' | 'error' }): ReactNode {
  if (kind === 'setup') {
    const setup = state.remoteSetup;
    const setupInstructions =
      '# To start a remote instance, run this behind a TLS proxy or tunnel:\n'
      + 'multitool serve --listen 0.0.0.0:4780\nmultitool manage token';
    const hasSaved = state.broker.has_saved_token
      && (setup.url.trim() === '' || setup.url.trim().replace(/\/+$/, '') === (state.broker.url ?? ''));
    const insecureRemote = insecureNonLoopbackHttp(setup.url);
    return (
      <div className="broker-pane" role="form" aria-label="Connect to hosted Multitool">
        <div className="bp-icon"><Icon markup={ICONS.appIcon} /></div>
        <h2>Connect to hosted Multitool</h2>
        <p className="bp-lead">Connect to a remote Multitool server with a management token.</p>
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
          <input id="rb-url" placeholder="https://multitool.dev" value={setup.url}
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

function Icon({ markup }: { markup?: IconDefinition }): ReactNode {
  return <AppIcon icon={markup} />;
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
    : state.tab === 'secrets' ? 'Credentials'
    : state.tab === 'inbox' ? 'Request inbox'
    // The sidebar keeps the tab's title-case label; the page header speaks
    // sentence case.
    : state.tab === 'activity' ? 'Activity log'
    : tabLabel(state.tab);

  const recheckRunning = state.connections.some((c) =>
    c.mcp_path ? Boolean(state.mcpStatus[c.id]?.running) : Boolean(state.connTests[c.id]?.running));
  const pageAction = state.tab === 'connections'
    ? <div className="dw-head-actions">
        <input id="tool-search" className="cat-search" type="search" placeholder="Search tools…"
          aria-label="Search tools" value={state.toolSearch}
          onChange={(e) => { state.toolSearch = e.currentTarget.value; render(); }} />
        <button className="btn primary add-tool-btn" data-act="open-add-palette"
          aria-haspopup="dialog">
          <Icon markup={ICONS.plus} /> Add a tool
        </button>
        <button className={`btn recheck-tools-btn ${recheckRunning ? 'running' : ''}`}
          data-act="recheck-tools" disabled={recheckRunning}
          title="Recheck all tools and connections"
          aria-label="Recheck all tools and connections">
          <Icon markup={ICONS.refresh} />
        </button>
      </div>
    : state.tab === 'secrets'
      ? <div className="dw-head-actions">
          <input id="secret-search" className="cat-search" type="search" placeholder="Search credentials…"
            aria-label="Search credentials" value={state.secretSearch}
            onChange={(e) => { state.secretSearch = e.currentTarget.value; render(); }} />
          <button className="btn primary add-tool-btn" data-act="open-add-secret">
            <Icon markup={ICONS.plus} /> Add credential
          </button>
        </div>
      : state.tab === 'activity'
        ? <button className="btn" data-act="clear-activity-ask"
            disabled={!state.activity.length}>Clear activity</button>
        : null;

  return (
    <>
      <div className="surface">
        <div className="dw-titlebar" data-tauri-drag-region="">
          <span className="dw-title dw-title-center">Multitool</span>
          <BrokerSwitch />
        </div>
        <div className="dw-body">
          <div className={`dw-side ${takeover ? 'disabled' : ''}`}>
            <div className="dw-brand">
              <div className="dd-appicon"><Icon markup={ICONS.appIcon} /></div>
              <div><div className="dd-title">Multitool</div><BrokerReady /></div>
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
                    // The credentials split needs more room than the reading
                    // column; its header widens with it so search and Add
                    // stay on the pane edge.
                    <div className={`dw-head ${state.tab === 'secrets' ? 'is-wide' : ''}`}>
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
                  {state.tab === 'start' ? null : <GlobalSections />}
                  <LoadFailureBand />
                  <div className="content"><TabContent /></div>
                  {state.tab === 'secrets' ? <SecretsStatusBar /> : null}
                </>}
          </div>
        </div>
      </div>
      {!takeover && (
        <><AddToolPalette /><Sheets /><ConfirmSheet /></>
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
          <div className="dd-appicon"><Icon markup={ICONS.appIcon} /></div>
          <div className="dd-identity"><div className="dd-title">Multitool</div></div>
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
          <div className="dd-appicon"><Icon markup={ICONS.appIcon} /></div>
          <div className="dd-identity">
            <div className="dd-title">Multitool</div><BrokerReady />
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
        <div className="dropdown-content-container">
          {state.tab === 'start' ? null : <GlobalSections />}
          <LoadFailureBand />
          <div className="content dd-content"><TabContent /></div>
          {state.tab === 'secrets' ? <SecretsStatusBar /> : null}
        </div>
      </div>
      <><AddToolPalette /><Sheets /><ConfirmSheet /></>
    </>
  );
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
      <div className="tile-menu" aria-label={`Options for ${connection.name}`}>
        <ConnectionMenuItems connection={connection} />
      </div>
    </div>,
    document.body,
  );
}

/** A credential row's right-click menu, portaled and pointer-anchored like
 * the tool rows'. It carries the reveal, which has no other affordance: a
 * value only goes on screen when it is asked for by name and confirmed. */
function SecretContextMenu(): ReactNode {
  const secret = state.secretMenuPoint && state.secretMenuOpen
    ? state.secrets.find((candidate) => candidate.id === state.secretMenuOpen)
    : null;
  if (!secret) return null;
  const revealed = state.reveal[secret.id] !== undefined;
  const displayName = credentialDisplayName(secret);
  const noun = credentialNoun(secret);
  return createPortal(
    <div className="tile-menu-wrap secret-context-menu-wrap">
      <div className="tile-menu" aria-label={`Options for ${displayName}`}>
        {revealed
          ? <button className="menu-item" data-act="unreveal-secret" data-id={secret.id}>
              <Icon markup={ICONS.eyeOff} /> Unreveal {noun}
            </button>
          : <button className="menu-item" data-act="reveal-secret-ask" data-id={secret.id}>
              <Icon markup={ICONS.eye} /> Reveal {noun}…
            </button>}
      </div>
    </div>,
    document.body,
  );
}

/** The detail-pane action menu is portaled out of its scrolling card so the
 * card cannot clip it. positionConnActionMenu keeps it attached to the ⋯
 * trigger and flips it above when there is not enough viewport below. */
function ConnectionActionMenu(): ReactNode {
  const connection = !state.connMenuPoint && state.connMenuOpen
    ? state.connections.find((candidate) => candidate.id === state.connMenuOpen)
    : null;
  if (!connection) return null;
  return createPortal(
    <div className="tile-menu-wrap conn-action-menu-wrap" data-conn={connection.id}>
      <div className="tile-menu" aria-label={`Options for ${connection.name}`}>
        <ConnectionMenuItems connection={connection} />
      </div>
    </div>,
    overlays(),
  );
}

/* ---------------------------------- lock --------------------------------- */
// The lock takeover. Rendered above every other surface in both windows, so
// whatever was on screen when the lock engaged is covered rather than
// unmounted — after unlocking the user is back where they were.
//
// This is a UI gate, not storage protection: the Rust side refuses the
// credential-bearing commands while locked (see applock.rs), and the broker
// keeps serving agents throughout. The copy says so rather than implying
// everything stopped.
function LockOverlay(): ReactNode {
  const lock = state.lock;
  const inputRef = useRef<HTMLButtonElement | null>(null);
  const slotRef = useRef<HTMLDivElement | null>(null);
  const locked = lock.locked;
  const embedded = lock.embedded;
  useEffect(() => {
    if (!locked) return;
    // Take focus off whatever was behind the overlay so a stray keystroke
    // cannot reach a form under it, and give Return an obvious target.
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    inputRef.current?.focus();
  }, [locked]);
  // The inline Touch ID control is a native NSView the Rust side parents to
  // this window, not an element in this document — all the webview owns is
  // the hole it sits in. So the slot's position has to be reported up, and
  // re-reported whenever the layout moves it.
  useEffect(() => {
    if (!locked || !embedded) return undefined;
    const report = (): void => {
      const rect = slotRef.current?.getBoundingClientRect();
      if (!rect) return;
      void invoke('start_embedded_unlock', {
        slot: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
      }).catch((error) => console.error('start_embedded_unlock', error));
    };
    report();
    window.addEventListener('resize', report);
    return () => {
      window.removeEventListener('resize', report);
      // A native view outlives this component's DOM; leaving it parented
      // would float a live Touch ID control over the unlocked app.
      void invoke('stop_embedded_unlock').catch(() => { /* window may be gone */ });
    };
    // `embeddedError` is a dependency because the card is centred: adding the
    // error line grows it and shifts the slot out from under the control.
  }, [locked, embedded, lock.embeddedError]);
  if (!locked) return null;
  const prompt = lock.mechanism === 'biometry'
    ? `Touch ID or enter the password for the user “${state.localUsername || 'this account'}” to unlock.`
    : `Enter the password for the user “${state.localUsername || 'this account'}” to unlock.`;
  return (
    <div className="lock-takeover" role="dialog" aria-modal="true"
      aria-label="Multitool is locked">
      <div className="lock-card">
        <div className="lock-icon"><Icon markup={ICONS.appIcon} /></div>
        <h2 className="lock-title">Multitool Is Locked</h2>
        <p className="lock-sub">{prompt}</p>
        {embedded
          // Deliberately empty: the native control is drawn over this box, and
          // anything rendered inside it would show through around the edges if
          // the two ever disagreed about size.
          ? <div ref={slotRef} className="lock-sensor-slot" aria-hidden="true" />
          : null}
        {lock.embeddedError
          ? <p className="lock-error" role="alert">
              {lock.embeddedError}{' '}
              <button className="cd-live-link" data-act="retry-embedded-unlock">Try again</button>
            </p>
          : null}
        <button ref={inputRef} className={`btn lock-unlock ${embedded ? '' : 'primary'}`}
          data-act="unlock-app" disabled={state.unlocking}>
          {state.unlocking ? 'Waiting for authentication…'
            : embedded ? 'Enter password…' : 'Unlock'}
        </button>
        {state.unlockError
          ? <p className="lock-error" role="alert">{state.unlockError}</p>
          : null}
        <p className="lock-note">Agents keep working while the app is locked.</p>
      </div>
    </div>
  );
}

// Heartbeat for the idle timer. Throttled hard: the Rust side only compares
// it against delays measured in minutes, so one call per interaction burst
// is plenty and an unthrottled listener would be a per-keystroke IPC.
let lastActivityPing = 0;

function noteActivity(): void {
  if (!state.lock.enabled || !state.lock.autoLockSecs || state.lock.locked) return;
  const now = Date.now();
  if (now - lastActivityPing < 15000) return;
  lastActivityPing = now;
  void invoke('note_activity').catch(() => { /* the watchdog is best-effort */ });
}

async function unlockApp(): Promise<void> {
  if (state.unlocking) return;
  state.unlocking = true;
  state.unlockError = '';
  render();
  try {
    state.lock = await invoke('unlock_app');
    // A cancelled or failed sheet returns normally, still locked. Say so
    // once instead of leaving the button looking inert.
    if (state.lock.locked) state.unlockError = 'Authentication was cancelled.';
  } catch (error) {
    state.unlockError = errorMessage(error);
  } finally {
    state.unlocking = false;
    render();
  }
}

// Locking must also drop whatever the webview is holding: a revealed value
// sitting behind the overlay is exactly what the lock is supposed to stop
// someone from reading over a shoulder.
function receiveLockState(next: LockState): void {
  const wasLocked = state.lock.locked;
  state.lock = next;
  if (next.locked && !wasLocked) {
    state.reveal = {};
    state.unlockError = '';
    closeSheet();
    state.menuOpen = false;
  }
  if (!next.locked) state.unlockError = '';
  if (booted) render();
}

function AppRoot(): ReactNode {
  // Subscribes this root to store publications; the revision itself is not
  // used as a key — the windows reconcile in place rather than remounting.
  useUiRevision(uiStore);
  useBrokerQueryRevision();
  useExternalAppEvents();
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
      <div className="app-loading" role="status" aria-label="Loading Multitool">
        <span className="app-loading-spinner" />
      </div>
    );
  }
  return (
    <div className="app-event-root" style={{ display: 'contents' }}
      onClick={handleActionClick}
      onContextMenu={handleRowContextMenu}
      onDragStart={handleConnectionDragStart}
      onDragOver={handleConnectionDragOver}
      onDrop={handleConnectionDrop}
      onDragEnd={handleConnectionDragEnd}>
      <RequestLiveRegion />
      {mode === 'dropdown' ? <DropdownWindow /> : <MainWindow />}
      <ConnectionActionMenu />
      <ConnectionContextMenu />
      <SecretContextMenu />
      <LockOverlay />
    </div>
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
function EndpointIssuedSheet(): ReactNode {
  const info = state.sheet?.endpoint;
  if (!info) return null;
  const addressLabel = info.type === 'ssh' ? 'Agent socket' : info.type === 'pg' ? 'DSN' : 'Base URL';
  const field = (label: string, value: string, fieldKey: string, note = ''): ReactNode => (
    <div className="issued-ep-field">
      <div className="ep-label">{label}{note ? <> <span className="ep-note">{note}</span></> : null}</div>
      <code className="ep-code">{value}</code>
      <button className="btn ghost sm" data-act="copy-endpoint" data-field={fieldKey}
        aria-label={`Copy ${label}`}>Copy</button>
    </div>
  );
  const sheetSubtitle = info.type === 'ssh'
    ? "Paste this into your tool's config. Note: SSH addresses have no separate secret; the socket path is the whole capability. You can copy it again anytime from the tool's details."
    : "Paste this into your tool's config. You can copy it again anytime from the tool's details.";
  const remoteCaution = remoteEndpointCaution(state.broker, info.type);
  return (
    <>
      <h3 id="ep-title">Your connection address</h3>
      <p className="sheet-sub">{sheetSubtitle}</p>
      {field(addressLabel, info.dsn, 'dsn')}
      {info.secret ? field('Secret', info.secret, 'secret') : null}
      {field('Example', info.example, 'example')}
      {Number.isNaN(new Date(info.expires_at).getTime())
        ? null
        : <div className="rule-note">
            This address expires {new Date(info.expires_at).toLocaleString()}. Renewing it later
            keeps the same address and secret.
          </div>}
      {remoteCaution ? <div className="rule-note ep-remote-note">{remoteCaution}</div> : null}
      <div className="sheet-actions"><button className="btn" data-act="sheet-cancel">Done</button></div>
    </>
  );
}

// Reissue/revoke endpoint asks: a centered confirm dialog with the same
// chrome as the other confirm sheets, instead of an inline row swap.
function EndpointConfirm(): ReactNode {
  const confirm = state.confirm;
  if (!confirm || (confirm.kind !== 'reissue-endpoint' && confirm.kind !== 'revoke-endpoint')) return null;
  const conn = state.connections.find((candidate) => candidate.id === confirm.id);
  const name = conn ? conn.name : 'this tool';
  const reissue = confirm.kind === 'reissue-endpoint';
  return (
    <>
      <h3 id="ep-confirm-title">{reissue ? 'Get a new address?' : 'Revoke this address?'}</h3>
      <p>{reissue
        ? 'You’ll get a new address to paste into your tools. The current address stops working the moment the new one is issued.'
        : `Tools using ${name}’s address lose access immediately.`}</p>
      <div className="sheet-actions">
        <button className="btn" data-act="confirm-cancel">Cancel</button>
        {reissue
          ? <button className="btn primary" data-act="reissue-endpoint-confirm"
              data-conn={String(confirm.id ?? '')}>Get new address</button>
          : <button className="btn danger" data-act="revoke-endpoint-confirm"
              data-conn={String(confirm.id ?? '')}>Revoke</button>}
      </div>
    </>
  );
}

// Deleting a tool asks in the same centered dialog as the other
// destructive confirms, instead of an inline row swap.
function DeleteConnectionConfirm(): ReactNode {
  const confirm = state.confirm;
  if (!confirm || confirm.kind !== 'del-conn') return null;
  const conn = state.connections.find((candidate) => candidate.id === confirm.id);
  const name = conn ? conn.name : 'this tool';
  const enabled = Boolean(conn && conn.agent_access.enabled);
  return (
    <>
      <h3 id="del-conn-title">Delete {name}?</h3>
      <p>The connection and its settings will be removed.
        {enabled ? ' Agents will lose access immediately.' : ''}</p>
      <div className="sheet-actions">
        <button className="btn" data-act="confirm-cancel">Cancel</button>
        <button className="btn danger" data-act="del-conn-confirm" data-sheet-autofocus="true"
          data-id={String(confirm.id ?? '')}>Delete</button>
      </div>
    </>
  );
}

function DeleteOnePasswordConfirm(): ReactNode {
  const confirm = state.confirm;
  if (!confirm || confirm.kind !== 'del-onepassword') return null;
  const integration = state.onepasswordIntegrations.find((candidate) => candidate.id === confirm.id);
  const name = integration?.label ?? 'this 1Password connection';
  return <>
    <h3 id="del-onepassword-title">Remove {name}?</h3>
    <p>Multitool will remove the connected vault and credentials. No 1Password items will be changed.</p>
    <div className="sheet-actions">
      <button className="btn" data-act="confirm-cancel">Cancel</button>
      <button className="btn danger" data-act="onepassword-delete-confirm" data-sheet-autofocus="true"
        data-id={String(confirm.id ?? '')}>Remove</button>
    </div>
  </>;
}

// Unlink / delete a free credential asks in a centered dialog so the longer
// 1Password copy is not truncated inside a table row.
function DeleteSecretConfirm(): ReactNode {
  const confirm = state.confirm;
  if (!confirm || confirm.kind !== 'del-secret') return null;
  const secret = state.secrets.find((candidate) => candidate.id === confirm.id);
  const name = secret ? credentialDisplayName(secret) : 'this credential';
  const linked = secret?.source?.kind === 'one_password';
  return (
    <>
      <h3 id="del-secret-title">{linked ? `Unlink ${name}?` : `Delete ${name}?`}</h3>
      <p>{linked
        ? 'Multitool will stop using this 1Password field. The item in 1Password won’t be changed.'
        : 'This credential will be removed from the macOS Keychain.'}</p>
      <div className="sheet-actions">
        <button className="btn" data-act="confirm-cancel">Cancel</button>
        <button className="btn danger" data-act="del-secret-confirm" data-sheet-autofocus="true"
          data-id={String(confirm.id ?? '')}>{linked ? 'Unlink' : 'Delete'}</button>
      </div>
    </>
  );
}

// A reveal puts the whole credential on the screen, so it is asked for
// rather than toggled: the confirm says what will be visible and for how
// long, since the window drops the value again on its own.
function RevealSecretConfirm(): ReactNode {
  const confirm = state.confirm;
  if (!confirm || confirm.kind !== 'reveal-secret') return null;
  const secret = state.secrets.find((candidate) => candidate.id === confirm.id);
  const name = secret ? credentialDisplayName(secret) : 'this credential';
  return (
    <>
      <h3 id="reveal-secret-title">Reveal {name}?</h3>
      <p>The full value will be shown in the window — visible to anyone looking
        at your screen, and to anything recording it. It stays on screen until
        you unreveal it, leave this tab, or the window loses focus.</p>
      <div className="sheet-actions">
        <button className="btn" data-act="confirm-cancel">Cancel</button>
        <button className="btn primary" data-act="reveal-secret-confirm"
          data-id={String(confirm.id ?? '')}>Reveal</button>
      </div>
    </>
  );
}

// Editing starts with only a placeholder. Asking to expose the saved value
// deliberately takes the same confirmed, broker-audited release path as the
// credential row's Reveal action.
function RevealEditSecretConfirm(): ReactNode {
  const confirm = state.confirm;
  if (!confirm || confirm.kind !== 'reveal-edit-secret') return null;
  const secret = state.secrets.find((candidate) => candidate.id === confirm.id);
  const password = secret?.kind === 'password';
  const noun = password ? 'password' : 'secret';
  const name = secret ? credentialDisplayName(secret) : `this ${noun}`;
  return (
    <>
      <h3 id="reveal-edit-secret-title">Show {noun} for {name}?</h3>
      <p>The saved {noun} will be placed in the edit form — visible to anyone
        looking at your screen, and to anything recording it. It will be hidden
        again when you uncheck the box or the window loses focus.</p>
      <div className="sheet-actions">
        <button className="btn" data-act="confirm-cancel">Cancel</button>
        <button className="btn primary" data-act="reveal-edit-secret-confirm"
          data-id={String(confirm.id ?? '')}>Show {noun}</button>
      </div>
    </>
  );
}

// In-use credentials cannot be deleted until their tools are gone; offer a
// path to each tool’s delete confirm instead of an inline table-row swap.
function SecretInUseConfirm(): ReactNode {
  const confirm = state.confirm;
  if (!confirm || confirm.kind !== 'del-secret-inuse') return null;
  const secret = state.secrets.find((candidate) => candidate.id === confirm.id);
  const name = secret ? credentialDisplayName(secret) : 'this credential';
  const usedBy = secret?.used_by_names ?? [];
  return (
    <>
      <h3 id="del-secret-inuse-title">Can’t delete {name}</h3>
      <p>{usedBy.length
        ? `Currently used by ${usedBy.join(', ')}. Delete the tool first.`
        : 'This credential is still used by a tool. Delete the tool first.'}</p>
      <div className="sheet-actions">
        {usedBy.map((toolName) => {
          const connection = state.connections.find((candidate) => candidate.name === toolName);
          return connection
            ? <button key={connection.id} className="btn danger"
                data-act="delete-using-connection" data-id={connection.id}>
                Delete {toolName}…
              </button>
            : null;
        })}
        <button className="btn" data-act="confirm-cancel">OK</button>
      </div>
    </>
  );
}

function CloseSessionConfirm(): ReactNode {
  const confirm = state.confirm;
  if (!confirm || confirm.kind !== 'close-session') return null;
  const session = state.sessions.find((candidate) => candidate.id === confirm.id);
  const who = session
    ? (session.agent
      ? `${session.agent} → ${session.connection}`
      : session.connection)
    : 'this session';
  return (
    <>
      <h3 id="close-session-title">Close {who}?</h3>
      <p>The agent’s live connection will drop immediately.
        {session?.detail ? ` ${session.detail}` : ''}</p>
      <div className="sheet-actions">
        <button className="btn" data-act="confirm-cancel">Cancel</button>
        <button className="btn danger" data-act="close-session-confirm"
          data-id={String(confirm.id ?? '')}>Close</button>
      </div>
    </>
  );
}

function RotateKeyConfirm(): ReactNode {
  if (state.confirm?.kind !== 'rotate-key') return null;
  const subject = state.broker.mode === 'local' ? 'this computer’s' : 'the broker’s';
  return (
    <>
      <h3 id="rotate-key-title">Rotate {subject} agent key?</h3>
      <p>Every live agent session and direct endpoint stops working immediately.
        Agents that read the token file reconnect automatically; pasted addresses must be reissued.</p>
      <div className="sheet-actions">
        <button className="btn" data-act="confirm-cancel">Cancel</button>
        <button className="btn danger" data-act="rotate-key-confirm">Rotate key</button>
      </div>
    </>
  );
}

function ConfirmSheet(): ReactNode {
  const kind = state.confirm?.kind;
  if (kind === 'reissue-endpoint' || kind === 'revoke-endpoint') {
    return (
      <Sheet titleId="ep-confirm-title" className="wide confirm-sheet"
        backdropAction="confirm-cancel">
        <EndpointConfirm />
      </Sheet>
    );
  }
  if (kind === 'del-conn') {
    return (
      <Sheet titleId="del-conn-title" className="wide confirm-sheet"
        backdropAction="confirm-cancel">
        <DeleteConnectionConfirm />
      </Sheet>
    );
  }
  if (kind === 'del-onepassword') {
    return (
      <Sheet titleId="del-onepassword-title" className="wide confirm-sheet"
        backdropAction="confirm-cancel">
        <DeleteOnePasswordConfirm />
      </Sheet>
    );
  }
  if (kind === 'del-secret') {
    return (
      <Sheet titleId="del-secret-title" className="wide confirm-sheet"
        backdropAction="confirm-cancel">
        <DeleteSecretConfirm />
      </Sheet>
    );
  }
  if (kind === 'reveal-secret') {
    return (
      <Sheet titleId="reveal-secret-title" className="wide confirm-sheet"
        backdropAction="confirm-cancel">
        <RevealSecretConfirm />
      </Sheet>
    );
  }
  if (kind === 'reveal-edit-secret') {
    return (
      <Sheet titleId="reveal-edit-secret-title" className="wide confirm-sheet"
        backdropAction="confirm-cancel">
        <RevealEditSecretConfirm />
      </Sheet>
    );
  }
  if (kind === 'del-secret-inuse') {
    return (
      <Sheet titleId="del-secret-inuse-title" className="wide confirm-sheet"
        backdropAction="confirm-cancel">
        <SecretInUseConfirm />
      </Sheet>
    );
  }
  if (kind === 'close-session') {
    return (
      <Sheet titleId="close-session-title" className="wide confirm-sheet"
        backdropAction="confirm-cancel">
        <CloseSessionConfirm />
      </Sheet>
    );
  }
  if (kind === 'rotate-key') {
    return (
      <Sheet titleId="rotate-key-title" className="wide confirm-sheet"
        backdropAction="confirm-cancel">
        <RotateKeyConfirm />
      </Sheet>
    );
  }
  return null;
}

/** The open sheet: converted forms render as controlled TSX, the rest as
 * React-owned view tree. */
function Sheets(): ReactNode {
  if (!state.sheet) return null;
  switch (state.sheet.kind) {
    case 'add-secret':
      return <Sheet titleId="secret-sheet-title" className="wide"><SecretSheet editing={false} /></Sheet>;
    case 'edit-secret':
      return <Sheet titleId="secret-sheet-title" className="wide"><SecretSheet editing /></Sheet>;
    case 'onepassword':
      return <Sheet titleId="onepassword-sheet-title" className="wide onepassword-sheet">
        <OnePasswordSheet />
      </Sheet>;
    case 'add-conn':
      return <ConnectionSheets editing={false} />;
    case 'edit-conn':
      return <ConnectionSheets editing />;
    case 'wiring-tools':
      return <Sheet titleId="wt-title" className="wide"><WiringToolsSheet /></Sheet>;
    case 'settings':
      return <Sheet titleId="settings-title" className="wide">
        <SettingsSheet />
      </Sheet>;
    case 'clear-activity':
      return <Sheet titleId="clear-activity-title" className="wide confirm-sheet">
        <ClearActivitySheet />
      </Sheet>;
    case 'elicitation':
      return <Sheet titleId="elicit-title" className="elicit-sheet" role="alertdialog">
        <ElicitationSheet />
      </Sheet>;
    case 'approval':
      return <Sheet titleId="approval-title" className="elicit-sheet" role="alertdialog">
        <ApprovalSheet />
      </Sheet>;
    case 'mcp-auth':
      return <Sheet titleId="mcp-auth-title" className="wide auth-sheet">
        <McpAuthSheet />
      </Sheet>;
    case 'endpoint-issued':
      return <Sheet titleId="ep-title" className="endpoint-issued-sheet">
        <EndpointIssuedSheet />
      </Sheet>;
    default: return null;
  }
}

function ConnectionSheets({ editing }: { editing: boolean }): ReactNode {
  return (
    <>
      <Sheet titleId="conn-sheet-title" className="wide">
        <ConnSheet editing={editing} />
      </Sheet>
      {state.confirmDiscard && (
        <Sheet titleId="discard-conn-title" className="wide confirm-sheet discard-confirm"
          backdropAction="discard-keep" backdropClassName="over-sheet">
          <h3 id="discard-conn-title">{editing ? 'Discard changes?' : 'Discard this tool?'}</h3>
          <p>You have unsaved changes in this form. Closing it discards them.</p>
          <div className="sheet-actions">
            <button className="btn" data-act="discard-keep">Keep editing</button>
            <button className="btn danger" data-act="discard-confirm">Discard</button>
          </div>
        </Sheet>
      )}
    </>
  );
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
        <div className="elicit-dlg-ico"><Icon markup={ICONS.bell} /></div>
        <h3 id="elicit-title" className="elicit-dlg-title">This request is gone</h3>
        <div className="elicit-dlg-context">It was answered somewhere else or expired.</div>
        <div className="sheet-actions elicit-dlg-actions">
          <button className="btn primary" data-act="sheet-cancel">OK</button>
        </div>
      </>
    );
  }
  return (
    <>
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
              sent back to it as ordinary text, and Multitool neither masks nor stores it.
              Credentials belong in <strong>Credentials</strong>, where they stay in the Keychain and
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
    </>
  );
}

/**
 * The traffic-confirmation dialog.
 *
 * Same alert shape as the elicitation sheet, and deliberately so — but the
 * question is the opposite one. There, the upstream asks the user for
 * input; here, Multitool asks whether the traffic should happen at all, and
 * the answer is a decision about access rather than a value to forward.
 *
 * The three answers are the whole point of the switch: let this through for
 * a while, stop asking altogether, or refuse. "Stop asking" turns the
 * connection's confirmation off as part of this explicit decision.
 */
function ApprovalSheet(): ReactNode {
  const approval = state.approvals.find((a) => a.id === state.sheet?.id);
  if (!approval) {
    return (
      <>
        <div className="elicit-dlg-ico"><Icon markup={ICONS.shieldAlert} /></div>
        <h3 id="approval-title" className="elicit-dlg-title">This request is gone</h3>
        <div className="elicit-dlg-context">
          It was answered elsewhere, or nobody answered in time and the call was refused.
        </div>
        <div className="sheet-actions elicit-dlg-actions">
          <button className="btn primary" data-act="sheet-cancel">OK</button>
        </div>
      </>
    );
  }
  const minutes = Math.max(1, Math.round(approval.window_secs / 60));
  const answering = state.approvalAnswering !== null;
  const hostKeyDecision = approval.unit === 'host_key'
    && Boolean(approval.host_key_fingerprint);
  const credentialNames = approval.credential_names ?? [];
  const provenance = state.approvalHostKeyProvenance?.approvalId === approval.id
    ? state.approvalHostKeyProvenance
    : null;
  const matchingKnownHost = provenance?.candidates.find(
    (candidate) => candidate.fingerprint === approval.host_key_fingerprint,
  );
  const revokedKnownHost = Boolean(
    approval.host_key_fingerprint
      && provenance?.revokedFingerprints.includes(approval.host_key_fingerprint),
  );
  const hostKeyProvenance = hostKeyDecision
    ? !provenance
      ? 'This computer’s known_hosts comparison is unavailable. '
        + 'Verify the fingerprint through another trusted channel before pinning it.'
      : provenance.loading
      ? 'Checking this computer’s known_hosts…'
      : provenance.error
        ? `Could not check this computer’s known_hosts: ${provenance.error}`
        : revokedKnownHost
          ? 'Warning: this computer’s known_hosts marks this exact key as revoked. Do not trust it.'
          : matchingKnownHost
            ? `Matches ${matchingKnownHost.algorithm} in ${matchingKnownHost.source}.`
          : provenance.candidates.length
            ? `Warning: this fingerprint does not match the ${provenance.candidates.length} `
              + `key${provenance.candidates.length === 1 ? '' : 's'} in this computer’s known_hosts.`
            : provenance.hasCertificateAuthority
              ? 'This computer’s known_hosts trusts a certificate authority for this destination, '
                + 'but Multitool cannot verify this concrete key through that CA. '
                + 'Verify it through another trusted channel before pinning it.'
            : 'No key for this destination was found in this computer’s known_hosts. '
              + 'Verify the fingerprint through another trusted channel before pinning it.'
    : null;
  return (
    <>
      <div className="elicit-dlg-ico"><Icon markup={ICONS.shieldAlert} /></div>
      <h3 id="approval-title" className="elicit-dlg-title untrusted-identity" dir="auto">
        {agentLabel(approval.agent)} {approvalUnit(approval)}
      </h3>
      <div className="elicit-dlg-context untrusted-identity" dir="auto">
        {approval.connection} · {approval.target}
      </div>
      <dl className="approval-facts">
        <div>
          <dt>{credentialNames.length === 1 ? 'Credential' : 'Credentials'}</dt>
          <dd className="untrusted-identity" dir="auto">
            {credentialNames.length ? credentialNames.join(', ') : 'None'}
          </dd>
        </div>
        {approval.method
          ? <div><dt>Method</dt><dd><code>{approval.method}</code></dd></div>
          : null}
        {approval.path
          ? <div><dt>Path</dt><dd><code className="untrusted-identity" dir="auto">
              {approval.path}
            </code></dd></div>
          : null}
        {approval.host_key_fingerprint
          ? <div><dt>Host key</dt><dd><code>{approval.host_key_fingerprint}</code></dd></div>
          : null}
      </dl>
      {hostKeyProvenance
        ? <div className={matchingKnownHost && !revokedKnownHost
            ? 'rule-note'
            : 'approval-consequence'}
            role="status">{hostKeyProvenance}</div>
        : null}
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
        {!hostKeyDecision
          ? <button className="btn" data-act="approval-approve-all"
              data-id={approval.id} disabled={answering}
              title="Allow this call and turn traffic confirmation off for this tool">Stop asking</button>
          : null}
        <button className="btn primary" data-act="approval-approve-window"
          data-id={approval.id} disabled={answering}>
          {answering ? 'Answering…' : hostKeyDecision ? 'Trust and pin' : `Approve ${minutes}m`}
        </button>
      </div>
    </>
  );
}

/**
 * Per-wiring tool picker: which of an MCP server's tools one agent may
 * call. "All tools" is the default and the reset; a curated subset is
 * enforced broker-side on every tools/call, and the MCP host lists only
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
      <h3 id="wt-title">Tools agents may call on {wt.connectionName}</h3>
      <p className="wt-sub">Agents can call {count} on this server. Everything
        unchecked is refused by the broker and hidden from the agent's tool list.</p>
      {body}
      <div className="sheet-actions">
        <button className="btn" data-act="sheet-cancel">Cancel</button>
        <button className="btn primary" data-act="wt-save" disabled={wt.loading || wt.saving}>
          {wt.saving ? 'Saving…' : 'Save'}</button>
      </div>
    </>
  );
}

function ClearActivitySheet(): ReactNode {
  return (
    <>
      <h3 id="clear-activity-title">Clear activity?</h3>
      <p>This permanently removes all activity history from this device.</p>
      <div className="sheet-actions">
        <button className="btn" data-act="sheet-cancel">Cancel</button>
        <button className="btn danger" data-act="clear-activity-confirm">Clear activity</button>
      </div>
    </>
  );
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

/** Which shape the credential sheet is showing. Editing locks the type to
 * the record's; adding follows the segment (secret unless preselected). */
function sheetSecretKind(editing: boolean, secret: SecretSummary | null): SecretKind {
  if (editing) {
    if (secret) return secret.kind === 'password' ? 'password' : 'secret';
    return state.draft.secretKind === 'password' ? 'password' : 'secret';
  }
  return supportsTypedCredentials(state.broker) && state.draft.secretKind === 'password'
    ? 'password'
    : 'secret';
}

function SecretSheet({ editing }: { editing: boolean }): ReactNode {
  const d = state.draft;
  const secret = editing
    ? state.secrets.find((candidate) => candidate.id === state.sheet?.id) ?? null
    : null;
  const linked = secret?.source?.kind === 'one_password' ? secret.source : null;
  const password = sheetSecretKind(editing, secret) === 'password';
  const storedSite = password ? normalizedSitePreview(d.site ?? '') : null;
  const title = linked ? 'Edit linked credential'
    : editing ? (password ? 'Edit password' : 'Edit secret')
    : supportsTypedCredentials(state.broker) ? 'Add credential' : 'Add secret';
  const showValue = Boolean(d.showCredentialValue);
  const generationFormat = d.passwordGenerationFormat ?? 'strong';
  const generatorMenuOpen = state.formMenuOpen === 'password-generator-menu';
  const toggleValueVisibility = (checked: boolean) => {
    if (!checked) {
      state.draft.showCredentialValue = false;
      // A revealed stored value is presentation-only. Scrub it when hidden;
      // user-entered replacement text remains available behind the mask.
      if (editing && !state.draft.secretValueModified) state.draft.value = '';
      render();
      return;
    }
    if (editing && !state.draft.secretValueModified) {
      state.confirm = { kind: 'reveal-edit-secret', id: state.sheet?.id };
      render();
      return;
    }
    state.draft.showCredentialValue = true;
    render();
  };
  // The value field's write-only machinery (placeholder on edit, modified
  // flag) is shared by both shapes; only its labels change.
  const valueField = (label: string, placeholder: string) => (
    <input id="f-value" className={fieldCls('value')} type={showValue ? 'text' : 'password'}
      placeholder={placeholder}
      value={d.value ?? ''}
      onChange={(e) => {
        if (editing) state.draft.secretValueModified = true;
        setDraftField('value', 'value', e.currentTarget.value);
      }} aria-label={label} />
  );
  const visibilityControl = (
    <label className="show-value-check">
      <input type="checkbox" checked={showValue}
        onChange={(e) => toggleValueVisibility(e.currentTarget.checked)} />
      <span>{password ? 'Show password' : 'Show secret'}</span>
    </label>
  );
  return (
    <>
      <h3 id="secret-sheet-title">{title}</h3>
      {!editing && supportsTypedCredentials(state.broker)
        ? <div className="seg in-form secret-kind-seg" role="radiogroup" aria-label="Credential type">
            <button className={`seg-btn ${password ? 'on' : ''}`} role="radio"
              aria-checked={password} data-act="secret-kind" data-kind="password">Password</button>
            <button className={`seg-btn ${!password ? 'on' : ''}`} role="radio"
              aria-checked={!password} data-act="secret-kind" data-kind="secret">Secret</button>
          </div>
        : null}
      {password
        ? <>
            <div className="f-row">
              <label htmlFor="f-site">Website</label>
              <input id="f-site" className={fieldCls('site')} placeholder="e.g. github.com"
                autoComplete="off" spellCheck={false}
                value={d.site ?? ''}
                onChange={(e) => setDraftField('site', 'site', e.currentTarget.value)} />
              <FieldError k="site" />
              {storedSite ? <div className="field-hint">Stored as {storedSite}</div> : null}
            </div>
            <div className="f-row">
              <label htmlFor="f-username">Username</label>
              <input id="f-username" placeholder="you@example.com"
                autoComplete="off" spellCheck={false} dir="auto"
                value={d.username ?? ''}
                onChange={(e) => setDraftField('username', 'username', e.currentTarget.value)} />
            </div>
            <div className="f-row">
              <label htmlFor="f-value">{editing ? 'New password (saved to macOS Keychain)' : 'Password'}</label>
              <div className="gen-row">
                {valueField('Password', editing ? EDIT_SECRET_MASK : 'Saved in Keychain')}
                <div className="password-generator cred-select">
                  <div className="password-generator-group">
                    <button type="button" className="btn password-generator-main"
                      data-act="generate-password" title="Fill in a generated password">Generate</button>
                    <button type="button" id="password-generator-menu"
                      className="btn password-generator-menu-trigger"
                      data-act="generate-password-menu" title="Password format"
                      aria-label="Choose password format" aria-haspopup="listbox"
                      aria-expanded={generatorMenuOpen}>
                      <Icon markup={ICONS.chevronDown} />
                    </button>
                  </div>
                  {generatorMenuOpen
                    ? createPortal(
                        <div className="cred-menu password-format-menu" role="listbox"
                          aria-label="Password format">
                          {PASSWORD_GENERATION_FORMATS.map((format) => (
                            <button type="button" className="cred-opt" role="option"
                              aria-selected={generationFormat === format.id}
                              data-act="password-format" data-id={format.id} key={format.id}>
                              <span className="cred-opt-col"><span className="cred-name">
                                {format.label}
                              </span></span>
                              {generationFormat === format.id
                                ? <span className="cred-opt-check"><Icon markup={ICONS.check} /></span>
                                : null}
                            </button>
                          ))}
                        </div>,
                        overlays(),
                      )
                    : null}
                </div>
              </div>
              <FieldError k="value" />
              {visibilityControl}
            </div>
            <div className="adv-collapse credential-advanced">
              <button type="button" className="adv-toggle" data-act="credential-advanced"
                aria-expanded={Boolean(d.credentialAdvancedOpen)}>
                <span className="adv-toggle-icon" aria-hidden="true">
                  <Icon markup={ICONS.chevronDown} />
                </span>Advanced</button>
              {d.credentialAdvancedOpen
                ? <div className="f-row">
                    <label htmlFor="f-totp">2FA secret <span className="label-note">optional</span></label>
                    <input id="f-totp" className={fieldCls('totp')} type="password"
                      placeholder={secret?.totp
                        ? '•••••••• (set) — paste to replace'
                        : 'Base32 secret or otpauth:// URI'}
                      autoComplete="off" spellCheck={false}
                      value={d.totp ?? ''}
                      onChange={(e) => {
                        state.draft.removeTotp = false;
                        setDraftField('totp', 'totp', e.currentTarget.value);
                      }} />
                    <FieldError k="totp" />
                    {secret?.totp
                      ? <label className="totp-remove-check">
                          <input type="checkbox" checked={Boolean(d.removeTotp)}
                            onChange={(e) => {
                              state.draft.removeTotp = e.currentTarget.checked;
                              if (e.currentTarget.checked) state.draft.totp = '';
                              delete state.sheetErrors.totp;
                              render();
                            }} />
                          <span>Remove 2FA secret</span>
                        </label>
                      : null}
                  </div>
                : null}
            </div>
          </>
        : <>
            <div className="f-row">
              <label htmlFor="f-name">Name</label>
              <input id="f-name" className={fieldCls('name')} placeholder="e.g. STRIPE_API_KEY"
                value={d.name ?? ''}
                onChange={(e) => setDraftField('name', 'name', e.currentTarget.value)} />
              <FieldError k="name" />
            </div>
            {linked ? <div className="linked-secret-source">
              <span><Icon markup={ICONS.onepassword} /></span>
              <div><b>{linked.integration_label}</b>
                <small>{linked.vault_label} › {linked.item_label} › {linked.field_label}</small></div>
            </div> : <div className="f-row">
              <label htmlFor="f-value">{editing ? 'New value (saved to macOS Keychain)' : 'Value'}</label>
              {valueField('Value', editing ? EDIT_SECRET_MASK : 'Your secret (saved in Keychain)')}
              <FieldError k="value" />
              {visibilityControl}
            </div>}
          </>}
      <FormGlobalError />
      <div className="sheet-actions">
        <button className="btn" data-act="sheet-cancel">Cancel</button>
        <button className="btn primary" data-act="save-secret">Save</button>
      </div>
    </>
  );
}

// Sentinel option value in the saved-credential select that switches the
// chooser into "create a new credential" mode.
const NEW_CREDENTIAL_OPTION = '__new__';
const NO_CREDENTIAL_OPTION = '__none__';

/** The credential source to assume when the draft has not chosen one yet.
 *  Branded API presets exist to inject a key, so they start at "new";
 *  manual-token MCP does likewise, while credential-optional infrastructure
 *  and MCP OAuth stay at "none". */
function defaultSecretSource(
  type: ConnectionType,
  draft: ConnectionDraft,
): 'existing' | 'new' | 'none' {
  return initialSecretSource({
    type,
    explicit: draft.secretSource,
    imported: Boolean(draft.importedCredential || draft.sshImportId),
    mcp: isMcpDraft(draft),
    authMode: draft.authMode,
    brandedApi: Boolean(state.connPreset),
  });
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
  const allowNone = type === 'pg' || type === 'ssh' || type === 'api';
  const source = defaultSecretSource(type, draft);
  const secretLabel = type === 'pg' ? 'Database password'
    : type === 'ssh' ? 'SSH private key'
    : 'Token or API key';
  const keyBadge = <span className="cred-badge" aria-hidden="true"><Icon markup={ICONS.key} /></span>;
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
          Used once, to unlock the key. Multitool stores the unlocked key in the
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
  if (t === 'api' && ((d.clientCertPath || '').trim() || (d.clientKeyPath || '').trim())) {
    return true;
  }
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
  const renameOnlyOAuth = Boolean(editPresentation?.renameOnlyOAuth);
  let draftTarget = null;
  if (editing && conn) {
    if (t === 'pg' || t === 'ssh') {
      draftTarget = {
        type: t,
        host: (d.host || '').trim(),
        port: Number((d.port || '').trim() || (t === 'ssh' ? 22 : 5432)),
        user: (d.user || '').trim() || state.localUsername.trim(),
        dbname: t === 'pg' ? (d.dbname || '').trim() : null,
        destination: t === 'ssh' ? (d.destination || '').trim() || null : null,
        hostKeyFingerprint: t === 'ssh'
          ? (d.hostKeyFingerprint || '').trim()
          : null,
      };
    } else if (t === 'api') {
      try {
        const parsed = isMcpDraft(d)
          ? parseMcpServerUrl(d.origin || '')
          : { ...parseApiOrigin(d.origin || ''), mcpPath: null };
        draftTarget = {
          type: t,
          scheme: parsed.scheme,
          host: parsed.host,
          port: parsed.port,
          mcpPath: parsed.mcpPath,
        };
      } catch {
        // Validation owns the malformed URL; do not add a misleading
        // endpoint warning until the draft names a real target.
      }
    }
  }
  const endpointWillBeRevoked = Boolean(
    conn?.agent_access.endpoint && retargetsIssuedEndpoint({
      type: conn.type,
      scheme: conn.scheme,
      host: conn.host,
      port: conn.port,
      dbname: conn.dbname,
      user: conn.user,
      destination: conn.destination,
      mcpPath: conn.mcp_path,
      hostKeyFingerprint: conn.host_key_fingerprint,
    }, draftTarget),
  );
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
          value={url} readOnly={renameOnlyOAuth}
          aria-readonly={renameOnlyOAuth ? 'true' : undefined}
          onChange={(e) => setDraftField('origin', 'origin', e.currentTarget.value)} />
        <FieldError k="origin" />
        {renameOnlyOAuth
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
          value={origin} readOnly={renameOnlyOAuth}
          aria-readonly={renameOnlyOAuth ? 'true' : undefined}
          onChange={(e) => setDraftField('origin', 'origin', e.currentTarget.value)} />
        <FieldError k="origin" />
        {renameOnlyOAuth
          ? <div className="rule-note">This OAuth connection can only be renamed. Reconnect it to change its API root or authentication.</div>
          : null}
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
      // Naming the jump host without saying what it means read as ordinary
      // imported detail, so the limitation was met later as a connection
      // failure. A tool pins one host key, and the jump hop is a second SSH
      // login against a second one — so it cannot be brokered in one tool.
      d.proxyJump
        ? <div className="rule-note warn" key="proxyjump">
            Connects through ProxyJump <b>{d.proxyJump}</b>, which Multitool
            cannot broker in one tool: the jump hop is a separate SSH login
            against its own host key. Add <b>{d.proxyJump}</b> as its own tool
            and connect in two hops.
          </div>
        : null,
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
  if (t === 'api' && !renameOnlyOAuth) {
    apiTlsFields = (
      <>
        <div className="f-row" key="api-ca-bundle">
          <label htmlFor="f-api-ca-bundle">Trusted CA bundle <span className="label-detail">(optional)</span></label>
          <input id="f-api-ca-bundle" placeholder="/path/to/private-ca.pem"
            value={d.pgCaBundlePath ?? ''}
            onChange={(e) => setDraftField('pgCaBundlePath', 'pgCaBundlePath', e.currentTarget.value)} />
          <div className="rule-note">Replaces public certificate authorities for this API connection.</div>
        </div>
        <div className="f-row" key="api-test-path">
          <label htmlFor="f-api-test-path">Test path <span className="label-detail">(optional)</span></label>
          <input id="f-api-test-path" className={fieldCls('testPath')} placeholder="/user"
            value={d.testPath ?? ''}
            onChange={(e) => setDraftField('testPath', 'testPath', e.currentTarget.value)} />
          <FieldError k="testPath" />
          <div className="rule-note">
            What Test fetches. Left blank it fetches the origin root, which
            most APIs answer without ever checking the credential.
          </div>
        </div>
        <div className="f-row" key="api-client-cert">
          <label htmlFor="f-api-client-cert">Client certificate <span className="label-detail">(optional)</span></label>
          <input id="f-api-client-cert" className={fieldCls('clientCertPath')} placeholder="/path/to/client.pem"
            value={d.clientCertPath ?? ''}
            onChange={(e) => setDraftField('clientCertPath', 'clientCertPath', e.currentTarget.value)} />
          <FieldError k="clientCertPath" />
        </div>
        <div className="f-row" key="api-client-key">
          <label htmlFor="f-api-client-key">Client certificate key</label>
          <input id="f-api-client-key" className={fieldCls('clientKeyPath')} placeholder="/path/to/client-key.pem"
            value={d.clientKeyPath ?? ''}
            onChange={(e) => setDraftField('clientKeyPath', 'clientKeyPath', e.currentTarget.value)} />
          <FieldError k="clientKeyPath" />
          <div className="rule-note">
            Presented to the upstream on the TLS handshake (mTLS). Configure
            the certificate and its key together.
          </div>
        </div>
      </>
    );
  }
  const templateField = (placeholder?: string, note?: ReactNode): ReactNode => (
    <div className="f-row">
      <label htmlFor="c-template">Credential template</label>
      <input id="c-template" className={fieldCls('template')} placeholder={placeholder}
        value={d.template ?? ''}
        onChange={(e) => {
          if (editing && t === 'api') d.apiCredentialTemplate = e.currentTarget.value;
          setDraftField('template', 'template', e.currentTarget.value);
        }} />
      <FieldError k="template" />
      {note}
    </div>
  );
  // OAuth authentication belongs to the sign-in flow. Keep its generated
  // secret name and injection template out of the ordinary editor: reconnect
  // is the only supported way to replace that grant.
  if (renameOnlyOAuth) {
    fields.push(
      <div className="f-row" key="auth">
        <label>Authentication</label>
        <input value={managedMcpOAuth ? 'OAuth (managed by Multitool)' : 'OAuth (your app)'}
          readOnly aria-readonly="true" />
        <div className="rule-note">
          {conn?.account ? `Connected account: ${conn.account}. ` : ''}
          Tokens are stored securely and refreshed automatically. Reconnect to
          replace this grant; OAuth tools can otherwise only be renamed.
        </div>
      </div>,
    );
  // A single saved reference maps cleanly to the ordinary chooser. Composed
  // templates remain custom authentication because one picker cannot express
  // several independently bound credentials.
  } else if (editing && t === 'api' && conn?.signer) {
    // A signed connection has no injected credential to choose or template
    // to edit. Show the signer; an edit that keeps the pinned target keeps
    // it (the backend re-attaches an omitted signer), while retargeting
    // drops it and the connection must be re-created.
    const signer = conn.signer;
    const gcp = signer.algorithm === 'gcp_service_account';
    fields.push(
      <div className="f-row" key="auth">
        <label>Authentication</label>
        <input value={gcp
          ? `GCP service account (${signer.scope ?? ''})`
          : `AWS SigV4 (${signer.region} · ${signer.service})`}
          readOnly aria-readonly="true" />
        <div className="rule-note">
          {gcp
            ? `Mints short-lived tokens from ${signer.key_ref ?? 'the service-account key'}.`
            : `Signs each request with ${signer.access_key_ref} / ${signer.secret_key_ref}`
              + (signer.session_token_ref ? ` and session token ${signer.session_token_ref}` : '')
              + '.'}
          {' '}Changing the pinned host drops the signer.
        </div>
      </div>,
    );
  } else if (editing && t === 'api') {
    const credentialNames = conn?.secret_names ?? [];
    if (credentialNames.length <= 1) {
      fields.push(
        <CredentialChooser type={t} allowNew={false} key="chooser" />,
      );
    } else {
      fields.push(
        <div className="f-row" key="auth">
          <label>Authentication</label>
          <input value="Custom authentication" readOnly aria-readonly="true" />
          <div className="rule-note">
            Uses {credentialNames.join(', ')}. Edit the composed references below.
          </div>
        </div>,
      );
    }
    fields.push(
      <details className="set-collapse" open={Boolean(state.sheetErrors.template)} key="auth-template">
        <summary>Custom authentication</summary>
        <div className="set-panel">
          {templateField(undefined,
            <div className="rule-note">
              References saved credentials by name using <code>{'{{ … }}'}</code>.
              Choosing another credential above preserves this header or query shape.
            </div>)}
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
      // Dispatch-time request signing: no injected credential at all — the
      // broker signs each request with vault-referenced keys (AWS APIs) or
      // mints short-lived tokens from a service-account key (GCP APIs).
      ...(!mcpAdd ? [
        ['sigv4', 'AWS SigV4 request signing'] as [string, string],
        ['gcp', 'GCP service account signing'] as [string, string],
      ] : []),
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
    if (modeValue === 'sigv4') {
      const refSelect = (
        id: string,
        label: ReactNode,
        errKey: string,
        value: string | null | undefined,
        optional: boolean,
      ): ReactNode => (
        <div className="f-row" key={id}>
          <label htmlFor={id}>{label}</label>
          <CustomSelect id={id} errCls={fieldCls(errKey)}
            options={[
              ['', optional ? 'None' : 'Select a credential…'],
              ...state.secrets.map((secret) => [secret.name, secret.name] as [string, string]),
            ]}
            selectedValue={value ?? ''} />
          <FieldError k={errKey} />
        </div>
      );
      fields.push(
        <div className="rule-note" key="sigv4-note">
          The broker signs each request with these keys at dispatch time; no
          credential is ever injected into the request itself. Save the access
          key ID and secret access key under Credentials first.
        </div>,
        <div className="f-row" key="sigv4-region">
          <label htmlFor="c-signer-region">Region</label>
          <input id="c-signer-region" className={fieldCls('signerRegion')} placeholder="us-east-1"
            value={d.signerRegion ?? ''}
            onChange={(e) => setDraftField('signerRegion', 'signerRegion', e.currentTarget.value)} />
          <FieldError k="signerRegion" />
        </div>,
        <div className="f-row" key="sigv4-service">
          <label htmlFor="c-signer-service">Service</label>
          <input id="c-signer-service" className={fieldCls('signerService')} placeholder="s3"
            value={d.signerService ?? ''}
            onChange={(e) => setDraftField('signerService', 'signerService', e.currentTarget.value)} />
          <FieldError k="signerService" />
        </div>,
        refSelect('c-signer-access', 'Access key ID credential', 'signerAccessKeyRef',
          d.signerAccessKeyRef, false),
        refSelect('c-signer-secret', 'Secret access key credential', 'signerSecretKeyRef',
          d.signerSecretKeyRef, false),
        refSelect('c-signer-token',
          <>Session token credential <span className="label-detail">(optional)</span></>,
          'signerSessionTokenRef', d.signerSessionTokenRef, true),
      );
    } else if (modeValue === 'gcp') {
      fields.push(
        <div className="rule-note" key="gcp-note">
          The broker mints short-lived access tokens from a service-account
          key at request time; no long-lived credential is ever injected.
          Save the service account&rsquo;s JSON key file under Credentials first.
        </div>,
        <div className="f-row" key="gcp-key">
          <label htmlFor="c-signer-gcp-key">Service-account key credential</label>
          <CustomSelect id="c-signer-gcp-key" errCls={fieldCls('signerGcpKeyRef')}
            options={[
              ['', 'Select a credential…'],
              ...state.secrets.map((secret) => [secret.name, secret.name] as [string, string]),
            ]}
            selectedValue={d.signerGcpKeyRef ?? ''} />
          <FieldError k="signerGcpKeyRef" />
        </div>,
        <div className="f-row" key="gcp-scope">
          <label htmlFor="c-signer-gcp-scope">OAuth scope</label>
          <input id="c-signer-gcp-scope" className={fieldCls('signerGcpScope')}
            placeholder="https://www.googleapis.com/auth/devstorage.read_only"
            value={d.signerGcpScope ?? ''}
            onChange={(e) => setDraftField('signerGcpScope', 'signerGcpScope', e.currentTarget.value)} />
          <FieldError k="signerGcpScope" />
          <div className="rule-note">
            Space-separated scopes. Prefer the narrowest scope the agent
            needs — a read-only scope is a real guardrail.
          </div>
        </div>,
      );
    } else if (modeValue === 'advanced') {
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
    const advancedError = [
      'hostKeyFingerprint', 'pgCaBundlePath', 'testPath',
      'clientCertPath', 'clientKeyPath',
    ].some((key) => state.sheetErrors[key]);
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
      <h3 id="conn-sheet-title">{title}</h3>
      {fields}
      {endpointWillBeRevoked
        ? <div className="pair-identity-warning retarget-warning" role="status">
            <b>Saving will revoke this tool’s direct endpoint.</b><br />
            <span>Its current address grants access only to the existing target.
              Issue a new address after saving.</span>
          </div>
        : null}
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
                    aria-expanded={menuOpen}
                    data-act="toggle-conn-menu" data-id={`sheet:${conn.id}`}>
                    <Icon markup={ICONS.ellipsis} /></button>
                  {menuOpen && createPortal(
                    <div className="anchored-menu-portal sheet-conn-menu-wrap">
                      <div className="tile-menu" aria-label={`More options for ${conn.name}`}>
                        <button className="menu-item"
                          data-act={conn.mcp_path ? 'reconnect-mcp' : 'oauth-reconnect'}
                          data-id={conn.id}>
                          <Icon markup={ICONS.refresh} /> Reconnect (sign in again)</button>
                      </div>
                    </div>,
                    overlays(),
                  )}
                </div>
              : null}
          </>
        )}
        <button className="btn" data-act="sheet-cancel">Cancel</button>
        <button className="btn primary" data-act="save-conn" disabled={dt?.running}>
          {editing ? 'Save' : oauthSelected ? 'Sign in & connect' : `Add ${label}`}</button>
      </div>
    </>
  );
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
function McpAuthSheet(): ReactNode {
  const auth = state.mcpAuth;
  if (!auth) return null;
  const stepIndex = AUTH_STEPS.findIndex(([phase]) => phase === auth.phase);
  const succeeded = auth.phase === 'succeeded';
  const steps = AUTH_STEPS.map(([, label], index) => {
    const done = succeeded || stepIndex > index;
    const current = !isTerminalAuth(auth) && stepIndex === index;
    return (
      <li key={label} className={`auth-step ${done ? 'done' : ''} ${current ? 'current' : ''}`}>
        <span className="auth-step-mark" aria-hidden="true">
          {done ? <Icon markup={ICONS.check} /> : current ? <span className="auth-spinner" /> : null}
        </span>
        <span>{label}</span>
      </li>
    );
  });

  let body: ReactNode = null;
  let actions: ReactNode = <button className="btn" data-act="mcp-auth-cancel">Cancel</button>;
  if (auth.phase === 'awaiting_authorization') {
    body = <>
      <div className="auth-note">Your browser should have opened. Approve the request there,
        then come back — this dialog follows along by itself.</div>
      <div className="auth-url"><code title={auth.authorization_url}>{auth.authorization_url}</code></div>
    </>;
    actions = <>
      <button className="btn" data-act="mcp-auth-cancel">Cancel</button>
      <button className="btn primary" data-act="mcp-open-browser"
        data-url={auth.authorization_url}>Open browser again</button>
    </>;
  } else if (auth.phase === 'succeeded') {
    body = <div className="auth-done"><Icon markup={ICONS.circleCheck} />
      <div><b>{auth.connection_name} is connected{auth.account ? ` as ${auth.account}` : ''}.</b>
        {auth.warning
          ? <div className="auth-warning">Token saved, but verification did not complete: {sentenceCase(auth.warning)}</div>
          : <div className="auth-sub">Use the status button on the tool any time to re-check the server and account.</div>}
      </div>
    </div>;
    actions = <button className="btn primary" data-act="mcp-auth-done">Done</button>;
  } else if (auth.phase === 'failed') {
    body = <div className="auth-failed"><Icon markup={ICONS.circleX} />
      <div><b>{cap(auth.message)}</b>
        {auth.hint ? <div className="auth-sub">{auth.hint}</div> : null}</div>
    </div>;
    actions = <>
      <button className="btn" data-act="mcp-open-browser" data-url={auth.target}>Open in browser</button>
      {state.mcpAuthDraft && !state.mcpAuthDraft.reauth_connection_id
        ? <button className="btn" data-act="mcp-auth-token">Use a token instead</button>
        : <button className="btn" data-act="sheet-cancel">Close</button>}
      {state.mcpAuthDraft
        ? <button className="btn primary" data-act="mcp-auth-retry">Try again</button>
        : null}
    </>;
  } else if (auth.phase === 'cancelled') {
    body = <div className="auth-note">Sign-in cancelled. Nothing was saved.</div>;
    actions = <>
      <button className="btn" data-act="sheet-cancel">Close</button>
      {state.mcpAuthDraft
        ? <button className="btn primary" data-act="mcp-auth-retry">Try again</button>
        : null}
    </>;
  }
  return (
    <>
      <h3 id="mcp-auth-title">Connect {auth.name}</h3>
      <div className="auth-target"><code>{auth.target}</code></div>
      <ol className="auth-steps">{steps}</ol>
      {body}
      <div className="sheet-actions">{actions}</div>
    </>
  );
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

function SettingsSheet(): ReactNode {
  const s = state.settings;
  const notifications = state.notificationSettings;
  const notificationModeBtn = (
    value: NotificationSettings['mode'],
    label: string,
  ): ReactNode => (
    <button className={`seg-btn ${notifications.mode === value ? 'on' : ''}`}
      data-act="set-notification-mode" data-id={value} role="radio"
      aria-checked={notifications.mode === value}>{label}</button>
  );
  const notificationRow = <div className="set-row notification-setting"><div className="set-txt">
      <div className="st-title">Request notifications</div>
      <div className="st-sub">Native notifications are delivered by this computer and never include request details. Window only still brings the Inbox forward.</div></div>
      <div className="seg in-form notification-modes" role="radiogroup" aria-label="Request notifications">
        {notificationModeBtn('off', 'Window only')}
        {notificationModeBtn('when_hidden', 'When away')}
        {notificationModeBtn('always', 'Always')}
      </div></div>;
  const notificationWarning = notifications.available ? null
    : <div className="notification-warning" role="status">
      <b>Native notifications are unavailable.</b>
      <span>{notifications.unavailableReason || 'Use the Request Inbox for waiting requests.'}</span>
      {notifications.canRequestPermission
        ? <button className="cd-live-link" data-act="request-notification-permission">Enable notifications</button>
        : notifications.canOpenSystemSettings
        ? <button className="cd-live-link" data-act="open-notification-settings">Open notification settings</button>
        : null}
    </div>;
  const notificationPreviewRow = notifications.mode === 'off' ? null
    : <div className="set-row"><div className="set-txt"><div className="st-title">Show agent and tool names</div>
      <div className="st-sub">Include only those names in notifications. Targets, summaries, and arguments always stay in the Inbox.</div></div>
      <button className={`switch ${notifications.showContext ? 'on' : ''}`}
        data-act="toggle-notification-context" role="checkbox"
        aria-label="Show agent and tool names in notifications"
        aria-checked={notifications.showContext}></button></div>;
  const notificationSoundRow = notifications.mode === 'off' ? null
    : <div className="set-row"><div className="set-txt"><div className="st-title">Play a sound</div>
      <div className="st-sub">Use this computer’s default notification sound for new and expired requests.</div></div>
      <button className={`switch ${notifications.playSound ? 'on' : ''}`}
        data-act="toggle-notification-sound" role="checkbox"
        aria-label="Play a request notification sound"
        aria-checked={notifications.playSound}></button></div>;
  const notificationFocusRow = notifications.mode === 'off' ? null
    : <div className="set-row"><div className="set-txt"><div className="st-title">Time-sensitive delivery</div>
      <div className="st-sub">Ask the operating system to deliver through Focus or Do Not Disturb where supported. Your system settings remain in control.</div></div>
      <button className={`switch ${notifications.timeSensitive ? 'on' : ''}`}
        data-act="toggle-notification-time-sensitive" role="checkbox"
        aria-label="Use time-sensitive request notifications"
        aria-checked={notifications.timeSensitive}></button></div>;
  const escalationBtn = (secs: NotificationSettings['escalationSecs'], label: string): ReactNode => (
    <button className={`seg-btn ${notifications.escalationSecs === secs ? 'on' : ''}`}
      data-act="set-notification-escalation" data-id={secs} role="radio"
      aria-checked={notifications.escalationSecs === secs}>{label}</button>
  );
  const notificationEscalationRow = notifications.mode === 'off' ? null
    : <div className="set-row"><div className="set-txt"><div className="st-title">Re-alert before the deadline</div>
      <div className="st-sub">Bring the Inbox forward only while the same request is still waiting. The final in-app fallback remains on when re-alerting is off.</div></div>
      <div className="seg in-form" role="radiogroup" aria-label="Re-alert before a waiting request expires">
        {escalationBtn(0, 'Off')}{escalationBtn(15, '15 sec')}
        {escalationBtn(30, '30 sec')}{escalationBtn(60, '1 min')}
      </div></div>;
  const lock = state.lock;
  // The lock is this computer's, like the notification rows: it gates these
  // windows, not the broker they are driving.
  const lockRow = <div className="set-row"><div className="set-txt">
      <div className="st-title">Lock this window</div>
      <div className="st-sub">
        Require Touch ID or your account password to use Multitool's windows.
        Agents keep working while it is locked — this covers the app, not the
        broker.
      </div></div>
      <button className={`switch ${lock.enabled ? 'on' : ''}`}
        data-act="toggle-app-lock" role="checkbox"
        aria-label="Lock this window"
        disabled={!lock.available}
        aria-checked={lock.enabled}></button></div>;
  const lockWarning = lock.available ? null
    : <div className="notification-warning" role="status">
      <b>This computer can't authenticate you.</b>
      <span>{lock.unavailableReason || 'Set an account password or enroll Touch ID.'}</span>
    </div>;
  const autoLockBtn = (secs: LockState['autoLockSecs'], label: string): ReactNode => (
    <button className={`seg-btn ${lock.autoLockSecs === secs ? 'on' : ''}`}
      data-act="set-auto-lock" data-id={secs} role="radio"
      aria-checked={lock.autoLockSecs === secs}>{label}</button>
  );
  const autoLockRow = !lock.enabled ? null
    : <div className="set-row"><div className="set-txt"><div className="st-title">Lock when idle</div>
      <div className="st-sub">Lock after this long without interaction. ⌘L locks immediately.</div></div>
      <div className="seg in-form" role="radiogroup" aria-label="Lock when idle">
        {autoLockBtn(0, 'Never')}{autoLockBtn(60, '1 min')}{autoLockBtn(300, '5 min')}
        {autoLockBtn(900, '15 min')}{autoLockBtn(3600, '1 hr')}
      </div></div>;
  const lockOnHideRow = !lock.enabled ? null
    : <div className="set-row"><div className="set-txt"><div className="st-title">Lock when put away</div>
      <div className="st-sub">Lock as soon as both the window and the menu-bar dropdown are closed.</div></div>
      <button className={`switch ${lock.lockOnHide ? 'on' : ''}`}
        data-act="toggle-lock-on-hide" role="checkbox"
        aria-label="Lock when put away"
        aria-checked={lock.lockOnHide}></button></div>;
  const autostartRow = <div className="set-row"><div className="set-txt">
      <div className="st-title">Launch Multitool at login</div>
      <div className="st-sub">Start the broker and tray automatically so agents do not arrive before their approval surface.</div></div>
      <button className={`switch ${state.launchAtLogin ? 'on' : ''}`}
        data-act="toggle-autostart" role="checkbox"
        aria-label="Launch Multitool at login"
        aria-checked={state.launchAtLogin}></button></div>;
  const sampleToolsRow = <div className="set-row"><div className="set-txt">
      <div className="st-title">Show sample tools</div>
      <div className="st-sub">Display the Hacker News and Stack Overflow starter card on the Tools page.</div></div>
      <button className={`switch ${state.samplesDismissed ? '' : 'on'}`}
        data-act="toggle-sample-tools" role="checkbox"
        aria-label="Show sample tools"
        aria-checked={!state.samplesDismissed}></button></div>;
  // The settings read is the sheet's only source of broker truth, and this
  // sheet is the only place that truth is consumed — a failed read has no
  // other surface. Never present defaults or stale values as the broker's
  // state; the notification rows stay because they are this machine's.
  const settingsFailed = state.loadStatus.settings.status === 'error';
  const settingsFailureRow = settingsFailed
    ? <div className="load-failure" role="alert">
        <div><b>Couldn’t load this broker’s settings.</b>{state.loadStatus.settings.error
          ? <span>{state.loadStatus.settings.error}</span> : null}</div>
        <button className="btn sm" data-act="retry-view-loads">Retry</button>
      </div>
    : null;
  // Window chrome is a this-machine concern: in remote mode the toggle
  // would patch the *remote* broker's setting, which this app's chrome
  // deliberately never reads (windows.rs) — and could silently reconfigure
  // a desktop app running on the broker host. Local mode only.
  const dockRow = state.broker.mode === 'local'
    ? <div className="set-row"><div className="set-txt"><div className="st-title">Hide Dock icon in the menu bar</div>
      <div className="st-sub">When minimized to the menu bar, hide the Dock icon.</div></div>
      <button className={`switch ${s.menu_bar_hides_dock ? 'on' : ''}`}
        data-act="toggle-menubar-dock" role="checkbox"
        aria-checked={s.menu_bar_hides_dock}></button></div>
    : null;
  // Applies to the broker that actually signs, so unlike the window-chrome
  // toggle above this one is meaningful in remote mode too.
  const hostKeyRow = <div className="set-row"><div className="set-txt">
      <div className="st-title">Ask before trusting a new SSH host key</div>
      <div className="st-sub">
        Unpinned servers are otherwise trusted the first time they answer, and
        the pin is permanent. Needs Multitool open to answer: with nothing
        attached, a first login to an unpinned server is refused.
      </div></div>
    <button className={`switch ${s.confirm_ssh_host_keys ? 'on' : ''}`}
      data-act="toggle-confirm-host-keys" role="checkbox"
      aria-checked={s.confirm_ssh_host_keys}></button></div>;
  const brokerKeyRow = <div className="set-row"><div className="set-txt">
      <div className="st-title">
        {state.broker.mode === 'local' ? 'This computer’s agent key' : 'Broker agent key'}
      </div>
      <div className="st-sub">
        {state.identity?.token_path
          ? `Stored at ${state.identity.token_path}. `
          : ''}
        Rotating it disconnects every agent using the current key.
      </div></div>
      <button className="btn danger sm" data-act="rotate-key-ask">Rotate key…</button>
    </div>;
  return (
    <>
      <h3 id="settings-title">Settings</h3>
      {notificationRow}{notificationWarning}{notificationPreviewRow}
      {notificationSoundRow}{notificationFocusRow}{notificationEscalationRow}
      {lockRow}{lockWarning}{autoLockRow}{lockOnHideRow}
      {autostartRow}{sampleToolsRow}
      {brokerKeyRow}
      {settingsFailed ? settingsFailureRow : <>{hostKeyRow}{dockRow}</>}
      <div className="sheet-actions"><button className="btn primary" data-act="sheet-cancel">Done</button></div>
    </>
  );
}

/* --------------------------------- helpers ------------------------------- */
const cap = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);
const tabLabel = (tab: Tab): string =>
  tab === 'connections' ? 'Tools'
  : tab === 'start' ? 'Connect agents'
  : tab === 'secrets' ? 'Credentials'
  // The menu-bar dropdown's segmented tabs are narrow; the full "Activity
  // Log" belongs to the window's sidebar, where there is room for it.
  : tab === 'activity' ? (mode === 'dropdown' ? 'Activity' : 'Activity Log')
  : cap(tab);

// Flash "Copied" in place of the masked value for a moment after a copy.
let copiedTimer: ReturnType<typeof setTimeout> | null = null;
function flashCopied(id: string): void {
  state.copied = id;
  render();
  if (copiedTimer) clearTimeout(copiedTimer);
  copiedTimer = setTimeout(() => { state.copied = null; render(); }, 1400);
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
  if (menu.classList.contains('password-format-menu')) {
    const width = Math.max(210, rect.width);
    menu.style.left = `${Math.max(8, rect.right - width)}px`;
    menu.style.width = `${width}px`;
  } else {
    menu.style.left = `${rect.left}px`;
    menu.style.width = `${rect.width}px`;
  }
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
    focusMenuEdge(menu, 'selected');
  }, 0);
}

// Keys that walk an open listbox. Focus is the cursor, so moving it also
// scrolls a menu taller than its max-height — focus() reveals its target.
const MENU_MOVE_KEYS = new Set(['ArrowDown', 'ArrowUp', 'Home', 'End']);

function menuOptions(menu: HTMLElement | null): HTMLElement[] {
  return menu ? Array.from(menu.querySelectorAll<HTMLElement>('[role="option"]')) : [];
}

/** Focus the selected option (or an end of the list) as a menu opens. */
function focusMenuEdge(menu: HTMLElement | null, at: 'selected' | 'last'): void {
  const options = menuOptions(menu);
  if (!options.length) return;
  if (at === 'last') {
    options[options.length - 1].focus();
    return;
  }
  (options.find((option) => option.getAttribute('aria-selected') === 'true')
    ?? options[0]).focus();
}

/** Move focus within an open listbox. Arrows step and clamp at the ends —
 *  no wrap, matching a native select — while Home/End jump to an edge. */
function moveMenuFocus(menu: HTMLElement | null, key: string): void {
  const options = menuOptions(menu);
  if (!options.length) return;
  const from = options.indexOf(document.activeElement as HTMLElement);
  const step = key === 'ArrowDown' ? 1 : -1;
  const to = key === 'Home' ? 0
    : key === 'End' ? options.length - 1
    : from === -1 ? (step === 1 ? 0 : options.length - 1)
    : Math.min(Math.max(from + step, 0), options.length - 1);
  options[to].focus();
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
  if (inline.field === 'totp' && state.sheet?.kind.includes('secret')) {
    state.draft.credentialAdvancedOpen = true;
  }
  render();
  const defaultNameId = state.sheet && state.sheet.kind.includes('secret') ? 'f-name' : 'f-cname';
  const inputId = inline.field === 'name'
    ? defaultNameId
    : INPUT_BY_ERROR_FIELD[inline.field as keyof typeof INPUT_BY_ERROR_FIELD];
  if (inputId) focusField(inputId);
}

function fillGeneratedPassword(format: PasswordGenerationFormat): void {
  if (state.sheet?.kind === 'edit-secret') state.draft.secretValueModified = true;
  state.draft.passwordGenerationFormat = format;
  state.draft.value = generatedPassword(format);
  state.draft.showCredentialValue = true;
  state.formMenuOpen = null;
  delete state.sheetErrors.value;
  render();
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
    || sheet?.kind === 'elicitation' || sheet?.kind === 'onepassword';
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

async function runMcpStatusCheck(id: string): Promise<void> {
  if (state.mcpStatus[id]?.running) return;
  const connection = state.connections.find((x) => x.id === id);
  if (!connection) return;
  const epoch = brokerEpoch;
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
    if (!brokerEpochIsCurrent(epoch)) return;
    state.mcpStatus[id] = { running: false, report };
  } catch (error) {
    if (!brokerEpochIsCurrent(epoch)) return;
    state.mcpStatus[id] = { running: false, error: errorMessage(error) };
  }
  // The check can update the stored account acknowledgment.
  await load('connections', 'list_connections');
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
    state.draft.testPath = entry.preset.testPath;
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

/**
 * One press → a live tool. A sample is a keyless public API, so there is no
 * credential to collect and no form to open: register the pinned origin the
 * way the add form would with "No credential" chosen (empty template), then
 * test the saved row so its health verdict appears immediately.
 */
async function connectSampleTool(sampleId: string): Promise<void> {
  const sample = sampleToolById(sampleId);
  if (!sample || state.sampleConnecting) return;
  if (sampleConnection(sample, state.connections)) return;
  const epoch = brokerEpoch;
  state.sampleConnecting = sample.id;
  render();
  const name = availableConnectionName(sample.name);
  const input: ConnectionInput = {
    name,
    type: 'api',
    host: sample.host,
    scheme: 'https',
    port: null,
    template: '',
    mcp_path: null,
    trusted_ca_bundle_path: null,
    test_path: sample.testPath,
  };
  const ok = await run(() => invoke('add_connection', { input }));
  if (state.sampleConnecting === sample.id) state.sampleConnecting = null;
  if (!brokerEpochIsCurrent(epoch)) return;
  if (!ok) { render(); return; }
  toast('🔌 Connected');
  await refresh('all');
  if (!brokerEpochIsCurrent(epoch)) return;
  render();
  const saved = state.connections.find((connection) => connection.name === name);
  if (saved) void runConnectionTest(saved.id);
}

async function saveSecret(): Promise<void> {
  const sheet = state.sheet;
  if (!sheet || (sheet.kind !== 'add-secret' && sheet.kind !== 'edit-secret')) return;
  const epoch = brokerEpoch;
  const adding = sheet.kind === 'add-secret';
  const editingSecret = adding
    ? null
    : state.secrets.find((secret) => secret.id === sheet.id) ?? null;
  const password = sheetSecretKind(!adding, editingSecret) === 'password';
  const name = (state.draft.name || '').trim();
  const value = state.draft.value || '';
  const site = (state.draft.site || '').trim();
  const username = (state.draft.username || '').trim();
  const totp = (state.draft.totp || '').trim();
  const valueModified = Boolean(state.draft.secretValueModified);
  let dependentConnectionIds: string[] = [];
  const errs = password
    ? validatePasswordForm({ adding, site, value, valueModified })
    : validateSecretForm({ adding, name, value, valueModified });
  if (Object.keys(errs).length) { state.sheetErrors = errs; render(); return; }
  if (adding) {
    try {
      await invoke('add_secret', password
        ? {
            value,
            kind: 'password',
            site,
            username: username || null,
            totp: totp || null,
          }
        : { name, value });
    } catch (error) {
      if (brokerEpochIsCurrent(epoch)) showFormError(error);
      return;
    }
    if (!brokerEpochIsCurrent(epoch)) return;
    toast('🔑 Saved to macOS Keychain');
  } else {
    const usedBy = editingSecret?.used_by_names ?? [];
    dependentConnectionIds = state.connections
      .filter((connection) => usedBy.includes(connection.name))
      .map((connection) => connection.id);
    try {
      await invoke('edit_secret', password
        ? {
            id: sheet.id ?? '',
            newValue: valueModified ? value : null,
            newSite: site !== (editingSecret?.site ?? '') ? site : null,
            newUsername: username !== (editingSecret?.username ?? '') ? username : null,
            // Removal is an explicit empty string; otherwise only a typed
            // seed crosses. The stored seed itself never round-trips.
            newTotp: state.draft.removeTotp ? '' : totp || null,
          }
        : {
            id: sheet.id ?? '',
            newName: name,
            newValue: valueModified ? value : null,
          });
    } catch (error) {
      if (brokerEpochIsCurrent(epoch)) showFormError(error);
      return;
    }
    if (!brokerEpochIsCurrent(epoch)) return;
    toast(password ? '✏️ Password updated' : '✏️ Secret updated');
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
  const existingConnection = adding
    ? null
    : state.connections.find((connection) => connection.id === sheet.id) ?? null;
  const toolNameTaken = adding && toolNameIsTaken(name);
  const mcpAdd = adding && t === 'api' && isMcpDraft(d);
  const authMode = d.authMode || (mcpAdd ? 'oauth' : 'bearer');
  const usesOauth = mcpAdd && authMode === 'oauth';
  const oauthPreset = adding && t === 'api' && !mcpAdd && d.entryId
    ? catalogEntryById(d.entryId)?.oauthPreset : undefined;
  const byoOauth = !!oauthPreset && authMode === 'oauth';
  const errs: Record<string, string> = {};
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
  const sigv4 = adding && t === 'api' && !mcpAdd && authMode === 'sigv4';
  const gcpSigner = adding && t === 'api' && !mcpAdd && authMode === 'gcp';
  const signed = sigv4 || gcpSigner;
  const usesRecipe = adding && t === 'api'
    && authMode !== 'advanced' && !signed && !usesOauth && !byoOauth;
  const editingApiCredential = !adding && t === 'api'
    && !existingConnection?.oauth
    && !existingConnection?.oauth_spec
    && (existingConnection?.secret_names.length ?? 0) <= 1;
  const needsCredentialChoice = !usesOauth && !byoOauth && !signed && (
    (adding && !(t === 'api' && authMode === 'advanced')) ||
    (!adding && t !== 'api') ||
    editingApiCredential);
  const secretSource = adding
    ? defaultSecretSource(t, d)
    : (d.secretSource || 'existing');
  let selectedSecret: SecretSummary | null = null;
  let newSecretName: string | null = null;
  let newSecretNameTaken = false;
  if (needsCredentialChoice && secretSource === 'existing') {
    selectedSecret = state.secrets.find((secret) => secret.id === d.secretId) || null;
  } else if (needsCredentialChoice && secretSource === 'new') {
    newSecretName = (d.newSecretName || suggestedSecretName(name, t)).trim();
    newSecretNameTaken = credentialNameIsTaken(newSecretName);
  }
  const templateSecretName = selectedSecret ? selectedSecret.name : newSecretName;
  let injectionTemplate = (d.template || '').trim();
  if (usesRecipe && secretSource !== 'none') {
    try { injectionTemplate = authTemplate(t, authMode, templateSecretName || '', (d.authDetail || '').trim()); }
    catch (error) { errs.authDetail = errorMessage(error); }
  }
  const validation = validateConnectionForm({
    adding,
    type: t,
    name,
    host: d.host,
    port: d.port,
    dbname: d.dbname,
    user,
    oauthClientRequired: Boolean(mcpOauthApp) || byoOauth,
    oauthClientId: d.oauthClientId,
    oauthUrls: byoOauth
      ? {
          auth: d.oauthAuthUrl ?? oauthPreset!.authUrl,
          token: d.oauthTokenUrl ?? oauthPreset!.tokenUrl,
        }
      : undefined,
    needsCredentialChoice,
    secretSource,
    selectedSecretPresent: Boolean(selectedSecret),
    newSecretName,
    newSecretValue: d.newSecretValue ?? d.importedCredential,
    hasImportedIdentity: Boolean(t === 'ssh' && d.sshImportId && d.identityFile),
    advancedTemplateRequired: t === 'api' && authMode === 'advanced',
    injectionTemplate,
    editingTemplateRequired: !adding && t === 'api'
      // A signed connection has no injection template; the backend
      // re-attaches the omitted signer on a non-retargeting edit.
      && !existingConnection?.signer
      && (editingApiCredential
        ? secretSource !== 'none'
        : Boolean(existingConnection?.secret_names.length)
          || d.template !== existingConnection?.template),
  });
  Object.assign(errs, validation.errors);
  if (sigv4) {
    if (!(d.signerRegion || '').trim()) errs.signerRegion = 'Enter the signing region.';
    if (!(d.signerService || '').trim()) errs.signerService = 'Enter the signing service.';
    if (!d.signerAccessKeyRef) errs.signerAccessKeyRef = 'Pick the access key ID credential.';
    if (!d.signerSecretKeyRef) errs.signerSecretKeyRef = 'Pick the secret access key credential.';
  }
  if (gcpSigner) {
    if (!d.signerGcpKeyRef) {
      errs.signerGcpKeyRef = 'Pick the service-account key credential.';
    }
    if (!(d.signerGcpScope || '').trim()) errs.signerGcpScope = 'Enter the OAuth scope.';
  }
  if (t === 'api') {
    const certPath = (d.clientCertPath || '').trim();
    const keyPath = (d.clientKeyPath || '').trim();
    if (Boolean(certPath) !== Boolean(keyPath)) {
      errs[certPath ? 'clientKeyPath' : 'clientCertPath'] =
        'Configure the client certificate and its key together.';
    }
  }
  const port = validation.port;
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
    input.template = signed ? '' : injectionTemplate;
    input.mcp_path = mcpPath;
    input.trusted_ca_bundle_path = (d.pgCaBundlePath || '').trim() || null;
    input.test_path = (d.testPath || '').trim() || null;
    input.client_cert_path = (d.clientCertPath || '').trim() || null;
    input.client_key_path = (d.clientKeyPath || '').trim() || null;
    if (sigv4) {
      input.signer_region = (d.signerRegion || '').trim();
      input.signer_service = (d.signerService || '').trim();
      input.signer_access_key_ref = d.signerAccessKeyRef;
      input.signer_secret_key_ref = d.signerSecretKeyRef;
      input.signer_session_token_ref = d.signerSessionTokenRef || null;
    } else if (gcpSigner) {
      input.signer_gcp_key_ref = d.signerGcpKeyRef;
      input.signer_gcp_scope = (d.signerGcpScope || '').trim();
    }
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
  state.onepasswordFlow = null;
  state.approvalHostKeyProvenance = null;
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
  'hostKeyFingerprint', 'sslmode', 'pgCaBundlePath', 'testPath', 'secretId', 'secretSource',
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
/** Place a pointer-anchored menu wholly inside the current viewport. */
function positionPointerMenu(selector: string, point: ConnMenuPoint | null): void {
  const wrap = document.querySelector<HTMLElement>(selector);
  if (!point || !wrap) return;
  const inset = 8;
  const box = wrap.getBoundingClientRect();
  const maxLeft = Math.max(inset, window.innerWidth - box.width - inset);
  const maxTop = Math.max(inset, window.innerHeight - box.height - inset);
  wrap.style.left = `${Math.min(Math.max(inset, point.x), maxLeft)}px`;
  wrap.style.top = `${Math.min(Math.max(inset, point.y), maxTop)}px`;
  wrap.style.visibility = 'visible';
}

/** Keep the pointer-anchored tool menu wholly inside the current viewport. */
function positionConnContextMenu(): void {
  positionPointerMenu('.conn-context-menu-wrap', state.connMenuPoint);
}

/** The same for a credential row's reveal menu. */
function positionSecretContextMenu(): void {
  positionPointerMenu('.secret-context-menu-wrap', state.secretMenuPoint);
}

/** Anchor the detail pane's portaled action menu without letting any edge
 * leave the viewport. The menu itself has a viewport-bounded max-height, so
 * its final measured box can always be placed inside these insets. */
function positionConnActionMenu(): void {
  const id = state.connMenuOpen;
  if (!id || state.connMenuPoint) return;
  // Sheet reconnect ⋯ uses the same toggle id prefix and its own portal.
  if (id.startsWith('sheet:')) {
    const trigger = Array.from(
      document.querySelectorAll<HTMLElement>('[data-act="toggle-conn-menu"]'),
    ).find((candidate) => candidate.dataset.id === id);
    const wrap = document.querySelector<HTMLElement>('.sheet-conn-menu-wrap');
    if (trigger && wrap) placeAnchoredMenu(wrap, trigger, 'start');
    return;
  }
  const trigger = Array.from(
    document.querySelectorAll<HTMLElement>('[data-conn-menu-trigger]'),
  ).find((candidate) => candidate.dataset.connMenuTrigger === id);
  const wrap = document.querySelector<HTMLElement>('.conn-action-menu-wrap');
  if (!trigger || !wrap) return;
  placeAnchoredMenu(wrap, trigger);
}

/** Copy-format menu on the detail-pane address field. */
function positionEpCopyMenu(): void {
  const id = state.epMenuOpen;
  if (!id) return;
  const trigger = Array.from(
    document.querySelectorAll<HTMLElement>('[data-ep-menu-trigger]'),
  ).find((candidate) => candidate.dataset.epMenuTrigger === id);
  const wrap = document.querySelector<HTMLElement>('.ep-copy-menu-wrap');
  if (trigger && wrap) placeAnchoredMenu(wrap, trigger);
}

/** Address lifecycle ⋯ on the Connect section label. */
function positionEpOptsMenu(): void {
  const id = state.epOptsMenuOpen;
  if (!id) return;
  const trigger = Array.from(
    document.querySelectorAll<HTMLElement>('[data-ep-opts-trigger]'),
  ).find((candidate) => candidate.dataset.epOptsTrigger === id);
  const wrap = document.querySelector<HTMLElement>('.ep-opts-menu-wrap');
  if (trigger && wrap) placeAnchoredMenu(wrap, trigger);
}

/** Catalog "more ways to connect" split-button menu. */
function positionCatalogConnectMenu(): void {
  const id = state.catalogActionMenuOpen;
  if (!id) return;
  const trigger = Array.from(
    document.querySelectorAll<HTMLElement>('[data-act="toggle-catalog-connect-menu"]'),
  ).find((candidate) => candidate.dataset.id === id);
  const wrap = document.querySelector<HTMLElement>('.cat-connect-menu-wrap');
  if (trigger && wrap) placeAnchoredMenu(wrap, trigger);
}

/** Vault ⋯ menu inside the Secrets status-bar popover. */
function positionVaultMenu(): void {
  const id = state.vaultMenuOpen;
  if (!id) return;
  const trigger = Array.from(
    document.querySelectorAll<HTMLElement>('[data-act="toggle-vault-menu"]'),
  ).find((candidate) => candidate.dataset.id === id);
  const wrap = document.querySelector<HTMLElement>('.vault-menu-wrap');
  if (trigger && wrap) placeAnchoredMenu(wrap, trigger);
}

/** Connect-agents sentence blanks (tool / client). */
function positionStartMenu(): void {
  const kind = state.startMenuOpen;
  if (!kind) return;
  const trigger = document.getElementById(`start-blank-${kind}`);
  const wrap = document.querySelector<HTMLElement>('.start-menu-portal');
  if (trigger && wrap) placeAnchoredMenu(wrap, trigger, 'center', 6);
}

/** Activity Log agent filter menu. */
function positionActivityAgentMenu(): void {
  if (!state.activityAgentMenuOpen) return;
  const trigger = document.querySelector<HTMLElement>('.act-filter-trigger');
  const wrap = document.querySelector<HTMLElement>('.act-filter-menu-wrap');
  if (trigger && wrap) placeAnchoredMenu(wrap, trigger);
}

// Opportunistic re-check: coming back to the app re-tests anything the
// broker last saw unhealthy, so a fixed credential clears its badge
// without a manual test. Throttled so window-switching stays free.
let lastFocusRecheck = 0;
function handleWindowBlur(): void {
  if (clearSensitivePresentation()) render();
}

function handleWindowFocus(): void {
  if (Date.now() - lastFocusRecheck < 60_000) return;
  lastFocusRecheck = Date.now();
  for (const connection of state.connections) {
    if ((connection.last_status === 'needs_reconnect' || connection.last_status === 'failed')
      && !state.connTests[connection.id]?.running) {
      void runConnectionTest(connection.id);
    }
  }
}

/** Right-click opens the row menu for the two lists that have one: tools and
 * credentials. Anything else keeps the platform's own menu. */
function handleRowContextMenu(e: ReactMouseEvent<HTMLDivElement>): void {
  const target = e.target instanceof Element ? e.target : null;
  const connectionId = target?.closest<HTMLElement>('.flat-conn-wrap')?.dataset.connRow;
  if (connectionId) {
    e.preventDefault();
    state.selectedConn = connectionId;
    state.connMenuOpen = connectionId;
    state.connMenuPoint = { x: e.clientX, y: e.clientY };
    state.secretMenuOpen = null;
    state.secretMenuPoint = null;
    state.catalogActionMenuOpen = null;
    render();
    return;
  }
  const secretId = target?.closest<HTMLElement>('[data-secret-row]')?.dataset.secretRow;
  if (!secretId) return;
  e.preventDefault();
  state.secretMenuOpen = secretId;
  state.secretMenuPoint = { x: e.clientX, y: e.clientY };
  state.connMenuOpen = null;
  state.connMenuPoint = null;
  render();
}

async function handleActionClick(e: ReactMouseEvent<HTMLDivElement>): Promise<void> {
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
  if (state.startMenuOpen
      && !target?.closest('.start-blank-wrap')
      && !target?.closest('.start-menu-portal')) {
    state.startMenuOpen = null;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.catalogActionMenuOpen
      && !target?.closest('.cat-connect-wrap')
      && !target?.closest('.cat-connect-menu-wrap')) {
    state.catalogActionMenuOpen = null;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.vaultMenuOpen
      && !target?.closest('.vaults-panel')
      && !target?.closest('.vault-menu-wrap')) {
    state.vaultMenuOpen = null;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.vaultsPanelOpen
      && !target?.closest('.secrets-statusbar')
      && !target?.closest('.vault-menu-wrap')) {
    state.vaultsPanelOpen = false;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.activityAgentMenuOpen
      && !target?.closest('.act-filter-select')
      && !target?.closest('.act-filter-menu-wrap')) {
    state.activityAgentMenuOpen = false;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.connMenuOpen
      && !target?.closest('.tile-menu-wrap')
      && !target?.closest('.sheet-conn-menu-wrap')
      && !target?.closest('.conn-action-menu-wrap')
      && !target?.closest('.conn-context-menu-wrap')) {
    state.connMenuOpen = null;
    state.connMenuPoint = null;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.secretMenuOpen && !target?.closest('.secret-context-menu-wrap')) {
    state.secretMenuOpen = null;
    state.secretMenuPoint = null;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.epMenuOpen
      && !target?.closest('.ep-copy-wrap')
      && !target?.closest('.ep-copy-menu-wrap')) {
    state.epMenuOpen = null;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (state.epOptsMenuOpen
      && !target?.closest('.ep-opts-wrap')
      && !target?.closest('.ep-opts-menu-wrap')) {
    state.epOptsMenuOpen = null;
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
  switch (act) {
    case 'tab': {
      const tab = btn.dataset.tab;
      clearSensitivePresentation();
      if (tab && TABS.includes(tab as Tab)) state.tab = tab as Tab;
      state.confirm = null;
      state.startMenuOpen = null;
      state.addPalette = null;
      state.catalogActionMenuOpen = null;
      closeVaultsPanel();
      state.activityAgentMenuOpen = false;
      state.connMenuOpen = null;
      state.connMenuPoint = null;
      state.epMenuOpen = null;
      state.epOptsMenuOpen = null;
      // The slide-overs are transient views; coming back to a tab starts
      // at its list, not with a panel already over it.
      state.connDetailOpen = false;
      state.secretDetailOpen = false;
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
    case 'toggle-conn-menu':
      state.connMenuPoint = null;
      state.connMenuOpen = state.connMenuOpen === id ? null : id;
      state.epOptsMenuOpen = null;
      state.epMenuOpen = null;
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
      state.epOptsMenuOpen = null;
      state.confirm = { kind: 'reissue-endpoint', id: btn.dataset.conn || '' };
      render();
      break;
    case 'renew-endpoint': {
      state.connMenuOpen = null;
      state.connMenuPoint = null;
      state.epOptsMenuOpen = null;
      const connectionId = btn.dataset.conn || '';
      if (await run(() => invoke('renew_endpoint', { connectionId }))) {
        toast('Connection address renewed for 30 days');
        await refresh('all');
      } else {
        render();
      }
      break;
    }
    case 'revoke-endpoint-ask':
      state.connMenuOpen = null;
      state.connMenuPoint = null;
      state.epOptsMenuOpen = null;
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
    case 'toggle-endpoint': {
      const id = btn.dataset.conn;
      if (id) {
        state.epExpanded = { ...state.epExpanded, [id]: !state.epExpanded[id] };
        render();
      }
      break;
    }
    case 'toggle-ep-menu': {
      const id = btn.dataset.conn ?? null;
      state.epMenuOpen = state.epMenuOpen === id ? null : id;
      state.epOptsMenuOpen = null;
      render();
      break;
    }
    case 'toggle-ep-opts-menu': {
      const id = btn.dataset.conn ?? null;
      state.epOptsMenuOpen = state.epOptsMenuOpen === id ? null : id;
      state.epMenuOpen = null;
      render();
      break;
    }
    case 'copy-endpoint-dsn': {
      const conn = state.connections.find((candidate) => candidate.id === btn.dataset.conn);
      state.epMenuOpen = null;
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
      state.epMenuOpen = null;
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
      if (await run(() => invoke('copy_agent_setup'))) toast('📋 Setup instructions copied');
      break;
    case 'clear-activity-ask':
      setSheet({ kind: 'clear-activity' });
      render();
      break;
    case 'clear-activity-confirm':
      if (await run(() => invoke('clear_activity'))) {
        state.activity = [];
        state.activityNextBefore = null;
        state.activityLoadingOlder = false;
        state.activityOlderError = null;
        closeSheet();
        toast('Activity cleared');
      }
      break;

    case 'reveal-secret-ask':
      state.secretMenuOpen = null;
      state.secretMenuPoint = null;
      state.confirm = { kind: 'reveal-secret', id };
      render();
      break;
    case 'reveal-secret-confirm': {
      const epoch = brokerEpoch;
      const presentationEpoch = sensitivePresentationEpoch;
      try {
        const value = await invoke('reveal_secret', { id });
        if (!brokerEpochIsCurrent(epoch)) break;
        if (presentationEpoch !== sensitivePresentationEpoch) {
          if (state.confirm?.kind === 'reveal-secret' && state.confirm.id === id) {
            state.confirm = null;
            render();
          }
          break;
        }
        state.reveal[id] = value;
        // A confirmed reveal must land somewhere visible. The value renders
        // in the inspector (window) or the expanded row (tray), so surface
        // that container — the row that was right-clicked may be neither
        // selected nor expanded, and the narrow layout may have the
        // inspector closed.
        if (mode === 'dropdown') {
          state.dropdownSecretOpen = id;
        } else {
          state.selectedSecret = id;
          state.secretDetailOpen = true;
        }
        state.confirm = null;
        render();
      } catch (error) {
        if (brokerEpochIsCurrent(epoch)) toast('⚠ ' + errorMessage(error));
      }
      break;
    }
    case 'reveal-edit-secret-confirm': {
      const epoch = brokerEpoch;
      const presentationEpoch = sensitivePresentationEpoch;
      try {
        const value = await invoke('reveal_secret', { id });
        if (!brokerEpochIsCurrent(epoch)) break;
        if (presentationEpoch !== sensitivePresentationEpoch) {
          if (state.confirm?.kind === 'reveal-edit-secret' && state.confirm.id === id) {
            state.confirm = null;
            render();
          }
          break;
        }
        // The edit form may have been dismissed while the broker request was
        // in flight. Never put a released value into another sheet or draft.
        if (state.sheet?.kind === 'edit-secret' && state.sheet.id === id) {
          state.draft.value = value;
          state.draft.secretValueModified = false;
          state.draft.showCredentialValue = true;
        }
        state.confirm = null;
        render();
      } catch (error) {
        if (brokerEpochIsCurrent(epoch)) toast('⚠ ' + errorMessage(error));
      }
      break;
    }
    case 'unreveal-secret':
      delete state.reveal[id];
      state.secretMenuOpen = null;
      state.secretMenuPoint = null;
      render();
      break;
    case 'copy-secret':
      if (await run(() => invoke('copy_secret', { id }))) {
        toast('📋 Copied for 30s');
        flashCopied(id);
      }
      break;
    case 'copy-user': {
      // The user name is public metadata, so the webview clipboard suffices;
      // no broker round-trip and no 30s clear.
      const text = btn.dataset.text ?? '';
      if (!text) break;
      try {
        await navigator.clipboard.writeText(text);
        flashCopied(`user:${id}`);
      } catch {
        toast('⚠ Could not copy');
      }
      break;
    }
    case 'select-secret':
      // A shown code belongs to the moment it was asked for; moving to
      // another credential puts the button back.
      if (state.selectedSecret !== id) state.totpVisible = null;
      state.selectedSecret = id;
      // Inert in the wide layout; in the narrow one this rides the
      // inspector over the list (same shape as the tools slide-over).
      state.secretDetailOpen = true;
      render();
      break;
    case 'show-totp':
      state.totpVisible = id;
      render();
      break;
    case 'close-cred-detail':
      state.secretDetailOpen = false;
      render();
      break;
    case 'secret-category':
      state.secretCategory = (btn.dataset.id as SecretCategory | undefined) ?? 'all';
      state.secretDetailOpen = false;
      render();
      break;
    case 'toggle-dd-secret':
      state.dropdownSecretOpen = state.dropdownSecretOpen === id ? null : id;
      render();
      break;
    case 'del-secret-ask': {
      const s = state.secrets.find((x) => x.id === id);
      state.confirm = { kind: s && s.used_by ? 'del-secret-inuse' : 'del-secret', id };
      render();
      break;
    }
    case 'del-secret-confirm':
      {
        const linked = state.secrets.find((secret) => secret.id === id)?.source?.kind === 'one_password';
        if (await run(() => invoke('delete_secret', { id }))) {
          state.confirm = null;
          toast(linked ? 'Unlinked from Multitool' : '🗑 Removed from macOS Keychain');
          await refresh('secrets');
        }
      }
      break;
    case 'show-connection':
      state.tab = 'connections';
      state.addPalette = null;
      state.selectedConn = id;
      state.connDetailOpen = true;
      state.confirm = null;
      render();
      break;
    case 'delete-using-connection':
      state.tab = 'connections';
      state.addPalette = null;
      state.selectedConn = id;
      state.connDetailOpen = true;
      state.confirm = { kind: 'del-conn', id };
      render();
      break;
    case 'edit-secret': {
      if (!await holdDropdownFormOpen()) break;
      setSheet({ kind: 'edit-secret', id });
      // Controlled fields read the draft, so seed the public identity fields
      // only. The credential value and 2FA seed remain write-only; the value
      // input renders its mask as a placeholder until a confirmed reveal.
      const secret = state.secrets.find((s) => s.id === id);
      state.draft = {
        name: secret?.name ?? '',
        value: '',
        secretKind: secret?.kind,
        site: secret?.site ?? '',
        username: secret?.username ?? '',
      };
      state.sheetErrors = {};
      render();
      if (secret?.kind === 'password') focusField('f-site');
      else focusField('f-value');
      break;
    }
    case 'open-add-secret': {
      if (!await holdDropdownFormOpen()) break;
      const kind = supportsTypedCredentials(state.broker)
        ? btn.dataset.kind === 'secret' ? 'secret' as const : 'password' as const
        : undefined;
      setSheet({ kind: 'add-secret' });
      state.draft = kind ? { secretKind: kind } : {};
      state.sheetErrors = {};
      render();
      focusField(kind === 'password' ? 'f-site' : 'f-name');
      break;
    }
    case 'secret-kind': {
      const kind = btn.dataset.kind === 'password' ? 'password' as const : 'secret' as const;
      if (state.draft.secretKind === kind) break;
      state.draft.secretKind = kind;
      state.sheetErrors = {};
      render();
      focusField(kind === 'password' ? 'f-site' : 'f-name');
      break;
    }
    case 'credential-advanced':
      state.draft.credentialAdvancedOpen = !state.draft.credentialAdvancedOpen;
      render();
      break;
    case 'generate-password-menu':
      state.formMenuOpen = state.formMenuOpen === 'password-generator-menu'
        ? null
        : 'password-generator-menu';
      render();
      if (state.formMenuOpen) focusMenuOption();
      break;
    case 'password-format': {
      const format = PASSWORD_GENERATION_FORMATS.find((candidate) => candidate.id === id)?.id;
      if (format) fillGeneratedPassword(format);
      break;
    }
    case 'generate-password':
      fillGeneratedPassword(state.draft.passwordGenerationFormat ?? 'strong');
      break;
    case 'copy-totp': {
      const epoch = brokerEpoch;
      try {
        const secondsRemaining = await invoke('copy_secret_totp', { id });
        if (!brokerEpochIsCurrent(epoch)) break;
        toast(`🔑 2FA code copied · valid ${secondsRemaining}s`);
      } catch (error) {
        if (brokerEpochIsCurrent(epoch)) toast('⚠ ' + errorMessage(error));
      }
      break;
    }
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
        // The picked option is about to unmount, so hand the keyboard back
        // to the blank it belongs to (as the form listboxes do).
        closeStartMenu('tool');
      }
      break;
    case 'start-mode':
      if (id) {
        state.connectMode = id;
        closeStartMenu('client');
      }
      break;
    case 'start-menu':
      if (state.startMenuOpen === id) {
        closeStartMenu(state.startMenuOpen);
      } else {
        state.startMenuOpen = id === 'tool' || id === 'client' ? id : null;
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
    case 'copy-first-task': {
      const connectionId = btn.dataset.conn ?? '';
      const taskBody = btn.dataset.task ?? '';
      if (connectionId && taskBody && await run(() => invoke('copy_endpoint_text', {
        connectionId,
        format: 'first-task',
        taskBody,
      }))) {
        toast('📋 Copied for 30s');
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
    case 'toggle-connection-advanced':
      state.connDetailAdvancedOpen = state.connDetailAdvancedOpen === id ? null : id;
      render();
      break;
    case 'toggle-connection-details':
      state.connDetailDetailsOpen = state.connDetailDetailsOpen === id ? null : id;
      render();
      break;
    case 'open-add-palette':
      state.addPalette = { query: '', index: 0 };
      render();
      focusField('add-palette-input');
      break;
    case 'close-add-palette':
      state.addPalette = null;
      render();
      break;
    case 'palette-add':
      await activatePaletteEntry(id);
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
      if (entry) await addCatalogEntry(entry);
      break;
    }
    case 'toggle-vaults-panel':
      state.vaultsPanelOpen = !state.vaultsPanelOpen;
      state.vaultMenuOpen = null;
      render();
      break;
    case 'toggle-vault-menu':
      state.vaultMenuOpen = state.vaultMenuOpen === id ? null : id;
      render();
      break;
    case 'onepassword-open':
      closeVaultsPanel();
      await openOnePasswordFlow();
      break;
    case 'onepassword-browse': {
      const integration = state.onepasswordIntegrations.find((candidate) => candidate.id === id);
      closeVaultsPanel();
      if (integration) await openOnePasswordFlow(integration);
      break;
    }
    case 'onepassword-update': {
      const integration = state.onepasswordIntegrations.find((candidate) => candidate.id === id)
        ?? state.onepasswordFlow?.integration;
      closeVaultsPanel();
      if (!integration || integration.kind === 'desktop_app') break;
      if (state.sheet?.kind === 'onepassword') closeSheet();
      await openOnePasswordFlow(integration, 'update');
      break;
    }
    case 'onepassword-delete-ask': {
      const integration = state.onepasswordIntegrations.find((candidate) => candidate.id === id)
        ?? state.onepasswordFlow?.integration;
      closeVaultsPanel();
      if (!integration) break;
      if (state.sheet?.kind === 'onepassword') closeSheet();
      state.confirm = { kind: 'del-onepassword', id: integration.id };
      render();
      break;
    }
    case 'onepassword-delete-confirm':
      if (await run(() => invoke('delete_onepassword_integration', { id }))) {
        state.confirm = null;
        state.onepasswordIntegrations = state.onepasswordIntegrations
          .filter((integration) => integration.id !== id);
        toast('1Password connection removed');
        await refresh('secrets');
      }
      break;
    case 'onepassword-method': {
      const flow = state.onepasswordFlow;
      const method = btn.dataset.method;
      if (!flow || (method !== 'desktop_app' && method !== 'service_account' && method !== 'connect')) break;
      if (state.broker.mode === 'remote' && method === 'desktop_app') break;
      flow.method = method;
      flow.token = '';
      flow.error = null;
      render();
      break;
    }
    case 'onepassword-connect':
      await connectOnePassword();
      break;
    case 'onepassword-show-vaults': {
      const flow = state.onepasswordFlow;
      if (!flow) break;
      flow.vault = null;
      flow.item = null;
      flow.items = [];
      flow.fields = [];
      flow.error = null;
      render();
      break;
    }
    case 'onepassword-show-items': {
      const flow = state.onepasswordFlow;
      if (!flow) break;
      flow.item = null;
      flow.fields = [];
      flow.error = null;
      render();
      break;
    }
    case 'onepassword-vault':
      await chooseOnePasswordVault(id);
      break;
    case 'onepassword-item':
      await chooseOnePasswordItem(id, btn.dataset.vaultId);
      break;
    case 'onepassword-retry': {
      const flow = state.onepasswordFlow;
      if (!flow) break;
      if (flow.item) await chooseOnePasswordItem(flow.item.id, flow.item.vault_id);
      else if (flow.vault) await chooseOnePasswordVault(flow.vault.id);
      else await loadOnePasswordVaults();
      break;
    }
    case 'onepassword-review': {
      const flow = state.onepasswordFlow;
      if (!flow || !Object.keys(flow.selections).length || onePasswordSelectionErrors().size) break;
      flow.step = 3;
      flow.error = null;
      render();
      break;
    }
    case 'onepassword-back': {
      const flow = state.onepasswordFlow;
      if (!flow) break;
      flow.step = 2;
      flow.error = null;
      render();
      break;
    }
    case 'onepassword-save':
      await saveOnePasswordSelections();
      break;
    case 'connect-sample':
      await connectSampleTool(id);
      break;
    case 'dismiss-samples':
      state.samplesDismissed = true;
      persistSamplesDismissed();
      render();
      break;
    case 'toggle-sample-tools':
      state.samplesDismissed = !state.samplesDismissed;
      persistSamplesDismissed(state.samplesDismissed);
      toast(state.samplesDismissed ? 'Sample tools hidden' : 'Sample tools shown on Tools');
      render();
      break;
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
        apiCredentialTemplate: c.type === 'api' ? c.template : null,
        apiCredentialName: c.type === 'api' && c.secret_names.length === 1
          ? c.secret_names[0]
          : null,
        destination: c.destination,
        hostKeyFingerprint: c.host_key_fingerprint,
        sslmode: c.sslmode || 'verify-full', pgCaBundlePath: c.trusted_ca_bundle_path,
        testPath: c.test_path ?? null,
        // Restated on save so a non-retargeting edit keeps the mTLS pair.
        clientCertPath: c.client_cert_path ?? null,
        clientKeyPath: c.client_key_path ?? null,
        secretId: null,
        secretSource: c.secret_names.length ? 'existing' : 'none' };
      // best-effort: prefill single-secret binding by name→id
      if (c.secret_names.length === 1) {
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
        const lookup = await invoke('check_known_hosts', {
          host,
          port: Number.isInteger(port) && port > 0 ? port : 22,
        });
        if (!brokerEpochIsCurrent(epoch) || state.draft !== draft) break;
        const { candidates } = lookup;
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
      else if (menuId === 'c-signer-access') state.draft.signerAccessKeyRef = id || null;
      else if (menuId === 'c-signer-secret') state.draft.signerSecretKeyRef = id || null;
      else if (menuId === 'c-signer-token') state.draft.signerSessionTokenRef = id || null;
      else if (menuId === 'c-signer-gcp-key') state.draft.signerGcpKeyRef = id || null;
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
      if (state.sheet?.kind === 'edit-conn' && state.connType === 'api') {
        const connection = state.connections.find((item) => item.id === state.sheet?.id);
        const editable = connection
          && !connection.oauth
          && !connection.oauth_spec
          && connection.secret_names.length <= 1;
        if (editable && id === NO_CREDENTIAL_OPTION) {
          // Retain apiCredentialTemplate separately: switching back from
          // "None" can restore the existing header/query form.
          state.draft.template = '';
          delete state.sheetErrors.template;
        } else if (editable && id !== NEW_CREDENTIAL_OPTION) {
          const secret = state.secrets.find((item) => item.id === id);
          if (secret) {
            const rebound = rebindApiCredentialTemplate(
              state.draft.apiCredentialTemplate ?? state.draft.template ?? '',
              state.draft.apiCredentialName,
              secret.name,
            );
            state.draft.template = rebound;
            state.draft.apiCredentialTemplate = rebound;
            state.draft.apiCredentialName = secret.name;
            delete state.sheetErrors.template;
          }
        }
      }
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
    case 'mcp-status':
      state.connMenuOpen = null;
      state.connMenuPoint = null;
      await runMcpStatusCheck(id);
      break;
    case 'recheck-tools':
      // Re-pull the list first so the sweep tests what the broker actually
      // holds, then fan the per-tool checks out concurrently.
      await refresh('connections');
      for (const connection of state.connections) {
        if (connection.mcp_path) void runMcpStatusCheck(connection.id);
        else void runConnectionTest(connection.id);
      }
      break;
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
    case 'act-filter-alerts':
      state.activityAlertsOnly = !state.activityAlertsOnly;
      render();
      break;
    case 'act-filter-agent-menu':
      state.activityAgentMenuOpen = !state.activityAgentMenuOpen;
      render();
      break;
    case 'act-filter-agent': {
      // An empty value is the "All agents" default at the top of the menu.
      state.activityAgent = btn.dataset.value || null;
      state.activityAgentMenuOpen = false;
      render();
      break;
    }
    case 'activity-load-older':
      await loadOlderActivity();
      break;
    case 'request-filter-alerts':
      state.requestAlertsOnly = !state.requestAlertsOnly;
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
      state.addPalette = null;
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
    case 'response-credentials-on':
      // This expands what an agent receives and opens the broker's fresh
      // confirmation sheet. Keep the dropdown alive while that sheet owns
      // focus, exactly like the other high-consequence toggles.
      if (!await holdDropdownFormOpen()) break;
      if (await run(() => invoke('set_expose_response_credentials', {
        connectionId: btn.dataset.conn || '', expose: true,
      }))) {
        toast('⚠ Upstream cookies and authentication fields are now returned to agents');
      }
      releaseDropdownForm();
      await refresh('connections');
      break;
    case 'response-credentials-off':
      if (await run(() => invoke('set_expose_response_credentials', {
        connectionId: btn.dataset.conn || '', expose: false,
      }))) {
        toast('🔒 Upstream response credentials are contained');
      }
      await refresh('connections');
      break;
    case 'endpoint-auth-on':
      if (await run(() => invoke('set_endpoint_require_auth', {
        connectionId: btn.dataset.conn || '', requireAuth: true,
      }))) {
        toast('🔒 The agent socket now requires the endpoint secret');
      }
      await refresh('connections');
      break;
    case 'endpoint-auth-off':
      if (await run(() => invoke('set_endpoint_require_auth', {
        connectionId: btn.dataset.conn || '', requireAuth: false,
      }))) {
        toast('🔓 The agent socket no longer requires the endpoint secret');
      }
      await refresh('connections');
      break;
    case 'endpoint-expiry-on':
      if (await run(() => invoke('set_endpoint_expiry', {
        connectionId: btn.dataset.conn || '', expire: true,
      }))) {
        toast('⏳ The connection address now expires');
      }
      await refresh('connections');
      break;
    case 'endpoint-expiry-off':
      if (await run(() => invoke('set_endpoint_expiry', {
        connectionId: btn.dataset.conn || '', expire: false,
      }))) {
        toast('♾️ The connection address no longer expires');
      }
      await refresh('connections');
      break;
    case 'statements-on':
      if (await run(() => invoke('set_audit_statements', {
        connectionId: btn.dataset.conn || '', auditStatements: true,
      }))) {
        toast('📝 Recording statement text in Activity');
      }
      await refresh('connections');
      break;
    case 'statements-off':
      if (await run(() => invoke('set_audit_statements', {
        connectionId: btn.dataset.conn || '', auditStatements: false,
      }))) {
        toast('📝 No longer recording statement text');
      }
      await refresh('connections');
      break;

    case 'rotate-key-ask': {
      state.confirm = { kind: 'rotate-key' };
      render();
      break;
    }
    case 'rotate-key-confirm': {
      if (await run(() => invoke('rotate_key'))) {
        state.confirm = null;
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
    // releases (or refuses) the parked call broker-side.
    case 'approval-open': {
      if (!await holdDropdownFormOpen()) break;
      const approval = state.approvals.find((candidate) => candidate.id === id);
      setSheet({ kind: 'approval', id });
      render();
      if (approval?.unit === 'host_key' && approval.host_key_fingerprint) {
        const connection = state.connections.find(
          (candidate) => candidate.id === approval.connection_id,
        );
        if (connection?.host) {
          state.approvalHostKeyProvenance = {
            approvalId: approval.id,
            loading: true,
            candidates: [],
            revokedFingerprints: [],
            hasCertificateAuthority: false,
          };
          render();
          try {
            const lookup = await invoke('check_known_hosts', {
              host: connection.host,
              port: connection.port ?? 22,
            });
            if (state.sheet?.kind === 'approval' && state.sheet.id === approval.id) {
              state.approvalHostKeyProvenance = {
                approvalId: approval.id,
                loading: false,
                ...lookup,
              };
              render();
            }
          } catch (error) {
            if (state.sheet?.kind === 'approval' && state.sheet.id === approval.id) {
              state.approvalHostKeyProvenance = {
                approvalId: approval.id,
                loading: false,
                candidates: [],
                revokedFingerprints: [],
                hasCertificateAuthority: false,
                error: errorMessage(error),
              };
              render();
            }
          }
        }
      }
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
        const label = id === 'off'
          ? 'use the Inbox window only'
          : id === 'always' ? 'always on' : 'on when you’re away';
        toast(`🔔 Request notifications ${label}`);
      } catch (error) {
        toast('⚠ ' + errorMessage(error));
      }
      render();
      break;
    }
    case 'request-notification-permission': {
      try {
        state.notificationSettings = await invoke('request_notification_permission');
        toast('🔔 Request notifications enabled');
      } catch (error) {
        toast('⚠ ' + errorMessage(error));
      }
      render();
      break;
    }
    case 'unlock-app': await unlockApp(); break;
    case 'retry-embedded-unlock':
      state.lock = { ...state.lock, embeddedError: undefined };
      render();
      await invoke('retry_embedded_unlock');
      break;
    case 'lock-now': {
      state.lock = await invoke('lock_app');
      render();
      break;
    }
    case 'toggle-app-lock': {
      const enabled = !state.lock.enabled;
      try {
        state.lock = await invoke('set_lock_settings', {
          settings: {
            enabled,
            autoLockSecs: state.lock.autoLockSecs,
            lockOnHide: state.lock.lockOnHide,
          },
        });
        toast(enabled ? '🔒 Multitool will lock' : 'Multitool will not lock');
      } catch (error) {
        toast('⚠ ' + errorMessage(error));
      }
      render();
      break;
    }
    case 'set-auto-lock': {
      const autoLockSecs = Number(id);
      try {
        state.lock = await invoke('set_lock_settings', {
          settings: {
            enabled: state.lock.enabled,
            autoLockSecs,
            lockOnHide: state.lock.lockOnHide,
          },
        });
        toast(autoLockSecs === 0
          ? 'Multitool will not lock on its own'
          : `🔒 Multitool locks after ${relLockDelay(autoLockSecs)} idle`);
      } catch (error) {
        toast('⚠ ' + errorMessage(error));
      }
      render();
      break;
    }
    case 'toggle-lock-on-hide': {
      const lockOnHide = !state.lock.lockOnHide;
      try {
        state.lock = await invoke('set_lock_settings', {
          settings: {
            enabled: state.lock.enabled,
            autoLockSecs: state.lock.autoLockSecs,
            lockOnHide,
          },
        });
      } catch (error) {
        toast('⚠ ' + errorMessage(error));
      }
      render();
      break;
    }
    case 'toggle-autostart': {
      try {
        state.launchAtLogin = await invoke('set_autostart', {
          on: !state.launchAtLogin,
        });
        toast(state.launchAtLogin
          ? '✓ Multitool will launch at login'
          : 'Multitool will not launch at login');
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
    case 'toggle-notification-sound': {
      const settings: NotificationSettings = {
        ...state.notificationSettings,
        playSound: !state.notificationSettings.playSound,
      };
      const settingsEpoch = notificationSettingsEpoch;
      try {
        const saved = await invoke('set_notification_settings', { settings });
        if (settingsEpoch === notificationSettingsEpoch) state.notificationSettings = saved;
        toast(settings.playSound
          ? '🔔 Request notification sounds on'
          : '🔕 Request notification sounds off');
      } catch (error) {
        toast('⚠ ' + errorMessage(error));
      }
      render();
      break;
    }
    case 'toggle-notification-time-sensitive': {
      const settings: NotificationSettings = {
        ...state.notificationSettings,
        timeSensitive: !state.notificationSettings.timeSensitive,
      };
      const settingsEpoch = notificationSettingsEpoch;
      try {
        const saved = await invoke('set_notification_settings', { settings });
        if (settingsEpoch === notificationSettingsEpoch) state.notificationSettings = saved;
        toast(settings.timeSensitive
          ? '🔔 Time-sensitive request notifications on'
          : '🔔 Request notifications respect Focus and Do Not Disturb');
      } catch (error) {
        toast('⚠ ' + errorMessage(error));
      }
      render();
      break;
    }
    case 'set-notification-escalation': {
      const secs = Number(id);
      if (secs !== 0 && secs !== 15 && secs !== 30 && secs !== 60) break;
      const settings: NotificationSettings = {
        ...state.notificationSettings,
        escalationSecs: secs,
      };
      const settingsEpoch = notificationSettingsEpoch;
      try {
        const saved = await invoke('set_notification_settings', { settings });
        if (settingsEpoch === notificationSettingsEpoch) state.notificationSettings = saved;
        toast(secs === 0
          ? '🔕 Native request re-alerts off'
          : `🔔 Requests re-alert ${secs} seconds before expiry`);
      } catch (error) {
        toast('⚠ ' + errorMessage(error));
      }
      render();
      break;
    }
    case 'toggle-menubar-dock':
      {
        const on = !state.settings.menu_bar_hides_dock;
        await run(() => invoke('set_menu_bar_hides_dock', { on }));
        toast(on ? '🚢 Dock icon hidden in the menu bar' : '🚢 Dock icon kept in the menu bar');
      }
      await refresh('settings');
      break;
    case 'toggle-confirm-host-keys':
      {
        const on = !state.settings.confirm_ssh_host_keys;
        // Turning it off weakens a gate, so the broker authenticates first
        // and a refused sheet leaves the switch alone — the same shape the
        // read-gate and traffic-confirmation switches use.
        if (!on && !await holdDropdownFormOpen()) break;
        if (await run(() => invoke('set_confirm_ssh_host_keys', { on }))) {
          toast(on
            ? '🔑 Asking before trusting a new SSH host key'
            : '🔑 New SSH host keys are pinned without asking');
        }
        if (!on) releaseDropdownForm();
      }
      await refresh('settings');
      break;
    default: break;
  }
}

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
  keyboardReorderConnId = id;
  const focusGeneration = ++keyboardReorderFocusGeneration;
  render();
  const restoreFocus = (): void => {
    if (focusGeneration !== keyboardReorderFocusGeneration) return;
    const row = document.querySelector<HTMLElement>(
      `[data-conn-row="${CSS.escape(id)}"] .flat-conn-row`,
    );
    row?.focus({ preventScroll: true });
    row?.scrollIntoView({ block: 'nearest' });
    keyboardReorderConnId = null;
    render();
  };
  if (document.hidden) setTimeout(restoreFocus, 0);
  else requestAnimationFrame(restoreFocus);
  const generation = ++connectionReorderGeneration;
  void persistConnOrder(ids, previous, generation);
}

function handleConnectionDragStart(e: ReactDragEvent<HTMLDivElement>): void {
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
}

function handleConnectionDragOver(e: ReactDragEvent<HTMLDivElement>): void {
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
}

function handleConnectionDrop(e: ReactDragEvent<HTMLDivElement>): void {
  if (!dragConnId) return;
  if ((e.target instanceof Element ? e.target : null)?.closest('[data-conn-list="on"]')) {
    e.preventDefault();
  }
  commitConnDrag();
}

// Fires after every drag, including one cancelled outside the list; it is the
// backstop that clears the dragging state and commits the final order.
function handleConnectionDragEnd(): void {
  commitConnDrag();
}

/** Close a hero blank's menu and put focus back on the blank itself, so the
 *  sentence never loses the keyboard when a menu goes away. */
function closeStartMenu(kind: 'tool' | 'client'): void {
  state.startMenuOpen = null;
  render();
  focusField(startBlankId(kind));
}

// Focus an option once the hero blank's menu has mounted.
function focusStartMenuOption(at: 'selected' | 'last'): void {
  setTimeout(() => {
    focusMenuEdge(document.querySelector<HTMLElement>('.start-menu'), at);
  }, 0);
}

/** Keyboard driving for the Connect agents hero blanks, matching the form
 *  listboxes: ArrowDown/ArrowUp on a closed blank opens its menu, arrows and
 *  Home/End then walk the options — which scrolls a menu longer than its
 *  max-height, since focus() reveals what it focuses — and Tab leaves by
 *  closing the menu rather than stepping through the options one by one.
 *  Enter and Space need no handling: the options are real buttons. Returns
 *  whether the key was consumed. */
function handleStartMenuKeyDown(e: KeyboardEvent): boolean {
  if (e.altKey || e.ctrlKey || e.metaKey) return false;
  const active = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const open = state.startMenuOpen;
  if (!open) {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return false;
    const kind = active?.closest<HTMLElement>('.start-blank')?.dataset.id;
    if (kind !== 'tool' && kind !== 'client') return false;
    e.preventDefault();
    state.startMenuOpen = kind;
    render();
    focusStartMenuOption(e.key === 'ArrowUp' ? 'last' : 'selected');
    return true;
  }
  const menu = document.querySelector<HTMLElement>('.start-menu');
  if (MENU_MOVE_KEYS.has(e.key)) {
    e.preventDefault();
    moveMenuFocus(menu, e.key);
    return true;
  }
  if (e.key === 'Tab' && active && menu?.contains(active)) {
    e.preventDefault();
    closeStartMenu(open);
    return true;
  }
  return false;
}

function handleAppKeyDown(e: KeyboardEvent): void {
  noteActivity();
  // Locked: the overlay owns the keyboard. Return re-raises the system
  // prompt; nothing else reaches the surfaces underneath.
  if (state.lock.locked) {
    // Touch ID is already armed when the control is hosted; Return is the
    // deliberate reach for the password sheet.
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      void unlockApp();
    }
    return;
  }
  // ⌘L mirrors the File ▸ Lock Now menu item. The native accelerator only
  // fires while a native menu is attached, and the dropdown panel has none.
  if (e.key.toLowerCase() === 'l' && (e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey) {
    if (state.lock.enabled) {
      e.preventDefault();
      void invoke('lock_app').then(receiveLockState);
      return;
    }
  }
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
    // The dropdown has no Connect agents tab; cycle only the tabs it shows.
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
  if (handleStartMenuKeyDown(e)) return;
  if (e.key === 'Escape') {
    if (state.addPalette) { state.addPalette = null; render(); return; }
    if (state.catalogActionMenuOpen) { state.catalogActionMenuOpen = null; render(); return; }
    if (state.vaultMenuOpen) { state.vaultMenuOpen = null; render(); return; }
    if (state.vaultsPanelOpen) { state.vaultsPanelOpen = false; render(); return; }
    if (state.activityAgentMenuOpen) { state.activityAgentMenuOpen = false; render(); return; }
    if (state.startMenuOpen) { closeStartMenu(state.startMenuOpen); return; }
    if (state.connMenuOpen) {
      state.connMenuOpen = null;
      state.connMenuPoint = null;
      render();
      return;
    }
    if (state.secretMenuOpen) {
      state.secretMenuOpen = null;
      state.secretMenuPoint = null;
      render();
      return;
    }
    if (state.epMenuOpen) { state.epMenuOpen = null; render(); return; }
    if (state.epOptsMenuOpen) { state.epOptsMenuOpen = null; render(); return; }
    // The detail slide-overs only exist in the narrow layout; in the wide
    // layout the flags are inert and Escape passes through.
    if (state.connDetailOpen && window.matchMedia(NARROW_LAYOUT).matches) {
      state.connDetailOpen = false; render(); return;
    }
    if (state.secretDetailOpen && window.matchMedia(NARROW_LAYOUT).matches) {
      state.secretDetailOpen = false; render(); return;
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
        (e.key === 'ArrowDown' && (document.activeElement?.classList.contains('cred-trigger')
          || document.activeElement?.classList.contains('password-generator-menu-trigger'))))) {
    // Native-select keyboard behavior for the listboxes: ArrowDown on a
    // closed trigger opens it; arrows move between options once open.
    e.preventDefault();
    if (!state.formMenuOpen) {
      state.formMenuOpen = (document.activeElement as HTMLElement).id;
      render();
      focusMenuOption();
      return;
    }
    moveMenuFocus(document.querySelector<HTMLElement>('.cred-menu'), e.key);
  } else if ((e.key === 'Home' || e.key === 'End') && state.formMenuOpen
      && e.target instanceof Element && e.target.closest('.cred-menu')) {
    // Only once an option holds focus — Home/End inside a form field still
    // belong to its caret.
    e.preventDefault();
    moveMenuFocus(document.querySelector<HTMLElement>('.cred-menu'), e.key);
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
}

// Custom-select triggers map to the draft field whose inline validation
// error a new pick clears (text fields clear their own via setDraftField).
const ERR_KEY_BY_INPUT = {
  'f-sslmode': 'sslmode', 'c-secret': 'secret', 'c-auth-mode': 'authMode',
  'c-identity-file': 'newSecretValue',
  'c-signer-access': 'signerAccessKeyRef', 'c-signer-secret': 'signerSecretKeyRef',
  'c-signer-token': 'signerSessionTokenRef', 'c-signer-gcp-key': 'signerGcpKeyRef',
};

// Form fields are controlled React inputs; their onChange handlers own
// draft updates, error clearing, and the draft-test-override disarm.

function handleDocumentScroll(): void {
  // Reading a long list by trackpad is interaction: without this, scrolling
  // through the activity log for six minutes gets you locked mid-read.
  noteActivity();
  positionOpenMenus();
}

function handleWindowResize(): void {
  positionOpenMenus();
}

// Browser-level events that are genuinely global stay native, but their
// lifetime belongs to React so Strict Mode and future root remounts cannot
// accumulate duplicate listeners. Click, context-menu, and drag events are
// handled by the React event boundary above.
function useExternalAppEvents(): void {
  useEffect(() => {
    window.addEventListener('blur', handleWindowBlur);
    window.addEventListener('focus', handleWindowFocus);
    window.addEventListener('resize', handleWindowResize);
    document.addEventListener('keydown', handleAppKeyDown);
    document.addEventListener('pointerdown', noteActivity, true);
    document.addEventListener('scroll', handleDocumentScroll, true);
    return () => {
      window.removeEventListener('blur', handleWindowBlur);
      window.removeEventListener('focus', handleWindowFocus);
      window.removeEventListener('resize', handleWindowResize);
      document.removeEventListener('keydown', handleAppKeyDown);
      document.removeEventListener('pointerdown', noteActivity, true);
      document.removeEventListener('scroll', handleDocumentScroll, true);
    };
  }, []);
}

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
  if (mode === 'dropdown' && state.tab === 'start') state.tab = 'secrets';
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
  // Both windows observe the same lock, and either can engage it. Subscribe
  // before the first read so a lock taken during boot is not missed.
  await listen('aka://lock-changed', (event) => receiveLockState(event.payload));
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
  // Prime the shared shell data before the first real paint. Secrets remains
  // the landing page even when no tools have been configured yet.
  await Promise.all([
    loadLocalUsername(),
    loadNotificationSettings(),
    loadLockState(),
    load('connections', 'list_connections'),
    loadIdentity(),
  ]);
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
  await listen('aka://secrets-changed', async () => {
    await Promise.all([
      load('secrets', 'list_secrets'),
      load('connections', 'list_connections'),
    ]);
    render();
  });
  await listen('aka://integrations-changed', async () => {
    await loadOnePasswordIntegrations();
    render();
  });
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
  // This precise event means the log was cleared, so retaining the previous
  // pagination depth would only issue empty historical reads.
  await listen('aka://activity-changed', () => loadActivity(false).then(() => render()));
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
    state.elicitValues = {};
    state.onepasswordFlow = null;
    state.sheetErrors = {};
    state.sheetBaseline = null;
    state.confirmDiscard = false;
    state.confirm = null;
    state.catalogActionMenuOpen = null;
    closeVaultsPanel();
    state.startMenuOpen = null;
    state.addPalette = null;
    state.connMenuOpen = null;
    state.connMenuPoint = null;
    state.secretMenuOpen = null;
    state.secretMenuPoint = null;
    state.epMenuOpen = null;
    state.epOptsMenuOpen = null;
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
