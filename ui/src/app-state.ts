import type { ConnectionPreset } from './catalog';
import { LOCAL_BROKER } from './broker';
import type { HostKeyCandidate } from './connection-input';
import type {
  ActivityEntry,
  Approval,
  BrokerProfile,
  ConnectionSummary,
  ConnectionType,
  ElicitationRequest,
  IdentityInfo,
  IssuedEndpoint,
  McpAuthDraft,
  McpAuthState,
  McpStatusReport,
  McpToolInfo,
  NotificationSettings,
  RequestRecord,
  SecretSummary,
  SessionSummary,
  Settings,
  TestErrorKind,
} from './types';
import {
  getBrokerQueryData,
  removeBrokerQueryData,
  setBrokerQueryData,
} from './query-client';
import { UiStore } from './ui-store';

export const TABS = ['start', 'connections', 'secrets', 'inbox', 'activity'] as const;
export const DROPDOWN_TABS = TABS.filter((tab) => tab !== 'start');
export type Tab = typeof TABS[number];

export interface SheetState {
  kind: 'add-secret' | 'edit-secret' | 'add-conn' | 'edit-conn' | 'settings'
    | 'clear-activity' | 'elicitation' | 'approval' | 'mcp-auth' | 'wiring-tools'
    | 'endpoint-issued';
  id?: string;
  expectedUpdatedAt?: string;
  endpoint?: IssuedEndpoint;
}

export interface ConfirmState {
  kind: string;
  id?: string | number;
  name?: string;
}

export interface ConnectionDraft {
  name?: string;
  nameIsAutomatic?: boolean;
  value?: string;
  importWarnings?: string[];
  origin?: string | null;
  isMcp?: boolean;
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
  hostKeyAutoPinned?: boolean;
  proxyJump?: string | null;
  sslmode?: string | null;
  sslmodeIsAutomatic?: boolean;
  pgCaBundlePath?: string | null;
  testPath?: string | null;
  url?: string | null;
  template?: string | null;
  secretId?: string | null;
  secretSource?: 'existing' | 'new' | 'none';
  newSecretName?: string;
  newSecretValue?: string;
  importedCredential?: string | null;
  identityFile?: string;
  keyPassphrase?: string;
  identityFiles?: string[];
  sshImportId?: string;
  destination?: string | null;
  authMode?: string;
  oauthClientId?: string;
  oauthClientSecret?: string;
  oauthAuthUrl?: string;
  oauthTokenUrl?: string;
  oauthScopes?: string[];
  authDetail?: string;
  import?: string;
  setupSource?: 'manual' | 'import';
}

export interface ConnectionReadyState {
  name: string;
}

export interface RemoteSetupState {
  open: boolean;
  advancedOpen: boolean;
  url: string;
  token: string;
  busy: boolean;
  error: string | null;
}

export interface ConnMenuPoint {
  x: number;
  y: number;
}

export type LoadKey = 'secrets' | 'connections' | 'identity' | 'sessions' | 'activity'
  | 'settings' | 'elicitations' | 'approvals' | 'requests';

export interface LoadStatus {
  status: 'idle' | 'loading' | 'ready' | 'error';
  error?: string;
}

export interface WiringToolsState {
  connectionId: string;
  connectionName: string;
  loading: boolean;
  error?: string;
  tools?: McpToolInfo[];
  stale?: boolean;
  fetchedAt?: string;
  cacheAgeSeconds?: number;
  truncated?: boolean;
  selected: string[] | null;
  saving: boolean;
}

export interface McpStatusState {
  running: boolean;
  report?: McpStatusReport;
  error?: string;
}

export interface ConnectionTestState {
  running: boolean;
  ok?: boolean;
  detail?: string;
  kind?: TestErrorKind;
}

export interface AppState {
  tab: Tab;
  broker: BrokerProfile;
  brokerMenuOpen: boolean;
  remoteSetup: RemoteSetupState;
  localUsername: string;
  secrets: SecretSummary[];
  connections: ConnectionSummary[];
  identity: IdentityInfo | null;
  sessions: SessionSummary[];
  activity: ActivityEntry[];
  activityNextBefore: number | null;
  activityLoadingOlder: boolean;
  activityOlderError: string | null;
  elicitations: ElicitationRequest[];
  elicitValues: Record<string, string>;
  approvals: Approval[];
  requests: RequestRecord[];
  approvalAnswering: string | null;
  approvalHostKeyProvenance: {
    approvalId: string;
    loading: boolean;
    candidates: HostKeyCandidate[];
    error?: string;
  } | null;
  agentSetupInstructions: string;
  settings: Settings;
  notificationSettings: NotificationSettings;
  loadStatus: Record<LoadKey, LoadStatus>;
  reveal: Record<string, string>;
  epExpanded: Record<string, boolean>;
  sshSockets: Record<string, string>;
  sheet: SheetState | null;
  draft: ConnectionDraft;
  sheetErrors: Record<string, string>;
  sheetBaseline: string | null;
  confirmDiscard: boolean;
  formMenuOpen: string | null;
  connAdvancedOpen: boolean;
  connType: ConnectionType;
  connEntryName: string | null;
  connPreset: ConnectionPreset | null;
  confirm: ConfirmState | null;
  toolSearch: string;
  secretSearch: string;
  catalogActionMenuOpen: string | null;
  sectionsExpanded: string[];
  startOption: string;
  connectMode: string;
  /** Which hero-sentence blank has its menu open. */
  startMenuOpen: 'tool' | 'client' | null;
  /** A completed walkthrough step re-opened to show its body again. */
  startStepOpen: number | null;
  connImportSource: string;
  connImportError: string | null;
  menuOpen: boolean;
  agentMenuOpen: string | null;
  connMenuOpen: string | null;
  connMenuPoint: ConnMenuPoint | null;
  addToolOpen: boolean;
  selectedConn: string | null;
  connDetailOpen: boolean;
  copied: string | null;
  readyCopied: boolean;
  connectionReady: ConnectionReadyState | null;
  connTests: Record<string, ConnectionTestState>;
  draftTest: ConnectionTestState | null;
  draftTestOverride: boolean;
  mcpAuth: McpAuthState | null;
  mcpAuthDraft: McpAuthDraft | null;
  mcpAuthOpenedUrl: string | null;
  mcpStatus: Record<string, McpStatusState>;
  wiringTools: WiringToolsState | null;
  activityQuery: string;
  activityAgent: string | null;
  activityIssuesOnly: boolean;
  requestQuery: string;
  requestAgent: string | null;
  requestIssuesOnly: boolean;
  expandedRequests: string[];
}

export const DEFAULT_SETTINGS: Settings = {
  reauth_on_read: true,
  menu_bar_hides_dock: false,
  confirm_ssh_host_keys: false,
  presence_window_secs: 15 * 60,
};

const DEFAULT_NOTIFICATION_SETTINGS: NotificationSettings = {
  mode: 'when_hidden',
  showContext: false,
  playSound: true,
  timeSensitive: false,
  escalationSecs: 30,
  available: true,
  canOpenSystemSettings: false,
};

export const defaultLoadStatus = (): Record<LoadKey, LoadStatus> => ({
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

function createInitialState(): AppState {
  return {
    tab: 'connections',
    broker: LOCAL_BROKER,
    brokerMenuOpen: false,
    remoteSetup: {
      open: false, advancedOpen: false, url: '', token: '', busy: false, error: null,
    },
    localUsername: '',
    secrets: [],
    connections: [],
    identity: null,
    sessions: [],
    activity: [],
    activityNextBefore: null,
    activityLoadingOlder: false,
    activityOlderError: null,
    elicitations: [],
    elicitValues: {},
    approvals: [],
    requests: [],
    approvalAnswering: null,
    approvalHostKeyProvenance: null,
    agentSetupInstructions: '',
    settings: { ...DEFAULT_SETTINGS },
    notificationSettings: { ...DEFAULT_NOTIFICATION_SETTINGS },
    loadStatus: defaultLoadStatus(),
    reveal: {},
    epExpanded: {},
    sshSockets: {},
    sheet: null,
    draft: {},
    sheetErrors: {},
    sheetBaseline: null,
    confirmDiscard: false,
    formMenuOpen: null,
    connAdvancedOpen: false,
    connType: 'api',
    connEntryName: null,
    connPreset: null,
    confirm: null,
    toolSearch: '',
    secretSearch: '',
    catalogActionMenuOpen: null,
    sectionsExpanded: [],
    startOption: 'postgres',
    connectMode: 'direct',
    startMenuOpen: null,
    startStepOpen: null,
    connImportSource: '',
    connImportError: null,
    menuOpen: false,
    agentMenuOpen: null,
    connMenuOpen: null,
    connMenuPoint: null,
    addToolOpen: false,
    selectedConn: null,
    connDetailOpen: false,
    copied: null,
    readyCopied: false,
    connectionReady: null,
    connTests: {},
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
}

export const uiStore = new UiStore(createInitialState());
export const state = uiStore.state;

const EMPTY_SECRETS: SecretSummary[] = [];
const EMPTY_CONNECTIONS: ConnectionSummary[] = [];
const EMPTY_SESSIONS: SessionSummary[] = [];
const EMPTY_ELICITATIONS: ElicitationRequest[] = [];
const EMPTY_APPROVALS: Approval[] = [];
const EMPTY_REQUESTS: RequestRecord[] = [];

function bindQueryBackedField<K extends keyof AppState>(
  field: K,
  read: () => AppState[K],
  write: (value: AppState[K]) => void,
): void {
  Object.defineProperty(state, field, {
    configurable: false,
    enumerable: true,
    get: read,
    set: write,
  });
}

// Broker-owned resources live canonically in TanStack Query. Keeping these
// accessors on the existing state facade lets the action layer migrate
// incrementally without maintaining a second copy of each server response.
bindQueryBackedField(
  'secrets',
  () => getBrokerQueryData(state.broker, 'list_secrets') ?? EMPTY_SECRETS,
  (value) => setBrokerQueryData(state.broker, 'list_secrets', value),
);
bindQueryBackedField(
  'connections',
  () => getBrokerQueryData(state.broker, 'list_connections') ?? EMPTY_CONNECTIONS,
  (value) => setBrokerQueryData(state.broker, 'list_connections', value),
);
bindQueryBackedField(
  'identity',
  () => getBrokerQueryData(state.broker, 'get_identity') ?? null,
  (value) => {
    if (value === null) removeBrokerQueryData(state.broker, 'get_identity');
    else setBrokerQueryData(state.broker, 'get_identity', value);
  },
);
bindQueryBackedField(
  'sessions',
  () => getBrokerQueryData(state.broker, 'list_sessions') ?? EMPTY_SESSIONS,
  (value) => setBrokerQueryData(state.broker, 'list_sessions', value),
);
bindQueryBackedField(
  'elicitations',
  () => getBrokerQueryData(state.broker, 'list_elicitations') ?? EMPTY_ELICITATIONS,
  (value) => setBrokerQueryData(state.broker, 'list_elicitations', value),
);
bindQueryBackedField(
  'approvals',
  () => getBrokerQueryData(state.broker, 'list_approvals') ?? EMPTY_APPROVALS,
  (value) => setBrokerQueryData(state.broker, 'list_approvals', value),
);
bindQueryBackedField(
  'requests',
  () => getBrokerQueryData(state.broker, 'list_requests') ?? EMPTY_REQUESTS,
  (value) => setBrokerQueryData(state.broker, 'list_requests', value),
);
bindQueryBackedField(
  'settings',
  () => getBrokerQueryData(state.broker, 'get_settings') ?? DEFAULT_SETTINGS,
  (value) => setBrokerQueryData(state.broker, 'get_settings', value),
);
