export type ConnectionType = 'api' | 'pg' | 'ws' | 'ssh';

export interface SecretSummary {
  id: string;
  name: string;
  used_by: number;
  used_by_names: string[];
  created_at: string;
  updated_at: string;
}

/**
 * A connection's agent access. There is one shared local identity, so this
 * is a property of the connection — one setting covers every agent.
 */
export interface AgentAccess {
  /** Whether agents may use the connection (default true). */
  enabled: boolean;
  /**
   * Whether traffic asks the user when no approval window is open (default
   * false). What one decision gates depends on the kind: one request for an
   * API tool, one `tools/call` for an MCP tool, one session for Postgres.
   */
  confirm?: boolean;
  /**
   * While an approval window is open, the RFC 3339 time it lapses — so the
   * panel can say why nothing is being asked right now.
   */
  confirm_window_until?: string | null;
  /** Curated upstream MCP tool subset; absent means all tools. */
  allowed_tools?: string[] | null;
  /**
   * The direct endpoint issued for this connection, if any. Its presence
   * flips the row's control from "Issue" to "Reissue / Revoke". `dsn` is the
   * pasteable address (including the retained Postgres endpoint credential)
   * or, for SSH, the stable agent-socket path.
   */
  endpoint?: { endpoint_id: string; type: ConnectionType; dsn?: string | null } | null;
}

/**
 * The result of issuing a direct endpoint: the pasteable address, a
 * ready-to-run example, and the secret (empty for SSH, whose socket path is
 * the whole capability). The secret is retained on the endpoint, so the
 * row's chip DSN keeps carrying it after this sheet closes.
 */
export interface IssuedEndpoint {
  endpoint_id: string;
  type: ConnectionType;
  dsn: string;
  secret: string;
  example: string;
}

export interface ConnectionSummary {
  id: string;
  name: string;
  type: ConnectionType;
  /** Set when an API upstream speaks MCP at that path. */
  mcp_path?: string | null;
  /**
   * The upstream account this connection's credential was last verified as
   * (an MCP whoami answer). Display metadata — it tells two connections to
   * the same service apart; it is never authorization.
   */
  account?: string | null;
  target: string;
  secret_names: string[];
  /** True when the broker injects and refreshes a vault-backed OAuth grant. */
  oauth: boolean;
  agent_access: AgentAccess;
  host: string | null;
  scheme: string | null;
  port: number | null;
  template: string | null;
  dbname: string | null;
  user: string | null;
  host_key_fingerprint: string | null;
  destination: string | null;
  sslmode: string | null;
  url: string | null;
  trusted_ca_bundle_path: string | null;
  /** Set when the credential is a BYO-app OAuth token set (never tokens). */
  oauth_spec?: { auth_url: string; token_url: string; client_id: string; scopes: string[] } | null;
  /**
   * Last-known health, learned passively (brokered calls) and from tests
   * and status checks: 'ok' | 'failed' | 'needs_reconnect'. All absent
   * while untested.
   */
  last_status?: 'ok' | 'failed' | 'needs_reconnect' | null;
  last_detail?: string | null;
  last_checked_at?: string | null;
}

/** The shared broker identity ("this computer's key") — never the key itself. */
export interface IdentityInfo {
  client_id: string;
  /** Where the plaintext key lives (`~/.aka/token`). */
  token_path: string;
  /** The broker socket, for the Connect page's setup snippets. */
  socket_path: string;
  minted_at: string;
  last_used: string;
  /** Legacy per-agent tokens still working as aliases (cleared by rotation). */
  legacy_aliases: number;
}

export interface SessionSummary {
  id: number;
  type: ConnectionType;
  agent: string;
  connection: string;
  detail: string;
  opened_at: string;
}

export interface ActivityEntry {
  icon: string;
  tone: string;
  text: string;
  detail: string | null;
  /** Which agent acted / which connection was touched, when attributable. */
  agent?: string | null;
  connection?: string | null;
  /** Brokered call / session duration, when measured. */
  duration_ms?: number | null;
  /** How a gated action was authorized ("os_authentication",
   * "management_token", …), when one was. */
  confirmation?: string | null;
  at: string;
}

/**
 * One input the upstream asked for (SEP-2322 `InputRequiredResult`).
 *
 * DESIGN MOCK — the broker does not produce these yet. The shape mirrors
 * what `/v1/elicitations` is proposed to return; see ELICITATION.md.
 */
export interface ElicitationField {
  name: string;
  label: string;
  /** Render as a password field; the value is sent upstream, never shown again. */
  secret?: boolean;
}

/** A paused upstream MCP tool call waiting on the user (SEP-2322). */
export interface ElicitationRequest {
  id: string;
  /** Agent whose tool call is paused. It cannot see this prompt or its answer. */
  agent: string;
  /** Connection (upstream MCP server) that asked. */
  connection: string;
  /** The MCP tool name the agent called. */
  tool: string;
  /** The upstream's own prompt, shown verbatim but never interpreted. */
  prompt: string;
  fields: ElicitationField[];
  requested_at: string;
  /** The request disappears on its own at this time. */
  expires_at: string;
}

/**
 * Agent traffic parked on the user: it goes nowhere until this is answered
 * (or until it lapses, when the call is refused).
 *
 * Unlike an elicitation — the upstream asking the *agent* something — this
 * is AgentMFA asking the *user* whether the traffic should happen at all.
 * It is answered here and never through the agent.
 */
export interface Approval {
  id: string;
  connection_id: string;
  connection: string;
  /** Connection kind, so the prompt can name the unit it is asking about. */
  type: ConnectionType;
  /** Exact traffic unit; absent when connected to an older broker. */
  unit?: 'request' | 'tool' | 'session' | null;
  /** The pinned destination the traffic would reach. */
  target: string;
  /** Self-reported agent label. Attribution, never authorization. */
  agent: string;
  /** The headline: `GET /user/repos`, `search_issues`, `New Postgres session`. */
  summary: string;
  /** A body preview, a tool's arguments, or the client's application name. */
  detail?: string | null;
  /** How many calls are riding this one prompt. */
  waiting: number;
  requested_at: string;
  /** When it gives up on its own and the parked traffic is refused. */
  expires_at: string;
  /** How long "approve for now" lasts, so the button can name it. */
  window_secs: number;
}

/** One request decision lifecycle through its terminal disposition. */
export interface RequestRecord {
  id: string;
  /** Extensible request family; approvals are the broker producer today. */
  kind: 'approval' | 'elicitation';
  status: 'pending' | 'approved' | 'denied' | 'expired' | 'revoked'
    | 'unavailable' | 'abandoned';
  connection_id?: string | null;
  connection: string;
  connection_type?: ConnectionType | null;
  unit?: 'request' | 'tool' | 'session' | null;
  target?: string | null;
  agent: string;
  summary: string;
  detail?: string | null;
  waiting: number;
  requested_at: string;
  expires_at?: string | null;
  resolved_at?: string | null;
  resolution?: string | null;
  window_secs?: number | null;
}

/** What the user chose on a prompt. */
export type ApprovalDecision = 'approve_window' | 'approve_all' | 'deny';

/**
 * Which broker this app manages and the state of the link to it. Local
 * mode is always connected (the broker runs in-process); remote mode
 * reflects the manage-API link.
 */
export interface BrokerProfile {
  mode: 'local' | 'remote';
  url: string | null;
  connected: boolean;
  error: string | null;
  /** A saved management token exists for `url`. */
  has_saved_token: boolean;
}

export interface Settings {
  reauth_on_read: boolean;
  show_websockets: boolean;
  menu_bar_hides_dock: boolean;
  /** Seconds one OS authentication keeps user-plane actions from re-prompting. */
  presence_window_secs: number;
}

/** Native request notifications are local to this desktop shell. */
export interface NotificationSettings {
  mode: 'off' | 'when_hidden' | 'always';
  /** Include agent and connection names, never request summaries/details. */
  showContext: boolean;
}

export interface HostKeyCandidate {
  fingerprint: string;
  algorithm: string;
  source: string;
}

export interface SshImportPreview {
  importId: string;
  destination: string;
  host: string;
  port: number;
  user: string;
  proxyJump: string | null;
  identityFiles: string[];
  hostKeyCandidates: HostKeyCandidate[];
  warnings: string[];
}

export interface ConnectionInput {
  name: string;
  type: ConnectionType;
  secret_id?: string | null;
  new_secret_name?: string | null;
  new_secret_value?: string | null;
  ssh_import_id?: string | null;
  identity_file?: string | null;
  destination?: string | null;
  host?: string | null;
  scheme?: string | null;
  port?: number | null;
  /** Set when this API upstream speaks MCP at that path. */
  mcp_path?: string | null;
  // BYO-app OAuth (plain REST rows): non-secret provider coordinates.
  oauth_auth_url?: string | null;
  oauth_token_url?: string | null;
  oauth_client_id?: string | null;
  oauth_scopes?: string[] | null;
  oauth_extra_params?: Array<[string, string]> | null;
  template?: string | null;
  dbname?: string | null;
  user?: string | null;
  host_key_fingerprint?: string | null;
  sslmode?: string | null;
  trusted_ca_bundle_path?: string | null;
  url?: string | null;
}

/** Why a connection test failed, as the broker serializes it. The detail
 * prose is presentation only — branch on this, never on the text. */
export type TestErrorKind =
  | 'unreachable'
  | 'tls_declined'
  | 'cert_unverified'
  | 'needs_password'
  | 'auth_rejected'
  | 'wrong_protocol'
  | 'timeout'
  | 'other';

// Pass/fail summary of a broker-side service connectivity test.
export interface ConnectionTestReport {
  ok: boolean;
  detail: string;
  /** Present on failures. */
  kind?: TestErrorKind;
}

/* ------------------------------- MCP types -------------------------------- */

/** What the UI submits to start (or restart) an MCP sign-in. */
export interface McpAuthDraft {
  name: string;
  scheme: string;
  host: string;
  port?: number | null;
  mcp_path: string;
  /** Re-authenticate an existing connection instead of creating one. */
  reauth_connection_id?: string | null;
  whoami_tool?: string | null;
  /** Pre-registered OAuth client, for servers without dynamic registration. */
  oauth_client_id?: string | null;
  oauth_client_secret?: string | null;
  /** Scopes to request instead of everything the resource advertises. */
  oauth_scope?: string | null;
  /** Extra authorize-URL params (e.g. Google's access_type=offline). */
  extra_auth_params?: Array<[string, string]>;
}

/** One step of the sign-in flow, tagged the way the broker serializes it. */
export type McpAuthPhase =
  | { phase: 'probing' }
  | { phase: 'discovering' }
  | { phase: 'registering' }
  | { phase: 'awaiting_authorization'; authorization_url: string }
  | { phase: 'exchanging' }
  | { phase: 'verifying' }
  | {
      phase: 'succeeded';
      connection_id: string;
      connection_name: string;
      account?: string;
      expires_in?: number;
      warning?: string;
    }
  | { phase: 'failed'; message: string; hint?: string }
  | { phase: 'cancelled' };

export type McpAuthState = {
  /** Auth-session id (not a connection id). */
  id: string;
  name: string;
  target: string;
  updated_at: string;
} & McpAuthPhase;

export interface McpResourceInfo {
  uri: string;
  name: string;
  description?: string;
}

/** Broker-side MCP status check result. Never credential material. */
export interface McpStatusReport {
  ok: boolean;
  detail: string;
  /** The server answered but refused the credential (401/403). The broker
   * already tried a silent token refresh before reporting this, so seeing
   * it means Reconnect is the remaining remedy. */
  credential_rejected?: boolean;
  server?: string;
  protocol_version?: string;
  account?: string;
  tools: string[];
  resources_supported: boolean;
  resources: McpResourceInfo[];
}

export interface McpCheckOptions {
  whoami_tool?: string | null;
}

/** One upstream tool, as the per-wiring tool picker lists it. */
export interface McpToolInfo {
  name: string;
  description?: string;
}

interface CommandSpec<Args, Result> {
  args: Args;
  result: Result;
}

export interface CommandMap {
  get_local_username: CommandSpec<undefined, string>;
  get_broker_profile: CommandSpec<undefined, BrokerProfile>;
  connect_remote_broker: CommandSpec<{ url: string; token?: string | null }, BrokerProfile>;
  retry_remote_broker: CommandSpec<undefined, BrokerProfile>;
  switch_broker_local: CommandSpec<undefined, BrokerProfile>;
  list_secrets: CommandSpec<undefined, SecretSummary[]>;
  list_connections: CommandSpec<undefined, ConnectionSummary[]>;
  get_identity: CommandSpec<undefined, IdentityInfo>;
  list_sessions: CommandSpec<undefined, SessionSummary[]>;
  list_activity: CommandSpec<{ limit: number }, ActivityEntry[]>;
  clear_activity: CommandSpec<undefined, void>;
  get_settings: CommandSpec<undefined, Settings>;
  get_notification_settings: CommandSpec<undefined, NotificationSettings>;
  set_notification_settings: CommandSpec<{
    settings: NotificationSettings;
  }, NotificationSettings>;
  get_agent_setup: CommandSpec<undefined, string>;
  copy_agent_setup: CommandSpec<undefined, void>;
  inspect_ssh_import: CommandSpec<{ source: string }, SshImportPreview>;
  check_known_hosts: CommandSpec<{ host: string; port: number }, HostKeyCandidate[]>;
  add_secret: CommandSpec<{ name: string; value: string }, void>;
  edit_secret: CommandSpec<{
    id: string;
    newName?: string | null;
    newValue?: string | null;
  }, void>;
  delete_secret: CommandSpec<{ id: string }, void>;
  reveal_secret_prefix: CommandSpec<{ id: string }, string>;
  copy_secret: CommandSpec<{ id: string }, void>;
  add_connection: CommandSpec<{ input: ConnectionInput }, void>;
  edit_connection: CommandSpec<{ id: string; input: ConnectionInput }, void>;
  delete_connection: CommandSpec<{ id: string }, void>;
  reorder_connections: CommandSpec<{ orderedIds: string[] }, void>;
  test_connection: CommandSpec<{ id: string }, ConnectionTestReport>;
  test_connection_draft: CommandSpec<{ input: ConnectionInput }, ConnectionTestReport>;
  start_mcp_auth: CommandSpec<{ input: McpAuthDraft }, McpAuthState>;
  get_mcp_auth: CommandSpec<{ id: string }, McpAuthState | null>;
  cancel_mcp_auth: CommandSpec<{ id: string }, boolean>;
  mcp_status: CommandSpec<{ id: string; options?: McpCheckOptions | null }, McpStatusReport>;
  set_allowed_tools: CommandSpec<{ connectionId: string; tools?: string[] | null }, boolean>;
  list_mcp_tools: CommandSpec<{ id: string }, McpToolInfo[]>;
  oauth_connect: CommandSpec<{ input: ConnectionInput; clientSecret?: string | null }, void>;
  oauth_reconnect: CommandSpec<{ id: string }, void>;
  open_url: CommandSpec<{ url: string }, void>;
  set_tool_access: CommandSpec<{ connectionId: string; enabled: boolean }, boolean>;
  set_confirm_mode: CommandSpec<{ connectionId: string; on: boolean }, boolean>;
  list_approvals: CommandSpec<undefined, Approval[]>;
  list_requests: CommandSpec<undefined, RequestRecord[]>;
  respond_approval: CommandSpec<{ id: string; decision: ApprovalDecision }, boolean>;
  issue_endpoint: CommandSpec<{ connectionId: string }, IssuedEndpoint>;
  get_endpoint: CommandSpec<{ connectionId: string }, IssuedEndpoint | null>;
  revoke_endpoint: CommandSpec<{ endpointId: string }, boolean>;
  rotate_key: CommandSpec<undefined, void>;
  copy_key: CommandSpec<undefined, void>;
  close_session: CommandSpec<{ id: number }, boolean>;
  list_elicitations: CommandSpec<undefined, ElicitationRequest[]>;
  respond_elicitation: CommandSpec<{
    id: string;
    approved: boolean;
    /** Field name -> value; required when approved, forbidden otherwise. */
    values?: Record<string, string>;
  }, void>;
  set_reauth_on_read: CommandSpec<{ on: boolean }, void>;
  set_show_websockets: CommandSpec<{ on: boolean }, void>;
  set_menu_bar_hides_dock: CommandSpec<{ on: boolean }, void>;
  set_presence_window: CommandSpec<{ secs: number }, void>;
  ui_set_mode: CommandSpec<{ mode: string }, void>;
  ui_hide_main: CommandSpec<undefined, void>;
  ui_hide_dropdown: CommandSpec<undefined, void>;
  ui_set_dropdown_form_active: CommandSpec<{ active: boolean }, void>;
  ui_take_open_requests: CommandSpec<undefined, boolean>;
}

export type CommandName = keyof CommandMap;
export type CommandArgs<K extends CommandName> = CommandMap[K]['args'];
export type CommandResult<K extends CommandName> = CommandMap[K]['result'];

export interface EventMap {
  'aka://broker-changed': BrokerProfile;
  'aka://activity-appended': ActivityEntry;
  'aka://activity-changed': Record<string, never>;
  'aka://agents-changed': Record<string, never>;
  'aka://connections-changed': Record<string, never>;
  'aka://wirings-changed': Record<string, never>;
  'aka://sessions-changed': Record<string, never>;
  'aka://elicitations-changed': Record<string, never>;
  'aka://approvals-changed': Record<string, never>;
  'aka://settings-changed': Record<string, never>;
  'aka://mcp-auth-changed': McpAuthState;
  'aka://connect-requested': { agent: string; service: string };
  'aka://open-settings': Record<string, never>;
  'aka://open-requests': Record<string, never>;
  'aka://notification-settings-changed': NotificationSettings;
  'aka://dropdown-hidden': Record<string, never>;
  'aka://dropdown-shown': Record<string, never>;
}

export type EventName = keyof EventMap;
export interface EventPayload<T> {
  event: string;
  payload: T;
}

export type Unlisten = () => void;

declare global {
  interface Window {
    __TAURI__?: {
      core: {
        invoke(command: string, args?: Record<string, unknown>): Promise<unknown>;
      };
      event: {
        listen(
          event: string,
          callback: (event: EventPayload<unknown>) => void,
        ): Promise<Unlisten>;
      };
    };
    tippy?: {
      delegate(
        target: string,
        options: Record<string, unknown>,
      ): void;
    };
  }
}
