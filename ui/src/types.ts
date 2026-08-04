export type ConnectionType = 'api' | 'pg' | 'ssh';

export interface SecretSummary {
  id: string;
  name: string;
  used_by: number;
  used_by_names: string[];
  created_at: string;
  updated_at: string;
  source?:
    | { kind: 'local' }
    | {
        kind: 'one_password';
        integration_id: string;
        integration_label: string;
        vault_id: string;
        vault_label: string;
        item_id: string;
        item_label: string;
        section_id?: string | null;
        section_label?: string | null;
        field_id: string;
        field_label: string;
        field_type?: string | null;
      };
}

export interface OnePasswordIntegration {
  id: string;
  label: string;
  kind: 'desktop_app' | 'service_account' | 'connect';
  account?: string | null;
  connect_url?: string | null;
  created_at: string;
  updated_at: string;
}

export interface OnePasswordHealth {
  ok: boolean;
  detail: string;
}

export interface OnePasswordVault {
  id: string;
  title: string;
  item_count: number;
}

export interface OnePasswordItem {
  id: string;
  title: string;
  category?: string | null;
  /** Present only when the UI aggregates items from several vaults. */
  vault_id?: string;
  vault_title?: string;
}

export interface OnePasswordField {
  id: string;
  title: string;
  section_id?: string | null;
  section_title?: string | null;
  field_type: string;
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
   * API tool, one `tools/call` for an MCP tool, one session for Postgres,
   * one login for SSH.
   */
  confirm?: boolean;
  /** Whether HTTP tools relay upstream credential-bearing response headers (default true). */
  expose_response_credentials?: boolean;
  /**
   * While an approval window is open, the RFC 3339 time the last of them
   * lapses — so the panel can say why nothing is being asked right now.
   */
  confirm_window_until?: string | null;
  /**
   * Which agents those windows cover. An approval is scoped to the agent the
   * prompt named, so the panel names them: other agents are still asked.
   */
  confirm_window_agents?: string[] | null;
  /**
   * While a denial's cooldown runs, the RFC 3339 time it lifts. Retries
   * during it are refused without a fresh prompt, and the panel says so.
   */
  confirm_cooldown_until?: string | null;
  /** Curated upstream MCP tool subset; absent means all tools. */
  allowed_tools?: string[] | null;
  /**
   * Per-connection override for recording Postgres statement text; absent
   * means the broker-wide default applies.
   */
  audit_statements?: boolean | null;
  /** What that resolves to, override or default — what the row renders. */
  audit_statements_effective?: boolean;
  /**
   * The direct endpoint issued for this connection, if any. Its presence
   * flips the row's control from "Issue" to "Reissue / Revoke". `dsn` is the
   * pasteable address (including the retained Postgres endpoint credential)
   * or, for SSH, the stable agent-socket path.
   */
  endpoint?: {
    endpoint_id: string;
    type: ConnectionType;
    dsn?: string | null;
    /**
     * SSH only: the agent socket refuses to list or sign until the caller
     * presents the endpoint secret. Changes what the row can say — such a
     * socket is reached through `multitool ssh-agent`, not by pointing
     * `IdentityAgent` straight at the path.
     */
    require_auth?: boolean;
    /** Absolute deadline plus broker-clock remainder for remote brokers. */
    expires_at: string;
    expires_in_secs?: number | null;
  } | null;
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
  /** Second address for the same endpoint (Postgres: the TCP form). */
  tcp_dsn?: string | null;
  secret: string;
  example: string;
  expires_at: string;
  expires_in_secs?: number | null;
}

/** A dispatch-time request signer, mirrored from `SignerDto`. The populated
 * fields follow the algorithm: `aws_sigv4` carries region/service and the
 * AWS refs; `gcp_service_account` carries `key_ref` and `scope`. */
export interface SignerInfo {
  algorithm: string;
  region?: string;
  service?: string;
  access_key_ref?: string;
  secret_key_ref?: string;
  session_token_ref?: string | null;
  key_ref?: string | null;
  scope?: string | null;
}

export interface ConnectionSummary {
  id: string;
  name: string;
  /** Opaque version returned unchanged when replacing this connection. */
  updated_at: string;
  type: ConnectionType;
  /** Set when an API upstream speaks MCP at that path. */
  mcp_path?: string | null;
  /** The path the Test button probes instead of the origin root. */
  test_path?: string | null;
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
  trusted_ca_bundle_path: string | null;
  /** Set when the credential is a BYO-app OAuth token set (never tokens). */
  oauth_spec?: { auth_url: string; token_url: string; client_id: string; scopes: string[] } | null;
  /**
   * Set when the connection signs each request at dispatch time (AWS SigV4)
   * instead of injecting a template. Credential references only — the key
   * material never reaches the webview.
   */
  signer?: SignerInfo | null;
  /** PEM client-certificate chain presented on the upstream TLS leg. */
  client_cert_path?: string | null;
  /** PEM private key for client_cert_path. */
  client_key_path?: string | null;
  /**
   * Last-known health, learned passively (brokered calls) and from tests
   * and status checks: 'ok' | 'warning' | 'failed' |
   * 'needs_reconnect'. All absent while untested.
   */
  last_status?: 'ok' | 'warning' | 'failed' | 'needs_reconnect' | null;
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
  /** Older keys still accepted inside a bounded recovery window. */
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
  /** Stable audit event classification (`denied`, `session_closed`, …). */
  kind?: string | null;
  text: string;
  detail: string | null;
  /** Which agent acted / which connection was touched, when attributable. */
  agent?: string | null;
  connection?: string | null;
  outcome?: string | null;
  protocol?: string | null;
  /** Brokered call / session duration, when measured. */
  duration_ms?: number | null;
  /** Decision provenance. A remote approver is the directly connected
   * socket peer (often a reverse proxy), not an authenticated person. */
  approver?: string | null;
  surface?: 'app_window' | 'cli' | 'remote' | 'harness' | null;
  /** How a gated action was authorized ("os_authentication",
   * "management_token", …), when one was. */
  confirmation?: string | null;
  at: string;
}

export interface ActivityPage {
  entries: ActivityEntry[];
  /** Opaque broker cursor; pass back unchanged to fetch the next older page. */
  next_before?: number | null;
}

/**
 * One input the upstream asked for (SEP-2322 `InputRequiredResult`).
 *
 * Mirrors `ElicitationFieldDto` returned by `/v1/manage/elicitations`.
 */
export interface ElicitationField {
  name: string;
  label: string;
  /** Whether the field appears in the schema object's `required` array.
   * Absent from brokers that predate the flag — treated as required (the UI
   * they shipped against required every field); only an explicit `false`
   * makes a field optional. */
  required?: boolean;
  /** A JSON Schema `boolean`: render a toggle; the answer is sent as a real boolean. */
  boolean?: boolean;
  /** A fixed set of choices (a JSON Schema `enum`): render a dropdown. */
  options?: string[];
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
  /**
   * The schema asked for something credential-shaped. Fields are plain text
   * either way — nothing an upstream declares produces a masked input — so
   * this drives a warning, never the rendering.
   */
  credential_warning?: boolean;
  requested_at: string;
  /** The request disappears on its own at this time. */
  expires_at: string;
  /** Seconds left on the broker's clock when this snapshot was built; the
   * bridge re-anchors `expires_at` from it so countdowns survive skew. */
  expires_in_secs?: number | null;
}

/**
 * Agent traffic parked on the user: it goes nowhere until this is answered
 * (or until it lapses, when the call is refused).
 *
 * Unlike an elicitation — the upstream asking the *agent* something — this
 * is Multitool asking the *user* whether the traffic should happen at all.
 * It is answered here and never through the agent.
 */
export interface Approval {
  id: string;
  connection_id: string;
  connection: string;
  /** Connection kind, so the prompt can name the unit it is asking about. */
  type: ConnectionType;
  /** Exact traffic unit; absent when connected to an older broker. */
  unit?: 'request' | 'tool' | 'session' | 'login' | 'host_key' | null;
  /** The pinned destination the traffic would reach. */
  target: string;
  /** Self-reported agent label. Attribution, never authorization. */
  agent: string;
  /** The headline: `GET /user/repos`, `search_issues`, `New Postgres session`. */
  summary: string;
  /** A body preview, a tool's arguments, or the client's application name. */
  detail?: string | null;
  /** Saved credential names only; credential values never reach the UI. */
  credential_names?: string[];
  /** Structured HTTP operation fields; never reconstructed from summary. */
  method?: string | null;
  path?: string | null;
  /** First-seen SSH host key being considered for a durable pin. */
  host_key_fingerprint?: string | null;
  /**
   * What approving hands over, written by the broker rather than derived from
   * the request. Render it in the broker's own voice, outside the block that
   * shows the agent's text — a Postgres session carries every statement the
   * client sends, not just the one that raised the prompt.
   */
  consequence?: string | null;
  /** How many calls are riding this one prompt. */
  waiting: number;
  requested_at: string;
  /** When it gives up on its own and the parked traffic is refused. */
  expires_at: string;
  /** Seconds left on the broker's clock when this snapshot was built; the
   * bridge re-anchors `expires_at` from it so countdowns survive skew. */
  expires_in_secs?: number | null;
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
  unit?: 'request' | 'tool' | 'session' | 'login' | 'host_key' | null;
  target?: string | null;
  agent: string;
  summary: string;
  detail?: string | null;
  credential_names?: string[];
  method?: string | null;
  path?: string | null;
  host_key_fingerprint?: string | null;
  waiting: number;
  requested_at: string;
  expires_at?: string | null;
  /** Seconds left on the broker's clock, present only while pending. */
  expires_in_secs?: number | null;
  resolved_at?: string | null;
  resolution?: string | null;
  window_secs?: number | null;
}

/** What the user chose on a prompt. */
export type ApprovalDecision = 'approve_window' | 'approve_all' | 'deny';

/**
 * Which broker this app manages and the state of the link to it. Local
 * Local mode normally runs in-process, but `connected` still reflects
 * whether its command surface answered. Remote mode reflects the manage-API
 * link.
 */
export interface BrokerProfile {
  mode: 'local' | 'remote';
  url: string | null;
  connected: boolean;
  error: string | null;
  /** A saved management token exists for `url`. */
  has_saved_token: boolean;
  /** Optional management features advertised by the active broker. */
  capabilities: string[];
}

export interface Settings {
  menu_bar_hides_dock: boolean;
  /** Ask before trusting a first-seen SSH host key. */
  confirm_ssh_host_keys: boolean;
}

/** Native request notifications are local to this desktop shell. */
export interface NotificationSettings {
  mode: 'off' | 'when_hidden' | 'always';
  /** Include agent and connection names, never request summaries/details. */
  showContext: boolean;
  /** Play the operating system's default notification sound. */
  playSound: boolean;
  /** Ask the operating system for time-sensitive delivery through Focus/DND. */
  timeSensitive: boolean;
  /** Seconds before a still-waiting request surfaces the Inbox; zero is off. */
  escalationSecs: 0 | 15 | 30 | 60;
  /** Runtime platform health; preferences can still be edited when false. */
  available: boolean;
  unavailableReason?: string;
  canOpenSystemSettings: boolean;
  canRequestPermission: boolean;
}

export interface HostKeyCandidate {
  fingerprint: string;
  algorithm: string;
  source: string;
}

export interface KnownHostsLookup {
  candidates: HostKeyCandidate[];
  /** Revoked keys are evidence, never candidates a form may offer to pin. */
  revokedFingerprints: string[];
  /** A CA entry cannot corroborate a concrete key without certificate verification. */
  hasCertificateAuthority: boolean;
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
  /**
   * Passphrase for an encrypted SSH private key. Spent by the backend to
   * decrypt the key at import; the vault stores the unlocked OpenSSH form, and
   * the passphrase is neither stored nor echoed back.
   */
  key_passphrase?: string | null;
  destination?: string | null;
  host?: string | null;
  scheme?: string | null;
  port?: number | null;
  /** Set when this API upstream speaks MCP at that path. */
  mcp_path?: string | null;
  /** The path the Test button probes instead of the origin root. */
  test_path?: string | null;
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
  // API dispatch-time signer: non-secret coordinates plus vault credential
  // *references* — the four required parts are all-or-nothing.
  signer_region?: string | null;
  signer_service?: string | null;
  signer_access_key_ref?: string | null;
  signer_secret_key_ref?: string | null;
  signer_session_token_ref?: string | null;
  // GCP service-account signer (mutually exclusive with the SigV4 fields):
  // vaulted JSON-key reference plus the OAuth scope.
  signer_gcp_key_ref?: string | null;
  signer_gcp_scope?: string | null;
  // Upstream mTLS paths, both-or-neither (store-enforced).
  client_cert_path?: string | null;
  client_key_path?: string | null;
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
  trusted_ca_bundle_path?: string | null;
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
  truncated?: boolean;
}

export interface McpCheckOptions {
  whoami_tool?: string | null;
}

/** One upstream tool, as the per-wiring tool picker lists it. */
export interface McpToolInfo {
  /** Exact upstream identifier used for the policy selection. */
  name: string;
  /** Display-safe form when the identifier contains invisible text or was capped. */
  display_name?: string;
  description?: string;
}

export interface McpToolCatalog {
  tools: McpToolInfo[];
  truncated: boolean;
  stale: boolean;
  fetched_at: string;
  cache_age_seconds: number;
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
  list_onepassword_integrations: CommandSpec<undefined, OnePasswordIntegration[]>;
  add_onepassword_integration: CommandSpec<{
    label: string;
    method: 'desktop_app' | 'service_account' | 'connect';
    account?: string | null;
    connectUrl?: string | null;
    token?: string | null;
  }, OnePasswordIntegration>;
  replace_onepassword_token: CommandSpec<
    { id: string; token: string },
    OnePasswordIntegration
  >;
  delete_onepassword_integration: CommandSpec<{ id: string }, void>;
  onepassword_health: CommandSpec<{ id: string }, OnePasswordHealth>;
  list_onepassword_vaults: CommandSpec<{ id: string }, OnePasswordVault[]>;
  list_onepassword_items: CommandSpec<
    { id: string; vaultId: string },
    OnePasswordItem[]
  >;
  list_onepassword_fields: CommandSpec<
    { id: string; vaultId: string; itemId: string },
    OnePasswordField[]
  >;
  add_onepassword_secret: CommandSpec<{
    name: string;
    integrationId: string;
    vaultId: string;
    vaultLabel: string;
    itemId: string;
    itemLabel: string;
    sectionId?: string | null;
    sectionLabel?: string | null;
    fieldId: string;
    fieldLabel: string;
    fieldType?: string;
  }, SecretSummary>;
  list_connections: CommandSpec<undefined, ConnectionSummary[]>;
  get_identity: CommandSpec<undefined, IdentityInfo>;
  list_sessions: CommandSpec<undefined, SessionSummary[]>;
  list_activity: CommandSpec<{ limit: number; before?: number | null }, ActivityPage>;
  clear_activity: CommandSpec<undefined, void>;
  get_settings: CommandSpec<undefined, Settings>;
  get_notification_settings: CommandSpec<undefined, NotificationSettings>;
  set_notification_settings: CommandSpec<{
    settings: NotificationSettings;
  }, NotificationSettings>;
  request_notification_permission: CommandSpec<undefined, NotificationSettings>;
  open_notification_settings: CommandSpec<undefined, void>;
  get_autostart: CommandSpec<undefined, boolean>;
  set_autostart: CommandSpec<{ on: boolean }, boolean>;
  get_agent_setup: CommandSpec<undefined, string>;
  copy_agent_setup: CommandSpec<undefined, void>;
  inspect_ssh_import: CommandSpec<{ source: string }, SshImportPreview>;
  check_known_hosts: CommandSpec<{ host: string; port: number }, KnownHostsLookup>;
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
  edit_connection: CommandSpec<{
    id: string;
    expectedUpdatedAt: string;
    input: ConnectionInput;
  }, void>;
  delete_connection: CommandSpec<{ id: string }, void>;
  reorder_connections: CommandSpec<{ orderedIds: string[] }, void>;
  test_connection: CommandSpec<{ id: string }, ConnectionTestReport>;
  test_connection_draft: CommandSpec<{ input: ConnectionInput }, ConnectionTestReport>;
  start_mcp_auth: CommandSpec<{ input: McpAuthDraft }, McpAuthState>;
  get_mcp_auth: CommandSpec<{ id: string }, McpAuthState | null>;
  cancel_mcp_auth: CommandSpec<{ id: string }, boolean>;
  mcp_status: CommandSpec<{ id: string; options?: McpCheckOptions | null }, McpStatusReport>;
  set_allowed_tools: CommandSpec<{ connectionId: string; tools?: string[] | null }, boolean>;
  set_audit_statements: CommandSpec<
    { connectionId: string; auditStatements?: boolean | null },
    boolean
  >;
  set_endpoint_require_auth: CommandSpec<
    { connectionId: string; requireAuth: boolean },
    boolean
  >;
  list_mcp_tools: CommandSpec<{ id: string }, McpToolCatalog>;
  oauth_connect: CommandSpec<{ input: ConnectionInput; clientSecret?: string | null }, void>;
  oauth_reconnect: CommandSpec<{ id: string }, void>;
  open_url: CommandSpec<{ url: string }, void>;
  set_tool_access: CommandSpec<{ connectionId: string; enabled: boolean }, boolean>;
  set_confirm_mode: CommandSpec<{ connectionId: string; on: boolean }, boolean>;
  set_expose_response_credentials: CommandSpec<
    { connectionId: string; expose: boolean },
    boolean
  >;
  list_approvals: CommandSpec<undefined, Approval[]>;
  list_requests: CommandSpec<undefined, RequestRecord[]>;
  respond_approval: CommandSpec<{ id: string; decision: ApprovalDecision }, boolean>;
  issue_endpoint: CommandSpec<{ connectionId: string }, IssuedEndpoint>;
  renew_endpoint: CommandSpec<{ connectionId: string }, IssuedEndpoint>;
  set_endpoint_expiry: CommandSpec<{ connectionId: string; expire: boolean }, IssuedEndpoint>;
  get_endpoint: CommandSpec<{ connectionId: string }, IssuedEndpoint | null>;
  copy_endpoint_text: CommandSpec<
    { connectionId: string; format: string; taskBody?: string },
    void
  >;
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
  }, boolean>;
  set_menu_bar_hides_dock: CommandSpec<{ on: boolean }, void>;
  set_confirm_ssh_host_keys: CommandSpec<{ on: boolean }, void>;
  ui_set_mode: CommandSpec<{ mode: string }, void>;
  ui_hide_main: CommandSpec<undefined, void>;
  ui_hide_dropdown: CommandSpec<undefined, void>;
  ui_set_dropdown_form_active: CommandSpec<{ active: boolean }, void>;
  ui_set_request_inbox_visible: CommandSpec<{ visible: boolean }, void>;
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
  'aka://secrets-changed': Record<string, never>;
  'aka://integrations-changed': Record<string, never>;
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
