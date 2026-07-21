export type ConnectionType = 'api' | 'pg' | 'ws' | 'ssh';

export interface SecretSummary {
  id: string;
  name: string;
  used_by: number;
  used_by_names: string[];
  created_at: string;
  updated_at: string;
}

/** One agent wired to a connection. */
export interface WiringSummary {
  agent_id: string;
  agent: string;
  /** Curated upstream MCP tool subset for this agent; absent means all. */
  allowed_tools?: string[] | null;
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
  wired_agents: WiringSummary[];
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
  /**
   * Last-known health, learned passively (brokered calls) and from tests
   * and status checks: 'ok' | 'failed' | 'needs_reconnect'. All absent
   * while untested.
   */
  last_status?: 'ok' | 'failed' | 'needs_reconnect' | null;
  last_detail?: string | null;
  last_checked_at?: string | null;
}

export interface AgentSummary {
  id: string;
  name: string;
  paired_at: string;
  last_used: string;
  wiring_count: number;
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

export interface Settings {
  reauth_on_read: boolean;
  show_websockets: boolean;
  menu_bar_hides_dock: boolean;
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
  template?: string | null;
  dbname?: string | null;
  user?: string | null;
  host_key_fingerprint?: string | null;
  sslmode?: string | null;
  trusted_ca_bundle_path?: string | null;
  url?: string | null;
}

// Pass/fail summary of a broker-side service connectivity test.
export interface ConnectionTestReport {
  ok: boolean;
  detail: string;
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
  expected_tools?: string[];
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
  missing_tools: string[];
  resources_supported: boolean;
  resources: McpResourceInfo[];
}

export interface McpCheckOptions {
  whoami_tool?: string | null;
  expected_tools?: string[];
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
  list_secrets: CommandSpec<undefined, SecretSummary[]>;
  list_connections: CommandSpec<undefined, ConnectionSummary[]>;
  list_agents: CommandSpec<undefined, AgentSummary[]>;
  list_sessions: CommandSpec<undefined, SessionSummary[]>;
  list_activity: CommandSpec<{ limit: number }, ActivityEntry[]>;
  clear_activity: CommandSpec<undefined, void>;
  get_settings: CommandSpec<undefined, Settings>;
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
  test_connection: CommandSpec<{ id: string }, ConnectionTestReport>;
  start_mcp_auth: CommandSpec<{ input: McpAuthDraft }, McpAuthState>;
  get_mcp_auth: CommandSpec<{ id: string }, McpAuthState | null>;
  cancel_mcp_auth: CommandSpec<{ id: string }, boolean>;
  mcp_status: CommandSpec<{ id: string; options?: McpCheckOptions | null }, McpStatusReport>;
  set_wiring_tools: CommandSpec<
    { agentId: string; connectionId: string; tools?: string[] | null },
    boolean
  >;
  list_mcp_tools: CommandSpec<{ id: string }, McpToolInfo[]>;
  open_url: CommandSpec<{ url: string }, void>;
  set_wiring: CommandSpec<{
    agentId: string;
    connectionId: string;
    wired: boolean;
  }, boolean>;
  confirm_agent_disconnect: CommandSpec<undefined, boolean>;
  revoke_agent: CommandSpec<{ id: string }, boolean>;
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
  ui_set_mode: CommandSpec<{ mode: string }, void>;
  ui_hide_main: CommandSpec<undefined, void>;
  ui_hide_dropdown: CommandSpec<undefined, void>;
  ui_set_dropdown_form_active: CommandSpec<{ active: boolean }, void>;
}

export type CommandName = keyof CommandMap;
export type CommandArgs<K extends CommandName> = CommandMap[K]['args'];
export type CommandResult<K extends CommandName> = CommandMap[K]['result'];

export interface EventMap {
  'aka://activity-appended': ActivityEntry;
  'aka://activity-changed': Record<string, never>;
  'aka://agents-changed': Record<string, never>;
  'aka://connections-changed': Record<string, never>;
  'aka://wirings-changed': Record<string, never>;
  'aka://sessions-changed': Record<string, never>;
  'aka://elicitations-changed': Record<string, never>;
  'aka://settings-changed': Record<string, never>;
  'aka://mcp-auth-changed': McpAuthState;
  'aka://open-settings': Record<string, never>;
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
