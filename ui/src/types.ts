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
}

export interface ConnectionSummary {
  id: string;
  name: string;
  type: ConnectionType;
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

export interface Settings {
  reauth_on_read: boolean;
  menu_bar_hides_dock: boolean;
  show_agent_walkthrough: boolean;
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
  get_broker_instructions: CommandSpec<undefined, string>;
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
  set_wiring: CommandSpec<{
    agentId: string;
    connectionId: string;
    wired: boolean;
  }, boolean>;
  confirm_agent_disconnect: CommandSpec<undefined, boolean>;
  revoke_agent: CommandSpec<{ id: string }, boolean>;
  close_session: CommandSpec<{ id: number }, boolean>;
  set_reauth_on_read: CommandSpec<{ on: boolean }, void>;
  set_menu_bar_hides_dock: CommandSpec<{ on: boolean }, void>;
  set_agent_walkthrough_visible: CommandSpec<{ on: boolean }, void>;
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
  'aka://settings-changed': Record<string, never>;
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
