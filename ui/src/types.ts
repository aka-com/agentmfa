export type ConnectionType = 'api' | 'pg' | 'ws' | 'ssh';
export type PermissionScope = 'read' | 'full';
export type Decision = 'deny' | 'allow_once' | 'allow_session' | 'always_allow';

export interface SecretSummary {
  id: string;
  name: string;
  used_by: number;
  used_by_names: string[];
  created_at: string;
  updated_at: string;
}

export interface PermissionSummary {
  id: string;
  agent: string;
  scope: PermissionScope;
  expires_at: string | null;
}

export interface ConnectionSummary {
  id: string;
  name: string;
  type: ConnectionType;
  target: string;
  secret_names: string[];
  permissions: PermissionSummary[];
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
  program: string;
  verification: string;
  identity: string;
  paired_at: string;
  last_used: string;
  permission_count: number;
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
  show_service_walkthrough: boolean;
  show_agent_walkthrough: boolean;
}

export interface PairingIdentity {
  program: string;
  verification: string;
  technical: string;
  warning: string | null;
}

export interface ApprovalConnection {
  id: string;
  name: string;
  type: ConnectionType;
  target: string;
}

export interface InheritedConnection {
  name: string;
  type: ConnectionType;
  target: string;
}

export interface HttpPayloadView {
  method: string;
  path: string;
  headers: Array<[string, string]>;
  body_preview: string | null;
  body_len: number;
  body_truncated: boolean;
  mutating: boolean;
}

export interface TemporaryAccess {
  scope: PermissionScope;
  duration_seconds: number;
}

export interface ApprovalRequest {
  id: string;
  agent: string;
  kind: 'pair' | 'http' | 'ws' | 'pg' | 'ssh';
  connection: ApprovalConnection | null;
  action: string;
  notification: string;
  received_at: string;
  deadline: string;
  identity: string | null;
  pairing_identity: PairingIdentity | null;
  replaces_existing_agent: boolean;
  inherited: InheritedConnection[];
  http: HttpPayloadView | null;
  temporary_access: TemporaryAccess | null;
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
  get_queue: CommandSpec<undefined, ApprovalRequest[]>;
  get_settings: CommandSpec<undefined, Settings>;
  get_agent_setup: CommandSpec<undefined, string>;
  get_broker_instructions: CommandSpec<undefined, string>;
  copy_agent_setup: CommandSpec<undefined, void>;
  inspect_ssh_import: CommandSpec<{ source: string }, SshImportPreview>;
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
  remove_permission: CommandSpec<{ id: string }, boolean>;
  revoke_agent: CommandSpec<{ id: string }, boolean>;
  close_session: CommandSpec<{ id: number }, boolean>;
  set_reauth_on_read: CommandSpec<{ on: boolean }, void>;
  set_menu_bar_hides_dock: CommandSpec<{ on: boolean }, void>;
  set_service_walkthrough_visible: CommandSpec<{ on: boolean }, void>;
  set_agent_walkthrough_visible: CommandSpec<{ on: boolean }, void>;
  decide: CommandSpec<{
    id: string;
    decision: Decision;
    revokeInheritedRules?: boolean;
  }, void>;
  ui_set_mode: CommandSpec<{ mode: string }, void>;
  ui_hide_main: CommandSpec<undefined, void>;
  ui_hide_dropdown: CommandSpec<undefined, void>;
  ui_show_approval: CommandSpec<undefined, void>;
}

export type CommandName = keyof CommandMap;
export type CommandArgs<K extends CommandName> = CommandMap[K]['args'];
export type CommandResult<K extends CommandName> = CommandMap[K]['result'];

export interface EventMap {
  'amfa://activity-appended': ActivityEntry;
  'amfa://activity-changed': Record<string, never>;
  'amfa://agents-changed': Record<string, never>;
  'amfa://connections-changed': Record<string, never>;
  'amfa://queue-changed': ApprovalRequest[];
  'amfa://rules-changed': Record<string, never>;
  'amfa://sessions-changed': Record<string, never>;
  'amfa://settings-changed': Record<string, never>;
  'amfa://open-settings': Record<string, never>;
  'amfa://dropdown-hidden': Record<string, never>;
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
    __mockApproval?: (kind?: 'http' | 'post' | 'pair', ttlMs?: number) => void;
    tippy?: {
      delegate(
        target: string,
        options: Record<string, unknown>,
      ): void;
    };
  }
}
