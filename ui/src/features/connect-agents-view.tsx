// The Connect agents view. The hero is an editable sentence — “Connect
// to <tool> from <client>” — whose two blanks are the only choices the page asks
// for. Below it, the same three steps as always (add the tool, connect the
// agent, ask for something useful), all open all the time: status colors
// the badge — checked, current, upcoming — but never hides a step's
// contents, so the whole path is readable in one pass.

import { Fragment } from 'react';
import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { state } from '../app-state';
import { canQuickConnectMcp, catalogEntryById } from '../catalog';
import { EndpointStrip } from './endpoint-view';
import {
  CLI_INSTALL_COMMAND,
  CONNECT_MODE_LABELS,
  START_OPTIONS,
  clientMatchesLabel,
  connectClientById,
  connectModeSentenceLabel,
  connectModesFor,
  directEndpointAddress,
  directStartTask,
  redactedStartTask,
  resolveConnectMode,
  sshInvocationCommand,
  startAddAnotherLabel,
  startAddLead,
  startAddedLead,
  startOptionById,
  startProgress,
  startTask,
} from '../connect-agents';
import type {
  ConnectClientEnv,
  ConnectModeId,
  Platform,
  StartOption,
  StartProgress,
} from '../connect-agents';
import { AppIcon } from '../icon';
import { ICONS, relTime } from '../util';

function detectPlatform(): Platform {
  const ua = navigator.userAgent;
  if (ua.includes('Win')) return 'windows';
  if (ua.includes('Mac')) return 'macos';
  return 'linux';
}

function connectClientEnv(): ConnectClientEnv {
  return {
    socket: state.identity?.socket_path ?? '~/.aka/broker.sock',
    token: state.identity?.token_path ?? '~/.aka/token',
    platform: detectPlatform(),
  };
}

/** The latest activity timestamp per self-reported client label. */
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

/** When the chosen client last reached the broker, if it ever has. */
function clientSeenAt(connectMode: ConnectModeId): string | null {
  const client = connectClientById(connectMode);
  if (!client) return null;
  const seen = recentClients().find((recent) => clientMatchesLabel(client, recent.name));
  return seen ? seen.at : null;
}

/* ---- the hero sentence -------------------------------------------------- */

function ToolMenu({ option }: { option: StartOption }): ReactNode {
  return (
    <div className="start-menu" role="listbox" aria-label="What to connect">
      {START_OPTIONS.map((candidate) => (
        <button key={candidate.id} role="option" aria-selected={candidate.id === option.id}
          className={`start-menu-item ${candidate.id === option.id ? 'on' : ''}`}
          data-act="start-option" data-id={candidate.id}>
          <span className="start-menu-ico" aria-hidden="true">
            <AppIcon icon={ICONS[candidate.icon]} />
          </span>
          <span className="start-menu-name">{candidate.label}</span>
        </button>
      ))}
    </div>
  );
}

function ClientMenu({ option, connectMode }: {
  option: StartOption;
  connectMode: ConnectModeId;
}): ReactNode {
  return (
    <div className="start-menu start-menu-clients" role="listbox"
      aria-label="How your agent connects">
      {connectModesFor(option).map((mode, index) => {
        const client = connectClientById(mode);
        const sub = mode === 'direct'
          ? (option.connType === 'ssh'
              ? 'Connect via local SSH socket'
              : 'Connect via local Postgres endpoint')
          : client?.sub;
        // Rules split the menu into direct / named agents / escape hatches.
        const startsGroup = (mode === 'claude-code' && index > 0) || mode === 'mcp';
        return (
          <Fragment key={mode}>
            {/* Decorative inside the listbox: the option labels carry the
                grouping, and a listbox admits no separator child. */}
            {startsGroup ? <div className="start-menu-rule" aria-hidden="true" /> : null}
            <button role="option" aria-selected={mode === connectMode}
              className={`start-menu-item ${mode === connectMode ? 'on' : ''}`}
              data-act="start-mode" data-id={mode}>
              <span className="start-menu-tx">
                <span className="start-menu-name">{CONNECT_MODE_LABELS[mode]}</span>
                {sub ? <span className="start-menu-sub">{sub}</span> : null}
              </span>
            </button>
          </Fragment>
        );
      })}
    </div>
  );
}

/** The id of a blank's trigger button, so the keyboard handler in the shell
 *  can hand focus back to it when its menu closes. */
export function startBlankId(kind: 'tool' | 'client'): string {
  return `start-blank-${kind}`;
}

function SentenceBlank({ kind, label, menu }: {
  kind: 'tool' | 'client';
  label: string;
  menu: ReactNode;
}): ReactNode {
  const open = state.startMenuOpen === kind;
  const portalRoot = document.getElementById('overlays');
  return (
    <span className="start-blank-wrap">
      <button id={startBlankId(kind)} className={`start-blank ${open ? 'on' : ''}`}
        data-act="start-menu" data-id={kind}
        aria-haspopup="listbox" aria-expanded={open}>
        {label}
        <span className="start-blank-chev" aria-hidden="true">
          <AppIcon icon={ICONS.chevronDown} />
        </span>
      </button>
      {open && portalRoot
        ? createPortal(
            <div className="anchored-menu-portal start-menu-portal" data-start-menu-portal={kind}>
              {menu}
            </div>,
            portalRoot,
          )
        : null}
    </span>
  );
}

function StartSentence({ option, connectMode }: {
  option: StartOption;
  connectMode: ConnectModeId;
}): ReactNode {
  return (
    <div className="start-hero">
      <h3 className="start-sentence">
        {'Connect to '}
        <SentenceBlank kind="tool" label={option.label} menu={<ToolMenu option={option} />} />
        <span className="start-sentence-from">{' from '}</span>
        <SentenceBlank kind="client" label={connectModeSentenceLabel(connectMode, option)}
          menu={<ClientMenu option={option} connectMode={connectMode} />} />
      </h3>
    </div>
  );
}

/* ---- step 2's connect pane ---------------------------------------------- */

function StartConnectPane({ mode: connectMode, option, progress }: {
  mode: ConnectModeId;
  option: StartOption;
  progress: StartProgress;
}): ReactNode {
  const connection = progress.toolName
    ? state.connections.find((candidate) => candidate.name === progress.toolName) ?? null
    : null;
  const snippet = (text: string): ReactNode =>
    <pre className="setup-instructions"><code>{text}</code></pre>;
  const copyButton = (text: string, label: string): ReactNode =>
    <button className="btn primary sm" data-act="copy-text" data-text={text}>{label}</button>;

  if (connectMode === 'direct') {
    if (!connection) {
      const prerequisite = option.connType === 'pg'
        ? 'Add a Postgres database first.'
        : option.connType === 'ssh'
        ? 'Add an SSH server first.'
        : `Add a ${option.label} tool first.`;
      return <><p>{prerequisite}</p>
        <div className="start-actions"><button className="btn primary sm" disabled>
          Get connection address</button></div></>;
    }
    if (!connection.agent_access.endpoint) {
      const lead = connection.type === 'pg'
        ? `Get a local DSN for “${connection.name}” that any unmodified Postgres client can use — psql, drivers, ORMs.`
        : `Get a signing-agent socket for “${connection.name}”. Plain ssh, git, and rsync work unmodified; the private key never leaves this machine.`;
      return <><p>{lead}</p>
        <div className="start-actions"><button className="btn primary sm"
          data-act="issue-endpoint" data-conn={connection.id}>Get connection address</button></div></>;
    }
    const lead = connection.type === 'pg'
      ? 'Tell your agent to connect directly to this database.'
      : 'Tell your agent to connect directly to this server.';
    return <><p>{lead}</p><EndpointStrip connection={connection} /></>;
  }

  const client = connectClientById(connectMode);
  if (!client) return null;
  const env = connectClientEnv();
  if (client.paneSource === 'agent-setup') {
    return <><p>{client.lead(env)}</p>
      {snippet(state.agentSetupInstructions || 'Loading…')}
      <div className="start-actions"><button className="btn primary sm"
        data-act="copy-agent-setup">{client.copyLabel}</button></div></>;
  }
  const clientSnippet = client.snippet(env);
  if (client.requiresCli && !client.inlineCliInstall) {
    return <><p>Install the Multitool CLI:</p>
      {snippet(CLI_INSTALL_COMMAND)}
      <p className="start-pane-next">{client.lead(env)}</p>
      {snippet(clientSnippet)}
      <div className="start-actions">{copyButton(clientSnippet, client.copyLabel)}</div></>;
  }
  const text = client.inlineCliInstall
    ? `${CLI_INSTALL_COMMAND}\n${clientSnippet}`
    : clientSnippet;
  return <><p>{client.lead(env)}</p>{snippet(text)}
    <div className="start-actions">{copyButton(text, client.copyLabel)}</div></>;
}

/* ---- the steps ----------------------------------------------------------- */

type StepStatus = 'done' | 'now' | 'todo';

/**
 * Every step shows its body, whatever its status. The walkthrough is short
 * enough to read as one page, and a finished step's contents stay useful —
 * the address it issued, the prompt it built — so hiding them behind a
 * disclosure only costs a click. Status colors the badge; it no longer
 * decides what is visible.
 */
function StartStep({ number, status, title, body }: {
  number: number;
  status: StepStatus;
  title: ReactNode;
  body: ReactNode;
}): ReactNode {
  const badge = status === 'done'
    ? <span className="start-num" aria-hidden="true"><AppIcon icon={ICONS.check} /></span>
    : <span className="start-num" aria-hidden="true">{number}</span>;
  return (
    <li className={`start-step ${status}`}>
      {badge}
      <div className="start-body"><b>{title}</b>{body}</div>
    </li>
  );
}

function StartWalkthrough(): ReactNode {
  const option = startOptionById(state.startOption);
  const catalogEntry = option.catalogId ? catalogEntryById(option.catalogId) : undefined;
  const progress = startProgress(option, state.connections);
  const connectMode = resolveConnectMode(state.connectMode, option);
  const addAction = catalogEntry && canQuickConnectMcp(catalogEntry)
    ? 'catalog-connect-oauth' : 'catalog-add';
  const addVerb = addAction === 'catalog-connect-oauth' ? 'Connect' : 'Add';

  const directConnection = progress.toolName
    ? state.connections.find((candidate) => candidate.name === progress.toolName) ?? null
    : null;
  const directEndpoint = directConnection?.agent_access.endpoint ?? null;
  const directAddress = directConnection && directEndpoint
    ? directEndpointAddress(
        directConnection.type,
        directEndpoint,
        state.sshSockets[directConnection.id],
      )
    : null;

  const seenAt = connectMode === 'direct' ? null : clientSeenAt(connectMode);
  const step1Done = progress.added;
  const step2Done = connectMode === 'direct' ? Boolean(directEndpoint) : Boolean(seenAt);
  const clientLabel = CONNECT_MODE_LABELS[connectMode];

  const task = connectMode === 'direct'
    ? directStartTask(
        option,
        progress,
        directEndpoint
          ? {
              ...directEndpoint,
              dsn: directAddress,
              sshInvocation: directConnection?.type === 'ssh'
                ? sshInvocationCommand(directConnection)
                : null,
            }
          : null,
      )
    : startTask(option, progress);
  const shownTask = redactedStartTask(task);

  // A finished step keeps its action — a second workspace, a second database
  // — but loses the filled button: the eye should land on step 2, which is
  // what the user still has to do, not on a repeat of what they just did.
  const addBody = <>
    <p>{step1Done ? startAddedLead(option, progress) : startAddLead(option)}</p>
    <div className="start-actions">
      <button className={`btn ${step1Done ? '' : 'primary '}sm`}
        data-act={addAction} data-id={option.catalogId}>
        {step1Done
          ? startAddAnotherLabel(option, addVerb)
          : `${addVerb} ${option.label}`}
      </button>
    </div>
  </>;

  const connectBody = <>
    <StartConnectPane mode={connectMode} option={option} progress={progress} />
    {connectMode !== 'direct' && step1Done && !step2Done
      ? <div className="start-waiting">
          <span className="start-pulse" aria-hidden="true"></span>
          Waiting for {clientLabel} to connect to Multitool…
        </div>
      : null}
  </>;

  return (
    <ol className="start-steps">
      <StartStep number={1} status={step1Done ? 'done' : 'now'}
        title={step1Done
          ? `${option.label} connected`
          : `${addVerb} ${option.label}`}
        body={addBody} />
      <StartStep number={2}
        status={step2Done ? 'done' : step1Done ? 'now' : 'todo'}
        title={step2Done
          ? connectMode === 'direct'
            ? 'Direct address issued'
            : <>{clientLabel} connected · seen {relTime(seenAt as string)}</>
          : connectMode === 'direct'
            ? 'Connect your agent directly'
            : `Connect ${clientLabel}`}
        body={connectBody} />
      <StartStep number={3} status={step1Done && step2Done ? 'now' : 'todo'}
        title="Ask for something useful"
        body={<>
          <pre className="setup-instructions"><code>{shownTask}</code></pre>
          {shownTask !== task
            ? <p className="start-redact-note">The address stays redacted on screen — Copy
                carries the real one.</p>
            : null}
          <div className="start-actions"><button className="btn primary sm"
            data-act={connectMode === 'direct' && directConnection && directEndpoint
              ? 'copy-first-task'
              : 'copy-text'}
            data-conn={connectMode === 'direct' ? directConnection?.id : undefined}
            data-task={connectMode === 'direct' ? option.taskBody : undefined}
            data-text={connectMode === 'direct' ? undefined : task}>Copy prompt</button></div>
        </>} />
    </ol>
  );
}

export function StartViewPage({ globalSections }: {
  globalSections?: ReactNode;
}): ReactNode {
  const option = startOptionById(state.startOption);
  const connectMode = resolveConnectMode(state.connectMode, option);
  return (
    <div className="start">
      <StartSentence option={option} connectMode={connectMode} />
      {globalSections}
      <div className="start-view-body">
        <StartWalkthrough />
      </div>
    </div>
  );
}
