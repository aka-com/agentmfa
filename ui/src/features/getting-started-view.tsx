import type { ReactNode } from 'react';
import { state } from '../app-state';
import type { StartView } from '../app-state';
import { canQuickConnectMcp, catalogEntryById } from '../catalog';
import { EndpointStrip } from './endpoint-view';
import {
  CLI_INSTALL_COMMAND,
  CONNECT_CLIENTS,
  CONNECT_MODE_LABELS,
  START_OPTIONS,
  clientMatchesLabel,
  connectClientById,
  connectGuideSteps,
  connectModesFor,
  directEndpointAddress,
  directStartTask,
  resolveConnectMode,
  sshInvocationCommand,
  startKindLabel,
  startOptionById,
  startProgress,
  startTask,
} from '../getting-started';
import type {
  ConnectClient,
  ConnectClientEnv,
  ConnectModeId,
  ConnectStep,
  Platform,
  StartOption,
  StartProgress,
} from '../getting-started';
import { AppIcon } from '../icon';
import type { IdentityInfo } from '../types';
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

function ConnectKeyCard({ identity }: { identity: IdentityInfo }): ReactNode {
  const menuOpen = state.agentMenuOpen === 'identity';
  const copied = state.copied === 'shared-key';
  return (
    <div className="agent-block">
      <div className="agent-card">
        <span className="agent-avatar" role="img" aria-label="This computer's key">
          <AppIcon icon={ICONS.fileKey} />
        </span>
        <div className="agent-id"><div className="c-name">This computer’s key</div>
          <div className="s-sub agent-sub">{identity.token_path}
            {identity.legacy_aliases
              ? ` · ${identity.legacy_aliases} older key${identity.legacy_aliases === 1 ? '' : 's'} still accepted briefly`
              : ''}
          </div>
        </div>
        <button className="btn sm" data-act="copy-key">
          {copied ? <><AppIcon icon={ICONS.check} /> Copied</> : 'Copy key'}
        </button>
        <div className="agent-menu-wrap">
          <button className={`icon-btn agent-menu-btn ${menuOpen ? 'on' : ''}`}
            title="Key options" aria-label="Key options" aria-haspopup="menu"
            aria-expanded={menuOpen} data-act="toggle-agent-menu" data-id="identity">
            <AppIcon icon={ICONS.ellipsis} />
          </button>
          {menuOpen
            ? <div className="agent-menu" role="menu" aria-label="Key options">
                <button className="menu-item danger" role="menuitem" data-act="rotate-key-ask">
                  <AppIcon icon={ICONS.unplug} /> Rotate key…
                </button>
              </div>
            : null}
        </div>
      </div>
      <div className="connect-keynote">One shared key for everything that runs as you on this
        computer. Rotating it disconnects every agent at once.</div>
    </div>
  );
}

function ConnectStepView({ step, number }: {
  step: ConnectStep;
  number: number;
}): ReactNode {
  return (
    <div className="connect-step">
      <span className="connect-step-n" aria-hidden="true">{number}</span>
      <div className="connect-step-bd"><b>{step.title}</b>
        {step.detail ? <div className="connect-step-d">{step.detail}</div> : null}
        {step.snippet
          ? <div className="connect-snip"><pre><code>{step.snippet}</code></pre>
              <button className="btn sm connect-copy" data-act="copy-text"
                data-text={step.snippet}>Copy</button>
            </div>
          : null}
        {step.followup
          ? <div className="connect-step-d connect-step-followup">{step.followup}</div>
          : null}
      </div>
    </div>
  );
}

function ConnectCard({ client, env }: {
  client: ConnectClient;
  env: ConnectClientEnv;
}): ReactNode {
  const open = state.connectOpen === client.id;
  const seen = recentClients().find((recent) => clientMatchesLabel(client, recent.name));
  return (
    <div className={`agent-block connect-card ${open ? 'open' : ''}`}>
      <button className="connect-row" data-act="connect-toggle" data-id={client.id}
        aria-expanded={open}>
        <span className={`connect-mark ${client.id}`} aria-hidden="true">
          {client.icon ? <AppIcon icon={ICONS[client.icon]} /> : client.mark}
        </span>
        <span className="connect-tx"><b>{client.name}</b><span>{client.sub}</span></span>
        {seen
          ? <span className="connect-seen" title="An agent using this label reached the broker">
              ● seen {relTime(seen.at)}
            </span>
          : null}
        <span className={`cat-chev ${open ? 'open' : ''}`}>
          <AppIcon icon={ICONS.chevronDown} />
        </span>
      </button>
      {open
        ? <div className="connect-steps">
            {connectGuideSteps(client, env).map((step, index) =>
              <ConnectStepView key={`${client.id}:${index}`} step={step} number={index + 1} />)}
            {client.note ? <div className="connect-note">{client.note}</div> : null}
          </div>
        : null}
    </div>
  );
}

function RecentClients(): ReactNode {
  const clients = recentClients();
  if (!clients.length) return null;
  return <>
    <div className="connect-sec-lbl">Recently seen</div>
    <div className="agent-block"><div className="connect-recent">
      {clients.map((client) => <div key={client.name} className="connect-recent-row">
        <code>{client.name}</code><span className="grow"></span>
        <span className="s-sub">{relTime(client.at)}</span>
      </div>)}
    </div>
    <div className="connect-keynote">Names are labels agents report about themselves for the
      activity log — they aren’t identities, and access doesn’t depend on them.</div></div>
  </>;
}

function ConnectGuides(): ReactNode {
  const identity = state.identity;
  if (!identity) return null;
  const env = connectClientEnv();
  return <>
    <ConnectKeyCard identity={identity} />
    <div className="connect-sec-lbl">Connect an agent</div>
    {CONNECT_CLIENTS.map((client) => <ConnectCard key={client.id} client={client} env={env} />)}
    <RecentClients />
  </>;
}

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
    return <><p>Install the AgentMFA CLI:</p>
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

function StartViewToggle(): ReactNode {
  const button = (view: StartView, label: string): ReactNode => (
    <button className={`seg-btn ${state.startView === view ? 'on' : ''}`}
      aria-pressed={state.startView === view} data-act="start-view" data-id={view}>{label}</button>
  );
  return <div className="start-view-toggle"><div className="seg" role="group"
    aria-label="Get started view">
    {button('walkthrough', 'Quick start')}{button('guides', 'Agent guides')}
  </div></div>;
}

function StartWalkthrough(): ReactNode {
  const option = startOptionById(state.startOption);
  const catalogEntry = option.catalogId ? catalogEntryById(option.catalogId) : undefined;
  const progress = startProgress(option, state.connections);
  const connectMode = resolveConnectMode(state.connectMode, option);
  const addAction = catalogEntry && canQuickConnectMcp(catalogEntry)
    ? 'catalog-connect-oauth' : 'catalog-add';
  const optionKind = startKindLabel(option);
  const optionName = optionKind ? `${option.label} ${optionKind}` : option.label;
  const addLabel = progress.added ? `${optionName} Connected` : `Add ${optionName}`;
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
  const step = (number: number, title: string, done: boolean, body: ReactNode): ReactNode => (
    <li className={`start-step ${done ? 'done' : ''}`}>
      <span className="start-num" aria-hidden="true">{number}</span>
      <div className="start-body"><b>{title}</b>{body}</div>
    </li>
  );
  return (
    <ol className="start-steps">
      {step(1, 'Select a tool to connect', progress.added, <>
        <p>AgentMFA supports databases, SSH, APIs, and MCPs.</p>
        <div className="start-picker" role="group" aria-label="What to connect">
          {START_OPTIONS.map((candidate) => {
            const candidateEntry = candidate.catalogId
              ? catalogEntryById(candidate.catalogId) : undefined;
            const kind = startKindLabel(candidate);
            const fullLabel = kind ? `${candidate.label} ${kind}` : candidate.label;
            return <button key={candidate.id}
              className={`start-pick ${candidate.showPickerLabel ? 'has-label' : ''} ${
                candidate.id === option.id ? 'on' : ''}`}
              aria-pressed={candidate.id === option.id} aria-label={fullLabel} title={fullLabel}
              data-act="start-option" data-id={candidate.id}>
              <span className="start-pick-icon" aria-hidden="true">
                <AppIcon icon={ICONS[candidate.icon]} />
              </span>
              {candidate.showPickerLabel
                ? <span className="start-pick-label">{candidate.label}</span> : null}
              {candidateEntry?.limitedSupport
                ? <span className="start-pick-limited">Limited</span> : null}
            </button>;
          })}
        </div>
        <div className="start-actions">
          <button className="btn primary sm" data-act={addAction} data-id={option.catalogId}
            disabled={progress.added}>{addLabel}</button>
        </div>
      </>)}
      {step(2, 'Connect your agent', recentClients().length > 0, <>
        <div className="start-picker" role="group" aria-label="How your agent connects">
          {connectModesFor(option).map((candidate) => (
            <button key={candidate}
              className={`start-pick has-label ${candidate === connectMode ? 'on' : ''}`}
              aria-pressed={candidate === connectMode} data-act="start-mode" data-id={candidate}>
              <span className="start-pick-label">{CONNECT_MODE_LABELS[candidate]}</span>
            </button>
          ))}
        </div>
        <StartConnectPane mode={connectMode} option={option} progress={progress} />
      </>)}
      {step(3, 'Ask for something useful', progress.wired, <>
        <pre className="setup-instructions"><code>{task}</code></pre>
        <div className="start-actions"><button className="btn primary sm"
          data-act="copy-text" data-text={task}>Copy</button></div>
      </>)}
    </ol>
  );
}

export function StartViewPage({ globalSections }: {
  globalSections?: ReactNode;
}): ReactNode {
  return (
    <div className="start">
      <div className="start-hero"><h3>Connect your agent to tools and services</h3></div>
      <StartViewToggle />
      {globalSections}
      <div className="start-view-body">
        {state.startView === 'guides'
          ? <ConnectGuides />
          : <StartWalkthrough />}
      </div>
    </div>
  );
}
