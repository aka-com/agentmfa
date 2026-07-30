import type { ReactNode } from 'react';
import { state } from '../app-state';
import { ENDPOINT_FORMATS } from '../endpoint-formats';
import { directEndpointAddress, sshDirectCommand } from '../getting-started';
import { AppIcon } from '../icon';
import type { ConnectionSummary, ConnectionType } from '../types';
import { ICONS } from '../util';

export const ENDPOINTABLE: Record<ConnectionType, boolean> = {
  pg: true,
  ssh: true,
  api: true,
};

export function maskedEndpoint(address: string): string {
  return address.replace(/(:\/\/[^:@/\s]*:)[^@\s]+(?=@)/, '$1******');
}

function BreakableAddress({ address }: { address: string }): ReactNode {
  const parts = address.split(/(?<=[/?&@:=])(?![/?&@:=])/);
  return <>{parts.map((part, index) => (
    <span key={`${index}:${part}`}>{index ? <wbr /> : null}{part}</span>
  ))}</>;
}

function EndpointFormatRow({ connection, address }: {
  connection: ConnectionSummary;
  address: string;
}): ReactNode {
  const formats = ENDPOINT_FORMATS[connection.type].filter(
    (format) =>
      format.needsSecret || format.needsAltAddress || format.build(connection, address) != null,
  );
  if (!formats.length) return null;
  return (
    <div className="ep-formats" role="group" aria-label="Copy the connection for other applications">
      <span className="ep-formats-lbl">Copy for</span>
      {formats.map((format) => {
        const copied = state.copied === `epf:${connection.id}:${format.key}`;
        return <button key={format.key}
          className={`btn sm ep-fmt ${copied ? 'is-copied' : ''}`} title={format.title}
          aria-label={`${copied ? 'Copied. ' : ''}${format.title} for ${connection.name}`}
          data-act="copy-endpoint-format" data-conn={connection.id} data-format={format.key}>
          <span className="ep-fmt-label">{format.label}</span>
          {copied
            ? <span className="ep-fmt-check" aria-hidden="true">
                <AppIcon icon={ICONS.check} />
              </span>
            : null}
        </button>;
      })}
    </div>
  );
}

export function EndpointStrip({ connection: c, withFormats = false }: {
  connection: ConnectionSummary;
  withFormats?: boolean;
}): ReactNode {
  if (!c.agent_access.enabled || !ENDPOINTABLE[c.type]) return null;
  const endpoint = c.agent_access.endpoint ?? null;
  if (!endpoint) {
    return <div className="ep-strip">
      <button className="btn primary sm" data-act="issue-endpoint" data-conn={c.id}
        title="A pasteable address for an unmodified tool">Get connection address…</button>
    </div>;
  }
  const copied = state.copied === `ep:${c.id}`;
  const expanded = Boolean(state.epExpanded[c.id]);
  const endpointAddress = directEndpointAddress(c.type, endpoint, state.sshSockets[c.id]);
  const endpointText = endpointAddress
    ? c.type === 'ssh'
      ? sshDirectCommand(endpointAddress, c, Boolean(endpoint.require_auth))
      : endpointAddress
    : null;
  const copyTitle = c.type === 'ssh' ? 'Copy the SSH command' : 'Copy the connection command';
  const copyButton = endpointText
    ? <button className="btn sm ep-copy" title={copyTitle}
        aria-label={`${copyTitle} for ${c.name}`} data-act="copy-endpoint-dsn" data-conn={c.id}>
        {copied
          ? <><AppIcon icon={ICONS.check} /> Copied</>
          : <><AppIcon icon={ICONS.copy} /> Copy</>}
      </button>
    : null;
  let address: ReactNode;
  if (!endpointText) {
    address = <span className="ep-addr ep-addr-hidden">Connection address unavailable</span>;
  } else if (expanded) {
    address = <div className="ep-field">
      <code className="ep-addr"><BreakableAddress address={endpointText} /></code>
      {copyButton}
    </div>;
  } else {
    address = <div className="ep-field collapsed">
      <button className="ep-addr ep-addr-masked" title="Show the full address"
        aria-label={`Show the full connection address for ${c.name}`}
        aria-expanded={false} data-act="expand-endpoint" data-conn={c.id}>
        {maskedEndpoint(endpointText)}
      </button>
      {copyButton}
    </div>;
  }
  return <>
    <div className="ep-strip">{address}</div>
    {withFormats && endpointText && endpointAddress
      ? <EndpointFormatRow connection={c} address={endpointAddress} />
      : null}
    <EndpointAuthRow connection={c} />
  </>;
}

/**
 * Whether this SSH endpoint's agent socket makes callers prove they hold the
 * endpoint secret.
 *
 * SSH is the only kind that needs asking. Postgres and HTTP endpoints present
 * their secret as part of connecting, but the ssh-agent protocol has no field
 * for one — so without this the socket is authorized by whoever can open it,
 * and its unguessable filename is the only thing standing between a
 * same-machine process and a login as the pinned user.
 *
 * Off by default, because turning it on is a real trade: stock `ssh` cannot
 * send the extension, so an authenticated endpoint has to be reached through
 * `mfa ssh-agent` rather than by naming the socket.
 */
function EndpointAuthRow({ connection: c }: { connection: ConnectionSummary }): ReactNode {
  const endpoint = c.agent_access.endpoint;
  if (c.type !== 'ssh' || !endpoint) return null;
  const on = Boolean(endpoint.require_auth);
  return <div className="cd-confirm-row cd-ep-auth">
    <div className="cd-confirm-txt">
      <div className="cd-confirm-lbl">Require the endpoint secret</div>
      <div className="cd-confirm-sub">
        {on
          ? 'The signing socket refuses to list keys or sign until the caller presents this '
            + 'endpoint’s secret. Reach it with the mfa ssh-agent command above.'
          : 'Any process running as you that finds the signing socket can log in as the '
            + 'pinned user. The ssh-agent protocol carries no password of its own.'}
      </div>
    </div>
    <button className={`switch ${on ? 'on' : ''}`} role="switch" aria-checked={on}
      title={on ? 'The socket requires the endpoint secret' : 'The socket requires no secret'}
      aria-label={`${on ? 'Stop requiring' : 'Require'} the endpoint secret for ${c.name}`}
      data-act={on ? 'endpoint-auth-off' : 'endpoint-auth-on'} data-conn={c.id}></button>
  </div>;
}

export function ConnectionToggle({ connection: c }: {
  connection: ConnectionSummary;
}): ReactNode {
  const enabled = c.agent_access.enabled;
  return <button className={`switch ${enabled ? 'on' : ''}`} role="switch"
    aria-checked={enabled}
    title={enabled ? 'Agents may use this tool' : 'Agents may not use this tool'}
    aria-label={`${enabled ? 'Disable' : 'Enable'} ${c.name} for agents`}
    data-act={enabled ? 'disable-tool' : 'enable-tool'} data-conn={c.id}></button>;
}
