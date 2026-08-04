import type { ReactNode } from 'react';
import { state } from '../app-state';
import { ENDPOINT_FORMATS } from '../endpoint-formats';
import { endpointExpired, expiredAgoLabel } from '../endpoint-expiry';
import { directEndpointAddress, sshDirectCommand } from '../connect-agents';
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

/** The formats a connection's endpoint can be copied as, beyond the raw
 * address. Empty when nothing but the address applies. */
function copyFormats(connection: ConnectionSummary, address: string) {
  return ENDPOINT_FORMATS[connection.type].filter(
    (format) =>
      format.needsSecret || format.needsAltAddress || format.build(connection, address) != null,
  );
}

/** One Copy ▾ control: the plain address first, then every format the kind
 * supports. Replaces the wrapping chip row — one button, a menu of targets. */
function EndpointCopyMenu({ connection: c, address, copyTitle }: {
  connection: ConnectionSummary;
  address: string;
  copyTitle: string;
}): ReactNode {
  const formats = copyFormats(c, address);
  const open = state.epMenuOpen === c.id;
  const copied = state.copied === `ep:${c.id}`
    || formats.some((format) => state.copied === `epf:${c.id}:${format.key}`);
  return <div className="ep-copy-wrap">
    <button className="btn sm ep-copy" title={copyTitle}
      aria-label={`${copyTitle} for ${c.name}`} aria-haspopup="menu" aria-expanded={open}
      data-act="toggle-ep-menu" data-conn={c.id}>
      {copied
        ? <><AppIcon icon={ICONS.check} /> Copied</>
        : <><AppIcon icon={ICONS.copy} /> Copy <AppIcon icon={ICONS.chevronDown} /></>}
    </button>
    {open
      ? <div className="tile-menu ep-copy-menu" role="menu"
          aria-label={`Copy formats for ${c.name}`}>
          <button className="menu-item" role="menuitem"
            data-act="copy-endpoint-dsn" data-conn={c.id}>
            {c.type === 'ssh' ? 'SSH command' : 'Connection address'}
          </button>
          {formats.map((format) => (
            <button key={format.key} className="menu-item" role="menuitem" title={format.title}
              data-act="copy-endpoint-format" data-conn={c.id} data-format={format.key}>
              {format.label}
            </button>
          ))}
        </div>
      : null}
  </div>;
}

/**
 * Lifecycle actions for an issued direct endpoint: renew (when expiry is
 * opted in), rotate, revoke. Lives on the "Connect to this…" section label
 * rather than the tool's general ⋯ menu so address management stays next to
 * the address itself.
 */
export function EndpointOptionsMenu({ connection: c }: {
  connection: ConnectionSummary;
}): ReactNode {
  const endpoint = c.agent_access.endpoint;
  if (!endpoint || !ENDPOINTABLE[c.type]) return null;
  const open = state.epOptsMenuOpen === c.id;
  const expired = endpointExpired(endpoint.expires_at, endpoint.expires_in_secs);
  const expiryDate = new Date(endpoint.expires_at);
  // Empty expires_at means expiry is off (the default) — no date or Renew.
  const expiryOn = Boolean(endpoint.expires_at) && !Number.isNaN(expiryDate.getTime());
  const dateLabel = expiryOn
    ? `${expired ? 'Expired' : 'Expires'} ${expiryDate.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      })}`
    : null;
  return <div className="tile-menu-wrap ep-opts-wrap">
    <button className={`icon-btn tile-menu-btn ${open ? 'on' : ''}`}
      title="Connection address options"
      aria-label={`Connection address options for ${c.name}`}
      aria-haspopup="menu" aria-expanded={open}
      data-act="toggle-ep-opts-menu" data-conn={c.id}>
      <AppIcon icon={ICONS.ellipsis} />
    </button>
    {open
      ? <div className="tile-menu ep-opts-menu" role="menu"
          aria-label={`Connection address options for ${c.name}`}>
          {dateLabel
            ? <div className="menu-meta" role="presentation">{dateLabel}</div>
            : null}
          {expiryOn
            ? <button className="menu-item" role="menuitem"
                data-act="renew-endpoint" data-conn={c.id}>
                <AppIcon icon={ICONS.clockAlert} /> Renew connection address
              </button>
            : null}
          {!expired
            ? <button className="menu-item" role="menuitem"
                data-act="reissue-endpoint-ask" data-conn={c.id}>
                <AppIcon icon={ICONS.refresh} /> Rotate connection address
              </button>
            : null}
          <button className="menu-item danger" role="menuitem"
            data-act="revoke-endpoint-ask" data-conn={c.id}>
            <AppIcon icon={ICONS.x} /> Revoke connection address
          </button>
        </div>
      : null}
  </div>;
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
  const expired = endpointExpired(endpoint.expires_at, endpoint.expires_in_secs);
  // Future deadlines live in the section's ⋯ menu. The strip only surfaces
  // a problem: the address has already stopped working.
  const expiredLabel = expired
    ? expiredAgoLabel(endpoint.expires_at, endpoint.expires_in_secs)
    : '';
  const expanded = Boolean(state.epExpanded[c.id]);
  const endpointAddress = directEndpointAddress(c.type, endpoint, state.sshSockets[c.id]);
  const endpointText = endpointAddress
    ? c.type === 'ssh'
      ? sshDirectCommand(endpointAddress, c, Boolean(endpoint.require_auth))
      : endpointAddress
    : null;
  const copyTitle = c.type === 'ssh' ? 'Copy the SSH command' : 'Copy the connection command';
  const copyButton = endpointText && !expired
    ? withFormats && endpointAddress
      ? <EndpointCopyMenu connection={c} address={endpointAddress} copyTitle={copyTitle} />
      : <button className="btn sm ep-copy" title={copyTitle}
          aria-label={`${copyTitle} for ${c.name}`} data-act="copy-endpoint-dsn" data-conn={c.id}>
          {copied
            ? <><AppIcon icon={ICONS.check} /> Copied</>
            : <><AppIcon icon={ICONS.copy} /> Copy</>}
        </button>
    : null;
  let address: ReactNode;
  if (!endpointText) {
    address = <span className="ep-addr ep-addr-hidden">Connection address unavailable</span>;
  } else {
    // Both states share BreakableAddress + overflow-wrap: break-word so the
    // layout does not jump when the secret is revealed; only the secret
    // characters change. Click toggles reveal either way.
    const shown = expanded ? endpointText : maskedEndpoint(endpointText);
    address = <div className={`ep-field${expanded ? '' : ' collapsed'}`}>
      <button className="ep-addr" title={expanded ? 'Hide the secret in the address' : 'Show the full address'}
        aria-label={`${expanded ? 'Hide' : 'Show'} the full connection address for ${c.name}`}
        aria-expanded={expanded} data-act="toggle-endpoint" data-conn={c.id}>
        <BreakableAddress address={shown} />
      </button>
      {copyButton}
    </div>;
  }
  return <>
    <div className="ep-strip">{address}</div>
    {expiredLabel
      ? <div className="ep-expiry expired"><span>{expiredLabel}</span></div>
      : null}
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
 * `multitool ssh-agent` rather than by naming the socket.
 */
export function EndpointAuthRow({ connection: c }: {
  connection: ConnectionSummary;
}): ReactNode {
  const endpoint = c.agent_access.endpoint;
  if (c.type !== 'ssh' || !endpoint) return null;
  const on = Boolean(endpoint.require_auth);
  return <div className="cd-confirm-row cd-ep-auth">
    <div className="cd-confirm-txt">
      <div className="cd-confirm-lbl">Require the endpoint secret</div>
      <div className="cd-confirm-sub">
        {on
          ? 'The signing socket refuses to list keys or sign until the caller presents this '
            + 'endpoint’s secret. Reach it with the multitool ssh-agent command above.'
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

/**
 * Opt this connection's issued address into (or out of) a 30-day expiry.
 * Off by default: the address works until revoked. Turning it on starts a
 * fresh window; the pane's expiry line (and Renew) only render while this
 * is on.
 */
export function EndpointExpiryRow({ connection: c }: {
  connection: ConnectionSummary;
}): ReactNode {
  const endpoint = c.agent_access.endpoint;
  if (!endpoint || !ENDPOINTABLE[c.type]) return null;
  const on = Boolean(endpoint.expires_at);
  return <div className="cd-confirm-row cd-ep-expiry">
    <div className="cd-confirm-txt">
      <div className="cd-confirm-lbl">Connection expiry</div>
      <div className="cd-confirm-sub">
        {on
          ? 'The connection address stops working on its deadline unless renewed.'
          : 'The connection address keeps working until you revoke it.'}
      </div>
    </div>
    <button className={`switch ${on ? 'on' : ''}`} role="switch" aria-checked={on}
      title={on ? 'The address expires on its deadline' : 'The address does not expire'}
      aria-label={`${on ? 'Disable' : 'Enable'} connection expiry for ${c.name}`}
      data-act={on ? 'endpoint-expiry-off' : 'endpoint-expiry-on'} data-conn={c.id}></button>
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
