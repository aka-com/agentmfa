// This computer's shared broker key: the one credential every local agent
// rides. It lives on the Secrets page — it is key management, not
// onboarding — while the Get started walkthrough stays focused on the next
// action.

import type { ReactNode } from 'react';
import { state } from '../app-state';
import { AppIcon } from '../icon';
import type { IdentityInfo } from '../types';
import { ICONS } from '../util';

export function SharedKeyCard({ identity }: { identity: IdentityInfo }): ReactNode {
  const menuOpen = state.agentMenuOpen === 'identity';
  const copied = state.copied === 'shared-key';
  return (
    <div className="agent-block shared-key-card">
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
            title="Key options" aria-label="Key options"
            aria-expanded={menuOpen} data-act="toggle-agent-menu" data-id="identity">
            <AppIcon icon={ICONS.ellipsis} />
          </button>
          {menuOpen
            ? <div className="agent-menu" aria-label="Key options">
                <button className="menu-item danger" data-act="rotate-key-ask">
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
