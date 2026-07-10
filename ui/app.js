// AgentMFA frontend. One file drives all Tauri windows (main, tray dropdown,
// and approval), chosen from location.hash. Every mutation and
// read goes through the Rust core via Tauri commands; the webview never
// holds a secret value (DESIGN.md §2). When run outside Tauri (a plain
// browser), a dev mock stands in for the core so the UI is developable
// standalone.

import { invoke, listen, mode } from '/src/bridge.js';
import { ICONS, TYPES, esc, escAttr, toast, relTime, absTime } from '/src/util.js';
import {
  apiOriginFromParts, authTemplate, parseApiOrigin, parseConnectionImport,
  portForTypeSwitch, suggestedSecretName,
} from '/src/connection-input.mjs';

const EDIT_SECRET_MASK = '••••••••••••';
const ACTIVITY_RENDER_LIMIT = 200;

// The left-nav tabs, in order — also the cycle order for Ctrl-Tab.
const TABS = ['secrets', 'connections', 'activity'];

/* ------------------------------ local state ------------------------------ */
const state = {
  tab: 'secrets',
  secrets: [],
  connections: [],
  agents: [],
  sessions: [],
  activity: [],
  queue: [],
  agentSetupInstructions: '',
  settings: { reauth_on_read: true, hide_secret_prefixes: true, pg_trusted_ca_bundle_path: null, menu_bar_hides_dock: false },
  reveal: {},            // secretId -> prefix string (transient)
  // sheet / confirm state
  sheet: null,           // {kind:'add-secret'|'edit-secret'|'add-conn'|'edit-conn'|'settings', ...}
  draft: {},
  sheetErrors: {},       // field key -> inline validation message
  connType: 'api',
  confirm: null,         // {kind, id/name}
  alwaysOpen: false,
  reqDetailOpen: null,   // approval payload disclosure override
  revokeInheritedRules: false,
  approvalRequestId: null,
  menuOpen: false,       // desktop-mode settings popover (gear) open
  copied: null,          // secretId whose value was just copied (transient "Copied" flash)
  readyCopied: false,    // transient feedback on the setup-instructions status button
  setupInstructionsOpen: false,
};

const root = () => document.getElementById('root');
let accessExpiryTimer = null;

/* ------------------------------ data loading ----------------------------- */
async function refresh(which = 'all') {
  const jobs = [];
  if (which === 'all' || which === 'secrets') jobs.push(load('secrets', 'list_secrets'));
  if (which === 'all' || which === 'connections') jobs.push(load('connections', 'list_connections'));
  if (which === 'all' || which === 'agents') jobs.push(load('agents', 'list_agents'));
  if (which === 'all' || which === 'sessions') jobs.push(load('sessions', 'list_sessions'));
  if (which === 'all' || which === 'activity') {
    jobs.push(load('activity', 'list_activity', { limit: ACTIVITY_RENDER_LIMIT }));
  }
  if (which === 'all' || which === 'queue') jobs.push(load('queue', 'get_queue'));
  if (which === 'all') jobs.push(load('agentSetupInstructions', 'get_agent_setup'));
  if (which === 'all' || which === 'settings') jobs.push(loadSettings());
  await Promise.all(jobs);
  render();
}
async function load(key, cmd, args) {
  try { state[key] = await invoke(cmd, args); } catch (e) { console.error(cmd, e); }
}
async function loadSettings() {
  try { state.settings = await invoke('get_settings'); } catch (e) { console.error(e); }
}
async function refreshAccessViews() {
  await Promise.all([
    load('connections', 'list_connections'),
    load('agents', 'list_agents'),
  ]);
  render();
  scheduleAccessExpiryRefresh();
}

function scheduleAccessExpiryRefresh() {
  if (accessExpiryTimer !== null) clearTimeout(accessExpiryTimer);
  accessExpiryTimer = null;
  const expiries = state.connections
    .flatMap((connection) => (connection.permissions || [])
      .filter((permission) => permission.expires_at)
      .map((permission) => new Date(permission.expires_at).getTime()))
    .filter((expiresAt) => Number.isFinite(expiresAt) && expiresAt > Date.now());
  if (!expiries.length) return;
  const delay = Math.max(0, Math.min(...expiries) - Date.now() + 50);
  accessExpiryTimer = setTimeout(() => {
    accessExpiryTimer = null;
    if (mode !== 'approval') refreshAccessViews();
  }, Math.min(delay, 2_147_483_647));
}

/* --------------------------------- render -------------------------------- */
// Rebuilding #root from scratch would drop anything the DOM holds that state
// doesn't: in-progress sheet input and the focused control. Broker events
// (queue/sessions/activity changes) re-render at arbitrary times, so every
// render first captures open drafts and then puts focus (and any text
// selection) back where it was.
function render(capture = true) {
  if (capture) captureDrafts();
  const active = document.activeElement;
  const focusId = active && active.id ? active.id : null;
  const sel = focusId && typeof active.selectionStart === 'number'
    ? { start: active.selectionStart, end: active.selectionEnd, dir: active.selectionDirection }
    : null;

  if (mode === 'approval') renderApproval();
  else if (mode === 'dropdown') renderDropdown();
  else renderMainWindow();

  if (focusId) {
    const el = document.getElementById(focusId);
    if (el) {
      el.focus();
      if (sel && typeof el.setSelectionRange === 'function') {
        try { el.setSelectionRange(sel.start, sel.end, sel.dir || 'none'); } catch { /* non-text input */ }
      }
    }
  }
}

function pendingBannerHTML() {
  if (!state.queue.length) return '';
  return `<div class="pending-banner"><span>⏳ ${state.queue.length} request${state.queue.length > 1 ? 's' : ''} waiting</span>
    <button class="btn sm" data-act="open-approval">Review</button></div>`;
}

function globalSectionsHTML() {
  let out = '';
  if (!state.agents.length) {
    if (state.tab !== 'activity') {
      out += `<div class="agent-onboarding"><div class="onboarding-copy"><b>Connect an agent</b>
        <span>Copy a short setup message into your coding agent.</span></div>
        <div class="onboarding-actions">
          <button class="btn primary sm" data-act="copy-agent-setup">Copy setup instructions</button>
          <button class="setup-toggle" data-act="toggle-setup-instructions" aria-expanded="${state.setupInstructionsOpen}">See instructions<span class="setup-toggle-icon">${ICONS.chevronDown}</span></button>
        </div>
        ${state.setupInstructionsOpen ? `<pre class="setup-instructions"><code>${esc(state.agentSetupInstructions)}</code></pre>` : ''}</div>`;
    }
  } else {
    out += '<div class="live-head">Connected agents</div>' + state.agents.map((a) => {
      const sub = `${a.program} · ${a.verification} · last used ${relTime(a.last_used)}` +
        (a.permission_count ? ` · ${a.permission_count} permission${a.permission_count === 1 ? '' : 's'}` : '');
      if (state.confirm && state.confirm.kind === 'revoke-agent' && state.confirm.id === a.id) {
        return `<div class="live-row"><span class="badge b-agent">agent</span>
          <div class="live-txt"><div class="c-name">${esc(a.name)}</div>
          <div class="disconnect-copy">Disconnect this agent? Temporary access, saved access, and open connections will end.</div></div>
          <button class="btn sm" data-act="confirm-cancel">Cancel</button>
          <button class="btn sm danger" data-act="revoke-confirm" data-id="${a.id}">Disconnect</button></div>`;
      }
      return `<div class="live-row"><span class="badge b-agent">agent</span>
        <div class="live-txt"><div class="c-name">${esc(a.name)}</div>
        <div class="s-sub" style="max-width:300px" title="${escAttr(a.identity)}">${esc(sub)}</div></div>
        <button class="btn sm" data-act="revoke-ask" data-id="${a.id}" data-name="${escAttr(a.name)}">Disconnect</button></div>`;
    }).join('');
  }
  if (state.sessions.length) {
    out += '<div class="live-head">Open connections</div>' + state.sessions.map((s) => {
      const t = TYPES[s.type];
      // who holds the session matters as much as what it's connected to
      const who = s.agent ? `${esc(s.agent)} → ${esc(s.connection)}` : esc(s.connection);
      if (state.confirm && state.confirm.kind === 'close-session' && state.confirm.id === s.id) {
        return `<div class="live-row"><span class="badge ${t.cls}">${t.label}</span>
          <div class="live-txt"><div class="c-name">${who}</div>
          <div class="s-sub">Close this connection now?</div></div>
          <button class="btn sm" data-act="confirm-cancel">Cancel</button>
          <button class="btn sm danger" data-act="close-session-confirm" data-id="${s.id}">Close</button></div>`;
      }
      return `<div class="live-row"><span class="badge ${t.cls}">${t.label}</span>
        <div class="live-txt"><div class="c-name">${who}</div>
        <div class="s-sub" title="${escAttr(s.detail)}">${esc(s.detail)}</div></div>
        <button class="btn sm" data-act="close-session-ask" data-id="${s.id}">Close</button></div>`;
    }).join('');
  }
  return out ? `<div class="dd-global ${!state.agents.length ? 'onboarding-global' : ''}">${out}</div>` : '';
}

function secretsHTML() {
  if (!state.secrets.length) {
    return `<div class="empty"><div class="empty-ico">🔐</div><h3>No secrets</h3>
      <p>Store API keys, connection strings, and other credentials and secrets here.</p>
      <button class="btn primary" data-act="open-add-secret">＋ Add secret</button></div>`;
  }
  const rows = state.secrets.map((s) => {
    if (state.confirm && state.confirm.kind === 'del-secret-inuse' && state.confirm.id === s.id) {
      return `<tr class="confirm-row"><td colspan="3"><div class="confirm-inline"><span>Currently used by ${esc(s.used_by_names.join(', '))}. Delete the connection first.</span>
          <button class="btn sm" data-act="confirm-cancel">OK</button></div></td></tr>`;
    }
    if (state.confirm && state.confirm.kind === 'del-secret' && state.confirm.id === s.id) {
      return `<tr class="confirm-row"><td colspan="3"><div class="confirm-inline"><span>Delete “${esc(s.name)}” from the macOS Keychain?</span>
          <button class="btn sm" data-act="confirm-cancel">Cancel</button>
          <button class="btn sm danger" data-act="del-secret-confirm" data-id="${s.id}">Delete</button></div></td></tr>`;
    }
    // The eye reveals only an audited short prefix (the full value never
    // enters the webview); the "Hide secret prefixes" setting removes the
    // affordance entirely.
    const revealed = state.settings.hide_secret_prefixes ? null : state.reveal[s.id];
    const copied = state.copied === s.id;
    // the eye toggles reveal ↔ conceal; copy is a ghost button that surfaces on
    // hovering the value (available whether or not the prefix is revealed)
    const eyeBtn = state.settings.hide_secret_prefixes ? ''
      : revealed
      ? `<button class="icon-btn eye-btn" title="Hide prefix" aria-label="Hide prefix" data-act="hide-secret" data-id="${s.id}">${ICONS.eyeOff}</button>`
      : `<button class="icon-btn eye-btn" title="Reveal prefix" aria-label="Reveal prefix" data-act="reveal-secret" data-id="${s.id}">${ICONS.eye}</button>`;
    // The copy affordance and the post-copy "Copied" status both overlay the
    // masked value, centered — never beside it (the placeholder dims behind).
    const overlay = copied
      ? `<span class="copied-badge">${ICONS.check}<span>Copied</span></span>`
      : `<button class="ghost-copy" title="Copy value" data-act="copy-secret" data-id="${s.id}">${ICONS.copy}<span>Copy</span></button>`;
    const valText = revealed ? esc(revealed) : '••••••••';
    const sub = `Used by ${s.used_by} connection${s.used_by === 1 ? '' : 's'}`;
    return `<tr>
      <td><div><div class="s-name">${esc(s.name)}</div><div class="s-sub secret-usage">${esc(sub)}</div></div></td>
      <td class="val"><span class="val-wrap"><span class="val-slot ${copied ? 'is-copied' : ''}"><code>${valText}</code><span class="val-overlay">${overlay}</span></span></span> ${eyeBtn}</td>
      <td class="rowdel">
        <button class="icon-btn" title="Edit secret" aria-label="Edit secret ${escAttr(s.name)}" data-act="edit-secret" data-id="${s.id}">${ICONS.pencil}</button>
        <button class="icon-btn" title="Delete secret" aria-label="Delete secret ${escAttr(s.name)}" data-act="del-secret-ask" data-id="${s.id}">${ICONS.trash}</button></td></tr>`;
  }).join('');
  return `<table class="sec-table"><tbody>${rows}</tbody></table>`;
}

/* ---- connections tab ---- */
function accessDescription(connection, scope) {
  if (scope === 'read') return 'Can fetch data';
  if (connection.type === 'api') return 'Can make any request';
  return 'Can open and use this connection';
}

const accessRowsHTML = (c) => {
  const rows = (c.permissions || [])
    .filter((permission) => !permission.expires_at || new Date(permission.expires_at).getTime() > Date.now())
    .map((permission) => {
      const expiring = !!permission.expires_at;
      const suffix = expiring
        ? ` · ${Math.max(1, Math.ceil((new Date(permission.expires_at).getTime() - Date.now()) / 60000))} min left`
        : ' without asking';
      const action = expiring ? 'End now' : 'Require approval';
      return `<div class="access-row"><div class="access-copy"><b>${esc(permission.agent)}</b>
        <span>${esc(accessDescription(c, permission.scope))}${suffix}</span></div>
        <button class="btn ghost sm" aria-label="${action} for ${escAttr(permission.agent)}" data-act="del-permission" data-id="${permission.id}">${action}</button></div>`;
    });
  return rows.length ? `<div class="access-list"><div class="access-head">Agent access</div>${rows.join('')}</div>` : '';
};
const liveCount = (c) => state.sessions.filter((s) => s.connection === c.name).length;
const connActionsHTML = (c) =>
  `<button class="icon-btn" title="Edit connection" aria-label="Edit connection ${escAttr(c.name)}" data-act="edit-conn" data-id="${c.id}">${ICONS.pencil}</button>
   <button class="icon-btn" title="Delete connection" aria-label="Delete connection ${escAttr(c.name)}" data-act="del-conn-ask" data-id="${c.id}">${ICONS.trash}</button>`;

// Card grid, after TablePlus launchers / Keybase device cards: one
// connection = one object with everything about it inside its border.
function connectionsHTML() {
  if (!state.connections.length) {
    return `<div class="empty"><div class="empty-ico">🔌</div><h3>No connections</h3>
      <p>Connect to APIs, databases, remote servers, etc.</p>
      <button class="btn primary" data-act="open-add-conn">＋ Add connection</button></div>`;
  }
  return `<div class="conn-cards">` + state.connections.map((c) => {
    const t = TYPES[c.type];
    if (state.confirm && state.confirm.kind === 'del-conn' && state.confirm.id === c.id) {
      return `<div class="conn-card confirm-card">
        <div class="cc-top"><span class="badge ${t.cls}">${t.label}</span>
          <span class="c-name" title="${escAttr(c.name)}">${esc(c.name)}</span></div>
        <div class="cc-confirm">Delete this connection?${(c.permissions || []).some((permission) => !permission.expires_at) ? ' Affected agents will need approval again.' : ''}</div>
        <div class="cc-foot"><button class="btn sm" data-act="confirm-cancel">Cancel</button>
          <button class="btn sm danger" data-act="del-conn-confirm" data-id="${c.id}">Delete</button></div></div>`;
    }
    const chips = c.secret_names.map((n) => `<span class="key-chip">🔑 ${esc(n)}</span>`).join('');
    return `<div class="conn-card">
      <div class="cc-top"><span class="badge ${t.cls}">${t.label}</span>
        <span class="c-name" title="${escAttr(c.name)}">${esc(c.name)}</span>
        ${liveCount(c) ? '<span class="cc-live">● live</span>' : ''}</div>
      <div class="cc-target" title="${escAttr(c.target)}">${esc(c.target)}</div>
      <div class="cc-chips">${chips}</div>
      ${accessRowsHTML(c)}
      <div class="cc-foot">${connActionsHTML(c)}</div></div>`;
  }).join('') + `</div>`;
}

// Console.app-style rows: a proportional timestamp gutter, restrained
// semantic Lucide icon, then plain primary text with optional detail.
function activityRowHTML(a) {
  const icon = ICONS[a.icon] || '';
  return `<div class="act-row ${a.detail ? '' : 'single-line'}">
    <span class="act-gutter"><span class="act-time" data-tippy-content="${escAttr(absTime(a.at))}" data-tippy-theme="activity-time">${esc(relTime(a.at))}</span></span>
    <span class="act-ico tone-${escAttr(a.tone || 'neutral')}">${icon}</span>
    <span class="act-txt">${esc(a.text)}${a.detail ? `<div class="act-detail">${esc(a.detail)}</div>` : ''}</span></div>`;
}

function activityHTML() {
  if (!state.activity.length) {
    return `<div class="muted-note">No activity yet.<br>Requests and broker actions will appear here.</div>`;
  }
  return '<div class="act-list">' + state.activity
    .slice(0, ACTIVITY_RENDER_LIMIT)
    .map(activityRowHTML).join('') + '</div>';
}

async function receiveActivity(entry) {
  if (!entry || !entry.at || !entry.text) {
    await load('activity', 'list_activity', { limit: ACTIVITY_RENDER_LIMIT });
    if (mode !== 'approval' && state.tab === 'activity' && !state.sheet && !state.menuOpen) render();
    return;
  }

  const duplicate = state.activity.some((item) =>
    item.at === entry.at && item.icon === entry.icon && item.text === entry.text && item.detail === entry.detail);
  if (duplicate) return;
  state.activity = [entry, ...state.activity].slice(0, ACTIVITY_RENDER_LIMIT);

  if (mode === 'approval' || state.tab !== 'activity' || state.sheet || state.menuOpen) return;
  const list = document.querySelector('.act-list');
  if (!list) {
    render();
    return;
  }
  list.insertAdjacentHTML('afterbegin', activityRowHTML(entry));
  while (list.children.length > ACTIVITY_RENDER_LIMIT) list.lastElementChild.remove();
}

function tabContentHTML() {
  return state.tab === 'secrets' ? secretsHTML()
    : state.tab === 'connections' ? connectionsHTML()
    : activityHTML();
}

function brokerReadyHTML() {
  const copied = state.readyCopied;
  return `<button class="dd-sub ready-copy ${copied ? 'is-copied' : ''}"
    data-act="copy-ready-setup" title="${copied ? 'Setup instructions copied' : 'Copy setup instructions'}"
    aria-label="Copy setup instructions"><span class="dot"></span>
    <span class="ready-copy-label" aria-live="polite">${copied ? `${ICONS.check} Copied` : 'Ready'}</span></button>`;
}

function renderMainWindow() {
  const nav = TABS.map((tb) =>
    `<button class="nav-item ${state.tab === tb ? 'on' : ''}" data-act="tab" data-tab="${tb}">${cap(tb)}</button>`).join('');
  // One view-specific action, always in the header row next to the title.
  const actionBtn = state.tab === 'connections'
    ? `<button class="btn" data-act="open-add-conn">＋ Add connection</button>`
    : state.tab === 'secrets'
    ? `<button class="btn" data-act="open-add-secret">＋ Add secret</button>`
    : `<button class="btn" data-act="clear-activity-ask" ${state.activity.length ? '' : 'disabled'}>Clear activity</button>`;
  const menu = state.menuOpen
    ? `<div class="settings-menu">
        <button class="menu-item" data-act="mode-tray">${ICONS.menubar} Minimize to menu bar</button>
        <button class="menu-item" data-act="open-settings">${ICONS.gear} Settings</button>
      </div>` : '';
  root().innerHTML = `<div class="surface">
    <div class="dw-titlebar" data-tauri-drag-region><span class="dw-title">AgentMFA</span></div>
    <div class="dw-body">
      <div class="dw-side">
        <div class="dw-brand"><div class="dd-appicon">🔐</div>
          <div><div class="dd-title">AgentMFA</div>${brokerReadyHTML()}</div></div>
        <div class="dw-nav">${nav}</div>
        <div class="dw-settings">${menu}
          <button class="nav-item gear-btn ${state.menuOpen ? 'on' : ''}" data-act="toggle-settings-menu" title="Settings" aria-label="Settings">${ICONS.gear}</button>
        </div>
      </div>
      <div class="dw-main">
        <div class="dw-head"><h2>${cap(state.tab)}</h2>${actionBtn}</div>
        ${pendingBannerHTML()}
        ${globalSectionsHTML()}
        <div class="content">${tabContentHTML()}</div>
      </div>
    </div></div>${sheetsHTML()}`;
}

function renderDropdown() {
  const tabs = TABS.map((tb) =>
    `<button class="seg-btn ${state.tab === tb ? 'on' : ''}" data-act="tab" data-tab="${tb}">${cap(tb)}</button>`).join('');
  const footer = state.tab === 'secrets'
    ? '<div class="dd-footer"><button class="btn block" data-act="open-add-secret">＋ Add secret</button></div>'
    : state.tab === 'connections'
    ? '<div class="dd-footer"><button class="btn block" data-act="open-add-conn">＋ Add connection</button></div>' : '';
  root().innerHTML = `<div class="surface dropdown-surface">
    <div class="dd-head"><div class="dd-appicon">🔐</div>
      <div class="dd-identity"><div class="dd-title">AgentMFA</div>${brokerReadyHTML()}</div>
      <button class="icon-btn" title="Open as a window" aria-label="Open as a window" data-act="mode-window">${ICONS.window}</button>
      <button class="icon-btn" title="Settings" aria-label="Settings" data-act="open-settings">${ICONS.gear}</button></div>
    ${pendingBannerHTML()}${globalSectionsHTML()}
    <div class="seg">${tabs}</div>
    <div class="content dd-content">${tabContentHTML()}</div>
    ${footer}</div>${sheetsHTML()}`;
}

/* --------------------------------- sheets -------------------------------- */
function sheetsHTML() {
  if (!state.sheet) return '';
  switch (state.sheet.kind) {
    case 'add-secret': return addSecretSheet(false);
    case 'edit-secret': return addSecretSheet(true);
    case 'add-conn': return connSheet(false);
    case 'edit-conn': return connSheet(true);
    case 'settings': return settingsSheet();
    case 'clear-activity': return clearActivitySheet();
    default: return '';
  }
}

function clearActivitySheet() {
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide confirm-sheet" role="dialog" aria-modal="true" aria-labelledby="clear-activity-title">
      <h3 id="clear-activity-title">Clear activity?</h3>
      <p>This permanently removes all activity history from this device.</p>
      <div class="sheet-actions">
        <button class="btn" data-act="sheet-cancel">Cancel</button>
        <button class="btn danger" data-act="clear-activity-confirm">Clear activity</button>
      </div></div>`;
}

// Inline per-field validation: saveSecret/saveConn fill state.sheetErrors
// keyed by field, the sheet renders the message under the offending input,
// and editing the field clears its error (the `input` listener below).
const fieldErr = (key) =>
  state.sheetErrors[key] ? `<div class="field-error">${esc(state.sheetErrors[key])}</div>` : '';
const fieldCls = (key) => (state.sheetErrors[key] ? 'err' : '');
const selectControlHTML = (id, options) => `<span class="select-control">
  <select id="${id}">${options}</select>
  <span class="select-chevron" aria-hidden="true">${ICONS.chevronDown}</span></span>`;

function addSecretSheet(editing) {
  const d = state.draft;
  const s = editing ? state.secrets.find((x) => x.id === state.sheet.id) : null;
  const title = editing ? 'Edit secret' : 'Add secret';
  const valueLabel = editing ? 'New value (saved to macOS Keychain)' : 'Value';
  const valuePlaceholder = editing ? '' : 'Your secret (saved in Keychain)';
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>${title}</h3>
    <div class="f-row"><label>Name</label><input id="f-name" class="${fieldCls('name')}" placeholder="e.g. STRIPE_API_KEY" value="${escAttr(d.name ?? (s ? s.name : ''))}">${fieldErr('name')}</div>
    <div class="f-row"><label>${valueLabel}</label><input id="f-value" class="${fieldCls('value')}" type="password" placeholder="${valuePlaceholder}" value="${escAttr(d.value ?? '')}">${fieldErr('value')}</div>
    <div class="sheet-actions">
      <button class="btn" data-act="sheet-cancel">Cancel</button>
      <button class="btn primary" data-act="save-secret">Save</button></div></div>`;
}

function credentialChooserHTML(type, draft, allowNew = true) {
  const source = allowNew
    ? (draft.secretSource || (draft.importedCredential || !state.secrets.length ? 'new' : 'existing'))
    : 'existing';
  const secretLabel = type === 'pg' ? 'Database password'
    : type === 'ssh' ? 'SSH private key'
    : 'Token or API key';
  const sourceOptions = state.secrets.length
    ? `<option value="existing" ${source === 'existing' ? 'selected' : ''}>Use a saved credential</option>` : '';
  const select = allowNew
    ? selectControlHTML('c-secret-source', `${sourceOptions}<option value="new" ${source === 'new' ? 'selected' : ''}>Save a new credential</option>`)
    : '';
  if (source === 'existing' && state.secrets.length) {
    const opts = state.secrets.map((secret) =>
      `<option value="${escAttr(secret.id)}" ${draft.secretId === secret.id ? 'selected' : ''}>${esc(secret.name)}</option>`).join('');
    return `${allowNew ? `<div class="f-row"><label>${secretLabel}</label>${select}</div>` : ''}
      <div class="f-row"><label>${allowNew ? 'Saved credential' : secretLabel}</label>${selectControlHTML('c-secret', opts)}${fieldErr('secret')}</div>`;
  }
  const suggested = suggestedSecretName(draft.name, type);
  return `<div class="f-row"><label>${secretLabel}</label>${select}</div>
    <div class="f-row"><label>Credential name</label><input id="c-new-secret-name" class="${fieldCls('newSecretName')}" placeholder="${escAttr(suggested)}" value="${escAttr(draft.newSecretName ?? '')}">${fieldErr('newSecretName')}</div>
    <div class="f-row"><label>Credential value</label><input id="c-new-secret-value" class="${fieldCls('newSecretValue')}" type="password" placeholder="Saved directly to macOS Keychain" value="${escAttr(draft.newSecretValue ?? draft.importedCredential ?? '')}">${fieldErr('newSecretValue')}
      <div class="rule-note">The value is submitted only when you save this connection and is never written to connection metadata.</div></div>`;
}

function connSheet(editing) {
  const d = state.draft;
  const t = state.connType;
  const conn = editing ? state.connections.find((c) => c.id === state.sheet.id) : null;
  const typeBtn = (val, label) => {
    if (editing) return `<button type="button" class="seg-btn ${t === val ? 'on' : ''}" disabled ${t === val ? '' : 'style="opacity:.35"'}>${label}</button>`;
    return `<button type="button" class="seg-btn ${t === val ? 'on' : ''}" data-act="conn-type" data-type="${val}">${label}</button>`;
  };
  const importWarnings = !editing && d.importWarnings && d.importWarnings.length
    ? `<div class="pair-identity-warning"><b>Review imported details</b><ul>${d.importWarnings.map((warning) => `<li>${esc(warning)}</li>`).join('')}</ul></div>` : '';
  let fields = editing ? '' : `<div class="set-panel"><div class="f-row"><label>Paste an existing connection</label>
      <div class="f-2col"><input id="f-import" placeholder="Postgres DSN, API/WS URL, or ssh user@host" value="${escAttr(d.importSource ?? '')}">
      <button type="button" class="btn sm" data-act="apply-connection-import">Use</button></div>
      ${fieldErr('import')}</div></div>${importWarnings}<div class="form-divider" role="separator"></div>`;
  fields += `<div class="f-row"><label>Name</label><input id="f-cname" class="${fieldCls('name')}" placeholder="e.g. github" value="${escAttr(d.name ?? '')}">${fieldErr('name')}</div>
    <div class="f-row"><label>Type${editing ? ': fixed after creation' : ''}</label>
    <div class="seg in-form">${typeBtn('api', 'API key')}${typeBtn('pg', 'Postgres')}${typeBtn('ssh', 'SSH')}${typeBtn('ws', 'WebSocket')}</div></div>`;
  if (t === 'api') {
    const origin = d.origin ?? apiOriginFromParts(d.scheme, d.host, d.port);
    fields += `<div class="f-row"><label>API origin</label><input id="f-origin" class="${fieldCls('origin')}" placeholder="https://api.github.com" value="${escAttr(origin)}">${fieldErr('origin')}
      <div class="rule-note">Scheme, host, and optional port only. The agent supplies each request path.</div></div>`;
  } else if (t === 'ssh') {
    fields += `<div class="f-2col">
      <div class="f-row"><label>Host</label><input id="f-host" class="${fieldCls('host')}" placeholder="prod.example.com" value="${escAttr(d.host ?? '')}">${fieldErr('host')}</div>
      <div class="f-row" style="flex:0 0 90px"><label>Port</label><input id="f-port" class="${fieldCls('port')}" inputmode="numeric" value="${escAttr(d.port ?? '22')}">${fieldErr('port')}</div></div>
      <div class="f-row"><label>User</label><input id="f-user" class="${fieldCls('user')}" placeholder="deploy" value="${escAttr(d.user ?? '')}">${fieldErr('user')}</div>`;
    fields += `<div class="f-row"><label>Host key fingerprint</label><input id="f-host-key" class="${fieldCls('hostKeyFingerprint')}" placeholder="SHA256:…" value="${escAttr(d.hostKeyFingerprint ?? '')}">${fieldErr('hostKeyFingerprint')}</div>`;
  } else if (t === 'pg') {
    const sslmode = d.sslmode || 'require';
    const sslOpts = [
      ['disable', 'Disable'],
      ['prefer', 'Prefer (TLS optional)'],
      ['require', 'Require TLS (no certificate verification)'],
      ['verify-ca', 'Verify CA only (no hostname verification)'],
      ['verify-full', 'Verify full'],
    ].map(([value, label]) =>
      `<option value="${value}" ${sslmode === value ? 'selected' : ''}>${label}</option>`).join('');
    fields += `<div class="f-2col">
      <div class="f-row"><label>Host</label><input id="f-host" class="${fieldCls('host')}" placeholder="db.internal.example.com" value="${escAttr(d.host ?? '')}">${fieldErr('host')}</div>
      <div class="f-row" style="flex:0 0 90px"><label>Port</label><input id="f-port" class="${fieldCls('port')}" inputmode="numeric" value="${escAttr(d.port ?? '5432')}">${fieldErr('port')}</div></div>
      <div class="f-row"><label>Database</label><input id="f-db" class="${fieldCls('dbname')}" placeholder="app_production" value="${escAttr(d.dbname ?? '')}">${fieldErr('dbname')}</div>
      <div class="f-row"><label>User</label><input id="f-user" class="${fieldCls('user')}" placeholder="app" value="${escAttr(d.user ?? '')}">${fieldErr('user')}</div>
      <div class="f-row"><label>TLS mode</label>${selectControlHTML('f-sslmode', sslOpts)}</div>`;
  } else {
    fields += `<div class="f-row"><label>URL</label><input id="f-url" class="${fieldCls('url')}" placeholder="wss://stream.example.com/feed" value="${escAttr(d.url ?? '')}">${fieldErr('url')}</div>`;
  }
  // Authentication is recipe-driven for new connections. Existing custom
  // templates remain directly editable so the UI round-trips every config.
  if (editing && t === 'api') {
    fields += `<div class="f-row"><label>Injection template</label>
      <input id="c-template" class="${fieldCls('template')}" value="${escAttr(d.template ?? '')}">${fieldErr('template')}
      <div class="rule-note">Advanced template; references saved credentials by name.</div></div>`;
  } else if (editing) {
    if (t !== 'ws' || !d.template) fields += credentialChooserHTML(t, d, false);
    if (t === 'ws' && d.template) {
      fields += `<details class="set-collapse" ${d.template ? 'open' : ''}><summary>Custom authentication header</summary>
        <div class="set-panel"><div class="f-row"><label>Injection template</label>
        <input id="c-template" class="${fieldCls('template')}" placeholder="Authorization: Bearer {{TOKEN_NAME}}" value="${escAttr(d.template ?? '')}">${fieldErr('template')}</div></div></details>`;
    }
  } else if (t === 'api' || t === 'ws') {
    const modeValue = d.authMode || 'bearer';
    const recipes = [
      ['bearer', 'Bearer token'], ['header', 'Custom header'],
      ...(t === 'api' ? [['query', 'Query parameter']] : []),
      ['advanced', 'Advanced template'],
    ].map(([value, label]) => `<option value="${value}" ${modeValue === value ? 'selected' : ''}>${label}</option>`).join('');
    fields += `<div class="f-row"><label>Authentication</label>${selectControlHTML('c-auth-mode', recipes)}</div>`;
    if (modeValue === 'header') {
      fields += `<div class="f-row"><label>Header name</label><input id="c-auth-detail" class="${fieldCls('authDetail')}" placeholder="X-API-Key" value="${escAttr(d.authDetail ?? '')}">${fieldErr('authDetail')}</div>`;
    } else if (modeValue === 'query') {
      fields += `<div class="f-row"><label>Query parameter</label><input id="c-auth-detail" class="${fieldCls('authDetail')}" placeholder="api_key" value="${escAttr(d.authDetail ?? '')}">${fieldErr('authDetail')}</div>`;
    }
    if (modeValue === 'advanced') {
      fields += `<div class="f-row"><label>Injection template</label><input id="c-template" class="${fieldCls('template')}" placeholder="Authorization: Bearer {{TOKEN_NAME}}" value="${escAttr(d.template ?? '')}">${fieldErr('template')}
        <div class="rule-note">References credentials by name using <code>{{ … }}</code>. Use this for Basic auth or composed credentials.</div></div>`;
    } else {
      fields += credentialChooserHTML(t, d);
    }
  } else {
    fields += credentialChooserHTML(t, d);
  }
  if (t === 'pg' || t === 'ws') {
    fields += `<div class="f-row"><label class="checkbox-label">
      <input type="checkbox" id="c-multi" ${d.multiConnect !== false ? 'checked' : ''} style="width:auto">
      <span>Let tools reconnect for 60 seconds after opening. <span class="label-detail">Useful for connection pools and tools that reconnect automatically.</span></span></label></div>`;
  }
  if (editing && conn && (conn.permissions || []).some((permission) => !permission.expires_at)) {
    fields += `<div class="rule-note">Changing the destination makes affected agents ask for approval again.</div>`;
  }
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>${editing ? 'Edit connection' : 'Add connection'}</h3>${fields}
    <div class="sheet-actions"><button class="btn" data-act="sheet-cancel">Cancel</button>
      <button class="btn primary" data-act="save-conn">Save</button></div></div>`;
}

function settingsSheet() {
  const s = state.settings;
  const pgCaPath = state.draft.pgCaBundlePath ?? s.pg_trusted_ca_bundle_path ?? '';
  const reauthRow = `<div class="set-row"><div class="set-txt"><div class="st-title">Confirm before using saved secrets</div>
      <div class="st-sub">Use OS authentication before showing, copying, or sending a saved credential.</div></div>
      <button class="switch ${s.reauth_on_read ? 'on' : ''}" data-act="toggle-reauth" role="checkbox" aria-checked="${s.reauth_on_read ? 'true' : 'false'}"></button></div>`;
  const prefixRow = `<div class="set-row"><div class="set-txt"><div class="st-title">Hide secret prefixes</div>
      <div class="st-sub">Don't show the beginning of secrets in the secret list.</div></div>
      <button class="switch ${s.hide_secret_prefixes ? 'on' : ''}" data-act="toggle-hide-prefixes" role="checkbox" aria-checked="${s.hide_secret_prefixes ? 'true' : 'false'}"></button></div>`;
  const dockRow = `<div class="set-row"><div class="set-txt"><div class="st-title">Hide Dock icon in the menu bar</div>
      <div class="st-sub">When minimized to the menu bar, hide the Dock icon until the window is reopened.</div></div>
      <button class="switch ${s.menu_bar_hides_dock ? 'on' : ''}" data-act="toggle-menubar-dock" role="checkbox" aria-checked="${s.menu_bar_hides_dock ? 'true' : 'false'}"></button></div>`;
  const pgTls = `<details class="set-collapse pg-options" ${pgCaPath ? 'open' : ''}>
      <summary><span class="pg-options-chevron" aria-hidden="true">${ICONS.chevronDown}</span><span>Postgres options</span></summary>
      <div class="set-panel">
        <div class="f-row"><label>Trusted CA bundle</label>
          <input id="f-pg-ca-bundle" placeholder="/path/to/ca-bundle.pem" value="${escAttr(pgCaPath)}"></div>
        <div class="rule-note">Choose a PEM file containing certificates for your enterprise or private CA.</div>
        <div class="set-actions">
          <button class="btn sm" data-act="clear-pg-ca-bundle">Clear</button>
          <button class="btn sm primary" data-act="save-pg-ca-bundle">Save</button>
        </div>
      </div>
    </details>`;
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>Settings</h3>
    ${reauthRow}${prefixRow}${dockRow}${pgTls}
    <div class="sheet-actions"><button class="btn primary" data-act="sheet-cancel">Done</button></div></div>`;
}

/* ----------------------------- approval window --------------------------- */
let countdownTimer = null;

function durationLabel(seconds) {
  if (seconds % 60 === 0) {
    const minutes = seconds / 60;
    return `${minutes} minute${minutes === 1 ? '' : 's'}`;
  }
  return `${seconds} seconds`;
}

function approvalHeading(req) {
  const name = req.connection ? req.connection.name : 'AgentMFA';
  if (req.kind === 'pair') return `Let ${req.agent} connect to AgentMFA?`;
  if (req.kind === 'http' && req.http && !req.http.mutating) {
    return `${req.agent} wants to fetch data from ${name}`;
  }
  if (req.kind === 'http') return `${req.agent} wants to make a request through ${name}`;
  if (req.kind === 'ssh') return `${req.agent} wants to sign in through ${name}`;
  return `${req.agent} wants to connect to ${name}`;
}

function temporaryAccessExplanation(req) {
  const connection = req.connection ? req.connection.name : 'this connection';
  const access = req.temporary_access || { scope: 'full', duration_seconds: 900 };
  const duration = durationLabel(access.duration_seconds);
  if (access.scope === 'read') {
    return {
      duration,
      text: `For ${duration}, ${req.agent} can fetch data from ${connection} without asking again. Requests that may make changes will still ask.`,
    };
  }
  if (req.kind === 'http') {
    return {
      duration,
      text: `For ${duration}, ${req.agent} can make any request through ${connection} without asking again, including changes and deletes.`,
    };
  }
  return {
    duration,
    text: `For ${duration}, ${req.agent} can open and use ${connection} without asking again. Activity inside an open connection is not reviewed individually.`,
  };
}

function ongoingAccessExplanation(req) {
  const connection = req.connection ? req.connection.name : 'this connection';
  if (req.temporary_access && req.temporary_access.scope === 'read') {
    return `${req.agent} will be able to fetch data from ${connection} without asking again. Requests that may make changes will still ask.`;
  }
  if (req.kind === 'http') {
    return `${req.agent} will be able to make any request through ${connection} without asking again, including changes and deletes.`;
  }
  return `${req.agent} will be able to open and use ${connection} without asking again. Activity inside an open connection is not reviewed individually.`;
}

function renderApproval() {
  const req = state.queue[0];
  const el = root();
  if (!req) {
    el.innerHTML = `<div class="surface approval"><div class="ap-empty">No requests waiting.</div></div>`;
    return;
  }
  const conn = req.connection;
  const t = conn ? TYPES[conn.type] : null;
  const isPair = req.kind === 'pair';
  if (state.approvalRequestId !== req.id) {
    state.approvalRequestId = req.id;
    state.alwaysOpen = false;
    state.reqDetailOpen = null;
    state.revokeInheritedRules = isPair && !!(req.inherited && req.inherited.length);
  }
  const cd = countdownParts(req.deadline);
  const connCell = conn
    ? (t ? `<span class="badge ${t.cls}">${t.label}</span> ` : '') + `<b>${esc(conn.name)}</b>`
    : '';
  const connectionRow = conn ? `<div class="ap-row"><span>Connection</span><span>${connCell}</span></div>` : '';
  const targetRow = conn ? `<div class="ap-row"><span>Target</span><code>${esc(conn.target)}</code></div>` : '';
  const scopeRow = (req.kind === 'pg' || req.kind === 'ws' || req.kind === 'ssh') && conn && conn.multi_connect
    ? `<div class="ap-row"><span>Reconnects</span><span>Allowed for 60 seconds after this connection is opened</span></div>` : '';
  const pairIdentity = req.pairing_identity || {
    program: req.identity || 'Unknown program',
    verification: 'Program identity',
    technical: req.identity || 'Unavailable',
    warning: null,
  };
  const identityRows = isPair ? `
      <div class="ap-row"><span>Requested name</span><span><b>${esc(req.agent)}</b> <em class="self-reported">supplied by program</em></span></div>
      <div class="ap-row"><span>Program</span><b>${esc(pairIdentity.program)}</b></div>
      <div class="ap-row"><span>Verification</span><span>${esc(pairIdentity.verification)}</span></div>` : '';

  let inherit = '';
  if (isPair && req.inherited && req.inherited.length) {
    inherit = `<div class="inherit-warn"><span class="iw-head">This name already has access that does not require approval</span>
      <ul>${req.inherited.map((c) => `<li><b>${esc(c.name)}</b> — ${c.type === 'api' ? 'Any request' : 'Open and use this connection'}</li>`).join('')}</ul>
      <div class="pair-choice-head">When this program connects:</div>
      <label class="pair-choice"><input type="radio" name="pair-access" data-act="pair-inheritance" data-revoke="true" ${state.revokeInheritedRules ? 'checked' : ''}>
        <span><b>Require approval again</b><small>Recommended</small></span></label>
      <label class="pair-choice"><input type="radio" name="pair-access" data-act="pair-inheritance" data-revoke="false" ${state.revokeInheritedRules ? '' : 'checked'}>
        <span><b>Keep existing access</b><small>The new program inherits everything listed above</small></span></label></div>`;
  }

  const replacement = isPair && req.replaces_existing_agent
    ? `<div class="pair-replace"><b>${esc(req.agent)} is already connected.</b> Connecting again replaces its current sign-in. Other ${esc(req.agent)} processes may need to reload their saved sign-in.</div>` : '';
  const identityWarning = isPair && pairIdentity.warning
    ? `<div class="pair-identity-warning">${esc(pairIdentity.warning)}</div>` : '';
  const identityDetails = isPair
    ? `<details class="pair-tech"><summary>Technical identity</summary><code>${esc(pairIdentity.technical)}</code></details>` : '';

  const detail = requestDetailHTML(req);

  let always = '';
  if (!isPair) {
    const box = state.alwaysOpen
      ? `<div class="always-box"><div class="f-row"><label>Use without asking</label>
        <div class="rule-note">${esc(ongoingAccessExplanation(req))} You can require approval again from the Connections tab.</div></div>
        <button class="btn primary sm" data-act="always-save">Don’t ask again</button></div>` : '';
    always = { btn: `<button class="btn ghost sm" data-act="always-toggle">Don’t ask again…</button>`, box };
  }

  const temporary = isPair ? null : temporaryAccessExplanation(req);
  const sessionNote = !isPair
    ? `<div class="ap-access-summary"><b>If you allow for ${esc(temporary.duration)}</b><p>${esc(temporary.text)}</p></div>` : '';

  // The window is fixed-size and non-resizable, so the variable-height
  // middle (rows, payload, inherited-permissions list) scrolls; Deny/Allow
  // can never be pushed out of reach.
  el.innerHTML = `<div class="surface approval">
    <div class="ap-head"><div class="ap-icon">🔐</div>
      <div><div class="ap-title">${esc(approvalHeading(req))}</div></div></div>
    <div class="ap-scroll">
    ${isPair ? `<div class="pair-explainer">Connecting lets this program see connection names and destinations and ask AgentMFA to use them. It cannot read saved secret values.</div>` : ''}
    <div class="ap-rows">
      ${isPair ? identityRows : `<div class="ap-row"><span>Agent</span><b>${esc(req.agent)}</b></div>
      ${connectionRow}${targetRow}
      <div class="ap-row"><span>This request</span><code>${esc(req.action)}</code></div>${scopeRow}`}
      <div class="ap-row"><span>Approve within</span><span><span class="ap-countdown${cd.s === 0 ? ' expired' : cd.s <= COUNTDOWN_LOW_S ? ' low' : ''}" id="ap-countdown">${cd.text}</span></span></div>
    </div>
    ${identityWarning}${replacement}${inherit}${identityDetails}${detail}
    ${sessionNote}
    ${always ? `<div class="ap-ongoing-action">${always.btn}</div>${always.box}` : ''}
    </div>
    <div class="ap-buttons">
      <button class="btn deny" data-act="decide-deny" data-id="${req.id}">${isPair ? 'Don’t connect' : 'Deny'}</button>
      ${isPair ? '' : `<button class="btn ghost sm" data-act="decide-once" data-id="${req.id}">This request only</button>`}
      <span class="spacer"></span>
      <button class="btn primary" data-act="decide-allow" data-id="${req.id}">${isPair ? 'Connect agent' : `Allow for ${esc(temporary.duration)}`}</button></div>
    ${state.queue.length > 1 ? `<div class="aw-queue">${state.queue.length - 1} more request${state.queue.length > 2 ? 's' : ''} waiting</div>` : ''}
  </div>`;
  armCountdown();
}

function requestDetailHTML(req) {
  if (req.kind !== 'http' || !req.http) return '';
  const h = req.http;
  const shown = state.reqDetailOpen === null ? h.mutating : state.reqDetailOpen;
  const head = `<div class="req-detail-head"><button class="btn ghost sm" data-act="req-detail-toggle">${shown ? '▾' : '▸'} Technical request details${h.mutating ? `<span class="mut-tag">${esc(h.method)}</span>` : ''}</button></div>`;
  if (!shown) return head;
  const hdrs = h.headers && h.headers.length
    ? h.headers.map(([k, v]) => `<div class="rd-line"><span class="rd-k">${esc(k)}:</span> ${esc(String(v))}</div>`).join('')
    : '<div class="rd-empty">none</div>';
  let bodyBlock;
  if (h.body_preview == null) bodyBlock = '<div class="rd-empty">none</div>';
  else bodyBlock = `<pre class="rd-body">${esc(h.body_preview)}${h.body_truncated ? `\n… +${h.body_len - h.body_preview.length} bytes not shown` : ''}</pre>`;
  return head + `<div class="req-detail">
    <div class="rd-sub">Additional agent headers</div>${hdrs}
    <div class="rd-sub">Body</div>${bodyBlock}</div>`;
}

const COUNTDOWN_LOW_S = 30;
function countdownParts(deadlineIso) {
  const ms = new Date(deadlineIso).getTime() - Date.now();
  const s = Math.max(0, Math.ceil(ms / 1000));
  const text = s === 0 ? 'Expired' : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
  return { s, text };
}
function countdown(deadlineIso) {
  return countdownParts(deadlineIso).text;
}
// The timer only touches the countdown node (no re-render): text, plus the
// urgency classes — pulsing red in the last 30 s, steady red once expired
// (the core auto-denies moments later).
function armCountdown() {
  if (countdownTimer) clearInterval(countdownTimer);
  countdownTimer = setInterval(() => {
    const req = state.queue[0];
    const el = document.getElementById('ap-countdown');
    if (!req || !el) return;
    const { s, text } = countdownParts(req.deadline);
    el.textContent = text;
    el.classList.toggle('low', s > 0 && s <= COUNTDOWN_LOW_S);
    el.classList.toggle('expired', s === 0);
  }, 1000);
}

/* --------------------------------- helpers ------------------------------- */
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

// Flash "Copied" in place of the masked value for a moment after a copy.
let copiedTimer = null;
function flashCopied(id) {
  state.copied = id;
  render();
  if (copiedTimer) clearTimeout(copiedTimer);
  copiedTimer = setTimeout(() => { state.copied = null; render(); }, 1400);
}

let readyCopiedTimer = null;
function flashReadyCopied() {
  state.readyCopied = true;
  render();
  if (readyCopiedTimer) clearTimeout(readyCopiedTimer);
  readyCopiedTimer = setTimeout(() => { state.readyCopied = false; render(); }, 1400);
}

// Focus a sheet field on open (after the render that creates it).
function focusField(id) {
  setTimeout(() => {
    const el = document.getElementById(id);
    if (el) el.focus();
  }, 0);
}

function selectEditSecretMask() {
  setTimeout(() => {
    const el = document.getElementById('f-value');
    if (state.sheet && state.sheet.kind === 'edit-secret' && el && el.value === EDIT_SECRET_MASK) {
      el.focus();
      el.select();
    }
  }, 0);
}

function captureDrafts() {
  const g = (id) => { const el = document.getElementById(id); return el ? el.value : undefined; };
  const gc = (id) => { const el = document.getElementById(id); return el ? el.checked : undefined; };
  if (state.sheet && (state.sheet.kind === 'add-secret' || state.sheet.kind === 'edit-secret')) {
    if (g('f-name') !== undefined) state.draft.name = g('f-name');
    if (g('f-value') !== undefined) state.draft.value = g('f-value');
  }
  if (state.sheet && (state.sheet.kind === 'add-conn' || state.sheet.kind === 'edit-conn')) {
    if (g('f-cname') !== undefined) state.draft.name = g('f-cname');
    if (g('f-import') !== undefined) state.draft.importSource = g('f-import');
    if (g('f-origin') !== undefined) state.draft.origin = g('f-origin');
    if (g('f-host') !== undefined) state.draft.host = g('f-host');
    if (g('f-port') !== undefined) state.draft.port = g('f-port');
    if (g('f-db') !== undefined) state.draft.dbname = g('f-db');
    if (g('f-user') !== undefined) state.draft.user = g('f-user');
    if (g('f-host-key') !== undefined) state.draft.hostKeyFingerprint = g('f-host-key');
    if (g('f-sslmode') !== undefined) state.draft.sslmode = g('f-sslmode');
    if (g('f-url') !== undefined) state.draft.url = g('f-url');
    if (g('c-template') !== undefined) state.draft.template = g('c-template');
    if (g('c-secret') !== undefined) state.draft.secretId = g('c-secret');
    if (g('c-secret-source') !== undefined) state.draft.secretSource = g('c-secret-source');
    if (g('c-new-secret-name') !== undefined) state.draft.newSecretName = g('c-new-secret-name');
    if (g('c-new-secret-value') !== undefined) {
      state.draft.newSecretValue = g('c-new-secret-value');
      delete state.draft.importedCredential;
    }
    if (g('c-auth-mode') !== undefined) state.draft.authMode = g('c-auth-mode');
    if (g('c-auth-detail') !== undefined) state.draft.authDetail = g('c-auth-detail');
    if (gc('c-multi') !== undefined) state.draft.multiConnect = gc('c-multi');
  }
  if (state.sheet && state.sheet.kind === 'settings') {
    if (g('f-pg-ca-bundle') !== undefined) state.draft.pgCaBundlePath = g('f-pg-ca-bundle');
  }
}

/* --------------------------------- actions ------------------------------- */
async function run(fn) {
  try { await fn(); return true; } catch (e) { toast('⚠ ' + (e.message || e)); return false; }
}

async function saveSecret() {
  captureDrafts();
  const name = (state.draft.name || '').trim();
  const value = state.draft.value || '';
  const errs = {};
  if (!name) errs.name = 'Name is required';
  if (state.sheet.kind === 'add-secret' && !value) errs.value = 'Value is required';
  if (Object.keys(errs).length) { state.sheetErrors = errs; render(); return; }
  if (state.sheet.kind === 'add-secret') {
    if (!await run(() => invoke('add_secret', { name, value }))) return;
    toast('🔑 Saved to macOS Keychain');
  } else {
    if (value !== EDIT_SECRET_MASK && (!value || value.includes('•'))) {
      state.sheetErrors = { value: 'Invalid value' };
      render();
      return;
    }
    if (!await run(() => invoke('edit_secret', {
      id: state.sheet.id,
      newName: name,
      newValue: value === EDIT_SECRET_MASK ? null : value,
    }))) return;
    toast('✏️ Secret updated');
  }
  closeSheet();
  await refresh('secrets');
}

async function saveConn() {
  captureDrafts();
  const d = state.draft;
  const name = (d.name || '').trim();
  const t = state.connType;
  const adding = state.sheet.kind === 'add-conn';
  const authMode = d.authMode || 'bearer';
  const errs = {};
  if (!name) errs.name = 'Name is required';
  if (t === 'api' || t === 'pg' || t === 'ssh') {
    if (t !== 'api' && !(d.host || '').trim()) errs.host = 'Host is required';
  }
  let port = t === 'ssh' ? 22 : 5432;
  if (t === 'pg' || t === 'ssh') {
    const portStr = (d.port ?? '').trim() || String(port);
    port = Number(portStr);
    if (!/^\d+$/.test(portStr) || !Number.isInteger(port) || port < 1 || port > 65535) {
      errs.port = 'Port must be 1–65535';
    }
    if (t === 'pg' && !(d.dbname || '').trim()) errs.dbname = 'Database is required';
    if (!(d.user || '').trim()) errs.user = 'User is required';
    if (t === 'ssh' && !(d.hostKeyFingerprint || '').trim()) {
      errs.hostKeyFingerprint = 'Host key fingerprint is required';
    }
  }
  if (t === 'ws') {
    const url = (d.url || '').trim();
    if (!url) errs.url = 'URL is required';
    else if (!/^wss?:\/\//i.test(url)) errs.url = 'Must start with ws:// or wss://';
  }
  let apiOrigin = null;
  if (t === 'api') {
    try { apiOrigin = parseApiOrigin(d.origin || ''); }
    catch (error) { errs.origin = error.message; }
  }
  const usesRecipe = adding && (t === 'api' || t === 'ws') && authMode !== 'advanced';
  const needsCredentialChoice = (adding && !((t === 'api' || t === 'ws') && authMode === 'advanced')) ||
    (!adding && t !== 'api');
  const secretSource = adding
    ? (d.secretSource || (d.importedCredential || !state.secrets.length ? 'new' : 'existing'))
    : 'existing';
  let selectedSecret = null;
  let newSecretName = null;
  if (needsCredentialChoice && secretSource === 'existing') {
    selectedSecret = state.secrets.find((secret) => secret.id === d.secretId) || state.secrets[0] || null;
    if (!selectedSecret) errs.secret = 'Choose a saved credential or save a new one';
  } else if (needsCredentialChoice) {
    newSecretName = (d.newSecretName || suggestedSecretName(name, t)).trim();
    const newSecretValue = d.newSecretValue ?? d.importedCredential ?? '';
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(newSecretName)) {
      errs.newSecretName = 'Use letters, numbers, and underscores; start with a letter or underscore';
    }
    if (!newSecretValue) errs.newSecretValue = 'Credential value is required';
  }
  const templateSecretName = selectedSecret ? selectedSecret.name : newSecretName;
  let injectionTemplate = (d.template || '').trim();
  if (usesRecipe) {
    try { injectionTemplate = authTemplate(t, authMode, templateSecretName || '', (d.authDetail || '').trim()); }
    catch (error) { errs.authDetail = error.message; }
  } else if ((t === 'api' || (adding && t === 'ws')) && authMode === 'advanced' && !injectionTemplate) {
    errs.template = 'Injection template is required';
  } else if (!adding && t === 'api' && !injectionTemplate) {
    errs.template = 'Injection template is required';
  }
  if (Object.keys(errs).length) { state.sheetErrors = errs; render(); return; }
  const input = { name, type: t, multi_connect: t === 'ssh' || d.multiConnect !== false };
  if (adding && needsCredentialChoice && secretSource === 'new') {
    input.new_secret_name = newSecretName;
    input.new_secret_value = d.newSecretValue ?? d.importedCredential;
  }
  if (t === 'api') {
    input.host = apiOrigin.host;
    input.scheme = apiOrigin.scheme;
    input.port = apiOrigin.port;
    input.template = injectionTemplate;
  } else if (t === 'pg') {
    input.host = (d.host || '').trim();
    input.port = port;
    input.dbname = (d.dbname || '').trim();
    input.user = (d.user || '').trim();
    input.sslmode = d.sslmode || 'require';
    if (selectedSecret) input.secret_id = selectedSecret.id;
  } else if (t === 'ssh') {
    input.host = (d.host || '').trim();
    input.port = port;
    input.user = (d.user || '').trim();
    input.host_key_fingerprint = (d.hostKeyFingerprint || '').trim();
    if (selectedSecret) input.secret_id = selectedSecret.id;
  } else {
    input.url = (d.url || '').trim();
    input.template = injectionTemplate || null;
    if (selectedSecret) input.secret_id = selectedSecret.id;
  }
  const cmd = adding ? 'add_connection' : 'edit_connection';
  const args = adding ? { input } : { id: state.sheet.id, input };
  try {
    await invoke(cmd, args);
    toast(state.sheet.kind === 'add-conn' ? '🔌 Connection saved' : '✏️ Connection updated');
    closeSheet();
    await refresh('all');
  } catch (e) {
    toast('⚠ ' + (e.message || e));
  }
}

function closeSheet() {
  state.sheet = null;
  state.draft = {};
  state.sheetErrors = {};
  render();
}

/* --------------------------------- events -------------------------------- */
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-act]');
  // Dismiss the desktop settings popover on any click outside it (its own
  // toggle handles itself; menu-item clicks close it in their handlers).
  if (state.menuOpen && !e.target.closest('.settings-menu') &&
      !(btn && btn.dataset.act === 'toggle-settings-menu')) {
    state.menuOpen = false;
    if (!btn) { render(); return; }
    // fall through: the clicked action runs and its render reflects the close
  }
  if (!btn) return;
  const act = btn.dataset.act;
  const id = btn.dataset.id;
  const name = btn.dataset.name;
  switch (act) {
    case 'tab': state.tab = btn.dataset.tab; state.confirm = null; render(); break;
    case 'mode-tray': state.menuOpen = false; run(() => invoke('ui_set_mode', { mode: 'tray' })); break;
    case 'mode-window': run(() => invoke('ui_set_mode', { mode: 'window' })); break;
    case 'toggle-settings-menu': state.menuOpen = !state.menuOpen; render(); break;
    case 'open-settings': state.menuOpen = false; state.sheet = { kind: 'settings' }; render(); break;
    case 'copy-agent-setup':
      if (await run(() => invoke('copy_agent_setup'))) toast('📋 Setup instructions copied');
      break;
    case 'toggle-setup-instructions':
      state.setupInstructionsOpen = !state.setupInstructionsOpen;
      render();
      break;
    case 'copy-ready-setup':
      if (await run(() => invoke('copy_agent_setup'))) flashReadyCopied();
      break;
    case 'clear-activity-ask':
      state.sheet = { kind: 'clear-activity' };
      render();
      break;
    case 'clear-activity-confirm':
      if (await run(() => invoke('clear_activity'))) {
        state.activity = [];
        closeSheet();
        toast('Activity cleared');
      }
      break;

    case 'reveal-secret':
      await run(async () => { state.reveal[id] = await invoke('reveal_secret_prefix', { id }); render(); });
      break;
    case 'hide-secret':
      delete state.reveal[id]; render(); break;
    case 'copy-secret':
      if (await run(() => invoke('copy_secret', { id }))) {
        toast('📋 Copied for 30s');
        flashCopied(id);
      }
      break;
    case 'del-secret-ask': {
      const s = state.secrets.find((x) => x.id === id);
      state.confirm = { kind: s && s.used_by ? 'del-secret-inuse' : 'del-secret', id };
      render();
      break;
    }
    case 'del-secret-confirm':
      if (await run(() => invoke('delete_secret', { id }))) {
        state.confirm = null; toast('🗑 Removed from macOS Keychain'); await refresh('secrets');
      }
      break;
    case 'edit-secret':
      state.sheet = { kind: 'edit-secret', id };
      state.draft = { value: EDIT_SECRET_MASK };
      state.sheetErrors = {};
      render();
      selectEditSecretMask();
      break;
    case 'open-add-secret': state.sheet = { kind: 'add-secret' }; state.draft = {}; state.sheetErrors = {}; render(); focusField('f-name'); break;
    case 'save-secret': await saveSecret(); break;

    case 'open-add-conn': state.sheet = { kind: 'add-conn' }; state.connType = 'api'; state.draft = {}; state.sheetErrors = {}; render(); focusField('f-cname'); break;
    case 'apply-connection-import': {
      captureDrafts();
      try {
        const imported = parseConnectionImport(state.draft.importSource || '');
        state.connType = imported.type;
        state.draft = {
          ...state.draft,
          ...imported.fields,
          importSource: '',
          name: state.draft.name || imported.name,
          importedCredential: imported.credential,
          importWarnings: imported.warnings,
          port: imported.fields.port == null ? state.draft.port : String(imported.fields.port),
        };
        delete state.sheetErrors.import;
        render(false);
        focusField('f-cname');
      } catch (error) {
        state.sheetErrors.import = error.message;
        render();
      }
      break;
    }
    case 'edit-conn': {
      const c = state.connections.find((x) => x.id === id);
      state.sheet = { kind: 'edit-conn', id }; state.connType = c.type;
      state.sheetErrors = {};
      state.draft = { name: c.name, host: c.host, scheme: c.scheme,
        origin: c.type === 'api' ? apiOriginFromParts(c.scheme, c.host, c.port) : null,
        port: c.port ? String(c.port) : (c.type === 'ssh' ? '22' : '5432'),
        dbname: c.dbname, user: c.user, url: c.url, template: c.template,
        hostKeyFingerprint: c.host_key_fingerprint,
        sslmode: c.sslmode || 'require',
        secretId: null, multiConnect: c.multi_connect };
      // best-effort: prefill single-secret binding by name→id
      if (c.type !== 'api' && c.secret_names.length) {
        const s = state.secrets.find((s) => s.name === c.secret_names[0]);
        if (s) state.draft.secretId = s.id;
      }
      render(); focusField('f-cname'); break;
    }
    case 'conn-type': {
      captureDrafts();
      const nextType = btn.dataset.type;
      state.draft.port = portForTypeSwitch(state.connType, nextType, state.draft.port);
      state.connType = nextType;
      render(false);
      break;
    }
    case 'save-conn': await saveConn(); break;
    case 'del-conn-ask': state.confirm = { kind: 'del-conn', id }; render(); break;
    case 'del-conn-confirm':
      if (await run(() => invoke('delete_connection', { id }))) {
        state.confirm = null; toast('🗑 Connection removed'); await refresh('all');
      }
      break;
    case 'del-permission':
      await run(() => invoke('remove_permission', { id }));
      toast('🔒 Approval will be required again'); await refresh('all');
      break;

    case 'revoke-ask': state.confirm = { kind: 'revoke-agent', id, name }; render(); break;
    case 'revoke-confirm':
      if (await run(() => invoke('revoke_agent', { id }))) {
        state.confirm = null; toast('🔒 Agent disconnected'); await refresh('all');
      }
      break;
    case 'close-session-ask': state.confirm = { kind: 'close-session', id: Number(id) }; render(); break;
    case 'close-session-confirm':
      if (await run(() => invoke('close_session', { id: Number(id) }))) {
        state.confirm = null; toast('⏹ Connection closed'); await refresh('sessions');
      }
      break;
    case 'confirm-cancel': state.confirm = null; render(); break;

    case 'sheet-cancel': closeSheet(); break;
    case 'toggle-reauth':
      {
        const on = !state.settings.reauth_on_read;
        await run(() => invoke('set_reauth_on_read', { on }));
        toast(on ? '💳 Confirmation required before using saved secrets' : '💳 Extra confirmation removed');
      }
      await refresh('settings');
      break;
    case 'toggle-hide-prefixes':
      {
        const on = !state.settings.hide_secret_prefixes;
        if (on) state.reveal = {}; // conceal anything currently revealed
        await run(() => invoke('set_hide_secret_prefixes', { on }));
        toast(on ? '👁 Secret prefixes hidden' : '👁 Secret prefixes shown');
      }
      await refresh('settings');
      break;
    case 'toggle-menubar-dock':
      {
        const on = !state.settings.menu_bar_hides_dock;
        await run(() => invoke('set_menu_bar_hides_dock', { on }));
        toast(on ? '🚢 Dock icon hidden in the menu bar' : '🚢 Dock icon kept in the menu bar');
      }
      await refresh('settings');
      break;
    case 'save-pg-ca-bundle': {
      captureDrafts();
      const path = (state.draft.pgCaBundlePath || '').trim();
      if (await run(() => invoke('set_pg_trusted_ca_bundle_path', { path: path || null }))) {
        state.draft.pgCaBundlePath = path;
        toast(path ? '🔐 Postgres CA bundle saved' : '🔐 Postgres CA bundle cleared');
        await refresh('settings');
      }
      break;
    }
    case 'clear-pg-ca-bundle':
      state.draft.pgCaBundlePath = '';
      if (await run(() => invoke('set_pg_trusted_ca_bundle_path', { path: null }))) {
        toast('🔐 Postgres CA bundle cleared');
        await refresh('settings');
      }
      break;

    // Approval window
    case 'req-detail-toggle': {
      const req = state.queue[0];
      const shownNow = state.reqDetailOpen === null ? (req.http && req.http.mutating) : state.reqDetailOpen;
      state.reqDetailOpen = !shownNow; render(); break;
    }
    case 'pair-inheritance': state.revokeInheritedRules = btn.dataset.revoke === 'true'; render(); break;
    case 'always-toggle': state.alwaysOpen = !state.alwaysOpen; render(); break;

    case 'decide-deny': await decide(id, 'deny'); break;
    case 'decide-allow': await decide(id, mode === 'approval' && state.queue[0] && state.queue[0].kind !== 'pair' ? 'allow_session' : 'allow_once'); break;
    case 'decide-once': await decide(id, 'allow_once'); break;
    case 'always-save': await decide(id, 'always_allow'); break;
    case 'open-approval': run(() => invoke('ui_show_approval')); break;
    default: break;
  }
});

async function decide(id, decision) {
  try {
    const req = state.queue[0];
    const revokeInheritedRules =
      decision === 'allow_once' && req && req.kind === 'pair' && !!state.revokeInheritedRules;
    await invoke('decide', { id, decision, revokeInheritedRules });
    state.alwaysOpen = false;
    state.reqDetailOpen = null;
    state.revokeInheritedRules = false;
  } catch (e) {
    // OS authentication cancelled or failed: keep the request pending.
    toast('🔒 ' + (e.message || e));
  }
  await refresh('queue');
}

document.addEventListener('keydown', (e) => {
  // Ctrl-Tab / Ctrl-Shift-Tab cycle the left-nav tabs when the main window is
  // open (the approval window has no tabs; a modal sheet keeps focus).
  if (e.key === 'Tab' && e.ctrlKey && mode !== 'approval' && !state.sheet) {
    e.preventDefault();
    const i = TABS.indexOf(state.tab);
    const n = TABS.length;
    state.tab = TABS[(i + (e.shiftKey ? -1 : 1) + n) % n];
    state.menuOpen = false;
    render();
    return;
  }
  if (e.key === 'Escape') {
    if (state.menuOpen) { state.menuOpen = false; render(); return; }
    if (state.sheet) { closeSheet(); return; }
    if (state.confirm) { state.confirm = null; render(); return; }
    if (mode === 'dropdown') invoke('ui_hide_dropdown');
  } else if (e.key === 'Enter' && e.target.tagName === 'INPUT') {
    if (state.sheet && (state.sheet.kind === 'add-secret' || state.sheet.kind === 'edit-secret')) { e.preventDefault(); saveSecret(); }
    else if (state.sheet && (state.sheet.kind === 'add-conn' || state.sheet.kind === 'edit-conn')) { e.preventDefault(); saveConn(); }
  } else if (e.key === 'Tab' && state.sheet) {
    // Keep keyboard focus inside the modal sheet, wrapping at either end.
    const sheet = document.querySelector('.sheet');
    if (!sheet) return;
    const focusables = sheet.querySelectorAll(
      'button:not([disabled]), input:not([disabled]), select:not([disabled]), summary');
    if (!focusables.length) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const inside = sheet.contains(document.activeElement);
    if (e.shiftKey && (!inside || document.activeElement === first)) {
      e.preventDefault(); last.focus();
    } else if (!e.shiftKey && (!inside || document.activeElement === last)) {
      e.preventDefault(); first.focus();
    }
  }
});

// Editing a field clears its inline validation error.
const ERR_KEY_BY_INPUT = {
  'f-name': 'name', 'f-value': 'value', 'f-import': 'import',
  'f-cname': 'name', 'f-origin': 'origin', 'f-host': 'host', 'f-port': 'port',
  'f-db': 'dbname', 'f-user': 'user', 'f-host-key': 'hostKeyFingerprint',
  'f-url': 'url', 'c-template': 'template', 'c-secret': 'secret',
  'c-new-secret-name': 'newSecretName', 'c-new-secret-value': 'newSecretValue',
  'c-auth-detail': 'authDetail',
};
document.addEventListener('input', (e) => {
  const key = e.target && ERR_KEY_BY_INPUT[e.target.id];
  if (key && state.sheetErrors[key]) {
    delete state.sheetErrors[key];
    render();
  }
});

// These selects reveal a different, stateful portion of the form. Capture
// first so switching does not discard fields the user may switch back to.
document.addEventListener('change', (e) => {
  if (!e.target || !['c-secret-source', 'c-auth-mode'].includes(e.target.id)) return;
  captureDrafts();
  render(false);
});

/* --------------------------------- boot ---------------------------------- */
async function boot() {
  await refresh(mode === 'approval' ? 'queue' : 'all');
  if (mode !== 'approval') scheduleAccessExpiryRefresh();
  // Hover tooltips (absolute timestamps on activity rows, etc.). Delegated
  // from #root so they survive re-renders; content is each element's
  // data-tippy-content. Vendored Tippy.js (self-hosted for the 'self' CSP).
  if (window.tippy) {
    window.tippy.delegate('#root', {
      target: '[data-tippy-content]',
      delay: [250, 0],
      duration: [120, 80],
    });
  }
  // Relative timestamps drift; re-render the activity view every minute so
  // "just now" becomes "1m", etc., while that tab is open.
  setInterval(() => {
    if (mode !== 'approval' && state.tab === 'activity' && !state.sheet && !state.menuOpen) render();
  }, 60000);
  // Access sessions are in-memory and expire without a persisted state
  // change. Refresh access rows and agent summaries so expiry disappears
  // promptly everywhere it is presented.
  setInterval(() => {
    if (mode !== 'approval' && !state.sheet && !state.menuOpen) refreshAccessViews();
  }, 30000);
  // Live updates from the core.
  await listen('amfa://queue-changed', (ev) => { state.queue = ev.payload || []; render(); });
  await listen('amfa://sessions-changed', () => refresh('sessions'));
  await listen('amfa://agents-changed', async () => {
    const before = new Map(state.agents.map((agent) => [agent.name, agent.paired_at]));
    await load('agents', 'list_agents');
    render();
    const connected = state.agents.find((agent) =>
      !before.has(agent.name) || before.get(agent.name) !== agent.paired_at);
    if (connected) toast(`🔗 ${connected.name} is connected and can now ask to use your connections`);
  });
  await listen('amfa://rules-changed', () => {
    if (mode !== 'approval') refreshAccessViews();
  });
  await listen('amfa://activity-appended', (ev) => receiveActivity(ev.payload));
  await listen('amfa://activity-changed', () => refresh('activity'));
  await listen('amfa://open-settings', () => {
    state.sheet = { kind: 'settings' };
    state.draft = {};
    state.sheetErrors = {};
    render();
  });
  await listen('amfa://dropdown-hidden', () => {
    state.reveal = {};
    state.sheet = null;
    state.draft = {};
    state.sheetErrors = {};
    state.confirm = null;
    render();
  });
}
boot();
