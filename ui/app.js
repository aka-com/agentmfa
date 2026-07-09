// AgentMFA frontend. One file drives both Tauri windows (the main window and
// the approval window), chosen from location.hash. Every mutation and
// read goes through the Rust core via Tauri commands; the webview never
// holds a secret value (DESIGN.md §2). When run outside Tauri (a plain
// browser), a dev mock stands in for the core so the UI is developable
// standalone.

import { invoke, listen, mode } from '/src/bridge.js';
import { ICONS, TYPES, esc, escAttr, toast, relTime, absTime } from '/src/util.js';

const EDIT_SECRET_MASK = '••••••••••••';

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
  settings: { icloud_sync: true, reauth_on_read: true, hide_secret_prefixes: true, pg_trusted_ca_bundle_path: null, menu_bar_hides_dock: false },
  reveal: {},            // secretId -> prefix string (transient)
  // sheet / confirm state
  sheet: null,           // {kind:'add-secret'|'edit-secret'|'add-conn'|'edit-conn'|'settings', ...}
  draft: {},
  sheetErrors: {},       // field key -> inline validation message
  connType: 'api',
  confirm: null,         // {kind, id/name}
  syncConfirm: false,    // 'on' | 'off' | false
  alwaysOpen: false,
  reqDetailOpen: null,   // approval payload disclosure override
  revokeInheritedRules: false,
  menuOpen: false,       // desktop-mode settings popover (gear) open
  copied: null,          // secretId whose value was just copied (transient "Copied" flash)
};

const root = () => document.getElementById('root');

/* ------------------------------ data loading ----------------------------- */
async function refresh(which = 'all') {
  const jobs = [];
  if (which === 'all' || which === 'secrets') jobs.push(load('secrets', 'list_secrets'));
  if (which === 'all' || which === 'connections') jobs.push(load('connections', 'list_connections'));
  if (which === 'all' || which === 'agents') jobs.push(load('agents', 'list_agents'));
  if (which === 'all' || which === 'sessions') jobs.push(load('sessions', 'list_sessions'));
  if (which === 'all' || which === 'activity') jobs.push(load('activity', 'list_activity'));
  if (which === 'all' || which === 'queue') jobs.push(load('queue', 'get_queue'));
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

/* --------------------------------- render -------------------------------- */
// Rebuilding #root from scratch would drop anything the DOM holds that state
// doesn't: in-progress sheet input and the focused control. Broker events
// (queue/sessions/activity changes) re-render at arbitrary times, so every
// render first captures open drafts and then puts focus (and any text
// selection) back where it was.
function render() {
  captureDrafts();
  const active = document.activeElement;
  const focusId = active && active.id ? active.id : null;
  const sel = focusId && typeof active.selectionStart === 'number'
    ? { start: active.selectionStart, end: active.selectionEnd, dir: active.selectionDirection }
    : null;

  if (mode === 'approval') renderApproval();
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
  return `<div class="pending-banner"><span>⏳ ${state.queue.length} approval${state.queue.length > 1 ? 's' : ''} pending</span>
    <button class="btn sm" data-act="open-approval">Review</button></div>`;
}

function globalSectionsHTML() {
  let out = '';
  if (state.agents.length) {
    out += '<div class="live-head">Paired agents</div>' + state.agents.map((a) => {
      const sub = `${a.identity} · token ${a.token_preview}` +
        (a.rule_count ? ` · ${a.rule_count} auto-allow rule${a.rule_count > 1 ? 's' : ''}` : '');
      if (state.confirm && state.confirm.kind === 'revoke-agent' && state.confirm.name === a.name) {
        return `<div class="live-row"><span class="badge b-agent">agent</span>
          <div class="live-txt"><div class="c-name">${esc(a.name)}</div>
          <div class="s-sub">Revoke this agent’s pair token?</div></div>
          <button class="btn sm" data-act="confirm-cancel">Cancel</button>
          <button class="btn sm danger" data-act="revoke-confirm" data-name="${escAttr(a.name)}">Revoke</button></div>`;
      }
      return `<div class="live-row"><span class="badge b-agent">agent</span>
        <div class="live-txt"><div class="c-name">${esc(a.name)}</div>
        <div class="s-sub" style="max-width:260px" title="${escAttr(sub)}">${esc(sub)}</div></div>
        <button class="btn sm" data-act="revoke-ask" data-name="${escAttr(a.name)}">Revoke</button></div>`;
    }).join('');
  }
  if (state.sessions.length) {
    out += '<div class="live-head">Live sessions</div>' + state.sessions.map((s) => {
      const t = TYPES[s.type];
      // who holds the session matters as much as what it's connected to
      const who = s.agent ? `${esc(s.agent)} → ${esc(s.connection)}` : esc(s.connection);
      if (state.confirm && state.confirm.kind === 'close-session' && state.confirm.id === s.id) {
        return `<div class="live-row"><span class="badge ${t.cls}">${t.label}</span>
          <div class="live-txt"><div class="c-name">${who}</div>
          <div class="s-sub">Close this live session?</div></div>
          <button class="btn sm" data-act="confirm-cancel">Cancel</button>
          <button class="btn sm danger" data-act="close-session-confirm" data-id="${s.id}">Close</button></div>`;
      }
      return `<div class="live-row"><span class="badge ${t.cls}">${t.label}</span>
        <div class="live-txt"><div class="c-name">${who}</div>
        <div class="s-sub" title="${escAttr(s.detail)}">${esc(s.detail)}</div></div>
        <button class="btn sm" data-act="close-session-ask" data-id="${s.id}">Close</button></div>`;
    }).join('');
  }
  return out ? `<div class="dd-global">${out}</div>` : '';
}

function secretsHTML() {
  if (!state.secrets.length) {
    return `<div class="empty"><div class="empty-ico">🔐</div><h3>No secrets yet</h3>
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
      <td><div><div class="s-name">${esc(s.name)}</div><div class="s-sub">${esc(sub)}</div></div></td>
      <td class="val"><span class="val-wrap"><span class="val-slot ${copied ? 'is-copied' : ''}"><code>${valText}</code><span class="val-overlay">${overlay}</span></span></span> ${eyeBtn}</td>
      <td class="rowdel">
        <button class="icon-btn" title="Edit secret" aria-label="Edit secret ${escAttr(s.name)}" data-act="edit-secret" data-id="${s.id}">${ICONS.pencil}</button>
        <button class="icon-btn" title="Delete secret" aria-label="Delete secret ${escAttr(s.name)}" data-act="del-secret-ask" data-id="${s.id}">${ICONS.trash}</button></td></tr>`;
  }).join('');
  return `<table class="sec-table"><tbody>${rows}</tbody></table>`;
}

/* ---- connections tab ---- */
const ruleChipsHTML = (c) => c.rules.map((r) =>
  `<div class="allow-chip">⚡ ${esc(r.agent)}<button title="Remove auto-allow" aria-label="Remove auto-allow for ${escAttr(r.agent)}" data-act="del-rule" data-id="${r.id}">✕</button></div>`).join('');
const liveCount = (c) => state.sessions.filter((s) => s.connection === c.name).length;
const connActionsHTML = (c) =>
  `<button class="icon-btn" title="Edit connection" aria-label="Edit connection ${escAttr(c.name)}" data-act="edit-conn" data-id="${c.id}">${ICONS.pencil}</button>
   <button class="icon-btn" title="Delete connection" aria-label="Delete connection ${escAttr(c.name)}" data-act="del-conn-ask" data-id="${c.id}">${ICONS.trash}</button>`;

// Card grid, after TablePlus launchers / Keybase device cards: one
// connection = one object with everything about it inside its border.
function connectionsHTML() {
  if (!state.connections.length) {
    return `<div class="empty"><div class="empty-ico">🔌</div><h3>No connections yet</h3>
      <p>Connect to APIs, databases, remote servers, etc.</p>
      <button class="btn primary" data-act="open-add-conn">＋ Add connection</button></div>`;
  }
  return `<div class="conn-cards">` + state.connections.map((c) => {
    const t = TYPES[c.type];
    if (state.confirm && state.confirm.kind === 'del-conn' && state.confirm.id === c.id) {
      return `<div class="conn-card confirm-card">
        <div class="cc-top"><span class="badge ${t.cls}">${t.label}</span>
          <span class="c-name" title="${escAttr(c.name)}">${esc(c.name)}</span></div>
        <div class="cc-confirm">Delete this connection?${c.rules.length ? ' Its auto-allow rules are removed too.' : ''}</div>
        <div class="cc-foot"><button class="btn sm" data-act="confirm-cancel">Cancel</button>
          <button class="btn sm danger" data-act="del-conn-confirm" data-id="${c.id}">Delete</button></div></div>`;
    }
    const chips = c.secret_names.map((n) => `<span class="key-chip">🔑 ${esc(n)}</span>`).join('');
    return `<div class="conn-card">
      <div class="cc-top"><span class="badge ${t.cls}">${t.label}</span>
        <span class="c-name" title="${escAttr(c.name)}">${esc(c.name)}</span>
        ${liveCount(c) ? '<span class="cc-live">● live</span>' : ''}</div>
      <div class="cc-target" title="${escAttr(c.target)}">${esc(c.target)}</div>
      <div class="cc-chips">${chips}${ruleChipsHTML(c)}</div>
      <div class="cc-foot">${connActionsHTML(c)}</div></div>`;
  }).join('') + `</div>`;
}

// Console.app-style rows: a mono timestamp gutter, then the emoji the core
// already records for the entry, then the two-line anatomy (plain primary
// line + smaller, fainter detail line).
function activityHTML() {
  if (!state.activity.length) {
    return `<div class="muted-note">No activity yet.<br>Pair an agent and make a request to get started.</div>`;
  }
  return '<div class="act-list">' + state.activity.map((a) =>
    `<div class="act-row" data-tippy-content="${escAttr(absTime(a.at))}">
      <span class="act-gutter">${esc(relTime(a.at))}</span>
      <span class="act-ico">${a.icon}</span>
      <span class="act-txt">${esc(a.text)}${a.detail ? `<div class="act-detail">${esc(a.detail)}</div>` : ''}</span></div>`
  ).join('') + '</div>';
}

function tabContentHTML() {
  return state.tab === 'secrets' ? secretsHTML()
    : state.tab === 'connections' ? connectionsHTML()
    : activityHTML();
}

function renderMainWindow() {
  const nav = TABS.map((tb) =>
    `<button class="nav-item ${state.tab === tb ? 'on' : ''}" data-act="tab" data-tab="${tb}">${cap(tb)}</button>`).join('');
  // One Add affordance, always in the header row next to the view title.
  const addBtn = state.tab === 'connections'
    ? `<button class="btn" data-act="open-add-conn">＋ Add connection</button>`
    : state.tab === 'secrets'
    ? `<button class="btn" data-act="open-add-secret">＋ Add secret</button>` : '';
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
          <div><div class="dd-title">AgentMFA</div><div class="dd-sub"><span class="dot"></span>broker.sock</div></div></div>
        <div class="dw-nav">${nav}</div>
        <div class="dw-settings">${menu}
          <button class="nav-item gear-btn ${state.menuOpen ? 'on' : ''}" data-act="toggle-settings-menu" title="Settings" aria-label="Settings">${ICONS.gear}</button>
        </div>
      </div>
      <div class="dw-main">
        <div class="dw-head"><h2>${cap(state.tab)}</h2>${addBtn}</div>
        ${pendingBannerHTML()}
        ${globalSectionsHTML()}
        <div class="content">${tabContentHTML()}</div>
      </div>
    </div></div>${sheetsHTML()}`;
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
    default: return '';
  }
}

// Inline per-field validation: saveSecret/saveConn fill state.sheetErrors
// keyed by field, the sheet renders the message under the offending input,
// and editing the field clears its error (the `input` listener below).
const fieldErr = (key) =>
  state.sheetErrors[key] ? `<div class="field-error">${esc(state.sheetErrors[key])}</div>` : '';
const fieldCls = (key) => (state.sheetErrors[key] ? 'err' : '');

function addSecretSheet(editing) {
  const d = state.draft;
  const s = editing ? state.secrets.find((x) => x.id === state.sheet.id) : null;
  const title = editing ? 'Edit secret' : 'Add secret';
  const valueLabel = editing ? 'New value' : 'Value';
  const valuePlaceholder = editing ? '' : 'Your secret (saved in Keychain)';
  const keychainNote = editing ? '<span class="keychain-note">🔒 Saved to macOS Keychain</span>' : '';
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>${title}</h3>
    <div class="f-row"><label>Name</label><input id="f-name" class="${fieldCls('name')}" placeholder="e.g. STRIPE_API_KEY" value="${escAttr(d.name ?? (s ? s.name : ''))}">${fieldErr('name')}</div>
    <div class="f-row"><label>${valueLabel}</label><input id="f-value" class="${fieldCls('value')}" type="password" placeholder="${valuePlaceholder}" value="${escAttr(d.value ?? '')}">${fieldErr('value')}</div>
    <div class="sheet-actions">${keychainNote}
      <button class="btn" data-act="sheet-cancel">Cancel</button>
      <button class="btn primary" data-act="save-secret">Save</button></div></div>`;
}

function connSheet(editing) {
  const d = state.draft;
  const t = state.connType;
  const conn = editing ? state.connections.find((c) => c.id === state.sheet.id) : null;
  const typeBtn = (val, label) => {
    if (editing) return `<button type="button" class="seg-btn ${t === val ? 'on' : ''}" disabled ${t === val ? '' : 'style="opacity:.35"'}>${label}</button>`;
    return `<button type="button" class="seg-btn ${t === val ? 'on' : ''}" data-act="conn-type" data-type="${val}">${label}</button>`;
  };
  let fields = `<div class="f-row"><label>Name</label><input id="f-cname" class="${fieldCls('name')}" placeholder="e.g. github" value="${escAttr(d.name ?? '')}">${fieldErr('name')}</div>
    <div class="f-row"><label>Type${editing ? ': fixed after creation' : ''}</label>
    <div class="seg in-form">${typeBtn('api', 'API key')}${typeBtn('pg', 'Postgres')}${typeBtn('ssh', 'SSH')}${typeBtn('ws', 'WebSocket')}</div></div>`;
  if (t === 'api') {
    fields += `<div class="f-row"><label>Host</label><input id="f-host" class="${fieldCls('host')}" placeholder="api.github.com" value="${escAttr(d.host ?? '')}">${fieldErr('host')}</div>`;
  } else if (t === 'ssh') {
    fields += `<div class="f-2col">
      <div class="f-row"><label>Host</label><input id="f-host" class="${fieldCls('host')}" placeholder="prod.example.com" value="${escAttr(d.host ?? '')}">${fieldErr('host')}</div>
      <div class="f-row" style="flex:0 0 90px"><label>Port</label><input id="f-port" class="${fieldCls('port')}" inputmode="numeric" value="${escAttr(d.port ?? '22')}">${fieldErr('port')}</div></div>
      <div class="f-row"><label>User</label><input id="f-user" class="${fieldCls('user')}" placeholder="deploy" value="${escAttr(d.user ?? '')}">${fieldErr('user')}</div>`;
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
      <div class="f-row"><label>TLS mode</label><select id="f-sslmode">${sslOpts}</select></div>`;
  } else {
    fields += `<div class="f-row"><label>URL</label><input id="f-url" class="${fieldCls('url')}" placeholder="wss://stream.example.com/feed" value="${escAttr(d.url ?? '')}">${fieldErr('url')}</div>`;
  }
  // Secret picker (pg/ws bind one; api derives refs from the template).
  if (t !== 'api') {
    const secretLabel = t === 'pg' ? 'Password secret'
      : t === 'ssh' ? 'Private key secret'
      : 'Token secret';
    const hasSecrets = state.secrets.length > 0;
    const opts = state.secrets.map((s) =>
      `<option value="${escAttr(s.id)}" ${d.secretId === s.id ? 'selected' : ''}>${esc(s.name)}</option>`).join('');
    fields += `<div class="f-row"><label>${secretLabel}</label><select id="c-secret" ${hasSecrets ? '' : 'disabled'}>${hasSecrets ? opts : '<option>No secrets, add one first</option>'}</select></div>`;
    if (t !== 'ssh') {
      fields += `<div class="f-row"><label style="display:flex;align-items:center;gap:7px;cursor:pointer">
        <input type="checkbox" id="c-multi" ${d.multiConnect !== false ? 'checked' : ''} style="width:auto">
        <span>Allow multiple client connections per approval</span></label>
        <div class="rule-note">Pools and reconnecting clients may redeem the session ticket any number of times within its 60s window, under the one approval.</div></div>`;
    }
  } else {
    fields += `<div class="f-row"><label>Injection template</label>
      <input id="c-template" placeholder="Authorization: Bearer {{GITHUB_API_KEY}}" value="${escAttr(d.template ?? '')}">
      <div class="rule-note">References secrets by name in <code>{{ … }}</code>. API connections may compose several (e.g. <code>base64(USER ":" PASS)</code>).</div></div>`;
  }
  if (editing && conn && conn.rules.length) {
    fields += `<div class="rule-note">Changing the target resets this connection’s auto-allow rules.</div>`;
  }
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>${editing ? 'Edit connection' : 'Add connection'}</h3>${fields}
    <div class="sheet-actions"><span class="keychain-note">👆 Confirmed with Touch ID</span>
      <button class="btn" data-act="sheet-cancel">Cancel</button>
      <button class="btn primary" data-act="save-conn">Save</button></div></div>`;
}

function settingsSheet() {
  const s = state.settings;
  const pgCaPath = state.draft.pgCaBundlePath ?? s.pg_trusted_ca_bundle_path ?? '';
  let confirm = '';
  if (state.syncConfirm) {
    const on = state.syncConfirm === 'on';
    const head = on ? 'Turn on iCloud Keychain sync?' : 'Turn off iCloud Keychain sync?';
    const body = on
      ? 'Every secret is rewritten in the Keychain as a synchronizable item that rides iCloud Keychain to your other Macs.'
      : 'Every secret is rewritten as a this-device-only item. iCloud propagates the deletion, so the synced copies are removed from your other Macs. After this, the secrets exist only on this Mac.';
    confirm = `<div class="sync-confirm"><span class="sc-head">${head}</span>${body}
      <div style="margin-top:8px;display:flex;gap:8px;justify-content:flex-end">
        <button class="btn sm" data-act="sync-confirm-no">Cancel</button>
        <button class="btn sm primary" data-act="sync-confirm-yes">${on ? 'Turn on sync' : 'Turn off sync'}</button></div></div>`;
  }
  const reauthRow = `<div class="set-row"><div class="set-txt"><div class="st-title">Require Touch ID to read secrets</div>
      <div class="st-sub">Re-authenticate before reveal, copy, or agent credential injection.</div></div>
      <button class="switch ${s.reauth_on_read ? 'on' : ''}" data-act="toggle-reauth" role="checkbox" aria-checked="${s.reauth_on_read ? 'true' : 'false'}"></button></div>`;
  const prefixRow = `<div class="set-row"><div class="set-txt"><div class="st-title">Hide secret prefixes</div>
      <div class="st-sub">Remove the reveal-prefix eye from the secrets list; values stay copy-only.</div></div>
      <button class="switch ${s.hide_secret_prefixes ? 'on' : ''}" data-act="toggle-hide-prefixes" role="checkbox" aria-checked="${s.hide_secret_prefixes ? 'true' : 'false'}"></button></div>`;
  const dockRow = `<div class="set-row"><div class="set-txt"><div class="st-title">Hide Dock icon in the menu bar</div>
      <div class="st-sub">When you minimize to the menu bar, also remove the Dock icon until the window is reopened.</div></div>
      <button class="switch ${s.menu_bar_hides_dock ? 'on' : ''}" data-act="toggle-menubar-dock" role="checkbox" aria-checked="${s.menu_bar_hides_dock ? 'true' : 'false'}"></button></div>`;
  const pgTls = `<details class="set-collapse" ${pgCaPath ? 'open' : ''}>
      <summary>Postgres TLS</summary>
      <div class="set-panel">
        <div class="f-row"><label>Trusted CA bundle path</label>
          <input id="f-pg-ca-bundle" placeholder="/path/to/ca-bundle.pem" value="${escAttr(pgCaPath)}"></div>
        <div class="rule-note">PEM certificates trusted for Postgres verify-ca and verify-full.</div>
        <div class="set-actions">
          <button class="btn sm" data-act="clear-pg-ca-bundle">Clear</button>
          <button class="btn sm primary" data-act="save-pg-ca-bundle">Save</button>
        </div>
      </div>
    </details>`;
  return `<div class="sheet-backdrop" data-act="sheet-cancel"></div>
    <div class="sheet wide"><h3>Settings</h3>
    <div class="set-row"><div class="set-txt"><div class="st-title">Sync secrets via iCloud Keychain</div>
      <div class="st-sub">Allows secrets to sync to your other devices.</div></div>
      <button class="switch ${s.icloud_sync ? 'on' : ''}" data-act="toggle-sync" role="checkbox" aria-checked="${s.icloud_sync ? 'true' : 'false'}" aria-label="Sync secrets via iCloud Keychain"></button></div>
    ${confirm}${reauthRow}${prefixRow}${dockRow}${pgTls}
    <div class="sheet-actions"><button class="btn primary" data-act="sheet-cancel">Done</button></div></div>`;
}

/* ----------------------------- approval window --------------------------- */
let countdownTimer = null;

function renderApproval() {
  const req = state.queue[0];
  const el = root();
  if (!req) {
    el.innerHTML = `<div class="surface approval"><div class="ap-empty">No pending approvals.</div></div>`;
    return;
  }
  const conn = req.connection;
  const t = conn ? TYPES[conn.type] : null;
  const isPair = req.kind === 'pair';
  const cd = countdownParts(req.deadline);
  const connCell = conn
    ? (t ? `<span class="badge ${t.cls}">${t.label}</span> ` : '') + `<b>${esc(conn.name)}</b>`
    : '';
  const connectionRow = conn ? `<div class="ap-row"><span>Connection</span><span>${connCell}</span></div>` : '';
  const targetRow = conn ? `<div class="ap-row"><span>Target</span><code>${esc(conn.target)}</code></div>` : '';
  const scopeRow = (req.kind === 'pg' || req.kind === 'ws' || req.kind === 'ssh') && conn && conn.multi_connect
    ? `<div class="ap-row"><span>Scope</span><span>All connects within the 60 s ticket window · up to 60 sessions</span></div>` : '';
  const identityRow = isPair
    ? `<div class="ap-row"><span>Identity</span><code title="The issued token is pinned to this peer identity">${esc(req.identity || 'Unsigned/ad-hoc, no local fingerprint')}</code></div>` : '';

  let inherit = '';
  if (isPair && req.inherited && req.inherited.length) {
    const revoked = state.revokeInheritedRules;
    inherit = `<div class="inherit-warn"><span class="iw-head">⚠ This pairing inherits permissions</span>
      <div class="inherit-grants ${revoked ? 'revoked' : ''}">Approving this pairing grants access to these previously-authorized connections:
      <ul>${req.inherited.map((c) => `<li><code>${esc(`${c.name} (${TYPES[c.type].label.toLowerCase()} · ${c.target})`)}</code></li>`).join('')}</ul></div>
      <label class="inherit-revoke"><input type="checkbox" data-act="toggle-inherited-revoke" ${revoked ? 'checked' : ''}> Revoke prior standing permissions on approval</label></div>`;
  }

  const detail = requestDetailHTML(req);

  let always = '';
  if (!isPair) {
    const box = state.alwaysOpen
      ? `<div class="always-box"><div class="f-row"><label>Auto-allow rule <span class="stub-badge">policy engine v1 stub</span></label>
        <div class="rule-line"><code>${esc(req.agent)}</code> → <code>${esc(req.connection ? req.connection.name : '')}</code></div>
        <div class="rule-note">Future requests on this connection are approved automatically. Remove it anytime from the Connections tab. Saving requires Touch ID.</div></div>
        <button class="btn primary sm" data-act="always-save">Save rule &amp; allow</button></div>` : '';
    always = { btn: `<button class="btn ghost sm" data-act="always-toggle">Always allow…</button>`, box };
  }

  // The window is fixed-size and non-resizable, so the variable-height
  // middle (rows, payload, inherited-permissions list) scrolls; Deny/Allow
  // can never be pushed out of reach.
  el.innerHTML = `<div class="surface approval">
    <div class="ap-head"><div class="ap-icon">🔐</div>
      <div><div class="ap-title">Approval required</div></div></div>
    <div class="ap-scroll">
    <div class="ap-rows">
      <div class="ap-row"><span>Agent</span><b>${esc(req.agent)}</b></div>
      ${identityRow}
      ${connectionRow}
      ${targetRow}
      <div class="ap-row"><span>Action</span><code>${esc(req.action)}</code></div>
      ${scopeRow}
      <div class="ap-row"><span>Approve within</span><span><span class="ap-countdown${cd.s === 0 ? ' expired' : cd.s <= COUNTDOWN_LOW_S ? ' low' : ''}" id="ap-countdown">${cd.text}</span></span></div>
    </div>
    ${detail}${inherit}
    </div>
    <div class="ap-buttons">
      <button class="btn deny" data-act="decide-deny" data-id="${req.id}">Deny</button>
      ${always ? always.btn : ''}
      <span class="spacer"></span>
      <button class="btn primary" data-act="decide-allow" data-id="${req.id}">${isPair ? 'Approve pairing' : 'Allow once'}</button></div>
    ${always ? always.box : ''}
    ${state.queue.length > 1 ? `<div class="aw-queue">${state.queue.length - 1} more pending</div>` : ''}
  </div>`;
  armCountdown();
}

function requestDetailHTML(req) {
  if (req.kind !== 'http' || !req.http) return '';
  const h = req.http;
  const shown = state.reqDetailOpen === null ? h.mutating : state.reqDetailOpen;
  const head = `<div class="req-detail-head"><button class="btn ghost sm" data-act="req-detail-toggle">${shown ? '▾' : '▸'} Request payload${h.mutating ? `<span class="mut-tag">${esc(h.method)}</span>` : ''}</button></div>`;
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
    if (g('f-host') !== undefined) state.draft.host = g('f-host');
    if (g('f-port') !== undefined) state.draft.port = g('f-port');
    if (g('f-db') !== undefined) state.draft.dbname = g('f-db');
    if (g('f-user') !== undefined) state.draft.user = g('f-user');
    if (g('f-sslmode') !== undefined) state.draft.sslmode = g('f-sslmode');
    if (g('f-url') !== undefined) state.draft.url = g('f-url');
    if (g('c-template') !== undefined) state.draft.template = g('c-template');
    if (g('c-secret') !== undefined) state.draft.secretId = g('c-secret');
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
  const errs = {};
  if (!name) errs.name = 'Name is required';
  if (t === 'api' || t === 'pg' || t === 'ssh') {
    if (!(d.host || '').trim()) errs.host = 'Host is required';
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
  }
  if (t === 'ws') {
    const url = (d.url || '').trim();
    if (!url) errs.url = 'URL is required';
    else if (!/^wss?:\/\//i.test(url)) errs.url = 'Must start with ws:// or wss://';
  }
  if (Object.keys(errs).length) { state.sheetErrors = errs; render(); return; }
  const input = { name, type: t, multi_connect: t === 'ssh' || d.multiConnect !== false };
  if (t === 'api') {
    input.host = (d.host || '').trim();
    input.template = (d.template || '').trim();
  } else if (t === 'pg') {
    input.host = (d.host || '').trim();
    input.port = port;
    input.dbname = (d.dbname || '').trim();
    input.user = (d.user || '').trim();
    input.sslmode = d.sslmode || 'require';
    input.secret_id = d.secretId || (state.secrets[0] && state.secrets[0].id);
  } else if (t === 'ssh') {
    input.host = (d.host || '').trim();
    input.port = port;
    input.user = (d.user || '').trim();
    input.secret_id = d.secretId || (state.secrets[0] && state.secrets[0].id);
  } else {
    input.url = (d.url || '').trim();
    input.secret_id = d.secretId || (state.secrets[0] && state.secrets[0].id);
  }
  const cmd = state.sheet.kind === 'add-conn' ? 'add_connection' : 'edit_connection';
  const args = state.sheet.kind === 'add-conn' ? { input } : { id: state.sheet.id, input };
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
  state.syncConfirm = false;
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
    case 'toggle-settings-menu': state.menuOpen = !state.menuOpen; render(); break;
    case 'open-settings': state.menuOpen = false; state.sheet = { kind: 'settings' }; render(); break;

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
    case 'edit-conn': {
      const c = state.connections.find((x) => x.id === id);
      state.sheet = { kind: 'edit-conn', id }; state.connType = c.type;
      state.sheetErrors = {};
      state.draft = { name: c.name, host: c.host,
        port: c.port ? String(c.port) : (c.type === 'ssh' ? '22' : '5432'),
        dbname: c.dbname, user: c.user, url: c.url, template: c.template,
        sslmode: c.sslmode || 'require',
        secretId: null, multiConnect: c.multi_connect };
      // best-effort: prefill single-secret binding by name→id
      if (c.type !== 'api' && c.secret_names.length) {
        const s = state.secrets.find((s) => s.name === c.secret_names[0]);
        if (s) state.draft.secretId = s.id;
      }
      render(); focusField('f-cname'); break;
    }
    case 'conn-type': captureDrafts(); state.connType = btn.dataset.type; render(); break;
    case 'save-conn': await saveConn(); break;
    case 'del-conn-ask': state.confirm = { kind: 'del-conn', id }; render(); break;
    case 'del-conn-confirm':
      if (await run(() => invoke('delete_connection', { id }))) {
        state.confirm = null; toast('🗑 Connection removed'); await refresh('all');
      }
      break;
    case 'del-rule':
      await run(() => invoke('remove_rule', { id }));
      toast('🗑 Auto-allow removed'); await refresh('connections');
      break;

    case 'revoke-ask': state.confirm = { kind: 'revoke-agent', name }; render(); break;
    case 'revoke-confirm':
      if (await run(() => invoke('revoke_agent', { name }))) {
        state.confirm = null; toast('🔒 Pair token revoked'); await refresh('agents');
      }
      break;
    case 'close-session-ask': state.confirm = { kind: 'close-session', id: Number(id) }; render(); break;
    case 'close-session-confirm':
      if (await run(() => invoke('close_session', { id: Number(id) }))) {
        state.confirm = null; toast('⏹ Session closed'); await refresh('sessions');
      }
      break;
    case 'confirm-cancel': state.confirm = null; render(); break;

    case 'sheet-cancel': closeSheet(); break;
    case 'toggle-sync':
      state.syncConfirm = state.syncConfirm ? false : (state.settings.icloud_sync ? 'off' : 'on'); render(); break;
    case 'sync-confirm-no': state.syncConfirm = false; render(); break;
    case 'sync-confirm-yes': {
      const on = state.syncConfirm === 'on';
      await run(async () => {
        const migrated = await invoke('set_icloud_sync', { on });
        toast(on ? `💳 Sync turned on (migrated ${migrated} secret(s))` : `💳 Sync turned off`);
      });
      state.syncConfirm = false; await refresh('settings');
      break;
    }
    case 'toggle-reauth':
      {
        const on = !state.settings.reauth_on_read;
        await run(() => invoke('set_reauth_on_read', { on }));
        toast(on ? '💳 Touch ID required to read secrets' : '💳 Touch ID requirement removed');
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
    case 'toggle-inherited-revoke': state.revokeInheritedRules = btn.checked; render(); break;
    case 'always-toggle': state.alwaysOpen = !state.alwaysOpen; render(); break;

    case 'decide-deny': await decide(id, 'deny'); break;
    case 'decide-allow': await decide(id, 'allow_once'); break;
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
    // Touch ID cancelled or failed: keep the request pending, tell the user.
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
    if (state.confirm) { state.confirm = null; render(); }
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
  'f-name': 'name', 'f-value': 'value',
  'f-cname': 'name', 'f-host': 'host', 'f-port': 'port',
  'f-db': 'dbname', 'f-user': 'user', 'f-url': 'url', 'c-template': 'template',
};
document.addEventListener('input', (e) => {
  const key = e.target && ERR_KEY_BY_INPUT[e.target.id];
  if (key && state.sheetErrors[key]) {
    delete state.sheetErrors[key];
    render();
  }
});

/* --------------------------------- boot ---------------------------------- */
async function boot() {
  await refresh('all');
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
  // Live updates from the core.
  await listen('amfa://queue-changed', (ev) => { state.queue = ev.payload || []; render(); });
  await listen('amfa://sessions-changed', () => refresh('sessions'));
  await listen('amfa://agents-changed', () => refresh('agents'));
  await listen('amfa://rules-changed', () => refresh('connections'));
  await listen('amfa://activity-appended', () => refresh('activity'));
}
boot();
