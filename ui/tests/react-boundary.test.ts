import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';

// Every way first-party code could hand a raw HTML string to the DOM,
// bypassing the SafeMarkup sanitize-and-parse boundary.
const RAW_HTML_SINKS = [
  /\.innerHTML\s*=/,
  /\.outerHTML\s*=/,
  /insertAdjacentHTML\s*\(/,
  /dangerouslySetInnerHTML/,
  /document\.write/,
  /createContextualFragment\s*\(/,
];

test('first-party UI rendering has no raw HTML assignment sink', async () => {
  const srcDir = new URL('../src/', import.meta.url);
  const srcFiles = (await readdir(srcDir))
    .filter((name) => name.endsWith('.ts') || name.endsWith('.tsx'))
    .map((name) => new URL(name, srcDir));
  const files = [new URL('../app.tsx', import.meta.url), ...srcFiles];

  for (const file of files) {
    const source = await readFile(file, 'utf8');
    for (const sink of RAW_HTML_SINKS) {
      assert.doesNotMatch(source, sink, `${file.pathname} contains raw HTML sink ${sink}`);
    }
  }

  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  assert.match(app, /DOMPurify\.sanitize\(/);
});

test('window components reconcile in place rather than remounting per revision', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  // key={revision} forces a full unmount/mount per store publication, which
  // silently reintroduces innerHTML-replacement semantics (focus loss, IME
  // breakage, full sanitize/parse per render). Reconciliation must stay in
  // place; forms are controlled components that write the store directly.
  assert.doesNotMatch(app, /key=\{revision\}/);
});

test('drag reordering leaves React-owned DOM order to reconciliation', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.doesNotMatch(app, /\.appendChild\(/);
  assert.doesNotMatch(app, /\.insertBefore\(/);
  assert.match(app, /dragConnOrder = next;\s+render\(\)/);
});

test('activity row block content has a block container', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.match(app, /<div className="act-txt">/);
  assert.doesNotMatch(app, /<span className="act-txt">/);
});

test('the activity log mounts a window of rows, not the whole log', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');
  const list = app.match(/function ActivityList\(\{ entries \}[\s\S]*?\n\}\n/)?.[0];

  assert.ok(list, 'windowed activity list is present');
  // Mapping the whole array would put every loaded row back in the DOM, which
  // is what the window exists to avoid — every live event and the per-minute
  // timestamp refresh reconciles this list.
  assert.match(list, /entries\.slice\(view\.start, view\.end\)\.map\([\s\S]{0,40}<ActivityRow/);
  assert.doesNotMatch(list, /\{entries\.map\(/);
  // Heights are cached by row identity, not position: a live prepend shifts
  // every index, and index-keyed heights would then describe the wrong rows.
  assert.match(list, /activityRowHeights\.get\(keys\[i\]\)/);
  // Spacers stand in for the unmounted rows, and must not be shrinkable — a
  // squashed spacer would shorten the scroll range and strand the oldest rows.
  assert.match(list, /className="act-pad"/);
  assert.match(styles, /\.act-pad\{ flex: 0 0 auto; \}/);
});

test('portaled listbox tabbing closes the menu relative to its trigger', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const portalTab = app.match(
    /e\.key === 'Tab' && state\.formMenuOpen([\s\S]*?)e\.key === 'Enter'/,
  )?.[1];

  assert.ok(portalTab, 'portaled listbox Tab handler is present');
  assert.match(portalTab, /e\.target\.closest\('\.cred-menu'\)/);
  assert.match(portalTab, /state\.formMenuOpen = null/);
  assert.match(portalTab, /focusables\[\(triggerIndex \+ offset/);
});

test('form state is not read back out of the DOM', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  // captureDrafts / reading .value off a looked-up input scraped uncontrolled
  // fields back into state; controlled components make that an anti-pattern.
  // Its return would mean a form regressed to uncontrolled. (focus()/select()
  // on a looked-up element is fine — only reading .value is forbidden.)
  assert.doesNotMatch(app, /function captureDrafts/);
  assert.doesNotMatch(app, /getElementById\([^)]*\)\s+as[^;]*;\s*\n[^\n]*\.value(?!\s*=)/);
  assert.doesNotMatch(app, /getElementById\([^)]*\)[^;\n]*\.value(?!\s*=)/);
});

test('credential listbox edits invalidate a failed draft-test override', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const selectPick = app.match(/case 'select-pick': \{([\s\S]*?)case 'credential-pick'/)?.[1];
  const credentialPick = app.match(/case 'credential-pick':([\s\S]*?)case 'save-conn'/)?.[1];

  assert.ok(selectPick, 'select-pick handler is present');
  assert.ok(credentialPick, 'credential-pick handler is present');
  assert.match(selectPick, /disarmDraftTestOverride\(\)/);
  assert.match(credentialPick, /disarmDraftTestOverride\(\)/);
});

test('creating a credential does not auto-trigger the endpoint confirmation gate', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const postSave = app.match(
    /const createdCredential = adding && newSecretName !== null;([\s\S]*?)function closeSheet/,
  )?.[1];

  assert.ok(postSave, 'post-save connection flow is present');
  assert.match(
    postSave,
    /if \(!createdCredential[\s\S]*?invoke\('issue_endpoint'/,
    'automatic endpoint issuance must remain behind the new-credential guard',
  );
});

test('the post-add banner stays a compact success message', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const readyCard = app.match(
    /function connectionReadyCardHTML\(\): string \{([\s\S]*?)function connectionsHTML/,
  )?.[1];

  assert.ok(readyCard, 'connection success banner is present');
  assert.match(readyCard, /\$\{esc\(ready\.name\)\} successfully added/);
  assert.doesNotMatch(readyCard, /Ask your agent|Copy task|copy-first-task/);
});

test('the MCP tool filter is pinned to the detail heading’s right edge', async () => {
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');
  const aside = styles.match(/\.cd-lbl-aside \{([\s\S]*?)\}/)?.[1];

  assert.ok(aside, 'MCP heading aside styles are present');
  assert.match(aside, /flex: 1 1 auto/);
  assert.match(aside, /justify-content: flex-end/);
  assert.match(styles, /\.cd-lbl-aside \.cat-meta-tools \{[^}]*margin-left: auto/);
});

test('connection detail headings have no leading connection icon', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const detail = app.match(
    /function connDetailHTML\([\s\S]*?\): string \{([\s\S]*?)function mcpStatusHTML/,
  )?.[1];

  assert.ok(detail, 'connection detail renderer is present');
  assert.doesNotMatch(detail, /ICONS\.chevronsLeftRightEllipsis/);
});

test('selected master rows have no left accent border', async () => {
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');
  const selected = styles.match(/\.flat-conn-wrap\.sel \{([^}]*)\}/)?.[1];

  assert.ok(selected, 'selected master-row styles are present');
  assert.doesNotMatch(selected, /border-left|inset\s+\d+px\s+0/);
});

test('Activity Log sits above the normal sidebar footer', async () => {
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');

  assert.match(
    styles,
    /@media \(min-width: 721px\) \{[\s\S]*?\.dw-nav \.nav-item\[data-tab="activity"\]\s*\{\s*margin-top: auto;\s*margin-bottom: 4px;/,
  );
});

test('the Activity Log shows live sessions independently of audit filters', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const activity = app.match(
    /function ActivityView\(\): ReactNode \{([\s\S]*?)async function receiveActivity/,
  )?.[1];

  assert.ok(activity, 'Activity view is present');
  assert.match(activity, /state\.sessions\.length/);
  assert.match(activity, /liveSessionsHTML\('activity-live-sessions'\)/);
  assert.match(activity, /\{liveSessions\}\s*<div className="act-filters">/);
});

test('the Inbox ticks its second-level countdowns while requests wait', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const secondTicker = app.match(
    /setInterval\(\(\) => \{\s*if \(state\.sheet\?\.kind === 'approval'([\s\S]*?)\}, 1000\);/,
  )?.[1];

  assert.ok(secondTicker, 'the one-second countdown interval is present');
  assert.match(secondTicker, /state\.tab === 'inbox'/);
  assert.match(secondTicker, /activeRequestCount\(state\.approvals, state\.elicitations\) > 0/);
});

test('the SSH endpoint field includes the configured ssh invocation', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const endpointStrip = app.match(
    /function endpointStripHTML\([\s\S]*?\): string \{([\s\S]*?)function connToggleHTML/,
  )?.[1];

  assert.ok(endpointStrip, 'endpoint strip renderer is present');
  assert.match(endpointStrip, /c\.type === 'ssh'\s*\?\s*sshDirectCommand\(endpointAddress, c\)/);
  assert.doesNotMatch(endpointStrip, /sshAuthSockCommand/);
});

test('direct connection guides tell the user to hand the address to their agent', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.match(app, /Tell your agent to connect directly to this database\./);
  assert.match(app, /Tell your agent to connect directly to this server\./);
  assert.doesNotMatch(app, /Connect directly to this (?:database|remote server) via AgentMFA\./);
});

test('the first-use task does not restate automatic agent access', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.doesNotMatch(app, /Tools are enabled for all agents when you add them\./);
});

test('Custom WebSocket uses the Configure catalog action', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.match(app, /\['mcp', 'http', 'websocket'\]\.includes\(entry\.id\)/);
});

test('the settings menu shows the build version above its first item', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  // Plain div, ahead of the first action: a clickable row here would read as
  // an action and steal a tab stop from the two that are.
  assert.match(
    app,
    /<div className="settings-menu">\s*<div className="menu-version">Version \{APP_VERSION\}<\/div>\s*<button className="menu-item"/,
  );
  assert.doesNotMatch(app, /<button[^>]*menu-version/);

  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');
  const version = styles.match(/\.menu-version\{([^}]*)\}/)?.[1];

  assert.ok(version, 'settings menu version styles are present');
  assert.match(version, /color: var\(--muted\)/);
  assert.doesNotMatch(styles, /\.menu-version:hover/);
});

test('the settings menu overhangs the sidebar rather than matching its width', async () => {
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');
  // The narrow-rail override earlier in the file also selects .settings-menu;
  // this is the base rule, the one that sizes the popover in the wide layout.
  const menu = styles.match(/\.settings-menu\{\s*position: absolute;([^}]*)\}/)?.[1];

  assert.ok(menu, 'settings menu styles are present');
  assert.match(menu, /right: -70px/);
});

test('connection-string credentials are masked with asterisks', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const masker = app.match(/function maskedEndpoint\(address: string\): string \{([\s\S]*?)\}/)?.[1];

  assert.ok(masker, 'connection-string masker is present');
  assert.match(masker, /\$1\*{6}/);
  assert.doesNotMatch(masker, /•/);
});
