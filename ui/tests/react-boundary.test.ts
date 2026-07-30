import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';

// Every way first-party code could hand a raw HTML string to the DOM,
// bypassing React's escaping and reconciliation.
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
  const collectSourceFiles = async (directory: URL): Promise<URL[]> => {
    const entries = await readdir(directory, { withFileTypes: true });
    const nested = await Promise.all(entries.map((entry) => {
      const url = new URL(entry.name + (entry.isDirectory() ? '/' : ''), directory);
      if (entry.isDirectory()) return collectSourceFiles(url);
      return entry.name.endsWith('.ts') || entry.name.endsWith('.tsx') ? [url] : [];
    }));
    return nested.flat();
  };
  const srcFiles = await collectSourceFiles(srcDir);
  const files = [new URL('../app.tsx', import.meta.url), ...srcFiles];

  for (const file of files) {
    const source = await readFile(file, 'utf8');
    for (const sink of RAW_HTML_SINKS) {
      assert.doesNotMatch(source, sink, `${file.pathname} contains raw HTML sink ${sink}`);
    }
  }
});

test('React owns pointer actions and native global listeners have cleanup', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  for (const event of ['click', 'contextmenu', 'dragstart', 'dragover', 'drop', 'dragend']) {
    assert.doesNotMatch(
      app,
      new RegExp(`document\\.addEventListener\\('${event}'`),
      `${event} must stay on the React event boundary`,
    );
  }
  assert.match(app, /className="app-event-root"[\s\S]*?onClick=\{handleActionClick\}/);
  assert.match(app, /onContextMenu=\{handleConnectionContextMenu\}/);
  assert.match(app, /onDragStart=\{handleConnectionDragStart\}/);
  assert.match(app, /function useExternalAppEvents\(\): void \{/);
  assert.match(app, /document\.removeEventListener\('keydown', handleAppKeyDown\)/);
  assert.match(app, /document\.removeEventListener\('scroll', handleDocumentScroll, true\)/);
});

test('feature views and state are kept outside the application shell', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const appState = await readFile(new URL('../src/app-state.ts', import.meta.url), 'utf8');
  const endpointView = await readFile(
    new URL('../src/features/endpoint-view.tsx', import.meta.url),
    'utf8',
  );
  const startView = await readFile(
    new URL('../src/features/getting-started-view.tsx', import.meta.url),
    'utf8',
  );

  assert.match(app, /from '\/src\/app-state'/);
  assert.match(app, /from '\/src\/features\/endpoint-view'/);
  assert.match(app, /from '\/src\/features\/getting-started-view'/);
  assert.doesNotMatch(app, /interface AppState/);
  assert.doesNotMatch(app, /function EndpointStrip/);
  assert.doesNotMatch(app, /function StartWalkthrough/);
  assert.match(appState, /export interface AppState/);
  assert.match(endpointView, /export function EndpointStrip/);
  assert.match(startView, /export function StartViewPage/);
  assert.doesNotMatch(endpointView, /from ['"].*app(?:\.tsx)?['"]/);
  assert.doesNotMatch(startView, /from ['"].*app(?:\.tsx)?['"]/);
});

test('broker-owned resources are canonical in the broker-scoped query cache', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const appState = await readFile(new URL('../src/app-state.ts', import.meta.url), 'utf8');
  const queryClient = await readFile(
    new URL('../src/query-client.ts', import.meta.url),
    'utf8',
  );

  const resources = [
    ['secrets', 'list_secrets'],
    ['connections', 'list_connections'],
    ['identity', 'get_identity'],
    ['sessions', 'list_sessions'],
    ['elicitations', 'list_elicitations'],
    ['approvals', 'list_approvals'],
    ['requests', 'list_requests'],
    ['settings', 'get_settings'],
  ];
  for (const [field, command] of resources) {
    assert.match(
      appState,
      new RegExp(
        `bindQueryBackedField\\(\\s*'${field}',[\\s\\S]*?getBrokerQueryData\\(state\\.broker, '${command}'\\)[\\s\\S]*?setBrokerQueryData\\(state\\.broker, '${command}', value\\)`,
      ),
      `${field} must read and write the ${command} broker query`,
    );
  }

  assert.match(queryClient, /brokerQueryKey\(broker, command, args\)/);
  assert.match(queryClient, /queryClient\.getQueryData/);
  assert.match(queryClient, /queryClient\.setQueryData/);
  assert.match(app, /useBrokerQueryRevision\(\)/);

  const clear = app.match(
    /function clearBrokerOwnedState\(\): void \{([\s\S]*?)\n\}/,
  )?.[1];
  assert.ok(clear, 'broker reset function is present');
  for (const [field] of resources) {
    assert.doesNotMatch(
      clear,
      new RegExp(`state\\.${field}\\s*=`),
      `${field} must be cleared by query namespace removal, not copied UI state`,
    );
  }
  assert.match(
    app,
    /removeBrokerQueries\(state\.broker\);\s+clearBrokerOwnedState\(\);\s+\}\s+state\.broker = profile/,
  );
});

test('window components reconcile in place rather than remounting per revision', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  // key={revision} forces a full unmount/mount per store publication, which
  // silently reintroduces innerHTML-replacement semantics (focus loss, IME
  // breakage, full sanitize/parse per render). Reconciliation must stay in
  // place; forms are controlled components that write the store directly.
  assert.doesNotMatch(app, /key=\{revision\}/);
});

test('ordinary publications stay on the React scheduler', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const render = app.match(/function render\(\): void \{[\s\S]*?\n\}\n\nfunction finishRender/)?.[0];

  assert.ok(render, 'render publication function is present');
  assert.match(render, /uiStore\.publish\(\)/);
  assert.match(render, /requestAnimationFrame\(/);
  assert.doesNotMatch(render, /flushSync/);
  assert.match(app, /flushSync\(\(\) => \{\s*reactRoot\.render/);
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
    /function ConnectionReadyCard\(\): ReactNode \{([\s\S]*?)function ConnectionsView/,
  )?.[1];

  assert.ok(readyCard, 'connection success banner is present');
  assert.match(readyCard, /\{ready\.name\} successfully added/);
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
    /function ConnectionDetail\([\s\S]*?\): ReactNode \{([\s\S]*?)function FlatConnectionRow/,
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
  assert.match(activity, /<LiveSessions extraClass="activity-live-sessions"/);
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
  const endpointView = await readFile(
    new URL('../src/features/endpoint-view.tsx', import.meta.url),
    'utf8',
  );
  const endpointStrip = endpointView.match(
    /function EndpointStrip\([\s\S]*?\): ReactNode \{([\s\S]*?)function ConnectionToggle/,
  )?.[1];

  assert.ok(endpointStrip, 'endpoint strip renderer is present');
  assert.match(
    endpointStrip,
    /c\.type === 'ssh'\s*\?\s*sshDirectCommand\(endpointAddress, c, Boolean\(endpoint\.require_auth\)\)/,
  );
  assert.doesNotMatch(endpointStrip, /sshAuthSockCommand/);
});

test('direct connection guides tell the user to hand the address to their agent', async () => {
  const startView = await readFile(
    new URL('../src/features/getting-started-view.tsx', import.meta.url),
    'utf8',
  );

  assert.match(startView, /Tell your agent to connect directly to this database\./);
  assert.match(startView, /Tell your agent to connect directly to this server\./);
  assert.doesNotMatch(startView, /Connect directly to this (?:database|remote server) via AgentMFA\./);
});

test('the first-use task does not restate automatic agent access', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.doesNotMatch(app, /Tools are enabled for all agents when you add them\./);
});

test('generic custom rows use the Configure catalog action', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.match(app, /\['mcp', 'http'\]\.includes\(entry\.id\)/);
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

test('typography and narrow form columns follow the user text scale', async () => {
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');

  assert.doesNotMatch(styles, /font-size:\s*[^;}]*\bpx\b/);
  assert.match(styles, /--content-max:\s*47\.5rem/);
  assert.match(styles, /\.dw-side\{[^}]*flex:\s*0 0 9\.75rem/);
  assert.match(styles, /\.f-2col\{[^}]*flex-wrap:\s*wrap/);
  assert.match(styles, /\.f-2col \.f-row\{[^}]*flex:\s*1 1 16ch/);
});

test('connection-string credentials are masked with asterisks', async () => {
  const endpointView = await readFile(
    new URL('../src/features/endpoint-view.tsx', import.meta.url),
    'utf8',
  );
  const masker = endpointView.match(
    /function maskedEndpoint\(address: string\): string \{([\s\S]*?)\}/,
  )?.[1];

  assert.ok(masker, 'connection-string masker is present');
  assert.match(masker, /\$1\*{6}/);
  assert.doesNotMatch(masker, /•/);
});

test('endpoint credentials use the native hygienic copy command', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const endpointCopy = app.match(
    /case 'copy-endpoint-dsn':([\s\S]*?)case 'open-settings'/,
  )?.[1];

  assert.ok(endpointCopy, 'endpoint copy handlers are present');
  assert.match(endpointCopy, /invoke\('copy_endpoint_text'/);
  assert.doesNotMatch(endpointCopy, /navigator\.clipboard\.writeText/);
  assert.doesNotMatch(app, /data-act="copy-endpoint-dsn"[^>]*data-text=/);
});

test('failed broker reads stay visible and never trigger empty-vault onboarding', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const appState = await readFile(new URL('../src/app-state.ts', import.meta.url), 'utf8');

  assert.match(appState, /loadStatus: Record<LoadKey, LoadStatus>/);
  assert.match(app, /<LoadFailureBand \/>/);
  assert.match(
    app,
    /state\.loadStatus\.connections\.status === 'ready'[\s\S]*?!state\.connections\.length/,
  );
});

test('dropdown approval and elicitation dialogs hold the native form lease', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const protectedSheets = app.match(
    /function isProtectedFormSheet[\s\S]*?\n\}/,
  )?.[0] ?? '';

  assert.match(protectedSheets, /sheet\?\.kind === 'approval'/);
  assert.match(protectedSheets, /sheet\?\.kind === 'elicitation'/);
  assert.match(app, /case 'elicit-open': \{\s*if \(!await holdDropdownFormOpen\(\)\)/);
  assert.match(app, /case 'approval-open': \{\s*if \(!await holdDropdownFormOpen\(\)\)/);
});

test('elicitation forms preserve optional fields and validate required ones', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  // Absence of the flag (an older broker) must stay required — only an
  // explicit `false` marks a field optional, so the form fails closed.
  assert.match(app, /field\.required !== false/);
  assert.match(app, /required \? <b aria-hidden="true">\*<\/b>/);
  assert.match(app, /if \(!elicitFieldRequired\(field\)\) continue;/);
  assert.match(app, /if \(!value && elicitFieldRequired\(field\)\)/);
  assert.match(app, /if \(value\) values\[field\.name\] = value/);
});

test('known-host lookup is reachable from the SSH form', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.match(app, /data-act="check-known-hosts"/);
  assert.match(app, /invoke\('check_known_hosts'/);
  assert.match(app, /data-act="pick-host-key"/);
});

test('approval sheets use structured credential and TOFU provenance context', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.match(app, /approval\.credential_names/);
  assert.match(app, /approval\.method/);
  assert.match(app, /approval\.path/);
  assert.match(app, /approval\.host_key_fingerprint/);
  assert.match(app, /Matches \$\{matchingKnownHost\.algorithm\} in/);
  assert.match(app, /fingerprint does not match/);
  assert.match(app, /hostKeyDecision \? 'Trust and pin'/);
});

test('request history and secret dependencies remain actionable', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.match(app, /data-act="request-history-toggle"/);
  assert.match(app, /data-act="request-open-connection"/);
  assert.match(app, /data-act="show-connection"/);
  assert.match(app, /data-act="delete-using-connection"/);
  assert.match(app, /void runConnectionTest\(connectionId\)/);
});

test('untrusted prompt identity text is bidi-isolated and self-reported', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');

  assert.match(app, /Agent reported as “\$\{agent\}”/);
  assert.match(app, /className="approval-summary untrusted-identity" dir="auto"/);
  assert.match(styles, /\.untrusted-identity\{ unicode-bidi: isolate; \}/);
});
