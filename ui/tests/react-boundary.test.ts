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
  assert.match(app, /onContextMenu=\{handleRowContextMenu\}/);
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
    new URL('../src/features/connect-agents-view.tsx', import.meta.url),
    'utf8',
  );

  assert.match(app, /from '\/src\/app-state'/);
  assert.match(app, /from '\/src\/features\/endpoint-view'/);
  assert.match(app, /from '\/src\/features\/connect-agents-view'/);
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

test('the connected Tools list delegates rows to a windowed feature component', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const feature = await readFile(
    new URL('../src/features/connected-tools-list.tsx', import.meta.url),
    'utf8',
  );

  assert.match(app, /<ConnectedToolsList items=\{matching\}/);
  assert.doesNotMatch(app, /matching\.map\(\(connection\)/);
  assert.match(feature, /virtualListWindow\(\{/);
  assert.match(feature, /const start = dragging \? 0/);
  assert.match(feature, /pinnedIndex >= 0 \? Math\.min\(view\.start, pinnedIndex\)/);
  assert.match(feature, /items\.slice\(start, end\)\.map\(renderItem\)/);
  assert.match(app, /keepMountedId=\{keyboardReorderConnId\}/);
  assert.match(app, /row\?\.scrollIntoView\(\{ block: 'nearest' \}\)/);
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

test('manual API edits use the saved-credential chooser without weakening OAuth edits', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const apiEditFields = app.match(
    /else if \(editing && t === 'api'\) \{([\s\S]*?)\} else if \(editing\)/,
  )?.[1];
  const credentialPick = app.match(/case 'credential-pick':([\s\S]*?)case 'save-conn'/)?.[1];

  assert.ok(apiEditFields, 'manual API edit fields are present');
  assert.match(apiEditFields, /<CredentialChooser type=\{t\} allowNew=\{false\}/);
  assert.match(apiEditFields, /credentialNames\.length <= 1/);
  assert.match(credentialPick || '', /rebindApiCredentialTemplate\(/);
  assert.match(app, /const renameOnlyOAuth = Boolean\(editPresentation\?\.renameOnlyOAuth\)/);
  assert.match(app, /readOnly=\{renameOnlyOAuth\}/);
  assert.match(app, /if \(renameOnlyOAuth\) \{/);
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

test('forms preserve credential-less edits without guessing from masked text', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const appState = await readFile(new URL('../src/app-state.ts', import.meta.url), 'utf8');
  const saveSecret = app.match(
    /async function saveSecret\(\): Promise<void> \{([\s\S]*?)\n\}/,
  )?.[0] ?? '';
  const saveConnection = app.match(
    /async function saveConn\(\): Promise<void> \{([\s\S]*?)\n\}/,
  )?.[0] ?? '';

  assert.match(app, /return initialSecretSource\(\{/);
  assert.match(appState, /secretValueModified\?: boolean/);
  assert.match(saveSecret, /Boolean\(state\.draft\.secretValueModified\)/);
  assert.match(saveSecret, /valueModified \? value : null/);
  assert.doesNotMatch(saveSecret, /includes\('•'\)/);
  assert.match(saveConnection, /existingConnection\?\.secret_names\.length/);
  assert.match(saveConnection, /d\.template !== existingConnection\?\.template/);
});

test('degraded connection health renders as an amber issue', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const types = await readFile(new URL('../src/types.ts', import.meta.url), 'utf8');

  assert.match(types, /'ok' \| 'warning' \| 'failed' \| 'needs_reconnect'/);
  assert.match(app, /if \(c\.last_status === 'warning'\)/);
  assert.match(app, /text: c\.last_detail \|\| 'The last connection check completed with a warning\.'/);
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

test('connection detail headings have no leading connection icon', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const detail = app.match(
    /function ConnectionDetail\([\s\S]*?\): ReactNode \{([\s\S]*?)function FlatConnectionRow/,
  )?.[1];

  assert.ok(detail, 'connection detail renderer is present');
  assert.doesNotMatch(detail, /ICONS\.chevronsLeftRightEllipsis/);
});

test('Credentials leaves agent-key management to Settings', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const secrets = app.match(
    /function SecretsView\(\): ReactNode \{([\s\S]*?)function ActivityRow/,
  )?.[1];
  const settings = app.match(
    /function SettingsSheet\(\): ReactNode \{([\s\S]*?)\/\* --------------------------------- helpers/,
  )?.[1];

  assert.ok(secrets, 'Credentials view is present');
  assert.doesNotMatch(secrets, /identity|agent key|rotate-key|SharedKeyCard/);
  assert.match(app, /case 'secrets': return \['secrets'\]/);
  assert.ok(settings, 'Settings sheet is present');
  assert.match(settings, /This computer’s agent key/);
  assert.match(settings, /data-act="rotate-key-ask"/);
});

test('selected master rows have no left accent border', async () => {
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');
  const selected = styles.match(/\.flat-conn-wrap\.sel \{([^}]*)\}/)?.[1];

  assert.ok(selected, 'selected master-row styles are present');
  assert.doesNotMatch(selected, /border-left|inset\s+\d+px\s+0/);
});

test('the tray detail drawer stays inside the content below its tabs', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');
  const pane = styles.match(/\.dropdown-content-container\{([^}]*)\}/)?.[1];

  assert.match(
    app,
    /<div className="dropdown-content-container">[\s\S]*?<div className="content dd-content"><TabContent \/><\/div>/,
  );
  assert.ok(pane, 'the tray content container is present');
  assert.match(pane, /contain: paint/);
  assert.match(pane, /border-top: 1px solid var\(--line\)/);
  assert.match(styles, /\.dropdown-content-container \.conn-detail-col \{ top: 0; bottom: 0; \}/);
  assert.match(
    styles,
    /\.dropdown-content-container \.catalog\.detail-open \.conn-detail-backdrop \{[\s\S]*?background: rgba\(15,17,30,\.19\)/,
  );
});

test('the connection menu escapes the clipping detail pane through a portal', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');

  assert.match(app, /function ConnectionActionMenu\(\): ReactNode \{[\s\S]*?createPortal\(/);
  assert.match(app, /<ConnectionActionMenu \/>/);
  const detail = app.match(
    /function ConnectionDetail[\s\S]*?function FlatConnectionRow/,
  )?.[0];
  assert.ok(detail, 'connection detail is present');
  assert.doesNotMatch(detail, /<div className="tile-menu"/);
  assert.match(styles, /\.conn-action-menu-wrap \{[\s\S]*?position: fixed;/);
  assert.match(
    styles,
    /\.conn-action-menu-wrap \.tile-menu \{[\s\S]*?max-height: calc\(100vh - 16px\)/,
  );
});

test('detail-pane endpoint menus and other scroll-contained menus portal out', async () => {
  const endpoint = await readFile(new URL('../src/features/endpoint-view.tsx', import.meta.url), 'utf8');
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const start = await readFile(
    new URL('../src/features/connect-agents-view.tsx', import.meta.url),
    'utf8',
  );
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');

  assert.match(endpoint, /createPortal\([\s\S]*?ep-copy-menu-wrap/);
  assert.match(endpoint, /createPortal\([\s\S]*?ep-opts-menu-wrap/);
  // Menus that used to live under overflow:auto surfaces now portal.
  assert.match(app, /createPortal\([\s\S]*?cat-connect-menu-wrap/);
  assert.match(app, /createPortal\([\s\S]*?act-filter-menu-wrap/);
  assert.match(app, /createPortal\([\s\S]*?sheet-conn-menu-wrap/);
  assert.match(start, /createPortal\([\s\S]*?start-menu-portal/);
  assert.match(app, /function positionEpCopyMenu/);
  assert.match(app, /function positionOpenMenus/);
  assert.match(styles, /\.anchored-menu-portal/);
});

test('the Activity Log sits above the normal sidebar footer', async () => {
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');

  assert.match(
    styles,
    /@media \(min-width: 721px\) \{[\s\S]*?\.dw-nav \.nav-item\[data-tab="activity"\]\s*\{\s*margin-top: auto; margin-bottom: 4px;/,
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

test('the waiting requests tick their second-level countdowns', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const secondTicker = app.match(
    /setInterval\(\(\) => \{\s*if \(state\.sheet\?\.kind === 'approval'([\s\S]*?)\}, 1000\);/,
  )?.[1];

  assert.ok(secondTicker, 'the one-second countdown interval is present');
  assert.match(secondTicker, /state\.tab === 'activity'/);
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
    new URL('../src/features/connect-agents-view.tsx', import.meta.url),
    'utf8',
  );

  assert.match(startView, /Tell your agent to connect directly to this database\./);
  assert.match(startView, /Tell your agent to connect directly to this server\./);
  assert.doesNotMatch(startView, /Connect directly to this (?:database|remote server) via Multitool\./);
});

test('a finished step 1 keeps its action but gives up the primary button', async () => {
  const startView = await readFile(
    new URL('../src/features/connect-agents-view.tsx', import.meta.url),
    'utf8',
  );
  const addBody = startView.match(/const addBody = <>([\s\S]*?)<\/>;/)?.[1];

  assert.ok(addBody, 'step 1 body is present');
  // Only the step the user still has to do gets the filled button, so the
  // page reads as one next action rather than three.
  const className = addBody.match(/<button className=\{([\s\S]*?)\}\s/)?.[1];
  assert.ok(className, 'the action computes its class');
  assert.match(className, /step1Done/);
  assert.match(className, /primary/);
  assert.doesNotMatch(addBody, /className="btn primary sm"/);
  // The lead switches with the step, so a finished one stops reading as an
  // instruction to do what it already did.
  assert.match(addBody, /startAddedLead\(option, progress\)/);
  // And the label names what a second one would be, not a bare "another".
  assert.match(addBody, /startAddAnotherLabel\(option, addVerb\)/);
  assert.doesNotMatch(addBody, /\$\{addVerb\} another/);
});

test('the first-use task does not restate automatic agent access', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.doesNotMatch(app, /Tools are enabled for all agents when you add them\./);
});

test('setup-oriented rows use the Configure catalog action', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.match(app, /\['mcp', 'http', 'postgres', 'ssh'\]\.includes\(entry\.id\)/);
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

test('secret copy controls keep stable pixel-aligned positions', async () => {
  const styles = await readFile(new URL('../styles.css', import.meta.url), 'utf8');
  const copyIcon = styles.match(/\.ghost-copy svg\{([^}]*)\}/)?.[1];

  assert.match(styles, /\.val-slot code\{ transform: translateY\(-2px\)/);
  assert.ok(copyIcon, 'copy icon styles are present');
  assert.match(copyIcon, /display: block/);
  assert.match(copyIcon, /flex: 0 0 12px/);
  assert.match(copyIcon, /transform: none/);
  assert.match(copyIcon, /transition: none/);
});

test('endpoint credentials use the native hygienic copy command', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const gettingStarted = await readFile(
    new URL('../src/features/connect-agents-view.tsx', import.meta.url),
    'utf8',
  );
  const endpointCopy = app.match(
    /case 'copy-endpoint-dsn':([\s\S]*?)case 'open-settings'/,
  )?.[1];

  assert.ok(endpointCopy, 'endpoint copy handlers are present');
  assert.match(endpointCopy, /invoke\('copy_endpoint_text'/);
  assert.doesNotMatch(endpointCopy, /navigator\.clipboard\.writeText/);
  assert.doesNotMatch(app, /data-act="copy-endpoint-dsn"[^>]*data-text=/);
  assert.match(gettingStarted, /'copy-first-task'/);
  assert.doesNotMatch(gettingStarted, /data-text=\{task\}/);
  assert.match(app, /case 'copy-first-task':[\s\S]*?format: 'first-task'/);
});

test('dropdown hide clears credential-shaped elicitation answers', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const cleanup = app.match(
    /listen\('aka:\/\/dropdown-hidden',[\s\S]*?\n  \}\);/,
  )?.[0];
  assert.ok(cleanup, 'dropdown cleanup listener is present');
  assert.match(cleanup, /state\.elicitValues = \{\}/);
});

test('popover disclosures do not claim an unimplemented ARIA menu model', async () => {
  const sources = await Promise.all([
    readFile(new URL('../app.tsx', import.meta.url), 'utf8'),
    readFile(new URL('../src/features/connect-agents-view.tsx', import.meta.url), 'utf8'),
  ]);
  const popovers = sources.join('\n');
  assert.doesNotMatch(popovers, /role="menu(?:item|itemradio)?"/);
  assert.doesNotMatch(popovers, /aria-haspopup="menu"/);
});

test('broker truth drives secret refreshes and request refusal counts', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const secretListener = app.match(
    /listen\('aka:\/\/secrets-changed',[\s\S]*?\n  \}\);/,
  )?.[0];
  assert.ok(secretListener);
  assert.match(secretListener, /load\('secrets', 'list_secrets'\)/);
  assert.match(secretListener, /load\('connections', 'list_connections'\)/);
  assert.match(app, /record\.status === 'unavailable'/);
  assert.doesNotMatch(app, /startsWith\('Refused \(nobody could confirm\):'\)/);
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
  assert.match(app, /revokedFingerprints\.includes\(approval\.host_key_fingerprint\)/);
  assert.match(app, /marks this exact key as revoked/);
  assert.match(app, /hasCertificateAuthority/);
  assert.match(app, /port: connection\.port \?\? 22/);
  assert.match(app, /hostKeyDecision \? 'Trust and pin'/);
});

test('request attention policy exposes escalation, onboarding, and autostart controls', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.match(app, /data-act="toggle-notification-sound"/);
  assert.match(app, /data-act="toggle-notification-time-sensitive"/);
  assert.match(app, /data-act="set-notification-escalation"/);
  assert.match(app, /data-act="request-notification-permission"/);
  assert.match(app, /data-act="toggle-autostart"/);
  assert.match(app, /invoke\('set_autostart'/);
  assert.match(app, /notificationModeBtn\('off', 'Window only'\)/);
  assert.match(app, /Window only still brings the waiting requests forward/);
  assert.match(app, /Your system settings remain in control/);
});

test('connection detail keeps only Ask before outside its Advanced disclosure', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  const endpointView = await readFile(
    new URL('../src/features/endpoint-view.tsx', import.meta.url),
    'utf8',
  );
  const relay = app.match(
    /function ResponseCredentialRelay\([\s\S]*?\n\}\n\n\/\*\*/,
  )?.[0];
  const confirmation = app.match(
    /function ConfirmationSection\([\s\S]*?\n\}\n\n\/\*\*/,
  )?.[0];
  const advanced = app.match(
    /function ConnectionAdvancedSection\([\s\S]*?\n\}\n\nfunction McpStatus/,
  )?.[0];
  const enable = app.match(
    /case 'response-credentials-on':([\s\S]*?)case 'response-credentials-off':/,
  )?.[1];
  const disable = app.match(
    /case 'response-credentials-off':([\s\S]*?)case 'endpoint-auth-on':/,
  )?.[1];

  assert.ok(relay, 'API detail view exposes the response-credential policy');
  assert.match(relay, /if \(c\.type !== 'api'\) return null/);
  assert.match(relay, /Boolean\(c\.agent_access\.expose_response_credentials\)/);
  assert.ok(confirmation, 'Ask before has its own primary detail section');
  assert.doesNotMatch(confirmation, /ResponseCredentialRelay|StatementRecording|EndpointAuthRow/);
  assert.ok(advanced, 'secondary connection options have an Advanced disclosure');
  assert.match(advanced, /ConnectionToolScope/);
  assert.match(advanced, /ResponseCredentialRelay/);
  assert.match(advanced, /StatementRecording/);
  assert.match(advanced, /EndpointAuthRow/);
  const endpointStrip = endpointView.match(
    /export function EndpointStrip\([\s\S]*?\n\}\n\n\/\*\*/,
  )?.[0];
  assert.ok(endpointStrip);
  assert.doesNotMatch(endpointStrip, /EndpointAuthRow/);
  assert.ok(enable, 'the opt-in action is wired');
  assert.match(enable, /holdDropdownFormOpen\(\)/);
  assert.match(
    enable,
    /invoke\('set_expose_response_credentials',[\s\S]*?expose: true/,
  );
  assert.ok(disable, 'the containment action is wired');
  assert.match(
    disable,
    /invoke\('set_expose_response_credentials',[\s\S]*?expose: false/,
  );
  assert.doesNotMatch(disable, /holdDropdownFormOpen\(\)/);
  assert.match(app, /Multitool has not connected to this tool yet\. The SSH host key will be pinned on first connection\./);
});

test('waiting requests and secret dependencies remain actionable', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  assert.match(app, /data-act="approval-open"/);
  assert.match(app, /data-act="elicit-open"/);
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
