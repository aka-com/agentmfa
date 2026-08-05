import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { createServer } from 'vite';
import type { ViteDevServer } from 'vite';

const dom = new JSDOM(
  '<!doctype html><html><body><div id="root"></div><div id="overlays"></div></body></html>',
  { url: 'http://localhost/' },
);

class TestResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperties(globalThis, {
  window: { configurable: true, value: dom.window },
  document: { configurable: true, value: dom.window.document },
  location: { configurable: true, value: dom.window.location },
  localStorage: { configurable: true, value: dom.window.localStorage },
  navigator: { configurable: true, value: dom.window.navigator },
  Node: { configurable: true, value: dom.window.Node },
  Element: { configurable: true, value: dom.window.Element },
  HTMLElement: { configurable: true, value: dom.window.HTMLElement },
  HTMLButtonElement: { configurable: true, value: dom.window.HTMLButtonElement },
  HTMLInputElement: { configurable: true, value: dom.window.HTMLInputElement },
  HTMLTextAreaElement: { configurable: true, value: dom.window.HTMLTextAreaElement },
  Event: { configurable: true, value: dom.window.Event },
  MouseEvent: { configurable: true, value: dom.window.MouseEvent },
  MutationObserver: { configurable: true, value: dom.window.MutationObserver },
  ResizeObserver: { configurable: true, value: TestResizeObserver },
  getComputedStyle: {
    configurable: true,
    value: dom.window.getComputedStyle.bind(dom.window),
  },
});
const nativeSetInterval = globalThis.setInterval;
const nativeSetTimeout = globalThis.setTimeout;
Object.defineProperty(globalThis, 'setInterval', {
  configurable: true,
  value: (...args: Parameters<typeof setInterval>) => {
    const timer = nativeSetInterval(...args);
    timer.unref();
    return timer;
  },
});
Object.defineProperty(globalThis, 'setTimeout', {
  configurable: true,
  value: (...args: Parameters<typeof setTimeout>) => {
    const timer = nativeSetTimeout(...args);
    timer.unref();
    return timer;
  },
});
Object.defineProperty(dom.window, 'matchMedia', {
  configurable: true,
  value: () => ({
    matches: false,
    addEventListener() {},
    removeEventListener() {},
  }),
});
Object.defineProperty(dom.window, 'scrollTo', {
  configurable: true,
  value: () => {},
});
dom.window.__TAURI__ = {
  core: {
    async invoke(command, args) {
      const mock = await import('../src/mock-bridge');
      return (mock.invoke as (
        command: never,
        args?: never,
      ) => Promise<unknown>)(command as never, args as never);
    },
  },
  event: {
    async listen(event, callback) {
      const mock = await import('../src/mock-bridge');
      return (mock.listen as (
        event: never,
        callback: never,
      ) => Promise<() => void>)(event as never, callback as never);
    },
  },
};

type TestingLibrary = typeof import('@testing-library/react');
let testingLibrary: TestingLibrary;
let vite: ViteDevServer;

test.before(async () => {
  testingLibrary = await import('@testing-library/react');
  vite = await createServer({
    appType: 'custom',
    server: { middlewareMode: true },
  });
  await vite.ssrLoadModule('/app.tsx');
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelector('.surface'));
    assert.equal(document.querySelector('.app-loading'), null);
  });
});

test.after(async () => {
  await vite.close();
});

test('the application root boots against the mock bridge', () => {
  assert.ok(testingLibrary.getAllByText(document.body, 'Multitool').length >= 1);
  assert.ok(testingLibrary.getByRole(document.body, 'button', { name: 'Settings' }));
  const tabs = [...document.querySelectorAll<HTMLButtonElement>('.dw-nav [data-act="tab"]')];
  assert.deepEqual(
    tabs.slice(0, 3).map((tab) => tab.textContent?.trim()),
    ['Credentials', 'Tools', 'Connect agents'],
  );
  assert.equal(tabs[0]?.dataset.tab, 'secrets');
  assert.equal(tabs[0]?.classList.contains('on'), true);
  assert.ok(document.body.textContent?.includes('Credentials'));
});

/** Select a credential row by its title and wait for its inspector pane. */
async function openCredentialDetail(title: string): Promise<HTMLElement> {
  const row = [...document.querySelectorAll<HTMLElement>('.cred-row')]
    .find((candidate) => candidate.querySelector('b')?.textContent === title);
  assert.ok(row, `a list row for ${title}`);
  testingLibrary.fireEvent.click(row);
  return testingLibrary.waitFor(() => {
    const pane = document.querySelector<HTMLElement>('.cred-detail-pane');
    assert.ok(pane, 'the inspector pane is visible');
    assert.equal(pane.querySelector('.cdet-title')?.textContent, title);
    return pane;
  });
}

test('the credential library always groups passwords apart from secrets', async () => {
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('button[data-act="tab"][data-tab="secrets"]')!,
  );
  await testingLibrary.waitFor(() => {
    const cards = document.querySelectorAll('.cred-rows');
    assert.equal(cards.length, 2, 'both typed groups are always visible');
  });
  // Passwords lead the page unlabelled; only the secrets card is headed,
  // in the same register as the page title.
  const sectionHeads = [...document.querySelectorAll<HTMLElement>('.creds-sec-h')];
  assert.deepEqual(sectionHeads.map((head) => head.textContent), ['Secrets']);
  assert.equal(document.querySelector('.secrets-group-h'), null);
  assert.equal(document.querySelector('.credential-group-add'), null,
    'the per-group add links are gone from the desktop listing');

  // The category tiles scope the list and count the whole inventory.
  const tiles = [...document.querySelectorAll<HTMLElement>('.cred-tile')];
  assert.deepEqual(
    tiles.map((tile) => tile.querySelector('.cred-tile-label')?.textContent),
    ['All', 'Passwords', 'Secrets', 'Codes'],
    'the 1Password tile waits for the integration',
  );
  assert.equal(tiles[0]?.getAttribute('aria-checked'), 'true');

  // Password rows read site over username; selecting the x.com entry shows
  // its inspector with the current 2FA code and countdown.
  const hosts = [...document.querySelectorAll<HTMLElement>('.site-host')]
    .map((host) => host.textContent);
  assert.deepEqual(hosts, ['google.com', 'x.com']);
  assert.ok(document.body.textContent?.includes('raykyri@gmail.com'));
  const googleDetail = await openCredentialDetail('google.com');
  assert.equal(googleDetail.querySelector('.totp-live'), null);
  const xRow = [...document.querySelectorAll<HTMLElement>('.site-host')]
    .find((host) => host.textContent === 'x.com')?.closest('button');
  const xDetail = await openCredentialDetail('x.com');
  // Codes are issued on request: selection shows only the Show code button.
  assert.equal(xDetail.querySelector('.totp-live'), null);
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(xDetail, 'button', { name: 'Show the current 2FA code for x.com' }),
  );
  const liveTotp = await testingLibrary.waitFor(() => {
    const button = xDetail.querySelector<HTMLButtonElement>('.totp-live:not(.totp-live-loading)');
    assert.ok(button);
    assert.match(button.textContent ?? '', /246 801\d+s/);
    return button;
  });
  assert.equal(liveTotp.getAttribute('aria-label'), 'Copy the current 2FA code for x.com');
  assert.ok(testingLibrary.getByRole(xDetail, 'button', { name: 'Edit password x.com' }));
  const deletePassword = testingLibrary.getByRole(xDetail, 'button', {
    name: 'Delete password x.com',
  });
  // Derived names stay internal — password rows never show them.
  assert.equal(document.body.textContent?.includes('PASSWORD_X_COM'), false);

  // The status bar reports one combined credential inventory.
  assert.match(
    document.querySelector('.sb-count')?.textContent ?? '',
    /9 credentials/,
  );

  // The live display is still a copy action when pressed.
  testingLibrary.fireEvent.click(liveTotp);
  const mock = await import('../src/mock-bridge');
  await testingLibrary.waitFor(async () => {
    const page = await mock.invoke('list_activity', { limit: 5 }) as {
      entries: Array<{ text: string }>;
    };
    assert.ok(page.entries.some((entry) => entry.text.includes('2FA code issued')));
  });

  // Generated PASSWORD_* identifiers are wiring details, including in
  // context menus and destructive/reveal confirmations.
  testingLibrary.fireEvent.contextMenu(xRow!, { clientX: 20, clientY: 20 });
  const menu = await testingLibrary.findByLabelText(document.body, 'Options for x.com');
  const reveal = testingLibrary.getByRole(menu, 'button', { name: 'Reveal password…' });
  testingLibrary.fireEvent.click(reveal);
  const revealDialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Reveal x.com?',
  });
  assert.equal(revealDialog.textContent?.includes('PASSWORD_X_COM'), false);
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(revealDialog, 'button', { name: 'Cancel' }),
  );

  testingLibrary.fireEvent.click(deletePassword);
  const deleteDialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Delete x.com?',
  });
  assert.equal(deleteDialog.textContent?.includes('PASSWORD_X_COM'), false);
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(deleteDialog, 'button', { name: 'Cancel' }),
  );
});

test('the typed add sheet saves passwords with a 2FA seed', { timeout: 8_000 }, async () => {
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>(
      '.dw-head-actions button[data-act="open-add-secret"]',
    )!,
  );
  const dialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Add credential',
  });
  await testingLibrary.waitFor(() => {
    assert.ok(dialog.querySelector('#f-site'), 'the add sheet preselects the password shape');
    assert.equal(dialog.querySelector('#f-name'), null);
    assert.equal(
      dialog.querySelector('button[data-act="secret-kind"][data-kind="password"]')
        ?.getAttribute('aria-checked'),
      'true',
    );
  });
  const passwordInput = dialog.querySelector<HTMLInputElement>('#f-value')!;
  const showPassword = testingLibrary.getByRole<HTMLInputElement>(dialog, 'checkbox', { name: 'Show password' });
  assert.equal(passwordInput.type, 'password');
  assert.equal(showPassword.checked, false);
  assert.equal(dialog.querySelector('#f-totp'), null, '2FA stays folded under Advanced');
  assert.equal(dialog.textContent?.includes('the code it offers for manual entry'), false);
  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#f-site')!, {
    target: { value: 'https://WWW.Example.com/login' },
  });
  assert.equal(dialog.querySelector('.field-hint')?.textContent, 'Stored as example.com');
  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#f-username')!, {
    target: { value: 'user@example.com' },
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="generate-password"]')!,
  );
  const generated = passwordInput.value;
  assert.match(generated, /^[^-]{5}(-[^-]{5}){3}$/, 'Generate fills a grouped password');
  assert.equal(showPassword.checked, true, 'generated passwords are shown');
  assert.equal(passwordInput.type, 'text');

  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="generate-password-menu"]')!,
  );
  const formatMenu = await testingLibrary.findByRole(document.body, 'listbox', {
    name: 'Password format',
  });
  assert.deepEqual(
    testingLibrary.getAllByRole(formatMenu, 'option').map((option) => option.textContent?.trim()),
    ['Strong Password', 'Without Special Characters', 'Easy to Type'],
  );
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(formatMenu, 'option', { name: 'Without Special Characters' }),
  );
  assert.match(passwordInput.value, /^[A-Za-z0-9]{20}$/);
  assert.equal(showPassword.checked, true);

  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(dialog, 'button', { name: 'Advanced' }),
  );
  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#f-totp')!, {
    target: { value: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' },
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="save-secret"]')!,
  );
  // React Testing Library's waitFor act()-wrapper live-locks while this
  // save's command promise is pending, so settle natively — the same
  // reasoning as the 1Password save's deliberate nativeSetTimeout below.
  await new Promise<void>((resolve, reject) => {
    const t0 = Date.now();
    const iv = nativeSetInterval(() => {
      if (!document.querySelector('#f-site')) { clearInterval(iv); resolve(); }
      else if (Date.now() - t0 > 5000) { clearInterval(iv); reject(new Error('sheet still open')); }
    }, 50);
    iv.unref();
  });
  const hosts = [...document.querySelectorAll<HTMLElement>('.site-host')]
    .map((host) => host.textContent);
  assert.ok(hosts.includes('example.com'), `site is canonicalized (got ${hosts.join(', ')})`);
  const newDetail = await openCredentialDetail('example.com');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(newDetail, 'button', {
      name: 'Show the current 2FA code for example.com',
    }),
  );
  assert.ok(newDetail.querySelector('.totp-live'), 'the saved 2FA seed shows a desktop live code');
  assert.match(document.querySelector('.sb-count')?.textContent ?? '', /10 credentials/);

  testingLibrary.fireEvent.click(
    newDetail.querySelector<HTMLButtonElement>('button[data-act="edit-secret"]')!,
  );
  const editDialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Edit password',
  });
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(editDialog, 'button', { name: 'Advanced' }),
  );
  const removeTotp = editDialog.querySelector<HTMLInputElement>('.totp-remove-check input');
  assert.ok(removeTotp, 'stored 2FA factors use the remove checkbox');
  assert.equal(removeTotp.checked, false);
  assert.equal(editDialog.querySelector('button[data-act="remove-totp"]'), null);
  testingLibrary.fireEvent.click(removeTotp);
  assert.equal(removeTotp.checked, true);
  testingLibrary.fireEvent.click(
    editDialog.querySelector<HTMLButtonElement>('button[data-act="sheet-cancel"]')!,
  );
});

test('credential value visibility is direct on add and confirmed on edit', async () => {
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>(
      '.dw-head-actions button[data-act="open-add-secret"]',
    )!,
  );
  const addDialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Add credential',
  });
  // The header entry point preselects the password shape; this test wants
  // the secret one.
  testingLibrary.fireEvent.click(
    addDialog.querySelector<HTMLButtonElement>(
      'button[data-act="secret-kind"][data-kind="secret"]',
    )!,
  );
  const addValue = addDialog.querySelector<HTMLInputElement>('#f-value')!;
  const addShow = testingLibrary.getByRole<HTMLInputElement>(addDialog, 'checkbox', { name: 'Show secret' });
  assert.equal(addValue.type, 'password');
  testingLibrary.fireEvent.click(addShow);
  assert.equal(addValue.type, 'text');
  testingLibrary.fireEvent.click(addShow);
  assert.equal(addValue.type, 'password');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(addDialog, 'button', { name: 'Cancel' }),
  );

  const xDetail = await openCredentialDetail('x.com');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(xDetail, 'button', { name: 'Edit password x.com' }),
  );
  let editDialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Edit password',
  });
  let editValue = editDialog.querySelector<HTMLInputElement>('#f-value')!;
  let editShow = testingLibrary.getByRole<HTMLInputElement>(editDialog, 'checkbox', { name: 'Show password' });
  assert.equal(editValue.value, '', 'the stored password is not placed in the form on open');
  assert.equal(editValue.placeholder, '••••••••••••');
  testingLibrary.fireEvent.click(editShow);
  const passwordConfirm = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Show password for x.com?',
  });
  assert.equal(editShow.checked, false, 'requesting confirmation does not pre-check the box');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(passwordConfirm, 'button', { name: 'Show password' }),
  );
  await testingLibrary.waitFor(() => {
    editDialog = testingLibrary.getByRole(document.body, 'dialog', { name: 'Edit password' });
    editValue = editDialog.querySelector<HTMLInputElement>('#f-value')!;
    editShow = testingLibrary.getByRole<HTMLInputElement>(editDialog, 'checkbox', { name: 'Show password' });
    assert.equal(editValue.value, 'demo-pw-x');
    assert.equal(editValue.type, 'text');
    assert.equal(editShow.checked, true);
  });
  testingLibrary.fireEvent.click(editShow);
  assert.equal(editValue.value, '', 'hiding scrubs the broker-released value from the draft');
  assert.equal(editValue.type, 'password');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(editDialog, 'button', { name: 'Cancel' }),
  );

  const secretDetail = await openCredentialDetail('GITHUB_API_KEY');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(secretDetail, 'button', { name: 'Edit secret GITHUB_API_KEY' }),
  );
  editDialog = await testingLibrary.findByRole(document.body, 'dialog', { name: 'Edit secret' });
  editValue = editDialog.querySelector<HTMLInputElement>('#f-value')!;
  editShow = testingLibrary.getByRole<HTMLInputElement>(editDialog, 'checkbox', { name: 'Show secret' });
  assert.equal(editValue.value, '');
  testingLibrary.fireEvent.click(editShow);
  const secretConfirm = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Show secret for GITHUB_API_KEY?',
  });
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(secretConfirm, 'button', { name: 'Show secret' }),
  );
  await testingLibrary.waitFor(() => {
    assert.equal(editValue.value, 'ghp_9aXf2Qe7LmNoP3demoToken41c');
    assert.equal(editValue.type, 'text');
  });
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(editDialog, 'button', { name: 'Cancel' }),
  );
});

test('the 1Password sheet links a field through all three steps', { timeout: 8_000 }, async () => {
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('button[data-act="tab"][data-tab="secrets"]')!,
  );
  const open = await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>('button[data-act="onepassword-open"]');
    assert.ok(button);
    return button;
  });
  testingLibrary.fireEvent.click(open);

  const dialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Connect 1Password',
  });
  assert.ok(dialog.querySelector('.onepassword-sheet-logo svg'));
  assert.equal(dialog.querySelectorAll('.onepassword-method-icon svg').length, 3);
  assert.equal(dialog.textContent?.includes('Link vault fields to this Mac'), false);
  assert.ok(dialog.textContent?.includes(
    'Use the name at the top of the 1Password sidebar, or account UUID.',
  ));
  assert.equal(dialog.textContent?.includes('1Password will ask you to authorize Multitool.'), false);
  assert.equal(dialog.querySelector('.onepassword-account-preview-nav')?.textContent, 'Profile');

  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#op-account')!, {
    target: { value: 'Work' },
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-connect"]')!,
  );
  const vault = await testingLibrary.waitFor(() => {
    const button = dialog.querySelector<HTMLButtonElement>(
      'button[data-act="onepassword-vault"][data-id="vault-work"]',
    );
    assert.ok(button);
    assert.equal(button.querySelector('.onepassword-vault-count')?.textContent, '(2)');
    assert.equal(button.querySelector('small'), null);
    return button;
  });
  testingLibrary.fireEvent.click(vault);
  const item = await testingLibrary.waitFor(() => {
    const button = dialog.querySelector<HTMLButtonElement>(
      'button[data-act="onepassword-item"][data-id="item-stripe"]',
    );
    assert.ok(button);
    const back = dialog.querySelector('.onepassword-browser-list')?.lastElementChild;
    assert.equal(back?.textContent?.trim(), 'Back');
    assert.ok(back?.querySelector('svg'));
    return button;
  });
  testingLibrary.fireEvent.click(item);
  assert.ok(dialog.querySelector(
    'button[data-act="onepassword-item"][data-id="item-stripe"]',
  ));
  assert.equal(dialog.querySelector('.onepassword-browser-list .onepassword-loading'), null);
  const checkbox = await testingLibrary.waitFor(() => {
    const input = dialog.querySelector<HTMLInputElement>('.onepassword-field input[type="checkbox"]');
    assert.ok(input);
    return input;
  });
  const unsupported = [...dialog.querySelectorAll<HTMLElement>('.onepassword-field')]
    .find((row) => row.querySelector('b')?.textContent === 'single sign-on');
  assert.ok(unsupported?.classList.contains('unsupported'));
  assert.equal(unsupported?.querySelector<HTMLInputElement>('input[type="checkbox"]')?.disabled, true);
  testingLibrary.fireEvent.click(checkbox);
  const alias = dialog.querySelector<HTMLInputElement>('.onepassword-alias input');
  assert.ok(alias?.value);
  assert.ok(dialog.textContent?.includes('Stored as'));

  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-review"]')!,
  );
  await testingLibrary.waitFor(() => {
    assert.ok(dialog.textContent?.includes('Retrieved on use'));
    assert.equal(dialog.textContent?.includes('Resolved only when an agent uses them'), false);
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-save"]')!,
  );
  // The save handler publishes both integration and secret events before its
  // own final refresh. Let that deliberately concurrent work settle before
  // asserting the closed sheet and newly linked row.
  await new Promise((resolve) => nativeSetTimeout(resolve, 100));
  assert.equal(document.querySelector('.onepassword-sheet'), null);
  assert.ok(document.body.textContent?.includes(alias.value));
  const linkedRow = [...document.querySelectorAll<HTMLElement>('.s-name')]
    .find((name) => name.textContent === alias.value)?.closest('button');
  assert.ok(linkedRow?.querySelector('.s-source-icon svg'));
  assert.equal(linkedRow?.querySelector('.s-source'), null);
  const credentialCount = document.querySelector<HTMLElement>('.secrets-statusbar .sb-count');
  assert.match(credentialCount?.textContent?.trim() ?? '', /\d+ credentials/);
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('button[data-act="tab"][data-tab="connections"]')!,
  );
});

/** Open the Secrets status bar's vault popover (idempotent) and return it. */
async function openVaultsPanel(): Promise<HTMLElement> {
  const toggle = await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>(
      'button[data-act="toggle-vaults-panel"]',
    );
    assert.ok(button, 'the status bar offers a vault toggle');
    return button;
  });
  if (toggle.getAttribute('aria-expanded') !== 'true') testingLibrary.fireEvent.click(toggle);
  return testingLibrary.waitFor(() => {
    const panel = document.querySelector<HTMLElement>('.vaults-panel');
    assert.ok(panel);
    return panel;
  });
}

const vaultRowByLabel = (label: string): HTMLElement | undefined =>
  [...document.querySelectorAll<HTMLElement>('.onepassword-integration-row')]
    .find((element) => element.querySelector('b')?.textContent === label);

test('1Password credentials can recover and connections can be removed', { timeout: 8_000 }, async () => {
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('button[data-act="tab"][data-tab="secrets"]')!,
  );
  // The earlier test's desktop-app connection moves the vault surface behind
  // the status bar's vault button; connecting another lives in its popover.
  const connectPanel = await openVaultsPanel();
  testingLibrary.fireEvent.click(
    connectPanel.querySelector<HTMLButtonElement>('button[data-act="onepassword-open"]')!,
  );
  let dialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Connect 1Password',
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-method="service_account"]')!,
  );
  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#op-label')!, {
    target: { value: 'Recovery Account' },
  });
  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#op-token')!, {
    target: { value: 'invalid-token' },
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-connect"]')!,
  );
  await testingLibrary.waitFor(() => {
    assert.match(dialog.querySelector('[role="alert"]')?.textContent ?? '', /rejected/i);
  });

  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#op-token')!, {
    target: { value: 'valid-token' },
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-connect"]')!,
  );
  await testingLibrary.waitFor(() => {
    assert.ok(dialog.querySelector('button[data-act="onepassword-vault"]'));
    const placeholder = dialog.querySelector('.onepassword-breadcrumb-placeholder');
    assert.equal(placeholder?.textContent, 'Select a vault…');
  });
  const allVaults = dialog.querySelector<HTMLButtonElement>(
    'button[data-act="onepassword-vault"][data-id="__all_vaults__"]',
  );
  assert.equal(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-vault"]'),
    allVaults,
  );
  assert.equal(allVaults?.querySelector('.onepassword-vault-count')?.textContent, '(4)');
  testingLibrary.fireEvent.click(allVaults!);
  const aggregatedItem = await testingLibrary.waitFor(() => {
    const item = dialog.querySelector<HTMLButtonElement>(
      'button[data-act="onepassword-item"][data-id="item-cloudflare"]',
    );
    assert.ok(item);
    return item;
  });
  assert.equal(aggregatedItem.dataset.vaultId, 'vault-shared');
  assert.equal(aggregatedItem.querySelector('small')?.textContent, 'Shared Services · API Credential');
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button.onepassword-list-back')!,
  );
  await testingLibrary.waitFor(() => {
    assert.ok(dialog.querySelector('button[data-act="onepassword-vault"][data-id="vault-empty"]'));
  });
  const emptyVault = dialog.querySelector<HTMLButtonElement>(
    'button[data-act="onepassword-vault"][data-id="vault-empty"]',
  );
  assert.equal(emptyVault?.querySelector('.onepassword-vault-count')?.textContent, '(0)');
  testingLibrary.fireEvent.click(emptyVault!);
  await testingLibrary.waitFor(() => {
    assert.equal(dialog.querySelector('.onepassword-list-empty')?.textContent, 'No items');
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button.onepassword-list-back')!,
  );
  await testingLibrary.waitFor(() => {
    assert.ok(dialog.querySelector('button[data-act="onepassword-vault"][data-id="vault-empty"]'));
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="sheet-cancel"]')!,
  );

  await openVaultsPanel();
  const row = await testingLibrary.waitFor(() => {
    const candidate = vaultRowByLabel('Recovery Account');
    assert.ok(candidate);
    assert.equal(candidate.querySelector('.onepassword-integration-icon'), null);
    // The linked count reads on its own line under the connection method.
    assert.match(candidate.textContent ?? '', /Service account/);
    assert.match(candidate.textContent ?? '', /0 linked credentials/);
    return candidate;
  });
  testingLibrary.fireEvent.click(
    row.querySelector<HTMLButtonElement>('button[data-act="toggle-vault-menu"]')!,
  );
  const update = await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>(
      '.vault-menu-wrap button[data-act="onepassword-update"]',
    );
    assert.ok(button);
    assert.equal(button.textContent, 'Edit connection method…');
    return button;
  });
  testingLibrary.fireEvent.click(update);
  dialog = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Update 1Password credential',
  });
  assert.equal(dialog.querySelector('.onepassword-steps'), null);
  testingLibrary.fireEvent.change(dialog.querySelector<HTMLInputElement>('#op-token')!, {
    target: { value: 'replacement-token' },
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="onepassword-connect"]')!,
  );
  await testingLibrary.waitFor(() => assert.ok(!document.querySelector('.onepassword-sheet')));

  await openVaultsPanel();
  const updatedRow = await testingLibrary.waitFor(() => {
    const candidate = vaultRowByLabel('Recovery Account');
    assert.ok(candidate);
    return candidate;
  });
  testingLibrary.fireEvent.click(
    updatedRow.querySelector<HTMLButtonElement>('button[data-act="toggle-vault-menu"]')!,
  );
  const remove = await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>(
      '.vault-menu-wrap button[data-act="onepassword-delete-ask"]',
    );
    assert.ok(button);
    return button;
  });
  testingLibrary.fireEvent.click(remove);
  const confirm = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Remove Recovery Account?',
  });
  assert.ok(confirm.textContent?.includes(
    'Multitool will remove the connected vault and credentials. No 1Password items will be changed.',
  ));
  testingLibrary.fireEvent.click(
    confirm.querySelector<HTMLButtonElement>('button[data-act="onepassword-delete-confirm"]')!,
  );
  // The surviving connection keeps the popover available; the removed one is
  // gone from it.
  await openVaultsPanel();
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelectorAll('.onepassword-integration-row').length >= 1);
    assert.equal(vaultRowByLabel('Recovery Account'), undefined);
  });
});

test('legacy remote brokers disable the 1Password surface', async () => {
  const mock = await import('../src/mock-bridge');
  await mock.invoke('connect_remote_broker', {
    url: 'https://legacy.example.test',
    token: 'akamgr_test',
  });
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('button[data-act="tab"][data-tab="secrets"]')!,
  );
  const connect = await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>('button[data-act="onepassword-open"]');
    assert.ok(button);
    assert.equal(button.disabled, true);
    return button;
  });
  assert.equal(connect.textContent?.trim(), 'Unavailable');
  assert.match(connect.title, /remote broker/i);

  await mock.invoke('switch_broker_local');
  // Back on the local broker, the earlier tests' surviving connection
  // reloads and the vault surface returns.
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelector('button[data-act="toggle-vaults-panel"]'));
  });
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('button[data-act="tab"][data-tab="connections"]')!,
  );
});

test('dismissed sample tools can be restored from settings', async () => {
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(document.body, 'button', { name: 'Hide sample tools' }),
  );
  assert.equal(
    testingLibrary.queryByRole(document.body, 'button', { name: 'Hide sample tools' }),
    null,
  );

  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(document.body, 'button', { name: 'Settings' }),
  );
  const openSettings = document.querySelector<HTMLButtonElement>(
    'button[data-act="open-settings"]',
  );
  assert.ok(openSettings);
  testingLibrary.fireEvent.click(openSettings);
  const dialog = await testingLibrary.findByRole(document.body, 'dialog', { name: 'Settings' });
  const showSamples = testingLibrary.getByRole(dialog, 'checkbox', { name: 'Show sample tools' });
  assert.equal(showSamples.getAttribute('aria-checked'), 'false');
  testingLibrary.fireEvent.click(showSamples);
  assert.equal(showSamples.getAttribute('aria-checked'), 'true');
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(dialog, 'button', { name: 'Done' }),
  );

  assert.ok(testingLibrary.getByRole(document.body, 'button', { name: 'Hide sample tools' }));
});

// Options are compared by their data-id, never by node identity: a failed
// assert.equal on two jsdom elements spends minutes inspecting the DOM graph
// to build its diff, which reads as a hung test rather than a failed one.
const activeOptionId = (): string | null | undefined =>
  document.activeElement?.getAttribute('data-id');

test('the hero-sentence menus open and move under the arrow keys', async () => {
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('button[data-act="tab"][data-tab="start"]')!,
  );
  const blank = await testingLibrary.waitFor(() => {
    const trigger = document.querySelector<HTMLButtonElement>('#start-blank-client');
    assert.ok(trigger, 'the client blank renders on the Connect agents tab');
    return trigger;
  });

  // ArrowDown on a closed blank opens its listbox on the current choice.
  blank.focus();
  testingLibrary.fireEvent.keyDown(blank, { key: 'ArrowDown' });
  const ids = await testingLibrary.waitFor(() => {
    const options = [...document.querySelectorAll<HTMLElement>('.start-menu [role="option"]')];
    assert.ok(options.length > 2, 'the client menu has options to walk');
    assert.equal(document.activeElement?.getAttribute('aria-selected'), 'true');
    return options.map((option) => option.dataset.id);
  });
  const last = ids[ids.length - 1];

  // Arrows step, Home/End jump, and neither runs off an end of the list.
  const press = (key: string): void => {
    testingLibrary.fireEvent.keyDown(document.activeElement as HTMLElement, { key });
  };
  press('Home');
  assert.equal(activeOptionId(), ids[0]);
  press('ArrowUp');
  assert.equal(activeOptionId(), ids[0]);
  press('ArrowDown');
  assert.equal(activeOptionId(), ids[1]);
  press('ArrowUp');
  assert.equal(activeOptionId(), ids[0]);
  press('End');
  assert.equal(activeOptionId(), last);
  press('ArrowDown');
  assert.equal(activeOptionId(), last);

  // Tab leaves the menu and Escape closes it — both hand the keyboard back to
  // the blank rather than dropping it on the document. ArrowUp reopens from
  // the far end, the way a native select does.
  press('Tab');
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.start-menu'), null);
    assert.equal(document.activeElement?.id, 'start-blank-client');
  });
  press('ArrowUp');
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelector('.start-menu'));
    assert.equal(activeOptionId(), last);
  });
  press('Escape');
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.start-menu'), null);
    assert.equal(document.activeElement?.id, 'start-blank-client');
  });

  // Activating an option — the options are real buttons, so Enter clicks
  // them — rewrites the sentence and leaves focus on the blank it changed.
  const toolBlank = document.querySelector<HTMLButtonElement>('#start-blank-tool')!;
  const before = toolBlank.textContent;
  toolBlank.focus();
  testingLibrary.fireEvent.keyDown(toolBlank, { key: 'ArrowDown' });
  await testingLibrary.waitFor(() => {
    assert.ok(document.querySelector('.start-menu'));
    assert.equal(document.activeElement?.getAttribute('aria-selected'), 'true');
  });
  press('ArrowDown');
  testingLibrary.fireEvent.click(document.activeElement as HTMLElement);
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.start-menu'), null);
    assert.equal(document.activeElement?.id, 'start-blank-tool');
    assert.notEqual(document.querySelector('#start-blank-tool')?.textContent, before);
  });
});

test('the activity agent filter holds one agent at a time', async () => {
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('button[data-act="tab"][data-tab="activity"]')!,
  );
  const trigger = await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>(
      'button[data-act="act-filter-agent-menu"]',
    );
    assert.ok(button, 'the activity filters offer an agent picker');
    return button;
  });
  // The default covers every agent, so the picker starts unpressed.
  assert.equal(trigger.textContent, 'Agent:All');
  assert.equal(trigger.classList.contains('on'), false);

  testingLibrary.fireEvent.click(trigger);
  const options = await testingLibrary.waitFor(() => {
    const found = [...document.querySelectorAll<HTMLElement>('.act-filter-menu [role="option"]')];
    assert.ok(found.length > 2, 'the menu lists the default plus the agents seen');
    return found;
  });
  assert.equal(options[0].textContent, 'All agents');
  assert.equal(options[0].getAttribute('aria-selected'), 'true');

  const agent = options[1].dataset.value!;
  testingLibrary.fireEvent.click(options[1]);
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.act-filter-menu'), null);
    assert.equal(trigger.textContent, `Agent:${agent}`);
    assert.ok(trigger.classList.contains('on'));
  });

  // Every mounted entry belongs to the chosen agent — one filter, not the
  // union the chip row allowed.
  const chips = [...document.querySelectorAll<HTMLElement>('.act-chip.untrusted-identity')];
  assert.ok(chips.length, 'the filtered list still has entries');
  for (const chip of chips) assert.equal(chip.textContent, `reported as “${agent}”`);

  testingLibrary.fireEvent.click(trigger);
  const back = await testingLibrary.findByRole(document.body, 'option', { name: 'All agents' });
  testingLibrary.fireEvent.click(back);
  await testingLibrary.waitFor(() => {
    assert.equal(document.querySelector('.act-filter-menu'), null);
    assert.equal(trigger.textContent, 'Agent:All');
    assert.equal(trigger.classList.contains('on'), false);
  });
});

test('key rotation requires an ordinary destructive confirmation', async () => {
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(document.body, 'button', { name: 'Settings' }),
  );
  const openSettings = document.querySelector<HTMLButtonElement>(
    'button[data-act="open-settings"]',
  );
  assert.ok(openSettings);
  testingLibrary.fireEvent.click(openSettings);
  const dialog = await testingLibrary.findByRole(document.body, 'dialog', { name: 'Settings' });
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(dialog, 'button', { name: 'Rotate key…' }),
  );
  const confirmation = await testingLibrary.findByRole(
    document.body,
    'dialog',
    { name: 'Rotate this computer’s agent key?' },
  );
  assert.match(confirmation.textContent ?? '', /direct endpoint stops working immediately/);
  assert.ok(testingLibrary.getByRole(confirmation, 'button', { name: 'Rotate key' }));
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(confirmation, 'button', { name: 'Cancel' }),
  );
});
