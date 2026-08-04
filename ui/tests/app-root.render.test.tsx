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
    return button;
  });
  testingLibrary.fireEvent.click(vault);
  const item = await testingLibrary.waitFor(() => {
    const button = dialog.querySelector<HTMLButtonElement>(
      'button[data-act="onepassword-item"][data-id="item-stripe"]',
    );
    assert.ok(button);
    return button;
  });
  testingLibrary.fireEvent.click(item);
  const checkbox = await testingLibrary.waitFor(() => {
    const input = dialog.querySelector<HTMLInputElement>('.onepassword-field input[type="checkbox"]');
    assert.ok(input);
    return input;
  });
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
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('button[data-act="tab"][data-tab="connections"]')!,
  );
});

test('1Password credentials can recover and connections can be removed', { timeout: 8_000 }, async () => {
  testingLibrary.fireEvent.click(
    document.querySelector<HTMLButtonElement>('button[data-act="tab"][data-tab="secrets"]')!,
  );
  testingLibrary.fireEvent.click(
    await testingLibrary.waitFor(() => {
      const button = document.querySelector<HTMLButtonElement>('button[data-act="onepassword-open"]');
      assert.ok(button);
      return button;
    }),
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
  });
  testingLibrary.fireEvent.click(
    dialog.querySelector<HTMLButtonElement>('button[data-act="sheet-cancel"]')!,
  );

  const row = await testingLibrary.waitFor(() => {
    const candidate = [...document.querySelectorAll<HTMLElement>('.onepassword-integration-row')]
      .find((element) => element.querySelector('b')?.textContent === 'Recovery Account');
    assert.ok(candidate);
    return candidate;
  });
  testingLibrary.fireEvent.click(
    row.querySelector<HTMLButtonElement>('button[data-act="onepassword-update"]')!,
  );
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

  const updatedRow = await testingLibrary.waitFor(() => {
    const candidate = [...document.querySelectorAll<HTMLElement>('.onepassword-integration-row')]
      .find((element) => element.querySelector('b')?.textContent === 'Recovery Account');
    assert.ok(candidate);
    return candidate;
  });
  testingLibrary.fireEvent.click(
    updatedRow.querySelector<HTMLButtonElement>('button[data-act="onepassword-delete-ask"]')!,
  );
  const confirm = await testingLibrary.findByRole(document.body, 'dialog', {
    name: 'Remove Recovery Account?',
  });
  testingLibrary.fireEvent.click(
    confirm.querySelector<HTMLButtonElement>('button[data-act="onepassword-delete-confirm"]')!,
  );
  await testingLibrary.waitFor(() => {
    assert.equal(
      [...document.querySelectorAll<HTMLElement>('.onepassword-integration-row')]
        .some((element) => element.querySelector('b')?.textContent === 'Recovery Account'),
      false,
    );
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
  assert.match(document.body.textContent ?? '', /remote broker needs an update/i);

  await mock.invoke('switch_broker_local');
  await testingLibrary.waitFor(() => {
    const button = document.querySelector<HTMLButtonElement>('button[data-act="onepassword-open"]');
    assert.ok(button);
    assert.equal(button.disabled, false);
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
    assert.ok(trigger, 'the client blank renders on the Get started tab');
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
