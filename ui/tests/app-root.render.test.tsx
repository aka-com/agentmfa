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
