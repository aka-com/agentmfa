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
  assert.ok(testingLibrary.getAllByText(document.body, 'AgentMFA').length >= 1);
  assert.ok(testingLibrary.getByRole(document.body, 'button', { name: 'Settings' }));
});

test('the mounted Settings sheet exposes broker key rotation', async () => {
  testingLibrary.fireEvent.click(
    testingLibrary.getByRole(document.body, 'button', { name: 'Settings' }),
  );
  const openSettings = document.querySelector<HTMLButtonElement>(
    'button[data-act="open-settings"]',
  );
  assert.ok(openSettings);
  testingLibrary.fireEvent.click(openSettings);
  const dialog = await testingLibrary.findByRole(document.body, 'dialog', { name: 'Settings' });
  assert.ok(testingLibrary.getByRole(dialog, 'button', { name: 'Rotate key…' }));
});
