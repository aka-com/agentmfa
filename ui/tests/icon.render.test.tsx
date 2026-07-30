import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';
import { AppIcon } from '../src/icon';
import { LUCIDE_ICONS } from '../src/icons';

const dom = new JSDOM('<!doctype html><html><body></body></html>', {
  url: 'http://localhost/',
});
Object.defineProperties(globalThis, {
  window: { configurable: true, value: dom.window },
  document: { configurable: true, value: dom.window.document },
  navigator: { configurable: true, value: dom.window.navigator },
  Node: { configurable: true, value: dom.window.Node },
  Element: { configurable: true, value: dom.window.Element },
  HTMLElement: { configurable: true, value: dom.window.HTMLElement },
  Event: { configurable: true, value: dom.window.Event },
  MouseEvent: { configurable: true, value: dom.window.MouseEvent },
  MutationObserver: { configurable: true, value: dom.window.MutationObserver },
  getComputedStyle: {
    configurable: true,
    value: dom.window.getComputedStyle.bind(dom.window),
  },
});
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;

type TestingLibrary = typeof import('@testing-library/react');
let testingLibrary: TestingLibrary;

test.before(async () => {
  testingLibrary = await import('@testing-library/react');
});

test.afterEach(() => {
  testingLibrary.cleanup();
  document.body.replaceChildren();
});

test('icons render as React-owned SVG elements', () => {
  const view = testingLibrary.render(<AppIcon icon={LUCIDE_ICONS.circleCheck} />);
  const svg = view.container.querySelector('svg');

  assert.ok(svg);
  assert.equal(svg.getAttribute('aria-hidden'), 'true');
  assert.equal(svg.getAttribute('focusable'), 'false');
  assert.equal(svg.getAttribute('stroke-linecap'), 'round');
  assert.ok(svg.querySelector('path, circle, polyline'));
});

test('icons reconcile in place', () => {
  const view = testingLibrary.render(<AppIcon icon={LUCIDE_ICONS.circleCheck} />);
  const before = view.container.querySelector('svg');

  view.rerender(<AppIcon icon={LUCIDE_ICONS.circleX} />);

  assert.equal(view.container.querySelector('svg'), before);
});
