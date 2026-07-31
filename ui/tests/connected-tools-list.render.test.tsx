import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>', {
  url: 'http://localhost/',
});

class TestResizeObserver {
  observe() {}
  disconnect() {}
}

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
  ResizeObserver: { configurable: true, value: TestResizeObserver },
});
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;

type TestingLibrary = typeof import('@testing-library/react');
let testingLibrary: TestingLibrary;
let ConnectedToolsList:
  typeof import('../src/features/connected-tools-list')['ConnectedToolsList'];

test.before(async () => {
  testingLibrary = await import('@testing-library/react');
  ({ ConnectedToolsList } = await import('../src/features/connected-tools-list'));
});

test.afterEach(() => {
  testingLibrary.cleanup();
  document.body.replaceChildren();
});

test('connected tools mount a bounded window and retain row activation', () => {
  const items = Array.from({ length: 100 }, (_, index) => ({ id: `tool-${index}` }));
  let activated = '';
  const view = testingLibrary.render(
    <div className="content">
      <ConnectedToolsList items={items} reorderable dragging={false}
        renderItem={(item) =>
          <div className="flat-conn-wrap" key={item.id}>
            <button onClick={() => { activated = item.id; }}>{item.id}</button>
          </div>} />
    </div>,
  );

  const mounted = view.container.querySelectorAll('.flat-conn-wrap');
  assert.ok(mounted.length > 0);
  assert.ok(mounted.length < items.length, 'offscreen tool rows stay unmounted');
  testingLibrary.fireEvent.click(view.getByRole('button', { name: 'tool-0' }));
  assert.equal(activated, 'tool-0');
  assert.equal(
    view.container.querySelector('[data-conn-list="on"]') instanceof HTMLElement,
    true,
  );
  assert.ok(view.container.querySelector('.tool-list-pad'));
});

test('an active drag mounts every ordered row until the gesture ends', () => {
  const items = Array.from({ length: 50 }, (_, index) => ({ id: `tool-${index}` }));
  const rows = (dragging: boolean) => (
    <div className="content">
      <ConnectedToolsList items={items} reorderable dragging={dragging}
        renderItem={(item) =>
          <div className="flat-conn-wrap" data-conn-row={item.id} key={item.id}>{item.id}</div>} />
    </div>
  );
  const view = testingLibrary.render(rows(false));
  assert.ok(view.container.querySelectorAll('.flat-conn-wrap').length < items.length);

  view.rerender(rows(true));
  assert.equal(view.container.querySelectorAll('.flat-conn-wrap').length, items.length);
  assert.equal(view.container.querySelector('.tool-list-pad'), null);
  assert.equal(view.container.querySelector('.cat-rows')?.classList.contains('drag-active'), true);

  view.rerender(rows(false));
  assert.ok(view.container.querySelectorAll('.flat-conn-wrap').length < items.length);
});

test('a keyboard-reordered row can stay mounted until focus is restored', () => {
  const items = Array.from({ length: 50 }, (_, index) => ({ id: `tool-${index}` }));
  const view = testingLibrary.render(
    <div className="content">
      <ConnectedToolsList items={items} reorderable dragging={false}
        keepMountedId="tool-40"
        renderItem={(item) =>
          <div className="flat-conn-wrap" data-conn-row={item.id} key={item.id}>{item.id}</div>} />
    </div>,
  );

  assert.ok(view.container.querySelector('[data-conn-row="tool-40"]'));
  assert.ok(view.container.querySelector('.tool-list-pad'));
});
