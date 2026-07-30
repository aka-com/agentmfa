import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';

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
let SafeMarkup: typeof import('../src/safe-markup')['SafeMarkup'];

// These imports must follow jsdom setup: DOMPurify binds to the current
// window when the SafeMarkup module is evaluated.
test.before(async () => {
  testingLibrary = await import('@testing-library/react');
  ({ SafeMarkup } = await import('../src/safe-markup'));
});

test.afterEach(() => {
  testingLibrary.cleanup();
  document.body.replaceChildren();
});

test('SafeMarkup removes executable markup from the rendered DOM', () => {
  const view = testingLibrary.render(<SafeMarkup markup={`
    <section id="safe" onclick="globalThis.compromised = true">
      <script>globalThis.compromised = true</script>
      <a href="javascript:globalThis.compromised = true">Unsafe link</a>
      <img src="x" onerror="globalThis.compromised = true">
      <span>Visible content</span>
    </section>
  `} />);

  const section = view.container.querySelector('#safe');
  assert.ok(section);
  assert.equal(section.getAttribute('onclick'), null);
  assert.equal(view.container.querySelector('script'), null);
  assert.equal(view.container.querySelector('a')?.getAttribute('href'), null);
  assert.equal(view.container.querySelector('img')?.getAttribute('onerror'), null);
  assert.equal(view.getByText('Visible content').textContent, 'Visible content');
});

test('SafeMarkup preserves data actions and lets delegated clicks bubble', () => {
  let action: string | null = null;
  const listener = (event: Event) => {
    action = (event.target as Element).closest<HTMLElement>('[data-act]')?.dataset.act ?? null;
  };
  document.addEventListener('click', listener);
  try {
    const view = testingLibrary.render(
      <SafeMarkup markup='<button data-act="retry-view-loads">Retry</button>' />,
    );
    testingLibrary.fireEvent.click(view.getByRole('button', { name: 'Retry' }));
    assert.equal(action, 'retry-view-loads');
  } finally {
    document.removeEventListener('click', listener);
  }
});

test('SafeMarkup reconciles stable rows instead of replacing their DOM nodes', () => {
  const view = testingLibrary.render(
    <SafeMarkup markup='<button data-id="tool-1" data-act="open">Old label</button>' />,
  );
  const before = view.getByRole('button');

  view.rerender(
    <SafeMarkup markup='<button data-id="tool-1" data-act="open">New label</button>' />,
  );

  const after = view.getByRole('button');
  assert.equal(after, before);
  assert.equal(after.textContent, 'New label');
});
