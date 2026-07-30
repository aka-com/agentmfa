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
let Sheet: typeof import('../src/sheet')['Sheet'];

test.before(async () => {
  testingLibrary = await import('@testing-library/react');
  ({ Sheet } = await import('../src/sheet'));
});

test.afterEach(() => {
  testingLibrary.cleanup();
  document.body.replaceChildren();
});

test('Sheet isolates the application surface and restores its opener on close', async () => {
  const surface = document.createElement('main');
  surface.className = 'surface';
  const opener = document.createElement('button');
  opener.textContent = 'Open settings';
  surface.append(opener);
  document.body.append(surface);
  opener.focus();

  const view = testingLibrary.render(
    <Sheet titleId="settings-title" className="wide">
      <h3 id="settings-title">Settings</h3>
      <button>Done</button>
    </Sheet>,
  );

  const dialog = view.getByRole('dialog', { name: 'Settings' });
  assert.equal(dialog.getAttribute('aria-modal'), 'true');
  assert.equal(dialog.classList.contains('wide'), true);
  assert.equal(surface.inert, true);
  assert.equal(surface.getAttribute('aria-hidden'), 'true');
  assert.equal(document.activeElement, view.getByRole('button', { name: 'Done' }));

  view.unmount();
  await Promise.resolve();

  assert.equal(surface.inert, false);
  assert.equal(surface.getAttribute('aria-hidden'), null);
  assert.equal(document.activeElement, opener);
});

test('Sheet supports alert dialogs and custom backdrop actions', () => {
  const surface = document.createElement('main');
  surface.className = 'surface';
  document.body.append(surface);

  const view = testingLibrary.render(
    <Sheet titleId="approval-title" role="alertdialog" backdropAction="confirm-cancel">
      <h3 id="approval-title">Approve this request?</h3>
      <button>Deny</button>
    </Sheet>,
  );

  assert.equal(
    view.getByRole('alertdialog', { name: 'Approve this request?' }).getAttribute('aria-modal'),
    'true',
  );
  assert.equal(
    view.container.querySelector<HTMLElement>('.sheet-backdrop')?.dataset.act,
    'confirm-cancel',
  );
});

test('a stacked Sheet makes the underlying dialog inert until it closes', async () => {
  const surface = document.createElement('main');
  surface.className = 'surface';
  const opener = document.createElement('button');
  opener.textContent = 'Edit tool';
  surface.append(opener);
  document.body.append(surface);
  opener.focus();
  const layers = (confirming: boolean) => (
    <>
      <Sheet titleId="form-title">
        <h3 id="form-title">Edit tool</h3>
        <button>Cancel edit</button>
      </Sheet>
      {confirming && (
        <Sheet titleId="confirm-title" backdropClassName="over-sheet">
          <h3 id="confirm-title">Discard changes?</h3>
          <button>Keep editing</button>
        </Sheet>
      )}
    </>
  );
  const view = testingLibrary.render(layers(false));
  const form = view.getByRole('dialog', { name: 'Edit tool' });
  const formButton = view.getByRole('button', { name: 'Cancel edit' });

  view.rerender(layers(true));

  assert.equal(form.inert, true);
  assert.equal(form.getAttribute('aria-hidden'), 'true');
  assert.equal(document.activeElement, view.getByRole('button', { name: 'Keep editing' }));
  assert.equal(
    view.container.querySelector('.sheet-backdrop.over-sheet') instanceof HTMLElement,
    true,
  );

  view.rerender(layers(false));
  await Promise.resolve();

  assert.equal(form.inert, false);
  assert.equal(form.getAttribute('aria-hidden'), null);
  assert.equal(document.activeElement, formButton);
  assert.equal(surface.inert, true);

  view.unmount();
  await Promise.resolve();
  assert.equal(surface.inert, false);
  assert.equal(document.activeElement, opener);
});
