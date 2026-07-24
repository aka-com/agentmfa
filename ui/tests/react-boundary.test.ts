import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';

// Every way first-party code could hand a raw HTML string to the DOM,
// bypassing the SafeMarkup sanitize-and-parse boundary.
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
  const srcFiles = (await readdir(srcDir))
    .filter((name) => name.endsWith('.ts') || name.endsWith('.tsx'))
    .map((name) => new URL(name, srcDir));
  const files = [new URL('../app.tsx', import.meta.url), ...srcFiles];

  for (const file of files) {
    const source = await readFile(file, 'utf8');
    for (const sink of RAW_HTML_SINKS) {
      assert.doesNotMatch(source, sink, `${file.pathname} contains raw HTML sink ${sink}`);
    }
  }

  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');
  assert.match(app, /DOMPurify\.sanitize\(/);
});

test('window components reconcile in place rather than remounting per revision', async () => {
  const app = await readFile(new URL('../app.tsx', import.meta.url), 'utf8');

  // key={revision} forces a full unmount/mount per store publication, which
  // silently reintroduces innerHTML-replacement semantics (focus loss, IME
  // breakage, full sanitize/parse per render). Reconciliation must stay in
  // place; forms are controlled components that write the store directly.
  assert.doesNotMatch(app, /key=\{revision\}/);
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
