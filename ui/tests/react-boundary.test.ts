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
