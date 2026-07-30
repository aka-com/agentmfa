import { defineConfig } from 'vite';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function workspaceVersion(): string {
  const cargo = readFileSync(resolve(import.meta.dirname, '..', 'Cargo.toml'), 'utf8');
  const section = cargo.match(/\[workspace\.package\]([^[]*)/);
  const version = section?.[1].match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  if (!version) throw new Error('Cargo workspace version not found');
  return version;
}

// The sidecar is bundled for Node, not the browser: one file, no minifying
// (a readable stack trace in the broker's log is worth more than bytes),
// and Node built-ins left external.
export default defineConfig({
  define: {
    __AGENTMFA_SIDECAR_VERSION__: JSON.stringify(workspaceVersion()),
  },
  // Resolve entry and output against this directory rather than the cwd,
  // so the build works from the repo root.
  root: import.meta.dirname,
  // Vite externalizes dependencies for SSR by default, which would ship a
  // bundle whose imports resolve only next to a node_modules tree. The
  // .app has no node_modules, so everything but Node's own built-ins gets
  // inlined into the single file we bundle as a resource.
  ssr: { noExternal: true },
  build: {
    ssr: 'src/main.ts',
    outDir: '../dist/sidecar',
    emptyOutDir: true,
    target: 'node22',
    minify: false,
    rollupOptions: {
      output: {
        entryFileNames: 'main.mjs',
        format: 'esm',
        // One file, enforced. The Rust side resolves exactly
        // `dist/sidecar/main.js` and Tauri ships exactly that path as a
        // resource, so a build that split out a lazy chunk would package an
        // app whose sidecar could not load it.
        inlineDynamicImports: true,
      },
    },
  },
});
