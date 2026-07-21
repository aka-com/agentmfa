import { defineConfig } from 'vite';

// The sidecar is bundled for Node, not the browser: one file, no minifying
// (a readable stack trace in the broker's log is worth more than bytes),
// and Node built-ins left external.
export default defineConfig({
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
      output: { entryFileNames: 'main.js', format: 'esm' },
    },
  },
});
