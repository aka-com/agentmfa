import { defineConfig } from 'vite';

// The sidecar is bundled for Node, not the browser: one file, no minifying
// (a readable stack trace in the broker's log is worth more than bytes),
// and Node built-ins left external.
export default defineConfig({
  // Resolve entry and output against this directory rather than the cwd,
  // so the build works from the repo root.
  root: import.meta.dirname,
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
