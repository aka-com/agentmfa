import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The version the bundle ships as, stamped into the frontend at build time.
// Read from tauri.conf.json — the same field the bundler names the .app and
// .dmg with — so what the UI reports and what was built can never disagree.
// Injected as a define rather than fetched at runtime: reading it back from
// Tauri would mean widening the app's capability list for a string that is
// already fixed when the frontend is compiled.
const appVersion: string = JSON.parse(
  readFileSync(new URL('./src-tauri/tauri.conf.json', import.meta.url), 'utf8'),
).version;

export default defineConfig({
  root: 'ui',
  publicDir: 'public',
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(appVersion),
  },
  build: {
    outDir: '../dist/ui',
    emptyOutDir: true,
  },
  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
  },
  clearScreen: false,
});
