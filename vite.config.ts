import { defineConfig } from 'vite';

export default defineConfig({
  root: 'ui',
  publicDir: 'public',
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
