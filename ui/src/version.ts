// Build version of the app, for the hint line at the top of the settings menu.
//
// __APP_VERSION__ is substituted by vite.config.ts from tauri.conf.json. The
// fallback covers the paths that never go through Vite (node --test, tsx),
// where the define does not exist.
declare const __APP_VERSION__: string | undefined;

export const APP_VERSION =
  typeof __APP_VERSION__ === 'string' ? __APP_VERSION__ : 'dev';
