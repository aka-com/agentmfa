// Client-side "last used" stamps behind the tray's Recent section. The
// broker's audit stream attributes brokered calls to connections rather than
// credentials, so uses that happen directly in this UI (copying a value or
// user name, issuing a 2FA code) are stamped here and merged with
// per-connection activity at render time. Storage degrades to in-memory when
// localStorage is missing or refusing (tests, private mode), matching the
// dismissal storage in samples.ts.
const STORE_KEY = 'recentSecretUse';
const STORE_LIMIT = 50;

let fallback: Record<string, string> = {};

/** Last direct-use time per secret id, newest wins, RFC 3339 values. */
export function localSecretUse(): Record<string, string> {
  let stored: Record<string, string> = {};
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (raw) stored = JSON.parse(raw) as Record<string, string>;
  } catch { /* fall through to the in-memory copy */ }
  return { ...fallback, ...stored };
}

/** Stamp a secret as used now (copy, reveal, or code issue). */
export function noteSecretUsed(id: string): void {
  const map = localSecretUse();
  map[id] = new Date().toISOString();
  // Cap the map so deleted credentials' stamps age out instead of pooling.
  fallback = Object.fromEntries(Object.entries(map)
    .sort((a, b) => Date.parse(b[1]) - Date.parse(a[1]))
    .slice(0, STORE_LIMIT));
  try { localStorage.setItem(STORE_KEY, JSON.stringify(fallback)); } catch { /* in-memory only */ }
}
