import { BRAND_ICONS } from './brand-icons';
import { LUCIDE_ICONS } from './icons';

// Small shared helpers.

export function esc(s: unknown): string {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
export function escAttr(s: unknown): string {
  return esc(s).replace(/"/g, '&quot;');
}

// Activity timestamps. `relTime` renders relative ("just now", "5m", "3h")
// for anything under 24h and a short absolute date beyond that; `absTime` is
// the full, unambiguous value shown in the hover tooltip.
export function relTime(iso: string, now = Date.now()): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const secs = Math.max(0, Math.round((now - t) / 1000));
  if (secs < 45) return 'just now';
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  const d = new Date(t);
  const sameYear = d.getFullYear() === new Date(now).getFullYear();
  return d.toLocaleDateString(undefined, sameYear
    ? { month: 'short', day: 'numeric' }
    : { year: 'numeric', month: 'short', day: 'numeric' });
}

export function absTime(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  return new Date(t).toLocaleString(undefined, {
    weekday: 'short', year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

/**
 * A deadline in the near future, as a phrase. `relTime` deliberately reads
 * backwards ("5m" ago) and clamps anything future to "just now", which is
 * wrong for the two forward-looking things the app shows: how long a
 * confirmation prompt has left, and how long an approval window runs.
 */
export function timeLeft(iso: string, now = Date.now()): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const secs = Math.round((t - now) / 1000);
  if (secs <= 0) return 'any moment now';
  if (secs < 90) return `${secs}s`;
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m`;
  return `${Math.round(mins / 60)}h`;
}

/** A wall-clock time ("11:42 PM") — enough for a horizon within the day. */
export function clockTime(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  return new Date(t).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

export const TYPES = {
  api: { label: 'API', cls: 'b-api' },
  pg: { label: 'PG', cls: 'b-pg' },
  ws: { label: 'WS', cls: 'b-ws' },
  ssh: { label: 'SSH', cls: 'b-ssh' },
};

// Lucide line icons plus the inlined Simple Icons brand marks, under one
// lookup so a catalog entry just names its icon.
export const ICONS: Record<string, string> = { ...LUCIDE_ICONS, ...BRAND_ICONS };

let toastHost: HTMLElement | null = null;
export function toast(msg: string): void {
  toastHost = toastHost || document.getElementById('toasts');
  if (!toastHost) return;
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  toastHost.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => { el.classList.remove('show'); setTimeout(() => el.remove(), 300); }, 2600);
}
