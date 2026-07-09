import { LUCIDE_ICONS } from '/vendor/lucide-icons.js';

// Small shared helpers.

export function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
export function escAttr(s) {
  return esc(s).replace(/"/g, '&quot;');
}

// Activity timestamps. `relTime` renders relative ("just now", "5m", "3h")
// for anything under 24h and a short absolute date beyond that; `absTime` is
// the full, unambiguous value shown in the hover tooltip.
export function relTime(iso, now = Date.now()) {
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

export function absTime(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  return new Date(t).toLocaleString(undefined, {
    weekday: 'short', year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

export const TYPES = {
  api: { label: 'API', cls: 'b-api' },
  pg: { label: 'PG', cls: 'b-pg' },
  ws: { label: 'WS', cls: 'b-ws' },
  ssh: { label: 'SSH', cls: 'b-ssh' },
};

export const ICONS = LUCIDE_ICONS;

let toastHost;
export function toast(msg) {
  toastHost = toastHost || document.getElementById('toasts');
  if (!toastHost) return;
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  toastHost.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => { el.classList.remove('show'); setTimeout(() => el.remove(), 300); }, 2600);
}
