import AppWindow from '/vendor/lucide/esm/icons/app-window.mjs';
import Check from '/vendor/lucide/esm/icons/check.mjs';
import Copy from '/vendor/lucide/esm/icons/copy.mjs';
import Eye from '/vendor/lucide/esm/icons/eye.mjs';
import EyeOff from '/vendor/lucide/esm/icons/eye-off.mjs';
import Pencil from '/vendor/lucide/esm/icons/pencil.mjs';
import RotateCcwKey from '/vendor/lucide/esm/icons/rotate-ccw-key.mjs';
import Settings from '/vendor/lucide/esm/icons/settings.mjs';
import Trash from '/vendor/lucide/esm/icons/trash.mjs';

const SVG_ATTRS = {
  xmlns: 'http://www.w3.org/2000/svg',
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  'stroke-linecap': 'round',
  'stroke-linejoin': 'round',
  'aria-hidden': 'true',
  focusable: 'false',
};

function escAttr(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function attrsHTML(attrs) {
  return Object.entries(attrs)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([name, value]) => ` ${name}="${escAttr(value)}"`)
    .join('');
}

function nodeHTML([tag, attrs, children]) {
  const body = children ? children.map(nodeHTML).join('') : '';
  return body
    ? `<${tag}${attrsHTML(attrs)}>${body}</${tag}>`
    : `<${tag}${attrsHTML(attrs)}/>`;
}

function iconHTML(iconNode, size, attrs = {}) {
  return `<svg${attrsHTML({
    ...SVG_ATTRS,
    width: size,
    height: size,
    'stroke-width': 2,
    ...attrs,
  })}>${iconNode.map(nodeHTML).join('')}</svg>`;
}

export const LUCIDE_ICONS = {
  window: iconHTML(AppWindow, 15),
  eye: iconHTML(Eye, 14),
  eyeOff: iconHTML(EyeOff, 14),
  copy: iconHTML(Copy, 14),
  check: iconHTML(Check, 13),
  pencil: iconHTML(Pencil, 13),
  trash: iconHTML(Trash, 13),
  gear: iconHTML(Settings, 15),
  menubar: iconHTML(RotateCcwKey, 14),
};
