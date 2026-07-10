import AppWindow from '/vendor/lucide/esm/icons/app-window.mjs';
import Bell from '/vendor/lucide/esm/icons/bell.mjs';
import Check from '/vendor/lucide/esm/icons/check.mjs';
import ChevronDown from '/vendor/lucide/esm/icons/chevron-down.mjs';
import CircleCheck from '/vendor/lucide/esm/icons/circle-check.mjs';
import CircleSlash from '/vendor/lucide/esm/icons/circle-slash.mjs';
import CircleX from '/vendor/lucide/esm/icons/circle-x.mjs';
import ClipboardCopy from '/vendor/lucide/esm/icons/clipboard-copy.mjs';
import ClockAlert from '/vendor/lucide/esm/icons/clock-alert.mjs';
import Copy from '/vendor/lucide/esm/icons/copy.mjs';
import Eye from '/vendor/lucide/esm/icons/eye.mjs';
import EyeOff from '/vendor/lucide/esm/icons/eye-off.mjs';
import FileKey from '/vendor/lucide/esm/icons/file-key.mjs';
import Gauge from '/vendor/lucide/esm/icons/gauge.mjs';
import Globe from '/vendor/lucide/esm/icons/globe.mjs';
import KeyRound from '/vendor/lucide/esm/icons/key-round.mjs';
import List from '/vendor/lucide/esm/icons/list.mjs';
import LogIn from '/vendor/lucide/esm/icons/log-in.mjs';
import LogOut from '/vendor/lucide/esm/icons/log-out.mjs';
import Pencil from '/vendor/lucide/esm/icons/pencil.mjs';
import Plug from '/vendor/lucide/esm/icons/plug.mjs';
import RotateCcwKey from '/vendor/lucide/esm/icons/rotate-ccw-key.mjs';
import Settings from '/vendor/lucide/esm/icons/settings.mjs';
import ShieldAlert from '/vendor/lucide/esm/icons/shield-alert.mjs';
import ShieldMinus from '/vendor/lucide/esm/icons/shield-minus.mjs';
import ShieldPlus from '/vendor/lucide/esm/icons/shield-plus.mjs';
import ShieldX from '/vendor/lucide/esm/icons/shield-x.mjs';
import Timer from '/vendor/lucide/esm/icons/timer.mjs';
import TimerOff from '/vendor/lucide/esm/icons/timer-off.mjs';
import Trash from '/vendor/lucide/esm/icons/trash.mjs';
import Unplug from '/vendor/lucide/esm/icons/unplug.mjs';
import UserRoundCheck from '/vendor/lucide/esm/icons/user-round-check.mjs';
import UserRoundPlus from '/vendor/lucide/esm/icons/user-round-plus.mjs';
import UserRoundX from '/vendor/lucide/esm/icons/user-round-x.mjs';
import Zap from '/vendor/lucide/esm/icons/zap.mjs';

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
  chevronDown: iconHTML(ChevronDown, 13),
  pencil: iconHTML(Pencil, 13),
  trash: iconHTML(Trash, 13),
  gear: iconHTML(Settings, 15),
  menubar: iconHTML(RotateCcwKey, 14),
  bell: iconHTML(Bell, 15),
  circleCheck: iconHTML(CircleCheck, 15),
  circleSlash: iconHTML(CircleSlash, 15),
  circleX: iconHTML(CircleX, 15),
  clipboardCopy: iconHTML(ClipboardCopy, 15),
  clockAlert: iconHTML(ClockAlert, 15),
  fileKey: iconHTML(FileKey, 15),
  gauge: iconHTML(Gauge, 15),
  globe: iconHTML(Globe, 15),
  keyRound: iconHTML(KeyRound, 15),
  list: iconHTML(List, 15),
  logIn: iconHTML(LogIn, 15),
  logOut: iconHTML(LogOut, 15),
  plug: iconHTML(Plug, 15),
  shieldAlert: iconHTML(ShieldAlert, 15),
  shieldMinus: iconHTML(ShieldMinus, 15),
  shieldPlus: iconHTML(ShieldPlus, 15),
  shieldX: iconHTML(ShieldX, 15),
  timer: iconHTML(Timer, 15),
  timerOff: iconHTML(TimerOff, 15),
  unplug: iconHTML(Unplug, 15),
  userRoundCheck: iconHTML(UserRoundCheck, 15),
  userRoundPlus: iconHTML(UserRoundPlus, 15),
  userRoundX: iconHTML(UserRoundX, 15),
  zap: iconHTML(Zap, 15),
};
