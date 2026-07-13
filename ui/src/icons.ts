import {
  Bell,
  Bot,
  Check,
  ChevronDown,
  CircleCheck,
  CircleQuestionMark,
  CircleSlash,
  CircleX,
  ClipboardCopy,
  ClockAlert,
  Copy,
  Ellipsis,
  Eye,
  EyeOff,
  Expand,
  FileKey,
  FlaskConical,
  Gauge,
  Globe,
  KeyRound,
  List,
  Lock,
  LogIn,
  LogOut,
  Pencil,
  Plug,
  Plus,
  RotateCcwKey,
  Settings,
  ShieldAlert,
  ShieldMinus,
  ShieldPlus,
  ShieldX,
  Timer,
  TimerOff,
  Trash,
  Unplug,
  UserRoundCheck,
  UserRoundPlus,
  UserRoundX,
  X,
  Zap,
} from 'lucide';
import type { IconNode, SVGProps } from 'lucide';

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

function escAttr(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function attrsHTML(attrs: SVGProps): string {
  return Object.entries(attrs)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([name, value]) => ` ${name}="${escAttr(value)}"`)
    .join('');
}

function nodeHTML([tag, attrs]: IconNode[number]): string {
  return `<${tag}${attrsHTML(attrs)}/>`;
}

function iconHTML(iconNode: IconNode, size: number, attrs: SVGProps = {}): string {
  return `<svg${attrsHTML({
    ...SVG_ATTRS,
    width: size,
    height: size,
    'stroke-width': 2,
    ...attrs,
  })}>${iconNode.map(nodeHTML).join('')}</svg>`;
}

export const LUCIDE_ICONS: Record<string, string> = {
  bot: iconHTML(Bot, 15),
  expand: iconHTML(Expand, 15),
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
  circleQuestion: iconHTML(CircleQuestionMark, 15),
  circleCheck: iconHTML(CircleCheck, 15),
  circleSlash: iconHTML(CircleSlash, 15),
  circleX: iconHTML(CircleX, 15),
  clipboardCopy: iconHTML(ClipboardCopy, 15),
  clockAlert: iconHTML(ClockAlert, 15),
  ellipsis: iconHTML(Ellipsis, 15),
  fileKey: iconHTML(FileKey, 15),
  flaskConical: iconHTML(FlaskConical, 15),
  gauge: iconHTML(Gauge, 15),
  globe: iconHTML(Globe, 15),
  keyRound: iconHTML(KeyRound, 12),
  list: iconHTML(List, 15),
  lock: iconHTML(Lock, 15),
  logIn: iconHTML(LogIn, 15),
  logOut: iconHTML(LogOut, 15),
  plug: iconHTML(Plug, 15),
  plus: iconHTML(Plus, 12),
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
  x: iconHTML(X, 13),
  zap: iconHTML(Zap, 15),
};
