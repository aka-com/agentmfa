import { createElement } from 'react';
import type { IconNode, SVGProps as LucideSvgProps } from 'lucide';
import type { ReactNode, SVGProps } from 'react';

export type IconDefinition =
  | { kind: 'lucide'; node: IconNode; size: number; attrs?: LucideSvgProps }
  | { kind: 'brand'; path: string; size: number };

const REACT_ATTR_NAMES: Record<string, string> = {
  class: 'className',
  'stroke-linecap': 'strokeLinecap',
  'stroke-linejoin': 'strokeLinejoin',
  'stroke-width': 'strokeWidth',
  tabindex: 'tabIndex',
};

function reactAttributes(attributes: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(attributes).map(([name, value]) => [REACT_ATTR_NAMES[name] ?? name, value]),
  );
}

export function AppIcon({ icon }: { icon?: IconDefinition }): ReactNode {
  if (!icon) return null;
  const common: SVGProps<SVGSVGElement> = {
    xmlns: 'http://www.w3.org/2000/svg',
    viewBox: '0 0 24 24',
    width: icon.size,
    height: icon.size,
    'aria-hidden': true,
    focusable: false,
  };
  if (icon.kind === 'brand') {
    return <svg {...common} fill="currentColor"><path d={icon.path} /></svg>;
  }
  return <svg {...common} fill="none" stroke="currentColor" strokeLinecap="round"
    strokeLinejoin="round" strokeWidth={2}
    {...reactAttributes(icon.attrs ?? {})}>
    {icon.node.map(([tag, attributes], index) =>
      createElement(tag, { ...reactAttributes(attributes), key: attributes.key ?? index }))}
  </svg>;
}
